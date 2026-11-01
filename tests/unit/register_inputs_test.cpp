#include "RegisterContexts.h"
#include "CallEffects.h"
#include "CallResultContexts.h"
#include <iostream>
#include <memory>
#include <stdexcept>

using namespace SnapshotAnalysis;
namespace {
unsigned checks = 0;
void Check(bool value, const char* message) { ++checks; if (!value) throw std::runtime_error(message); }
Profile MakeProfile() {
	Profile p{"synthetic", ARM64_REG_X27, ARM64_REG_X26, 16, 8, 16, {}, {}};
	p.wordReturnRegister = ARM64_REG_X0;
	p.dispatchRegister = ARM64_REG_X21;
	p.classIdShift = 8; p.classIdBits = 16;
	p.nullRegister = ARM64_REG_X22; p.nullClassId = 1;
	p.dispatchEntries.resize(16); p.dispatchEntries[7] = 0x3000; p.dispatchEntries[8] = 0x3010;
	p.poolHeapClass = [](int64_t index) -> std::optional<uint32_t> { return index == 3 ? std::optional<uint32_t>{7} : index == 4 ? std::optional<uint32_t>{8} : std::nullopt; };
	p.nativeReturnClasses = {{0x4000, {7, "allocate_one_byte_string"}}, {0x5000, {8, "allocate_two_byte_string"}}};
	return p;
}
std::vector<uint8_t> Bytes(const std::vector<uint32_t>& words) {
	std::vector<uint8_t> out;
	for (const auto word : words) for (unsigned n = 0; n < 4; ++n) out.push_back(word >> (n*8));
	return out;
}
uint32_t Call(uint64_t site, uint64_t target) { return 0x94000000U | ((target-site)/4 & 0x3ffffff); }
ReceiverAnalysisResult Analyze(const std::vector<uint32_t>& words, Profile profile = MakeProfile(),
	const std::vector<RegisterInput>* inputs = nullptr, const std::set<uint64_t>& entries = {}) {
	const auto bytes = Bytes(words); csh handle = 0;
	if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK) throw std::runtime_error("decoder");
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); cs_insn* raw = nullptr;
	const auto count = cs_disasm(handle, bytes.data(), bytes.size(), 0x1000, 0, &raw);
	Check(count == words.size(), "Authored words must decode completely");
	auto result = AnalyzeReceivers(raw, count, profile, entries, nullptr, nullptr, nullptr, nullptr, false, false, false, inputs);
	cs_free(raw, count); cs_close(&handle); return result;
}
const std::vector<uint32_t> dispatch{0xb85ff020, 0xd3485c00, 0xf8607abe, 0xd63f03c0};
std::vector<uint32_t> WithDispatch(std::vector<uint32_t> words) { words.insert(words.end(), dispatch.begin(), dispatch.end()); return words; }
const std::vector<uint32_t> frame{0xa9bf79fd, 0xaa0f03fd, 0xd10081ef};
}
int main() {
	try {
		const std::vector<RegisterInput> inputs{{1, 7, {}}};
		Check(Analyze(dispatch, MakeProfile(), &inputs).resolutions.at(0x100c).snapshotTarget == 0x3000, "Bound X1 class resolves dispatch");
		Check(Analyze(dispatch).resolutions.empty(), "Unbound analysis stays unknown");
		Check(Analyze(WithDispatch({0xaa0203e1}), MakeProfile(), &inputs).resolutions.empty(), "Overwrite kills entry class");
		Check(Analyze(WithDispatch({0x2a0103e1}), MakeProfile(), &inputs).resolutions.empty(), "Narrow copy loses pointer class");
		Check(Analyze(WithDispatch({Call(0x1000, 0x7000)}), MakeProfile(), &inputs).resolutions.empty(), "Unknown call cannot recreate entry binding");
		Check(Analyze(WithDispatch({0xf9000040}), MakeProfile(), &inputs).resolutions.empty(), "Unknown store kills entry class");
		Check(Analyze(WithDispatch({0xf800f022}), MakeProfile(), &inputs).resolutions.size() == 1, "Known field store preserves header class");
		Check(Analyze(WithDispatch({0xb4000042, 0xaa0303e1}), MakeProfile(), &inputs).resolutions.empty(), "Conflicting branch drops entry class");
		Check(Analyze(WithDispatch({0xaa0303e1, 0xb5ffffe2}), MakeProfile(), &inputs).resolutions.empty(), "Entry backedge cannot recreate entry value");
		for (const auto bad : std::vector<std::vector<RegisterInput>>{{}, {{15,7,{}}}, {{1,0,{}}}, {{1,65536,{}}}, {{1,7,{}},{1,7,{}}}})
			Check(Analyze(dispatch, MakeProfile(), &bad).certificate.empty(), "Malformed register binding rejected");
		auto abi = MakeProfile(); abi.wordReturnRegister = ARM64_REG_INVALID;
		Check(Analyze(dispatch, abi, &inputs).certificate.empty(), "Unconfigured physical ABI rejected");
		auto reserved = MakeProfile(); reserved.nullRegister = ARM64_REG_X1;
		Check(Analyze(dispatch, reserved, &inputs).certificate.empty(), "Reserved register cannot be an input");
		auto words = frame; words.insert(words.end(), {0xf81f83a1, Call(0x1010, 0x7000), 0xf85f83a1});
		Check(Analyze(WithDispatch(words), MakeProfile(), &inputs).resolutions.empty(), "Unknown callee kills saved entry class");
		auto safe = MakeProfile(); safe.frameSafeCallees.insert(0x7000);
		Check(Analyze(WithDispatch(words), safe, &inputs).resolutions.size() == 1, "Separate frame proof preserves saved entry class");
		Check(Analyze(WithDispatch({Call(0x1000, 0x7000)}), safe, &inputs).resolutions.empty(), "Frame proof does not preserve working X1");
		const auto observed = Analyze({0xf9401761, Call(0x1004, 0x7000)});
		Check(observed.registerInputs.at(0x1004).size() == 1 && observed.registerInputs.at(0x1004)[0].classId == 7, "Global physical register observation");
		Check(Analyze({0xf9401761, Call(0x1004, 0x7000), Call(0x1008, 0x7100)}).registerInputs.count(0x1008) == 0, "Observation expires after unknown call");
		const auto leaf = Analyze({0xf9401760, 0xd65f03c0});
		Check(leaf.normalReturnClass == 7 && leaf.returnClasses.at(0x1004).classId == 7, "Closed leaf has a checked return class");
		Check(Analyze({0xaa0103e0, 0xd65f03c0}, MakeProfile(), &inputs).normalReturnClass == 7, "Conditional helper return from X1");
		Check(!Analyze({0xf9401760, 0x14000400, 0xd65f03c0}).normalReturnClass, "Escaping tail path rejects whole-body summary");
		Check(!Analyze({0xf9401760, 0xd503201f}).normalReturnClass, "Fallthrough is not a return proof");
		Check(!Analyze({0xb4000062, 0xf9401760, 0xd65f03c0, 0xf9401b60, 0xd65f03c0}).normalReturnClass, "Different normal return classes reject summary");
		Check(Analyze({0xb4000062, 0xf9401760, 0xd65f03c0, 0xf9401b60, 0xd65f03c0}).returnClasses.size() == 2, "Mixed RET facts remain individually visible");
		Check(!Analyze({0xb4000062, 0xf9401760, 0xd65f03c0, 0xd65f03c0}).normalReturnClass, "Untyped normal return rejects summary");
		Check(!Analyze({0xb4000062, 0xf9401760, 0xd65f03c0, 0xd65f0040}).normalReturnClass, "Alternate RET register rejects summary");
		auto throwing = MakeProfile(); throwing.nonReturningCalls[0x7000] = "range_error_without_fpu";
		const std::vector<uint32_t> exceptional{0xf9401760, 0xb5000042, 0xd65f03c0, Call(0x100c, 0x7000)};
		Check(Analyze(exceptional, throwing).normalReturnClass == 7, "Reviewed exceptional exit needs no result");
		Check(!Analyze(exceptional).normalReturnClass, "Unknown call remains potentially returning");
		auto returned = MakeProfile(); returned.provedReturnClasses[0x7000] = 7;
		Check(Analyze(WithDispatch({Call(0x1000,0x7000),0xaa0003e1}), returned).resolutions.size() == 1, "Machine result-only contract reaches dispatch");
		Check(Analyze(WithDispatch(words), returned, &inputs).resolutions.empty(), "Machine return contract grants no frame effect");
		Check(AnalyzeCallEffects({{0x1000, Bytes({0xa9bf79fd,0xaa0f03fd,Call(0x1008,0x7000),0xaa1d03ef,0xa8c179fd,0xd65f03c0})}},returned).certificates.empty(), "Return class cannot admit a frame certificate");
		returned.provedReturnClasses[0x4000] = 7;
		Check(Analyze(dispatch,returned,&inputs).certificate.empty(), "Overlapping native and machine identities rejected");
		// Authored call edges exercise selection and one-level grouping.
		Edge call{}; call.site=0x8000;call.kind="call";call.target=0x2000;call.registerInputs={{0,8,{0x7ffc}},{1,7,{0x7ff8}},{2,8,{0x7ff4}}};
		const auto contexts=AnalyzeRegisterContexts({call},{{0x2000,Bytes(dispatch)}},MakeProfile(),{});
		Check(contexts.contexts.size()==1 && contexts.contexts[0].registerInputs.size()==1 && contexts.contexts[0].registerInputs[0].reg==1,"Liveness excludes irrelevant entry registers");
		Check(contexts.contexts[0].analysis.resolutions.size()==1,"Selected input reaches conditional dispatch");
		call.registerInputs={{0,7,{0x7ffc}}};
		const auto identity=AnalyzeRegisterContexts({call},{{0x2000,Bytes({0xd65f03c0})}},MakeProfile(),{});
		Check(identity.contexts.size()==1 && identity.contexts[0].analysis.normalReturnClass==7,"Return X0 is a relevant physical use");
		call.registerInputs={{1,7,{0x7ffc}}};
		Check(AnalyzeRegisterContexts({call},{{0x2000,Bytes({0xaa0203e1,0xd65f03c0})}},MakeProfile(),{}).contexts.empty(),"Entry overwritten before use is excluded");
		Check(AnalyzeRegisterContexts({call},{{0x2000,Bytes({Call(0x2000,0x7000),0xaa0103e0,0xd65f03c0})}},MakeProfile(),{}).contexts.empty(),"Call-killed register does not create a result binding");
		auto siteBound = MakeProfile(); siteBound.callReturnClasses[0x1000] = {0x7000,7};
		Check(Analyze(WithDispatch({Call(0x1000,0x7000),0xaa0003e1}),siteBound).resolutions.size()==1,"Exact call-site result reaches consumer");
		Check(Analyze(WithDispatch({Call(0x1000,0x7004),0xaa0003e1}),siteBound).certificate.empty(),"Mismatched original BL rejects site result");
		Check(Analyze(WithDispatch({Call(0x1000,0x7000),Call(0x1004,0x7100),0xaa0003e1}),siteBound).resolutions.empty(),"Site result expires at another call");
		siteBound.callReturnClasses[0x2000]={0x7000,7};
		Check(Analyze(dispatch,siteBound).certificate.empty(),"Out-of-body call-site binding rejected");
		Edge producer{}; producer.site=0x1000;producer.source=0x1000;producer.kind="call";producer.target=0x2000;
		Edge consumer{};consumer.site=0x1014;consumer.source=0x1000;consumer.kind="indirect_call";
		const auto caller=Bytes(WithDispatch({Call(0x1000,0x2000),0xaa0003e1}));
		auto global=MakeProfile();global.provedReturnClasses[0x2000]=7;
		const auto result=AnalyzeCallResultContexts({producer,consumer},{{0x1000,caller}},global,{},{});
		Check(result.contexts.size()==1 && result.contexts[0].analysis.resolutions.size()==1,"Global helper return consumed in separate caller pass");
		RegisterContextResult conditional;RegisterContext typed{};typed.payload=0x2000;typed.callers={0x1000};typed.analysis.normalReturnClass=7;conditional.contexts.push_back(typed);
		Check(AnalyzeCallResultContexts({producer,consumer},{{0x1000,caller}},MakeProfile(),{},conditional).contexts.size()==1,"Conditional helper return stays bound to original caller");
		Check(AnalyzeCallResultContexts({producer,consumer},{{0x1000,caller}},global,{0x1004},{}).contexts.empty(),"Alternate caller entry cannot inherit call result");
		conditional.contexts[0].payload=0x2100;
		Check(AnalyzeCallResultContexts({producer,consumer},{{0x1000,caller}},MakeProfile(),{},conditional).contexts.empty(),"Wrong conditional callee is ignored");
		conditional.contexts[0]=typed;typed.analysis.normalReturnClass=8;conditional.contexts.push_back(typed);typed.analysis.normalReturnClass=7;conditional.contexts.push_back(typed);
		Check(AnalyzeCallResultContexts({producer,consumer},{{0x1000,caller}},MakeProfile(),{},conditional).contexts.empty(),"Conflicting conditional result cannot be revived");
		call.registerInputs={{1,7,{0x7ffc}}};
		const auto splitBody=Bytes({0xb4000062,0xaa0303e1,0xd65f03c0,0xb85ff020,0xd3485c00,0xf8607abe,0xd63f03c0});
		Check(AnalyzeRegisterContexts({call},{{0x2000,splitBody}},MakeProfile(),{}).contexts.size()==1,"Liveness unions entry uses across branch successors");
		call.stackInputs={{0,"heap_class",8,{}},{8,"word",2,{}}};
		auto narrow=dispatch;narrow.insert(narrow.begin(),0xb94009e2); // LDR W2,[X15,#8].
		const std::vector<EntryStackLoad> loads{{0x2000,0x2000,8,"w2",4,{0x2000}}};
		const auto selected=AnalyzeRegisterContexts({call},{{0x2000,Bytes(narrow)}},MakeProfile(),{},loads);
		Check(selected.contexts.size()==1 && selected.contexts[0].stackInputs.size()==1 && selected.contexts[0].stackInputs[0].spOffset==8,"Only observed callee slots bind; narrow word inputs remain available");
		std::vector<Edge> many;
		for (unsigned n=0;n<4097;++n) {
			Edge edge{};edge.site=0x10000+n*4;edge.source=edge.site;edge.kind="call";edge.target=0x2000;edge.registerInputs={{1,n+1,{edge.site-4}}};many.push_back(std::move(edge));
		}
		const auto bounded=AnalyzeRegisterContexts(many,{{0x2000,Bytes({0xaa0103e0,0xd65f03c0})}},MakeProfile(),{});
		Check(bounded.candidateGroups==4096 && bounded.contexts.size()==4096 && bounded.droppedCallers==1,"Register group bound reports the omitted caller explicitly");
		std::cout << checks << " register and return checks passed\n";
	} catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
