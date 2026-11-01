#include "ReceiverAnalysis.h"
#include "CallEffects.h"
#include "SdkStubResultAnalysis.h"
#include "Arm64Decode.h"
#include <algorithm>
#include <iostream>
#include <stdexcept>

using namespace SnapshotAnalysis;
namespace {
unsigned checks = 0;
void Check(bool value, const char* message)
{
    ++checks;
    if (!value) throw std::runtime_error(message);
}
const SdkStubReturnIdentity identity{0x4000,0x4000,0x4004,SdkStubReturnKind::GrowableArray,true};
const std::map<uint64_t,uint64_t> bounds{{0x4000,0x4004}};
Profile MakeProfile() {
	Profile p{"synthetic",ARM64_REG_X27,ARM64_REG_X26,16,8,8,{}, {}};
	p.wordReturnRegister = ARM64_REG_X0;
	p.consumeSdkStubReturns = true;
	p.classIdShift = 8;
	p.classIdBits = 16;
	p.dispatchRegister = ARM64_REG_X21;
	p.dispatchEntries.resize(8);
	p.dispatchEntries[7] = 0x3000;
	p.poolHeapClass=[](int64_t slot)->std::optional<uint32_t>{return slot==3?std::optional<uint32_t>{6}:std::nullopt;};
	p.sdkStubReturnClasses=SdkStubReturnContracts({identity},7,bounds,true);
	return p;
}
uint32_t Call(uint64_t at,uint64_t target) {return 0x94000000U|((target-at)/4&0x3ffffff);}
std::vector<uint8_t> Bytes(const std::vector<uint32_t>& words) {
	std::vector<uint8_t> bytes;
    for (const auto word : words)
        for (unsigned i = 0; i < 4; ++i) bytes.push_back(word >> (8 * i));
    return bytes;
}
ReceiverAnalysisResult Analyze(const std::vector<uint32_t>& words,const Profile& p) {
	csh handle = 0;
	Check(cs_open(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN,&handle)==CS_ERR_OK,"Decoder opens");
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_insn* raw = nullptr;
	const auto bytes = Bytes(words);
	const auto count=cs_disasm(handle,bytes.data(),bytes.size(),0x1000,0,&raw);
	Check(count==words.size(),"Authored words decode completely");
	const auto result = AnalyzeReceivers(raw, count, p, {});
	cs_free(raw, count);
	cs_close(&handle);
	return result;
}
const std::vector<uint32_t> dispatch{0xb85ff001,0xd3485c21,0xf8617abe,0xd63f03c0};
ReceiverAnalysisResult Dispatch(std::vector<uint32_t> prefix,const Profile& p) {
	prefix.insert(prefix.end(), dispatch.begin(), dispatch.end());
	return Analyze(prefix, p);
}
}
int main() {
	try {
		Check(MakeProfile().sdkStubReturnClasses.at(0x4000)==SdkStubReturnContract{7,SdkStubReturnKind::GrowableArray},"Exact identity selects matched class");
		Check(SdkStubReturnContracts({},7,bounds,true).empty(),"Missing identity stays unknown");
		Check(SdkStubReturnContracts({identity},0,bounds,true).empty(),"Missing SDK class stays unknown");
		Check(SdkStubReturnContracts({identity},7,bounds,false).empty(),"Unsupported result ABI stays unknown");
		Check(SdkStubReturnContracts({identity},7,{},true).empty(),"Original payload is required");
		for(unsigned defect=0;defect<7;++defect) {
			auto bad=identity;
			if (defect == 0) bad.entry += 2;
			if (defect == 1) bad.payload -= 4;
			if (defect == 2) bad.end += 4;
			if (defect == 3) bad.end = bad.entry;
			if (defect == 4) bad.kind = SdkStubReturnKind::Unknown;
			if (defect == 5) bad.entry = 0;
			if (defect == 6) bad.matchesReference = false;
			Check(SdkStubReturnContracts({bad},7,bounds,true).empty(),"Malformed identity rejected");
			Check(SdkStubReturnContracts({identity,bad,identity},7,bounds,true).contains(identity.entry)==(bad.entry!=identity.entry),"Conflicting same-entry identities never revive");
		}
		Check(SdkStubReturnContracts({identity,identity},7,bounds,true).size()==1,"Compatible duplicates coalesce");
		Check(Dispatch({Call(0x1000,0x4000)},MakeProfile()).resolutions.size()==1,"SDK result reaches receiver dispatch");
		Check(Dispatch({Call(0x1000,0x4000),0xaa0203e0},MakeProfile()).resolutions.empty(),"Register overwrite kills result");
		Check(Dispatch({Call(0x1000,0x4000),Call(0x1004,0x5000)},MakeProfile()).resolutions.empty(),"Unknown call kills result");
		Check(Dispatch({Call(0x1000,0x4004)},MakeProfile()).resolutions.empty(),"Nearby entry has no contract");
		// Authored frame, SDK call, field write, frame restoration and normal RET.
		std::vector<uint32_t> wrapper{0xa9bf79fd,0xaa0f03fd,Call(0x1008,0x4000),0xf800701f,0xaa1d03ef,0xa8c179fd,0xd65f03c0};
		Check(Analyze(wrapper,MakeProfile()).normalReturnClass==7,"Existing engine proves wrapper result through a field write");
		wrapper[3]=0xf81ff01f;
		Check(!Analyze(wrapper,MakeProfile()).normalReturnClass,"Header write invalidates returned class");
		const std::vector<uint32_t> spill{0xa9bf79fd,0xaa0f03fd,0xd10081ef,0xf9401760,0xf81f83a0,Call(0x1014,0x4000),0xf85f83a0};
		Check(Dispatch(spill,MakeProfile()).resolutions.empty(),"SDK result grants no preservation for saved caller object");
		auto abi=MakeProfile();abi.wordReturnRegister=ARM64_REG_INVALID;
		Check(Dispatch({Call(0x1000,0x4000)},abi).certificate.empty(),"Unconfigured ABI rejects supplied contract");
		for(unsigned conflict=0;conflict<5;++conflict) {
			auto p=MakeProfile();
			if(conflict==0)p.allocationReturns.emplace(0x4000,7);
			if(conflict==1)p.provedReturnClasses.emplace(0x4000,7);
			if(conflict==2)p.nativeReturnClasses.emplace(0x4000,NativeReturnContract{7,"allocate_one_byte_string"});
			if(conflict==3)p.nonReturningCalls.emplace(0x4000,"range_error_without_fpu");
			if(conflict==4)p.sdkStubReturnClasses.at(0x4000).classId=1U<<16;
			Check(Dispatch({Call(0x1000,0x4000)},p).certificate.empty(),"Conflicting or out-of-width contract is rejected");
		}
		Check(AnalyzeCallEffects({{0x1000,Bytes({0xa9bf79fd,0xaa0f03fd,Call(0x1008,0x4000),0xaa1d03ef,0xa8c179fd,0xd65f03c0})}},MakeProfile()).certificates.empty(),"Result identity does not prove a frame-safe callee");
		std::vector<Edge> edges;
		std::map<uint64_t, std::vector<uint8_t>> bodies;
		for (uint64_t n = 0; n < 4097; ++n) {
			const uint64_t start = 0x10000 + n * 32;
			Edge edge{};
			edge.site = start + 8;
			edge.source = start;
			edge.kind = "call";
			edge.target = 0x4000;
			edges.push_back(edge);
			bodies.emplace(start, Bytes({0xa9bf79fd, 0xaa0f03fd, Call(start + 8, 0x4000),
				0xaa1d03ef, 0xa8c179fd, 0xd65f03c0}));
		}
		auto ordinaryProfile = MakeProfile();
		ordinaryProfile.consumeSdkStubReturns = false;
		const auto before = AnalyzeCallResultContexts(edges, bodies, ordinaryProfile, {}, {});
		const auto supplemental = AnalyzeSdkStubResults(edges, bodies, ordinaryProfile, {}, {});
		const auto after = AnalyzeCallResultContexts(edges, bodies, ordinaryProfile, {}, {});
		Check(supplemental.producers.candidatePayloads == 4096 && supplemental.producers.droppedCallers == 1,
			"SDK producers have a separate explicit payload bound");
		Check(supplemental.producers.contexts.size() == 4096 && supplemental.summaries.size() == 4096,
			"Retained SDK producer certificates are complete at the boundary");
		Check(before.contexts.empty() && after.contexts.empty() && before.steps == after.steps,
			"Supplemental work cannot mutate ordinary candidates or work accounting");
		Check(!ordinaryProfile.consumeSdkStubReturns && ordinaryProfile.provedReturnClasses.empty(),
			"Producer summaries do not feed back into the supplied profile");
		const auto broken = AnalyzeSdkStubResults({edges.front()}, {{edges.front().source, Bytes({0xffffffff})}}, ordinaryProfile, {}, {});
		Check(broken.decodeFailures == std::vector<uint64_t>{edges.front().source} && broken.producers.contexts.empty(),
			"Undecodable producers are reported separately and publish no certificate");
		const auto source = edges.front().source;
		const auto overlappingLoad = Bytes({0xa9bf79fd, 0xaa0f03fd, Call(source + 8, 0x4000),
			0xf8400908, 0xaa1d03ef, 0xa8c179fd, 0xd65f03c0}); // LDTR X8,[X8].
		const auto recovered = AnalyzeSdkStubResults({edges.front()}, {{source, overlappingLoad}}, ordinaryProfile, {}, {});
		Check(recovered.decodeFailures.empty() && recovered.summaries.at(source) == 7,
			"SDK producer reuses allocated-LDTR compatibility without changing its bytes");
		csh decoder = 0;
		Check(cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &decoder) == CS_ERR_OK, "Compatibility decoder opens");
		cs_option(decoder, CS_OPT_DETAIL, CS_OPT_ON);
		const auto [decoded, count] = DecodeArm64Instructions(decoder, overlappingLoad.data(), overlappingLoad.size(), source);
		Check(count == 7 && decoded[3].id == ARM64_INS_LDTR && !decoded[3].detail->arm64.writeback,
			"Recovered load retains LDTR identity and has no writeback");
		Check(std::equal(decoded[3].bytes, decoded[3].bytes + 4, overlappingLoad.begin() + 12), "Recovered bytes remain original");
		cs_free(decoded, count);
		cs_close(&decoder);
		std::cout<<checks<<" SDK stub return checks passed\n";
	} catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
