#include "SnapshotCodeAnalysis.h"
#include "FieldInputOrigins.h"
#include "CapturedFieldValues.h"
#include "FreshFieldInitializations.h"
#include "FreshContentUses.h"
#include "CalleeEntryReads.h"
#include "ReceiverAnalysis.h"
#include <fstream>
#include <format>
#include <iostream>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <cstdlib>
#include <algorithm>
#include "AnalysisSelection.h"
#include "CallResultAnnotations.h"
#include "Arm64Decode.h"

// Standalone harness: no Dart runtime, SDK layout, or deserializer involved.
int main(int argc, char** argv)
{
	try {
		if (argc < 4 || argc % 2) throw std::runtime_error("output [address binary]...");
		struct Decoder { csh handle = 0; ~Decoder() { if (handle) cs_close(&handle); } } decoder;
		if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &decoder.handle) != CS_ERR_OK) return 2;
		const auto handle = decoder.handle;
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		struct Block { std::shared_ptr<cs_insn> instructions; size_t count; uint64_t start; };
		std::vector<Block> blocks;
		std::vector<SnapshotAnalysis::Payload> payloads;
		for (int i = 2; i < argc; i += 2) {
			const uint64_t start = std::stoull(argv[i], nullptr, 0);
			std::ifstream input(argv[i + 1], std::ios::binary);
			if (!input) throw std::runtime_error("Cannot read fixture");
			std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)), {});
			const auto [instructions, count] = SnapshotAnalysis::DecodeArm64Instructions(handle, bytes.data(), bytes.size(), start);
			blocks.push_back({std::shared_ptr<cs_insn>(instructions, [count](cs_insn* p) { cs_free(p, count); }), count, start});
			payloads.push_back({start, start + bytes.size(), {}, ""});
		}
		const bool lateHelper = std::getenv("BLUTTER_TEST_LATE_HELPER") && std::string(std::getenv("BLUTTER_TEST_LATE_HELPER")) == "1";
		const auto entryOffsetText = std::getenv("BLUTTER_TEST_HELPER_ENTRY_OFFSET");
		const uint64_t entryOffset = entryOffsetText ? std::stoull(entryOffsetText) : 0;
		if (entryOffset > 4096 || (entryOffset && lateHelper)) throw std::runtime_error("Invalid helper entry fixture");
		if (lateHelper) {
			// Authored budget-boundary control: no assembler process per filler.
			const uint8_t returnWord[] = {0xc0, 0x03, 0x5f, 0xd6};
			for (size_t n = 0; n < 16384; ++n) {
				const uint64_t start = 0x10000 + n*8;
				cs_insn* raw = nullptr;
				const auto count = cs_disasm(handle, returnWord, sizeof(returnWord), start, 0, &raw);
				if (count != 1) throw std::runtime_error("Cannot decode authored return control");
				blocks.push_back({std::shared_ptr<cs_insn>(raw, [count](cs_insn* p) { cs_free(p, count); }), count, start});
				payloads.push_back({start, start+4, {}, ""});
			}
			std::sort(blocks.begin(), blocks.end(), [](const auto& a, const auto& b) { return a.start < b.start; });
			std::sort(payloads.begin(), payloads.end(), [](const auto& a, const auto& b) { return a.start < b.start; });
		}
		SnapshotAnalysis::Profile profile{"test", ARM64_REG_X27, ARM64_REG_X26, 16, 8, 2048,
			{{0x78, "known_thread_field"}}, [](int64_t index) {
				SnapshotAnalysis::PoolSlot slot{"fixture", "slot " + std::to_string(index)};
				if (index == 2) slot.entryPoints = {{7, 0x2000}, {15, 0x2004}};
				if (index == 6) slot.entryPoints = {{7, 0x5000}};
				if (index == 7) slot.entryPoints = {{7, 0xa000}};
				if (index == 8) slot.entryPoints = {{7, 0xc000}};
				return slot;
			}};
		profile.dispatchRegister = ARM64_REG_X21;
		profile.wordReturnRegister = ARM64_REG_X0;
		if (const char* mode = std::getenv("BLUTTER_TEST_SDK_STUB_RETURNS"); mode && std::string(mode) == "1") {
			std::map<uint64_t, uint64_t> bounds;
			for (const auto& payload : payloads) bounds.emplace(payload.start, payload.end);
			profile.sdkStubReturnClasses = SnapshotAnalysis::SdkStubReturnContracts(
				{{0xf000, 0xf000, 0xf008, SnapshotAnalysis::SdkStubReturnKind::GrowableArray, true}}, 5, bounds, true);
		}
		profile.heapBitsRegister = ARM64_REG_X28;
		profile.fieldDecisionAbi = {true, 32, 48};
        profile.booleanValueBit = 4;
		profile.includeGraphStates = !(std::getenv("BLUTTER_TEST_GRAPH_COMPACT") && std::string(std::getenv("BLUTTER_TEST_GRAPH_COMPACT")) == "1");
		profile.dispatchOrigin = 4;
		profile.dispatchEntries = {0x2000, 0x2004, {}, 0x3000, 0x2000, 0x2004, 0x2000, 0x2004, 0xb000};
		if (lateHelper) {
			profile.dispatchEntries.push_back(0x40000);
			profile.dispatchEntries.push_back(0x40100);
		}
		if (entryOffset) {
			profile.dispatchEntries[8] = 0xb000 + entryOffset;
			profile.dispatchEntries.push_back(0xb100 + entryOffset);
		}
		profile.dispatchNullTarget = 0x3000;
		if (!profile.sdkStubReturnClasses.empty()) {
			profile.dispatchEntries.resize(10);
			profile.dispatchEntries[9] = 0x2000;
		}
		if (const char* mode = std::getenv("BLUTTER_TEST_NATIVE_RETURNS"); mode && std::string(mode) == "1") {
			// Authored runtime contracts; opaque fixture callees grant no frame effect.
			profile.nativeReturnClasses = {{0xd000, {5, "allocate_one_byte_string"}}, {0xe000, {6, "allocate_two_byte_string"}}};
			profile.dispatchEntries.resize(11);
			profile.dispatchEntries[9] = 0x2000;
			profile.dispatchEntries[10] = 0x2004;
		}
		profile.classIdShift = 8;
		profile.classIdBits = 16;
		profile.nullRegister = ARM64_REG_X22;
		profile.nullClassId = 1;
		profile.allocationReturns = {{0x2000, 1}, {0x6000, 2}, {0x7000, 3}, {0x8000, 4}};
		profile.preservedCallRegisters = {{0x7000, 1U << 2}, {0x9000, 31}};
		profile.threadHeapClasses = {{0xa8, 2}};
		profile.stackLimitOffset = 0x60;
		profile.framePreservingCalls = {{0x3000, "stack_overflow_without_fpu"}, {0x9000, "array_write_barrier"}, {0xa000, "double_to_integer"}};
		profile.nonReturningCalls = {{0xc000, "range_error_without_fpu"}};
		profile.leafMathContract = {0x80, 0x88, 0x90, 8};
		profile.allocationBodyBounds = {{0x2000, {7, 31}}, {0x7000, {7, 15}}, {0x8000, {7, 39}}};
		profile.arrayBodyContract = {0x6000, 2, 15, 4, 1};
		profile.arrayLengthLayout = SnapshotAnalysis::ArrayLengthLayout{2, 7, 4, 1};
		if (const char* width = std::getenv("BLUTTER_TEST_ARRAY_BYTES")) {
			if (std::string(width) == "8") { profile.arrayBodyContract[3] = 8; profile.arrayLengthLayout->bytes = 8; profile.heapBitsRegister = ARM64_REG_INVALID; }
			else if (std::string(width) != "4") throw std::runtime_error("Unsupported test array width");
		}
		profile.poolHeapClass = [](int64_t index) -> std::optional<uint32_t> {
			if (index == 3 || index == 4) return 1;
			if (index == 5) return 2;
			return {};
		};
		// Independent machine words: LDR x0,[x15]; LDR x30,[x21,x0,LSL#3]; BLR x30.
		const uint8_t budgetCode[] = {0xe0,0x01,0x40,0xf9,0xbe,0x7a,0x60,0xf8,0xc0,0x03,0x3f,0xd6};
		cs_insn* budgetRaw = nullptr;
		const auto budgetCount = cs_disasm(handle, budgetCode, sizeof(budgetCode), 0x8000, 0, &budgetRaw);
		const std::shared_ptr<cs_insn> budgetInstructions(budgetRaw, [budgetCount](cs_insn* p) { cs_free(p, budgetCount); });
		const std::vector<SnapshotAnalysis::StackInput> inputs{{0, "word", 1, {}}};
		for (size_t limit : {size_t{0}, size_t{1}, size_t{100}}) {
			auto remaining = limit;
			const auto result = SnapshotAnalysis::AnalyzeReceivers(budgetRaw, budgetCount, profile, {}, &inputs, &remaining);
			if ((result.resolutions.size() == 1) != (limit == 100) || (limit < 2 && !result.certificate.empty()))
				throw std::runtime_error("Context budget published incomplete analysis");
		}
		std::optional<uint64_t> selectedCaller;
		if (const auto* value = std::getenv("BLUTTER_TEST_ANALYSIS_CALLER"); value && *value)
			selectedCaller = SnapshotAnalysis::ParseAnalysisCaller(value);
		// Authored direct call: BL from 0x1000 to 0x2000, then RET.
		const uint8_t aliasCall[] = {0x00, 0x04, 0x00, 0x94, 0xc0, 0x03, 0x5f, 0xd6};
		cs_insn* aliasRaw = nullptr;
		const auto aliasCount = cs_disasm(handle, aliasCall, sizeof(aliasCall), 0x1000, 0, &aliasRaw);
		const std::shared_ptr<cs_insn> aliasInstructions(aliasRaw, [aliasCount](cs_insn* p) { cs_free(p, aliasCount); });
		if (aliasCount != 2) throw std::runtime_error("Cannot decode authored alias call");
		for (bool shared : {false, true}) {
			std::vector<SnapshotAnalysis::Name> names{{0x2000, "first_alias", "function"}, {0x2000, "runtime_alias", "stub"}};
			if (shared) names.push_back({0x2000, "second_alias", "function"});
			SnapshotAnalysis::Analyzer aliases(profile, {{0x1000, 0x1008, {}, ""}, {0x2000, 0x2004, {}, ""}}, std::move(names));
			aliases.RegisterEntries(aliasRaw, aliasCount);
			const auto comments = aliases.Analyze(aliasRaw, aliasCount, 0x1000);
			const auto note = comments.find(0x1000);
			if (note == comments.end() ||
				(note->second.find("shared Function entry: 2 metadata aliases; source identity unresolved") != std::string::npos) != shared)
				throw std::runtime_error("Shared machine entry was presented as a unique Function identity");
		}
		const bool async = std::getenv("BLUTTER_TEST_ASYNC_CONTRACTS") && std::string(std::getenv("BLUTTER_TEST_ASYNC_CONTRACTS")) == "1";
		if (async) {
			// Authored identities supplied by a synthetic runtime adapter.
			std::map<uint64_t, uint64_t> bounds;
			for (const auto& payload : payloads) bounds.emplace(payload.start, payload.end);
			using Op = SnapshotAnalysis::AsyncOperation;
			std::vector<SnapshotAnalysis::AsyncStubIdentity> ids;
			for (const auto& [entry, operation] : std::map<uint64_t, Op>{{0x11000, Op::Init}, {0x12000, Op::Await},
				{0x13000, Op::AwaitWithTypeCheck}, {0x14000, Op::CompleteValue}, {0x15000, Op::CompleteValueOrFuture}, {0x16000, Op::Resume}})
				if (bounds.contains(entry)) ids.push_back({entry, entry, bounds.at(entry), operation, true});
			profile.asyncContracts = SnapshotAnalysis::SelectAsyncContracts(ids, bounds, true);
		}
        if (const char* layout = std::getenv("BLUTTER_TEST_STUB_INPUTS"); layout && *layout) {
            const bool fieldInputs = std::string(layout).starts_with("field-inputs");
            const bool modern = std::string(layout) == "new" || std::string(layout) == "field-inputs";
            using K = SnapshotAnalysis::StubInputKind; using R = SnapshotAnalysis::StubInputRole;
            const K closure = modern ? K::Closure2 : K::Closure;
            SnapshotAnalysis::StubInputAbis abis{{K::Array, {{2,R::ArrayLength},{1,R::ArrayTypeArguments}}},
                {closure, {{1,R::ClosureFunction},{modern ? 3U : 2U,R::ClosureContext}}}};
            if (modern) abis[closure].push_back({2,R::ClosureLengthFlags});
            std::map<uint64_t,uint64_t> bounds;
            for (const auto& payload : payloads) bounds.emplace(payload.start,payload.end);
            std::vector<SnapshotAnalysis::StubInputIdentity> ids;
            for (const auto& [entry,kind] : std::map<uint64_t,K>{{fieldInputs ? 0x1a000 : 0x11000,K::Array},{fieldInputs ? 0x1b000 : 0x12000,closure}})
                if (bounds.contains(entry)) ids.push_back({entry,entry,bounds.at(entry),kind,true});
            profile.stubInputContracts = SnapshotAnalysis::SelectStubInputContracts(ids,abis,bounds,true);
        }
		if (const char* mode = std::getenv("BLUTTER_TEST_CALL_INPUTS"); mode && *mode) {
			profile.describeInputObject = [](int64_t index) -> std::optional<SnapshotAnalysis::InputObject> {
				if (index == 3) return SnapshotAnalysis::InputObject{"function", "authored_callback", 0x19000};
				return {};
			};
			profile.callInputAbi = {std::string(mode) != "unsupported", 4, 8, "verified_compiler_policy"};
			profile.callInputDescriptors.emplace(10, SnapshotAnalysis::CallInputDescriptor{10, 2, 3, 3, 3});
			profile.callInputModels.emplace(0x18000, SnapshotAnalysis::CallInputModel{0x18000, 3, 0, 2, "authored", {"Object", "Object", "Object"}});
			if (std::string(mode) == "mismatch") profile.callInputDescriptors.at(10).typeArguments = 1;
		}
		if (const char* mode = std::getenv("BLUTTER_TEST_CALL_INPUTS"); mode && (std::string(mode) == "prologue" || std::string(mode) == "named")) {
			profile.callInputModels.clear();
			if (std::string(mode) == "named") { auto& d = profile.callInputDescriptors.at(10); d.positional = 1; d.named = {{1,"first"},{2,"last"}}; }
			profile.descriptorPrologueAbi = {true, 4, 4, 1, 15, 23, 16, 19};

		}
		if (const char* mode = std::getenv("BLUTTER_TEST_CALL_INPUTS"); mode && *mode) {
			profile.readInputCode = [&](uint64_t address, size_t size) {
				std::vector<uint8_t> bytes;
				for (const auto& block : blocks) if (address == block.start && size <= block.count*4) {
					for (size_t n = 0; n < size/4; ++n) bytes.insert(bytes.end(), block.instructions.get()[n].bytes, block.instructions.get()[n].bytes+4);
					break;
				}
				return bytes;
			};
		}
		if (const char* mode=std::getenv("BLUTTER_TEST_COMPLETIONS");mode && *mode) {
			profile.completionExceptions={{0x17000,{0x17008,"null_cast_without_fpu",false}}, {0x17100,{0x17108,"async_error",true}}};
			for (const auto& payload:payloads) profile.completionBodies.emplace(payload.start,SnapshotAnalysis::CompletionBody{payload.end,true,true,{}});
			if (std::string(mode)=="missing") profile.completionBodies.clear();
			if (std::string(mode)=="handler") profile.completionBodies.at(0x1000).handlers={0x1010};
			if (std::string(mode)=="limited") profile.completionBodies.at(0x1000).end+=4;
		}
		if (const char* mode=std::getenv("BLUTTER_TEST_FUTURE_BINDINGS");mode && *mode) {
			profile.futureBindingAbi={true,-8};
			for (const auto& payload:payloads) profile.completionBodies[payload.start]={payload.end,true,true,{}};
			if (std::string(mode)=="missing") profile.completionBodies.clear();
			if (std::string(mode)=="unsupported") profile.futureBindingAbi={};
			if (std::string(mode)=="handler") profile.completionBodies.at(0x1000).handlers={0x1004};
			if (std::string(mode)=="dispatch-entry") profile.dispatchEntries.push_back(0x101c);
		}
		if(const char* mode=std::getenv("BLUTTER_TEST_SAVED_REFERENCES");mode && *mode) {
			const std::string value=mode;
			if(value=="fields-fresh"){profile.allocationReturns[0x1c000]=7;profile.allocationBodyBounds[0x1c000]={7,31};profile.freshContentAllocators.insert(0x7000);}
			profile.savedFrameAbi=value=="unsupported"?SnapshotAnalysis::SavedFrameAbi{}:SnapshotAnalysis::SavedFrameAbi{true,-8};
			if (value.starts_with("fields")) profile.describeInstanceLayout = [](uint32_t cid) {
				SnapshotAnalysis::InstanceLayout l;
				l.classId=cid; l.kind="instance"; l.header=8; l.end=32; l.tag=1; l.slotBytes=4;
				l.excluded={16}; l.unboxed={24,28}; l.fields={{8,cid,"enabled","bool?"}};
				return l;
			};
			profile.describeSavedStackMap=[value](uint64_t payload,uint64_t site){
				SnapshotAnalysis::SavedStackMap m{payload,site};if(value=="missing-map" || value=="fields-missing-map")return m;
				m.available=true;m.registerSlots=0;if(value=="fields-gap"){m.spillSlots=0;return m;}m.spillSlots=32;for(int bit=31;bit>=0;--bit){const int64_t slot=-8-bit*8;if((value!="nonpointer" && value!="fields-nonpointer") || slot!=-16)m.objects.push_back(slot);}return m;
			};
			if(value=="entry")profile.dispatchEntries.push_back(0x102c);
		}
        if (const auto* mode=std::getenv("BLUTTER_TEST_CLOSURE_CAPTURES"); mode && *mode) {
            const std::string value=mode;
            using K=SnapshotAnalysis::StubInputKind;
            profile.closureCaptureLayout={4,1,{{value=="legacy"?K::Closure:K::Closure2,value=="legacy"?19:35}},-8};
            profile.describeInputObject=[value](int64_t index)->std::optional<SnapshotAnalysis::InputObject>{
                if(index!=3)return {};
                SnapshotAnalysis::InputObject object{"function","authored_capture",0x19000};
                if(value!="missing-model")object.closureEntry=SnapshotAnalysis::ClosureEntryModel{0x19000,value=="arity"?3U:2U,value=="arity"?16:8};
                return object;
            };
            profile.describeSavedStackMap=[value](uint64_t payload,uint64_t site){
                SnapshotAnalysis::SavedStackMap m{payload,site};
                m.available=value!="missing-map";m.spillSlots=m.available?1:0;
                m.registerSlots=m.available?std::optional<uint32_t>{0}:std::nullopt;
                if(m.available && value!="untagged")m.objects={-8};
                return m;
            };
            profile.describeInstanceLayout=[](uint32_t cid){
                SnapshotAnalysis::InstanceLayout l;
                l.classId=cid;l.kind="instance";l.header=8;l.end=32;l.tag=1;l.slotBytes=4;
                l.excluded={16};l.unboxed={24,28};return l;
            };
            if(value=="discarded")profile.discardedWithoutHandlers.insert(0x19000);
            profile.describeCompletionBody=[&,value](uint64_t address){
                SnapshotAnalysis::CompletionBody b;
                for(const auto& block:blocks)if(block.start==address){b.end=address+block.count*4;b.available=value!="discarded" && value!="missing-body";}
                if(value=="handler")b.handlers={address+24};
                return b;
            };
            profile.readInputCode=[&](uint64_t address,size_t size){
                std::vector<uint8_t> data;
                for(const auto& block:blocks)if(block.start==address && size<=block.count*4)
                    for(size_t n=0;n<size/4;++n)data.insert(data.end(),block.instructions.get()[n].bytes,block.instructions.get()[n].bytes+4);
                return data;
            };
        }
		SnapshotAnalysis::Analyzer analyzer(std::move(profile), std::move(payloads), {{0x2000, "known_function", "function"}}, selectedCaller);
		for (const auto& block : blocks) analyzer.RegisterEntries(block.instructions.get(), block.count);
		SnapshotAnalysis::AssemblyNotes notes;
		for (const auto& block : blocks) {
			const auto comments = analyzer.Analyze(block.instructions.get(), block.count, block.start);
			if (async) for (const auto& [site, text] : comments)
				if (text.find("async ") != std::string::npos) notes[site].push_back(text);
		}
		auto appendNotes = [&](const auto& addedNotes) {
			for (const auto& [site, added] : addedNotes)
				for (const auto& line : added) {
					auto& retained = notes[site];
					if (std::find(retained.begin(), retained.end(), line) == retained.end()) retained.push_back(line);
				}
		};
		appendNotes(SnapshotAnalysis::BuildCallInputNotes(analyzer.Edges(), {}, analyzer.InputContracts(), analyzer.InputShapes()));
		analyzer.Write(argv[1], [&](const auto& result) {
			appendNotes(SnapshotAnalysis::BuildCallResultNotes(result, analyzer.Edges(), {}, analyzer.InputContracts(), analyzer.InputShapes()));
		}, {}, [&](const auto& result) {
			appendNotes(SnapshotAnalysis::BuildRegisterResultNotes(result, analyzer.Edges()));
		}, [&](const SnapshotAnalysis::FutureBindingsResult& result) {
			for (const auto& binding:result.bindings) if (binding.input.boundary.resumeSite) {
				const auto note=SnapshotAnalysis::AwaitFutureBindingNote(binding);
				if(!note.empty()) notes[*binding.input.boundary.resumeSite].push_back(note);
			}
		}, [&](const SnapshotAnalysis::SavedReferencesResult& result) {
			for(const auto& context:result.contexts)for(const auto& ref:context.observations)notes[ref.site].push_back(SnapshotAnalysis::RestoredReferenceNote(context,ref));
		}, [&](const SnapshotAnalysis::AsyncFieldsResult& result) {
			for(const auto& c:result.contexts)for(const auto& a:c.accesses)
				notes[a.site].push_back(SnapshotAnalysis::AsyncFieldAccessNote(c,a,result.layouts.at(c.classId)));
		}, [&](const SnapshotAnalysis::AsyncFieldsResult& fields, const std::vector<SnapshotAnalysis::CallInputOrigin>& origins,
			const SnapshotAnalysis::FieldInputLinksResult& result) {
			for (const auto& link:result.links) notes[origins[link.origin].site].push_back(SnapshotAnalysis::FieldInputNote(fields,origins,link));
		}, [&](const SnapshotAnalysis::AsyncFieldsResult& fields, const SnapshotAnalysis::CapturedFieldsResult& result) {
			for(const auto& c:result.contexts) for(const auto& r:c.reloads)
				notes[r.site].push_back(SnapshotAnalysis::CapturedFieldNote(fields,c,r));
		}, [&](const SnapshotAnalysis::AsyncFieldsResult& fields, const SnapshotAnalysis::CapturedFieldsResult& captures, const SnapshotAnalysis::FreshFieldsResult& result) {
			for(const auto& c:result.contexts) if(c.write)notes[c.write->site].push_back(SnapshotAnalysis::FreshFieldNote(fields,captures,c));
		}, [&](const SnapshotAnalysis::AsyncFieldsResult& fields, const SnapshotAnalysis::CapturedFieldsResult& captures,
			const SnapshotAnalysis::FreshFieldsResult& fresh, const std::vector<SnapshotAnalysis::CallInputOrigin>& origins,
			const SnapshotAnalysis::FreshContentResult& result) {
			for(const auto& c:result.contexts)for(const auto input:c.inputs)
				notes[*c.transfer].push_back(SnapshotAnalysis::FreshContentNote(fields,captures,fresh,origins,c,input));
		}, [&](const SnapshotAnalysis::AsyncFieldsResult& fields, const SnapshotAnalysis::CapturedFieldsResult& captures,
			const SnapshotAnalysis::FreshFieldsResult& fresh, const SnapshotAnalysis::FreshContentResult& contents,
			const SnapshotAnalysis::CalleeEntryResult& result) {
			for(const auto& link:result.links)notes[*contents.contexts[link.context].transfer].push_back(
				SnapshotAnalysis::ContainerEntryReadNote(fields,captures,fresh,contents,result,link));
		}, [&](const SnapshotAnalysis::JoinedReferencesResult& result) {
        for (const auto& context : result.contexts) for (const auto& reference : context.observations)
            notes[reference.site].push_back(SnapshotAnalysis::JoinedReferenceNote(context,reference));
	}, [&](const SnapshotAnalysis::JoinedReferencesResult& joined,
		const SnapshotAnalysis::FieldBranchUsesResult& result) {
		for (const auto& use : result.uses)
			notes[use.site].push_back(SnapshotAnalysis::FieldBranchNote(joined, use));
        for (const auto& decision : result.decisions)
            notes[decision.site].push_back(SnapshotAnalysis::FieldDecisionNote(joined, result, decision));
    }, [&](const SnapshotAnalysis::FieldBranchUsesResult& fields,
        const SnapshotAnalysis::DecisionBranchesResult& result) {
        for (const auto& use : result.uses)
            notes[use.site].push_back(SnapshotAnalysis::DecisionBranchNote(fields, result, use));
    }, [&](const SnapshotAnalysis::ClosureCapturesResult& result) {
        std::set<uint64_t> captureSites;
        for (const auto& transfer : result.transfers) {
            if (captureSites.insert(transfer.store).second)
                notes[transfer.store].push_back(SnapshotAnalysis::ClosureCaptureNote(transfer));
            notes[transfer.call].push_back(SnapshotAnalysis::ClosureCallbackNote(transfer));
        }
	});
		std::ofstream assembly(std::string(argv[1]) + ".asm");
		for (const auto& block : blocks) for (size_t n = 0; n < block.count; ++n) {
			const auto& instruction = block.instructions.get()[n];
			if (notes.contains(instruction.address)) for (const auto& note : notes.at(instruction.address)) assembly << "    // " << note << '\n';
			assembly << std::format("    // {:#x}: {} {}\n", instruction.address, instruction.mnemonic, instruction.op_str);
		}
		assembly.close();
		if (!assembly) throw std::runtime_error("Cannot write authored assembly fixture");
	} catch (const std::exception& error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
}
