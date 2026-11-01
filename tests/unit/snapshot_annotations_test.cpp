#include "SnapshotCodeAnalysis.h"
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
		SnapshotAnalysis::Analyzer analyzer(std::move(profile), std::move(payloads), {{0x2000, "known_function", "function"}}, selectedCaller);
		for (const auto& block : blocks) analyzer.RegisterEntries(block.instructions.get(), block.count);
		for (const auto& block : blocks) analyzer.Analyze(block.instructions.get(), block.count, block.start);
		SnapshotAnalysis::AssemblyNotes notes;
		analyzer.Write(argv[1], [&](const auto& result) {
			for (const auto& [site, added] : SnapshotAnalysis::BuildCallResultNotes(result, analyzer.Edges()))
				for (const auto& line : added) {
					auto& retained = notes[site];
					if (std::find(retained.begin(), retained.end(), line) == retained.end()) retained.push_back(line);
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
