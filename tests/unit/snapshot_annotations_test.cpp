#include "SnapshotCodeAnalysis.h"
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <stdexcept>

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
			cs_insn* instructions = nullptr;
			const auto count = cs_disasm(handle, bytes.data(), bytes.size(), start, 0, &instructions);
			blocks.push_back({std::shared_ptr<cs_insn>(instructions, [count](cs_insn* p) { cs_free(p, count); }), count, start});
			payloads.push_back({start, start + bytes.size(), {}, ""});
		}
		SnapshotAnalysis::Profile profile{"test", ARM64_REG_X27, ARM64_REG_X26, 16, 8, 2048,
			{{0x78, "known_thread_field"}}, [](int64_t index) {
				SnapshotAnalysis::PoolSlot slot{"fixture", "slot " + std::to_string(index)};
				if (index == 2) slot.entryPoints = {{7, 0x2000}, {15, 0x2004}};
				return slot;
			}};
		profile.dispatchRegister = ARM64_REG_X21;
		profile.dispatchOrigin = 4;
		profile.dispatchEntries = {0x2000, 0x2004, {}, 0x3000, 0x2000, 0x2004, 0x2000, 0x2004};
		profile.dispatchNullTarget = 0x3000;
		profile.classIdShift = 8;
		profile.classIdBits = 16;
		profile.nullRegister = ARM64_REG_X22;
		profile.nullClassId = 1;
		profile.allocationReturns = {{0x2000, 1}};
		profile.poolHeapClass = [](int64_t index) -> std::optional<uint32_t> {
			if (index == 3 || index == 4) return 1;
			if (index == 5) return 2;
			return {};
		};
		SnapshotAnalysis::Analyzer analyzer(std::move(profile), std::move(payloads), {{0x2000, "known_function", "function"}});
		for (const auto& block : blocks) analyzer.RegisterEntries(block.instructions.get(), block.count);
		for (const auto& block : blocks) analyzer.Analyze(block.instructions.get(), block.count, block.start);
		analyzer.Write(argv[1]);
	} catch (const std::exception& error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
}
