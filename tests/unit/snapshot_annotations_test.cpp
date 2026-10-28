#include "SnapshotCodeAnalysis.h"
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>

// Standalone harness: no Dart runtime, SDK layout, or deserializer involved.
int main(int argc, char** argv)
{
	try {
		if (argc < 4 || argc % 2) throw std::runtime_error("output [address binary]...");
		csh handle;
		if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK) return 2;
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		struct Block { cs_insn* instructions; size_t count; uint64_t start; };
		std::vector<Block> blocks;
		std::vector<SnapshotAnalysis::Payload> payloads;
		for (int i = 2; i < argc; i += 2) {
			const uint64_t start = std::stoull(argv[i], nullptr, 0);
			std::ifstream input(argv[i + 1], std::ios::binary);
			if (!input) throw std::runtime_error("Cannot read fixture");
			std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)), {});
			cs_insn* instructions = nullptr;
			const auto count = cs_disasm(handle, bytes.data(), bytes.size(), start, 0, &instructions);
			blocks.push_back({instructions, count, start});
			payloads.push_back({start, start + bytes.size(), {}, ""});
		}
		SnapshotAnalysis::Profile profile{"test", ARM64_REG_X27, ARM64_REG_X26, 16, 8, 2048,
			{{0x78, "known_thread_field"}}, [](int64_t index) {
				return SnapshotAnalysis::PoolSlot{"fixture", "slot " + std::to_string(index)};
			}};
		SnapshotAnalysis::Analyzer analyzer(std::move(profile), std::move(payloads), {{0x2000, "known_function", "function"}});
		for (const auto& block : blocks) analyzer.RegisterEntries(block.instructions, block.count);
		for (const auto& block : blocks) analyzer.Analyze(block.instructions, block.count, block.start);
		analyzer.Write(argv[1]);
		for (const auto& block : blocks) cs_free(block.instructions, block.count);
		cs_close(&handle);
	} catch (const std::exception& error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
}
