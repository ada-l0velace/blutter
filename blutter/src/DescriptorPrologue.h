#pragma once
#include <cstdint>
#include <optional>
#include <vector>

namespace SnapshotAnalysis {
struct DescriptorPrologueAbi {
	bool supported = false;
	unsigned descriptorRegister = 0, fieldBytes = 0, smiShift = 0;
	int64_t typeArgumentsOffset = 0, sizeOffset = 0, frameArgumentBase = 0;
	int64_t countOffset = 0;
};
struct DescriptorPrologue {
	uint64_t target, typeArgumentsLoad, branch, sizeLoad, addressAdd, vectorLoad;
	std::vector<uint64_t> proof;
	bool parameter = false;
	int64_t countBias = 0, frameLoadOffset = 0;
};
// Recognizes the reviewed generated type-vector prologue, including its entry
// frame and descriptor aliases. It is a packet ABI certificate, not a source
// Function identity, effect summary, or claim that the positive branch executes.
std::optional<DescriptorPrologue> ProveDescriptorPrologue(const std::vector<uint8_t>& bytes,
	uint64_t target, const DescriptorPrologueAbi& abi);
}
