#pragma once
#include "SnapshotCodeAnalysis.h"

namespace SnapshotAnalysis {
struct ArrayLengthSummary {
	int64_t arraySpOffset;
	std::vector<uint64_t> proof;
	uint32_t writtenRegisters = 0;
};
// Bounded, straight-line, call-free relation. No heap/stack writes are
// permitted. This is neither a promise of normal return nor a caller binding.
std::optional<ArrayLengthSummary> ProveArrayLength(const cs_insn* code, size_t count, const Profile& profile);
}
