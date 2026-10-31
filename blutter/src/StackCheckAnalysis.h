#pragma once
#include "SnapshotCodeAnalysis.h"

namespace SnapshotAnalysis {
// A path condition, not a no-write or no-GC contract for the runtime stub.
struct InitialStackCheck {
	uint64_t site, successor, slowPath, stub;
	std::vector<uint64_t> proof;
	bool operator==(const InitialStackCheck&) const = default;
};
std::optional<InitialStackCheck> FindInitialStackCheck(const cs_insn* code, size_t count, const Profile& profile);
std::optional<InitialStackCheck> FindStackCheckAt(const cs_insn* code, size_t count, const Profile& profile, uint64_t site);
}
