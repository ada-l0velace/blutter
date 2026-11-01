#pragma once
#include "CallResultContexts.h"

namespace SnapshotAnalysis {
struct SdkStubResultAnalysis {
	CallResultContextResult producers, callers;
	std::map<uint64_t, uint32_t> summaries;
	std::vector<uint64_t> decodeFailures;
};
// Supplemental work has independent bounds; ordinary passes retain their
// candidates, effects and budgets. Producer and consumer proofs never cycle.
SdkStubResultAnalysis AnalyzeSdkStubResults(const std::vector<Edge>& edges,
	const std::map<uint64_t, std::vector<uint8_t>>& bytes, Profile profile,
	const std::set<uint64_t>& entries, const RegisterContextResult& registers);
}
