#pragma once
#include "SnapshotCodeAnalysis.h"

namespace SnapshotAnalysis {
struct ReceiverAnalysisResult {
	std::map<uint64_t, StaticDispatch> resolutions;
	std::string certificate;
	std::map<int64_t, uint32_t> poolClasses;
};
// Must-facts over the known, normal-flow CFG. Unmodeled indirect jumps,
// resource limits and conflicting incoming values produce no new resolutions.
ReceiverAnalysisResult AnalyzeReceivers(const cs_insn* instructions, size_t count,
	const Profile& profile, const std::set<uint64_t>& externalEntries);
}
