#pragma once
#include "ReceiverAnalysis.h"

namespace SnapshotAnalysis {
struct RegisterContext {
	uint64_t payload;
	std::vector<uint64_t> callers;
	std::vector<StackInput> stackInputs;
	std::vector<RegisterInput> registerInputs;
	ReceiverAnalysisResult analysis;
};
struct RegisterContextResult {
	std::vector<RegisterContext> contexts;
	std::map<uint64_t, std::string> effects;
	std::map<uint64_t, int64_t> forwardedInputs;
	size_t candidateGroups = 0, attempted = 0, steps = 0;
	size_t bindingSteps = 0, droppedCallers = 0;
	size_t effectAttempts = 0, effectSteps = 0;
};
// One-level direct-call bindings have an independent budget. They never alter
// global receiver facts, the native inventory, or the older stack contexts.
RegisterContextResult AnalyzeRegisterContexts(const std::vector<Edge>& edges,
	const std::map<uint64_t, std::vector<uint8_t>>& bytes, Profile profile,
	const std::set<uint64_t>& externalEntries, const std::vector<EntryStackLoad>& entryLoads = {});
}
