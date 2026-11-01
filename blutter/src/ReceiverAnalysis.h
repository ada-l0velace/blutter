#pragma once
#include "SnapshotCodeAnalysis.h"
#include "StackCheckAnalysis.h"

namespace SnapshotAnalysis {
struct InitialStackCheck;
struct ReceiverAnalysisResult {
	std::map<uint64_t, StaticDispatch> resolutions;
	std::string certificate;
	std::map<int64_t, uint32_t> poolClasses;
	std::map<uint64_t, std::vector<StackInput>> stackInputs;
	std::map<uint64_t, std::vector<RegisterInput>> registerInputs;
	std::map<uint64_t, ReturnedClass> returnClasses;
	std::optional<uint32_t> normalReturnClass;
	std::vector<EntryStackLoad> entryStackLoads;
	std::map<uint64_t, ForwardedReturn> forwardedReturns;
	std::map<uint64_t, std::vector<ArrayArgument>> arrayArguments;
	std::map<uint64_t, IndexedReturn> indexedReturns;
	std::map<uint64_t, ArrayElementRead> arrayReads;
	std::map<uint64_t, ArrayLengthReturn> lengthReturns;
	bool arrayContinuationUsed = false;
	std::vector<uint64_t> traceBlocks;
	std::vector<InitialStackCheck> traceGuards;
	std::optional<uint64_t> traceStop;
	std::optional<uint64_t> traceGetter;
	std::optional<std::pair<uint64_t, uint64_t>> missingArrayEffect; // site, exact target; scheduling only
};
// Must-facts over the known, normal-flow CFG. Unmodeled indirect jumps,
// resource limits and conflicting incoming values produce no new resolutions.
ReceiverAnalysisResult AnalyzeReceivers(const cs_insn* instructions, size_t count,
	const Profile& profile, const std::set<uint64_t>& externalEntries,
	const std::vector<StackInput>* inputs = nullptr, size_t* sharedSteps = nullptr,
	const ArrayInputBinding* arrayInput = nullptr, const InitialStackCheck* initialPath = nullptr, bool firstTraversal = false, bool followIndexedResult = false, bool probeMissingEffects = false,
	const std::vector<RegisterInput>* registerInputs = nullptr);
}
