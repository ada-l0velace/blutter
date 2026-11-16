#pragma once
#include "AsyncContracts.h"
#include "WordOrigins.h"
#include <map>
#include <set>

namespace SnapshotAnalysis {
struct Profile;
// Metadata belongs to this exact native payload. Missing Code/handler data is
// unknown, not evidence that no handler can produce a normal completion.
struct CompletionBody {
	uint64_t end = 0;
	bool available = false, asyncErrorHandler = false;
	std::vector<uint64_t> handlers;
};
struct CompletionException {
	uint64_t end;
	std::string kind;
	bool tailOnly = false;
};
struct CompletionObservation {
	uint64_t site, callee;
	AsyncOperation operation;
	WordOriginResult origin;
	std::string value = "unknown", basis = "unproved";
	std::optional<uint32_t> classId;
	std::optional<int64_t> poolIndex;
};
struct CompletionExit {
	uint64_t site;
	std::optional<uint64_t> target;
	std::string kind;
};
struct CompletionSummary {
	uint64_t payload, end;
	std::string status = "unknown";
	bool closed = false, hasUnknownValue = false, mayBeNull = false, valueOrFuture = false;
	std::optional<uint32_t> exactClass;
	std::set<uint32_t> observedClasses;
	std::vector<uint64_t> initializations, reached, entries;
	std::vector<CompletionObservation> completions;
	std::vector<CompletionExit> exits;
	size_t steps = 0;
};
// All syntactic completion sites must be accounted for. Handler and alternate
// entries are separate roots. These observations never become machine-return,
// memory-preservation or producer-to-await contracts.
std::optional<CompletionSummary> AnalyzeCompletions(const cs_insn* instructions, size_t count,
	const Profile& profile, const CompletionBody& body, const std::set<uint64_t>& externalEntries,
	const std::map<uint64_t, int64_t>& checkedPoolLoads, size_t& remaining);
std::string CompletionSummaryNote(const CompletionSummary& summary);
std::string CompletionValueNote(const CompletionObservation& observation);
}
