#pragma once
#include "RegisterContexts.h"
#include <iosfwd>
#include <string_view>

namespace SnapshotAnalysis {
struct ResultBinding {
	uint64_t site, callee;
	uint32_t classId;
	bool conditional;
};
struct CallResultContext {
	uint64_t payload;
	std::vector<ResultBinding> bindings;
	ReceiverAnalysisResult analysis;
};
struct CallResultContextResult {
	std::vector<CallResultContext> contexts;
	size_t candidatePayloads = 0, attempted = 0, steps = 0, droppedCallers = 0;
	bool incomplete = false, exhausted = false;
};
inline constexpr size_t TargetedResultStepLimit = 1000000;
inline std::string_view CallResultContextStatus(const CallResultContextResult& result)
{
	// A complete certificate is valid even when its final transfer used the
	// last available step. Never hide an added context behind a budget label.
	if (!result.contexts.empty()) return "added";
	if (result.exhausted) return "step_limit";
	if (result.incomplete) return "no_certificate";
	return result.candidatePayloads ? "no_new_facts" : "no_return_bindings";
}
// Consume checked helper summaries once at their original direct caller sites.
// Newly derived caller facts do not feed back into their own producer proofs.
CallResultContextResult AnalyzeCallResultContexts(const std::vector<Edge>& edges,
	const std::map<uint64_t, std::vector<uint8_t>>& bytes, Profile profile,
	const std::set<uint64_t>& externalEntries, const RegisterContextResult& registers,
	std::optional<uint64_t> selectedPayload = {});
void WriteCallResultContexts(std::ostream& out, const CallResultContextResult& result);
}
