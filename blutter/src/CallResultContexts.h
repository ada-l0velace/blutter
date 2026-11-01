#pragma once
#include "RegisterContexts.h"
#include <iosfwd>

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
};
// Consume checked helper summaries once at their original direct caller sites.
// Newly derived caller facts do not feed back into their own producer proofs.
CallResultContextResult AnalyzeCallResultContexts(const std::vector<Edge>& edges,
	const std::map<uint64_t, std::vector<uint8_t>>& bytes, Profile profile,
	const std::set<uint64_t>& externalEntries, const RegisterContextResult& registers);
void WriteCallResultContexts(std::ostream& out, const CallResultContextResult& result);
}
