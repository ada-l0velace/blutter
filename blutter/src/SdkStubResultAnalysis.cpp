#include "SdkStubResultAnalysis.h"
#include "Arm64Decode.h"
#include <algorithm>
#include <memory>
#include <stdexcept>

namespace SnapshotAnalysis {
SdkStubResultAnalysis AnalyzeSdkStubResults(const std::vector<Edge>& edges,
	const std::map<uint64_t, std::vector<uint8_t>>& bytes, Profile profile,
	const std::set<uint64_t>& entries, const RegisterContextResult& registers)
{
	SdkStubResultAnalysis result;
	if (profile.sdkStubReturnClasses.empty() || profile.wordReturnRegister != ARM64_REG_X0) return result;
	std::map<uint64_t, std::vector<ResultBinding>> groups;
	for (const auto& edge : edges) {
		if (edge.kind != "call" || !edge.target || !bytes.contains(edge.source) || !profile.sdkStubReturnClasses.contains(*edge.target)) continue;
		if (groups.size() >= 4096 && !groups.contains(edge.source)) { ++result.producers.droppedCallers; continue; }
		groups[edge.source].emplace_back(edge.site, *edge.target, profile.sdkStubReturnClasses.at(*edge.target).classId, ResultBindingBasis::SdkStubIdentity);
	}
	result.producers.candidatePayloads = groups.size();
	if (groups.empty()) return result;
	struct Decoder {
		csh handle = 0;
		~Decoder() { if (handle) cs_close(&handle); }
	} decoder;
	if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &decoder.handle) != CS_ERR_OK ||
		cs_option(decoder.handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
		throw std::runtime_error("Cannot initialize SDK result decoder");
	profile.consumeSdkStubReturns = true;
	size_t remaining = 20000000;
	for (const auto& [entry, bindings] : groups) {
		if (!remaining) break;
		++result.producers.attempted;
		const auto& body = bytes.at(entry);
		const auto [raw, count] = DecodeArm64Instructions(decoder.handle, body.data(), body.size(), entry);
		const std::shared_ptr<cs_insn> owner(raw, [count](cs_insn* p) { cs_free(p, count); });
		if (count * 4 != body.size()) {
			result.decodeFailures.push_back(entry);
			result.producers.incomplete = true;
			continue;
		}
		auto analysis = AnalyzeReceivers(raw, count, profile, entries, nullptr, &remaining);
		if (analysis.certificate.empty()) {
			result.producers.incomplete = true;
			continue;
		}
		if (analysis.normalReturnClass && profile.provedReturnClasses.contains(entry) && profile.provedReturnClasses.at(entry) != *analysis.normalReturnClass)
			throw std::runtime_error("SDK result contradicts an existing normal-return summary");
		if (analysis.normalReturnClass && !profile.provedReturnClasses.contains(entry))
			result.summaries.emplace(entry, *analysis.normalReturnClass);
		result.producers.contexts.push_back({entry, bindings, std::move(analysis)});
	}
	result.producers.steps = 20000000 - remaining;
	result.producers.exhausted = !remaining;
	// No new summary is used to prove another producer. Only the subsequent
	// consumer pass sees this additional independently checked summary set.
	std::set<uint64_t> requested;
	for (const auto& [entry, cid] : result.summaries) {
		profile.provedReturnClasses.emplace(entry, cid);
		requested.insert(entry);
	}
	result.callers = AnalyzeCallResultContexts(edges, bytes, std::move(profile), entries, registers, {}, &requested);
	for (const auto entry : result.callers.decodeFailures)
		if (std::find(result.decodeFailures.begin(), result.decodeFailures.end(), entry) == result.decodeFailures.end()) result.decodeFailures.push_back(entry);
	for (auto& context : result.callers.contexts) for (auto& binding : context.bindings)
		if (result.summaries.contains(binding.callee)) binding.basis=ResultBindingBasis::SdkStubSummary;
	return result;
}
}
