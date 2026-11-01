#include "CallResultContexts.h"
#include <algorithm>
#include <memory>
#include <ostream>
#include <sstream>
#include <stdexcept>

namespace SnapshotAnalysis {
CallResultContextResult AnalyzeCallResultContexts(const std::vector<Edge>& edges,
	const std::map<uint64_t, std::vector<uint8_t>>& bytes, Profile profile,
	const std::set<uint64_t>& externalEntries, const RegisterContextResult& registers)
{
	CallResultContextResult result;
	if (profile.wordReturnRegister != ARM64_REG_X0) return result;
	std::map<uint64_t, std::pair<uint64_t, uint32_t>> conditional;
	std::set<uint64_t> conflicts;
	for (const auto& context : registers.contexts) if (context.analysis.normalReturnClass)
		for (const auto site : context.callers) {
			const auto value = std::make_pair(context.payload, *context.analysis.normalReturnClass);
			if (conditional.contains(site) && conditional.at(site) != value) conflicts.insert(site);
			else conditional.emplace(site, value);
		}
	for (const auto site : conflicts) conditional.erase(site);
	std::map<uint64_t, std::vector<ResultBinding>> groups;
	std::map<uint64_t, const Edge*> bySite;
	for (const auto& edge : edges) {
		bySite.emplace(edge.site, &edge);
		if (edge.kind != "call" || !edge.target || !bytes.contains(edge.source) || profile.allocationReturns.contains(*edge.target) || profile.nonReturningCalls.contains(*edge.target)) continue;
		const auto known = profile.provedReturnClasses.find(*edge.target);
		const auto bound = conditional.find(edge.site);
		if (known == profile.provedReturnClasses.end() && (bound == conditional.end() || bound->second.first != *edge.target)) continue;
		if (known != profile.provedReturnClasses.end() && bound != conditional.end() && known->second != bound->second.second) continue;
		if (groups.size() >= 4096 && !groups.contains(edge.source)) { ++result.droppedCallers; continue; }
		groups[edge.source].push_back({edge.site, *edge.target, known != profile.provedReturnClasses.end() ? known->second : bound->second.second, known == profile.provedReturnClasses.end()});
	}
	result.candidatePayloads = groups.size();
	if (groups.empty()) return result;
	struct Decoder { csh handle = 0; ~Decoder() { if (handle) cs_close(&handle); } } decoder;
	if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &decoder.handle) != CS_ERR_OK ||
		cs_option(decoder.handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) throw std::runtime_error("Cannot initialize call-result decoder");
	size_t remaining = 20000000;
	for (const auto& [entry, bindings] : groups) {
		if (!remaining) break;
		++result.attempted;
		profile.callReturnClasses.clear();
		for (const auto& binding : bindings) profile.callReturnClasses.emplace(binding.site, CallReturnClass{binding.callee, binding.classId});
		const auto& body = bytes.at(entry); cs_insn* raw = nullptr;
		const auto count = cs_disasm(decoder.handle, body.data(), body.size(), entry, 0, &raw);
		const std::shared_ptr<cs_insn> owner(raw, [count](cs_insn* p) { cs_free(p, count); });
		if (count*4 != body.size()) continue;
		auto analysis = AnalyzeReceivers(raw, count, profile, externalEntries, nullptr, &remaining);
		bool gain = false;
		for (auto it = analysis.resolutions.begin(); it != analysis.resolutions.end();) {
			const auto old = bySite.find(it->first);
			if (old != bySite.end() && old->second->staticDispatch && old->second->staticDispatch->snapshotTarget == it->second.snapshotTarget) it = analysis.resolutions.erase(it);
			else { gain = true; ++it; }
		}
		for (const auto& [site, values] : analysis.stackInputs) {
			const auto old = bySite.find(site); if (old == bySite.end()) continue;
			for (const auto& value : values) if (std::none_of(old->second->stackInputs.begin(), old->second->stackInputs.end(), [&](const auto& item) {
				return item.spOffset == value.spOffset && item.kind == value.kind && item.value == value.value;
			})) gain = true;
		}
		for (const auto& [site, arrays] : analysis.arrayArguments) {
			const auto old = bySite.find(site); if (old == bySite.end()) continue;
			for (const auto& array : arrays) {
				const auto previous = std::find_if(old->second->arrayArguments.begin(), old->second->arrayArguments.end(), [&](const auto& item) { return item.spOffset == array.spOffset && item.allocation == array.allocation; });
				if (previous == old->second->arrayArguments.end()) { gain = true; continue; }
				for (const auto& [index, cid] : array.elements) if (!previous->elements.contains(index) || previous->elements.at(index) != cid) gain = true;
			}
		}
		if (analysis.normalReturnClass && !profile.provedReturnClasses.contains(entry)) gain = true;
		if (gain && !analysis.certificate.empty()) result.contexts.push_back({entry, bindings, std::move(analysis)});
	}
	result.steps = 20000000-remaining;
	return result;
}
void WriteCallResultContexts(std::ostream& out, const CallResultContextResult& result)
{
	auto proof = [&](const auto& values) {
		out << '['; bool first = true;
		for (const auto value : values) { if (!first) out << ','; first = false; out << value; }
		out << ']';
	};
	out << '[';
	for (size_t n = 0; n < result.contexts.size(); ++n) {
		if (n) out << ','; const auto& context = result.contexts[n];
		out << "{\"payload\":" << context.payload << ",\"inputs\":[],\"return_bindings\":[";
		for (size_t k = 0; k < context.bindings.size(); ++k) {
			if (k) out << ','; const auto& value = context.bindings[k];
			out << "{\"site\":" << value.site << ",\"callee\":" << value.callee << ",\"class_id\":" << value.classId
				<< ",\"basis\":\"" << (value.conditional ? "register_context" : "machine_return_summary") << "\"}";
		}
		out << "],\"resolutions\":["; bool first = true;
		for (const auto& [site, value] : context.analysis.resolutions) {
			if (!first) out << ','; first = false;
			out << "{\"site\":" << site << ",\"load\":" << value.load << ",\"index\":" << value.index << ",\"table_index\":" << value.tableIndex
				<< ",\"snapshot_target\":" << value.snapshotTarget << ",\"proof\":"; proof(value.proof); out << '}';
		}
		out << "],\"forwarded_returns\":[],\"array_length_returns\":[],\"stack_observations\":["; first = true;
		for (const auto& [site, values] : context.analysis.stackInputs) {
			if (!first) out << ','; first = false;
			out << "{\"site\":" << site << ",\"values\":[";
			for (size_t k = 0; k < values.size(); ++k) {
				if (k) out << ','; const auto& value = values[k];
				std::ostringstream bits; bits << "0x" << std::hex << value.value;
				if (value.kind != "word" && value.kind != "heap_class") throw std::runtime_error("Invalid result-context stack kind");
				out << "{\"sp_offset\":" << value.spOffset << ",\"kind\":\"" << value.kind << "\",\"value\":\"" << bits.str() << "\",\"proof\":";
				proof(value.proof); out << '}';
			}
			out << "]}";
		}
		out << "],\"array_observations\":["; first = true;
		for (const auto& [site, values] : context.analysis.arrayArguments) {
			if (!first) out << ','; first = false;
			out << "{\"site\":" << site << ",\"values\":[";
			for (size_t k = 0; k < values.size(); ++k) {
				if (k) out << ','; const auto& value = values[k];
				out << "{\"sp_offset\":" << value.spOffset << ",\"allocation\":" << value.allocation << ",\"length\":" << value.length << ",\"elements\":[";
				bool firstElement = true;
				for (const auto& [index, cid] : value.elements) { if (!firstElement) out << ','; firstElement = false; out << '[' << index << ',' << cid << ']'; }
				out << "],\"proof\":"; proof(value.proof); out << '}';
			}
			out << "]}";
		}
		out << "],\"normal_return_class\":" << (context.analysis.normalReturnClass ? std::to_string(*context.analysis.normalReturnClass) : "null")
			<< ",\"certificate\":" << context.analysis.certificate << '}';
	}
	out << ']';
}
}
