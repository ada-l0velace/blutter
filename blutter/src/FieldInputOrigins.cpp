#include "FieldInputOrigins.h"
#include "SnapshotCodeAnalysis.h"
#include <format>
#include <ostream>
#include <stdexcept>

namespace SnapshotAnalysis
{
bool IsRoleProvenCallInput(const CallInputOrigin &input, const Profile &profile, const Edge &edge,
                const CallInputShapes &shapes)
{
	if (!profile.callInputAbi.supported || profile.callInputAbi.wordBytes != 8 || edge.site != input.site ||
	    edge.source != input.payload || !edge.target)
		return false;
	if (input.index) {
		const auto shape = shapes.find(input.site);
		return input.role == "supplied_input" && !input.reg && input.spOffset && edge.kind == "call" &&
		       shape != shapes.end() && ValidCallInputShape(shape->second) &&
		       shape->second.payload == input.payload && shape->second.target == *edge.target &&
		       SuppliedInputIndex(shape->second, *input.spOffset) == input.index;
	}
	if (!input.reg || *input.reg >= 15 || input.spOffset)
		return false;
	if (edge.kind == "call") {
		const auto contract = profile.stubInputContracts.find(*edge.target);
		if (contract != profile.stubInputContracts.end()) {
			if (!ValidStubInputContract(*edge.target, contract->second))
				throw std::runtime_error("Invalid field input SDK role contract");
			for (const auto &role : contract->second.inputs)
				if (role.reg == *input.reg && input.role == StubInputRoleName(role.role))
					return true;
		}
	}
	if (*input.reg != 0)
		return false;
	const auto async = profile.asyncContracts.find(*edge.target);
	if (async == profile.asyncContracts.end())
		return false;
	const auto op = async->second.operation;
	return (input.role == "await_input" && edge.kind == "call" &&
	        (op == AsyncOperation::Await || op == AsyncOperation::AwaitWithTypeCheck)) ||
	       (input.role == "completion_operand" && edge.kind == "jump" &&
	        (op == AsyncOperation::CompleteValue || op == AsyncOperation::CompleteValueOrFuture));
}
namespace
{
constexpr size_t Limit = 200000, LinkLimit = 4096;
bool Matches(const AsyncFieldContext &c, const AsyncFieldAccess &a, const InstanceLayout &layout,
             const CallInputOrigin &input)
{
	if (a.access != "read" || input.payload != c.payload || input.chain.empty() ||
	    input.chain.front().relation != "input")
		return false;
	const auto &step = input.chain.front();
	if (step.origin.stop != "load_endpoint" || step.poolIndex || !step.origin.source)
		return false;
	const auto &source = *step.origin.source;
	if ((source.kind != "load" && source.kind != "load_compressed") || !source.load ||
	    source.site != a.site || source.load->base.id != a.base || source.load->base.bits != 64 ||
	    source.load->displacement < 0 || source.load->displacement > 1048576 ||
	    source.load->displacement + layout.tag != a.offset ||
	    (source.kind == "load_compressed" ? 4U : 8U) != a.bytes || a.bytes != layout.slotBytes)
		return false;
	const auto &proof = source.proof;
	if (proof.size() < 2 || proof.size() > 65 || proof.front() != a.site || proof.back() != input.site ||
	    step.origin.steps != proof.size() - 1 || a.site < c.seed || c.steps > 64 ||
	    (a.site - c.seed) / 4 >= c.steps)
		return false;
	for (size_t n = 1; n < proof.size(); ++n)
		if (proof[n] < 4 || proof[n - 1] != proof[n] - 4)
			return false;
	return true;
}
std::string Quote(const std::string &text)
{
	std::string result = "\"";
	for (unsigned char ch : text) {
		if (ch == '"' || ch == '\\') {
			result += '\\';
			result += ch;
		} else if (ch < 32 || ch == 127)
			result += std::format("\\u{:04x}", ch);
		else
			result += ch;
	}
	return result + '"';
}
} // namespace

FieldInputLinksResult LinkFieldInputs(const AsyncFieldsResult &fields,
                                      const std::vector<CallInputOrigin> &origins, const Profile &profile,
                                      const std::vector<Edge> &edges, const CallInputShapes &shapes)
{
	FieldInputLinksResult result;
	if (!fields.supported)
		return result;
	std::map<std::pair<uint64_t, uint64_t>, std::vector<std::pair<size_t, size_t>>> loads;
	for (size_t n = 0; n < fields.contexts.size(); ++n) {
		const auto &c = fields.contexts[n];
		if (!fields.layouts.contains(c.classId))
			throw std::runtime_error("Field input owner lacks its layout");
		for (size_t m = 0; m < c.accesses.size(); ++m)
			if (c.accesses[m].access == "read")
				loads[{c.payload, c.accesses[m].site}].emplace_back(n, m);
	}
	if (loads.empty())
		return result;
	std::vector<size_t> potential;
	std::set<uint64_t> consumers;
	for (size_t n = 0; n < origins.size(); ++n) {
		++result.originsExamined;
		const auto &input = origins[n];
		if (!input.chain.empty() && input.chain.front().origin.source &&
		    loads.contains({input.payload, input.chain.front().origin.source->site})) {
			potential.push_back(n);
			consumers.insert(input.site);
		}
	}
	if (potential.empty())
		return result;
	std::map<uint64_t, const Edge *> calls;
	for (const auto &edge : edges)
		if (consumers.contains(edge.site))
			calls.emplace(edge.site, &edge);
	for (size_t n : potential) {
		const auto &input = origins[n];
		if (input.chain.empty() || !input.chain.front().origin.source)
			continue;
		const auto found = loads.find({input.payload, input.chain.front().origin.source->site});
		if (found == loads.end())
			continue;
		const auto call = calls.find(input.site);
		if (call == calls.end() || !IsRoleProvenCallInput(input, profile, *call->second, shapes))
			continue;
		for (const auto &[context, access] : found->second) {
			if (!result.remaining || result.links.size() == LinkLimit) {
				result.complete = false;
				return result;
			}
			--result.remaining;
			++result.candidates;
			const auto &c = fields.contexts[context];
			if (Matches(c, c.accesses[access], fields.layouts.at(c.classId), input))
				result.links.push_back({context, access, n});
		}
	}
	return result;
}

std::string FieldInputNote(const AsyncFieldsResult &fields, const std::vector<CallInputOrigin> &origins,
                           const FieldInputLink &link, const std::function<std::string(uint32_t)> &className)
{
	const auto &c = fields.contexts.at(link.context);
	const auto &a = c.accesses.at(link.access);
	const auto &input = origins.at(link.origin);
	const auto &layout = fields.layouts.at(c.classId);
	if (!Matches(c, a, layout, input))
		throw std::runtime_error("Invalid field input relation");
	std::string label;
	if (input.index)
		label = std::format("supplied input[{}] (SP+{:#x})", *input.index, input.spOffset.value_or(0));
	else if (input.reg && *input.reg < 15) {
		auto role = input.role == "completion_operand" ? std::string("async completion operand") : input.role;
		for (auto &ch : role)
			if (ch == '_')
				ch = ' ';
		label = std::format("{} (X{})", role, *input.reg);
	} else
		throw std::runtime_error("Field input relation lacks an input location");
	std::string owner = std::format("class {:#x}", c.classId);
	if (className)
		owner += " (" + Quote(className(c.classId)) + ')';
	std::string storage = a.kind == "context_parent" ? "context parent"
	                      : a.kind == "context_slot"
	                          ? std::format("context slot {} (bounds unknown)", *a.index)
	                          : "instance slot";
	for (const auto &f : layout.fields)
		if (f.offset == a.offset)
			storage = "field " + Quote(f.name);
	return std::format("field input origin: {} <- {} at byte {:#x} of {}; read {:#x} "
	                   "[conditional: {} seed {:#x}; delivery at await {:#x}; normal producer/call returns; "
	                   "successful SDK resumes; "
	                   "value/error-preserving callbacks; copied loaded word only; field value/type unknown]",
	                   label, storage, a.offset, owner, a.site, c.basis, c.seed, c.sourceAwait);
}

void WriteFieldInputs(std::ostream &out, const FieldInputLinksResult &result)
{
	out << ",\"async_field_input_links\":[";
	for (size_t n = 0; n < result.links.size(); ++n) {
		if (n)
			out << ',';
		const auto &link = result.links[n];
		out << "{\"context\":" << link.context << ",\"access\":" << link.access
		    << ",\"input_origin\":" << link.origin << ",\"scope\":\"conditional_loaded_word_only\"}";
	}
	out << "],\"async_field_input_work\":{\"limit\":" << Limit << ",\"link_limit\":" << LinkLimit
	    << ",\"origins_examined\":" << result.originsExamined << ",\"candidates\":" << result.candidates
	    << ",\"remaining\":" << result.remaining << ",\"complete\":" << (result.complete ? "true" : "false")
	    << '}';
}
} // namespace SnapshotAnalysis
