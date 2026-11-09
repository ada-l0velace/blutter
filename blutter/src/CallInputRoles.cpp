#include "CallInputRoles.h"
#include <set>
#include <stdexcept>

namespace SnapshotAnalysis {
const char* StubInputKindName(StubInputKind kind)
{
	switch (kind) {
	case StubInputKind::Array: return "allocate_array";
	case StubInputKind::Closure: return "allocate_closure";
	case StubInputKind::Closure1: return "allocate_closure_1";
	case StubInputKind::Closure2: return "allocate_closure_2";
	case StubInputKind::Closure3: return "allocate_closure_3";
	case StubInputKind::Closure4: return "allocate_closure_4";
	default: return "unknown";
	}
}
const char* StubInputRoleName(StubInputRole role)
{
	switch (role) {
	case StubInputRole::ArrayLength: return "array_length";
	case StubInputRole::ArrayTypeArguments: return "array_type_arguments";
	case StubInputRole::ClosureFunction: return "closure_function";
	case StubInputRole::ClosureContext: return "closure_context";
	case StubInputRole::ClosureLengthFlags: return "closure_length_flags";
	default: return "unknown";
	}
}
const char* StubInputRoleText(StubInputRole role)
{
	switch (role) {
	case StubInputRole::ArrayLength: return "array length";
	case StubInputRole::ArrayTypeArguments: return "array type arguments";
	case StubInputRole::ClosureFunction: return "closure function";
	case StubInputRole::ClosureContext: return "closure context";
	case StubInputRole::ClosureLengthFlags: return "closure length/flags";
	default: return "unknown role";
	}
}
bool ValidStubInputRoles(StubInputKind kind, const std::vector<StubRegisterRole>& inputs)
{
	using R = StubInputRole;
	std::set<R> expected;
	if (kind == StubInputKind::Array) expected = {R::ArrayLength, R::ArrayTypeArguments};
	else if (kind == StubInputKind::Closure) expected = {R::ClosureFunction, R::ClosureContext};
	else if (kind >= StubInputKind::Closure1 && kind <= StubInputKind::Closure4)
		expected = {R::ClosureFunction, R::ClosureContext, R::ClosureLengthFlags};
	else return false;
	if (inputs.size() != expected.size()) return false;
	std::set<unsigned> registers;
	for (const auto& input : inputs)
		if (input.reg >= 15 || !registers.insert(input.reg).second || !expected.erase(input.role)) return false;
	return expected.empty();
}
bool ValidStubInputContract(uint64_t entry, const StubInputContract& contract)
{
	return entry && entry % 4 == 0 && contract.end > entry && contract.end % 4 == 0 &&
		contract.end - entry <= (1U << 20) && ValidStubInputRoles(contract.kind, contract.inputs);
}
StubInputContracts SelectStubInputContracts(const std::vector<StubInputIdentity>& identities,
	const StubInputAbis& abis, const std::map<uint64_t, uint64_t>& payloads, bool supportedAbi)
{
	std::map<uint64_t, std::optional<StubInputContract>> groups;
	for (const auto& id : identities) {
		std::optional<StubInputContract> contract;
		const auto abi = abis.find(id.kind);
		if (supportedAbi && abi != abis.end() && ValidStubInputRoles(id.kind, abi->second) && id.matchesReference &&
			id.entry && id.entry % 4 == 0 && id.entry == id.payload && id.end > id.entry && id.end % 4 == 0 &&
			id.end - id.entry <= (1U << 20) && payloads.contains(id.entry) && payloads.at(id.entry) == id.end)
			contract = StubInputContract{id.end, id.kind, abi->second};
		const auto [it, inserted] = groups.emplace(id.entry, contract);
		if (!inserted && it->second != contract) it->second.reset();
	}
	StubInputContracts result;
	for (const auto& [entry, contract] : groups) if (contract) result.emplace(entry, *contract);
	return result;
}
std::optional<StubInputRole> FindStubInputRole(const StubInputContract& contract, unsigned reg)
{
	if (!ValidStubInputRoles(contract.kind, contract.inputs)) throw std::runtime_error("Invalid stub input role contract");
	for (const auto& input : contract.inputs) if (input.reg == reg) return input.role;
	return {};
}
}
