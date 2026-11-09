#pragma once
#include <cstdint>
#include <map>
#include <optional>
#include <string_view>
#include <vector>

namespace SnapshotAnalysis {
enum class StubInputKind { Unknown, Array, Closure, Closure1, Closure2, Closure3, Closure4 };
enum class StubInputRole { Unknown, ArrayLength, ArrayTypeArguments, ClosureFunction, ClosureContext, ClosureLengthFlags };
struct StubRegisterRole {
	unsigned reg;
	StubInputRole role;
	bool operator==(const StubRegisterRole&) const = default;
};
using StubInputAbis = std::map<StubInputKind, std::vector<StubRegisterRole>>;
struct StubInputIdentity {
	uint64_t entry, payload, end;
	StubInputKind kind;
	bool matchesReference = false;
};
struct StubInputContract {
	uint64_t end;
	StubInputKind kind;
	std::vector<StubRegisterRole> inputs;
	bool operator==(const StubInputContract&) const = default;
};
using StubInputContracts = std::map<uint64_t, StubInputContract>;
const char* StubInputKindName(StubInputKind kind);
const char* StubInputRoleName(StubInputRole role);
const char* StubInputRoleText(StubInputRole role);
bool ValidStubInputRoles(StubInputKind kind, const std::vector<StubRegisterRole>& inputs);
bool ValidStubInputContract(uint64_t entry, const StubInputContract& contract);
// Complete equality to a matched SDK reference and original payload bounds are
// supplied by the adapter. These contracts grant no return or memory effects.
StubInputContracts SelectStubInputContracts(const std::vector<StubInputIdentity>& identities,
	const StubInputAbis& abis, const std::map<uint64_t, uint64_t>& payloads, bool supportedAbi);
std::optional<StubInputRole> FindStubInputRole(const StubInputContract& contract, unsigned reg);
}
