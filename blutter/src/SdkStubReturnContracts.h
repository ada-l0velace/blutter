#pragma once
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace SnapshotAnalysis {
enum class SdkStubReturnKind { Unknown, GrowableArray };
struct SdkStubReturnIdentity {
	uint64_t entry, payload, end;
	SdkStubReturnKind kind;
	bool matchesReference = false;
};
struct SdkStubReturnContract {
	uint32_t classId;
	SdkStubReturnKind kind;
	bool operator==(const SdkStubReturnContract&) const = default;
};
// Identity comes from a matched SDK stub accessor; bounds come from the
// original instructions table. A result contract grants no memory effects.
inline std::map<uint64_t, SdkStubReturnContract> SdkStubReturnContracts(
	const std::vector<SdkStubReturnIdentity>& identities, uint32_t growableClass,
	const std::map<uint64_t, uint64_t>& payloads, bool returnsX0)
{
	std::map<uint64_t, std::optional<SdkStubReturnContract>> groups;
	for (const auto& id : identities) {
		std::optional<SdkStubReturnContract> match;
		if (returnsX0 && growableClass && id.matchesReference && id.kind == SdkStubReturnKind::GrowableArray &&
			id.entry && id.entry % 4 == 0 && id.entry == id.payload && id.end > id.entry && id.end % 4 == 0 &&
			payloads.contains(id.payload) && payloads.at(id.payload) == id.end)
			match = SdkStubReturnContract{growableClass, id.kind};
		const auto [it, inserted] = groups.emplace(id.entry, match);
		if (!inserted && it->second != match) it->second.reset();
	}
	std::map<uint64_t, SdkStubReturnContract> result;
	for (const auto& [entry, contract] : groups) if (contract) result.emplace(entry, *contract);
	return result;
}
}
