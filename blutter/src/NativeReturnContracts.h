#pragma once
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace SnapshotAnalysis {
// Normalize SDK enum symbols in the VM adapter; ordinal values vary by SDK.
enum class NativeReturnKind { Unknown, OneByteString, TwoByteString };
struct NativeReturnIdentity {
	uint64_t entry = 0, codeEntry = 0, payload = 0, end = 0;
	bool isNative = false, ownsCode = false;
	NativeReturnKind recognized = NativeReturnKind::Unknown;
	std::string nativeName, libraryUri;
};
struct NativeReturnContract {
	uint32_t classId;
	std::string contract;
	bool operator==(const NativeReturnContract&) const = default;
};
inline std::optional<NativeReturnContract> MatchNativeReturn(const NativeReturnIdentity& identity,
	uint32_t oneByteClass, uint32_t twoByteClass)
{
	if (!identity.isNative || !identity.ownsCode || !identity.entry || identity.entry % 4 ||
		identity.entry != identity.codeEntry || identity.entry != identity.payload || identity.end <= identity.entry ||
		identity.end % 4 || identity.libraryUri != "dart:_internal" || !oneByteClass || !twoByteClass || oneByteClass == twoByteClass) return {};
	if (identity.recognized == NativeReturnKind::OneByteString && identity.nativeName == "Internal_allocateOneByteString")
		return NativeReturnContract{oneByteClass, "allocate_one_byte_string"};
	if (identity.recognized == NativeReturnKind::TwoByteString && identity.nativeName == "Internal_allocateTwoByteString")
		return NativeReturnContract{twoByteClass, "allocate_two_byte_string"};
	return {};
}
inline std::map<uint64_t, NativeReturnContract> NativeReturnContracts(const std::vector<NativeReturnIdentity>& identities,
	uint32_t oneByteClass, uint32_t twoByteClass)
{
	std::map<uint64_t, std::optional<NativeReturnContract>> groups;
	for (const auto& identity : identities) {
		auto match = MatchNativeReturn(identity, oneByteClass, twoByteClass);
		const auto [it, inserted] = groups.emplace(identity.entry, match);
		if (!inserted && it->second != match) it->second.reset();
	}
	std::map<uint64_t, NativeReturnContract> result;
	for (const auto& [entry, match] : groups) if (match) result.emplace(entry, *match);
	return result;
}
}
