#pragma once
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

// Names describe entries inside a native payload, not new payload boundaries.
// A missing library identifies runtime code; conflicting owners stay native.
struct NativePayloadClaim {
	uint64_t entry;
	std::optional<size_t> library;
};

inline bool NativeFunctionMatchesPayload(uint64_t start, uint64_t end,
	uint64_t payload, uint64_t payloadSize, uint64_t entry)
{
	return start < end && start % 4 == 0 && end % 4 == 0 &&
		payload == start && payloadSize % 4 == 0 && payloadSize <= end - start &&
		entry >= start && entry < end && entry % 4 == 0 && entry - start <= payloadSize;
}

inline std::vector<std::optional<size_t>> NativePayloadDestinations(
	std::span<const std::pair<uint64_t, uint64_t>> ranges,
	std::span<const NativePayloadClaim> claims)
{
	std::vector<std::optional<size_t>> owners(ranges.size());
	std::vector<bool> seen(ranges.size()), shared(ranges.size());
	for (size_t i = 0; i < ranges.size(); ++i) {
		const auto [start, end] = ranges[i];
		if (start >= end || start % 4 || end % 4 || (i && ranges[i - 1].second > start))
			throw std::invalid_argument("Invalid native payload ranges");
	}
	for (const auto& claim : claims) {
		if (claim.entry % 4) throw std::invalid_argument("Unaligned native metadata entry");
		const auto next = std::upper_bound(ranges.begin(), ranges.end(), claim.entry,
			[](uint64_t entry, const auto& range) { return entry < range.first; });
		if (next == ranges.begin()) continue; // A separate VM image may have metadata too.
		const size_t i = std::prev(next) - ranges.begin();
		if (claim.entry >= ranges[i].second) continue;
		if (!claim.library || (seen[i] && owners[i] != claim.library)) shared[i] = true;
		if (!seen[i]) owners[i] = claim.library;
		seen[i] = true;
	}
	for (size_t i = 0; i < owners.size(); ++i) if (shared[i]) owners[i].reset();
	return owners;
}
