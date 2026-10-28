#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

// Canonical native payloads, not inferred source-language functions. Metadata
// entries may alias addresses inside these ranges without creating more bytes.
inline std::vector<std::pair<uint64_t, uint64_t>> SnapshotCodeRanges(
	uint64_t imageStart, uint64_t codeStart, uint64_t imageEnd, std::span<const uint64_t> entries)
{
	if (imageStart >= codeStart || codeStart >= imageEnd || codeStart % 4 || imageEnd % 4 ||
		entries.empty() || entries.front() != codeStart || entries.size() > (imageEnd - codeStart) / 4)
		throw std::invalid_argument("Invalid snapshot code inventory extent");
	std::vector<std::pair<uint64_t, uint64_t>> ranges;
	ranges.reserve(entries.size());
	for (std::size_t i = 0; i < entries.size(); ++i) {
		const auto start = entries[i];
		const auto end = i + 1 < entries.size() ? entries[i + 1] : imageEnd;
		if (start < codeStart || start >= end || end > imageEnd || start % 4 || end % 4)
			throw std::invalid_argument("Invalid snapshot code inventory boundary");
		ranges.emplace_back(start, end);
	}
	return ranges;
}
