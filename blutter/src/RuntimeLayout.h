#pragma once
#include <array>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>

namespace TargetRuntime {

struct ThreadOffsetRange {
	std::intptr_t first;
	std::intptr_t last;
	std::intptr_t adjustment;
};

struct Layout {
	std::span<const ThreadOffsetRange> threadOffsets;
	std::optional<std::intptr_t> nativeCallStateOffset;
};

constexpr bool ValidLayout(const Layout& candidate)
{
	if (candidate.nativeCallStateOffset &&
		(*candidate.nativeCallStateOffset <= 0 || *candidate.nativeCallStateOffset % 8 != 0)) {
		return false;
	}
	for (std::size_t index = 0; index < candidate.threadOffsets.size(); ++index) {
		const auto& range = candidate.threadOffsets[index];
		if (range.first < 0 || range.last < range.first || range.adjustment < -range.first) {
			return false;
		}
		if (range.adjustment > 0 && range.last > std::numeric_limits<std::intptr_t>::max() - range.adjustment) {
			return false;
		}
		if (index != 0) {
			const auto& previous = candidate.threadOffsets[index - 1];
			if (range.first <= previous.last ||
				range.first + range.adjustment <= previous.last + previous.adjustment) {
				return false;
			}
		}
	}
	return true;
}

// The selected SDK exports these flags; callers use the layout, not its identity.
#if (defined(BLUTTER_SHOREBIRD_3C9C) + defined(BLUTTER_SHOREBIRD_8399) + defined(BLUTTER_SHOREBIRD_7D8F)) > 1
#error "Select only one runtime layout"
#elif defined(BLUTTER_SHOREBIRD_3C9C)
inline constexpr std::array<ThreadOffsetRange, 3> threadOffsets = {{
	{0x290, 0x700, 0x10},
	{0x708, 0x8a0, 0x20},
	{0x8e0, 0x908, 0x80},
}};
inline constexpr Layout layout{threadOffsets, 0x8f0};
#elif defined(BLUTTER_SHOREBIRD_8399)
inline constexpr std::array<ThreadOffsetRange, 3> threadOffsets = {{
	{0x290, 0x6f0, 0x10},
	{0x6f8, 0x890, 0x20},
	{0x8d0, 0x8f8, 0x80},
}};
inline constexpr Layout layout{threadOffsets, 0x8e0};
#elif defined(BLUTTER_SHOREBIRD_7D8F)
inline constexpr std::array<ThreadOffsetRange, 3> threadOffsets = {{
	{0x290, 0x6e8, 0x10},
	{0x6f0, 0x898, 0x20},
	{0x8d8, 0x900, 0x80},
}};
inline constexpr Layout layout{threadOffsets, 0x8e8};
#else
inline constexpr std::array<ThreadOffsetRange, 0> threadOffsets{};
inline constexpr Layout layout{threadOffsets, std::nullopt};
#endif

static_assert(ValidLayout(layout), "Invalid target runtime layout");
inline constexpr bool hasNativeCallGuard = layout.nativeCallStateOffset.has_value();

constexpr std::intptr_t ThreadOffset(std::intptr_t source)
{
	for (const auto& range : layout.threadOffsets) {
		if (source >= range.first && source <= range.last) {
			return source + range.adjustment;
		}
	}
	return source;
}

}
