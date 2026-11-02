#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include "DartThreadInfo.h"
#include "RuntimeLayout.h"

static intptr_t ExpectedThreadOffset(intptr_t offset)
{
	// Keep the supported mappings independent of the production layout table.
#if defined(BLUTTER_SHOREBIRD_3C9C)
	if (offset >= 0x290 && offset <= 0x700) return offset + 0x10;
	if (offset >= 0x708 && offset <= 0x8a0) return offset + 0x20;
	if (offset >= 0x8e0 && offset <= 0x908) return offset + 0x80;
#elif defined(BLUTTER_SHOREBIRD_8399)
	if (offset >= 0x290 && offset <= 0x6f0) return offset + 0x10;
	if (offset >= 0x6f8 && offset <= 0x890) return offset + 0x20;
	if (offset >= 0x8d0 && offset <= 0x8f8) return offset + 0x80;
#elif defined(BLUTTER_SHOREBIRD_7D8F)
	if (offset >= 0x290 && offset <= 0x6e8) return offset + 0x10;
	if (offset >= 0x6f0 && offset <= 0x898) return offset + 0x20;
	if (offset >= 0x8d8 && offset <= 0x900) return offset + 0x80;
#endif
	return offset;
}

static void Check(intptr_t source, intptr_t target)
{
	if (TargetThreadOffset(source) != target)
		throw std::runtime_error("Incorrect target Thread offset");
	if (TargetRuntime::ThreadOffset(source) != target)
		throw std::runtime_error("Incorrect runtime layout offset");
}

static void CheckLayoutContract()
{
	using TargetRuntime::Layout;
	using TargetRuntime::ThreadOffsetRange;
	using TargetRuntime::ValidLayout;
	constexpr auto maximum = std::numeric_limits<std::intptr_t>::max();
	constexpr auto minimum = std::numeric_limits<std::intptr_t>::min();
	constexpr std::array<ThreadOffsetRange, 1> negativeStart = {{{-1, 8, 0}}};
	constexpr std::array<ThreadOffsetRange, 1> reversedRange = {{{16, 8, 0}}};
	constexpr std::array<ThreadOffsetRange, 1> overflow = {{{maximum - 8, maximum, 1}}};
	constexpr std::array<ThreadOffsetRange, 1> underflow = {{{0, 8, minimum}}};
	constexpr std::array<ThreadOffsetRange, 2> overlappingSources = {{{0, 8, 0}, {8, 16, 8}}};
	constexpr std::array<ThreadOffsetRange, 2> overlappingTargets = {{{0, 8, 8}, {16, 24, -8}}};
	constexpr std::array<ThreadOffsetRange, 2> unorderedSources = {{{16, 24, 0}, {0, 8, 0}}};
	constexpr std::array<ThreadOffsetRange, 1> validNegativeAdjustment = {{{8, 16, -8}}};
	constexpr std::array<ThreadOffsetRange, 1> validMaximum = {{{maximum, maximum, 0}}};
	for (const auto& ranges : {std::span<const ThreadOffsetRange>(negativeStart),
		std::span<const ThreadOffsetRange>(reversedRange), std::span<const ThreadOffsetRange>(overflow),
		std::span<const ThreadOffsetRange>(underflow), std::span<const ThreadOffsetRange>(overlappingSources),
		std::span<const ThreadOffsetRange>(overlappingTargets), std::span<const ThreadOffsetRange>(unorderedSources)}) {
		if (ValidLayout(Layout{ranges, std::nullopt})) {
			throw std::runtime_error("Invalid layout ranges accepted");
		}
	}
	if (!ValidLayout(Layout{validNegativeAdjustment, std::nullopt}) ||
		!ValidLayout(Layout{validMaximum, std::nullopt})) {
		throw std::runtime_error("Valid layout range rejected");
	}
	for (const auto offset : {minimum, std::intptr_t(-8), std::intptr_t(0), std::intptr_t(7)}) {
		if (ValidLayout(Layout{{}, offset})) {
			throw std::runtime_error("Invalid native-call state offset accepted");
		}
	}
#if defined(BLUTTER_SHOREBIRD_3C9C)
	constexpr std::optional<intptr_t> expectedStateOffset = 0x8f0;
#elif defined(BLUTTER_SHOREBIRD_8399)
	constexpr std::optional<intptr_t> expectedStateOffset = 0x8e0;
#elif defined(BLUTTER_SHOREBIRD_7D8F)
	constexpr std::optional<intptr_t> expectedStateOffset = 0x8e8;
#else
	constexpr std::optional<intptr_t> expectedStateOffset = std::nullopt;
#endif
	static_assert(TargetRuntime::layout.nativeCallStateOffset == expectedStateOffset);
	static_assert(TargetRuntime::hasNativeCallGuard == expectedStateOffset.has_value());
	static_assert(TargetNativeCallStateOffset() == expectedStateOffset.value_or(0));
	if (TargetRuntime::layout.nativeCallStateOffset != expectedStateOffset) {
		throw std::runtime_error("Incorrect runtime guard settings");
	}
	for (intptr_t offset = -64; offset <= 0x1100; ++offset) {
		Check(offset, ExpectedThreadOffset(offset));
	}
	Check(minimum, minimum);
	Check(maximum, maximum);
}

int main()
{
	try {
		CheckLayoutContract();
		Check(0x48, 0x48); // stack_limit
		Check(0x278, 0x278); // jump_to_frame_entry_point
		Check(0x280, 0x280); // slow_type_test_entry_point
		Check(0x288, 0x288); // resume_interpreter_adjusted_entry_point
#if defined(BLUTTER_SHOREBIRD_8399)
		Check(0x290, 0x2a0); // bootstrap_native_wrapper_entry_point
		Check(0x688, 0x698); // isolate_group
		Check(0x690, 0x6a0); // saved_stack_limit
		Check(0x6c8, 0x6d8); // vm_tag
		Check(0x6f0, 0x700); // saved_shadow_call_stack
		Check(0x6f8, 0x718); // execution_state
		Check(0x700, 0x720); // safepoint_state
		Check(0x740, 0x760); // LibcPow
		Check(0x888, 0x8a8); // MemoryMove
		Check(0x890, 0x8b0); // api_top_scope
		Check(0x8e8, 0x968); // dart_stream
		Check(0x8f8, 0x978); // thread_locals
		if (TargetNativeCallStateOffset() != 0x8e0) return 1;
#elif defined(BLUTTER_SHOREBIRD_3C9C)
		Check(0x290, 0x2a0);
		Check(0x6d8, 0x6e8); // vm_tag
		Check(0x700, 0x710);
		Check(0x708, 0x728); // execution_state
		Check(0x898, 0x8b8); // MemoryMove
		Check(0x8f8, 0x978); // dart_stream
		Check(0x908, 0x988);
		if (TargetNativeCallStateOffset() != 0x8f0) return 1;
#elif defined(BLUTTER_SHOREBIRD_7D8F)
		Check(0x290, 0x2a0); // bootstrap_native_wrapper_entry_point
		Check(0x680, 0x690); // isolate_group
		Check(0x6c0, 0x6d0); // vm_tag
		Check(0x6e8, 0x6f8); // saved_shadow_call_stack
		Check(0x6f0, 0x710); // execution_state
		Check(0x6f8, 0x718); // safepoint_state
		Check(0x890, 0x8b0); // MemoryMove
		Check(0x898, 0x8b8); // api_top_scope
		Check(0x8f0, 0x970); // dart_stream
		Check(0x900, 0x980); // thread_locals
		if (TargetNativeCallStateOffset() != 0x8e8) return 1;
#else
		for (intptr_t offset = 0; offset < 0x1000; offset += 8)
			Check(offset, offset);
		if (TargetNativeCallStateOffset() != 0) return 1;
#endif
		Check(0x1000, 0x1000);
	}
	catch (const std::exception& error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
	std::cout << "Target Thread layout checks passed\n";
	return 0;
}
