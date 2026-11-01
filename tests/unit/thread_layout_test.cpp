#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include "DartThreadInfo.h"

static void Check(intptr_t source, intptr_t target)
{
	if (TargetThreadOffset(source) != target)
		throw std::runtime_error("Incorrect target Thread offset");
}

int main()
{
	try {
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
