#pragma once
#include "RuntimeLayout.h"

// Target-code offsets, not the offline reader's native Thread layout.
inline intptr_t TargetThreadOffset(intptr_t offset)
{
	return TargetRuntime::ThreadOffset(offset);
}

inline constexpr intptr_t TargetNativeCallStateOffset()
{
	return TargetRuntime::layout.nativeCallStateOffset.value_or(0);
}

const std::string& GetThreadOffsetName(intptr_t offset);
intptr_t GetThreadMaxOffset();

// use for dumping all thread offsets
const std::unordered_map<intptr_t, std::string>& GetThreadOffsetsMap();

struct LeafFunctionInfo {
	std::string returnType;
	std::string params;
};
const LeafFunctionInfo* GetThreadLeafFunction(intptr_t offset);
