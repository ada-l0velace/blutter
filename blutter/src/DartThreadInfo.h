#pragma once

// Offsets in the app's generated code, separate from the offline reader's
// native Thread layout. Only this fingerprint's recovered ranges are mapped.
inline intptr_t TargetThreadOffset(intptr_t offset)
{
#if defined(BLUTTER_SHOREBIRD_3C9C)
	if (offset >= 0x290 && offset <= 0x700) return offset + 0x10;
	if (offset >= 0x708 && offset <= 0x8a0) return offset + 0x20;
	if (offset >= 0x8e0 && offset <= 0x908) return offset + 0x80;
#endif
	return offset;
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
