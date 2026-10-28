#pragma once
#include <cstdint>
#include <cstring>

// Compressed-pointer objects can place an eight-byte value at a four-byte
// boundary. Copy its representation without creating a misaligned typed lvalue.
inline uint64_t ReadUnaligned64(const void* source) noexcept
{
	uint64_t value;
	std::memcpy(&value, source, sizeof(value));
	return value;
}
