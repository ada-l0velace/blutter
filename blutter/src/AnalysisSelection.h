#pragma once
#include <charconv>
#include <cstdint>
#include <stdexcept>
#include <string_view>

namespace SnapshotAnalysis {
// A selection identifies an original payload, not a runtime/ASLR address.
inline uint64_t ParseAnalysisCaller(std::string_view text)
{
	int base = 10;
	if (text.starts_with("0x") || text.starts_with("0X")) { text.remove_prefix(2); base = 16; }
	if (text.empty()) throw std::invalid_argument("Analysis caller must be a positive, aligned ELF virtual address");
	uint64_t value = 0;
	const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value, base);
	if (error != std::errc{} || end != text.data() + text.size() || !value || value % 4)
		throw std::invalid_argument("Analysis caller must be a positive, aligned ELF virtual address");
	return value;
}
}
