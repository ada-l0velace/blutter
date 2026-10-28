#include "ReadUnaligned.h"
#include "DartNames.h"
#include <array>
#include <bit>
#include <iostream>
#include <limits>

int main()
{
	alignas(uint64_t) std::array<unsigned char, 16> storage{};
	unsigned checks = 0;
	for (const uint64_t value : {uint64_t{0}, uint64_t{1}, uint64_t{0x1020304050607080},
		std::numeric_limits<uint64_t>::max(), std::bit_cast<uint64_t>(-1.25)}) {
		for (size_t offset = 0; offset < 8; ++offset) {
			std::memcpy(storage.data() + offset, &value, sizeof(value));
			if (ReadUnaligned64(storage.data() + offset) != value) return 1;
			++checks;
		}
	}
	for (const auto& [url, expected] : std::array<std::pair<std::string_view, std::string_view>, 8>{{
		{"", ""}, {"x", "x"}, {"abc", "abc"}, {"dart", "dart"},
		{"dart:", "dart_"}, {"dart:core", "dart_core"},
		{"package:authored/unit.dart", "authored$unit"}, {"file:///tmp/unit.dart", "tmp$unit"}}}) {
		if (LibraryDisplayName(url) != expected) return 1;
		++checks;
	}
	std::cout << "Unaligned field checks passed: " << checks << '\n';
	return 0;
}
