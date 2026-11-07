#include "NativePayloadRouting.h"
#include <array>
#include <iostream>

namespace {
unsigned checks = 0;
void Check(bool value) { ++checks; if (!value) throw std::runtime_error("Native payload routing check failed"); }
}

int main()
{
	try {
		// Authored ranges and metadata; no runtime or application fixture is used.
		Check(NativeFunctionMatchesPayload(0x1000, 0x1020, 0x1000, 0x20, 0x1008));
		Check(NativeFunctionMatchesPayload(0x1000, 0x1020, 0x1000, 0x1c, 0x1018));
		Check(!NativeFunctionMatchesPayload(0x1000, 0x1020, 0x1000, 4, 0x1008)); // Negative body size.
		Check(!NativeFunctionMatchesPayload(0x1000, 0x1020, 0x1000, 0x1e, 0x1008));
		Check(!NativeFunctionMatchesPayload(0x1000, 0x1020, 0xffc, 0x20, 0x1008));
		Check(!NativeFunctionMatchesPayload(0x1000, 0x1020, 0x1000, 0x24, 0x1008));
		Check(!NativeFunctionMatchesPayload(0x1000, 0x1020, 0x1000, 0x20, 0xffc));
		Check(!NativeFunctionMatchesPayload(0x1000, 0x1020, 0x1000, 0x20, 0x1020));
		const std::array<std::pair<uint64_t, uint64_t>, 5> ranges{{
			{0x1000, 0x1020}, {0x1020, 0x1040}, {0x1040, 0x1060}, {0x1060, 0x1080}, {0x1080, 0x10a0}}};
		std::vector<NativePayloadClaim> names{{0x1008, 0}, {0x1008, 0}, {0x1010, 0},
			{0x1020, 1}, {0x1028, 2}, {0x1048, std::nullopt}, {0x1050, 3},
			{0x1080, 4}, {0x2000, 5}, {0, std::nullopt}};
		const auto result = NativePayloadDestinations(ranges, names);
		Check(result.size() == ranges.size());
		Check(result[0] == 0); // Interior entries keep the entire prefix and suffix.
		Check(!result[1]); // Different libraries sharing bytes have no unique owner.
		Check(!result[2]); // A runtime stub is not assigned a source library.
		Check(!result[3]); // Unnamed native code remains in the fallback output.
		Check(result[4] == 4); // The boundary belongs to the next payload.
		std::reverse(names.begin(), names.end());
		Check(NativePayloadDestinations(ranges, names) == result);
		Check(NativePayloadDestinations(ranges, {}) == std::vector<std::optional<size_t>>(5));
		Check(NativePayloadDestinations({}, names).empty());
		const std::array<std::pair<uint64_t, uint64_t>, 2> gap{{{0x1000, 0x1010}, {0x1020, 0x1030}}};
		Check(NativePayloadDestinations(gap, std::array<NativePayloadClaim, 1>{{{0x1010, 7}}}) ==
			std::vector<std::optional<size_t>>(2));
		for (const auto invalid : std::vector<std::vector<std::pair<uint64_t, uint64_t>>>{
			{{0x1000, 0x1000}}, {{0x1004, 0x1000}}, {{0x1001, 0x1010}}, {{0x1000, 0x1011}},
			{{0x1000, 0x1020}, {0x1010, 0x1030}}, {{0x1020, 0x1030}, {0x1000, 0x1010}}}) {
			bool refused = false;
			try { (void)NativePayloadDestinations(invalid, {}); }
			catch (const std::invalid_argument&) { refused = true; }
			Check(refused);
		}
		bool refused = false;
		try { (void)NativePayloadDestinations(ranges, std::array<NativePayloadClaim, 1>{{{0x1001, 0}}}); }
		catch (const std::invalid_argument&) { refused = true; }
		Check(refused);
		std::cout << checks << " native payload routing checks passed\n";
	}
	catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
