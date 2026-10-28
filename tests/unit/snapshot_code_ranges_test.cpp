#include "SnapshotCodeRanges.h"
#include <array>
#include <iostream>
#include <limits>

static unsigned checks = 0;
static void Check(bool condition)
{
	++checks;
	if (!condition) throw std::runtime_error("Snapshot code range check failed");
}

int main()
{
	try {
		const std::array<uint64_t, 3> entries{0x1080, 0x1090, 0x10a0};
		const auto ranges = SnapshotCodeRanges(0x1000, 0x1080, 0x10c0, entries);
		Check(ranges == std::vector<std::pair<uint64_t, uint64_t>>{{0x1080, 0x1090}, {0x1090, 0x10a0}, {0x10a0, 0x10c0}});
		uint64_t bytes = 0;
		for (const auto& [start, end] : ranges) bytes += end - start;
		Check(bytes == 0x40); // Every payload byte once, including the last entry.
		Check(SnapshotCodeRanges(0x1000, 0x1080, 0x1084, std::array<uint64_t, 1>{0x1080}).size() == 1);
		Check(SnapshotCodeRanges(0x1000, 0x1070, 0x1084, std::array<uint64_t, 1>{0x1070})[0].first == 0x1070);
		auto reject = [](uint64_t image, uint64_t start, uint64_t end, std::span<const uint64_t> values) {
			try { (void)SnapshotCodeRanges(image, start, end, values); }
			catch (const std::invalid_argument&) { Check(true); return; }
			Check(false);
		};
		reject(0x1000, 0x1080, 0x10c0, {});
		reject(0x1000, 0x1080, 0x10c0, std::array<uint64_t, 1>{0x1084});
		reject(0x1000, 0x1080, 0x10c0, std::array<uint64_t, 2>{0x1080, 0x1080});
		reject(0x1000, 0x1080, 0x10c0, std::array<uint64_t, 3>{0x1080, 0x10a0, 0x1090});
		reject(0x1000, 0x1080, 0x10c0, std::array<uint64_t, 2>{0x1080, 0x1092});
		reject(0x1000, 0x1080, 0x10c0, std::array<uint64_t, 2>{0x1080, 0x10c0});
		reject(0x1000, 0x1080, 0x10c0, std::array<uint64_t, 2>{0x1080, 0x10c4});
		reject(0x1080, 0x1080, 0x10c0, entries);
		reject(0x1084, 0x1080, 0x10c0, entries);
		reject(0x1000, 0x1080, 0x1080, entries);
		reject(0x1000, 0x1082, 0x10c0, entries);
		reject(0x1000, 0x1080, 0x10c2, entries);
		reject(0x1000, 0x1080, 0x1084, entries);
		reject(0x1000, 0x1080, 0, entries);
		const auto last = std::numeric_limits<uint64_t>::max() & ~uint64_t{3};
		Check(SnapshotCodeRanges(last - 12, last - 8, last, std::array<uint64_t, 1>{last - 8})[0].second == last);
		std::cout << "Snapshot code range checks passed: " << checks << '\n';
		return 0;
	}
	catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
