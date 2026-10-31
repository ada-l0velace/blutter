#include "StackCheckAnalysis.h"
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
using namespace SnapshotAnalysis;
namespace {
unsigned checks = 0;
void Check(bool value, const char* message) {
	++checks; if (!value) throw std::runtime_error(message);
}
struct Decoder {
	csh handle = 0;
	Decoder() {
		if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK ||
			cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) throw std::runtime_error("Decoder unavailable");
	}
	~Decoder() { if (handle) cs_close(&handle); }
};
std::optional<InitialStackCheck> Find(csh handle, const std::vector<uint32_t>& words, const Profile& profile) {
	std::vector<uint8_t> bytes;
	for (auto word : words) for (unsigned shift = 0; shift < 32; shift += 8) bytes.push_back(static_cast<uint8_t>(word >> shift));
	cs_insn* raw = nullptr;
	const auto count = cs_disasm(handle, bytes.data(), bytes.size(), 0x1000, 0, &raw);
	const std::shared_ptr<cs_insn> owner(raw, [count](cs_insn* p) { cs_free(p, count); });
	return count*4 == bytes.size() ? FindInitialStackCheck(raw, count, profile) : std::nullopt;
}
}
int main() {
	try {
		Decoder decoder;
		Profile profile{"synthetic", ARM64_REG_X27, ARM64_REG_X26, 16, 8, 0, {}, {}};
		profile.stackLimitOffset = 0x60;
		profile.framePreservingCalls[0x3000] = "stack_overflow_without_fpu";
		// LDR X16,[X26,#0x60]; CMP X15,X16; B.LS slow; BL helper;
		// RET; NOP; slow: BL runtime; B fast.
		const std::vector<uint32_t> plain{0xf9403350, 0xeb1001ff, 0x54000089, 0x940003fd,
			0xd65f03c0, 0xd503201f, 0x940007fa, 0x17fffffc};
		const auto value = Find(decoder.handle, plain, profile);
		Check(value && value->site == 0x1008 && value->successor == 0x100c && value->slowPath == 0x1018 && value->stub == 0x3000, "Initial guard not recognized");
		Check(value->proof == std::vector<uint64_t>{0x1000,0x1004,0x1008,0x1018,0x101c}, "Guard proof incomplete");
		for (const auto& [index, word] : std::vector<std::pair<size_t,uint32_t>>{
			{0,0xb9406350}, // Four-byte load.
			{0,0xf9403750}, // Different offset.
			{0,0xf9403330}, // Different base.
			{1,0xeb1001df}, // CMP X14,X16.
			{1,0xeb1005ff}, // Shifted limit.
			{2,0x54000088}, // B.HI.
			{2,0x54000049}, // Wrong slow block.
			{3,0x17fffffd}, // Revisit prefix.
			{3,0x14000003}, // Extra slow entry.
			{3,0x14000004}, // Extra slow-return entry.
			{3,0x14000000}, // Alternate fast entry.
			{4,0xd503201f}, // Slow block fallthrough.
			{6,0x940007fb}, // Different runtime.
			{7,0x17fffff9}, // Wrong slow return.
			{7,0x5400000e}, // Conditional alias is not unconditional B.
			{3,0xd61f0020}, // Unknown indirect jump.
		}) {
			auto changed = plain; changed[index] = word;
			Check(!Find(decoder.handle, changed, profile), "Unsafe guard shape accepted");
		}
		auto indirect = plain; indirect[3] = 0xd63f03c0;
		Check(Find(decoder.handle, indirect, profile).has_value(), "Indirect fast-path call unnecessarily rejected");
		auto missing = profile; missing.stackLimitOffset.reset();
		Check(!Find(decoder.handle, plain, missing), "Absent SDK offset accepted");
		missing = profile; missing.framePreservingCalls.clear();
		Check(!Find(decoder.handle, plain, missing), "Unaudited runtime accepted");
		missing = profile; missing.framePreservingCalls[0x3000] = "array_write_barrier";
		Check(!Find(decoder.handle, plain, missing), "Wrong helper contract accepted");
		for (auto offset : {-8, 3, 32768}) {
			missing = profile; missing.stackLimitOffset = offset;
			Check(!Find(decoder.handle, plain, missing), "Invalid SDK offset accepted");
		}
		Check(!FindInitialStackCheck(nullptr, 8, profile), "Null instructions accepted");
		std::cout << checks << " stack-check checks passed\n";
	} catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
