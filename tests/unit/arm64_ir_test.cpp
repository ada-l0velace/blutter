#include "Arm64Ir.h"
#include <array>
#include <iostream>
#include <iterator>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace SnapshotAnalysis;
namespace ir = SnapshotAnalysis::NativeIr;
namespace {
unsigned checks = 0;
void Check(bool condition, std::string_view name) {
	++checks;
	if (!condition) throw std::runtime_error(std::string(name));
}
struct Decoder {
	csh handle = 0;
	Decoder() {
		if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK ||
			cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) throw std::runtime_error("Cannot initialize authored-word decoder");
	}
	~Decoder() { if (handle) cs_close(&handle); }
};
std::shared_ptr<cs_insn> Decode(csh handle, uint32_t word) {
	const uint8_t bytes[] = {static_cast<uint8_t>(word), static_cast<uint8_t>(word >> 8), static_cast<uint8_t>(word >> 16), static_cast<uint8_t>(word >> 24)};
	cs_insn* raw = nullptr;
	const auto count = cs_disasm(handle, bytes, sizeof(bytes), 0x1000, 1, &raw);
	if (count != 1) { cs_free(raw, count); throw std::runtime_error("Authored instruction did not decode"); }
	return std::shared_ptr<cs_insn>(raw, [](cs_insn* p) { cs_free(p, 1); });
}
std::optional<uint64_t> Read(ir::RegisterView reg) {
	switch (reg.id) {
	case 0: return 0x1122334455667788;
	case 1: return 0x12345678ffffffff;
	case 2: return 1;
	case 30: return 0x8877665544332211;
	case 31: return 0x1000; // Native SP is distinct from ZR and the Dart stack GPR.
	default: return {};
	}
}
}
int main() {
	try {
		Decoder decoder;
		struct Case { uint32_t word; uint64_t expected; uint16_t destination; unsigned bits; };
		// Authored encodings with fixed expected values, assembled independently.
		const Case cases[] = {
			{0xd2800000, 0, 0, 64}, {0x92800000, UINT64_MAX, 0, 64}, {0x12800000, 0xffffffff, 0, 32},
			{0xaa0103e0, 0x12345678ffffffff, 0, 64}, {0x2a0103e0, 0xffffffff, 0, 32},
			{0xaa1f03e0, 0, 0, 64}, {0x2a1f03e0, 0, 0, 32},
			{0x910003e0, 0x1000, 0, 64}, {0x9100003f, 0x12345678ffffffff, 31, 64}, {0x110003e0, 0x1000, 0, 32},
			{0xaa1e03fd, 0x8877665544332211, 29, 64}, {0x2a1e03fd, 0x44332211, 29, 32},
			{0xd2c24680, 0x123400000000, 0, 64}, {0x92a24680, 0xffffffffedcbffff, 0, 64},
			{0xf2d579a0, 0x1122abcd55667788, 0, 64}, {0x72a24680, 0x12347788, 0, 32},
			{0xb2089fe0, 0xff00ff00ff00ff00, 0, 64}, {0x91400420, 0x1234567900000fff, 0, 64},
			{0x51000420, 0xfffffffe, 0, 32}, {0x8b020020, 0x1234567900000000, 0, 64}, {0x0b020020, 0, 0, 32},
			{0x910043e0, 0x1010, 0, 64}, {0x910043ff, 0x1010, 31, 64},
			{0xd3485c20, 0xffff, 0, 64}, {0x53043c20, 0xfff, 0, 32},
			{0xf2f579a0, 0xabcd334455667788, 0, 64}, {0x729579a0, 0x5566abcd, 0, 32},
			{0xd2f00000, 0x8000000000000000, 0, 64}, {0x8b0103e0, 0x12345678ffffffff, 0, 64}
		};
		for (const auto& item : cases) {
			const auto decoded = Decode(decoder.handle, item.word);
			const auto lowered = LowerArm64(*decoded);
			Check(lowered && lowered->source.address == 0x1000 && lowered->source.word == item.word, "Lowering lost original word/address");
			const auto effects = ir::GetEffects(*lowered);
			Check(effects.destination && effects.destination->id == item.destination && effects.destination->valueBits == item.bits &&
				effects.destination->storageBits == 64 && effects.destination->extension == (item.bits == 32 ? ir::Extension::Zero : ir::Extension::None), "Incorrect physical write semantics");
			Check(ir::Evaluate(*lowered, Read) == item.expected, "Lowered value differs from authored expectation");
			Check(effects.memory == ir::MemoryEffect::None && effects.flags == ir::FlagsEffect::Preserved &&
				effects.control == ir::ControlEffect::Fallthrough && !effects.unlistedRegistersMayChange, "Pure word operation acquired unknown effects");
		}
		for (const uint32_t word : {0x8b020c20U, 0x8b224c20U, 0xab020020U, 0xeb01001fU, 0xca020020U,
			0xf9400020U, 0xf9000020U, 0x94000004U, 0xd65f03c0U, 0x14000002U, 0x9e670000U,
			0xd340fc20U, 0xcb0103e0U}) {
			const auto decoded = Decode(decoder.handle, word);
			const auto lowered = LowerArm64(*decoded);
			Check(lowered && lowered->source.word == word && lowered->source.address == 0x1000, "Opaque instruction lost its source");
			Check(std::holds_alternative<ir::Opaque>(lowered->operation) && !ir::Evaluate(*lowered, Read), "Unmodeled instruction acquired arithmetic semantics");
			const auto effects = ir::GetEffects(*lowered);
			Check(!effects.destination && effects.unlistedRegistersMayChange && effects.memory == ir::MemoryEffect::Unknown &&
				effects.flags == ir::FlagsEffect::Unknown && effects.control == ir::ControlEffect::Unknown, "Opaque effects became an invented pure/fallthrough fact");
		}
		auto decoded = Decode(decoder.handle, 0xaa0103e0);
		auto malformed = *decoded;
		auto detail = *decoded->detail;
		malformed.detail = nullptr;
		Check(!LowerArm64(malformed), "Missing detail accepted");
		malformed.detail = &detail;
		malformed.size = 2;
		Check(!LowerArm64(malformed), "Non-word instruction accepted");
		malformed.size = 4;
		detail.groups_count = static_cast<uint8_t>(std::size(detail.groups) + 1);
		Check(!LowerArm64(malformed), "Oversized group list accepted");
		detail = *decoded->detail;
		detail.arm64.op_count = static_cast<uint8_t>(std::size(detail.arm64.operands) + 1);
		Check(!LowerArm64(malformed), "Oversized operand list accepted");
		detail = *decoded->detail;
		const auto old = detail.arm64;
		detail.arm64.op_count = 0;
		Check(std::holds_alternative<ir::Opaque>(LowerArm64(malformed)->operation), "Missing operands accepted");
		detail.arm64 = old;
		detail.arm64.operands[1].reg = ARM64_REG_W1;
		Check(std::holds_alternative<ir::Opaque>(LowerArm64(malformed)->operation), "Mismatched register widths accepted");
		detail.arm64 = old;
		detail.arm64.operands[1].shift.type = ARM64_SFT_LSL;
		detail.arm64.operands[1].shift.value = 3;
		Check(std::holds_alternative<ir::Opaque>(LowerArm64(malformed)->operation), "Shifted copy invented");
		detail.arm64 = old;
		detail.arm64.update_flags = true;
		Check(std::holds_alternative<ir::Opaque>(LowerArm64(malformed)->operation), "Unmodeled flags ignored");
		decoded = Decode(decoder.handle, 0xd3485c20);
		decoded->detail->arm64.operands[2].imm = std::numeric_limits<int64_t>::max();
		Check(std::holds_alternative<ir::Opaque>(LowerArm64(*decoded)->operation), "Oversized bit offset accepted");
		std::cout << "ARM64 IR checks passed: " << checks << '\n';
		return 0;
	} catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
