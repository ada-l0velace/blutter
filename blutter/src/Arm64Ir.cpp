#include "Arm64Ir.h"
#include <algorithm>
#include <iterator>

namespace SnapshotAnalysis {
namespace {
using namespace NativeIr;
unsigned Width(arm64_reg reg) {
	if ((reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) || reg == ARM64_REG_X29 || reg == ARM64_REG_X30 || reg == ARM64_REG_XZR || reg == ARM64_REG_SP) return 64;
	if ((reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) || reg == ARM64_REG_WZR || reg == ARM64_REG_WSP) return 32;
	return 0;
}
std::optional<RegisterView> Register(arm64_reg reg) {
	const auto bits = Width(reg);
	if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) return RegisterView{static_cast<uint16_t>(reg - ARM64_REG_X0), bits};
	if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) return RegisterView{static_cast<uint16_t>(reg - ARM64_REG_W0), bits};
	if (reg == ARM64_REG_X29 || reg == ARM64_REG_X30) return RegisterView{static_cast<uint16_t>(reg == ARM64_REG_X29 ? 29 : 30), bits};
	if (reg == ARM64_REG_SP || reg == ARM64_REG_WSP) return RegisterView{31, bits};
	return {};
}
bool Plain(const cs_arm64_op& operand) {
	return operand.ext == ARM64_EXT_INVALID &&
		(operand.shift.type == ARM64_SFT_INVALID || (operand.shift.type == ARM64_SFT_LSL && operand.shift.value == 0));
}
std::optional<Operand> Value(const cs_arm64_op& operand, unsigned bits, bool shiftedImmediate) {
	if (operand.ext != ARM64_EXT_INVALID) return {};
	if (operand.type == ARM64_OP_IMM) {
		if (!shiftedImmediate || (operand.imm >= 0 &&
			(operand.shift.type == ARM64_SFT_INVALID || (operand.shift.type == ARM64_SFT_LSL && operand.shift.value == 12))))
			return Literal{static_cast<uint64_t>(operand.imm) << (shiftedImmediate && operand.shift.type != ARM64_SFT_INVALID ? 12 : 0)};
	} else if (operand.type == ARM64_OP_REG && Width(operand.reg) == bits && Plain(operand)) {
		if (operand.reg == ARM64_REG_XZR || operand.reg == ARM64_REG_WZR) return Literal{0};
		if (const auto reg = Register(operand.reg)) return *reg;
	}
	return {};
}
}
std::optional<NativeIr::Instruction> LowerArm64(const cs_insn& instruction) {
	using namespace NativeIr;
	if (!instruction.detail || instruction.size != 4) return {};
	const auto& d = instruction.detail->arm64;
	if (instruction.detail->groups_count > std::size(instruction.detail->groups) || d.op_count > std::size(d.operands)) return {};
	const auto* bytes = instruction.bytes;
	Instruction result{{instruction.address, uint32_t{bytes[0]} | uint32_t{bytes[1]} << 8 | uint32_t{bytes[2]} << 16 | uint32_t{bytes[3]} << 24}};
	const auto transfer = [&](uint8_t group) { return std::find(instruction.detail->groups, instruction.detail->groups + instruction.detail->groups_count, group) != instruction.detail->groups + instruction.detail->groups_count; };
	if (d.update_flags || transfer(CS_GRP_CALL) || transfer(CS_GRP_JUMP) || transfer(CS_GRP_RET) || transfer(CS_GRP_INT) ||
		d.op_count < 2 || d.operands[0].type != ARM64_OP_REG) return result;
	const auto destination = Register(d.operands[0].reg);
	if (!destination) return result; // Includes discarded ZR destinations and non-word registers.
	const auto bits = destination->bits;
	const RegisterWrite target{destination->id, bits, 64, bits == 32 ? Extension::Zero : Extension::None};
	const auto& source = d.operands[1];
	if (instruction.id == ARM64_INS_MOV && d.op_count == 2) {
		if (const auto value = Value(source, bits, false)) result.operation = Assign{target, *value};
	} else if ((instruction.id == ARM64_INS_MOVZ || instruction.id == ARM64_INS_MOVN || instruction.id == ARM64_INS_MOVK) &&
		d.op_count == 2 && source.type == ARM64_OP_IMM && source.imm >= 0 && source.imm <= 65535 && source.ext == ARM64_EXT_INVALID &&
		(source.shift.type == ARM64_SFT_INVALID || source.shift.type == ARM64_SFT_LSL)) {
		const auto shift = source.shift.type == ARM64_SFT_INVALID ? 0 : source.shift.value;
		if (shift < bits && shift % 16 == 0) {
			const uint64_t value = static_cast<uint64_t>(source.imm) << shift;
			if (instruction.id == ARM64_INS_MOVK) result.operation = InsertBits{target, *destination, value, uint64_t{65535} << shift};
			else result.operation = Assign{target, Literal{instruction.id == ARM64_INS_MOVN ? ~value : value}};
		}
	} else if ((instruction.id == ARM64_INS_ADD || instruction.id == ARM64_INS_SUB) && d.op_count == 3 && source.type == ARM64_OP_REG && Width(source.reg) == bits) {
		const auto left = Value(source, bits, false), right = Value(d.operands[2], bits, true);
		if (left && right) result.operation = Binary{target, instruction.id == ARM64_INS_ADD ? BinaryKind::Add : BinaryKind::Subtract, *left, *right};
	} else if (instruction.id == ARM64_INS_UBFX && d.op_count == 4 && source.type == ARM64_OP_REG && Width(source.reg) == bits &&
		d.operands[2].type == ARM64_OP_IMM && d.operands[3].type == ARM64_OP_IMM) {
		const auto lsb = d.operands[2].imm, size = d.operands[3].imm;
		if (const auto value = Value(source, bits, false); value && lsb >= 0 && lsb < bits && size > 0 && size < 64 && size <= bits - lsb)
			result.operation = ExtractUnsigned{target, *value, static_cast<unsigned>(lsb), static_cast<unsigned>(size)};
	}
	return result;
}
}
