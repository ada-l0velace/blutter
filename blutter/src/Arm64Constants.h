#pragma once
#include "Arm64Patterns.h"

namespace arm64_patterns {

struct ConstantSuffix {
	size_t startIndex;
	uint64_t value;
};

// A bounded, self-contained integer constant immediately before a consumer.
// It never assumes the old value of a register or crosses an unrelated operation.
inline std::optional<ConstantSuffix> IntegerConstantSuffix(std::span<const cs_insn> function,
	size_t end, arm64_reg reg)
{
	if (end == 0 || end > function.size()) return std::nullopt;
	const auto lower = end > 8 ? end - 8 : 0;
	for (size_t start = end; start-- > lower;) {
		const auto& seed = function[start];
		if (!seed.detail || seed.size != 4 || seed.id != ARM64_INS_MOV) continue;
		const auto& first = seed.detail->arm64;
		if (first.op_count != 2 || first.update_flags || first.operands[0].type != ARM64_OP_REG ||
			first.operands[0].reg != reg || first.operands[1].type != ARM64_OP_IMM) continue;
		uint64_t value = static_cast<uint64_t>(first.operands[1].imm);
		bool valid = true;
		for (size_t i = start + 1; i < end; ++i) {
			const auto& instruction = function[i];
			if (!instruction.detail || instruction.size != 4 ||
				i - start > (std::numeric_limits<uint64_t>::max() - seed.address) / 4 ||
				instruction.address != seed.address + (i - start) * 4) { valid = false; break; }
			const auto& op = instruction.detail->arm64;
			if (!op.op_count || op.update_flags || op.operands[0].type != ARM64_OP_REG || op.operands[0].reg != reg) { valid = false; break; }
			if (instruction.id == ARM64_INS_MOVK && op.op_count == 2 && op.operands[1].type == ARM64_OP_IMM &&
				op.operands[1].imm >= 0 && op.operands[1].imm <= 0xffff && op.operands[1].shift.value <= 48 &&
				op.operands[1].shift.value % 16 == 0 &&
				(op.operands[1].shift.type == ARM64_SFT_LSL || op.operands[1].shift.type == ARM64_SFT_INVALID)) {
				const auto shift = op.operands[1].shift.value;
				value = (value & ~(uint64_t{0xffff} << shift)) | (static_cast<uint64_t>(op.operands[1].imm) << shift);
			}
			else if (instruction.id == ARM64_INS_EOR && op.op_count == 3 && op.operands[1].type == ARM64_OP_REG &&
				op.operands[1].reg == reg && op.operands[2].type == ARM64_OP_IMM && op.operands[2].shift.value == 0)
				value ^= static_cast<uint64_t>(op.operands[2].imm);
			else { valid = false; break; }
		}
		if (valid) return ConstantSuffix{start, value};
	}
	return std::nullopt;
}

}
