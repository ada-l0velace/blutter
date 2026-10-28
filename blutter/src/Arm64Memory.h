#pragma once
#include "Arm64Patterns.h"

namespace arm64_patterns {

struct ComputedLoadMatch {
	size_t lastIndex;
	arm64_reg destination, base, index;
	int64_t offset;
	arm64_extender extension;
	unsigned shift;
};

// Positive address proof for a bounded stack/frame/Thread-based load that
// happens to use displacement -1. It is not a heap class-header assertion.
inline std::optional<ComputedLoadMatch> ComputedBaseLoad(std::span<const cs_insn> insns,
	std::span<const arm64_reg> allowedBases, std::span<const uint64_t> blockEntries = {})
{
	if (insns.empty() || !insns[0].detail || insns[0].detail->arm64.op_count != 3) return std::nullopt;
	const auto& first = insns[0].detail->arm64;
	if (first.operands[0].type != ARM64_OP_REG || first.operands[1].type != ARM64_OP_REG) return std::nullopt;
	const auto destination = first.operands[0].reg, base = first.operands[1].reg;
	const int destinationNumber = destination >= ARM64_REG_X0 && destination <= ARM64_REG_X28 ?
		destination - ARM64_REG_X0 : destination == ARM64_REG_X29 ? 29 : destination == ARM64_REG_X30 ? 30 : -1;
	if (destinationNumber < 0 || destination == base ||
		std::find(allowedBases.begin(), allowedBases.end(), base) == allowedBases.end()) return std::nullopt;
	auto offset = ImmediateDelta(insns[0], destination, base);
	if (!offset) return std::nullopt;
	arm64_reg index = ARM64_REG_INVALID;
	arm64_extender extension = ARM64_EXT_INVALID;
	unsigned shift = 0;
	for (size_t i = 1; i < insns.size() && i <= 8; ++i) {
		const auto& instruction = insns[i];
		if (!instruction.detail || instruction.size != 4 ||
			i > (std::numeric_limits<uint64_t>::max() - insns[0].address) / 4 ||
			instruction.address != insns[0].address + i * 4) return std::nullopt;
		if (std::find(blockEntries.begin(), blockEntries.end(), instruction.address) != blockEntries.end()) return std::nullopt;
		const auto& op = instruction.detail->arm64;
		if (auto delta = ImmediateDelta(instruction, destination, destination)) { *offset += *delta; continue; }
		if (instruction.id == ARM64_INS_ADD && op.op_count == 3 && !op.update_flags &&
			op.operands[0].type == ARM64_OP_REG && op.operands[0].reg == destination &&
			op.operands[1].type == ARM64_OP_REG && op.operands[1].reg == destination &&
			op.operands[2].type == ARM64_OP_REG && index == ARM64_REG_INVALID) {
			const auto& operand = op.operands[2];
			const int number = static_cast<int>(operand.reg) - static_cast<int>(ARM64_REG_W0);
			if (number < 0 || number > 30 || number == destinationNumber || operand.shift.value > 3 ||
				(operand.shift.type != ARM64_SFT_INVALID && operand.shift.type != ARM64_SFT_LSL) ||
				(operand.ext != ARM64_EXT_SXTW && operand.ext != ARM64_EXT_UXTW)) return std::nullopt;
			index = operand.reg; extension = operand.ext; shift = operand.shift.value;
			continue;
		}
		if (instruction.id != ARM64_INS_LDUR || op.op_count != 2 || op.writeback ||
			op.operands[0].type != ARM64_OP_REG || op.operands[0].reg != destination ||
			op.operands[1].type != ARM64_OP_MEM || op.operands[1].mem.base != destination ||
			op.operands[1].mem.index != ARM64_REG_INVALID || op.operands[1].mem.disp != -1) return std::nullopt;
		return ComputedLoadMatch{i, destination, base, index, *offset - 1, extension, shift};
	}
	return std::nullopt;
}

}
