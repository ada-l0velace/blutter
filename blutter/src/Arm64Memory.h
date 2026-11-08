#pragma once
#include "Arm64Patterns.h"

namespace arm64_patterns {

struct BasedAccessMatch {
	size_t lastIndex;
	arm64_reg value, base, index;
	int64_t offset;
	arm64_extender extension;
	unsigned shift, bytes;
	bool isLoad;
};

inline unsigned MemoryRegisterWidth(arm64_reg reg)
{
	if ((reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) || reg == ARM64_REG_X29 ||
		reg == ARM64_REG_X30 || reg == ARM64_REG_XZR || reg == ARM64_REG_SP) return 64;
	if ((reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) || reg == ARM64_REG_WZR) return 32;
	return 0;
}

inline bool PlainMemoryOperand(const cs_arm64_op& op)
{
	return op.ext == ARM64_EXT_INVALID && op.shift.value == 0 &&
		(op.shift.type == ARM64_SFT_INVALID || op.shift.type == ARM64_SFT_LSL);
}

// A scalar access says nothing about the address's object identity or contents.
inline std::optional<BasedAccessMatch> ScalarMemoryAccess(const cs_insn& insn)
{
	const bool load = insn.id == ARM64_INS_LDR || insn.id == ARM64_INS_LDUR;
	const bool store = insn.id == ARM64_INS_STR || insn.id == ARM64_INS_STUR;
	if ((!load && !store) || !insn.detail || insn.size != 4 ||
		insn.address > std::numeric_limits<uint64_t>::max() - 4) return std::nullopt;
	const auto& op = insn.detail->arm64;
	if (op.op_count != 2 || op.writeback || op.update_flags ||
		op.operands[0].type != ARM64_OP_REG || !PlainMemoryOperand(op.operands[0]) ||
		op.operands[1].type != ARM64_OP_MEM || !PlainMemoryOperand(op.operands[1])) return std::nullopt;
	const auto value = op.operands[0].reg;
	const auto& memory = op.operands[1].mem;
	const auto bits = MemoryRegisterWidth(value);
	if (!bits || value == ARM64_REG_SP || MemoryRegisterWidth(memory.base) != 64 ||
		memory.base == ARM64_REG_XZR || memory.index != ARM64_REG_INVALID) return std::nullopt;
	return BasedAccessMatch{0, value, memory.base, ARM64_REG_INVALID, memory.disp,
		ARM64_EXT_INVALID, 0, bits / 8, load};
}

// Follow one temporary within a contiguous straight-line sequence. The caller
// supplies established address bases and all known entries into the sequence.
// No aliases survive an unrelated instruction, call, branch or redefinition.
inline std::optional<BasedAccessMatch> BasedMemoryAccess(std::span<const cs_insn> insns,
	std::span<const arm64_reg> allowedBases, std::span<const uint64_t> blockEntries = {}, bool allowBaseUpdate = false)
{
	const auto allowed = [&](arm64_reg reg) {
		return std::find(allowedBases.begin(), allowedBases.end(), reg) != allowedBases.end();
	};
	if (insns.empty() || !insns[0].detail || insns[0].size != 4) return std::nullopt;
	if (auto access = ScalarMemoryAccess(insns[0]); access && allowed(access->base)) return access;
	const auto& first = insns[0].detail->arm64;
	if ((first.op_count != 2 && first.op_count != 3) || first.writeback || first.update_flags ||
		first.operands[0].type != ARM64_OP_REG || first.operands[1].type != ARM64_OP_REG ||
		!PlainMemoryOperand(first.operands[0]) || !PlainMemoryOperand(first.operands[1])) return std::nullopt;
	const auto temporary = first.operands[0].reg, base = first.operands[1].reg;
	if (!allowed(base) || MemoryRegisterWidth(base) != 64 || MemoryRegisterWidth(temporary) != 64 ||
		temporary == ARM64_REG_SP || temporary == ARM64_REG_XZR || (!allowBaseUpdate && temporary == base)) return std::nullopt;
	const auto delta = [&](const cs_insn& insn, arm64_reg source) -> std::optional<int64_t> {
		const auto& op = insn.detail->arm64;
		if (op.op_count != 3 || op.writeback || !PlainMemoryOperand(op.operands[0]) ||
			!PlainMemoryOperand(op.operands[1]) || op.operands[2].ext != ARM64_EXT_INVALID) return std::nullopt;
		return ImmediateDelta(insn, temporary, source);
	};
	auto offset = insns[0].id == ARM64_INS_MOV && first.op_count == 2 ?
		std::optional<int64_t>{0} : delta(insns[0], base);
	if (!offset) return std::nullopt;
	arm64_reg index = ARM64_REG_INVALID;
	arm64_extender extension = ARM64_EXT_INVALID;
	unsigned shift = 0;
	for (size_t i = 1; i < insns.size() && i <= 8; ++i) {
		const auto& instruction = insns[i];
		if (!instruction.detail || instruction.size != 4 ||
			i > (std::numeric_limits<uint64_t>::max() - insns[0].address) / 4 ||
			instruction.address != insns[0].address + i * 4 ||
			std::find(blockEntries.begin(), blockEntries.end(), instruction.address) != blockEntries.end()) return std::nullopt;
		const auto& op = instruction.detail->arm64;
		// At most eight validated 12-bit immediates (optionally shifted by 12)
		// plus an int32 displacement cannot overflow this signed 64-bit offset.
		if (auto adjustment = delta(instruction, temporary)) { *offset += *adjustment; continue; }
		if (instruction.id == ARM64_INS_ADD && op.op_count == 3 && !op.update_flags && !op.writeback &&
			op.operands[0].type == ARM64_OP_REG && op.operands[0].reg == temporary && PlainMemoryOperand(op.operands[0]) &&
			op.operands[1].type == ARM64_OP_REG && op.operands[1].reg == temporary && PlainMemoryOperand(op.operands[1]) &&
			op.operands[2].type == ARM64_OP_REG && index == ARM64_REG_INVALID) {
			const auto& operand = op.operands[2];
			const int number = static_cast<int>(operand.reg) - static_cast<int>(ARM64_REG_W0);
			const int temporaryNumber = temporary == ARM64_REG_X29 ? 29 : temporary == ARM64_REG_X30 ? 30 : temporary - ARM64_REG_X0;
			if (number < 0 || number > 30 || number == temporaryNumber || operand.shift.value > 3 ||
				(operand.shift.type != ARM64_SFT_INVALID && operand.shift.type != ARM64_SFT_LSL) ||
				(operand.ext != ARM64_EXT_SXTW && operand.ext != ARM64_EXT_UXTW)) return std::nullopt;
			index = operand.reg; extension = operand.ext; shift = operand.shift.value;
			continue;
		}
		if (auto access = ScalarMemoryAccess(instruction); access && access->base == temporary) {
			access->lastIndex = i; access->base = base; access->offset += *offset;
			access->index = index; access->extension = extension; access->shift = shift;
			return access;
		}
		return std::nullopt;
	}
	return std::nullopt;
}

// The loaded table pointer is an immutable address origin for this proof even
// when the machine register is adjusted in place. Never follow other THR slots.
inline std::optional<BasedAccessMatch> FollowFieldTableAccess(std::span<const cs_insn> insns,
	const BasedAccessMatch& first, arm64_reg thread, int64_t tableOffset,
	std::span<const uint64_t> blockEntries = {})
{
	if (!first.isLoad || first.bytes != 8 || first.base != thread ||
		first.index != ARM64_REG_INVALID || first.offset != tableOffset ||
		first.lastIndex >= insns.size() || first.lastIndex + 1 == insns.size()) return std::nullopt;
	const auto next = first.lastIndex + 1;
	if (insns[first.lastIndex].address > std::numeric_limits<uint64_t>::max() - 4 ||
		insns[next].address != insns[first.lastIndex].address + 4 ||
		std::find(blockEntries.begin(), blockEntries.end(), insns[next].address) != blockEntries.end()) return std::nullopt;
	const arm64_reg tableBase[]{first.value};
	auto access = BasedMemoryAccess(insns.subspan(next), tableBase, blockEntries, true);
	if (access) access->lastIndex += next;
	return access;
}

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
	const auto match = BasedMemoryAccess(insns, allowedBases, blockEntries);
	if (!match || !match->lastIndex || !match->isLoad || match->bytes != 8 ||
		match->value != insns[0].detail->arm64.operands[0].reg ||
		insns[match->lastIndex].id != ARM64_INS_LDUR ||
		insns[match->lastIndex].detail->arm64.operands[1].mem.disp != -1) return std::nullopt;
	return ComputedLoadMatch{match->lastIndex, match->value, match->base, match->index,
		match->offset, match->extension, match->shift};
}

}
