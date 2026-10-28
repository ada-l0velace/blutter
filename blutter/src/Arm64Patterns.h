#pragma once
#include <capstone.h>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>

namespace arm64_patterns {

inline std::optional<int64_t> ImmediateDelta(const cs_insn& insn, arm64_reg dst, arm64_reg src)
{
	if (!insn.detail || insn.size != 4 || (insn.id != ARM64_INS_ADD && insn.id != ARM64_INS_SUB))
		return std::nullopt;
	const auto& op = insn.detail->arm64;
	if (op.op_count != 3 || op.update_flags || op.operands[0].type != ARM64_OP_REG ||
		op.operands[0].reg != dst || op.operands[1].type != ARM64_OP_REG || op.operands[1].reg != src ||
		op.operands[2].type != ARM64_OP_IMM || op.operands[2].imm < 0 || op.operands[2].imm > 0xfff)
		return std::nullopt;
	const auto& shift = op.operands[2].shift;
	if ((shift.type != ARM64_SFT_INVALID && shift.type != ARM64_SFT_LSL) ||
		(shift.value != 0 && shift.value != 12))
		return std::nullopt;
	const auto value = op.operands[2].imm << shift.value;
	return insn.id == ARM64_INS_SUB ? -value : value;
}

inline std::optional<bool> NullBoolean(const cs_insn& insn, arm64_reg nullReg,
	int64_t trueOffset, int64_t falseOffset)
{
	if (!insn.detail || insn.id != ARM64_INS_ADD || insn.detail->arm64.op_count != 3)
		return std::nullopt;
	const auto dst = insn.detail->arm64.operands[0].reg;
	auto offset = ImmediateDelta(insn, dst, nullReg);
	if (!offset)
		return std::nullopt;
	if (*offset == trueOffset)
		return true;
	if (*offset == falseOffset)
		return false;
	return std::nullopt;
}

struct GdtCallMatch {
	size_t callIndex;
	int64_t offset;
	bool usesTemporary;
};

// Bounded recognition only: unproven sequences stay in the raw assembly stream.
inline std::optional<GdtCallMatch> GdtCall(std::span<const cs_insn> insns,
	arm64_reg classIdReg, arm64_reg tableReg, arm64_reg tmpReg, std::optional<int64_t> tmpValue = std::nullopt)
{
	if (insns.empty())
		return std::nullopt;
	auto valid = [&](size_t i) {
		return i < insns.size() && insns[i].detail && insns[i].size == 4 &&
			i <= (std::numeric_limits<uint64_t>::max() - insns[0].address) / 4 &&
			insns[i].address == insns[0].address + i * 4;
	};
	auto advance = [&](size_t i) {
		++i;
		if (valid(i) && insns[i].id == ARM64_INS_NOP)
			++i;
		return i;
	};
	if (!valid(0))
		return std::nullopt;
	bool temporary = false;
	auto offset = ImmediateDelta(insns[0], ARM64_REG_X30, classIdReg);
	if (!offset) {
		const auto& op = insns[0].detail->arm64;
		if (!tmpValue || insns[0].id != ARM64_INS_ADD || op.op_count != 3 || op.update_flags ||
			op.operands[0].type != ARM64_OP_REG || op.operands[0].reg != ARM64_REG_X30 ||
			op.operands[1].type != ARM64_OP_REG || op.operands[1].reg != classIdReg ||
			op.operands[2].type != ARM64_OP_REG || op.operands[2].reg != tmpReg ||
			op.operands[2].ext != ARM64_EXT_INVALID || op.operands[2].shift.value != 0)
			return std::nullopt;
		offset = *tmpValue;
		temporary = true;
	}
	size_t i = advance(0), arithmeticCount = 1;
	while (valid(i)) {
		auto delta = ImmediateDelta(insns[i], ARM64_REG_X30, ARM64_REG_X30);
		if (!delta)
			break;
		if (++arithmeticCount > 8 ||
			(*delta > 0 && *offset > std::numeric_limits<int64_t>::max() - *delta) ||
			(*delta < 0 && *offset < std::numeric_limits<int64_t>::min() - *delta))
			return std::nullopt;
		*offset += *delta;
		i = advance(i);
	}
	if (!valid(i) || insns[i].id != ARM64_INS_LDR)
		return std::nullopt;
	const auto& load = insns[i].detail->arm64;
	if (load.op_count != 2 || load.writeback || load.operands[0].type != ARM64_OP_REG ||
		load.operands[0].reg != ARM64_REG_X30 || load.operands[1].type != ARM64_OP_MEM)
		return std::nullopt;
	const auto& address = load.operands[1];
	if (address.mem.base != tableReg || address.mem.index != ARM64_REG_X30 || address.mem.disp != 0 ||
		address.shift.type != ARM64_SFT_LSL || address.shift.value != 3 ||
		(address.ext != ARM64_EXT_INVALID && address.ext != ARM64_EXT_UXTX && address.ext != ARM64_EXT_SXTX))
		return std::nullopt;
	i = advance(i);
	if (!valid(i) || insns[i].id != ARM64_INS_BLR || insns[i].detail->arm64.op_count != 1 ||
		insns[i].detail->arm64.operands[0].type != ARM64_OP_REG ||
		insns[i].detail->arm64.operands[0].reg != ARM64_REG_X30)
		return std::nullopt;
	return GdtCallMatch{ i, *offset, temporary };
}

}
