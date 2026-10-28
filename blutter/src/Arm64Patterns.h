#pragma once
#include <capstone.h>
#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <vector>

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

struct NullBooleanMatch {
	size_t lastIndex;
	bool value;
};

inline std::vector<uint64_t> DirectBranchTargets(std::span<const cs_insn> insns)
{
	std::vector<uint64_t> targets;
	for (const auto& insn : insns) {
		if (!insn.detail)
			throw std::invalid_argument("Missing ARM64 instruction details for branch-boundary analysis");
		const auto& detail = *insn.detail;
		const bool transfer = std::any_of(detail.groups, detail.groups + detail.groups_count,
			[](uint8_t group) { return group == CS_GRP_JUMP || group == CS_GRP_CALL; });
		if (!transfer || !detail.arm64.op_count)
			continue;
		const auto& target = detail.arm64.operands[detail.arm64.op_count - 1];
		if (target.type == ARM64_OP_IMM)
			targets.push_back(static_cast<uint64_t>(target.imm));
	}
	std::sort(targets.begin(), targets.end());
	targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
	return targets;
}

inline std::optional<NullBooleanMatch> NullBooleanLoad(std::span<const cs_insn> insns,
	arm64_reg nullReg, int64_t trueOffset, int64_t falseOffset,
	std::span<const uint64_t> blockEntries = {})
{
	if (insns.empty())
		return std::nullopt;
	// Preserve canonical single-instruction loads and leave subsequent instructions alone.
	if (auto value = NullBoolean(insns[0], nullReg, trueOffset, falseOffset))
		return NullBooleanMatch{0, *value};
	if (insns.size() < 2 || !insns[0].detail || insns[0].id != ARM64_INS_ADD ||
		insns[0].detail->arm64.op_count != 3 || insns[0].detail->arm64.operands[0].type != ARM64_OP_REG)
		return std::nullopt;
	const auto dst = insns[0].detail->arm64.operands[0].reg;
	const bool general = (dst >= ARM64_REG_X0 && dst <= ARM64_REG_X28) ||
		dst == ARM64_REG_X29 || dst == ARM64_REG_X30;
	if (!general || dst == nullReg || insns[0].address > std::numeric_limits<uint64_t>::max() - 4 ||
		insns[1].address != insns[0].address + 4 ||
		std::find(blockEntries.begin(), blockEntries.end(), insns[1].address) != blockEntries.end())
		return std::nullopt;
	const auto first = ImmediateDelta(insns[0], dst, nullReg);
	const auto second = ImmediateDelta(insns[1], dst, dst);
	if (!first || !second)
		return std::nullopt;
	// Each validated immediate is at most 0xfff << 12; their sum fits int64_t.
	const auto offset = *first + *second;
	if (offset == trueOffset)
		return NullBooleanMatch{1, true};
	if (offset == falseOffset)
		return NullBooleanMatch{1, false};
	return std::nullopt;
}

struct GdtCallMatch {
	size_t callIndex;
	int64_t offset;
	bool usesTemporary;
};

// An unclaimed load/call through the reserved dispatch-table register is still a dispatch,
// even when its preceding index arithmetic is not supported by GdtCall.
inline bool IsDispatchCall(std::span<const cs_insn> insns, arm64_reg tableReg)
{
	if (insns.empty() || !insns[0].detail || insns[0].size != 4 || insns[0].id != ARM64_INS_LDR)
		return false;
	const auto& load = insns[0].detail->arm64;
	if (load.op_count != 2 || load.operands[0].type != ARM64_OP_REG ||
		load.operands[0].reg != ARM64_REG_X30 || load.operands[1].type != ARM64_OP_MEM ||
		load.operands[1].mem.base != tableReg)
		return false;
	size_t call = 1;
	if (call < insns.size() && insns[call].id == ARM64_INS_NOP && insns[call].size == 4 &&
		insns[call].address == insns[0].address + 4)
		++call;
	if (call >= insns.size() || !insns[call].detail || insns[call].size != 4 ||
		insns[0].address > std::numeric_limits<uint64_t>::max() - call * 4 ||
		insns[call].address != insns[0].address + call * 4 || insns[call].id != ARM64_INS_BLR)
		return false;
	const auto& branch = insns[call].detail->arm64;
	return branch.op_count == 1 && branch.operands[0].type == ARM64_OP_REG &&
		branch.operands[0].reg == ARM64_REG_X30;
}

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
	const auto& first = insns[0].detail->arm64;
	if (!offset && insns[0].id == ARM64_INS_MOV && first.op_count == 2 && !first.update_flags &&
		first.operands[0].type == ARM64_OP_REG && first.operands[0].reg == ARM64_REG_X30 &&
		first.operands[1].type == ARM64_OP_REG && first.operands[1].reg == classIdReg)
		offset = 0;
	if (!offset && insns[0].id == ARM64_INS_CSEL && first.op_count == 3 && !first.update_flags &&
		first.operands[0].type == ARM64_OP_REG && first.operands[0].reg == ARM64_REG_X30 &&
		first.operands[1].type == ARM64_OP_REG && first.operands[1].reg == classIdReg &&
		first.operands[2].type == ARM64_OP_REG && first.operands[2].reg == classIdReg)
		offset = 0;
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
		bool usesTemporary = false;
		const auto& op = insns[i].detail->arm64;
		if (!delta && tmpValue && insns[i].id == ARM64_INS_ADD && op.op_count == 3 && !op.update_flags &&
			op.operands[0].type == ARM64_OP_REG && op.operands[0].reg == ARM64_REG_X30 &&
			op.operands[1].type == ARM64_OP_REG && op.operands[1].reg == ARM64_REG_X30 &&
			op.operands[2].type == ARM64_OP_REG && op.operands[2].reg == tmpReg &&
			op.operands[2].ext == ARM64_EXT_INVALID && op.operands[2].shift.value == 0) {
			delta = *tmpValue;
			usesTemporary = true;
		}
		if (!delta)
			break;
		if (++arithmeticCount > 8 ||
			(*delta > 0 && *offset > std::numeric_limits<int64_t>::max() - *delta) ||
			(*delta < 0 && *offset < std::numeric_limits<int64_t>::min() - *delta))
			return std::nullopt;
		*offset += *delta;
		temporary |= usesTemporary;
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
