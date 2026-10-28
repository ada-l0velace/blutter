#pragma once
#include "Arm64Patterns.h"

namespace arm64_patterns {

struct BoxingAbi {
	arm64_reg stack, frame, link, pool, result;
	uint32_t preservedInputs;
	int64_t codeEntryOffset, valueOffset, tagSize;
};

struct BoxingCall {
	size_t instruction;
	std::optional<uint64_t> target;
	std::optional<int64_t> poolOffset;
	size_t poolLoad = 0;
};

struct BoxingMatch {
	size_t endIndex;
	arm64_reg source, result;
	BoxingCall call;
};

// Recognize the inverted branch, a proven unconditional zero-register skip,
// a balanced optional frame, an independently verified allocator and its value store.
template<class VerifyCall, class IsEntry>
std::optional<BoxingMatch> InvertedBoxInt64(std::span<const cs_insn> function, size_t start,
	const BoxingAbi& abi, VerifyCall verifyCall, IsEntry isEntry)
{
	if (start >= function.size()) return std::nullopt;
	const auto insns = function.subspan(start);
	auto valid = [&](size_t i) {
		return i < insns.size() && insns[i].detail && insns[i].size == 4 &&
			i <= (std::numeric_limits<uint64_t>::max() - insns[0].address) / 4 &&
			insns[i].address == insns[0].address + i * 4;
	};
	auto reg = [&](size_t i, size_t operand, arm64_reg expected) {
		return valid(i) && operand < insns[i].detail->arm64.op_count &&
			insns[i].detail->arm64.operands[operand].type == ARM64_OP_REG &&
			insns[i].detail->arm64.operands[operand].reg == expected;
	};
	auto memory = [&](size_t i, unsigned id, arm64_reg value, arm64_reg base, int64_t offset) {
		if (!valid(i) || insns[i].id != id || insns[i].detail->arm64.op_count != 2 ||
			insns[i].detail->arm64.writeback || !reg(i, 0, value)) return false;
		const auto& op = insns[i].detail->arm64.operands[1];
		return op.type == ARM64_OP_MEM && op.mem.base == base && op.mem.index == ARM64_REG_INVALID && op.mem.disp == offset;
	};
	auto copy = [&](size_t i, arm64_reg dst, arm64_reg src) {
		return valid(i) && insns[i].id == ARM64_INS_CSEL && insns[i].detail->arm64.op_count == 3 &&
			!insns[i].detail->arm64.update_flags && reg(i, 0, dst) && reg(i, 1, src) && reg(i, 2, src);
	};
	if (!valid(0) || insns[0].id != ARM64_INS_SBFIZ || insns[0].detail->arm64.op_count != 4 ||
		!reg(0, 0, abi.result) || insns[0].detail->arm64.operands[1].type != ARM64_OP_REG ||
		insns[0].detail->arm64.operands[2].type != ARM64_OP_IMM || insns[0].detail->arm64.operands[2].imm != abi.tagSize ||
		insns[0].detail->arm64.operands[3].type != ARM64_OP_IMM || insns[0].detail->arm64.operands[3].imm != 31) return std::nullopt;
	const auto source = insns[0].detail->arm64.operands[1].reg;
	if (source == abi.result || source == abi.stack || source == abi.frame || source == abi.link ||
		!((source >= ARM64_REG_X0 && source <= ARM64_REG_X28) || source == ARM64_REG_X29 || source == ARM64_REG_X30)) return std::nullopt;
	const auto sourceNumber = source >= ARM64_REG_X0 && source <= ARM64_REG_X28 ? source - ARM64_REG_X0 : source == ARM64_REG_X29 ? 29 : 30;
	if (!(abi.preservedInputs & (uint32_t{1} << sourceNumber))) return std::nullopt;
	if (!valid(1) || insns[1].id != ARM64_INS_CMP || insns[1].detail->arm64.op_count != 2 ||
		!reg(1, 0, source) || !reg(1, 1, abi.result) ||
		insns[1].detail->arm64.operands[1].shift.type != ARM64_SFT_ASR ||
		insns[1].detail->arm64.operands[1].shift.value != abi.tagSize) return std::nullopt;
	if (!valid(2) || insns[2].id != ARM64_INS_B || insns[2].detail->arm64.cc != ARM64_CC_NE ||
		insns[2].detail->arm64.op_count != 1 || insns[2].detail->arm64.operands[0].type != ARM64_OP_IMM ||
		!valid(4) || static_cast<uint64_t>(insns[2].detail->arm64.operands[0].imm) != insns[4].address) return std::nullopt;
	if (!valid(3) || insns[3].id != ARM64_INS_TBZ || insns[3].detail->arm64.op_count != 3 ||
		!(reg(3, 0, ARM64_REG_WZR) || reg(3, 0, ARM64_REG_XZR)) ||
		insns[3].detail->arm64.operands[1].type != ARM64_OP_IMM || insns[3].detail->arm64.operands[2].type != ARM64_OP_IMM) return std::nullopt;
	const auto continuation = static_cast<uint64_t>(insns[3].detail->arm64.operands[2].imm);
	if (continuation <= insns[4].address || continuation < insns[0].address ||
		(continuation - insns[0].address) % 4) return std::nullopt;
	const auto end = (continuation - insns[0].address) / 4;
	if (end > insns.size() || end > 32) return std::nullopt;
	for (size_t i = 0; i < end; ++i) if (!valid(i)) return std::nullopt;
	for (size_t i = 1; i < end; ++i) if (isEntry(insns[i].address)) return std::nullopt;
	// Only the two checked internal branches may enter the folded region.
	for (size_t i = 0; i < function.size(); ++i) {
		if (i >= start && i < start + end) continue;
		const auto& instruction = function[i];
		if (!instruction.detail) return std::nullopt;
		const auto& detail = *instruction.detail;
		const bool transfer = std::any_of(detail.groups, detail.groups + detail.groups_count,
			[](uint8_t group) { return group == CS_GRP_JUMP || group == CS_GRP_CALL; });
		if (transfer && detail.arm64.op_count) {
			const auto& target = detail.arm64.operands[detail.arm64.op_count - 1];
			if (target.type == ARM64_OP_IMM && static_cast<uint64_t>(target.imm) > insns[0].address &&
				static_cast<uint64_t>(target.imm) < continuation) return std::nullopt;
		}
	}
	size_t i = 4;
	const bool framed = insns[i].id == ARM64_INS_SUB;
	if (framed) {
		const auto allocation = ImmediateDelta(insns[i], abi.stack, abi.stack);
		if (!allocation || *allocation > -16 ||
			!memory(i + 1, ARM64_INS_STR, abi.frame, abi.stack, -*allocation - 16) ||
			!memory(i + 2, ARM64_INS_STR, abi.link, abi.stack, -*allocation - 8) || !valid(i + 3) ||
			ImmediateDelta(insns[i + 3], abi.stack, abi.stack) != -*allocation - 16 ||
			!copy(i + 4, abi.frame, abi.stack)) return std::nullopt;
		i += 5;
	}
	BoxingCall call{};
	if (valid(i) && insns[i].id == ARM64_INS_BL && insns[i].detail->arm64.op_count == 1 &&
		insns[i].detail->arm64.operands[0].type == ARM64_OP_IMM) {
		call.instruction = start + i;
		call.target = static_cast<uint64_t>(insns[i].detail->arm64.operands[0].imm);
		++i;
	}
	else {
		if (!valid(i) || insns[i].id != ARM64_INS_MOV || insns[i].detail->arm64.op_count != 2 ||
			!(reg(i, 0, abi.link) || reg(i, 0, ARM64_REG_W30)) ||
			insns[i].detail->arm64.operands[1].type != ARM64_OP_IMM || insns[i].detail->arm64.operands[1].imm < 0) return std::nullopt;
		const auto offset = insns[i].detail->arm64.operands[1].imm;
		if (offset > std::numeric_limits<int32_t>::max()) return std::nullopt;
		if (!valid(i + 1) || insns[i + 1].id != ARM64_INS_LDR || !reg(i + 1, 0, abi.link) ||
			insns[i + 1].detail->arm64.op_count != 2 || insns[i + 1].detail->arm64.writeback) return std::nullopt;
		const auto& address = insns[i + 1].detail->arm64.operands[1];
		if (address.type != ARM64_OP_MEM || address.mem.base != abi.pool || address.mem.disp != 0 ||
			(address.mem.index != abi.link && address.mem.index != ARM64_REG_W30) || address.shift.value != 0 ||
			(address.ext != ARM64_EXT_INVALID && address.ext != ARM64_EXT_UXTW && address.ext != ARM64_EXT_SXTW &&
			 address.ext != ARM64_EXT_UXTX && address.ext != ARM64_EXT_SXTX)) return std::nullopt;
		if (!(memory(i + 2, ARM64_INS_LDUR, abi.link, abi.link, abi.codeEntryOffset) ||
			memory(i + 2, ARM64_INS_LDTR, abi.link, abi.link, abi.codeEntryOffset)) ||
			!valid(i + 3) || insns[i + 3].id != ARM64_INS_BLR || insns[i + 3].detail->arm64.op_count != 1 || !reg(i + 3, 0, abi.link)) return std::nullopt;
		call.instruction = start + i + 3;
		call.poolOffset = offset;
		call.poolLoad = start + i + 1;
		i += 4;
	}
	if (framed) {
		if (!copy(i, abi.stack, abi.frame) || !valid(i + 1)) return std::nullopt;
		const auto restore = ImmediateDelta(insns[i + 1], abi.stack, abi.stack);
		if (!restore || *restore > 0 ||
			!memory(i + 2, ARM64_INS_LDR, abi.frame, abi.stack, -*restore) ||
			!memory(i + 3, ARM64_INS_LDR, abi.link, abi.stack, -*restore + 8) || !valid(i + 4) ||
			ImmediateDelta(insns[i + 4], abi.stack, abi.stack) != -*restore + 16) return std::nullopt;
		i += 5;
	}
	if (!valid(i)) return std::nullopt;
	const auto bias = ImmediateDelta(insns[i], abi.result, abi.result);
	if (!bias || !valid(i + 1) || insns[i + 1].detail->arm64.op_count != 2 ||
		insns[i + 1].detail->arm64.operands[1].type != ARM64_OP_MEM ||
		!memory(i + 1, ARM64_INS_STUR, source, abi.result, abi.valueOffset - *bias) || !valid(i + 2) ||
		ImmediateDelta(insns[i + 2], abi.result, abi.result) != -*bias || i + 3 != end) return std::nullopt;
	if (!verifyCall(call)) return std::nullopt;
	return BoxingMatch{start + static_cast<size_t>(end), source, abi.result, call};
}

}
