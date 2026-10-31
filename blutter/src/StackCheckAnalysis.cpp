#include "StackCheckAnalysis.h"
#include "Arm64Ir.h"
#include <algorithm>

namespace SnapshotAnalysis {
namespace {
bool Group(const cs_insn& i, uint8_t group) {
	return std::find(i.detail->groups, i.detail->groups + i.detail->groups_count, group) != i.detail->groups + i.detail->groups_count;
}
uint32_t Word(const cs_insn& i) {
	return uint32_t{i.bytes[0]} | uint32_t{i.bytes[1]} << 8 | uint32_t{i.bytes[2]} << 16 | uint32_t{i.bytes[3]} << 24;
}
bool Jump(const cs_insn& i) {
	return i.id == ARM64_INS_B && (Word(i) & 0xfc000000) == 0x14000000 &&
		i.detail->arm64.op_count == 1 && i.detail->arm64.operands[0].type == ARM64_OP_IMM;
}
}
static std::optional<InitialStackCheck> FindStackCheck(const cs_insn* code, size_t count, const Profile& profile, std::optional<uint64_t> selected) {
	if (!code || count < 6 || count > 16384 || profile.threadRegister != ARM64_REG_X26 || !profile.stackLimitOffset ||
		*profile.stackLimitOffset < 0 || *profile.stackLimitOffset > 32760 || *profile.stackLimitOffset % 8 ||
		code[0].address > UINT64_MAX - count * 4) return {};
	for (size_t n = 0; n < count; ++n) if (!LowerArm64(code[n]) || code[n].address != code[0].address + n * 4) return {};
	if (selected && (*selected < code[0].address || (*selected-code[0].address)%4 || (*selected-code[0].address)/4 >= count)) return {};
	const size_t first = selected ? (*selected-code[0].address)/4 : 0;
	const size_t stop = selected ? first+1 : std::min(count, size_t{32});
	for (size_t n = first; n < stop; ++n) {
		const auto& i = code[n]; const auto& branch = i.detail->arm64;
		if (Group(i, CS_GRP_CALL) || Group(i, CS_GRP_RET) || Group(i, CS_GRP_INT)) return {};
		if (!Group(i, CS_GRP_JUMP)) continue;
		if (n < 2 || i.id != ARM64_INS_B || branch.cc != ARM64_CC_LS || branch.op_count != 1 || branch.operands[0].type != ARM64_OP_IMM) return {};
		const auto lowered = LowerArm64(code[n-2]);
		const auto* load = std::get_if<NativeIr::Load>(&lowered->operation);
		if (!load || load->bytes != 8 || load->address.base.id != 26 || load->address.displacement != *profile.stackLimitOffset || load->target.id >= 29 ||
			load->target.id == 15 || load->target.id == 21 || load->target.id == 22 || load->target.id >= 26) return {};
		const auto limit = static_cast<arm64_reg>(ARM64_REG_X0 + load->target.id);
		const auto& cmp = code[n-1].detail->arm64;
		if (code[n-1].id != ARM64_INS_CMP || cmp.op_count != 2 || cmp.operands[0].type != ARM64_OP_REG || cmp.operands[0].reg != ARM64_REG_X15 ||
			cmp.operands[1].type != ARM64_OP_REG || cmp.operands[1].reg != limit || cmp.operands[1].ext != ARM64_EXT_INVALID ||
			cmp.operands[1].shift.type != ARM64_SFT_INVALID) return {};
		const auto slow = static_cast<uint64_t>(branch.operands[0].imm), fast = i.address + 4;
		if (slow <= fast || slow < code[0].address || (slow-code[0].address) % 4 || (slow-code[0].address)/4 + 1 >= count) return {};
		const auto index = (slow-code[0].address)/4; const auto& call = code[index].detail->arm64;
		if (code[index].id != ARM64_INS_BL || call.op_count != 1 || call.operands[0].type != ARM64_OP_IMM || !Jump(code[index+1]) ||
			static_cast<uint64_t>(code[index+1].detail->arm64.operands[0].imm) != fast) return {};
		const auto stub = static_cast<uint64_t>(call.operands[0].imm);
		if (!profile.framePreservingCalls.contains(stub) || profile.framePreservingCalls.at(stub) != "stack_overflow_without_fpu") return {};
		// The excluded slow block cannot acquire another entry or fallthrough.
		size_t before = index;
		while (before && Word(code[before-1]) == 0xd503201f && index-before < 3) --before;
		if (!before || !(Group(code[before-1], CS_GRP_RET) || Jump(code[before-1]) || code[before-1].id == ARM64_INS_BRK || code[before-1].id == ARM64_INS_HLT)) return {};
		for (size_t k = 0; k < count; ++k) {
			const auto& d = code[k].detail->arm64;
			if (!Group(code[k], CS_GRP_JUMP) && !Group(code[k], CS_GRP_CALL)) continue;
			if (!d.op_count || d.operands[d.op_count-1].type != ARM64_OP_IMM) {
				if (Group(code[k], CS_GRP_CALL)) continue;
				return {};
			}
			const auto target = static_cast<uint64_t>(d.operands[d.op_count-1].imm);
			if ((!selected && target >= code[0].address && target <= i.address) ||
				(target == fast && k != index+1) || (target == slow && k != n) || target == slow+4) return {};
		}
		return InitialStackCheck{i.address, fast, slow, stub, {code[n-2].address, code[n-1].address, i.address, slow, slow+4}};
	}
	return {};
}
std::optional<InitialStackCheck> FindInitialStackCheck(const cs_insn* code, size_t count, const Profile& profile) {
	return FindStackCheck(code, count, profile, {});
}
std::optional<InitialStackCheck> FindStackCheckAt(const cs_insn* code, size_t count, const Profile& profile, uint64_t site) {
	return FindStackCheck(code, count, profile, site);
}
}
