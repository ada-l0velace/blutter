#include "DescriptorPrologue.h"
#include "Arm64Memory.h"
#include "Arm64Ir.h"
#include <array>
#include <memory>
#include <set>
#include <map>

namespace SnapshotAnalysis {
namespace {
int Number(arm64_reg r) {
	if (r >= ARM64_REG_X0 && r <= ARM64_REG_X28) return r-ARM64_REG_X0;
	if (r >= ARM64_REG_W0 && r <= ARM64_REG_W30) return r-ARM64_REG_W0;
	if (r == ARM64_REG_X29 || r == ARM64_REG_X30) return r == ARM64_REG_X29 ? 29 : 30;
	return -1;
}
bool Full(arm64_reg r) { return arm64_patterns::MemoryRegisterWidth(r) == 64; }
bool Reg(const cs_arm64_op& o, arm64_reg r) { return o.type == ARM64_OP_REG && o.reg == r && arm64_patterns::PlainMemoryOperand(o); }
}
std::optional<DescriptorPrologue> ProveDescriptorPrologue(const std::vector<uint8_t>& bytes,
	uint64_t target, const DescriptorPrologueAbi& abi)
{
	if (!abi.supported || abi.descriptorRegister >= 15 || abi.fieldBytes != 4 || abi.smiShift != 1 ||
		abi.frameArgumentBase != 16 || abi.typeArgumentsOffset < 0 || abi.sizeOffset < 0 ||
		!target || target % 4 || bytes.size() < 32 || bytes.size() > 512 || bytes.size() % 4 || target > UINT64_MAX-bytes.size()) return {};
	struct Decoder { csh handle = 0; ~Decoder() { if (handle) cs_close(&handle); } } decoder;
	if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &decoder.handle) != CS_ERR_OK ||
		cs_option(decoder.handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) return {};
	cs_insn* raw = nullptr;
	const size_t count = cs_disasm(decoder.handle, bytes.data(), bytes.size(), target, 128, &raw);
	auto free = [count](cs_insn* p) { if (p) cs_free(p, count); };
	std::unique_ptr<cs_insn, decltype(free)> owned(raw, free);
	if (count < 8) return {};
	for (size_t n = 0; n < count; ++n)
		if (!raw[n].detail || raw[n].size != 4 || raw[n].address != target+n*4) return {};
	const auto& save = raw[0].detail->arm64;
	const auto& frame = raw[1].detail->arm64;
	if (raw[0].id != ARM64_INS_STP || save.op_count != 3 || !save.writeback || save.update_flags ||
		!Reg(save.operands[0], ARM64_REG_FP) || !Reg(save.operands[1], ARM64_REG_LR) ||
		save.operands[2].type != ARM64_OP_MEM || save.operands[2].mem.base != ARM64_REG_X15 ||
		save.operands[2].mem.index != ARM64_REG_INVALID || save.operands[2].mem.disp != -16 ||
		raw[1].id != ARM64_INS_MOV || frame.op_count != 2 || frame.writeback || frame.update_flags ||
		!Reg(frame.operands[0], ARM64_REG_FP) || !Reg(frame.operands[1], ARM64_REG_X15)) return {};
	std::set<int> aliases{static_cast<int>(abi.descriptorRegister)};
	int64_t stack = -16;
	std::map<int, std::pair<int64_t,uint64_t>> counts;
	for (size_t n = 2; n < count && n < 64; ++n) {
		const auto& i = raw[n]; const auto& d = i.detail->arm64;
		if (abi.countOffset > 0) {
			if (auto load = arm64_patterns::ScalarMemoryAccess(i); load && load->isLoad && load->bytes == 4 &&
				load->offset == abi.countOffset && aliases.contains(Number(load->base)) && Full(load->base) && Number(load->value) >= 0 && Number(load->value) < 15) {
				const int to = Number(load->value); aliases.erase(to); counts[to] = {0, i.address}; continue;
			}
			if (i.id == ARM64_INS_SUB && d.op_count == 3 && d.operands[0].type == ARM64_OP_REG && Full(d.operands[0].reg) &&
				d.operands[1].type == ARM64_OP_REG && Full(d.operands[1].reg) && counts.contains(Number(d.operands[1].reg)) &&
				d.operands[2].type == ARM64_OP_IMM && arm64_patterns::PlainMemoryOperand(d.operands[2]) && d.operands[2].imm >= 0 && d.operands[2].imm <= 64 && d.operands[2].imm%2 == 0 &&
				!d.update_flags && !d.writeback) {
				const int to = Number(d.operands[0].reg); if (to < 0 || to >= 15) return {};
				auto value = counts.at(Number(d.operands[1].reg)); value.first -= d.operands[2].imm;
				if (value.first < -64) return {}; aliases.erase(to); counts[to] = value; continue;
			}
			if (i.id == ARM64_INS_ADD && d.op_count == 3 && !d.update_flags && !d.writeback &&
				d.operands[0].type == ARM64_OP_REG && Full(d.operands[0].reg) && Number(d.operands[0].reg) >= 0 && Number(d.operands[0].reg) < 15 &&
				Reg(d.operands[1], ARM64_REG_FP) && d.operands[2].type == ARM64_OP_REG && !Full(d.operands[2].reg) &&
				d.operands[2].ext == ARM64_EXT_SXTW && d.operands[2].shift.value == 2 && counts.contains(Number(d.operands[2].reg)) && n+1 < count) {
				const auto load = arm64_patterns::ScalarMemoryAccess(raw[n+1]);
				if (!load || !load->isLoad || load->base != d.operands[0].reg || load->bytes != 8 || load->offset < -256 || load->offset > 512) return {};
				const auto value = counts.at(Number(d.operands[2].reg));
				DescriptorPrologue result{target, 0, 0, value.second, i.address, raw[n+1].address, {}, true, value.first, load->offset};
				for (size_t p = 0; p <= n+1; ++p) result.proof.push_back(raw[p].address);
				return result;
			}
		}
		if (auto load = arm64_patterns::ScalarMemoryAccess(i); load && load->isLoad &&
			aliases.contains(Number(load->base)) && load->offset == abi.typeArgumentsOffset && load->bytes == 4 && Number(load->value) >= 0 && Number(load->value) < 15) {
			if (n+1 >= count) return {};
			const auto& branch = raw[n+1]; const auto& b = branch.detail->arm64;
			if (branch.id != ARM64_INS_CBNZ || b.op_count != 2 || !Reg(b.operands[0], load->value) || b.operands[1].type != ARM64_OP_IMM ||
				static_cast<uint64_t>(b.operands[1].imm) < branch.address+4) return {};
			const auto jump = static_cast<uint64_t>(b.operands[1].imm);
			if (jump < target || (jump-target)%4 || (jump-target)/4+2 >= count || jump-branch.address > 32) return {};
			const size_t k = (jump-target)/4;
			auto descriptorAliases = aliases; descriptorAliases.erase(Number(load->value));
			const auto size = arm64_patterns::ScalarMemoryAccess(raw[k]);
			if (!size || !size->isLoad || size->bytes != 4 || Number(size->value) < 0 || Number(size->value) >= 15 || size->offset != abi.sizeOffset || !descriptorAliases.contains(Number(size->base)) ||
				!Full(size->base)) return {};
			const auto& add = raw[k+1].detail->arm64;
			if (raw[k+1].id != ARM64_INS_ADD || add.op_count != 3 || add.update_flags || add.writeback ||
				add.operands[0].type != ARM64_OP_REG || !Full(add.operands[0].reg) || Number(add.operands[0].reg) < 0 || Number(add.operands[0].reg) >= 15 ||
				!Reg(add.operands[1], ARM64_REG_FP) || add.operands[2].type != ARM64_OP_REG || add.operands[2].reg != size->value ||
				add.operands[2].ext != ARM64_EXT_SXTW || add.operands[2].shift.value != 2) return {};
			const auto vector = arm64_patterns::ScalarMemoryAccess(raw[k+2]);
			if (!vector || !vector->isLoad || vector->bytes != 8 || vector->base != add.operands[0].reg || vector->offset != abi.frameArgumentBase) return {};
			DescriptorPrologue result{target, i.address, branch.address, raw[k].address, raw[k+1].address, raw[k+2].address, {}};
			for (size_t p = 0; p <= n+1; ++p) result.proof.push_back(raw[p].address);
			result.proof.insert(result.proof.end(), {raw[k].address, raw[k+1].address, raw[k+2].address});
			return result;
		}
		if (i.id == ARM64_INS_MOV && d.op_count == 2 && d.operands[0].type == ARM64_OP_REG && d.operands[1].type == ARM64_OP_REG &&
			Full(d.operands[0].reg) && Full(d.operands[1].reg) && !d.update_flags && !d.writeback) {
			const int destination = Number(d.operands[0].reg), source = Number(d.operands[1].reg);
			if (destination < 0 || destination == 15 || destination == 29) return {};
			const bool alias = aliases.contains(source); aliases.erase(destination); if (alias) aliases.insert(destination);
			const auto value = counts.find(source); const auto countValue = value == counts.end() ? std::optional<std::pair<int64_t,uint64_t>>{} : value->second;
			counts.erase(destination); if (countValue) counts[destination] = *countValue;
			continue;
		}
		if (i.id == ARM64_INS_SUB && d.op_count == 3 && Reg(d.operands[0], ARM64_REG_X15) && Reg(d.operands[1], ARM64_REG_X15) &&
			d.operands[2].type == ARM64_OP_IMM && d.operands[2].imm >= 0 && d.operands[2].imm <= 1048576 && arm64_patterns::PlainMemoryOperand(d.operands[2]) &&
			!d.update_flags && !d.writeback && stack-d.operands[2].imm >= -1048576) { stack -= d.operands[2].imm; continue; }
		if (auto memory = arm64_patterns::ScalarMemoryAccess(i); memory && !memory->isLoad) {
			const auto offset = memory->offset + (memory->base == ARM64_REG_FP ? -16 : memory->base == ARM64_REG_X15 ? stack : 1048576);
			if (offset < stack || offset+memory->bytes > -16) return {};
			continue;
		}
		if (i.id == ARM64_INS_NOP || i.id == ARM64_INS_CMP || i.id == ARM64_INS_TST) continue;
		const auto lowered = LowerArm64(i);
		if (!lowered) return {};
		const auto effects = NativeIr::GetEffects(*lowered);
		if (effects.unlistedRegistersMayChange || effects.control != NativeIr::ControlEffect::Fallthrough ||
			(effects.memory != NativeIr::MemoryEffect::None && effects.memory != NativeIr::MemoryEffect::Read) || !effects.destination ||
			effects.destination->id == 15 || effects.destination->id >= 29) return {};
		aliases.erase(effects.destination->id); counts.erase(effects.destination->id);
	}
	return {};
}
}
