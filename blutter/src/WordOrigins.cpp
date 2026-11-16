#include "WordOrigins.h"
#include "SnapshotCodeAnalysis.h"
#include "Arm64Ir.h"
#include <algorithm>
#include <limits>
#include <iterator>

namespace SnapshotAnalysis {
namespace {
bool Valid(const cs_insn& i) {
	return i.detail && i.size == 4 && i.detail->groups_count <= std::size(i.detail->groups) &&
		i.detail->arm64.op_count <= std::size(i.detail->arm64.operands);
}
bool Group(const cs_insn& i, uint8_t group) {
	return std::find(i.detail->groups, i.detail->groups + i.detail->groups_count, group) != i.detail->groups + i.detail->groups_count;
}
unsigned Width(arm64_reg r) {
	if ((r >= ARM64_REG_X0 && r <= ARM64_REG_X28) || r == ARM64_REG_X29 || r == ARM64_REG_X30 || r == ARM64_REG_XZR) return 8;
	if ((r >= ARM64_REG_W0 && r <= ARM64_REG_W30) || r == ARM64_REG_WZR) return 4;
	if (r >= ARM64_REG_Q0 && r <= ARM64_REG_Q31) return 16;
	if (r >= ARM64_REG_D0 && r <= ARM64_REG_D31) return 8;
	if (r >= ARM64_REG_S0 && r <= ARM64_REG_S31) return 4;
	return 0;
}
std::optional<uint16_t> Register(arm64_reg r) {
	if (r >= ARM64_REG_X0 && r <= ARM64_REG_X28) return r - ARM64_REG_X0;
	if (r >= ARM64_REG_W0 && r <= ARM64_REG_W30) return r - ARM64_REG_W0;
	if (r == ARM64_REG_X29 || r == ARM64_REG_X30) return r == ARM64_REG_X29 ? 29 : 30;
	return {};
}
bool CompareOrNop(const cs_insn& i) {
	return i.id == ARM64_INS_NOP || i.id == ARM64_INS_CMP || i.id == ARM64_INS_CMN || i.id == ARM64_INS_TST;
}
struct Store { arm64_reg source; uint16_t base; int64_t offset; unsigned bytes; };
std::optional<std::vector<Store>> PlainStores(const cs_insn& i) {
	const auto& d = i.detail->arm64;
	const bool pair = i.id == ARM64_INS_STP;
	const bool scalar = i.id == ARM64_INS_STR || i.id == ARM64_INS_STUR || i.id == ARM64_INS_STRB ||
		i.id == ARM64_INS_STURB || i.id == ARM64_INS_STRH || i.id == ARM64_INS_STURH;
	if ((!scalar && !pair) || d.writeback || d.update_flags || d.op_count != (pair ? 3 : 2)) return {};
	const auto& memory = d.operands[pair ? 2 : 1];
	if (memory.type != ARM64_OP_MEM || memory.mem.index != ARM64_REG_INVALID) return {};
	const auto base = Register(memory.mem.base);
	if (!base || Width(memory.mem.base) != 8) return {};
	std::vector<Store> stores;
	for (unsigned part = 0; part < (pair ? 2U : 1U); ++part) {
		if (d.operands[part].type != ARM64_OP_REG) return {};
		const auto reg = d.operands[part].reg;
		const unsigned width = i.id == ARM64_INS_STRB || i.id == ARM64_INS_STURB ? 1 :
			i.id == ARM64_INS_STRH || i.id == ARM64_INS_STURH ? 2 : Width(reg);
		if (!width || (part && width != stores.front().bytes) || memory.mem.disp > INT64_MAX - static_cast<int64_t>((part+1)*width)) return {};
		stores.push_back({reg, *base, memory.mem.disp + part*static_cast<int64_t>(width), width});
	}
	return stores;
}
}
WordOriginResult TraceWordInput(const cs_insn* raw, size_t count, size_t consumer,
	WordLocation location, const Profile& profile, const std::function<bool(uint64_t)>& isEntry, size_t limit, bool extended, std::optional<uint16_t> invariantNull)
{
	WordOriginResult result{"unknown", {}, 0};
	if (!raw || consumer >= count || !Valid(raw[consumer]) || location.reg >= 31 ||
		(location.memory && (location.memory->base.bits != 64 || location.memory->base.id >= 31))) {
		result.stop = "unsupported_input"; return result;
	}
	std::optional<NativeIr::Address> memory = location.memory;
	std::optional<WordOrigin> fallback;
	uint16_t reg = location.reg;
	bool compressed = false;
	if (memory && memory->displacement > INT64_MAX-8) { result.stop = "address_overflow"; return result; }
	auto source = [&](size_t n, std::string kind) {
		WordOrigin value{std::move(kind), raw[n].address, {}, {}, {}, {}};
		for (size_t k = n; k <= consumer; ++k) value.proof.push_back(raw[k].address);
		return value;
	};
	auto finish = [&](const char* stop) {
		result.stop = stop;
		if (!result.source && fallback) result.source = fallback;
		return result;
	};
	for (size_t cursor = consumer; cursor > 0;) {
		if (isEntry && isEntry(raw[cursor].address)) return finish("entry_boundary");
		if (result.steps >= std::min(limit, size_t{64})) return finish("lookback_limit");
		const size_t n = --cursor;
		const auto& i = raw[n];
		++result.steps;
		if (!Valid(i) || raw[n+1].address < 4 || i.address != raw[n+1].address - 4) return finish("instruction_gap");
		const auto& d = i.detail->arm64;
		if ((Group(i, CS_GRP_JUMP) && !Group(i, CS_GRP_CALL)) || Group(i, CS_GRP_RET) || Group(i, CS_GRP_INT)) return finish("control_transfer");
		if (Group(i, CS_GRP_CALL)) {
			if (memory || reg != 0 || compressed) return finish("call_barrier");
			if (i.id != ARM64_INS_BL && i.id != ARM64_INS_BLR) return finish("unsupported_call");
			std::optional<uint64_t> callee;
			if (i.id == ARM64_INS_BL && d.op_count == 1 && d.operands[0].type == ARM64_OP_IMM) callee = static_cast<uint64_t>(d.operands[0].imm);
			else if (i.id != ARM64_INS_BLR || d.op_count != 1 || d.operands[0].type != ARM64_OP_REG) return finish("unsupported_call");
			if (callee && profile.nonReturningCalls.contains(*callee)) return finish("nonreturning_call");
			std::string kind = "post_call_x0";
			if (callee && profile.asyncContracts.contains(*callee)) {
				const auto operation = profile.asyncContracts.at(*callee).operation;
				if (operation == AsyncOperation::Await || operation == AsyncOperation::AwaitWithTypeCheck) kind = "await_delivery";
				else if (operation != AsyncOperation::Init) return finish("unsupported_async_call");
			}
			result.source = source(n, kind); result.source->callee = callee;
			return finish("matched");
		}
		if (extended && memory && memory->base.id == 15 && (i.id == ARM64_INS_ADD || i.id == ARM64_INS_SUB) &&
			d.op_count == 3 && d.operands[0].type == ARM64_OP_REG && d.operands[0].reg == ARM64_REG_X15 &&
			d.operands[1].type == ARM64_OP_REG && d.operands[1].reg == ARM64_REG_X15 &&
			d.operands[2].type == ARM64_OP_IMM && d.operands[2].imm >= 0 && d.operands[2].imm <= 1048576 &&
			d.operands[2].shift.value == 0 && !d.update_flags && !d.writeback) {
			const auto amount = d.operands[2].imm*(i.id == ARM64_INS_SUB ? -1 : 1);
			if ((amount > 0 && memory->displacement > INT64_MAX-amount) || (amount < 0 && memory->displacement < INT64_MIN-amount)) return finish("address_overflow");
			memory->displacement += amount; continue;
		}
		if (extended && d.writeback && (i.id == ARM64_INS_STP || i.id == ARM64_INS_STR) && d.op_count == (i.id == ARM64_INS_STP ? 3 : 2)) {
			const auto& m = d.operands[d.op_count-1];
			if (m.type != ARM64_OP_MEM || m.mem.base != ARM64_REG_X15 || m.mem.index != ARM64_REG_INVALID ||
				m.mem.disp >= 0 || m.mem.disp < -256 || m.mem.disp%8 || d.update_flags) return finish("unsupported_spill_update");
			if (!memory) { if (reg == 15) return finish("load_base_changed"); continue; }
			if (memory->base.id != 15) return finish("possible_alias_write");
			bool matched = false;
			for (unsigned part = 0; part < d.op_count-1; ++part) {
				if (d.operands[part].type != ARM64_OP_REG || Width(d.operands[part].reg) != 8) return finish("partial_spill_write");
				const auto off = static_cast<int64_t>(part*8);
				if (memory->displacement >= off+8 || memory->displacement+8 <= off) continue;
				if (memory->displacement != off) return finish("partial_spill_write");
				const auto r = d.operands[part].reg;
				if (r == ARM64_REG_XZR) { result.source = source(n, "literal"); result.source->bits = 0; return finish("matched"); }
				const auto stored = Register(r); if (!stored) return finish("unsupported_spill_source");
				if (invariantNull == stored && *stored == 22) { result.source = source(n, "runtime_null"); result.source->bits=22; return finish("matched"); }
				reg = *stored; memory.reset(); matched = true; break;
			}
			if (!matched) {
				if (memory->displacement < INT64_MIN-m.mem.disp) return finish("address_overflow");
				memory->displacement += m.mem.disp;
			}
			continue;
		}
		if (const auto stores = PlainStores(i)) {
			if (!memory) continue;
			const auto address = *memory;
			if (address.displacement > INT64_MAX-8) return finish("address_overflow");
			for (const auto& store : *stores) {
				if (store.base != address.base.id) return finish("possible_alias_write");
				if (store.offset >= address.displacement+8 || store.offset+store.bytes <= address.displacement) continue;
				if (store.offset != address.displacement || store.bytes != 8 || Width(store.source) != 8) return finish("partial_spill_write");
				if (store.source == ARM64_REG_XZR) {
					result.source = source(n, "literal"); result.source->bits = 0; return finish("matched");
				}
				const auto stored = Register(store.source);
				if (!stored) return finish("unsupported_spill_source");
				if (invariantNull == stored && *stored == 22) { result.source = source(n, "runtime_null"); result.source->bits=22; return finish("matched"); }
				reg = *stored; memory.reset(); break;
			}
			continue;
		}
		if (CompareOrNop(i) && !d.writeback) continue;
		if (extended && !memory && profile.heapBitsRegister == ARM64_REG_X28 && i.id == ARM64_INS_ADD && d.op_count == 3 &&
			d.operands[0].type == ARM64_OP_REG && d.operands[1].type == ARM64_OP_REG && d.operands[2].type == ARM64_OP_REG &&
			Register(d.operands[0].reg) == reg && d.operands[0].reg == d.operands[1].reg && Width(d.operands[0].reg) == 8 &&
			d.operands[2].reg == ARM64_REG_X28 && d.operands[2].shift.type == ARM64_SFT_LSL && d.operands[2].shift.value == 32 &&
			!d.update_flags && !d.writeback) { compressed = true; continue; }
		const auto lowered = LowerArm64(i);
		if (!lowered) return finish("unsupported_instruction");
		const auto effects = NativeIr::GetEffects(*lowered);
		if (effects.unlistedRegistersMayChange || effects.control != NativeIr::ControlEffect::Fallthrough) return finish("unknown_effects");
		if (memory) {
			if (effects.destination && effects.destination->id == memory->base.id) return finish("load_base_changed");
			if (effects.memory != NativeIr::MemoryEffect::None && effects.memory != NativeIr::MemoryEffect::Read) return finish("unknown_memory_effects");
			continue;
		}
		if (!effects.destination || effects.destination->id != reg) continue;
		if (compressed && !std::holds_alternative<NativeIr::Load>(lowered->operation)) return finish("compressed_definition");
		if (effects.destination->storageBits != 64 || (effects.destination->valueBits != 64 && !(compressed && effects.destination->valueBits == 32))) return finish("narrow_definition");
		if (const auto* assign = std::get_if<NativeIr::Assign>(&lowered->operation)) {
			if (const auto* input = std::get_if<NativeIr::RegisterView>(&assign->value); input && input->bits == 64 && input->id < 31) {
				if (invariantNull == input->id && input->id == 22) { result.source = source(n,"runtime_null"); result.source->bits=22; return finish("matched"); }
				reg = input->id;
			}
			else if (const auto* literal = std::get_if<NativeIr::Literal>(&assign->value)) {
				result.source = source(n, "literal"); result.source->bits = literal->value; return finish("matched");
			} else return finish("unsupported_copy");
		} else if (const auto* load = std::get_if<NativeIr::Load>(&lowered->operation); load && (load->bytes == 8 || (compressed && load->bytes == 4)) && load->address.base.bits == 64) {
			fallback = source(n, compressed && load->bytes == 4 ? "load_compressed" : "load"); fallback->load = load->address;
			if (load->address.base.id != 29 || load->bytes != 8) return finish("load_endpoint");
			memory = load->address;
		} else return finish("computed_definition");
	}
	if (extended && !compressed && !memory && reg < 15 && !result.source) {
		result.source = source(0, "entry_register"); result.source->bits = reg;
	}
	return finish("payload_entry");
}
}
