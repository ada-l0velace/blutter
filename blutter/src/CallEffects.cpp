#include "CallEffects.h"
#include <algorithm>
#include <array>
#include <bit>
#include <deque>
#include <memory>
#include <sstream>

namespace SnapshotAnalysis {
namespace {
enum Kind { Unknown, Stack, CallerFP, CallerLR, Pool, Code, Entry, Heap, Word, Input };
struct Alias {
	Kind kind = Unknown;
	int64_t offset = 0;
	int64_t begin = 0, end = 0;
	bool operator==(const Alias&) const = default;
};
struct State {
	std::array<Alias, 31> regs;
	std::map<int64_t, Alias> slots;
	bool operator==(const State&) const = default;
};
int Reg(arm64_reg r) {
	if (r >= ARM64_REG_X0 && r <= ARM64_REG_X28) return r - ARM64_REG_X0;
	if (r == ARM64_REG_X29) return 29;
	if (r == ARM64_REG_X30) return 30;
	if (r >= ARM64_REG_W0 && r <= ARM64_REG_W30) return r - ARM64_REG_W0;
	return -1;
}
unsigned Bytes(arm64_reg r) {
	if ((r >= ARM64_REG_W0 && r <= ARM64_REG_W30) || r == ARM64_REG_WZR) return 4;
	if (Reg(r) >= 0 || r == ARM64_REG_XZR || (r >= ARM64_REG_D0 && r <= ARM64_REG_D31)) return 8;
	if (r >= ARM64_REG_Q0 && r <= ARM64_REG_Q31) return 16;
	if (r >= ARM64_REG_S0 && r <= ARM64_REG_S31) return 4;
	if (r >= ARM64_REG_H0 && r <= ARM64_REG_H31) return 2;
	if (r >= ARM64_REG_B0 && r <= ARM64_REG_B31) return 1;
	return 0;
}
Alias Read(const State& state, arm64_reg r) {
	if (r == ARM64_REG_XZR || r == ARM64_REG_WZR) return {Word, 0};
	const auto number = Reg(r);
	if (number < 0) return {};
	auto value = state.regs[number];
	if (Bytes(r) == 4) {
		if (value.kind != Word) return {};
		value.offset = static_cast<uint32_t>(value.offset);
	}
	return value;
}
bool Group(const cs_insn& i, uint8_t g) {
	return std::find(i.detail->groups, i.detail->groups + i.detail->groups_count, g) != i.detail->groups + i.detail->groups_count;
}
bool Load(unsigned id) {
	switch (id) {
	case ARM64_INS_LDR: case ARM64_INS_LDUR: case ARM64_INS_LDRB: case ARM64_INS_LDURB:
	case ARM64_INS_LDRH: case ARM64_INS_LDURH: case ARM64_INS_LDRSB: case ARM64_INS_LDURSB:
	case ARM64_INS_LDRSH: case ARM64_INS_LDURSH: case ARM64_INS_LDRSW: case ARM64_INS_LDURSW:
	case ARM64_INS_LDP: case ARM64_INS_LDNP: case ARM64_INS_LDPSW: return true;
	default: return false;
	}
}
bool Pure(unsigned id) {
	// Positive register-only subset. Unknown/system/atomic instructions fail.
	switch (id) {
	case ARM64_INS_NOP: case ARM64_INS_MOV: case ARM64_INS_MOVZ: case ARM64_INS_MOVN: case ARM64_INS_MOVK:
	case ARM64_INS_ADD: case ARM64_INS_SUB: case ARM64_INS_ADDS: case ARM64_INS_SUBS:
	case ARM64_INS_AND: case ARM64_INS_ANDS: case ARM64_INS_ORR: case ARM64_INS_EOR: case ARM64_INS_BIC:
	case ARM64_INS_MVN: case ARM64_INS_NEG: case ARM64_INS_MUL: case ARM64_INS_MADD: case ARM64_INS_MSUB:
	case ARM64_INS_SDIV: case ARM64_INS_UDIV: case ARM64_INS_LSL: case ARM64_INS_LSR: case ARM64_INS_ASR:
	case ARM64_INS_UBFX: case ARM64_INS_SBFX: case ARM64_INS_SXTW: case ARM64_INS_UXTW:
	case ARM64_INS_CMP: case ARM64_INS_CMN: case ARM64_INS_TST: case ARM64_INS_CCMP: case ARM64_INS_CCMN:
	case ARM64_INS_CSEL: case ARM64_INS_CSINC: case ARM64_INS_CSINV: case ARM64_INS_CSNEG:
	case ARM64_INS_CSET: case ARM64_INS_CSETM: case ARM64_INS_CINC: case ARM64_INS_CNEG:
	case ARM64_INS_ADR: case ARM64_INS_ADRP:
	case ARM64_INS_FMOV: case ARM64_INS_FADD: case ARM64_INS_FSUB: case ARM64_INS_FMUL: case ARM64_INS_FDIV:
	case ARM64_INS_FNEG: case ARM64_INS_FABS: case ARM64_INS_FCMP: case ARM64_INS_FCMPE:
	case ARM64_INS_FCVT: case ARM64_INS_FCVTZS: case ARM64_INS_FCVTZU: case ARM64_INS_SCVTF: case ARM64_INS_UCVTF:
		return true;
	default: return false;
	}
}
bool LeafMath(const cs_insn* code, size_t count, const Profile& profile) {
	const auto& c = profile.leafMathContract;
	if (count < 13 || c.size() != 4 || profile.threadRegister != ARM64_REG_X26 || profile.poolRegister != ARM64_REG_X27) return false;
	for (unsigned j = 0; j < 3; ++j) if (c[j] < 0 || c[j] >= 32768 || c[j] % 8) return false;
	if (c[3] < 0 || c[3] > 65535) return false;
	const uint32_t words[] = {0xa9bf79fd, 0xaa0f03fd, 0x927cedef, 0x910001ff,
		0xf9400350U | (static_cast<uint32_t>(c[0] / 8) << 10),
		0xf9000350U | (static_cast<uint32_t>(c[1] / 8) << 10), 0xd63f0200,
		0xd2800010U | (static_cast<uint32_t>(c[3]) << 5),
		0xf9000350U | (static_cast<uint32_t>(c[1] / 8) << 10),
		0xf9400350U | (static_cast<uint32_t>(c[2] / 8) << 10), 0xd140061f, 0xaa1d03ef, 0xa8c179fd};
	for (size_t n = 0; n < 13; ++n) {
		const auto* b = code[n].bytes;
		if (code[n].size != 4 || (uint32_t{b[0]} | uint32_t{b[1]} << 8 | uint32_t{b[2]} << 16 | uint32_t{b[3]} << 24) != words[n]) return false;
	}
	return true;
}
bool Merge(std::optional<State>& to, const State& from) {
	if (!to) { to = from; return true; }
	auto result = *to;
	for (size_t r = 0; r < 31; ++r) if (result.regs[r] != from.regs[r]) result.regs[r] = {};
	for (auto it = result.slots.begin(); it != result.slots.end();)
		if (!from.slots.contains(it->first) || from.slots.at(it->first) != it->second) it = result.slots.erase(it); else ++it;
	if (result == *to) return false;
	to = std::move(result); return true;
}
void JsonState(std::ostream& out, uint64_t site, const State& state) {
	out << '[' << site << ",[";
	bool first = true;
	for (unsigned r = 0; r < 31; ++r) if (state.regs[r].kind != Unknown) {
		if (!first) out << ',';
		first = false;
		const auto& value = state.regs[r];
		out << '[' << r << ',' << value.kind << ',' << value.offset;
		if (value.kind == Heap) out << ',' << value.begin << ',' << value.end;
		out << ']';
	}
	out << "],["; first = true;
	for (const auto& [offset, value] : state.slots) {
		if (!first) out << ',';
		first = false;
		out << '[' << offset << ',' << value.kind << ',' << value.offset;
		if (value.kind == Heap) out << ',' << value.begin << ',' << value.end;
		out << ']';
	}
	out << "]]";
}
}

CallEffectResult AnalyzeCallEffects(const std::map<uint64_t, std::vector<uint8_t>>& bytes, const Profile& profile) {
	CallEffectResult result;
	if (profile.poolRegister != ARM64_REG_X27 || profile.threadRegister != ARM64_REG_X26) return result;
	for (const auto& [entry, contract] : profile.nonReturningCalls)
		if (contract != "range_error_without_fpu" || profile.allocationReturns.contains(entry) || profile.framePreservingCalls.contains(entry)) return result;
	for (const auto& [entry, interval] : profile.allocationBodyBounds)
		if (!profile.allocationReturns.contains(entry) || interval.first < 7 || interval.first > interval.second || interval.second > (1 << 20)) return result;
	const auto& array = profile.arrayBodyContract;
	if (!array.empty() && (array.size() != 5 || !profile.allocationReturns.contains(array[0]) || array[1] < 0 || array[1] > 14 ||
		array[2] < 7 || array[2] > (1 << 20) || (array[3] != 4 && array[3] != 8) || array[4] != 1)) return result;
	struct Decoder { csh handle = 0; ~Decoder() { if (handle) cs_close(&handle); } } decoder;
	if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &decoder.handle) != CS_ERR_OK ||
		cs_option(decoder.handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) return result;
	std::map<uint64_t, unsigned> depths;
	std::set<uint64_t> visiting, failed;
	std::function<bool(uint64_t)> prove = [&](uint64_t entry) {
		if (profile.nonReturningCalls.contains(entry)) return false;
		if (profile.allocationReturns.contains(entry) || profile.framePreservingCalls.contains(entry) || depths.contains(entry)) return true;
		if (!bytes.contains(entry) || failed.contains(entry) || visiting.contains(entry) || visiting.size() >= 8 || result.attempted >= 16384) return false;
		++result.attempted;
		const auto& code = bytes.at(entry);
		if (code.empty() || code.size() > 4096 || code.size() % 4 || entry > UINT64_MAX - code.size()) return false;
		cs_insn* raw = nullptr;
		const auto count = cs_disasm(decoder.handle, code.data(), code.size(), entry, 0, &raw);
		const std::shared_ptr<cs_insn> owner(raw, [count](cs_insn* p) { cs_free(p, count); });
		if (count * 4 != code.size()) { failed.insert(entry); return false; }
		// Keep exact input-bit aliases confined to call-free bodies: a moving GC
		// can update saved pointers. More general returns require a richer model.
		const bool trackInputs = profile.wordReturnRegister == ARM64_REG_X0 &&
			std::none_of(raw, raw + count, [](const cs_insn& i) { return Group(i, CS_GRP_CALL) || Group(i, CS_GRP_INT); });
		bool poolFixed = true, threadFixed = true, reservedFixed = true;
		for (size_t n = 0; n < count; ++n) for (unsigned j = 0; j < raw[n].detail->arm64.op_count; ++j) {
			const auto& op = raw[n].detail->arm64.operands[j];
			const auto r = op.type == ARM64_OP_REG && op.access & CS_AC_WRITE ? Reg(op.reg) : op.type == ARM64_OP_MEM && raw[n].detail->arm64.writeback ? Reg(op.mem.base) : -1;
			poolFixed &= r != 27; threadFixed &= r != 26;
			reservedFixed &= r != 21 && r != 22 && r != 26 && r != 27 && r != 28;
		}
		if (!reservedFixed) { failed.insert(entry); return false; }
		visiting.insert(entry);
		std::vector<std::optional<State>> incoming(count);
		State seed; seed.regs[15] = {Stack, 0}; seed.regs[29] = {CallerFP}; seed.regs[30] = {CallerLR};
		if (poolFixed) seed.regs[27] = {Pool};
		incoming[0] = seed;
		std::deque<size_t> pending{0};
		bool valid = true, returned = false;
		unsigned depth = 1;
		size_t localSteps = 0;
		while (valid && !pending.empty()) {
			if (++localSteps > 20000 || ++result.steps > 2000000) { valid = false; break; }
			const auto n = pending.front(); pending.pop_front();
			const auto& i = raw[n]; const auto& d = i.detail->arm64;
			auto state = *incoming[n]; const auto before = state;
			if (threadFixed && LeafMath(raw + n, count - n, profile)) {
				if (n + 13 >= count || before.regs[15].kind != Stack || before.regs[15].offset < -(1 << 20) + 16) { valid = false; break; }
				state.regs.fill({});
				for (const unsigned r : {15U, 29U, 30U}) state.regs[r] = before.regs[r];
				if (poolFixed) state.regs[27] = {Pool};
				if (Merge(incoming[n+13], state)) pending.push_back(n+13);
				continue;
			}
			std::set<int> writes;
			for (unsigned j = 0; j < i.detail->regs_write_count; ++j) if (const auto r = Reg(static_cast<arm64_reg>(i.detail->regs_write[j])); r >= 0) writes.insert(r);
			const bool flags = i.id == ARM64_INS_CMP || i.id == ARM64_INS_CMN || i.id == ARM64_INS_TST || i.id == ARM64_INS_CCMP || i.id == ARM64_INS_CCMN;
			for (unsigned j = 0; j < d.op_count; ++j) if (!flags && d.operands[j].type == ARM64_OP_REG && d.operands[j].access & CS_AC_WRITE)
				if (const auto r = Reg(d.operands[j].reg); r >= 0) writes.insert(r);
			for (const auto r : writes) state.regs[r] = {};
			for (unsigned j = 0; j < d.op_count; ++j)
				if (d.operands[j].type == ARM64_OP_REG && d.operands[j].access & CS_AC_WRITE &&
					(d.operands[j].reg == ARM64_REG_SP || d.operands[j].reg == ARM64_REG_WSP)) valid = false;
			if (!valid) break;
			const bool call = i.id == ARM64_INS_BL || i.id == ARM64_INS_BLR;
			const bool branch = i.id == ARM64_INS_B || i.id == ARM64_INS_CBZ || i.id == ARM64_INS_CBNZ || i.id == ARM64_INS_TBZ || i.id == ARM64_INS_TBNZ;
			if (call) {
				if (d.op_count != 1 || before.regs[15].kind != Stack || before.regs[15].offset > -16) { valid = false; break; }
				const int targetReg = d.operands[0].type == ARM64_OP_REG ? Reg(d.operands[0].reg) : -1;
				if (i.id == ARM64_INS_BL ? d.operands[0].type != ARM64_OP_IMM : targetReg < 0 || before.regs[targetReg].kind != Entry) { valid = false; break; }
				const auto target = static_cast<uint64_t>(i.id == ARM64_INS_BL ? d.operands[0].imm : before.regs[targetReg].offset);
				if (profile.nonReturningCalls.contains(target)) continue; // Exceptional exit; no returning effect is claimed.
				for (unsigned r = 0; r < 31; ++r) if (r != 15 && r != 29 && before.regs[r].kind == Stack) valid = false;
				if (!valid || !prove(target)) { valid = false; break; }
				if (depths.contains(target)) depth = std::max(depth, depths.at(target) + 1);
				if (depth > 8) { valid = false; break; }
				state.regs.fill({}); state.regs[15] = before.regs[15]; state.regs[29] = before.regs[29];
				if (poolFixed) state.regs[27] = {Pool};
				// Only SDK-reviewed preserved registers survive a call. Interior
				// heap addresses may be stale after a moving collection.
				if (const auto mask = profile.preservedCallRegisters.find(target); mask != profile.preservedCallRegisters.end())
					for (unsigned r = 0; r < 31; ++r) if ((mask->second & (1U << r)) && r != 15 && r != 29 && r != 30)
						if (before.regs[r].kind != Heap || before.regs[r].offset == 0) state.regs[r] = before.regs[r];
				for (auto it = state.slots.begin(); it != state.slots.end();)
					if (it->second.kind == Heap && it->second.offset != 0) it = state.slots.erase(it); else ++it;
				const int resultReg = Reg(profile.allocationResultRegister);
				if (resultReg >= 0) {
					if (const auto bound = profile.allocationBodyBounds.find(target); bound != profile.allocationBodyBounds.end())
						state.regs[resultReg] = {Heap, 0, bound->second.first, bound->second.second};
					if (!array.empty() && target == static_cast<uint64_t>(array[0])) {
						const auto length = before.regs[array[1]];
						if (length.kind == Word && length.offset >= 0 && !(length.offset & 1) &&
							(length.offset >> array[4]) <= ((1 << 20) - array[2]) / array[3])
							state.regs[resultReg] = {Heap, 0, array[2], array[2] + (length.offset >> array[4]) * array[3]};
					}
				}
			} else if (i.id == ARM64_INS_RET) {
				if (d.op_count != 0 && (d.op_count != 1 || d.operands[0].reg != ARM64_REG_X30)) valid = false;
				valid &= before.regs[15] == Alias{Stack, 0} && before.regs[29] == Alias{CallerFP} && before.regs[30] == Alias{CallerLR};
				returned |= valid;
				continue;
			} else if (i.id == ARM64_INS_BRK || i.id == ARM64_INS_HLT) {
				continue; // No normal return on this path; no non-return inference is exported.
			} else if (branch) {
				// Successors are checked below; conditions are never assumed constant.
			} else {
				bool memory = false;
				for (unsigned j = 0; j < d.op_count; ++j) if (d.operands[j].type == ARM64_OP_MEM) {
					memory = true; const auto& m = d.operands[j].mem;
					const int base = Reg(m.base);
					const bool load = Load(i.id);
					const bool store = i.id == ARM64_INS_STR || i.id == ARM64_INS_STUR || i.id == ARM64_INS_STP || i.id == ARM64_INS_STRB || i.id == ARM64_INS_STURB || i.id == ARM64_INS_STRH || i.id == ARM64_INS_STURH;
					if (!load && !store) { valid = false; break; }
					const bool pair = i.id == ARM64_INS_STP || i.id == ARM64_INS_LDP || i.id == ARM64_INS_LDNP || i.id == ARM64_INS_LDPSW;
					if (j != (pair ? 2U : 1U)) { valid = false; break; }
					unsigned width = Bytes(d.operands[0].reg);
					if (i.id == ARM64_INS_STRB || i.id == ARM64_INS_STURB) width = 1;
					if (i.id == ARM64_INS_STRH || i.id == ARM64_INS_STURH) width = 2;
					if (pair && Bytes(d.operands[1].reg) != width) { valid = false; break; }
					if (pair && load && d.operands[0].reg == d.operands[1].reg) { valid = false; break; }
					const bool stack = base >= 0 && before.regs[base].kind == Stack && m.index == ARM64_REG_INVALID;
					int64_t at = 0;
					if (stack) at = before.regs[base].offset + m.disp;
					if (d.writeback) {
						if (!stack || base != 15) { valid = false; break; }
						for (unsigned part = 0; part < (pair ? 2U : 1U); ++part)
							if (Reg(d.operands[part].reg) == base) valid = false;
						if (!valid) break;
						const bool post = j + 2 == d.op_count && d.operands[j+1].type == ARM64_OP_IMM;
						if (!post && j + 1 != d.op_count) { valid = false; break; }
						const auto delta = post ? d.operands[j+1].imm : m.disp;
						if (delta < -(1 << 20) || delta > (1 << 20)) { valid = false; break; }
						state.regs[15] = {Stack, before.regs[15].offset + delta};
					}
					if (store) {
						const auto low = std::min(before.regs[15].offset, state.regs[15].offset);
						const auto size = width * (pair ? 2 : 1);
						const auto heap = base >= 0 ? before.regs[base] : Alias{};
						const auto heapAt = heap.kind == Heap ? heap.offset + m.disp : 0;
						if (heap.kind == Heap && m.index == ARM64_REG_INVALID && !d.writeback && width &&
							heapAt >= heap.begin && heapAt <= heap.end - size) continue;
						if (!stack || !width || before.regs[15].kind != Stack || state.regs[15].kind != Stack || at < low || at > -static_cast<int64_t>(size)) { valid = false; break; }
						for (auto it = state.slots.begin(); it != state.slots.end();)
							if (at < it->first + 8 && it->first < at + size) it = state.slots.erase(it); else ++it;
						if (width == 8) for (unsigned part = 0; part < (pair ? 2U : 1U); ++part) {
							const int r = Reg(d.operands[part].reg);
							if (r >= 0 && before.regs[r].kind != Unknown) state.slots[at + part * 8] = before.regs[r];
						}
					} else if (stack && width == 8 && (i.id == ARM64_INS_LDR || i.id == ARM64_INS_LDUR || i.id == ARM64_INS_LDP || i.id == ARM64_INS_LDNP)) {
						for (unsigned part = 0; part < (pair ? 2U : 1U); ++part) {
							const int r = Reg(d.operands[part].reg);
							if (r >= 0 && state.slots.contains(at + part * 8)) state.regs[r] = state.slots.at(at + part * 8);
							else if (r >= 0 && trackInputs && at + part * 8 >= 0 && at + part * 8 <= 248 && (at + part * 8) % 8 == 0)
								state.regs[r] = {Input, at + part * 8};
						}
					} else if (!d.writeback && m.index == ARM64_REG_INVALID && (i.id == ARM64_INS_LDR || i.id == ARM64_INS_LDUR) && Bytes(d.operands[0].reg) == 8 && base >= 0 && Reg(d.operands[0].reg) >= 0) {
						const auto source = before.regs[base]; const auto dst = Reg(d.operands[0].reg);
						if (source.kind == Pool && profile.poolSlotSize == 8) {
							const auto offset = source.offset + m.disp - profile.poolDataOffset;
							if (offset >= 0 && offset % 8 == 0 && offset / 8 < profile.poolLength) state.regs[dst] = {Code, offset / 8};
						} else if (source.kind == Code && profile.describePoolSlot) {
							const auto slot = profile.describePoolSlot(source.offset);
							if (slot.entryPoints.contains(m.disp) && slot.entryPoints.at(m.disp) <= INT64_MAX) state.regs[dst] = {Entry, static_cast<int64_t>(slot.entryPoints.at(m.disp))};
						}
					}
				}
				if (!valid) break;
				if (!memory) {
					if (!Pure(i.id)) { valid = false; break; }
					const int dst = d.op_count && d.operands[0].type == ARM64_OP_REG ? Reg(d.operands[0].reg) : -1;
					if (dst >= 0 && writes.contains(dst)) {
						const auto bytes = Bytes(d.operands[0].reg);
						if (i.id == ARM64_INS_MOV && d.op_count == 2) {
							if (d.operands[1].type == ARM64_OP_REG && Bytes(d.operands[1].reg) == bytes) state.regs[dst] = Read(before, d.operands[1].reg);
							if (d.operands[1].type == ARM64_OP_IMM) state.regs[dst] = {Word, d.operands[1].imm};
						} else if ((i.id == ARM64_INS_MOVZ || i.id == ARM64_INS_MOVN || i.id == ARM64_INS_MOVK) && d.op_count == 2 && d.operands[1].type == ARM64_OP_IMM &&
							d.operands[1].imm >= 0 && d.operands[1].imm <= 65535 && (!d.operands[1].shift.type || d.operands[1].shift.type == ARM64_SFT_LSL)) {
							const auto shift = d.operands[1].shift.type ? d.operands[1].shift.value : 0;
							if (shift < bytes * 8 && shift % 16 == 0) {
								const auto part = static_cast<uint64_t>(d.operands[1].imm) << shift;
								if (i.id != ARM64_INS_MOVK || before.regs[dst].kind == Word) {
									const auto word = i.id == ARM64_INS_MOVN ? ~part : i.id == ARM64_INS_MOVK ? (std::bit_cast<uint64_t>(before.regs[dst].offset) & ~(uint64_t{65535} << shift)) | part : part;
									state.regs[dst] = {Word, std::bit_cast<int64_t>(word)};
								}
							}
						} else if ((i.id == ARM64_INS_ADD || i.id == ARM64_INS_SUB) && d.op_count == 3 && d.operands[1].type == ARM64_OP_REG && Bytes(d.operands[1].reg) == bytes &&
							d.operands[2].type == ARM64_OP_IMM && d.operands[2].imm >= 0 && d.operands[2].imm <= 4095 &&
							(!d.operands[2].shift.type || (d.operands[2].shift.type == ARM64_SFT_LSL && d.operands[2].shift.value == 12))) {
							const auto base = Read(before, d.operands[1].reg);
							const auto delta = d.operands[2].imm << (d.operands[2].shift.type ? 12 : 0);
							if (base.kind == Word) {
								const auto bits = std::bit_cast<uint64_t>(base.offset);
								state.regs[dst] = {Word, std::bit_cast<int64_t>(i.id == ARM64_INS_ADD ? bits + delta : bits - delta)};
							} else if (bytes == 8 && (base.kind == Stack || base.kind == Pool || base.kind == Heap)) {
								state.regs[dst] = base; state.regs[dst].offset += i.id == ARM64_INS_ADD ? delta : -delta;
							}
						}
						if (bytes == 4) {
							if (state.regs[dst].kind == Word) state.regs[dst].offset = static_cast<uint32_t>(state.regs[dst].offset);
							else state.regs[dst] = {};
						}
					}
				}
			}
			// Optional input facts must not consume the existing frame-proof budget.
			if (state.slots.size() > 128)
				for (auto it = state.slots.begin(); it != state.slots.end();)
					if (it->second.kind == Input) it = state.slots.erase(it); else ++it;
			if (state.regs[15].kind != Stack || state.regs[15].offset < -(1 << 20) || state.regs[15].offset > 0 || state.slots.size() > 128) { valid = false; break; }
			for (const auto& value : state.regs) if ((value.kind == Stack || value.kind == Pool || value.kind == Heap) && (value.offset < -(1 << 20) || value.offset > (1 << 20))) valid = false;
			for (auto it = state.slots.begin(); it != state.slots.end();)
				if (it->first < state.regs[15].offset) it = state.slots.erase(it); else ++it;
			std::vector<uint64_t> successors;
			if (branch) {
				if (!d.op_count || d.operands[d.op_count-1].type != ARM64_OP_IMM) { valid = false; break; }
				successors.push_back(d.operands[d.op_count-1].imm);
				if (i.id != ARM64_INS_B || (d.cc != ARM64_CC_INVALID && d.cc != ARM64_CC_AL)) successors.push_back(i.address + 4);
			} else successors.push_back(i.address + 4);
			for (const auto next : successors) {
				if (next < entry || next >= entry + code.size() || (next - entry) % 4) { valid = false; break; }
				if (Merge(incoming[(next-entry)/4], state)) pending.push_back((next-entry)/4);
			}
		}
		visiting.erase(entry);
		if (!valid || !returned || !pending.empty()) { failed.insert(entry); return false; }
		depths[entry] = depth;
		// Inspect the converged pre-states, never a transient worklist result.
		std::optional<int64_t> forwarded;
		bool forwards = trackInputs;
		for (size_t n = 0; n < count; ++n) if (incoming[n] && raw[n].id == ARM64_INS_RET) {
			const auto& value = incoming[n]->regs[0];
			if (value.kind != Input || (forwarded && *forwarded != value.offset)) forwards = false;
			else forwarded = value.offset;
		}
		std::ostringstream out; out << "{\"payload\":" << entry << ",\"depth\":" << depth << ",\"states\":[";
		bool first = true;
		for (size_t n = 0; n < count; ++n) if (incoming[n]) { if (!first) out << ','; first = false; JsonState(out, entry + n * 4, *incoming[n]); }
		out << ']';
		if (forwards && forwarded) {
			result.forwardedInputs.emplace(entry, *forwarded);
			out << ",\"return_input\":" << *forwarded;
		}
		out << '}';
		result.certificates.emplace(entry, out.str()); return true;
	};
	for (const auto& [entry, code] : bytes) { if (result.steps >= 2000000) break; prove(entry); }
	return result;
}
}
