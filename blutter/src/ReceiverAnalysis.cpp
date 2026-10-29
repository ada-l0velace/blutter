#include "ReceiverAnalysis.h"
#include <algorithm>
#include <array>
#include <bit>
#include <deque>
#include <limits>
#include <sstream>
#include <span>

namespace SnapshotAnalysis {
namespace {
enum Kind { Unknown, Word, Range, Object, Header, Pool, Dispatch, Target, Stack, Thread, HeapAddress };
struct Fact {
	Kind kind = Unknown;
	uint64_t value = 0, aux = 0, origin = 0;
	std::vector<uint64_t> proof;
	bool operator==(const Fact&) const = default;
};
struct Compare {
	int reg = -1;
	unsigned width = 0;
	uint64_t value = 0, site = 0;
	bool operator==(const Compare&) const = default;
};
struct State {
	std::array<Fact, 31> regs;
	Compare compare;
	// Input values are immutable analysis bindings. Writes kill liveness;
	// they never recreate an original caller input or introduce a new value.
	std::set<int64_t> liveInputs;
	// Heap classes of full-width spills in the active payload frame. Values
	// and object identities are deliberately not reconstructed from a class.
	std::map<int64_t, Fact> spills;
	bool operator==(const State&) const = default;
};
struct Block { size_t first, end; bool entry; std::optional<State> in; };
int Number(arm64_reg r)
{
	if (r >= ARM64_REG_X0 && r <= ARM64_REG_X28) return r - ARM64_REG_X0;
	if (r >= ARM64_REG_W0 && r <= ARM64_REG_W30) return r - ARM64_REG_W0;
	if (r == ARM64_REG_X29) return 29;
	if (r == ARM64_REG_X30) return 30;
	return -1;
}
unsigned Width(arm64_reg r)
{
	return (r >= ARM64_REG_W0 && r <= ARM64_REG_W30) || r == ARM64_REG_WZR ? 32 : Number(r) >= 0 || r == ARM64_REG_XZR ? 64 : 0;
}
uint64_t Mask(unsigned width) { return width == 64 ? UINT64_MAX : (uint64_t{1} << width) - 1; }
bool Group(const cs_insn& i, uint8_t group)
{
	return std::find(i.detail->groups, i.detail->groups + i.detail->groups_count, group) != i.detail->groups + i.detail->groups_count;
}
bool Terminal(const cs_insn& i) { return Group(i, CS_GRP_RET) || i.id == ARM64_INS_BRK || i.id == ARM64_INS_HLT; }
bool OpaqueMemory(const cs_insn& i) { return i.id == ARM64_INS_DC || i.id == ARM64_INS_SYS || i.id == ARM64_INS_SYSL; }
bool MemoryWrite(const cs_insn& i, const cs_arm64_op& operand)
{
	if (operand.access & CS_AC_WRITE) return true;
	// Capstone 5 marks some atomic stores' memory operands as reads. Only
	// positively recognized loads/prefetches are read-only; unknown forms kill.
	switch (i.id) {
	case ARM64_INS_LDR: case ARM64_INS_LDRB: case ARM64_INS_LDRH:
	case ARM64_INS_LDRSB: case ARM64_INS_LDRSH: case ARM64_INS_LDRSW:
	case ARM64_INS_LDUR: case ARM64_INS_LDURB: case ARM64_INS_LDURH:
	case ARM64_INS_LDURSB: case ARM64_INS_LDURSH: case ARM64_INS_LDURSW:
	case ARM64_INS_LDTR: case ARM64_INS_LDTRB: case ARM64_INS_LDTRH:
	case ARM64_INS_LDTRSB: case ARM64_INS_LDTRSH: case ARM64_INS_LDTRSW:
	case ARM64_INS_LDP: case ARM64_INS_LDNP: case ARM64_INS_LDPSW:
	case ARM64_INS_PRFM: case ARM64_INS_PRFUM: return false;
	default: return true;
	}
}
std::set<int> Writes(const cs_insn& i)
{
	std::set<int> result;
	for (unsigned n = 0; n < i.detail->regs_write_count; ++n) {
		const auto r = Number(static_cast<arm64_reg>(i.detail->regs_write[n]));
		if (r >= 0) result.insert(r);
	}
	for (unsigned n = 0; n < i.detail->arm64.op_count; ++n) {
		const auto& op = i.detail->arm64.operands[n];
		// Capstone 5 labels CMP/CMN/TST's first source as a write after
		// aliasing the discarded destination. These instructions only set flags.
		const bool flagsOnly = i.id == ARM64_INS_CMP || i.id == ARM64_INS_CMN || i.id == ARM64_INS_TST || i.id == ARM64_INS_CCMP || i.id == ARM64_INS_CCMN;
		if (!flagsOnly && op.type == ARM64_OP_REG && (op.access & CS_AC_WRITE) && Number(op.reg) >= 0) result.insert(Number(op.reg));
		if (op.type == ARM64_OP_MEM && i.detail->arm64.writeback && Number(op.mem.base) >= 0) result.insert(Number(op.mem.base));
	}
	return result;
}
std::vector<uint64_t> Union(const std::vector<uint64_t>& a, const std::vector<uint64_t>& b)
{
	auto result = a;
	result.insert(result.end(), b.begin(), b.end());
	std::sort(result.begin(), result.end());
	result.erase(std::unique(result.begin(), result.end()), result.end());
	return result;
}
Fact Proven(Fact f, uint64_t site)
{
	f.proof = Union(f.proof, {site});
	return f.proof.size() <= 128 ? f : Fact{};
}
Fact Read(const State& s, arm64_reg r)
{
	if (r == ARM64_REG_XZR || r == ARM64_REG_WZR) return {Word};
	const auto n = Number(r);
	if (n < 0) return {};
	auto f = s.regs[n];
	if (Width(r) == 32) {
		if (f.kind == Word) f.value &= UINT32_MAX;
		else if (f.kind == Range) f.value = std::min(f.value, uint64_t{UINT32_MAX});
		else if (f.kind == Header) return f;
		else return {Range, UINT32_MAX};
	}
	return f;
}
std::optional<int64_t> Add(int64_t a, int64_t b)
{
	if ((b > 0 && a > INT64_MAX - b) || (b < 0 && a < INT64_MIN - b)) return {};
	return a + b;
}
bool HeapField(const Fact& base, const cs_arm64_op& memory, bool writeback, int64_t header)
{
	if (writeback || memory.mem.index != ARM64_REG_INVALID || (base.kind != Object && base.kind != HeapAddress)) return false;
	const auto offset = Add(base.kind == HeapAddress ? std::bit_cast<int64_t>(base.value) : 0, memory.mem.disp);
	return offset && *offset >= header + 8;
}
Fact Operand(const State& s, const cs_arm64_op& op, unsigned width)
{
	if (op.ext != ARM64_EXT_INVALID) return {};
	if (op.type == ARM64_OP_IMM && op.imm >= 0 &&
		(op.shift.type == ARM64_SFT_INVALID || (op.shift.type == ARM64_SFT_LSL && op.shift.value == 12)))
		return {Word, static_cast<uint64_t>(op.imm) << (op.shift.type == ARM64_SFT_INVALID ? 0 : 12)};
	if (op.type == ARM64_OP_REG && Width(op.reg) == width &&
		(op.shift.type == ARM64_SFT_INVALID || (op.shift.type == ARM64_SFT_LSL && op.shift.value == 0))) return Read(s, op.reg);
	return {};
}
Fact Meet(const Fact& a, const Fact& b)
{
	if (a.kind == Unknown || b.kind == Unknown) return {};
	Fact result;
	if (a.kind == b.kind && a.value == b.value && a.aux == b.aux && a.origin == b.origin) result = a;
	else if ((a.kind == Word || a.kind == Range) && (b.kind == Word || b.kind == Range))
		result = {Range, std::max(a.value, b.value)};
	else return {};
	result.proof = Union(a.proof, b.proof);
	return result.proof.size() <= 128 ? result : Fact{};
}
bool Join(std::optional<State>& destination, const State& source)
{
	if (!destination) { destination = source; return true; }
	auto merged = *destination;
	for (unsigned r = 0; r < 31; ++r) merged.regs[r] = Meet(merged.regs[r], source.regs[r]);
	for (auto it = merged.liveInputs.begin(); it != merged.liveInputs.end();)
		if (!source.liveInputs.contains(*it)) it = merged.liveInputs.erase(it); else ++it;
	for (auto it = merged.spills.begin(); it != merged.spills.end();) {
		const auto incoming = source.spills.find(it->first);
		const auto value = incoming == source.spills.end() ? Fact{} : Meet(it->second, incoming->second);
		if (value.kind != Object) it = merged.spills.erase(it);
		else { it->second = value; ++it; }
	}
	if (merged.compare != source.compare) merged.compare = {};
	if (merged == *destination) return false;
	destination = std::move(merged);
	return true;
}
void JsonFact(std::ostream& out, unsigned reg, const Fact& f)
{
	out << '[' << reg << ',' << f.kind << ",\"0x" << std::hex << f.value << "\",\"0x" << f.aux << "\",\"0x" << f.origin << "\"]" << std::dec;
}
}

ReceiverAnalysisResult AnalyzeReceivers(const cs_insn* instructions, size_t count,
	const Profile& profile, const std::set<uint64_t>& externalEntries,
	const std::vector<StackInput>* inputs, size_t* sharedSteps)
{
	ReceiverAnalysisResult result;
	if (!count || count > 16384 || profile.poolSlotSize != 8 || !profile.classIdBits || profile.classIdBits > 32 ||
		profile.classIdShift > 32 - profile.classIdBits || profile.headerDisplacement < -8 || profile.headerDisplacement > 8) return result;
	if (instructions[0].address > UINT64_MAX - count * 4 || profile.nullClassId > Mask(profile.classIdBits)) return result;
	for (const auto& [entry, cid] : profile.allocationReturns) if (cid > Mask(profile.classIdBits)) return result;
	for (const auto& [offset, cid] : profile.threadHeapClasses) if (cid > Mask(profile.classIdBits)) return result;
	for (const auto& [entry, contract] : profile.nonReturningCalls)
		if (contract != "range_error_without_fpu" || profile.allocationReturns.contains(entry) || profile.framePreservingCalls.contains(entry) || profile.frameSafeCallees.contains(entry)) return result;
	for (const auto& [entry, mask] : profile.preservedCallRegisters)
		if ((mask & ((1U << 15) | (1U << 29) | (1U << 30) | (1U << 31))) ||
			((mask & (1U << 25)) && profile.framePreservingCalls.contains(entry) && profile.framePreservingCalls.at(entry) == "array_write_barrier")) return result;
	std::map<int64_t, Fact> inputValues;
	if (inputs) {
		if (inputs->empty() || inputs->size() > 32) return result;
		for (const auto& input : *inputs) {
			if (input.spOffset < 0 || input.spOffset >= 256 || input.spOffset % 8 ||
				(input.kind != "word" && input.kind != "heap_class") ||
				(input.kind == "heap_class" && input.value > Mask(profile.classIdBits)) || inputValues.contains(input.spOffset)) return result;
			inputValues.emplace(input.spOffset, Fact{input.kind == "word" ? Word : Object, input.value});
		}
	}
	const auto start = instructions[0].address, end = start + count * 4;
	std::set<size_t> leaders{0};
	std::set<size_t> calledEntries;
	std::set<int> written;
	for (size_t n = 0; n < count; ++n) {
		const auto& i = instructions[n];
		if (!i.detail || i.size != 4 || i.address != start + n * 4) return result;
		const auto writes = Writes(i);
		written.insert(writes.begin(), writes.end());
		if (externalEntries.contains(i.address)) leaders.insert(n);
		if (Group(i, CS_GRP_JUMP) || Group(i, CS_GRP_CALL) || Terminal(i)) {
			const auto& detail = i.detail->arm64;
			if (Group(i, CS_GRP_JUMP) && !Group(i, CS_GRP_CALL) && (!detail.op_count || detail.operands[detail.op_count - 1].type != ARM64_OP_IMM)) return result;
			if (n + 1 < count) leaders.insert(n + 1);
			if (!detail.op_count) continue;
			for (const auto& op : std::span(i.detail->arm64.operands + detail.op_count - 1, size_t{1})) {
				if (op.type == ARM64_OP_IMM && op.imm >= static_cast<int64_t>(start) && op.imm < static_cast<int64_t>(end) && (op.imm - start) % 4 == 0)
					{ leaders.insert((op.imm - start) / 4); if (Group(i, CS_GRP_CALL)) calledEntries.insert((op.imm - start) / 4); }
			}
		}
	}
	if (leaders.size() > 1024) return result;
	std::vector<size_t> begins(leaders.begin(), leaders.end());
	std::vector<Block> blocks;
	std::vector<size_t> blockOf(count);
	for (size_t n = 0; n < begins.size(); ++n) {
		const auto stop = n + 1 < begins.size() ? begins[n + 1] : count;
		blocks.push_back({begins[n], stop, begins[n] == 0 || (!inputs && (calledEntries.contains(begins[n]) || externalEntries.contains(start + begins[n] * 4))), {}});
		for (size_t k = begins[n]; k < stop; ++k) blockOf[k] = n;
	}
	State seed;
	seed.regs[15] = {Stack};
	seed.regs[29] = {Stack, 0, 1}; // Caller FP has no known relation to entry SP.
	for (const auto& [offset, value] : inputValues) seed.liveInputs.insert(offset);
	const auto poolReg = Number(profile.poolRegister), dispatchReg = Number(profile.dispatchRegister), nullReg = Number(profile.nullRegister), threadReg = Number(profile.threadRegister);
	if (poolReg >= 0 && !written.contains(poolReg)) seed.regs[poolReg] = {Pool};
	if (threadReg >= 0 && !written.contains(threadReg)) seed.regs[threadReg] = {Thread};
	if (dispatchReg >= 0 && !written.contains(dispatchReg)) seed.regs[dispatchReg] = {Dispatch};
	if (nullReg >= 0 && !written.contains(nullReg)) seed.regs[nullReg] = {Object, profile.nullClassId};
	std::map<int64_t, std::optional<uint32_t>> slots;
	auto slotAt = [&](int64_t offset) -> std::optional<uint32_t> {
		const auto relative = Add(offset, -profile.poolDataOffset);
		if (!profile.poolHeapClass || !relative || *relative < 0 || *relative % profile.poolSlotSize || *relative / profile.poolSlotSize >= profile.poolLength) return {};
		const auto index = *relative / profile.poolSlotSize;
		if (!slots.contains(index)) slots.emplace(index, profile.poolHeapClass(index));
		const auto cid = slots.at(index);
		if (!cid || *cid > Mask(profile.classIdBits)) return {};
		result.poolClasses[index] = *cid;
		return cid;
	};
	auto execute = [&](State state, const cs_insn& i) {
		const auto& d = i.detail->arm64;
		// BLR may overwrite its own source (LR), so capture the proven dispatch
		// target before applying architectural writes.
		Fact indirect;
		std::optional<uint64_t> indirectCallee;
		if (i.id == ARM64_INS_BLR && d.op_count == 1 && d.operands[0].type == ARM64_OP_REG) {
			indirect = Read(state, d.operands[0].reg);
			if (indirect.kind == Target && indirect.value < profile.dispatchEntries.size() && profile.dispatchEntries[indirect.value] &&
				profile.frameSafeCallees.contains(*profile.dispatchEntries[indirect.value])) indirectCallee = *profile.dispatchEntries[indirect.value];
		}
		const auto writes = Writes(i);
		Fact produced;
		const auto destination = d.op_count && d.operands[0].type == ARM64_OP_REG ? Number(d.operands[0].reg) : -1;
		const auto width = destination >= 0 ? Width(d.operands[0].reg) : 0;
		if (d.op_count >= 2 && destination >= 0) {
			const auto& op = d.operands[1];
			if (i.id == ARM64_INS_MOV && d.op_count == 2) {
				if (op.type == ARM64_OP_IMM) produced = {Word, static_cast<uint64_t>(op.imm) & Mask(width)};
				else if (op.type == ARM64_OP_REG && Width(op.reg) == width) produced = Read(state, op.reg);
			} else if ((i.id == ARM64_INS_MOVZ || i.id == ARM64_INS_MOVN || i.id == ARM64_INS_MOVK) && d.op_count == 2 && op.type == ARM64_OP_IMM && op.imm >= 0 && op.imm <= 0xffff &&
				(op.shift.type == ARM64_SFT_INVALID || op.shift.type == ARM64_SFT_LSL)) {
				const auto shift = op.shift.type == ARM64_SFT_INVALID ? 0 : op.shift.value;
				if (shift < width && shift % 16 == 0) {
					const auto value = static_cast<uint64_t>(op.imm) << shift;
					if (i.id == ARM64_INS_MOVK) {
						produced = state.regs[destination];
						if (produced.kind == Word) produced.value = (produced.value & ~(uint64_t{0xffff} << shift)) | value;
						else produced = {};
					} else produced = {Word, i.id == ARM64_INS_MOVN ? ~value : value};
					if (produced.kind == Word) produced.value &= Mask(width);
				}
			} else if ((i.id == ARM64_INS_ADD || i.id == ARM64_INS_SUB) && d.op_count == 3 && op.type == ARM64_OP_REG && Width(op.reg) == width) {
				const auto left = Read(state, op.reg), right = Operand(state, d.operands[2], width);
				if (right.kind == Word) {
					if (left.kind == Word) produced = {Word, (i.id == ARM64_INS_ADD ? left.value + right.value : left.value - right.value) & Mask(width)};
					else if (width == 64 && (left.kind == Object || left.kind == HeapAddress)) {
						const auto delta = std::bit_cast<int64_t>(right.value);
						if (i.id != ARM64_INS_SUB || delta != INT64_MIN)
							if (const auto offset = Add(left.kind == Object ? 0 : std::bit_cast<int64_t>(left.value), i.id == ARM64_INS_ADD ? delta : -delta);
								offset && *offset >= -(1 << 20) && *offset <= (1 << 20)) {
								const auto cid = left.kind == Object ? left.value : left.aux;
								produced = *offset == 0 ? Fact{Object, cid} : Fact{HeapAddress, std::bit_cast<uint64_t>(*offset), cid};
							}
					}
					else if (width == 64 && (left.kind == Pool || left.kind == Dispatch || left.kind == Stack || left.kind == Thread)) {
						const auto delta = std::bit_cast<int64_t>(right.value);
						if (i.id != ARM64_INS_SUB || delta != INT64_MIN)
							if (const auto offset = Add(std::bit_cast<int64_t>(left.value), i.id == ARM64_INS_ADD ? delta : -delta);
								offset && (left.kind != Stack || (*offset >= -(1 << 20) && *offset <= (1 << 20)))) produced = {left.kind, std::bit_cast<uint64_t>(*offset), left.aux};
					}
					produced.proof = Union(left.proof, right.proof);
				}
			} else if (i.id == ARM64_INS_UBFX && d.op_count == 4 && op.type == ARM64_OP_REG && Width(op.reg) == width && d.operands[2].type == ARM64_OP_IMM && d.operands[3].type == ARM64_OP_IMM) {
				const auto source = Read(state, op.reg);
				const auto lsb = d.operands[2].imm, bits = d.operands[3].imm;
				if (lsb >= 0 && bits > 0 && bits <= 32 && lsb + bits <= width) {
					produced = {Range, Mask(bits)};
					if (source.kind == Word) produced = {Word, (source.value >> lsb) & Mask(bits)};
					else if (source.kind == Header && lsb == profile.classIdShift && bits == profile.classIdBits) produced = {Word, source.value};
					produced.proof = source.proof;
				}
			}
			if ((i.id == ARM64_INS_LDR || i.id == ARM64_INS_LDUR) && d.op_count == 2 && op.type == ARM64_OP_MEM && !d.writeback) {
				const auto base = Read(state, op.mem.base);
				if (op.mem.index == ARM64_REG_INVALID) {
					if (base.kind == Pool && width == 64) {
						if (const auto offset = Add(std::bit_cast<int64_t>(base.value), op.mem.disp))
							if (const auto cid = slotAt(*offset)) produced = {Object, *cid};
					} else if (base.kind == Thread && width == 64) {
						if (const auto offset = Add(std::bit_cast<int64_t>(base.value), op.mem.disp))
							if (const auto found = profile.threadHeapClasses.find(*offset); found != profile.threadHeapClasses.end()) produced = {Object, found->second};
					} else if (base.kind == Stack && base.aux == 0) {
						if (const auto offset = Add(std::bit_cast<int64_t>(base.value), op.mem.disp); offset && state.liveInputs.contains(*offset)) {
							const auto value = inputValues.at(*offset);
							if (width == 64) produced = value;
							else if (width == 32 && value.kind == Word) produced = {Word, value.value & UINT32_MAX};
						}
						if (width == 64) if (const auto offset = Add(std::bit_cast<int64_t>(base.value), op.mem.disp); offset && state.spills.contains(*offset))
							produced = state.spills.at(*offset);
					} else if (base.kind == Object && op.mem.disp == profile.headerDisplacement && (width == 32 || width == 64)) produced = {Header, base.value};
					produced.proof = Union(produced.proof, base.proof);
				} else if (base.kind == Dispatch && width == 64 && Width(op.mem.index) == 64 && op.ext == ARM64_EXT_INVALID && op.shift.type == ARM64_SFT_LSL && op.shift.value == 3) {
					const auto index = Read(state, op.mem.index);
					const auto offset = Add(std::bit_cast<int64_t>(base.value), op.mem.disp);
					if (index.kind == Word && offset && *offset % 8 == 0) {
						const auto biased = Add(profile.dispatchOrigin, *offset / 8);
						const auto slot = biased ? Add(*biased, std::bit_cast<int64_t>(index.value)) : std::nullopt;
						if (slot && *slot >= 0 && static_cast<uint64_t>(*slot) < profile.dispatchEntries.size() && profile.dispatchEntries[*slot])
							produced = {Target, static_cast<uint64_t>(*slot), index.value, i.address, Union(base.proof, index.proof)};
					}
				}
			}
		}
		// An unknown write may alias a known object's header. Stores to the
		// managed stack, or beyond a known object's header, preserve its class.
		bool unsafeStore = OpaqueMemory(i);
		std::optional<std::pair<int, Fact>> stackWriteback;
		for (unsigned n = 0; n < d.op_count; ++n) if (d.operands[n].type == ARM64_OP_MEM && d.writeback) {
			const auto& memory = d.operands[n].mem;
			const auto base = Read(state, memory.base);
			const auto reg = Number(memory.base);
			if (base.kind == Stack && memory.index == ARM64_REG_INVALID && reg >= 0 && reg != destination) {
				std::optional<int64_t> delta;
				if (n + 1 == d.op_count) delta = memory.disp;
				else if (n + 2 == d.op_count && d.operands[n + 1].type == ARM64_OP_IMM) delta = d.operands[n + 1].imm;
				if (delta) if (const auto offset = Add(std::bit_cast<int64_t>(base.value), *delta);
					offset && *offset >= -(1 << 20) && *offset <= (1 << 20)) stackWriteback = {{reg, Proven({Stack, std::bit_cast<uint64_t>(*offset), base.aux, 0, base.proof}, i.address)}};
			}
		}
		for (unsigned n = 0; n < d.op_count; ++n) if (d.operands[n].type == ARM64_OP_MEM && MemoryWrite(i, d.operands[n])) {
			const auto& memory = d.operands[n].mem;
			const auto base = Read(state, memory.base);
			const bool stack = base.kind == Stack;
			const bool field = HeapField(base, d.operands[n], d.writeback, profile.headerDisplacement);
			unsafeStore |= !stack && !field;
			if (!field) {
				unsigned bytes = 0;
				if (i.id == ARM64_INS_STRB || i.id == ARM64_INS_STURB) bytes = 1;
				else if (i.id == ARM64_INS_STRH || i.id == ARM64_INS_STURH) bytes = 2;
				else if ((i.id == ARM64_INS_STR || i.id == ARM64_INS_STUR || i.id == ARM64_INS_STP) && d.operands[0].type == ARM64_OP_REG)
					bytes = Width(d.operands[0].reg) / 8 * (i.id == ARM64_INS_STP ? 2 : 1);
				const auto offset = Add(std::bit_cast<int64_t>(base.value), memory.disp);
				if (!stack || base.aux != 0 || memory.index != ARM64_REG_INVALID || !bytes || !offset || *offset > INT64_MAX - bytes)
					{ state.liveInputs.clear(); state.spills.clear(); }
				else {
					for (auto it = state.liveInputs.begin(); it != state.liveInputs.end();)
						if (*offset < *it + 8 && *it < *offset + bytes) it = state.liveInputs.erase(it); else ++it;
					for (auto it = state.spills.begin(); it != state.spills.end();)
						if (*offset < it->first + 8 && it->first < *offset + bytes) it = state.spills.erase(it); else ++it;
				}
				const auto sp = state.regs[15];
				const bool pair = i.id == ARM64_INS_STP;
				const bool fullStore = (i.id == ARM64_INS_STR || i.id == ARM64_INS_STUR || pair) &&
					!d.writeback && stack && base.aux == 0 && memory.index == ARM64_REG_INVALID &&
					sp.kind == Stack && sp.aux == 0 && d.operands[0].type == ARM64_OP_REG && Width(d.operands[0].reg) == 64 &&
					(!pair || (d.operands[1].type == ARM64_OP_REG && Width(d.operands[1].reg) == 64));
				if (fullStore) for (unsigned part = 0; part < (pair ? 2U : 1U); ++part) {
					const auto at = offset ? Add(*offset, part * 8) : std::nullopt;
					if (!at || *at >= 0 || *at % 8 || *at < std::bit_cast<int64_t>(sp.value)) continue;
					auto value = Read(state, d.operands[part].reg);
					value.proof = Union(value.proof, base.proof);
					value = Proven(std::move(value), i.address);
					if (value.kind != Object) continue;
					if (state.spills.size() >= 64) state.spills.clear();
					state.spills[*at] = std::move(value);
				}
			}
		}
		if (unsafeStore) {
			for (auto& f : state.regs) if (f.kind == Object || f.kind == Header || f.kind == HeapAddress) f = {};
			state.liveInputs.clear();
			state.spills.clear();
		}
		const bool writesFlags = d.update_flags || i.id == ARM64_INS_MSR ||
			std::find(i.detail->regs_write, i.detail->regs_write + i.detail->regs_write_count, ARM64_REG_NZCV) != i.detail->regs_write + i.detail->regs_write_count;
		if (writesFlags || writes.contains(state.compare.reg)) state.compare = {};
		for (const auto r : writes) state.regs[r] = {};
		if (destination >= 0 && writes.contains(destination)) {
			if (produced.kind == Unknown && width == 32) produced = {Range, UINT32_MAX};
			state.regs[destination] = Proven(std::move(produced), i.address);
		}
		if (stackWriteback) state.regs[stackWriteback->first] = std::move(stackWriteback->second);
		if (i.id == ARM64_INS_CMP && d.op_count == 2 && d.operands[0].type == ARM64_OP_REG && destination >= 0) {
			const auto right = Operand(state, d.operands[1], width);
			if (right.kind == Word) state.compare = {destination, width, right.value & Mask(width), i.address};
		}
		if (Group(i, CS_GRP_CALL) || Group(i, CS_GRP_INT)) {
			const auto sp = state.regs[15], fp = state.regs[29];
			auto live = state.liveInputs;
			auto spills = state.spills;
			const auto savedRegs = state.regs;
			bool preserves = (indirectCallee || (i.id == ARM64_INS_BL && d.op_count == 1 && d.operands[0].type == ARM64_OP_IMM &&
				(profile.allocationReturns.contains(d.operands[0].imm) || profile.framePreservingCalls.contains(d.operands[0].imm) || profile.frameSafeCallees.contains(d.operands[0].imm)))) &&
				sp.kind == Stack && sp.aux == 0 && std::bit_cast<int64_t>(sp.value) <= -16;
			for (unsigned r = 0; r < 31; ++r) if (r != 15 && r != 29 && state.regs[r].kind == Stack) preserves = false;
			state = seed;
			state.liveInputs = preserves ? std::move(live) : std::set<int64_t>{};
			if (preserves) for (auto& [offset, value] : spills) {
				if (indirectCallee) value.proof = Union(value.proof, indirect.proof);
				value = Proven(std::move(value), i.address);
				if (value.kind == Object) state.spills.emplace(offset, std::move(value));
			}
			// A returning Dart call preserves the caller's frame coordinates.
			// Never turn a repurposed/unknown register back into entry SP/FP.
			state.regs[15] = Group(i, CS_GRP_CALL) && sp.kind == Stack ? sp : Fact{};
			state.regs[29] = Group(i, CS_GRP_CALL) && fp.kind == Stack ? fp : Fact{};
			if (i.id == ARM64_INS_BL && d.op_count == 1 && d.operands[0].type == ARM64_OP_IMM) {
				if (const auto contract = profile.preservedCallRegisters.find(d.operands[0].imm); contract != profile.preservedCallRegisters.end())
					for (unsigned r = 0; r < 31; ++r) if (contract->second & (1U << r)) {
						const bool nonAllocatingBarrier = profile.framePreservingCalls.contains(d.operands[0].imm) &&
							profile.framePreservingCalls.at(d.operands[0].imm) == "array_write_barrier";
						// Interior heap addresses may be invalid after a moving GC.
						if (savedRegs[r].kind != HeapAddress || nonAllocatingBarrier) state.regs[r] = Proven(savedRegs[r], i.address);
					}
				const auto allocation = profile.allocationReturns.find(d.operands[0].imm);
				const int reg = Number(profile.allocationResultRegister);
				if (allocation != profile.allocationReturns.end() && reg >= 0) state.regs[reg] = {Object, allocation->second, 0, 0, {i.address}};
			}
		}
		const auto sp = state.regs[15];
		if (sp.kind != Stack || sp.aux != 0) state.spills.clear();
		else for (auto it = state.spills.begin(); it != state.spills.end();)
			if (it->first < std::bit_cast<int64_t>(sp.value)) it = state.spills.erase(it); else ++it;
		return state;
	};
	// Generate edge states and apply only equality constraints. A 32-bit test
	// never invents upper bits unless the input already guarantees zero extension.
	auto successors = [&](size_t block, const State& state) {
		std::vector<std::pair<size_t, State>> edges;
		const auto& b = blocks[block];
		const auto& i = instructions[b.end - 1];
		const auto& d = i.detail->arm64;
		auto append = [&](uint64_t address, State edge) {
			if (address >= start && address < end && (address - start) % 4 == 0) edges.emplace_back(blockOf[(address - start) / 4], std::move(edge));
		};
		if (Terminal(i)) return edges;
		if (i.id == ARM64_INS_BL && d.op_count == 1 && d.operands[0].type == ARM64_OP_IMM && profile.nonReturningCalls.contains(d.operands[0].imm)) return edges;
		if (Group(i, CS_GRP_CALL) || !Group(i, CS_GRP_JUMP)) { if (b.end < count) append(start + b.end * 4, state); return edges; }
		const auto target = static_cast<uint64_t>(d.operands[d.op_count - 1].imm);
		if (i.id == ARM64_INS_B && (d.cc == ARM64_CC_INVALID || d.cc == ARM64_CC_AL)) { append(target, state); return edges; }
		int compared = -1;
		unsigned width = 0;
		uint64_t equalValue = 0, compareSite = 0;
		bool equalityTaken = false;
		std::optional<bool> taken;
		if (i.id == ARM64_INS_B && (d.cc == ARM64_CC_EQ || d.cc == ARM64_CC_NE) && state.compare.reg >= 0) {
			compared = state.compare.reg; width = state.compare.width; equalValue = state.compare.value; compareSite = state.compare.site;
			equalityTaken = d.cc == ARM64_CC_EQ;
		} else if ((i.id == ARM64_INS_CBZ || i.id == ARM64_INS_CBNZ) && d.op_count == 2 && d.operands[0].type == ARM64_OP_REG) {
			compared = Number(d.operands[0].reg); width = Width(d.operands[0].reg); equalityTaken = i.id == ARM64_INS_CBZ;
		} else if ((i.id == ARM64_INS_TBZ || i.id == ARM64_INS_TBNZ) && d.op_count == 3 && d.operands[0].type == ARM64_OP_REG && d.operands[1].type == ARM64_OP_IMM) {
			const auto value = Read(state, d.operands[0].reg);
			const auto reg = Number(d.operands[0].reg);
			const auto bit = d.operands[1].imm;
			if (bit >= 0 && bit < 64) {
				if (value.kind == Word) taken = (((value.value >> bit) & 1) == 0) == (i.id == ARM64_INS_TBZ);
				else if (bit == 0 && reg >= 0 && state.regs[reg].kind == Object) taken = i.id == ARM64_INS_TBNZ;
			}
		}
		if (compared >= 0) {
			const auto& value = state.regs[compared];
			if (value.kind == Word) taken = ((value.value & Mask(width)) == equalValue) == equalityTaken;
			else if (value.kind == Range && equalValue > value.value) taken = !equalityTaken;
		}
		for (bool branch : {false, true}) {
			if (taken && *taken != branch) continue;
			auto edge = state;
			if (compared >= 0 && branch == equalityTaken) {
				const auto& old = state.regs[compared];
				if (width == 64 || ((old.kind == Word || old.kind == Range) && old.value <= UINT32_MAX)) {
					auto proof = old.proof;
					if (compareSite) proof = Union(proof, {compareSite});
					edge.regs[compared] = Proven({Word, equalValue, 0, 0, std::move(proof)}, i.address);
				}
			}
			append(branch ? target : i.address + 4, std::move(edge));
		}
		return edges;
	};
	std::deque<size_t> work;
	std::vector<bool> queued(blocks.size());
	for (size_t n = 0; n < blocks.size(); ++n) if (blocks[n].entry) {
		auto entry = seed;
		// Interior entries do not establish the payload entry's frame base.
		if (blocks[n].first) { entry.regs[15].aux = 2; entry.regs[29].aux = 3; }
		blocks[n].in = entry; work.push_back(n); queued[n] = true;
	}
	size_t steps = 0;
	while (!work.empty()) {
		const auto current = work.front(); work.pop_front(); queued[current] = false;
		auto state = *blocks[current].in;
		for (size_t n = blocks[current].first; n < blocks[current].end; ++n) {
			if (++steps > 1000000 || (sharedSteps && !*sharedSteps)) return {};
			if (sharedSteps) --*sharedSteps;
			state = execute(std::move(state), instructions[n]);
		}
		for (auto& [next, incoming] : successors(current, state))
			if (Join(blocks[next].in, incoming) && !queued[next]) { work.push_back(next); queued[next] = true; }
	}
	for (const auto& b : blocks) if (b.in) {
		auto state = *b.in;
		// Deliberately local to one basic block. These are recent physical
		// writes at a call boundary, not a signature or inferred argument count.
		std::map<int64_t, Fact> recentStores;
		for (size_t n = b.first; n < b.end; ++n) {
			const auto& i = instructions[n];
			const auto& d = i.detail->arm64;
			const auto sp = state.regs[15];
			if (OpaqueMemory(i)) recentStores.clear();
			if (Group(i, CS_GRP_CALL) && sp.kind == Stack) {
				for (const auto& [offset, value] : recentStores) {
					const auto relative = Add(offset, -std::bit_cast<int64_t>(sp.value));
					if (relative && *relative >= 0 && *relative < 256 && *relative % 8 == 0)
						result.stackInputs[i.address].push_back({*relative, value.kind == Word ? "word" : "heap_class", value.value, value.proof});
				}
			}
			for (unsigned m = 0; m < d.op_count; ++m) if (d.operands[m].type == ARM64_OP_MEM) {
				const auto& op = d.operands[m];
				const auto base = Read(state, op.mem.base);
				const bool pair = i.id == ARM64_INS_LDP || i.id == ARM64_INS_STP;
				if ((i.id == ARM64_INS_LDR || i.id == ARM64_INS_LDUR || i.id == ARM64_INS_LDP) &&
					base.kind == Stack && base.aux == 0 && !d.writeback && op.mem.index == ARM64_REG_INVALID) {
					for (unsigned part = 0; part < (pair ? 2U : 1U); ++part) if (d.operands[part].type == ARM64_OP_REG) {
						const auto bits = Width(d.operands[part].reg);
						const auto offset = Add(std::bit_cast<int64_t>(base.value), static_cast<int64_t>(op.mem.disp) + part * (bits / 8));
						const auto proof = Proven(base, i.address).proof;
						const auto r = Number(d.operands[part].reg);
						if (offset && *offset >= 0 && *offset < 256 && (bits == 32 || bits == 64) && r >= 0 && !proof.empty())
							result.entryStackLoads.push_back({i.address, start, *offset, std::string(bits == 64 ? "x" : "w") + std::to_string(r), bits / 8, proof});
					}
				}
				if (!MemoryWrite(i, op)) continue;
				const bool field = HeapField(base, op, d.writeback, profile.headerDisplacement);
				if (field) continue;
				const bool store = (i.id == ARM64_INS_STR || i.id == ARM64_INS_STUR || i.id == ARM64_INS_STP) &&
					!d.writeback && op.mem.index == ARM64_REG_INVALID && base.kind == Stack && sp.kind == Stack && base.aux == sp.aux &&
					d.operands[0].type == ARM64_OP_REG && Width(d.operands[0].reg) == 64 &&
					(!pair || (d.operands[1].type == ARM64_OP_REG && Width(d.operands[1].reg) == 64));
				if (!store) { recentStores.clear(); continue; }
				for (unsigned part = 0; part < (pair ? 2U : 1U); ++part) {
					const auto offset = Add(std::bit_cast<int64_t>(base.value), static_cast<int64_t>(op.mem.disp) + part * 8);
					if (!offset || *offset % 8) { recentStores.clear(); continue; }
					auto value = Read(state, d.operands[part].reg);
					value.proof = Union(value.proof, base.proof);
					value = Proven(std::move(value), i.address);
					recentStores.erase(*offset);
					if (recentStores.size() >= 256) recentStores.clear();
					if (value.kind == Word || value.kind == Object) recentStores.emplace(*offset, std::move(value));
				}
			}
			if ((i.id == ARM64_INS_BLR) && d.op_count == 1 && d.operands[0].type == ARM64_OP_REG) {
				const auto f = Read(state, d.operands[0].reg);
				if (f.kind == Target) {
					result.resolutions.emplace(i.address, StaticDispatch{f.origin, std::bit_cast<int64_t>(f.aux), f.value, *profile.dispatchEntries[f.value], f.proof});
				}
			}
			state = execute(std::move(state), i);
			if (Group(i, CS_GRP_CALL) || Group(i, CS_GRP_INT) || sp.kind != state.regs[15].kind || sp.aux != state.regs[15].aux) recentStores.clear();
		}
	}
	if (result.resolutions.empty() && (inputs || (result.stackInputs.empty() && result.entryStackLoads.empty()))) { result.poolClasses.clear(); return result; }
	std::ostringstream certificate;
	certificate << "{\"payload\":" << start << ",\"blocks\":[";
	for (size_t n = 0; n < blocks.size(); ++n) {
		if (n) certificate << ',';
		const auto& b = blocks[n];
		certificate << "{\"start\":" << start + b.first * 4 << ",\"end\":" << start + b.end * 4 << ",\"entry\":" << (b.entry ? "true" : "false")
			<< ",\"reachable\":" << (b.in ? "true" : "false") << ",\"facts\":[";
		bool comma = false;
		if (b.in) for (unsigned r = 0; r < 31; ++r) if (b.in->regs[r].kind != Unknown) { if (comma) certificate << ','; comma = true; JsonFact(certificate, r, b.in->regs[r]); }
		certificate << "],\"compare\":[";
		if (b.in && b.in->compare.reg >= 0) certificate << b.in->compare.reg << ',' << b.in->compare.width << ',' << b.in->compare.value << ',' << b.in->compare.site;
		certificate << "],\"live_inputs\":[";
		bool first = true;
		if (b.in) for (const auto offset : b.in->liveInputs) { if (!first) certificate << ','; first = false; certificate << offset; }
		certificate << "],\"spills\":["; first = true;
		if (b.in) for (const auto& [offset, value] : b.in->spills) { if (!first) certificate << ','; first = false; certificate << '[' << offset << ',' << value.value << ']'; }
		certificate << "]}";
	}
	certificate << "]}";
	result.certificate = certificate.str();
	return result;
}
}
