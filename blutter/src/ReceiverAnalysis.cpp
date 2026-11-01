#include "ReceiverAnalysis.h"
#include "StackCheckAnalysis.h"
#include "Arm64Ir.h"
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
// One selected edge only. Packed values and saved index words are dropped;
// this is not a general heap domain or a loop-carried allocation identity.
struct ArrayContinuation {
	uint64_t site;
	Fact seed;
	bool entryBinding;
	int64_t inputOffset;
	std::array<Fact, 31> aliases;
	std::map<int64_t, Fact> cells, roots;
	bool operator==(const ArrayContinuation&) const = default;
};
struct State {
	std::array<Fact, 31> regs;
	Compare compare;
	std::optional<uint64_t> indexedOrigin;
	uint32_t resultDependencies = 0;
	// Input values are immutable analysis bindings. Writes kill liveness;
	// they never recreate an original caller input or introduce a new value.
	std::set<int64_t> liveInputs;
	// Heap classes of full-width spills in the active payload frame. Values
	// and object identities are deliberately not reconstructed from a class.
	std::map<int64_t, Fact> spills;
	// One-instruction handoff from the allocation call to its return block.
	Fact freshArray;
	std::optional<ArrayContinuation> arrayContinuation;
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
bool ReadsResult(const cs_insn& i, uint32_t dependencies)
{
	const auto uses = [&](arm64_reg reg) { const int r = Number(reg); return r >= 0 && (dependencies & (1U << r)); };
	if (i.detail->regs_read_count > std::size(i.detail->regs_read)) return false;
	for (unsigned n = 0; n < i.detail->regs_read_count; ++n)
		if (uses(static_cast<arm64_reg>(i.detail->regs_read[n]))) return true;
	const auto& d = i.detail->arm64;
	for (unsigned n = 0; n < d.op_count; ++n) {
		const auto& op = d.operands[n];
		if (op.type == ARM64_OP_REG && (op.access & CS_AC_READ) && uses(op.reg)) return true;
		if (op.type == ARM64_OP_MEM && (uses(op.mem.base) || uses(op.mem.index))) return true;
	}
	return i.id == ARM64_INS_MOVK && d.op_count && d.operands[0].type == ARM64_OP_REG && uses(d.operands[0].reg);
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
// Contents are block-local, except checked length-call continuations and the
// explicitly conditioned initial fast edge. Other branches/calls discard them.
struct LocalArray {
	Fact seed;
	bool entryBinding = false;
	int64_t inputOffset = 0;
	std::array<Fact, 31> aliases, compressed;
	std::map<int64_t, Fact> cells;
	std::map<int64_t, Fact> roots, words;
	void Restore(const ArrayContinuation& value) {
		*this = {}; seed = value.seed; entryBinding = value.entryBinding; inputOffset = value.inputOffset;
		aliases = value.aliases; cells = value.cells; roots = value.roots;
	}
	std::optional<ArrayContinuation> Continue(uint64_t site, uint32_t writes) const {
		if (seed.kind != Word) return {};
		ArrayContinuation next{site, Proven(seed, site), entryBinding, inputOffset, aliases, cells, roots};
		if (next.seed.kind != Word) return {};
		for (unsigned r = 0; r < 31; ++r) next.aliases[r] = (writes & (1U << r)) || next.aliases[r].kind != Word ? Fact{} : Proven(next.aliases[r], site);
		for (auto* values : {&next.cells, &next.roots})
			for (auto it = values->begin(); it != values->end();) {
				it->second = Proven(it->second, site);
				if (it->second.kind == Unknown) it = values->erase(it); else ++it;
			}
		return next;
	}
	void Begin(const Fact& fresh, int resultReg) {
		if (fresh.kind != Word || resultReg < 0) return;
		*this = {}; seed = fresh; aliases[resultReg] = {Word, 0, 0, 0, fresh.proof};
	}
	void BeginInput(const ArrayInputBinding& input, const Profile& profile) {
		*this = {}; entryBinding = true; inputOffset = input.spOffset;
		seed = {Word, input.length}; roots[input.spOffset] = {Word};
		for (const auto& [index, cid] : input.elements)
			cells[profile.arrayBodyContract[2] + index * profile.arrayBodyContract[3]] = {Object, cid};
	}
	std::optional<int64_t> Address(const cs_arm64_op& memory, bool writeback) const {
		const int r = Number(memory.mem.base);
		if (writeback || memory.mem.index != ARM64_REG_INVALID || r < 0 || aliases[r].kind != Word) return {};
		return Add(std::bit_cast<int64_t>(aliases[r].value), memory.mem.disp);
	}
	Fact Load(const cs_insn& i, const Profile& profile) const {
		const auto& d = i.detail->arm64;
		if (seed.kind != Word || d.op_count != 2 || d.operands[1].type != ARM64_OP_MEM ||
			(i.id != ARM64_INS_LDR && i.id != ARM64_INS_LDUR) || Width(d.operands[0].reg) / 8 != profile.arrayBodyContract[3]) return {};
		const auto at = Address(d.operands[1], d.writeback);
		if (!at || !cells.contains(*at)) return {};
		const auto r = Number(d.operands[1].mem.base);
		auto value = cells.at(*at);
		// Internal packed-value metadata, removed before publishing an ordinary class fact.
		if (entryBinding) value.aux = (*at - profile.arrayBodyContract[2]) / profile.arrayBodyContract[3] + 1;
		value.proof = Union(value.proof, aliases[r].proof);
		return Proven(std::move(value), i.address);
	}
	Fact Result(const cs_insn& i, const Profile& profile, bool heapFixed) const {
		const auto& d = i.detail->arm64;
		if (seed.kind != Word) return {};
		if (profile.arrayBodyContract[3] == 8) return Load(i, profile);
		if (heapFixed && i.id == ARM64_INS_ADD && d.op_count == 3 && d.operands[0].type == ARM64_OP_REG &&
			Width(d.operands[0].reg) == 64 && d.operands[1].type == ARM64_OP_REG && Width(d.operands[1].reg) == 64 &&
			d.operands[2].type == ARM64_OP_REG && d.operands[2].reg == profile.heapBitsRegister &&
			d.operands[2].ext == ARM64_EXT_INVALID && d.operands[2].shift.type == ARM64_SFT_LSL && d.operands[2].shift.value == 32) {
			const int r = Number(d.operands[1].reg);
			if (r >= 0) return Proven(compressed[r], i.address);
		}
		return {};
	}
	void Step(const State& before, const cs_insn& i, const Profile& profile) {
		if (seed.kind != Word) return;
		const auto sp = before.regs[15];
		for (auto it = roots.begin(); it != roots.end();)
			if (sp.kind != Stack || sp.aux != 0 || it->first < std::bit_cast<int64_t>(sp.value)) it = roots.erase(it); else ++it;
		for (auto it = words.begin(); it != words.end();)
			if (sp.kind != Stack || sp.aux != 0 || it->first < std::bit_cast<int64_t>(sp.value)) it = words.erase(it); else ++it;
		if (Group(i, CS_GRP_CALL) || Group(i, CS_GRP_INT) || OpaqueMemory(i)) { *this = {}; return; }
		const auto& d = i.detail->arm64;
		Fact alias, packed;
		const int dst = d.op_count && d.operands[0].type == ARM64_OP_REG ? Number(d.operands[0].reg) : -1;
		if (i.id == ARM64_INS_MOV && d.op_count == 2 && dst >= 0 && d.operands[1].type == ARM64_OP_REG) {
			const int src = Number(d.operands[1].reg);
			if (src >= 0 && Width(d.operands[0].reg) == Width(d.operands[1].reg)) {
				if (Width(d.operands[0].reg) == 64) alias = Proven(aliases[src], i.address);
				packed = Proven(compressed[src], i.address);
			}
		}
		if ((i.id == ARM64_INS_ADD || i.id == ARM64_INS_SUB) && d.op_count == 3 && dst >= 0 && Width(d.operands[0].reg) == 64 &&
			d.operands[1].type == ARM64_OP_REG && Width(d.operands[1].reg) == 64 && d.operands[2].type == ARM64_OP_IMM &&
			d.operands[2].imm >= 0 && d.operands[2].imm <= 4095 && d.operands[2].shift.type == ARM64_SFT_INVALID) {
			const int src = Number(d.operands[1].reg);
			if (src >= 0 && aliases[src].kind == Word) {
				const auto at = Add(std::bit_cast<int64_t>(aliases[src].value), (i.id == ARM64_INS_ADD ? 1 : -1) * d.operands[2].imm);
				if (at && *at >= -4096 && *at <= 4096) alias = Proven({Word, std::bit_cast<uint64_t>(*at), 0, 0, aliases[src].proof}, i.address);
			}
		}
		if (profile.arrayBodyContract[3] == 4) if (const auto value = Load(i, profile); value.kind == Object) packed = value;
		if ((i.id == ARM64_INS_LDR || i.id == ARM64_INS_LDUR) && d.op_count == 2 && dst >= 0 && Width(d.operands[0].reg) == 64 && d.operands[1].type == ARM64_OP_MEM && !d.writeback) {
			const auto& m = d.operands[1]; const auto base = Read(before, m.mem.base);
			if (base.kind == Stack && base.aux == 0 && m.mem.index == ARM64_REG_INVALID)
				if (const auto at = Add(std::bit_cast<int64_t>(base.value), m.mem.disp); at && roots.contains(*at))
					alias = Proven({Word, 0, 0, 0, Union(roots.at(*at).proof, base.proof)}, i.address);
		}
		for (unsigned n = 0; n < d.op_count; ++n) if (d.operands[n].type == ARM64_OP_MEM && MemoryWrite(i, d.operands[n])) {
			const auto& m = d.operands[n]; const auto base = Read(before, m.mem.base);
			unsigned width = d.op_count && d.operands[0].type == ARM64_OP_REG ? Width(d.operands[0].reg) / 8 : 0;
			if (i.id == ARM64_INS_STRB || i.id == ARM64_INS_STURB) width = 1;
			if (i.id == ARM64_INS_STRH || i.id == ARM64_INS_STURH) width = 2;
			const bool pair = i.id == ARM64_INS_STP;
			const bool plain = i.id == ARM64_INS_STR || i.id == ARM64_INS_STUR || pair || i.id == ARM64_INS_STRB || i.id == ARM64_INS_STURB || i.id == ARM64_INS_STRH || i.id == ARM64_INS_STURH;
			const auto at = Address(m, d.writeback);
			const auto stackAt = Add(std::bit_cast<int64_t>(base.value), m.mem.disp);
			bool ownFrameWriteback = false;
			if (entryBinding && d.writeback && Number(m.mem.base) == 15 && base.kind == Stack && base.aux == 0 && stackAt && width && plain) {
				const bool post = n + 2 == d.op_count && d.operands[n+1].type == ARM64_OP_IMM;
				if (post || n + 1 == d.op_count) {
					const auto next = Add(std::bit_cast<int64_t>(base.value), post ? d.operands[n+1].imm : m.mem.disp);
					ownFrameWriteback = next && *next >= -(1 << 20) && *next <= 0 &&
						*stackAt >= std::min(std::bit_cast<int64_t>(base.value), *next) && *stackAt <= -static_cast<int64_t>(width * (pair ? 2 : 1));
				}
			}
			if (base.kind == Stack && base.aux == 0 && (!d.writeback || ownFrameWriteback) && m.mem.index == ARM64_REG_INVALID && plain && width && stackAt && *stackAt <= INT64_MAX - width * (pair ? 2 : 1)) {
				for (auto it = roots.begin(); it != roots.end();) if (*stackAt < it->first + 8 && it->first < *stackAt + width * (pair ? 2 : 1)) it = roots.erase(it); else ++it;
				for (auto it = words.begin(); it != words.end();) if (*stackAt < it->first + 8 && it->first < *stackAt + width * (pair ? 2 : 1)) it = words.erase(it); else ++it;
				if (width == 8) for (unsigned part = 0; part < (pair ? 2U : 1U); ++part) {
					const auto constant = Read(before, d.operands[part].reg);
					if (constant.kind == Word && words.size() < 64) {
						auto value = constant; value.proof = Union(value.proof, base.proof);
						value = Proven(std::move(value), i.address);
						if (value.kind == Word) words[*stackAt + part * 8] = std::move(value);
					}
					const int r = Number(d.operands[part].reg);
					if (r >= 0 && aliases[r].kind == Word && aliases[r].value == 0 && roots.size() < 64) {
						const auto root = Proven({Word, 0, 0, 0, Union(aliases[r].proof, base.proof)}, i.address);
						if (root.kind == Word) roots[*stackAt + part * 8] = root;
					}
				}
			} else if (at && plain && width && *at >= profile.arrayBodyContract[2] && *at <= profile.arrayBodyContract[2] + static_cast<int64_t>(seed.value) * profile.arrayBodyContract[3] - width * (pair ? 2 : 1)) {
				for (auto it = cells.begin(); it != cells.end();) if (*at < it->first + profile.arrayBodyContract[3] && it->first < *at + width * (pair ? 2 : 1)) it = cells.erase(it); else ++it;
				if (width == profile.arrayBodyContract[3] && (*at - profile.arrayBodyContract[2]) % width == 0) for (unsigned part = 0; part < (pair ? 2U : 1U); ++part) {
					const int r = Number(d.operands[part].reg);
					if (r < 0) continue;
					auto value = before.regs[r];
					if (value.kind != Object && width == 4) value = compressed[r];
					value.proof = Union(value.proof, aliases[Number(m.mem.base)].proof);
					value = Proven(std::move(value), i.address);
					if (value.kind == Object) cells[*at + part * width] = std::move(value);
				}
			} else { *this = {}; return; }
		}
		for (const int r : Writes(i)) { aliases[r] = {}; compressed[r] = {}; }
		if (dst >= 0 && Writes(i).contains(dst)) { aliases[dst] = std::move(alias); compressed[dst] = std::move(packed); }
	}
};
bool Join(std::optional<State>& destination, const State& source)
{
	if (!destination) { destination = source; return true; }
	auto merged = *destination;
	for (unsigned r = 0; r < 31; ++r) merged.regs[r] = Meet(merged.regs[r], source.regs[r]);
	merged.freshArray = Meet(merged.freshArray, source.freshArray);
	if (merged.arrayContinuation != source.arrayContinuation) merged.arrayContinuation.reset();
	for (auto it = merged.liveInputs.begin(); it != merged.liveInputs.end();)
		if (!source.liveInputs.contains(*it)) it = merged.liveInputs.erase(it); else ++it;
	for (auto it = merged.spills.begin(); it != merged.spills.end();) {
		const auto incoming = source.spills.find(it->first);
		const auto value = incoming == source.spills.end() ? Fact{} : Meet(it->second, incoming->second);
		if (value.kind != Object) it = merged.spills.erase(it);
		else { it->second = value; ++it; }
	}
	if (merged.compare != source.compare) merged.compare = {};
	if (merged.indexedOrigin != source.indexedOrigin) { merged.indexedOrigin.reset(); merged.resultDependencies = 0; }
	else merged.resultDependencies &= source.resultDependencies;
	for (unsigned r = 0; r < 31; ++r) if (merged.regs[r].kind == Unknown) merged.resultDependencies &= ~(1U << r);
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
	const std::vector<StackInput>* inputs, size_t* sharedSteps, const ArrayInputBinding* arrayInput, const InitialStackCheck* initialPath, bool firstTraversal, bool followIndexedResult, bool probeMissingEffects,
	const std::vector<RegisterInput>* registerInputs)
{
	ReceiverAnalysisResult result;
	if (!count || count > 16384 || profile.poolSlotSize != 8 || !profile.classIdBits || profile.classIdBits > 32 ||
		profile.classIdShift > 32 - profile.classIdBits || profile.headerDisplacement < -8 || profile.headerDisplacement > 8) return result;
	if (instructions[0].address > UINT64_MAX - count * 4 || profile.nullClassId > Mask(profile.classIdBits)) return result;
	for (const auto& [entry, cid] : profile.allocationReturns) if (cid > Mask(profile.classIdBits)) return result;
	for (const auto& [entry, contract] : profile.nativeReturnClasses)
		if (!entry || entry % 4 || !contract.classId || contract.classId > Mask(profile.classIdBits) ||
			(contract.contract != "allocate_one_byte_string" && contract.contract != "allocate_two_byte_string") ||
			profile.allocationReturns.contains(entry) || profile.nonReturningCalls.contains(entry)) return result;
	for (const auto& [entry, cid] : profile.provedReturnClasses)
		if (!entry || entry % 4 || !cid || cid > Mask(profile.classIdBits) || profile.nativeReturnClasses.contains(entry) ||
			profile.allocationReturns.contains(entry) || profile.nonReturningCalls.contains(entry)) return result;
	for (const auto& [offset, cid] : profile.threadHeapClasses) if (cid > Mask(profile.classIdBits)) return result;
	for (const auto& [entry, contract] : profile.nonReturningCalls)
		if (contract != "range_error_without_fpu" || profile.allocationReturns.contains(entry) || profile.framePreservingCalls.contains(entry) || profile.frameSafeCallees.contains(entry)) return result;
	for (const auto& [entry, mask] : profile.preservedCallRegisters)
		if ((mask & ((1U << 15) | (1U << 29) | (1U << 30) | (1U << 31))) ||
			((mask & (1U << 25)) && profile.framePreservingCalls.contains(entry) && profile.framePreservingCalls.at(entry) == "array_write_barrier")) return result;
	std::map<int64_t, Fact> inputValues;
	std::map<unsigned, Fact> registerValues;
	if (registerInputs) {
		if (profile.wordReturnRegister != ARM64_REG_X0 || registerInputs->empty() || registerInputs->size() > 15 || arrayInput || initialPath || firstTraversal) return result;
		for (const auto& input : *registerInputs) {
			if (input.reg > 14 || input.reg == Number(profile.poolRegister) || input.reg == Number(profile.threadRegister) ||
				input.reg == Number(profile.dispatchRegister) || input.reg == Number(profile.nullRegister) ||
				!input.classId || input.classId > Mask(profile.classIdBits) || registerValues.contains(input.reg)) return result;
			registerValues.emplace(input.reg, Fact{Object, input.classId});
		}
	}
	if (inputs) {
		if ((inputs->empty() && !registerInputs) || inputs->size() > 32) return result;
		for (const auto& input : *inputs) {
			if (input.spOffset < 0 || input.spOffset >= 256 || input.spOffset % 8 ||
				(input.kind != "word" && input.kind != "heap_class") ||
				(input.kind == "heap_class" && input.value > Mask(profile.classIdBits)) || inputValues.contains(input.spOffset)) return result;
			inputValues.emplace(input.spOffset, Fact{input.kind == "word" ? Word : Object, input.value});
		}
	}
	if ((firstTraversal && (!initialPath || !arrayInput)) || ((followIndexedResult || probeMissingEffects) && !firstTraversal) || (followIndexedResult && probeMissingEffects)) return result;
	const auto start = instructions[0].address, end = start + count * 4;
	for (const auto& [site, value] : profile.callReturnClasses) {
		if (profile.wordReturnRegister != ARM64_REG_X0 || site < start || site >= end || (site-start)%4 || !value.classId || value.classId > Mask(profile.classIdBits)) return result;
		const auto& i = instructions[(site-start)/4];
		if (!i.detail || i.id != ARM64_INS_BL || i.detail->arm64.op_count != 1 || i.detail->arm64.operands[0].type != ARM64_OP_IMM ||
			static_cast<uint64_t>(i.detail->arm64.operands[0].imm) != value.callee || profile.allocationReturns.contains(value.callee) || profile.nonReturningCalls.contains(value.callee) ||
			(profile.nativeReturnClasses.contains(value.callee) && profile.nativeReturnClasses.at(value.callee).classId != value.classId) ||
			(profile.provedReturnClasses.contains(value.callee) && profile.provedReturnClasses.at(value.callee) != value.classId)) return result;
	}
	if (initialPath) {
		const auto checked = FindInitialStackCheck(instructions, count, profile);
		for (const auto entry : externalEntries) if (entry > start && entry <= initialPath->site) return result;
		if (!arrayInput || !checked || *checked != *initialPath || externalEntries.contains(initialPath->successor) ||
			externalEntries.contains(initialPath->slowPath) || externalEntries.contains(initialPath->slowPath+4)) return result;
	}
	const auto& array = profile.arrayBodyContract;
	const bool arrayEnabled = array.size() == 5 && profile.allocationReturns.contains(array[0]) && array[1] >= 0 && array[1] <= 14 &&
		array[2] >= 7 && array[2] <= (1 << 20) && (array[3] == 4 || array[3] == 8) && array[4] == 1;
	if (arrayInput) {
		if (!inputs || !arrayEnabled || arrayInput->spOffset < 0 || arrayInput->spOffset > 248 || arrayInput->spOffset % 8 ||
			arrayInput->length > 32 || arrayInput->elements.empty() || arrayInput->elements.size() > 32 ||
			!inputValues.contains(arrayInput->spOffset) || inputValues.at(arrayInput->spOffset) != Fact{Object, profile.allocationReturns.at(array[0])}) return result;
		for (const auto& [index, cid] : arrayInput->elements)
			if (index < 0 || static_cast<uint64_t>(index) >= arrayInput->length || cid > Mask(profile.classIdBits)) return result;
	}
	std::set<size_t> leaders{0};
	std::set<size_t> calledEntries;
	std::set<uint64_t> targetedEntries = externalEntries;
	std::set<int> written;
	for (size_t n = 0; n < count; ++n) {
		const auto& i = instructions[n];
		if (!i.detail || i.size != 4 || i.address != start + n * 4) return result;
		// Reinitializing entry contents on a backedge would invent preservation.
		if (arrayInput && Group(i, CS_GRP_JUMP) && !Group(i, CS_GRP_CALL))
			for (unsigned j = 0; j < i.detail->arm64.op_count; ++j)
				if (i.detail->arm64.operands[j].type == ARM64_OP_IMM && static_cast<uint64_t>(i.detail->arm64.operands[j].imm) == start) return result;
		const auto writes = Writes(i);
		written.insert(writes.begin(), writes.end());
		if (externalEntries.contains(i.address)) leaders.insert(n);
		if (Group(i, CS_GRP_JUMP) || Group(i, CS_GRP_CALL) || Terminal(i)) {
			const auto& detail = i.detail->arm64;
			if (Group(i, CS_GRP_JUMP) && !Group(i, CS_GRP_CALL) && (!detail.op_count || detail.operands[detail.op_count - 1].type != ARM64_OP_IMM)) return result;
			if (n + 1 < count) leaders.insert(n + 1);
			if (!detail.op_count) continue;
			for (const auto& op : std::span(i.detail->arm64.operands + detail.op_count - 1, size_t{1})) {
				if (op.type == ARM64_OP_IMM) targetedEntries.insert(static_cast<uint64_t>(op.imm));
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
		blocks.push_back({begins[n], stop, begins[n] == 0 || (!inputs && !registerInputs && (calledEntries.contains(begins[n]) || externalEntries.contains(start + begins[n] * 4))), {}});
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
	auto forwardedAt = [&](const State& state, const cs_insn& i) -> std::optional<std::pair<Fact, ForwardedReturn>> {
		if (profile.wordReturnRegister != ARM64_REG_X0) return {};
		const auto& d = i.detail->arm64;
		if (d.op_count != 1) return {};
		std::optional<uint64_t> target;
		if (i.id == ARM64_INS_BL && d.operands[0].type == ARM64_OP_IMM) target = d.operands[0].imm;
		if (i.id == ARM64_INS_BLR && d.operands[0].type == ARM64_OP_REG) {
			const auto loaded = Read(state, d.operands[0].reg);
			if (loaded.kind == Target && loaded.value < profile.dispatchEntries.size()) target = profile.dispatchEntries[loaded.value];
		}
		if (!target || !profile.frameSafeCallees.contains(*target) || !profile.forwardedReturnInputs.contains(*target)) return {};
		const auto input = profile.forwardedReturnInputs.at(*target);
		const auto& sp = state.regs[15];
		if (input < 0 || input > 248 || input % 8 || sp.kind != Stack || sp.aux != 0 || std::bit_cast<int64_t>(sp.value) > -16) return {};
		for (unsigned r = 0; r < 31; ++r) if (r != 15 && r != 29 && state.regs[r].kind == Stack) return {};
		const auto offset = Add(std::bit_cast<int64_t>(sp.value), input);
		if (!offset) return {};
		Fact value;
		if (*offset >= 0 && state.liveInputs.contains(*offset) && inputValues.contains(*offset)) value = inputValues.at(*offset);
		else if (state.spills.contains(*offset)) value = state.spills.at(*offset);
		// The first consumer preserves object classes, not raw pointer bits or
		// arbitrary word values across earlier potentially allocating calls.
		if (value.kind != Object) return {};
		value.proof = Union(value.proof, sp.proof);
		value = Proven(std::move(value), i.address);
		if (value.kind != Object) return {};
		return std::pair{value, ForwardedReturn{*target, input, static_cast<uint32_t>(value.value), value.proof}};
	};
	auto indexedAt = [&](const State& state, const cs_insn& i, const LocalArray& contents) -> std::optional<std::pair<Fact, IndexedReturn>> {
		if (profile.wordReturnRegister != ARM64_REG_X0 || contents.seed.kind != Word || contents.entryBinding != firstTraversal) return {};
		const auto& d = i.detail->arm64;
		if (d.op_count != 1) return {};
		std::optional<uint64_t> target; std::vector<uint64_t> targetProof;
		if (i.id == ARM64_INS_BL && d.operands[0].type == ARM64_OP_IMM) target = d.operands[0].imm;
		if (i.id == ARM64_INS_BLR && d.operands[0].type == ARM64_OP_REG) {
			const auto value = Read(state, d.operands[0].reg);
			if (value.kind == Target && value.value < profile.dispatchEntries.size()) { target = profile.dispatchEntries[value.value]; targetProof = value.proof; }
		}
		if (!target || !profile.frameSafeCallees.contains(*target) || !profile.arrayReturnInputs.contains(*target)) return {};
		const auto& contract = profile.arrayReturnInputs.at(*target); const auto sp = state.regs[15];
		if (sp.kind != Stack || sp.aux != 0 || std::bit_cast<int64_t>(sp.value) > -16) return {};
		for (unsigned r = 0; r < 31; ++r) if (r != 15 && r != 29 && state.regs[r].kind == Stack) return {};
		const auto arrayAt = Add(std::bit_cast<int64_t>(sp.value), contract.arraySpOffset);
		const auto indexAt = Add(std::bit_cast<int64_t>(sp.value), contract.indexSpOffset);
		if (!arrayAt || !indexAt || !contents.roots.contains(*arrayAt) || !contents.words.contains(*indexAt)) return {};
		const auto index = contents.words.at(*indexAt);
		if (index.kind != Word || index.value > 62 || index.value % 2 || index.value / 2 >= contents.seed.value) return {};
		const auto at = profile.arrayBodyContract[2] + static_cast<int64_t>(index.value / 2) * profile.arrayBodyContract[3];
		if (!contents.cells.contains(at)) return {};
		auto value = contents.cells.at(at);
		for (const auto& proof : {sp.proof, contents.seed.proof, contents.roots.at(*arrayAt).proof, index.proof, targetProof}) value.proof = Union(value.proof, proof);
		value = Proven(std::move(value), i.address);
		if (value.kind != Object) return {};
		return std::pair{value, IndexedReturn{*target, contents.seed.origin, index.value / 2, static_cast<uint32_t>(value.value), value.proof, contents.entryBinding ? std::optional<int64_t>{contents.inputOffset} : std::nullopt}};
	};
	const bool heapFixed = profile.heapBitsRegister == ARM64_REG_X28 && !written.contains(28);
	auto lengthAt = [&](const State& state, const cs_insn& i, const LocalArray& contents) -> std::optional<std::pair<Fact, ArrayLengthReturn>> {
		if (!arrayEnabled || !profile.arrayLengthLayout || profile.wordReturnRegister != ARM64_REG_X0 || contents.seed.kind != Word) return {};
		const auto& layout = *profile.arrayLengthLayout;
		if (layout.classId != profile.allocationReturns.at(array[0]) || layout.bytes != array[3] || layout.smiShift != 1 || contents.seed.value > 32) return {};
		const auto& d = i.detail->arm64;
		if (d.op_count != 1) return {};
		std::optional<uint64_t> target; std::vector<uint64_t> targetProof;
		if (i.id == ARM64_INS_BL && d.operands[0].type == ARM64_OP_IMM) target = d.operands[0].imm;
		if (i.id == ARM64_INS_BLR && d.operands[0].type == ARM64_OP_REG) {
			const auto value = Read(state, d.operands[0].reg);
			if (value.kind == Target && value.value < profile.dispatchEntries.size()) { target = profile.dispatchEntries[value.value]; targetProof = value.proof; }
		}
		if (!target || !profile.frameSafeCallees.contains(*target) || !profile.arrayLengthEffects.contains(*target)) return {};
		const auto& effect = profile.arrayLengthEffects.at(*target); const auto sp = state.regs[15];
		if (effect.arraySpOffset < 0 || effect.arraySpOffset > 248 || effect.arraySpOffset % 8 ||
			sp.kind != Stack || sp.aux != 0 || std::bit_cast<int64_t>(sp.value) > -16) return {};
		for (unsigned r = 0; r < 31; ++r) if (r != 15 && r != 29 && state.regs[r].kind == Stack) return {};
		const auto at = Add(std::bit_cast<int64_t>(sp.value), effect.arraySpOffset);
		if (!at || !contents.roots.contains(*at)) return {};
		Fact value{Word, contents.seed.value << 1};
		for (const auto& proof : {contents.seed.proof, contents.roots.at(*at).proof, sp.proof, targetProof}) value.proof = Union(value.proof, proof);
		value = Proven(std::move(value), i.address);
		if (value.kind != Word) return {};
		ArrayLengthReturn claim{*target, contents.seed.value, effect.arraySpOffset, {}, {}, value.proof};
		if (contents.entryBinding) claim.entryInputSpOffset = contents.inputOffset; else claim.allocation = contents.seed.origin;
		return std::pair{value, claim};
	};
	auto execute = [&](State state, const cs_insn& i, LocalArray& contents) {
		if (arrayEnabled) contents.Begin(state.freshArray, Number(profile.allocationResultRegister));
		state.freshArray = {};
		state.arrayContinuation.reset();
		const auto indexedOrigin = state.indexedOrigin;
		const bool dependent = followIndexedResult && ReadsResult(i, state.resultDependencies);
		bool resultDispatch = false;
		if (followIndexedResult && indexedOrigin && i.id == ARM64_INS_BLR && i.detail->arm64.op_count == 1 && i.detail->arm64.operands[0].type == ARM64_OP_REG) {
			const auto r = Number(i.detail->arm64.operands[0].reg);
			resultDispatch = r >= 0 && (state.resultDependencies & (1U << r)) && state.regs[r].kind == Target;
		}
		if (probeMissingEffects && contents.entryBinding && contents.seed.kind == Word && !result.missingArrayEffect) {
			std::optional<uint64_t> target;
			const auto& d = i.detail->arm64;
			if (i.id == ARM64_INS_BL && d.op_count == 1 && d.operands[0].type == ARM64_OP_IMM) target = d.operands[0].imm;
			if (i.id == ARM64_INS_BLR && d.op_count == 1 && d.operands[0].type == ARM64_OP_REG) {
				const auto value = Read(state, d.operands[0].reg);
				if (value.kind == Target && value.value < profile.dispatchEntries.size()) target = profile.dispatchEntries[value.value];
			}
			const auto sp = state.regs[15];
			if (target && !profile.arrayReturnInputs.contains(*target) && !profile.arrayLengthEffects.contains(*target) &&
				sp.kind == Stack && sp.aux == 0 && std::bit_cast<int64_t>(sp.value) <= -16) {
				for (const auto& [at, root] : contents.roots) {
					const auto offset = Add(at, -std::bit_cast<int64_t>(sp.value));
					if (offset && *offset >= 0 && *offset <= 248 && *offset % 8 == 0) {
						result.missingArrayEffect = {{i.address, *target}}; break;
					}
				}
			}
		}
		const auto forwarded = forwardedAt(state, i);
		const auto indexed = indexedAt(state, i, contents);
		const auto lengthReturn = lengthAt(state, i, contents);
		std::optional<ArrayContinuation> continued;
		if (lengthReturn && i.address + 4 < end && (firstTraversal || !targetedEntries.contains(i.address + 4)))
			continued = contents.Continue(i.address, profile.arrayLengthEffects.at(lengthReturn->second.callee).writtenRegisters | (1U << 30));
		const auto element = contents.Result(i, profile, heapFixed);
		const auto length = arrayEnabled ? state.regs[array[1]] : Fact{};
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
			if (firstTraversal) if (const auto ir = LowerArm64(i); ir && std::holds_alternative<NativeIr::ExtractSigned>(ir->operation)) {
				std::vector<uint64_t> proof;
				const auto value = NativeIr::Evaluate(*ir, [&](NativeIr::RegisterView r) -> std::optional<uint64_t> {
					if (r.id >= 31 || state.regs[r.id].kind != Word) return {};
					proof = Union(proof, state.regs[r.id].proof); return state.regs[r.id].value;
				});
				if (value) produced = {Word, *value, 0, 0, std::move(proof)};
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
		if (element.kind == Object) { produced = element; produced.aux = 0; }
		contents.Step(state, i, profile);
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
		if (followIndexedResult) {
			for (const int r : writes) state.resultDependencies &= ~(1U << r);
			if (destination >= 0 && writes.contains(destination) && produced.kind != Unknown && dependent)
				state.resultDependencies |= 1U << destination;
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
				const auto native = profile.nativeReturnClasses.find(d.operands[0].imm);
				if (profile.wordReturnRegister == ARM64_REG_X0 && native != profile.nativeReturnClasses.end())
					state.regs[0] = {Object, native->second.classId, 0, 0, {i.address}};
				const auto returned = profile.provedReturnClasses.find(d.operands[0].imm);
				if (profile.wordReturnRegister == ARM64_REG_X0 && returned != profile.provedReturnClasses.end())
					state.regs[0] = {Object, returned->second, 0, 0, {i.address}};
				if (const auto bound = profile.callReturnClasses.find(i.address); bound != profile.callReturnClasses.end())
					state.regs[0] = {Object, bound->second.classId, 0, 0, {i.address}};
			}
			if (forwarded && preserves) state.regs[0] = forwarded->first;
			if (indexed && preserves) state.regs[0] = indexed->first;
			if (followIndexedResult) {
				state.indexedOrigin = indexedOrigin;
				state.resultDependencies = 0;
				if (indexed && preserves) {
					state.indexedOrigin = i.address;
					state.resultDependencies = 1U;
					state.liveInputs.clear(); state.spills.clear();
					result.traceGetter = i.address;
				}
			}
			if (lengthReturn && preserves) {
				const auto mask = profile.arrayLengthEffects.at(lengthReturn->second.callee).writtenRegisters | (1U << 30);
				for (unsigned r = 0; r < 31; ++r) if (!(mask & (1U << r)) && savedRegs[r].kind != Unknown)
					state.regs[r] = Proven(savedRegs[r], i.address);
				state.regs[0] = lengthReturn->first;
				state.arrayContinuation = std::move(continued);
			}
			if (arrayEnabled && i.id == ARM64_INS_BL && d.op_count == 1 && d.operands[0].type == ARM64_OP_IMM && d.operands[0].imm == array[0] &&
				length.kind == Word && length.value <= 64 && length.value % 2 == 0)
				state.freshArray = Proven({Word, length.value / 2, 0, i.address, length.proof}, i.address);
		}
		const auto sp = state.regs[15];
		if (sp.kind != Stack || sp.aux != 0) state.spills.clear();
		else for (auto it = state.spills.begin(); it != state.spills.end();)
			if (it->first < std::bit_cast<int64_t>(sp.value)) it = state.spills.erase(it); else ++it;
		if ((initialPath && i.address == initialPath->site) || (firstTraversal && Group(i, CS_GRP_JUMP) && !Group(i, CS_GRP_CALL)))
			state.arrayContinuation = contents.Continue(i.address, 0);
		if (firstTraversal && indexed && !followIndexedResult) result.traceStop = i.address;
		if (resultDispatch) result.traceStop = i.address;
		if (followIndexedResult) for (unsigned r = 0; r < 31; ++r)
			if (state.regs[r].kind == Unknown) state.resultDependencies &= ~(1U << r);
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
		if (Terminal(i) || (firstTraversal && result.traceStop == i.address)) return edges;
		if (probeMissingEffects && result.missingArrayEffect && result.missingArrayEffect->first == i.address) return edges;
		// A result use never crosses another call. The getter itself is the
		// one allowed returning producer; its mutable contents have expired.
		if (followIndexedResult && state.indexedOrigin && Group(i, CS_GRP_CALL) && *state.indexedOrigin != i.address) return edges;
		if (initialPath && i.address == initialPath->site) { append(initialPath->successor, state); return edges; }
		if (firstTraversal && Group(i, CS_GRP_JUMP) && !Group(i, CS_GRP_CALL)) {
			if (const auto guard = FindStackCheckAt(instructions, count, profile, i.address)) {
				if (result.traceGuards.size() >= 8) return edges;
				result.traceGuards.push_back(*guard); append(guard->successor, state); return edges;
			}
		}
		if (i.id == ARM64_INS_BL && d.op_count == 1 && d.operands[0].type == ARM64_OP_IMM && profile.nonReturningCalls.contains(d.operands[0].imm)) return edges;
		if (Group(i, CS_GRP_CALL) || !Group(i, CS_GRP_JUMP)) { if (b.end < count) append(start + b.end * 4, state); return edges; }
		const auto target = static_cast<uint64_t>(d.operands[d.op_count - 1].imm);
		if (i.id == ARM64_INS_B && (d.cc == ARM64_CC_INVALID || d.cc == ARM64_CC_AL)) { append(target, state); return edges; }
		int compared = -1;
		unsigned width = 0;
		uint64_t equalValue = 0, compareSite = 0;
		bool equalityTaken = false;
		std::optional<bool> taken;
		if (firstTraversal && b.end - b.first >= 2) taken = EvaluateArm64Condition(i, instructions[b.end-2], [&](NativeIr::RegisterView r) -> std::optional<uint64_t> {
			if (r.id >= 31 || state.regs[r.id].kind != Word) return {};
			return state.regs[r.id].value;
		});
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
		if (firstTraversal && !taken) return edges;
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
		// These bindings belong only to this invocation's payload entry. The
		// invariant seed used after calls must never recreate an entry value.
		if (!blocks[n].first) for (const auto& [reg, value] : registerValues) entry.regs[reg] = value;
		// Interior entries do not establish the payload entry's frame base.
		if (blocks[n].first) { entry.regs[15].aux = 2; entry.regs[29].aux = 3; }
		blocks[n].in = entry; work.push_back(n); queued[n] = true;
	}
	size_t steps = 0;
	while (!work.empty()) {
		const auto current = work.front(); work.pop_front(); queued[current] = false;
		if (firstTraversal) {
			const auto address = start + blocks[current].first*4;
			if (result.traceBlocks.size() >= 64 || std::find(result.traceBlocks.begin(), result.traceBlocks.end(), address) != result.traceBlocks.end()) return {};
			result.traceBlocks.push_back(address);
		}
		auto state = *blocks[current].in;
		LocalArray contents;
		if (arrayInput && blocks[current].first == 0) contents.BeginInput(*arrayInput, profile);
		else if (state.arrayContinuation) contents.Restore(*state.arrayContinuation);
		for (size_t n = blocks[current].first; n < blocks[current].end; ++n) {
			if (++steps > (firstTraversal ? 256U : 1000000U) || (sharedSteps && !*sharedSteps)) return {};
			if (sharedSteps) --*sharedSteps;
			state = execute(std::move(state), instructions[n], contents);
		}
		if (firstTraversal && !Group(instructions[blocks[current].end-1], CS_GRP_CALL))
			state.arrayContinuation = contents.Continue(instructions[blocks[current].end-1].address, 0);
		auto outgoing = successors(current, state);
		if (firstTraversal && outgoing.size() > 1) return {};
		for (auto& [next, incoming] : outgoing)
			if (Join(blocks[next].in, incoming) && !queued[next]) { work.push_back(next); queued[next] = true; }
	}
	if (firstTraversal && !result.traceStop) {
		ReceiverAnalysisResult unresolved;
		if (probeMissingEffects) unresolved.missingArrayEffect = result.missingArrayEffect;
		return unresolved;
	}
	std::set<uint64_t> normalReturns;
	for (const auto& b : blocks) if (b.in) {
		auto state = *b.in;
		LocalArray contents;
		if (arrayInput && b.first == 0) contents.BeginInput(*arrayInput, profile);
		else if (state.arrayContinuation) { contents.Restore(*state.arrayContinuation); result.arrayContinuationUsed = true; }
		// Deliberately local to one basic block. These are recent physical
		// writes at a call boundary, not a signature or inferred argument count.
		std::map<int64_t, Fact> recentStores;
		for (size_t n = b.first; n < b.end; ++n) {
			const auto& i = instructions[n];
			const auto& d = i.detail->arm64;
			const auto sp = state.regs[15];
			if (i.id == ARM64_INS_RET && (d.op_count == 0 || (d.op_count == 1 && d.operands[0].reg == ARM64_REG_X30))) {
				normalReturns.insert(i.address);
				if (profile.wordReturnRegister == ARM64_REG_X0 && state.regs[0].kind == Object && state.regs[0].value) {
					const auto value = Proven(state.regs[0], i.address);
					if (!value.proof.empty()) result.returnClasses.emplace(i.address, ReturnedClass{static_cast<uint32_t>(value.value), value.proof});
				}
			}
			if (!inputs && !registerInputs && Group(i, CS_GRP_CALL) && profile.wordReturnRegister == ARM64_REG_X0)
				for (unsigned reg = 0; reg < 15; ++reg) {
					const auto& value = state.regs[reg];
					if (reg != poolReg && reg != threadReg && reg != dispatchReg && reg != nullReg && value.kind == Object && value.value && !value.proof.empty())
						result.registerInputs[i.address].push_back({reg, static_cast<uint32_t>(value.value), value.proof});
				}
			if (arrayEnabled) contents.Begin(state.freshArray, Number(profile.allocationResultRegister));
			if (contents.entryBinding) {
				const auto value = contents.Result(i, profile, heapFixed);
				const int reg = d.op_count && d.operands[0].type == ARM64_OP_REG ? Number(d.operands[0].reg) : -1;
				if (value.kind == Object && value.aux && reg >= 0 && Width(d.operands[0].reg) == 64)
					result.arrayReads.emplace(i.address, ArrayElementRead{contents.inputOffset, static_cast<int64_t>(value.aux - 1), static_cast<uint32_t>(value.value), "x" + std::to_string(reg), value.proof});
			}
			if (const auto forwarded = forwardedAt(state, i)) result.forwardedReturns.emplace(i.address, forwarded->second);
			if (const auto indexed = indexedAt(state, i, contents)) result.indexedReturns.emplace(i.address, indexed->second);
			if (const auto lengthReturn = lengthAt(state, i, contents)) result.lengthReturns.emplace(i.address, lengthReturn->second);
			if (OpaqueMemory(i)) recentStores.clear();
			if (Group(i, CS_GRP_CALL) && sp.kind == Stack) {
				for (const auto& [offset, value] : recentStores) {
					const auto relative = Add(offset, -std::bit_cast<int64_t>(sp.value));
					if (relative && *relative >= 0 && *relative < 256 && *relative % 8 == 0)
						result.stackInputs[i.address].push_back({*relative, value.kind == Word ? "word" : "heap_class", value.value, value.proof});
					if (!inputs && relative && *relative >= 0 && *relative < 256 && *relative % 8 == 0 && contents.seed.kind == Word &&
						contents.roots.contains(offset) && !contents.cells.empty() && value.kind == Object) {
						ArrayArgument argument{*relative, contents.seed.origin, contents.seed.value, {}, Union(Union(contents.seed.proof, value.proof), {i.address})};
						argument.proof = Union(argument.proof, contents.roots.at(offset).proof);
						for (const auto& [at, element] : contents.cells) {
							argument.elements.emplace((at - array[2]) / array[3], element.value);
							argument.proof = Union(argument.proof, element.proof);
						}
						if (argument.proof.size() <= 128) result.arrayArguments[i.address].push_back(std::move(argument));
					}
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
			state = execute(std::move(state), i, contents);
			if (Group(i, CS_GRP_CALL) || Group(i, CS_GRP_INT) || sp.kind != state.regs[15].kind || sp.aux != state.regs[15].aux) recentStores.clear();
		}
	}
	// A local RET fact does not describe escaping branches or a tail call.
	// Require a closed normal-flow body and agreement at every reached return.
	bool closed = !initialPath && !firstTraversal && !normalReturns.empty();
	for (size_t n = 0; n < count; ++n) {
		const auto& i = instructions[n]; const auto& d = i.detail->arm64;
		if (Group(i, CS_GRP_RET) && (i.id != ARM64_INS_RET || (d.op_count && (d.op_count != 1 || d.operands[0].reg != ARM64_REG_X30)))) closed = false;
		if (Group(i, CS_GRP_JUMP) && !Group(i, CS_GRP_CALL)) {
			if (!d.op_count || d.operands[d.op_count-1].type != ARM64_OP_IMM) closed = false;
			else {
				const auto target = static_cast<uint64_t>(d.operands[d.op_count-1].imm);
				if (target < start || target >= end || (target-start)%4) closed = false;
			}
		}
	}
	const auto& last = instructions[count-1]; const auto& ld = last.detail->arm64;
	const bool stops = Terminal(last) || (last.id == ARM64_INS_B && (ld.cc == ARM64_CC_INVALID || ld.cc == ARM64_CC_AL)) ||
		(last.id == ARM64_INS_BL && ld.op_count == 1 && ld.operands[0].type == ARM64_OP_IMM && profile.nonReturningCalls.contains(ld.operands[0].imm));
	if (closed && stops && result.returnClasses.size() == normalReturns.size()) {
		const auto cid = result.returnClasses.begin()->second.classId;
		if (std::all_of(result.returnClasses.begin(), result.returnClasses.end(), [&](const auto& entry) { return entry.second.classId == cid; })) result.normalReturnClass = cid;
	}
	if (result.resolutions.empty() && result.forwardedReturns.empty() && result.indexedReturns.empty() && result.arrayReads.empty() && result.lengthReturns.empty() && result.returnClasses.empty() && result.registerInputs.empty() && ((inputs || registerInputs) || (result.stackInputs.empty() && result.entryStackLoads.empty()))) { result.poolClasses.clear(); return result; }
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
		certificate << "],\"fresh_array\":";
		if (b.in && b.in->freshArray.kind == Word) certificate << "{\"allocation\":" << b.in->freshArray.origin << ",\"length\":" << b.in->freshArray.value << '}';
		else certificate << "null";
		certificate << ",\"array_continuation\":";
		if (b.in && b.in->arrayContinuation) certificate << b.in->arrayContinuation->site; else certificate << "null";
		certificate << '}';
	}
	certificate << "],\"return_classes\":[";
	bool firstReturn = true;
	for (const auto& [site, value] : result.returnClasses) {
		if (!firstReturn) certificate << ','; firstReturn = false;
		certificate << "{\"site\":" << site << ",\"class_id\":" << value.classId << ",\"register\":\"x0\",\"proof\":[";
		for (size_t n = 0; n < value.proof.size(); ++n) { if (n) certificate << ','; certificate << value.proof[n]; }
		certificate << "]}";
	}
	certificate << "],\"normal_return_class\":" << (result.normalReturnClass ? std::to_string(*result.normalReturnClass) : "null") << '}';
	result.certificate = certificate.str();
	return result;
}
}
