#include "SnapshotCodeAnalysis.h"
#include "ReceiverAnalysis.h"
#include "RegisterContexts.h"
#include "CallResultContexts.h"
#include "SdkStubResultAnalysis.h"
#include "CallEffects.h"
#include "Arm64Ir.h"
#include "StackCheckAnalysis.h"
#include <algorithm>
#include <array>
#include <bit>
#include <format>
#include <fstream>
#include <limits>
#include <memory>
#include <set>
#include <stdexcept>
#include <tuple>

namespace SnapshotAnalysis {
namespace {
int RegNumber(arm64_reg reg)
{
	if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) return reg - ARM64_REG_X0;
	if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) return reg - ARM64_REG_W0;
	if (reg == ARM64_REG_X29) return 29;
	if (reg == ARM64_REG_X30) return 30;
	return -1;
}
bool IsX(arm64_reg reg)
{
	return (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) || reg == ARM64_REG_X29 || reg == ARM64_REG_X30;
}
unsigned RegWidth(arm64_reg reg)
{
	if (IsX(reg) || reg == ARM64_REG_SP || reg == ARM64_REG_XZR || (reg >= ARM64_REG_D0 && reg <= ARM64_REG_D31)) return 8;
	if (reg == ARM64_REG_WZR || (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) || (reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31)) return 4;
	if (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31) return 16;
	return 0;
}
std::string RegName(arm64_reg reg)
{
	const auto number = RegNumber(reg);
	return number < 0 ? "untracked" : std::format("{}{}", IsX(reg) ? "x" : "w", number);
}
bool Group(const cs_insn& instruction, uint8_t group)
{
	return std::find(instruction.detail->groups, instruction.detail->groups + instruction.detail->groups_count, group)
		!= instruction.detail->groups + instruction.detail->groups_count;
}
bool Transfer(const cs_insn& instruction)
{
	return Group(instruction, CS_GRP_JUMP) || Group(instruction, CS_GRP_CALL) || Group(instruction, CS_GRP_RET);
}
std::set<int> Written(const cs_insn& instruction)
{
	std::set<int> result;
	const auto& detail = *instruction.detail;
	for (uint8_t i = 0; i < detail.regs_write_count; ++i) {
		const auto number = RegNumber(static_cast<arm64_reg>(detail.regs_write[i]));
		if (number >= 0) result.insert(number);
	}
	for (uint8_t i = 0; i < detail.arm64.op_count; ++i) {
		const auto& op = detail.arm64.operands[i];
		if (op.type == ARM64_OP_REG && (op.access & CS_AC_WRITE)) {
			const auto number = RegNumber(op.reg);
			if (number >= 0) result.insert(number);
		}
		if (op.type == ARM64_OP_MEM && detail.arm64.writeback) {
			const auto number = RegNumber(op.mem.base);
			if (number >= 0) result.insert(number);
		}
	}
	return result;
}
std::optional<int64_t> Add(int64_t a, int64_t b)
{
	if ((b > 0 && a > std::numeric_limits<int64_t>::max() - b) ||
		(b < 0 && a < std::numeric_limits<int64_t>::min() - b)) return {};
	return a + b;
}
std::string Quoted(const std::string& value)
{
	std::string out = "\"";
	for (unsigned char c : value) {
		if (c == '"' || c == '\\') { out += '\\'; out += c; }
		else if (c < 0x20) out += std::format("\\u{:04x}", c);
		else out += c;
	}
	return out + '"';
}
std::string Preview(const std::string& value)
{
	auto out = Quoted(value);
	if (out.size() > 240) {
		size_t cut = 237;
		while (cut && (static_cast<unsigned char>(out[cut]) & 0xc0) == 0x80) --cut;
		out = out.substr(0, cut) + "...";
	}
	return out;
}
void Proof(std::ostream& out, const std::vector<uint64_t>& proof)
{
	out << '[';
	for (size_t i = 0; i < proof.size(); ++i) { if (i) out << ','; out << proof[i]; }
	out << ']';
}
void Forwarded(std::ostream& out, const ForwardedReturn& value, std::optional<uint64_t> site = {})
{
	out << '{';
	if (site) out << "\"site\":" << *site << ',';
	out << "\"callee\":" << value.callee << ",\"input_sp_offset\":" << value.inputSpOffset
		<< ",\"register\":\"x0\",\"class_id\":" << value.classId << ",\"proof\":";
	Proof(out, value.proof); out << '}';
}
void LengthReturn(std::ostream& out, const ArrayLengthReturn& value, std::optional<uint64_t> site = {})
{
	out << '{';
	if (site) out << "\"site\":" << *site << ',';
	out << "\"callee\":" << value.callee << ",\"input_sp_offset\":" << value.inputSpOffset << ",\"register\":\"x0\",\"length\":" << value.length
		<< ",\"value\":" << Quoted(std::format("{:#x}", value.length << 1)) << ",\"allocation\":" << (value.allocation ? std::to_string(*value.allocation) : "null")
		<< ",\"entry_input_sp_offset\":" << (value.entryInputSpOffset ? std::to_string(*value.entryInputSpOffset) : "null") << ",\"proof\":";
	Proof(out, value.proof); out << '}';
}
struct Origin {
	std::string kind;
	int64_t offset;
	bool address;
	std::vector<uint64_t> proof;
	std::optional<int64_t> fieldOffset;
	std::string indexRegister;
	std::optional<uint64_t> snapshotTarget;
	std::optional<DispatchAccess> dispatch;
};
struct Constant {
	uint64_t bits;
	std::vector<uint64_t> proof;
};
std::vector<uint64_t> MergeProof(const std::vector<uint64_t>& a, const std::vector<uint64_t>& b)
{
	auto result = a;
	result.insert(result.end(), b.begin(), b.end());
	std::sort(result.begin(), result.end());
	result.erase(std::unique(result.begin(), result.end()), result.end());
	return result;
}
std::optional<Constant> RegisterValue(arm64_reg reg, const std::array<std::optional<Constant>, 31>& constants)
{
	if (reg == ARM64_REG_XZR || reg == ARM64_REG_WZR) return Constant{0, {}};
	const int number = RegNumber(reg);
	return number >= 0 ? constants[number] : std::optional<Constant>{};
}
std::optional<Constant> ArithmeticOperand(const cs_arm64_op& op, unsigned width,
	const std::array<std::optional<Constant>, 31>& constants)
{
	if (op.ext != ARM64_EXT_INVALID) return {};
	if (op.type == ARM64_OP_IMM && op.imm >= 0 &&
		(op.shift.type == ARM64_SFT_INVALID || (op.shift.type == ARM64_SFT_LSL && op.shift.value == 12)))
		return Constant{static_cast<uint64_t>(op.imm) << (op.shift.type == ARM64_SFT_INVALID ? 0 : 12), {}};
	if (op.type == ARM64_OP_REG && RegWidth(op.reg) == width &&
		(op.shift.type == ARM64_SFT_INVALID || (op.shift.type == ARM64_SFT_LSL && op.shift.value == 0)))
		return RegisterValue(op.reg, constants);
	return {};
}
// A bounded, single-basic-block value domain. A W write defines the entire X
// register by zero extension. Unknown writes kill the fact; joins/calls reset
// everything. These are physical register observations, not Dart parameters.
std::optional<Constant> ConstantResult(const cs_insn& instruction,
	const std::array<std::optional<Constant>, 31>& constants)
{
	const auto ir = LowerArm64(instruction);
	if (!ir || std::holds_alternative<NativeIr::ExtractSigned>(ir->operation)) return {}; // This consumer retains its selected subset.
	const auto effects = NativeIr::GetEffects(*ir);
	if (!effects.destination || effects.destination->id >= constants.size()) return {};
	std::vector<uint64_t> proof;
	const auto value = NativeIr::Evaluate(*ir, [&](NativeIr::RegisterView reg) -> std::optional<uint64_t> {
		if (reg.id >= constants.size() || !constants[reg.id]) return {};
		proof = MergeProof(proof, constants[reg.id]->proof);
		return constants[reg.id]->bits;
	});
	if (!value || proof.size() >= 64) return {};
	proof.push_back(ir->source.address);
	return Constant{*value, std::move(proof)};
}
// Keep an unknown extracted bitfield plus a signed affine offset. No object
// identity, receiver class, branch constraint, or cross-block fact is assumed.
std::optional<IndexExpression> IndexResult(const cs_insn& instruction,
	const std::array<std::optional<IndexExpression>, 31>& indices,
	const std::array<std::optional<Constant>, 31>& constants)
{
	const auto& d = instruction.detail->arm64;
	if (d.op_count < 2 || d.operands[0].type != ARM64_OP_REG || !IsX(d.operands[0].reg) ||
		d.operands[1].type != ARM64_OP_REG || !IsX(d.operands[1].reg)) return {};
	const int source = RegNumber(d.operands[1].reg);
	std::optional<IndexExpression> result;
	if (instruction.id == ARM64_INS_UBFX && d.op_count == 4 && d.operands[2].type == ARM64_OP_IMM && d.operands[3].type == ARM64_OP_IMM) {
		const auto lsb = d.operands[2].imm, size = d.operands[3].imm;
		if (lsb >= 0 && size > 0 && size <= 32 && lsb + size <= 64)
			result = IndexExpression{instruction.address, RegName(d.operands[1].reg), static_cast<unsigned>(lsb), static_cast<unsigned>(size), 0, {}};
	} else if (instruction.id == ARM64_INS_MOV && d.op_count == 2) result = indices[source];
	else if ((instruction.id == ARM64_INS_ADD || instruction.id == ARM64_INS_SUB) && d.op_count == 3 && indices[source]) {
		if (const auto right = ArithmeticOperand(d.operands[2], 8, constants)) {
			const auto value = std::bit_cast<int64_t>(right->bits);
			if (instruction.id == ARM64_INS_SUB && value == INT64_MIN) return {};
			const auto delta = instruction.id == ARM64_INS_SUB ? -value : value;
			if (const auto offset = Add(indices[source]->addend, delta);
				offset && Add(*offset, (int64_t{1} << indices[source]->width) - 1)) {
				result = indices[source];
				result->addend = *offset;
				result->proof = MergeProof(result->proof, right->proof);
			}
		}
	}
	if (result) {
		if (result->proof.size() >= 64) return {};
		result->proof.push_back(instruction.address);
	}
	return result;
}
}

Analyzer::Analyzer(Profile config, std::vector<Payload> ranges, std::vector<Name> names,
	std::optional<uint64_t> selected)
	: profile(std::move(config)), selectedCaller(selected), payloads(std::move(ranges))
{
	if (RegNumber(profile.poolRegister) < 0 || RegNumber(profile.threadRegister) < 0 ||
		RegNumber(profile.poolRegister) == RegNumber(profile.threadRegister) ||
		(profile.dispatchRegister != ARM64_REG_INVALID && (RegNumber(profile.dispatchRegister) < 0 ||
			RegNumber(profile.dispatchRegister) == RegNumber(profile.poolRegister) || RegNumber(profile.dispatchRegister) == RegNumber(profile.threadRegister))) ||
		profile.dispatchOrigin < 0 || profile.dispatchEntries.size() > (1 << 24) ||
		profile.poolSlotSize <= 0 || profile.poolLength < 0 || profile.poolDataOffset < 0 || !profile.describePoolSlot)
		throw std::runtime_error("Invalid snapshot annotation profile");
	for (size_t i = 0; i < payloads.size(); ++i) {
		if (payloads[i].end <= payloads[i].start || (i && payloads[i-1].end > payloads[i].start))
			throw std::runtime_error("Overlapping or unsorted snapshot payloads");
	}
	if (selectedCaller && (!*selectedCaller || *selectedCaller % 4 ||
		std::none_of(payloads.begin(), payloads.end(), [&](const auto& p) { return p.start == *selectedCaller; })))
		throw std::runtime_error("Analysis caller must identify an original native payload start");
	std::sort(names.begin(), names.end(), [](const auto& a, const auto& b) {
		return std::tie(a.address, a.kind, a.text) < std::tie(b.address, b.kind, b.text);
	});
	for (auto& name : names) {
		entries.insert(name.address);
		receiverEntries.insert(name.address);
		if (const auto index = FindPayload(name.address)) payloads[*index].names.push_back(std::move(name));
	}
	for (auto& payload : payloads) {
		payload.label = payload.names.empty() ? std::format("unattributed_code_{:x}", payload.start) : payload.names.front().text;
	}
	for (const auto target : profile.dispatchEntries) if (target) receiverEntries.insert(*target);
}
void Analyzer::RegisterEntries(const cs_insn* instructions, size_t count)
{
	if (callEffectsPrepared) throw std::runtime_error("Entries must be registered before analysis");
	if (count && count <= 16384 && count * 4 <= 32 * 1024 * 1024 - contextBytesSize) {
		const auto index = FindPayload(instructions[0].address);
		if (index && payloads[*index].start == instructions[0].address && count * 4 == payloads[*index].end - payloads[*index].start && !contextBytes.contains(instructions[0].address)) {
			std::vector<uint8_t> bytes;
			for (size_t n = 0; n < count; ++n) {
				if (instructions[n].size != 4 || instructions[n].address != instructions[0].address + n * 4) { bytes.clear(); break; }
				bytes.insert(bytes.end(), instructions[n].bytes, instructions[n].bytes + 4);
			}
			if (!bytes.empty()) { contextBytesSize += bytes.size(); contextBytes.emplace(instructions[0].address, std::move(bytes)); }
		}
	}
	for (size_t i = 0; i < count; ++i) {
		if (!instructions[i].detail) throw std::runtime_error("Missing ARM64 instruction details");
		if (!Transfer(instructions[i])) continue;
		const auto& detail = instructions[i].detail->arm64;
		for (uint8_t n = 0; n < detail.op_count; ++n)
			if (detail.operands[n].type == ARM64_OP_IMM) {
				const auto target = static_cast<uint64_t>(detail.operands[n].imm);
				entries.insert(target);
				if (n == detail.op_count - 1 && (Group(instructions[i], CS_GRP_CALL) || FindPayload(target) != FindPayload(instructions[i].address))) receiverEntries.insert(target);
			}
	}
}
std::optional<size_t> Analyzer::FindPayload(uint64_t address) const
{
	auto it = std::upper_bound(payloads.begin(), payloads.end(), address,
		[](uint64_t value, const auto& range) { return value < range.start; });
	if (it == payloads.begin()) return {};
	--it;
	if (address >= it->end) return {};
	return static_cast<size_t>(it - payloads.begin());
}

std::map<uint64_t, std::string> Analyzer::Analyze(const cs_insn* instructions, size_t count, uint64_t payloadStart)
{
	if (!callEffectsPrepared) {
		const auto effects = AnalyzeCallEffects(contextBytes, profile);
		callEffectCertificates = effects.certificates;
		profile.forwardedReturnInputs = effects.forwardedInputs;
		profile.arrayReturnInputs = effects.arrayReturns;
		profile.arrayLengthEffects = effects.arrayLengths;
		callEffectAttempts = effects.attempted; callEffectSteps = effects.steps;
		for (const auto& [entry, certificate] : effects.certificates) profile.frameSafeCallees.insert(entry);
		callEffectsPrepared = true;
	}
	std::map<uint64_t, std::string> comments;
	const auto index = FindPayload(payloadStart);
	if (!index || payloads[*index].start != payloadStart) throw std::runtime_error("Unknown annotation payload");
	auto& payload = payloads[*index];
	// Do not infer references across undecoded bytes.
	if (!count || instructions[0].address != payload.start ||
		instructions[count-1].address + instructions[count-1].size != payload.end || count * 4 != payload.end - payload.start)
		return comments;
	if (payload.decoded) throw std::runtime_error("Duplicate annotation payload");
	payload.decoded = true;
	const auto firstEdge = edges.size();
	const int poolReg = RegNumber(profile.poolRegister);
	const int threadReg = RegNumber(profile.threadRegister);
	const int dispatchReg = RegNumber(profile.dispatchRegister);
	bool poolWritten = false, threadWritten = false, dispatchWritten = false;
	std::set<uint64_t> blockStarts;
	for (size_t i = 0; i < count; ++i) {
		const auto& instruction = instructions[i];
		if (!instruction.detail || instruction.size != 4) throw std::runtime_error("Missing ARM64 instruction details");
		const auto writes = Written(instruction);
		poolWritten |= writes.contains(poolReg);
		threadWritten |= writes.contains(threadReg);
		dispatchWritten |= writes.contains(dispatchReg);
		if (Transfer(instruction)) {
			const auto& detail = instruction.detail->arm64;
			for (uint8_t n = 0; n < detail.op_count; ++n) {
				if (detail.operands[n].type == ARM64_OP_IMM) blockStarts.insert(detail.operands[n].imm);
			}
		}
	}
	std::array<std::optional<Origin>, 31> state;
	std::array<std::optional<Constant>, 31> constants;
	std::array<std::optional<IndexExpression>, 31> indices;
	auto reset = [&]() {
		state.fill({});
		constants.fill({});
		indices.fill({});
		if (!poolWritten) state[poolReg] = Origin{"pool", 0, true, {}};
		if (!threadWritten) state[threadReg] = Origin{"thread", 0, true, {}};
		if (dispatchReg >= 0 && !dispatchWritten) state[dispatchReg] = Origin{"dispatch_table", 0, true, {}};
	};
	reset();
	bool afterTransfer = false;
	for (size_t n = 0; n < count; ++n) {
		const auto& instruction = instructions[n];
		const auto& detail = instruction.detail->arm64;
		if (afterTransfer || blockStarts.contains(instruction.address) || entries.contains(instruction.address)) reset();
		auto note = [&](const std::string& text) {
			auto& comment = comments[instruction.address];
			if (!comment.empty()) comment += " | ";
			comment += text;
		};
		const bool call = Group(instruction, CS_GRP_CALL);
		const bool jump = Group(instruction, CS_GRP_JUMP);
		auto callConstants = [&]() {
			std::vector<RegisterConstant> inputs;
			if (call) for (size_t r = 0; r < constants.size(); ++r)
				if (constants[r]) inputs.push_back({std::format("x{}", r), constants[r]->bits, constants[r]->proof});
			if (!inputs.empty()) {
				std::string text = "observed register constants:";
				for (size_t r = 0; r < std::min(inputs.size(), size_t{4}); ++r)
					text += std::format(" {}={:#x}", inputs[r].reg, inputs[r].bits);
				if (inputs.size() > 4) text += " [more in snapshot_calls.json]";
				note(text);
			}
			return inputs;
		};
		if ((call || jump) && detail.op_count) {
			const auto& target = detail.operands[detail.op_count - 1];
			if (target.type == ARM64_OP_IMM) {
				const auto address = static_cast<uint64_t>(target.imm);
				if (call || address < payload.start || address >= payload.end) {
					Edge edge{instruction.address, payload.start,
						call ? "call" : ((instruction.id == ARM64_INS_B && (detail.cc == ARM64_CC_INVALID || detail.cc == ARM64_CC_AL)) ? "jump" : "conditional_jump"),
						address, {}, "", "", "", {}, {}};
					if (const auto targetIndex = FindPayload(address)) {
						edge.targetPayload = payloads[*targetIndex].start;
						edge.targetLabel = payloads[*targetIndex].label;
						note(std::format("{} -> {} [payload {:#x}, entry +{:#x}]", edge.kind, Preview(edge.targetLabel), *edge.targetPayload, address - *edge.targetPayload));
					} else note(std::format("{} -> {:#x} [outside snapshot payloads]", edge.kind, address));
					edge.registerConstants = callConstants();
					if (call && profile.wordReturnRegister == ARM64_REG_X0 && profile.nativeReturnClasses.contains(address))
						note(std::format("normal return x0: heap class {:#x} [matched SDK native contract; caller memory effects unproved]",
							profile.nativeReturnClasses.at(address).classId));
					if (call && profile.sdkStubReturnClasses.contains(address))
						note(std::format("normal return x0: heap class {:#x} [matched SDK stub contract; caller memory effects unproved]",
							profile.sdkStubReturnClasses.at(address).classId));
					edges.push_back(std::move(edge));
				}
			} else if (target.type == ARM64_OP_REG) {
				Edge edge{instruction.address, payload.start, call ? "indirect_call" : "indirect_jump", {}, {}, "", RegName(target.reg), "", {}, {}};
				const int reg = RegNumber(target.reg);
				if (reg >= 0 && state[reg] && !state[reg]->address) {
					edge.viaKind = state[reg]->kind;
					edge.viaOffset = state[reg]->offset;
					edge.proof = state[reg]->proof;
					edge.viaFieldOffset = state[reg]->fieldOffset;
					edge.indexRegister = state[reg]->indexRegister;
					edge.snapshotTarget = state[reg]->snapshotTarget;
					edge.dispatch = state[reg]->dispatch;
				}
				note(std::format("{} via {} [target unresolved]", edge.kind, edge.targetRegister));
				if (edge.viaOffset) note(std::format("register loaded from {}+{:#x}", edge.viaKind, *edge.viaOffset));
				if (!edge.indexRegister.empty()) note("index at load: " + edge.indexRegister);
				if (edge.dispatch && edge.dispatch->index) note(std::format("dispatch index {}, table slot {} [{}]", *edge.dispatch->index,
					edge.dispatch->tableIndex ? std::to_string(*edge.dispatch->tableIndex) : "unknown", edge.dispatch->resolution));
				if (edge.dispatch && edge.dispatch->expression) {
					const auto& value = *edge.dispatch->expression;
					note(std::format("index = ubfx({}, {}, {}) + {} [receiver class unknown]", value.sourceRegister, value.lsb, value.width, value.addend));
				}
				if (edge.snapshotTarget) note(std::format("snapshot entry {:#x} [runtime target not proven]", *edge.snapshotTarget));
				edge.registerConstants = callConstants();
				edges.push_back(std::move(edge));
			}
		}

		std::optional<Origin> produced;
		int destination = -1;
		if (detail.op_count >= 2 && detail.operands[0].type == ARM64_OP_REG && IsX(detail.operands[0].reg)) {
			destination = RegNumber(detail.operands[0].reg);
			if (detail.operands[1].type == ARM64_OP_REG && IsX(detail.operands[1].reg)) {
				const int source = RegNumber(detail.operands[1].reg);
				if (state[source]) {
					if (instruction.id == ARM64_INS_MOV && detail.op_count == 2) produced = state[source];
					else if ((instruction.id == ARM64_INS_ADD || instruction.id == ARM64_INS_SUB) &&
						detail.op_count == 3 && detail.operands[2].type == ARM64_OP_IMM && state[source]->address) {
						const auto& operand = detail.operands[2];
						const unsigned shift = operand.shift.type == ARM64_SFT_INVALID ? 0 : operand.shift.value;
						if ((operand.shift.type == ARM64_SFT_INVALID || operand.shift.type == ARM64_SFT_LSL) &&
							shift < 63 && operand.imm >= 0 && operand.imm <= (std::numeric_limits<int64_t>::max() >> shift)) {
							const int64_t delta = operand.imm << shift;
							if (const auto offset = Add(state[source]->offset, instruction.id == ARM64_INS_ADD ? delta : -delta)) {
								produced = state[source];
								produced->offset = *offset;
							}
						}
					}
					if (produced) produced->proof.push_back(instruction.address);
				}
			}
		}

		const bool load = instruction.id == ARM64_INS_LDR || instruction.id == ARM64_INS_LDUR || instruction.id == ARM64_INS_LDP;
		const bool store = instruction.id == ARM64_INS_STR || instruction.id == ARM64_INS_STUR || instruction.id == ARM64_INS_STP;
		std::vector<std::pair<int, Origin>> loaded;
		if ((load || store) && !detail.writeback) {
			const bool pair = instruction.id == ARM64_INS_LDP || instruction.id == ARM64_INS_STP;
			const unsigned memoryIndex = pair ? 2 : 1;
			if (detail.op_count > memoryIndex && detail.operands[memoryIndex].type == ARM64_OP_MEM) {
				const auto& memory = detail.operands[memoryIndex].mem;
				const int base = RegNumber(memory.base);
				// A typed Code object loaded from PP can supply a snapshot entry.
				// A displacement match alone on an arbitrary object is insufficient.
				if (load && !pair && base >= 0 && memory.index == ARM64_REG_INVALID && state[base] &&
					state[base]->kind == "pool" && !state[base]->address && IsX(detail.operands[0].reg)) {
					const auto relative = Add(state[base]->offset, -profile.poolDataOffset);
					if (relative && *relative >= 0 && *relative % profile.poolSlotSize == 0) {
						const auto slot = poolSlots.find(*relative / profile.poolSlotSize);
						if (slot != poolSlots.end()) {
							const auto entry = slot->second.entryPoints.find(memory.disp);
							if (entry != slot->second.entryPoints.end()) {
								auto origin = *state[base];
								origin.kind = "pool_code_entry";
								origin.fieldOffset = memory.disp;
								origin.snapshotTarget = entry->second;
								origin.proof.push_back(instruction.address);
								loaded.emplace_back(RegNumber(detail.operands[0].reg), std::move(origin));
							}
						}
					}
				}
				// Indexed GDT loads identify the dispatch mechanism, not a callee.
				if (load && !pair && base >= 0 && state[base] && state[base]->address &&
					state[base]->kind == "dispatch_table" && IsX(detail.operands[0].reg) && IsX(memory.index) &&
					detail.operands[memoryIndex].ext == ARM64_EXT_INVALID &&
					detail.operands[memoryIndex].shift.type == ARM64_SFT_LSL && detail.operands[memoryIndex].shift.value == 3) {
					if (const auto offset = Add(state[base]->offset, memory.disp)) {
						auto origin = *state[base];
						origin.offset = *offset;
						origin.address = false;
						origin.indexRegister = RegName(memory.index);
						DispatchAccess access;
						const auto indexValue = RegisterValue(memory.index, constants);
						if (indexValue) {
							access.index = std::bit_cast<int64_t>(indexValue->bits);
							access.proof = indexValue->proof;
							if (*offset % 8 == 0) {
								if (const auto biased = Add(profile.dispatchOrigin, *offset / 8)) access.tableIndex = Add(*biased, *access.index);
								access.resolution = "out_of_bounds";
								if (profile.dispatchEntries.empty()) access.resolution = "table_unavailable";
								else if (access.tableIndex && *access.tableIndex >= 0 && static_cast<uint64_t>(*access.tableIndex) < profile.dispatchEntries.size()) {
									origin.snapshotTarget = profile.dispatchEntries[*access.tableIndex];
									access.resolution = !origin.snapshotTarget ? "unmapped_entry" :
										origin.snapshotTarget == profile.dispatchNullTarget ? "null_error_entry" : "snapshot_entry";
								}
							} else access.resolution = "misaligned_base";
						} else access.expression = indices[RegNumber(memory.index)];
						origin.dispatch = std::move(access);
						origin.proof.push_back(instruction.address);
						loaded.emplace_back(RegNumber(detail.operands[0].reg), std::move(origin));
					}
				}
				if (base >= 0 && memory.index == ARM64_REG_INVALID && state[base] && state[base]->address && state[base]->kind != "dispatch_table") {
					for (unsigned part = 0; part < (pair ? 2u : 1u); ++part) {
						const unsigned width = RegWidth(detail.operands[part].reg);
						const auto offset = Add(state[base]->offset, static_cast<int64_t>(memory.disp) + part * width);
						if (!offset || !width) continue;
						Reference ref{instruction.address, payload.start, state[base]->kind, load ? "load" : "store", *offset, width, RegName(memory.base), {}, "", state[base]->proof};
						if (ref.kind == "pool") {
							const auto relative = Add(ref.offset, -profile.poolDataOffset);
							if (relative && *relative >= 0 && *relative % profile.poolSlotSize == 0 && *relative / profile.poolSlotSize < profile.poolLength && width == profile.poolSlotSize) {
								ref.poolIndex = *relative / profile.poolSlotSize;
								if (!poolSlots.contains(*ref.poolIndex)) poolSlots.emplace(*ref.poolIndex, profile.describePoolSlot(*ref.poolIndex));
								note(std::format("PP+{:#x} [slot {} snapshot value {}]", ref.offset, *ref.poolIndex, Preview(poolSlots.at(*ref.poolIndex).description)));
							} else note(std::format("PP+{:#x} [slot/value unresolved]", ref.offset));
						} else {
							const auto name = profile.threadFields.find(ref.offset);
							if (name != profile.threadFields.end()) ref.fieldName = name->second;
							note(std::format("THR+{:#x} [{}]", ref.offset, ref.fieldName.empty() ? "field unknown" : ref.fieldName));
						}
						if (load && IsX(detail.operands[part].reg) && width == 8) {
							auto proof = ref.proof;
							proof.push_back(instruction.address);
							loaded.emplace_back(RegNumber(detail.operands[part].reg), Origin{ref.kind, ref.offset, false, std::move(proof)});
						}
						references.push_back(std::move(ref));
					}
				}
			}
		}
		const auto constant = ConstantResult(instruction, constants);
		const auto expression = IndexResult(instruction, indices, constants);
		for (const int reg : Written(instruction)) { state[reg].reset(); constants[reg].reset(); indices[reg].reset(); }
		if (constant) constants[RegNumber(detail.operands[0].reg)] = constant;
		if (expression) indices[RegNumber(detail.operands[0].reg)] = expression;
		if (produced && destination >= 0) state[destination] = std::move(produced);
		for (auto& [reg, origin] : loaded) state[reg] = std::move(origin);
		afterTransfer = Transfer(instruction);
	}
	if (profile.classIdBits) {
		auto receiver = AnalyzeReceivers(instructions, count, profile, receiverEntries);
		for (size_t n = firstEdge; n < edges.size(); ++n)
			if (const auto found = receiver.registerInputs.find(edges[n].site); found != receiver.registerInputs.end()) edges[n].registerInputs = found->second;
		for (const auto& [site, value] : receiver.returnClasses) {
			auto& comment = comments[site];
			if (!comment.empty()) comment += " | ";
			comment += std::format("normal-flow return x0: heap class {:#x} [this RET only]", value.classId);
		}
		if (receiver.normalReturnClass && !profile.nativeReturnClasses.contains(payloadStart) && !profile.sdkStubReturnClasses.contains(payloadStart) && !profile.allocationReturns.contains(payloadStart) && !profile.nonReturningCalls.contains(payloadStart))
			machineReturnClasses.emplace(payloadStart, *receiver.normalReturnClass);
		for (size_t n = firstEdge; n < edges.size(); ++n) if (const auto found = receiver.resolutions.find(edges[n].site); found != receiver.resolutions.end()) {
			edges[n].staticDispatch = found->second;
			auto& comment = comments[edges[n].site];
			if (!comment.empty()) comment += " | ";
			comment += std::format("normal-flow receiver/index proof -> snapshot {:#x}", found->second.snapshotTarget);
		}
		for (size_t n = firstEdge; n < edges.size(); ++n) if (const auto found = receiver.stackInputs.find(edges[n].site); found != receiver.stackInputs.end()) {
			edges[n].stackInputs = found->second;
			auto& comment = comments[edges[n].site];
			if (!comment.empty()) comment += " | ";
			comment += "recent stack inputs (partial): ";
			for (size_t k = 0; k < found->second.size(); ++k) {
				const auto& value = found->second[k];
				if (k) comment += ", ";
				comment += std::format("SP+{:#x} {} {:#x}", value.spOffset, value.kind, value.value);
			}
		}
		entryStackLoads.insert(entryStackLoads.end(), receiver.entryStackLoads.begin(), receiver.entryStackLoads.end());
		for (size_t n = firstEdge; n < edges.size(); ++n) if (const auto found = receiver.forwardedReturns.find(edges[n].site); found != receiver.forwardedReturns.end()) {
			edges[n].forwardedReturn = found->second;
			auto& comment = comments[edges[n].site];
			if (!comment.empty()) comment += " | ";
			comment += std::format("x0 forwards callee entry SP+{:#x} (heap class {:#x})", found->second.inputSpOffset, found->second.classId);
		}
		for (size_t n = firstEdge; n < edges.size(); ++n) if (const auto found = receiver.indexedReturns.find(edges[n].site); found != receiver.indexedReturns.end()) {
			edges[n].indexedReturn = found->second;
			auto& comment = comments[edges[n].site];
			if (!comment.empty()) comment += " | ";
			comment += std::format("x0 returns array[{}] (heap class {:#x})", found->second.index, found->second.classId);
		}
		for (size_t n = firstEdge; n < edges.size(); ++n) if (const auto found = receiver.arrayArguments.find(edges[n].site); found != receiver.arrayArguments.end())
			edges[n].arrayArguments = found->second;
		for (size_t n = firstEdge; n < edges.size(); ++n) if (const auto found = receiver.lengthReturns.find(edges[n].site); found != receiver.lengthReturns.end()) {
			edges[n].arrayLengthReturn = found->second;
			auto& comment = comments[edges[n].site];
			if (!comment.empty()) comment += " | ";
			comment += std::format("x0 returns known array length {} (Smi {:#x}); checked read-only leaf", found->second.length, found->second.length << 1);
		}
		if (!receiver.certificate.empty()) receiverCertificates.push_back(std::move(receiver.certificate));
		receiverPoolClasses.insert(receiver.poolClasses.begin(), receiver.poolClasses.end());
	}
	return comments;
}

void Analyzer::Write(const std::string& filename,
	const std::function<void(const CallResultContextResult&)>& presentResults,
	const std::function<void(uint64_t)>& reportSdkDecodeFailure) const
{
	using Bindings = std::vector<std::tuple<int64_t, std::string, uint64_t>>;
	std::map<std::pair<uint64_t, Bindings>, std::vector<uint64_t>> groups;
	std::map<uint64_t, uint64_t> globallyResolved;
	for (const auto& edge : edges) if (edge.staticDispatch) globallyResolved.emplace(edge.site, edge.staticDispatch->snapshotTarget);
	for (const auto& edge : edges) if (edge.kind == "call" && edge.target && !edge.stackInputs.empty() && contextBytes.contains(*edge.target)) {
		Bindings bindings;
		for (const auto& input : edge.stackInputs) bindings.emplace_back(input.spOffset, input.kind, input.value);
		std::sort(bindings.begin(), bindings.end());
		groups[{*edge.target, std::move(bindings)}].push_back(edge.site);
	}
	// These bindings do not change the existing scalar context groups or budget.
	using ArrayBindings = std::tuple<uint64_t, Bindings, int64_t, uint64_t, std::map<int64_t, uint32_t>>;
	std::map<ArrayBindings, std::vector<uint64_t>> arrayGroups;
	for (const auto& edge : edges) if (edge.kind == "call" && edge.target && !edge.stackInputs.empty() && contextBytes.contains(*edge.target)) {
		Bindings bindings;
		for (const auto& input : edge.stackInputs) bindings.emplace_back(input.spOffset, input.kind, input.value);
		std::sort(bindings.begin(), bindings.end());
		for (const auto& input : edge.arrayArguments) {
			ArrayBindings key{*edge.target, bindings, input.spOffset, input.length, input.elements};
			if (arrayGroups.size() < 4096 || arrayGroups.contains(key)) arrayGroups[std::move(key)].push_back(edge.site);
		}
	}
	struct Context {
		uint64_t payload;
		std::vector<uint64_t> callers;
		std::vector<StackInput> inputs;
		ReceiverAnalysisResult analysis;
	};
	std::vector<Context> contexts;
	std::map<std::pair<uint64_t, Bindings>, std::map<uint64_t, uint64_t>> scalarResolutions;
	struct ArrayContext {
		uint64_t payload;
		std::vector<uint64_t> callers;
		std::vector<StackInput> inputs;
		ArrayInputBinding binding;
		ReceiverAnalysisResult analysis;
		std::optional<InitialStackCheck> path;
	};
	std::vector<ArrayContext> arrayContexts, arrayPathContexts, arrayEntryTraces, arrayResultTraces;
	auto checkedPoolClasses = receiverPoolClasses;
	size_t attempted = 0, remainingSteps = 20000000;
	struct Decoder { csh handle = 0; ~Decoder() { if (handle) cs_close(&handle); } } decoder;
	if (!groups.empty() || !arrayGroups.empty()) {
		if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &decoder.handle) != CS_ERR_OK ||
			cs_option(decoder.handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) throw std::runtime_error("Cannot initialize context decoder");
	}
	for (const auto& [key, callers] : groups) {
		if (attempted >= 4096 || !remainingSteps) break;
		++attempted;
		const auto& [payload, bindings] = key;
		const auto& bytes = contextBytes.at(payload);
		cs_insn* raw = nullptr;
		const auto count = cs_disasm(decoder.handle, bytes.data(), bytes.size(), payload, 0, &raw);
		const std::shared_ptr<cs_insn> instructions(raw, [count](cs_insn* p) { cs_free(p, count); });
		if (count * 4 != bytes.size()) continue; // Never bridge an undecoded word.
		std::vector<StackInput> inputs;
		for (const auto& [offset, kind, value] : bindings) inputs.push_back({offset, kind, value, {}});
		auto analysis = AnalyzeReceivers(raw, count, profile, receiverEntries, &inputs, &remainingSteps);
		for (auto it = analysis.resolutions.begin(); it != analysis.resolutions.end();)
			if (globallyResolved.contains(it->first) && globallyResolved.at(it->first) == it->second.snapshotTarget) it = analysis.resolutions.erase(it); else ++it;
		if (analysis.resolutions.empty() && analysis.forwardedReturns.empty() && analysis.lengthReturns.empty()) continue;
		checkedPoolClasses.insert(analysis.poolClasses.begin(), analysis.poolClasses.end());
		for (const auto& [site, resolution] : analysis.resolutions) scalarResolutions[key][site] = resolution.snapshotTarget;
		contexts.push_back({payload, callers, std::move(inputs), std::move(analysis)});
	}
	size_t arrayAttempted = 0, arrayRemainingSteps = 20000000;
	for (const auto& [key, callers] : arrayGroups) {
		if (arrayAttempted >= 4096 || !arrayRemainingSteps) break;
		++arrayAttempted;
		const auto& [payload, bindings, offset, length, elements] = key;
		const auto& bytes = contextBytes.at(payload);
		cs_insn* raw = nullptr;
		const auto count = cs_disasm(decoder.handle, bytes.data(), bytes.size(), payload, 0, &raw);
		const std::shared_ptr<cs_insn> instructions(raw, [count](cs_insn* p) { cs_free(p, count); });
		std::vector<StackInput> inputs;
		for (const auto& [at, kind, value] : bindings) inputs.push_back({at, kind, value, {}});
		ArrayInputBinding binding{offset, length, elements};
		ReceiverAnalysisResult analysis;
		if (count * 4 == bytes.size()) analysis = AnalyzeReceivers(raw, count, profile, receiverEntries, &inputs, &arrayRemainingSteps, &binding);
		if (analysis.arrayReads.empty() && analysis.lengthReturns.empty()) analysis = {}; // Bindings alone do not establish a read or callee effect.
		else {
			const auto previous = scalarResolutions.find({payload, bindings});
			for (auto it = analysis.resolutions.begin(); it != analysis.resolutions.end();) {
				const auto site = it->first, target = it->second.snapshotTarget;
				if ((globallyResolved.contains(site) && globallyResolved.at(site) == target) ||
					(previous != scalarResolutions.end() && previous->second.contains(site) && previous->second.at(site) == target)) it = analysis.resolutions.erase(it);
				else ++it;
			}
			checkedPoolClasses.insert(analysis.poolClasses.begin(), analysis.poolClasses.end());
		}
		arrayContexts.push_back({payload, callers, std::move(inputs), std::move(binding), std::move(analysis)});
	}
	// Path-qualified results have their own budget and never replace normal-flow facts.
	size_t pathAttempted = 0, pathRemainingSteps = 20000000;
	for (const auto& [key, callers] : arrayGroups) {
		if (pathAttempted >= 4096 || !pathRemainingSteps) break;
		++pathAttempted;
		const auto& [payload, bindings, offset, length, elements] = key;
		const auto& bytes = contextBytes.at(payload);
		cs_insn* raw = nullptr;
		const auto count = cs_disasm(decoder.handle, bytes.data(), bytes.size(), payload, 0, &raw);
		const std::shared_ptr<cs_insn> instructions(raw, [count](cs_insn* p) { cs_free(p, count); });
		if (count * 4 != bytes.size()) continue;
		const auto path = FindInitialStackCheck(raw, count, profile);
		if (!path) continue;
		std::vector<StackInput> inputs;
		for (const auto& [at, kind, value] : bindings) inputs.push_back({at, kind, value, {}});
		ArrayInputBinding binding{offset, length, elements};
		auto analysis = AnalyzeReceivers(raw, count, profile, receiverEntries, &inputs, &pathRemainingSteps, &binding, &*path);
		if (analysis.arrayReads.empty() && analysis.lengthReturns.empty()) continue;
		const auto previous = scalarResolutions.find({payload, bindings});
		for (auto it = analysis.resolutions.begin(); it != analysis.resolutions.end();) {
			const auto site = it->first, target = it->second.snapshotTarget;
			if ((globallyResolved.contains(site) && globallyResolved.at(site) == target) ||
				(previous != scalarResolutions.end() && previous->second.contains(site) && previous->second.at(site) == target)) it = analysis.resolutions.erase(it);
			else ++it;
		}
		checkedPoolClasses.insert(analysis.poolClasses.begin(), analysis.poolClasses.end());
		arrayPathContexts.push_back({payload, callers, std::move(inputs), std::move(binding), std::move(analysis), path});
	}
	// Preserve the original broad pass and its budgets. Requests identify exact
	// callees only; no effect is granted until the ordinary proof succeeds.
	Profile prefixProfile = profile;
	std::map<uint64_t, std::string> prefixEffects;
	std::set<uint64_t> requestedEffects;
	std::set<uint64_t> dispatchTargets;
	for (const auto target : profile.dispatchEntries) if (target) dispatchTargets.insert(*target);
	size_t helperAttempts = 0, helperSteps = 0, probeSteps = 20000000, helperRounds = 0;
	for (size_t round = 0; round < 2 && probeSteps && helperAttempts < 128; ++round) {
		++helperRounds;
		std::set<uint64_t> requests;
		for (const auto& [key, callers] : arrayGroups) {
			if (!probeSteps) break;
			const auto& [payload, bindings, offset, length, elements] = key;
			const auto& bytes = contextBytes.at(payload);
			cs_insn* raw = nullptr;
			const auto count = cs_disasm(decoder.handle, bytes.data(), bytes.size(), payload, 0, &raw);
			const std::shared_ptr<cs_insn> instructions(raw, [count](cs_insn* p) { cs_free(p, count); });
			if (count * 4 != bytes.size()) continue;
			const auto path = FindInitialStackCheck(raw, count, prefixProfile);
			if (!path) continue;
			std::vector<StackInput> inputs;
			for (const auto& [at, kind, value] : bindings) inputs.push_back({at, kind, value, {}});
			ArrayInputBinding binding{offset, length, elements};
			const auto probe = AnalyzeReceivers(raw, count, prefixProfile, receiverEntries, &inputs, &probeSteps, &binding, &*path, true, false, true);
			if (probe.missingArrayEffect) requests.insert(probe.missingArrayEffect->second);
		}
		bool changed = false;
		for (const auto target : requests) {
			if (helperAttempts >= 128) break;
			if (!requestedEffects.insert(target).second || target % 4) continue;
			const auto index = FindPayload(target);
			if (!index) continue;
			const auto& container = payloads[*index];
			const auto bytes = contextBytes.find(container.start);
			if (bytes == contextBytes.end() || container.end - target > 256 || (target - container.start) % 4 ||
				(target != container.start && !dispatchTargets.contains(target))) continue;
			// A recorded dispatch entry can skip a payload's checked-entry prefix.
			// Prove its retained suffix without changing the native inventory.
			const std::vector<uint8_t> body(bytes->second.begin() + (target - container.start), bytes->second.end());
			++helperAttempts;
			const auto effects = AnalyzeCallEffects({{target, body}}, prefixProfile);
			helperSteps += effects.steps;
			if (!effects.certificates.contains(target) || (!effects.arrayReturns.contains(target) && !effects.arrayLengths.contains(target))) continue;
			auto certificate = effects.certificates.at(target);
			if (target != container.start) certificate.insert(certificate.size()-1, std::format(",\"containing_payload\":{}", container.start));
			prefixEffects.emplace(target, std::move(certificate));
			prefixProfile.frameSafeCallees.insert(target);
			if (effects.arrayReturns.contains(target)) prefixProfile.arrayReturnInputs[target] = effects.arrayReturns.at(target);
			if (effects.arrayLengths.contains(target)) prefixProfile.arrayLengthEffects[target] = effects.arrayLengths.at(target);
			changed = true;
		}
		if (!changed) break;
	}
	size_t entryAttempted = 0, entryRemainingSteps = 20000000;
	for (const auto& [key, callers] : arrayGroups) {
		if (entryAttempted >= 4096 || !entryRemainingSteps) break;
		++entryAttempted;
		const auto& [payload, bindings, offset, length, elements] = key;
		const auto& bytes = contextBytes.at(payload);
		cs_insn* raw = nullptr;
		const auto count = cs_disasm(decoder.handle, bytes.data(), bytes.size(), payload, 0, &raw);
		const std::shared_ptr<cs_insn> instructions(raw, [count](cs_insn* p) { cs_free(p, count); });
		if (count * 4 != bytes.size()) continue;
		const auto path = FindInitialStackCheck(raw, count, prefixProfile);
		if (!path) continue;
		std::vector<StackInput> inputs;
		for (const auto& [at, kind, value] : bindings) inputs.push_back({at, kind, value, {}});
		ArrayInputBinding binding{offset, length, elements};
		auto analysis = AnalyzeReceivers(raw, count, prefixProfile, receiverEntries, &inputs, &entryRemainingSteps, &binding, &*path, true);
		if (analysis.indexedReturns.empty() || !analysis.traceStop) continue;
		const auto previous = scalarResolutions.find({payload, bindings});
		for (auto it = analysis.resolutions.begin(); it != analysis.resolutions.end();) {
			const auto site = it->first, target = it->second.snapshotTarget;
			if ((globallyResolved.contains(site) && globallyResolved.at(site) == target) ||
				(previous != scalarResolutions.end() && previous->second.contains(site) && previous->second.at(site) == target)) it = analysis.resolutions.erase(it);
			else ++it;
		}
		checkedPoolClasses.insert(analysis.poolClasses.begin(), analysis.poolClasses.end());
		arrayEntryTraces.push_back({payload, callers, std::move(inputs), std::move(binding), std::move(analysis), path});
	}
	size_t resultAttempted = 0, resultRemainingSteps = 20000000;
	for (const auto& [key, callers] : arrayGroups) {
		if (resultAttempted >= 4096 || !resultRemainingSteps) break;
		++resultAttempted;
		const auto& [payload, bindings, offset, length, elements] = key;
		const auto& bytes = contextBytes.at(payload);
		cs_insn* raw = nullptr;
		const auto count = cs_disasm(decoder.handle, bytes.data(), bytes.size(), payload, 0, &raw);
		const std::shared_ptr<cs_insn> instructions(raw, [count](cs_insn* p) { cs_free(p, count); });
		if (count * 4 != bytes.size()) continue;
		const auto path = FindInitialStackCheck(raw, count, prefixProfile);
		if (!path) continue;
		std::vector<StackInput> inputs;
		for (const auto& [at, kind, value] : bindings) inputs.push_back({at, kind, value, {}});
		ArrayInputBinding binding{offset, length, elements};
		auto analysis = AnalyzeReceivers(raw, count, prefixProfile, receiverEntries, &inputs, &resultRemainingSteps, &binding, &*path, true, true);
		if (analysis.indexedReturns.size() != 1 || !analysis.traceGetter || !analysis.traceStop || analysis.traceGetter == analysis.traceStop) continue;
		const auto previous = scalarResolutions.find({payload, bindings});
		for (auto it = analysis.resolutions.begin(); it != analysis.resolutions.end();) {
			const auto site = it->first, target = it->second.snapshotTarget;
			if (site != *analysis.traceStop || (globallyResolved.contains(site) && globallyResolved.at(site) == target) ||
				(previous != scalarResolutions.end() && previous->second.contains(site) && previous->second.at(site) == target)) it = analysis.resolutions.erase(it);
			else ++it;
		}
		if (!analysis.resolutions.contains(*analysis.traceStop)) continue;
		checkedPoolClasses.insert(analysis.poolClasses.begin(), analysis.poolClasses.end());
		arrayResultTraces.push_back({payload, callers, std::move(inputs), std::move(binding), std::move(analysis), path});
	}
	Profile registerProfile = prefixProfile;
	registerProfile.provedReturnClasses = machineReturnClasses;
	const auto registerContexts = AnalyzeRegisterContexts(edges, contextBytes, std::move(registerProfile), receiverEntries, entryStackLoads);
	for (const auto& context : registerContexts.contexts)
		checkedPoolClasses.insert(context.analysis.poolClasses.begin(), context.analysis.poolClasses.end());
	Profile resultProfile = prefixProfile;
	resultProfile.provedReturnClasses = machineReturnClasses;
	for (const auto& [entry, certificate] : registerContexts.effects) resultProfile.frameSafeCallees.insert(entry);
	resultProfile.forwardedReturnInputs.insert(registerContexts.forwardedInputs.begin(), registerContexts.forwardedInputs.end());
	const auto sdkResults = AnalyzeSdkStubResults(edges, contextBytes, resultProfile, receiverEntries, registerContexts);
	for (const auto entry : sdkResults.decodeFailures) {
		if (!reportSdkDecodeFailure) throw std::runtime_error("Cannot decode SDK result producer payload");
		reportSdkDecodeFailure(entry);
	}
	auto resultContexts = AnalyzeCallResultContexts(edges, contextBytes, selectedCaller ? resultProfile : std::move(resultProfile), receiverEntries, registerContexts);
	CallResultContextResult targeted;
	std::string targetedStatus;
	if (selectedCaller) {
		if (std::ranges::any_of(resultContexts.contexts, [&](const auto& c) { return c.payload == *selectedCaller; })) targetedStatus = "already_recorded";
		else if (!contextBytes.contains(*selectedCaller)) targetedStatus = "no_retained_bytes";
		else if (profile.wordReturnRegister != ARM64_REG_X0) targetedStatus = "unsupported_return_abi";
		else {
			targeted = AnalyzeCallResultContexts(edges, contextBytes, std::move(resultProfile), receiverEntries, registerContexts, selectedCaller);
			targetedStatus = CallResultContextStatus(targeted);
			for (auto& context : targeted.contexts) resultContexts.contexts.push_back(std::move(context));
		}
	}
	for (const auto& context : resultContexts.contexts)
		checkedPoolClasses.insert(context.analysis.poolClasses.begin(), context.analysis.poolClasses.end());
	for (const auto* collection : {&sdkResults.producers, &sdkResults.callers})
		for (const auto& context : collection->contexts)
			checkedPoolClasses.insert(context.analysis.poolClasses.begin(), context.analysis.poolClasses.end());
	if (presentResults) {
		presentResults(resultContexts);
		presentResults(sdkResults.producers);
		presentResults(sdkResults.callers);
	}
	std::ofstream out(filename);
	if (!out) throw std::runtime_error("Cannot create snapshot call graph");
	out << "{\"format\":26,\"address_basis\":\"ELF virtual addresses\",\"profile\":{\"name\":" << Quoted(profile.name)
		<< ",\"pool_register\":" << Quoted(RegName(profile.poolRegister)) << ",\"thread_register\":" << Quoted(RegName(profile.threadRegister))
		<< ",\"dispatch_register\":" << (profile.dispatchRegister == ARM64_REG_INVALID ? "null" : Quoted(RegName(profile.dispatchRegister)))
		<< ",\"pool_data_offset\":" << profile.poolDataOffset << ",\"pool_slot_size\":" << profile.poolSlotSize
		<< ",\"pool_length\":" << profile.poolLength << "},\"nodes\":[";
	for (size_t i = 0; i < payloads.size(); ++i) {
		if (i) out << ',';
		const auto& node = payloads[i];
		out << std::format("{{\"start\":{},\"end\":{},\"decoded\":{},\"label\":", node.start, node.end, node.decoded ? "true" : "false") << Quoted(node.label) << ",\"names\":[";
		for (size_t n = 0; n < node.names.size(); ++n) {
			if (n) out << ',';
			out << "{\"address\":" << node.names[n].address << ",\"kind\":" << Quoted(node.names[n].kind) << ",\"name\":" << Quoted(node.names[n].text) << '}';
		}
		out << "]}";
	}
	out << "],\"edges\":[";
	for (size_t i = 0; i < edges.size(); ++i) {
		if (i) out << ',';
		const auto& edge = edges[i];
		out << std::format("{{\"site\":{},\"source\":{},\"kind\":", edge.site, edge.source) << Quoted(edge.kind)
			<< ",\"target\":" << (edge.target ? std::to_string(*edge.target) : "null")
			<< ",\"target_payload\":" << (edge.targetPayload ? std::to_string(*edge.targetPayload) : "null")
			<< ",\"target_label\":" << Quoted(edge.targetLabel) << ",\"target_register\":" << Quoted(edge.targetRegister)
			<< ",\"via_kind\":" << Quoted(edge.viaKind) << ",\"via_offset\":" << (edge.viaOffset ? std::to_string(*edge.viaOffset) : "null") << ",\"proof\":";
		Proof(out, edge.proof);
		out << ",\"via_field_offset\":" << (edge.viaFieldOffset ? std::to_string(*edge.viaFieldOffset) : "null")
			<< ",\"index_register\":" << Quoted(edge.indexRegister)
			<< ",\"snapshot_target\":" << (edge.snapshotTarget ? std::to_string(*edge.snapshotTarget) : "null")
			<< ",\"register_constants\":[";
		for (size_t n = 0; n < edge.registerConstants.size(); ++n) {
			if (n) out << ',';
			const auto& input = edge.registerConstants[n];
			out << "{\"register\":" << Quoted(input.reg) << ",\"bits\":" << Quoted(std::format("{:#x}", input.bits)) << ",\"proof\":";
			Proof(out, input.proof); out << '}';
		}
		out << "],\"dispatch\":";
		if (!edge.dispatch) out << "null";
		else {
			const auto& value = *edge.dispatch;
			out << "{\"index\":" << (value.index ? std::to_string(*value.index) : "null")
				<< ",\"table_index\":" << (value.tableIndex ? std::to_string(*value.tableIndex) : "null")
				<< ",\"resolution\":" << Quoted(value.resolution) << ",\"proof\":";
			Proof(out, value.proof);
			out << ",\"expression\":";
			if (!value.expression) out << "null";
			else {
				const auto& expression = *value.expression;
				out << "{\"site\":" << expression.site << ",\"source_register\":" << Quoted(expression.sourceRegister)
					<< ",\"lsb\":" << expression.lsb << ",\"width\":" << expression.width << ",\"addend\":" << expression.addend << ",\"proof\":";
				Proof(out, expression.proof); out << '}';
			}
			out << '}';
		}
		out << ",\"static_dispatch\":";
		if (!edge.staticDispatch) out << "null";
		else {
			const auto& value = *edge.staticDispatch;
			out << "{\"load\":" << value.load << ",\"index\":" << value.index << ",\"table_index\":" << value.tableIndex
				<< ",\"snapshot_target\":" << value.snapshotTarget << ",\"proof\":";
			Proof(out, value.proof); out << '}';
		}
		out << ",\"stack_inputs\":[";
		for (size_t n = 0; n < edge.stackInputs.size(); ++n) {
			if (n) out << ',';
			const auto& value = edge.stackInputs[n];
			out << "{\"sp_offset\":" << value.spOffset << ",\"kind\":" << Quoted(value.kind)
				<< ",\"value\":" << Quoted(std::format("{:#x}", value.value)) << ",\"proof\":";
			Proof(out, value.proof); out << '}';
		}
		out << "],\"register_inputs\":[";
		for (size_t n = 0; n < edge.registerInputs.size(); ++n) {
			if (n) out << ',';
			const auto& value = edge.registerInputs[n];
			out << "{\"register\":\"x" << value.reg << "\",\"class_id\":" << value.classId << ",\"proof\":";
			Proof(out, value.proof); out << '}';
		}
		out << "],\"forwarded_return\":";
		if (edge.forwardedReturn) Forwarded(out, *edge.forwardedReturn); else out << "null";
		out << ",\"indexed_return\":";
		if (edge.indexedReturn) {
			const auto& value = *edge.indexedReturn;
			out << "{\"callee\":" << value.callee << ",\"allocation\":" << value.allocation << ",\"index\":" << value.index << ",\"class_id\":" << value.classId << ",\"register\":\"x0\",\"proof\":";
			Proof(out, value.proof); out << '}';
		} else out << "null";
		out << ",\"array_length_return\":";
		if (edge.arrayLengthReturn) LengthReturn(out, *edge.arrayLengthReturn); else out << "null";
		out << ",\"native_return\":";
		if (edge.kind == "call" && edge.target && profile.wordReturnRegister == ARM64_REG_X0 && profile.nativeReturnClasses.contains(*edge.target)) {
			const auto& value = profile.nativeReturnClasses.at(*edge.target);
			out << "{\"callee\":" << *edge.target << ",\"class_id\":" << value.classId << ",\"register\":\"x0\",\"contract\":" << Quoted(value.contract)
				<< ",\"condition\":\"normal_return\",\"basis\":\"matched_sdk_native_identity\"}";
		} else out << "null";
		out << ",\"sdk_stub_return\":";
		if (edge.kind == "call" && edge.target && profile.sdkStubReturnClasses.contains(*edge.target)) {
			const auto& value = profile.sdkStubReturnClasses.at(*edge.target);
			out << "{\"callee\":" << *edge.target << ",\"class_id\":" << value.classId << ",\"register\":\"x0\",\"contract\":\"allocate_growable_array\""
				<< ",\"condition\":\"normal_return\",\"basis\":\"matched_sdk_stub_identity\"}";
		} else out << "null";
		out << ",\"array_arguments\":[";
		for (size_t n = 0; n < edge.arrayArguments.size(); ++n) {
			if (n) out << ',';
			const auto& value = edge.arrayArguments[n];
			out << "{\"sp_offset\":" << value.spOffset << ",\"allocation\":" << value.allocation << ",\"length\":" << value.length << ",\"elements\":[";
			bool first = true;
			for (const auto& [index, cid] : value.elements) { if (!first) out << ','; first = false; out << '[' << index << ',' << cid << ']'; }
			out << "],\"proof\":"; Proof(out, value.proof); out << '}';
		}
		out << ']';
		out << '}';
	}
	out << "],\"entry_stack_loads\":[";
	for (size_t n = 0; n < entryStackLoads.size(); ++n) {
		if (n) out << ',';
		const auto& value = entryStackLoads[n];
		out << "{\"site\":" << value.site << ",\"payload\":" << value.payload << ",\"entry_sp_offset\":" << value.entrySpOffset
			<< ",\"register\":" << Quoted(value.reg) << ",\"width\":" << value.width << ",\"proof\":";
		Proof(out, value.proof); out << '}';
	}
	out << "],\"references\":[";
	for (size_t i = 0; i < references.size(); ++i) {
		if (i) out << ',';
		const auto& ref = references[i];
		out << std::format("{{\"site\":{},\"payload\":{},\"kind\":", ref.site, ref.payload) << Quoted(ref.kind)
			<< ",\"access\":" << Quoted(ref.access) << ",\"offset\":" << ref.offset << ",\"width\":" << ref.width
			<< ",\"base_register\":" << Quoted(ref.baseRegister)
			<< ",\"pool_index\":" << (ref.poolIndex ? std::to_string(*ref.poolIndex) : "null") << ",\"field_name\":" << Quoted(ref.fieldName) << ",\"proof\":";
		Proof(out, ref.proof); out << '}';
	}
	out << "],\"pool_catalog\":[";
	bool comma = false;
	for (const auto& [index, slot] : poolSlots) {
		if (comma) out << ',';
		comma = true;
		out << "{\"index\":" << index << ",\"kind\":" << Quoted(slot.kind) << ",\"description\":" << Quoted(slot.description) << ",\"entry_points\":[";
		bool first = true;
		for (const auto& [offset, target] : slot.entryPoints) {
			if (!first) out << ',';
			first = false;
			out << "{\"field_offset\":" << offset << ",\"target\":" << target << '}';
		}
		out << "]}";
	}
	out << "],\"thread_catalog\":[";
	comma = false;
	for (const auto& [offset, name] : profile.threadFields) {
		if (comma) out << ',';
		comma = true;
		out << "{\"offset\":" << offset << ",\"name\":" << Quoted(name) << '}';
	}
	out << "],\"dispatch_table\":{\"origin\":" << profile.dispatchOrigin
		<< ",\"snapshot_address\":" << (profile.dispatchSnapshotAddress ? std::to_string(*profile.dispatchSnapshotAddress) : "null")
		<< ",\"snapshot_size\":" << profile.dispatchSnapshotSize
		<< ",\"null_target\":" << (profile.dispatchNullTarget ? std::to_string(*profile.dispatchNullTarget) : "null") << ",\"entries\":[";
	for (size_t i = 0; i < profile.dispatchEntries.size(); ++i) {
		if (i) out << ',';
		out << (profile.dispatchEntries[i] ? std::to_string(*profile.dispatchEntries[i]) : "null");
	}
	out << "]},\"receiver_metadata\":{\"header_displacement\":" << profile.headerDisplacement << ",\"class_id_shift\":" << profile.classIdShift
		<< ",\"class_id_bits\":" << profile.classIdBits << ",\"null_register\":" << Quoted(RegName(profile.nullRegister))
		<< ",\"null_class_id\":" << profile.nullClassId << ",\"allocation_result_register\":" << Quoted(RegName(profile.allocationResultRegister)) << ",\"pool_classes\":[";
	bool first = true;
	for (const auto& [slot, cid] : checkedPoolClasses) { if (!first) out << ','; first = false; out << '[' << slot << ',' << cid << ']'; }
	out << "],\"word_return_register\":" << (profile.wordReturnRegister == ARM64_REG_X0 ? "\"x0\"" : "null");
	out << ",\"stack_limit_offset\":" << (profile.stackLimitOffset ? std::to_string(*profile.stackLimitOffset) : "null");
	out << ",\"heap_bits_register\":" << (profile.heapBitsRegister == ARM64_REG_X28 ? "\"x28\"" : "null");
	out << ",\"allocation_returns\":["; first = true;
	for (const auto& [address, cid] : profile.allocationReturns) { if (!first) out << ','; first = false; out << '[' << address << ',' << cid << ']'; }
	out << "],\"native_return_classes\":["; first = true;
	for (const auto& [entry, value] : profile.nativeReturnClasses) {
		if (!first) out << ','; first = false;
		out << '[' << entry << ',' << value.classId << ',' << Quoted(value.contract) << ']';
	}
	out << "],\"sdk_stub_return_classes\":["; first = true;
	for (const auto& [entry, value] : profile.sdkStubReturnClasses) {
		if (!first) out << ','; first = false;
		out << '[' << entry << ',' << value.classId << ",\"allocate_growable_array\"]";
	}
	out << "],\"machine_return_classes\":["; first = true;
	for (const auto& [entry, cid] : machineReturnClasses) { if (!first) out << ','; first = false; out << '[' << entry << ',' << cid << ']'; }
	out << "],\"thread_heap_classes\":["; first = true;
	for (const auto& [offset, cid] : profile.threadHeapClasses) { if (!first) out << ','; first = false; out << '[' << offset << ',' << cid << ']'; }
	out << "],\"frame_preserving_calls\":["; first = true;
	for (const auto& [entry, contract] : profile.framePreservingCalls) { if (!first) out << ','; first = false; out << '[' << entry << ',' << Quoted(contract) << ']'; }
	out << "],\"nonreturning_calls\":["; first = true;
	for (const auto& [entry, contract] : profile.nonReturningCalls) { if (!first) out << ','; first = false; out << '[' << entry << ',' << Quoted(contract) << ']'; }
	out << "],\"preserved_call_registers\":["; first = true;
	for (const auto& [entry, mask] : profile.preservedCallRegisters) { if (!first) out << ','; first = false; out << '[' << entry << ',' << mask << ']'; }
	out << "],\"leaf_math_contract\":["; first = true;
	for (const auto value : profile.leafMathContract) { if (!first) out << ','; first = false; out << value; }
	out << "],\"allocation_body_bounds\":["; first = true;
	for (const auto& [entry, interval] : profile.allocationBodyBounds) { if (!first) out << ','; first = false; out << '[' << entry << ',' << interval.first << ',' << interval.second << ']'; }
	out << "],\"array_body_contract\":["; first = true;
	for (const auto value : profile.arrayBodyContract) { if (!first) out << ','; first = false; out << value; }
	out << "],\"array_length_layout\":[";
	if (profile.arrayLengthLayout) {
		const auto& layout = *profile.arrayLengthLayout;
		out << layout.classId << ',' << layout.displacement << ',' << layout.bytes << ',' << layout.smiShift;
	}
	out << "],\"entries\":["; first = true;
	for (const auto address : receiverEntries) { if (!first) out << ','; first = false; out << address; }
	out << "]},\"receiver_certificates\":[";
	for (size_t n = 0; n < receiverCertificates.size(); ++n) { if (n) out << ','; out << receiverCertificates[n]; }
	out << "],\"call_effects\":["; first = true;
	for (const auto& [entry, certificate] : callEffectCertificates) { if (!first) out << ','; first = false; out << certificate; }
	out << "],\"call_effect_analysis\":{\"attempted\":" << callEffectAttempts << ",\"transfer_steps\":" << callEffectSteps
		<< ",\"depth_limit\":8,\"payload_byte_limit\":4096,\"step_limit\":2000000},\"call_contexts\":[";
	for (size_t n = 0; n < contexts.size(); ++n) {
		if (n) out << ',';
		const auto& context = contexts[n];
		out << "{\"payload\":" << context.payload << ",\"callers\":"; Proof(out, context.callers);
		out << ",\"inputs\":[";
		for (size_t k = 0; k < context.inputs.size(); ++k) {
			if (k) out << ',';
			const auto& value = context.inputs[k];
			out << "{\"sp_offset\":" << value.spOffset << ",\"kind\":" << Quoted(value.kind) << ",\"value\":" << Quoted(std::format("{:#x}", value.value)) << '}';
		}
		out << "],\"resolutions\":["; bool firstResolution = true;
		for (const auto& [site, value] : context.analysis.resolutions) {
			if (!firstResolution) out << ','; firstResolution = false;
			out << "{\"site\":" << site << ",\"load\":" << value.load << ",\"index\":" << value.index << ",\"table_index\":" << value.tableIndex
				<< ",\"snapshot_target\":" << value.snapshotTarget << ",\"proof\":"; Proof(out, value.proof); out << '}';
		}
		out << "],\"forwarded_returns\":["; bool firstReturn = true;
		for (const auto& [site, value] : context.analysis.forwardedReturns) {
			if (!firstReturn) out << ','; firstReturn = false;
			Forwarded(out, value, site);
		}
		out << "],\"array_length_returns\":["; bool firstLength = true;
		for (const auto& [site, value] : context.analysis.lengthReturns) {
			if (!firstLength) out << ','; firstLength = false; LengthReturn(out, value, site);
		}
		out << "],\"certificate\":" << context.analysis.certificate << '}';
	}
	out << "],\"context_analysis\":{\"candidate_groups\":" << groups.size() << ",\"attempted_groups\":" << attempted
		<< ",\"transfer_steps\":" << 20000000 - remainingSteps << ",\"cached_bytes\":" << contextBytesSize
		<< ",\"group_limit\":4096,\"step_limit\":20000000,\"cache_limit\":33554432}";
	auto writeArrays = [&](const auto& collection) {
	out << '[';
	for (size_t n = 0; n < collection.size(); ++n) {
		if (n) out << ',';
		const auto& context = collection[n];
		out << "{\"payload\":" << context.payload << ",\"callers\":"; Proof(out, context.callers);
		out << ",\"inputs\":[";
		for (size_t k = 0; k < context.inputs.size(); ++k) {
			if (k) out << ',';
			const auto& input = context.inputs[k];
			out << "{\"sp_offset\":" << input.spOffset << ",\"kind\":" << Quoted(input.kind) << ",\"value\":" << Quoted(std::format("{:#x}", input.value)) << '}';
		}
		out << "],\"array_input\":{\"sp_offset\":" << context.binding.spOffset << ",\"length\":" << context.binding.length << ",\"elements\":[";
		bool firstElement = true;
		for (const auto& [index, cid] : context.binding.elements) {
			if (!firstElement) out << ','; firstElement = false; out << '[' << index << ',' << cid << ']';
		}
		out << "]},\"scope\":" << Quoted(context.analysis.traceGetter ? "entry_result_use" : !context.analysis.traceBlocks.empty() ? "entry_prefix" : context.path ? "initial_stack_check_fast_path" : context.analysis.arrayContinuationUsed ? "entry_chain" : "entry_block")
			<< ",\"status\":" << Quoted(context.analysis.traceGetter ? "result_dispatch_proved" : !context.analysis.traceBlocks.empty() ? "indexed_result_proved" : !context.analysis.arrayReads.empty() ? "read_proved" : !context.analysis.lengthReturns.empty() ? "length_proved" : "bound_only") << ",\"array_reads\":[";
		bool firstRead = true;
		for (const auto& [site, read] : context.analysis.arrayReads) {
			if (!firstRead) out << ','; firstRead = false;
			out << "{\"site\":" << site << ",\"input_sp_offset\":" << read.inputSpOffset << ",\"index\":" << read.index << ",\"class_id\":" << read.classId
				<< ",\"register\":" << Quoted(read.reg) << ",\"proof\":"; Proof(out, read.proof); out << '}';
		}
		out << "],\"resolutions\":["; bool firstResolution = true;
		for (const auto& [site, value] : context.analysis.resolutions) {
			if (!firstResolution) out << ','; firstResolution = false;
			out << "{\"site\":" << site << ",\"load\":" << value.load << ",\"index\":" << value.index << ",\"table_index\":" << value.tableIndex
				<< ",\"snapshot_target\":" << value.snapshotTarget << ",\"proof\":"; Proof(out, value.proof); out << '}';
		}
		out << "],\"array_length_returns\":["; bool firstLength = true;
		for (const auto& [site, value] : context.analysis.lengthReturns) {
			if (!firstLength) out << ','; firstLength = false; LengthReturn(out, value, site);
		}
		if (!context.analysis.traceBlocks.empty()) {
			out << "],\"indexed_returns\":["; bool firstIndexed = true;
			for (const auto& [site, value] : context.analysis.indexedReturns) {
				if (!firstIndexed) out << ','; firstIndexed = false;
				out << "{\"site\":" << site << ",\"callee\":" << value.callee << ",\"allocation\":null,\"entry_input_sp_offset\":" << *value.entryInputSpOffset
					<< ",\"index\":" << value.index << ",\"class_id\":" << value.classId << ",\"register\":\"x0\",\"proof\":";
				Proof(out, value.proof); out << '}';
			}
			out << "],\"trace\":{\"blocks\":"; Proof(out, context.analysis.traceBlocks);
			if (context.analysis.traceGetter) out << ",\"getter\":" << *context.analysis.traceGetter;
			out << ",\"stop\":" << *context.analysis.traceStop << ",\"stack_checks\":[";
			for (size_t k = 0; k < context.analysis.traceGuards.size(); ++k) {
				if (k) out << ',';
				const auto& guard = context.analysis.traceGuards[k];
				out << "{\"edge\":\"fallthrough\",\"site\":" << guard.site << ",\"successor\":" << guard.successor << ",\"slow_path\":" << guard.slowPath
					<< ",\"stub\":" << guard.stub << ",\"proof\":"; Proof(out, guard.proof); out << '}';
			}
			out << ']';
		}
		out << (context.analysis.traceBlocks.empty() ? "]" : "}") << ",\"certificate\":" << (context.analysis.certificate.empty() ? "null" : context.analysis.certificate);
		if (context.path) {
			const auto& path = *context.path;
			out << ",\"path_condition\":{\"edge\":\"fallthrough\",\"site\":" << path.site << ",\"successor\":" << path.successor
				<< ",\"slow_path\":" << path.slowPath << ",\"stub\":" << path.stub << ",\"proof\":";
			Proof(out, path.proof); out << '}';
		}
		out << '}';
	}
	out << ']';
	};
	out << ",\"prefix_call_effects\":["; first = true;
	for (const auto& [entry, certificate] : prefixEffects) { if (!first) out << ','; first = false; out << certificate; }
	out << "],\"prefix_effect_analysis\":{\"requested\":" << requestedEffects.size() << ",\"attempted\":" << helperAttempts
		<< ",\"accepted\":" << prefixEffects.size() << ",\"transfer_steps\":" << helperSteps << ",\"probe_steps\":" << 20000000 - probeSteps
		<< ",\"rounds\":" << helperRounds << ",\"round_limit\":2,\"attempt_limit\":128,\"payload_byte_limit\":256,\"probe_step_limit\":20000000,\"per_helper_step_limit\":20000,\"per_helper_array_step_limit\":300000}";
	out << ",\"array_contexts\":"; writeArrays(arrayContexts);
	out << ",\"array_path_contexts\":"; writeArrays(arrayPathContexts);
	out << ",\"array_entry_traces\":"; writeArrays(arrayEntryTraces);
	out << ",\"array_result_traces\":"; writeArrays(arrayResultTraces);
	out << ",\"array_result_analysis\":{\"candidate_groups\":" << arrayGroups.size() << ",\"attempted_groups\":" << resultAttempted
		<< ",\"transfer_steps\":" << 20000000 - resultRemainingSteps << ",\"group_limit\":4096,\"step_limit\":20000000,\"trace_instruction_limit\":256,\"trace_block_limit\":64}";
	out << ",\"array_entry_analysis\":{\"candidate_groups\":" << arrayGroups.size() << ",\"attempted_groups\":" << entryAttempted
		<< ",\"transfer_steps\":" << 20000000 - entryRemainingSteps << ",\"group_limit\":4096,\"step_limit\":20000000,\"trace_instruction_limit\":256,\"trace_block_limit\":64}";
	out << ",\"array_path_analysis\":{\"candidate_groups\":" << arrayGroups.size() << ",\"attempted_groups\":" << pathAttempted
		<< ",\"transfer_steps\":" << 20000000 - pathRemainingSteps << ",\"group_limit\":4096,\"step_limit\":20000000}";
	out << ",\"array_context_analysis\":{\"candidate_groups\":" << arrayGroups.size() << ",\"attempted_groups\":" << arrayAttempted
		<< ",\"transfer_steps\":" << 20000000 - arrayRemainingSteps << ",\"group_limit\":4096,\"step_limit\":20000000}";
	out << ",\"register_call_effects\":["; first = true;
	for (const auto& [entry, certificate] : registerContexts.effects) { if (!first) out << ','; first = false; out << certificate; }
	out << "],\"register_contexts\":[";
	for (size_t n = 0; n < registerContexts.contexts.size(); ++n) {
		if (n) out << ',';
		const auto& context = registerContexts.contexts[n];
		out << "{\"payload\":" << context.payload << ",\"callers\":"; Proof(out, context.callers);
		out << ",\"inputs\":[";
		for (size_t k = 0; k < context.stackInputs.size(); ++k) {
			if (k) out << ','; const auto& value = context.stackInputs[k];
			out << "{\"sp_offset\":" << value.spOffset << ",\"kind\":" << Quoted(value.kind) << ",\"value\":" << Quoted(std::format("{:#x}", value.value)) << '}';
		}
		out << "],\"register_inputs\":[";
		for (size_t k = 0; k < context.registerInputs.size(); ++k) {
			if (k) out << ','; const auto& value = context.registerInputs[k];
			out << "{\"register\":\"x" << value.reg << "\",\"class_id\":" << value.classId << '}';
		}
		out << "],\"resolutions\":["; first = true;
		for (const auto& [site, value] : context.analysis.resolutions) {
			if (!first) out << ','; first = false;
			out << "{\"site\":" << site << ",\"load\":" << value.load << ",\"index\":" << value.index << ",\"table_index\":" << value.tableIndex
				<< ",\"snapshot_target\":" << value.snapshotTarget << ",\"proof\":"; Proof(out, value.proof); out << '}';
		}
		out << "],\"forwarded_returns\":["; first = true;
		for (const auto& [site, value] : context.analysis.forwardedReturns) { if (!first) out << ','; first = false; Forwarded(out, value, site); }
		out << "],\"array_length_returns\":["; first = true;
		for (const auto& [site, value] : context.analysis.lengthReturns) { if (!first) out << ','; first = false; LengthReturn(out, value, site); }
		out << "],\"stack_observations\":["; first = true;
		for (const auto& [site, values] : context.analysis.stackInputs) {
			if (!first) out << ','; first = false;
			out << "{\"site\":" << site << ",\"values\":[";
			for (size_t k = 0; k < values.size(); ++k) {
				if (k) out << ','; const auto& value = values[k];
				out << "{\"sp_offset\":" << value.spOffset << ",\"kind\":" << Quoted(value.kind) << ",\"value\":" << Quoted(std::format("{:#x}", value.value)) << ",\"proof\":";
				Proof(out, value.proof); out << '}';
			}
			out << "]}";
		}
		out << "],\"normal_return_class\":" << (context.analysis.normalReturnClass ? std::to_string(*context.analysis.normalReturnClass) : "null")
			<< ",\"certificate\":" << context.analysis.certificate << '}';
	}
	out << "],\"register_context_analysis\":{\"candidate_groups\":" << registerContexts.candidateGroups << ",\"attempted_groups\":" << registerContexts.attempted
		<< ",\"transfer_steps\":" << registerContexts.steps << ",\"effect_attempts\":" << registerContexts.effectAttempts << ",\"effect_steps\":" << registerContexts.effectSteps
		<< ",\"binding_steps\":" << registerContexts.bindingSteps << ",\"dropped_callers\":" << registerContexts.droppedCallers
		<< ",\"group_limit\":4096,\"step_limit\":20000000,\"binding_step_limit\":2000000,\"effect_attempt_limit\":128,\"effect_byte_limit\":256,\"round_limit\":3}";
	out << ",\"call_result_contexts\":"; WriteCallResultContexts(out, resultContexts);
	out << ",\"sdk_stub_producer_contexts\":"; WriteCallResultContexts(out, sdkResults.producers);
	out << ",\"sdk_stub_caller_contexts\":"; WriteCallResultContexts(out, sdkResults.callers);
	out << ",\"sdk_stub_return_summaries\":["; first = true;
	for (const auto& [entry, cid] : sdkResults.summaries) {
		if (!first) out << ','; first = false;
		out << '[' << entry << ',' << cid << ']';
	}
	out << "],\"sdk_stub_decode_failures\":["; first = true;
	for (const auto entry : sdkResults.decodeFailures) { if (!first) out << ','; first = false; out << entry; }
	out << "],\"sdk_stub_result_analysis\":{\"producers\":";
	auto sdkWork = [&](const auto& work) {
		out << "{\"candidate_payloads\":" << work.candidatePayloads << ",\"attempted_payloads\":" << work.attempted
			<< ",\"transfer_steps\":" << work.steps << ",\"dropped_callers\":" << work.droppedCallers
			<< ",\"payload_limit\":4096,\"step_limit\":20000000}";
	};
	sdkWork(sdkResults.producers);
	out << ",\"callers\":"; sdkWork(sdkResults.callers); out << '}';
	out << ",\"call_result_analysis\":{\"candidate_payloads\":" << resultContexts.candidatePayloads << ",\"attempted_payloads\":" << resultContexts.attempted
		<< ",\"transfer_steps\":" << resultContexts.steps << ",\"dropped_callers\":" << resultContexts.droppedCallers << ",\"payload_limit\":4096,\"step_limit\":20000000}";
	if (selectedCaller) out << ",\"targeted_call_result_analysis\":{\"payload\":" << *selectedCaller << ",\"status\":" << Quoted(targetedStatus)
		<< ",\"candidate_payloads\":" << targeted.candidatePayloads << ",\"attempted_payloads\":" << targeted.attempted
		<< ",\"transfer_steps\":" << targeted.steps << ",\"payload_limit\":1,\"step_limit\":" << TargetedResultStepLimit << '}';
	out << ",\"limits\":\"Snapshot facts, not runtime target proof. static_dispatch remains the context-free normal-flow inference. call_contexts are one-level direct-caller analyses with explicit input bindings, not global receiver types. Only exact payload entries with recent stack observations are candidates. Unknown calls/stores and overlapping writes kill input bindings; they are never recreated. Reviewed SDK helpers and machine-code-proved callee effects preserve live inputs only with a separate negative caller frame and no other stack-address register aliases. Frame-only callee effects preserve caller-frame classes. Checked length leaves can additionally preserve unwritten working registers and selected array contents; no source return type is inferred. A separate return_input relation proves full-word X0 forwarding from one aligned entry stack slot on all normal returns of a call-free payload; its first consumer propagates only a known heap-object class. forwarded_returns in call_contexts remain conditional on their explicit caller bindings. Allocation body writes require separately audited fixed sizes or a known nonnegative Smi array length; headers and array metadata are excluded. native_return records are conditional matched-SDK result classes at direct calls, with no caller-frame, register or mutable-heap preservation implied. Unknown native calls, recursion and unsupported writes remain conservative. Bounds/unsupported paths may leave contexts unresolved. stack_inputs and entry_stack_loads remain partial physical observations, not complete source parameter lists. array_arguments are partial element-class observations in fresh arrays of at most 32 elements, confined to the allocation return block and checked unique length-call continuations. Other calls, branch boundaries and unproved stores discard their contents; known overlapping stores invalidate the affected elements. array_contexts separately bind one observed input array per direct-caller context, using an independent bounded budget. bound_only records establish supplied contents, not a callee read. read_proved records require an entry-block or checked entry-chain read certificate. length_proved records require a checked length-call result. Exact-target length leaves preserve contents only with a verified argument root and register-write mask at an untargeted immediate normal-return block. Packed values and saved index words are dropped there. Other calls and branch boundaries discard contents; entry backedges disable this consumer. array_path_contexts additionally require their explicit initial-stack-check fallthrough condition, checked against the matched SDK offset and slow stub. They exclude the initial slow edge only; the runtime stub has no asserted heap-preservation contract. They never replace unconditional array_contexts or global dispatch facts. array_entry_traces additionally describe one non-revisiting entry prefix ending at its first proved indexed result. Every chosen branch is concrete or an explicit checked stack condition; later iterations and post-getter execution are outside that scope. array_result_traces separately follow the getter result to the first later call, retaining scalar class/register data provenance and expiring array contents, prior input bindings and spills at the getter. Their stopped indirect target must derive from the result; unrelated or intervening calls produce no result-use claim. prefix_call_effects contain separately proved small callees requested by exact array-bound prefix calls. An interior helper must be an aligned dispatch-table entry within retained payload bytes; containing_payload identifies its unchanged native container and only the entry-to-end suffix is proved. They supplement entry/result traces only, with independent bounded work; original broad effects and ordinary contexts keep their original budgets and assumptions. These bindings do not claim global callee types or stable heap-pointer identities. A separate array_return certificate proves an element result for a nonnegative Smi index in [0,31] on all normal returns, with no heap writes or returning calls. indexed_return consumes this relation only for known in-bounds local fresh-array elements; array contents are still discarded at the call. Only separately audited SDK nonreturning_calls terminate call fallthrough. Unknown calls remain potentially returning. register_inputs additionally observe full-width heap classes in nonreserved X0 through X14; they are not source signatures. register_contexts have separate bounded work, explicit entry bindings, independent frame proofs and no promotion of conditional results to global helper types. Backward register liveness and observed callee stack loads select relevant bindings without proving types. return_classes describe individual normal RET sites; machine_return_classes additionally require a closed body and agreement at every reached normal return. These result-only summaries grant no preservation effects. call_result_contexts separately consume global or caller-qualified helper results at exact original direct BL sites; their derived caller facts never feed back into the producer proofs. Old scalar/array contexts retain their own inputs and budgets. Dropped register/result callers are counted explicitly. Exception-handler edges and unknown indirect entries are not recovered.\"}\n";
}
}
