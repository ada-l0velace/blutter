#include "SnapshotCodeAnalysis.h"
#include "ReceiverAnalysis.h"
#include <algorithm>
#include <array>
#include <bit>
#include <format>
#include <fstream>
#include <limits>
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
	const auto& d = instruction.detail->arm64;
	if (d.op_count < 2 || d.operands[0].type != ARM64_OP_REG || RegNumber(d.operands[0].reg) < 0) return {};
	const auto width = RegWidth(d.operands[0].reg);
	const uint64_t mask = width == 8 ? UINT64_MAX : UINT32_MAX;
	std::optional<Constant> result;
	const auto& source = d.operands[1];
	if (instruction.id == ARM64_INS_MOV && d.op_count == 2) {
		if (source.type == ARM64_OP_IMM) result = Constant{static_cast<uint64_t>(source.imm) & mask, {}};
		else if (source.type == ARM64_OP_REG && RegWidth(source.reg) == width) {
			if (source.reg == ARM64_REG_XZR || source.reg == ARM64_REG_WZR) result = Constant{0, {}};
			else if (const int r = RegNumber(source.reg); r >= 0) result = constants[r];
		}
	} else if ((instruction.id == ARM64_INS_MOVZ || instruction.id == ARM64_INS_MOVN || instruction.id == ARM64_INS_MOVK) &&
		d.op_count == 2 && source.type == ARM64_OP_IMM && source.imm >= 0 && source.imm <= 0xffff &&
		(source.shift.type == ARM64_SFT_INVALID || source.shift.type == ARM64_SFT_LSL)) {
		const unsigned shift = source.shift.type == ARM64_SFT_INVALID ? 0 : source.shift.value;
		if (shift % 16 == 0 && shift < width * 8) {
			const auto value = static_cast<uint64_t>(source.imm) << shift;
			if (instruction.id == ARM64_INS_MOVK) {
				result = constants[RegNumber(d.operands[0].reg)];
				if (result) result->bits = (result->bits & ~(uint64_t{0xffff} << shift)) | value;
			} else result = Constant{instruction.id == ARM64_INS_MOVN ? ~value : value, {}};
		}
	}
	else if ((instruction.id == ARM64_INS_ADD || instruction.id == ARM64_INS_SUB) && d.op_count == 3 &&
		source.type == ARM64_OP_REG && RegWidth(source.reg) == width) {
		const auto left = RegisterValue(source.reg, constants);
		const auto right = ArithmeticOperand(d.operands[2], width, constants);
		if (left && right)
			result = Constant{instruction.id == ARM64_INS_ADD ? left->bits + right->bits : left->bits - right->bits,
				MergeProof(left->proof, right->proof)};
	} else if (instruction.id == ARM64_INS_UBFX && d.op_count == 4 && source.type == ARM64_OP_REG &&
		RegWidth(source.reg) == width && d.operands[2].type == ARM64_OP_IMM && d.operands[3].type == ARM64_OP_IMM) {
		const auto value = RegisterValue(source.reg, constants);
		const auto lsb = d.operands[2].imm, size = d.operands[3].imm;
		if (value && lsb >= 0 && size > 0 && size < 64 && lsb + size <= width * 8)
			result = Constant{(value->bits >> lsb) & ((uint64_t{1} << size) - 1), value->proof};
	}
	if (result) {
		if (result->proof.size() >= 64) return {};
		result->bits &= mask;
		result->proof.push_back(instruction.address);
	}
	return result;
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

Analyzer::Analyzer(Profile config, std::vector<Payload> ranges, std::vector<Name> names)
	: profile(std::move(config)), payloads(std::move(ranges))
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
		for (size_t n = firstEdge; n < edges.size(); ++n) if (const auto found = receiver.resolutions.find(edges[n].site); found != receiver.resolutions.end()) {
			edges[n].staticDispatch = found->second;
			auto& comment = comments[edges[n].site];
			if (!comment.empty()) comment += " | ";
			comment += std::format("normal-flow receiver/index proof -> snapshot {:#x}", found->second.snapshotTarget);
		}
		if (!receiver.certificate.empty()) receiverCertificates.push_back(std::move(receiver.certificate));
		receiverPoolClasses.insert(receiver.poolClasses.begin(), receiver.poolClasses.end());
	}
	return comments;
}

void Analyzer::Write(const std::string& filename) const
{
	std::ofstream out(filename);
	if (!out) throw std::runtime_error("Cannot create snapshot call graph");
	out << "{\"format\":4,\"address_basis\":\"ELF virtual addresses\",\"profile\":{\"name\":" << Quoted(profile.name)
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
		out << '}';
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
	for (const auto& [slot, cid] : receiverPoolClasses) { if (!first) out << ','; first = false; out << '[' << slot << ',' << cid << ']'; }
	out << "],\"allocation_returns\":["; first = true;
	for (const auto& [address, cid] : profile.allocationReturns) { if (!first) out << ','; first = false; out << '[' << address << ',' << cid << ']'; }
	out << "],\"entries\":["; first = true;
	for (const auto address : receiverEntries) { if (!first) out << ','; first = false; out << address; }
	out << "]},\"receiver_certificates\":[";
	for (size_t n = 0; n < receiverCertificates.size(); ++n) { if (n) out << ','; out << receiverCertificates[n]; }
	out << "],\"limits\":\"Snapshot facts, not runtime target proof. static_dispatch uses a bounded normal-flow must-fact CFG with entry resets, equal-value joins and equality guards. Indirect-jump payloads and resource-limit failures produce no CFG results. Exception/unknown indirect entries and stack arguments are not recovered. Original local facts stop at transfers/joins.\"}\n";
}
}
