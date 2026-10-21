#include "SnapshotCodeAnalysis.h"
#include <algorithm>
#include <array>
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
	if (IsX(reg) || reg == ARM64_REG_SP || (reg >= ARM64_REG_D0 && reg <= ARM64_REG_D31)) return 8;
	if ((reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) || (reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31)) return 4;
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
};
}

Analyzer::Analyzer(Profile config, std::vector<Payload> ranges, std::vector<Name> names)
	: profile(std::move(config)), payloads(std::move(ranges))
{
	if (RegNumber(profile.poolRegister) < 0 || RegNumber(profile.threadRegister) < 0 ||
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
		if (const auto index = FindPayload(name.address)) payloads[*index].names.push_back(std::move(name));
	}
	for (auto& payload : payloads) {
		payload.label = payload.names.empty() ? std::format("unattributed_code_{:x}", payload.start) : payload.names.front().text;
	}
}
void Analyzer::RegisterEntries(const cs_insn* instructions, size_t count)
{
	for (size_t i = 0; i < count; ++i) {
		if (!instructions[i].detail) throw std::runtime_error("Missing ARM64 instruction details");
		if (!Transfer(instructions[i])) continue;
		const auto& detail = instructions[i].detail->arm64;
		for (uint8_t n = 0; n < detail.op_count; ++n)
			if (detail.operands[n].type == ARM64_OP_IMM) entries.insert(detail.operands[n].imm);
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
	const int poolReg = RegNumber(profile.poolRegister);
	const int threadReg = RegNumber(profile.threadRegister);
	bool poolWritten = false, threadWritten = false;
	std::set<uint64_t> blockStarts;
	for (size_t i = 0; i < count; ++i) {
		const auto& instruction = instructions[i];
		if (!instruction.detail || instruction.size != 4) throw std::runtime_error("Missing ARM64 instruction details");
		const auto writes = Written(instruction);
		poolWritten |= writes.contains(poolReg);
		threadWritten |= writes.contains(threadReg);
		if (Transfer(instruction)) {
			const auto& detail = instruction.detail->arm64;
			for (uint8_t n = 0; n < detail.op_count; ++n) {
				if (detail.operands[n].type == ARM64_OP_IMM) blockStarts.insert(detail.operands[n].imm);
			}
		}
	}
	std::array<std::optional<Origin>, 31> state;
	auto reset = [&]() {
		state.fill({});
		if (!poolWritten) state[poolReg] = Origin{"pool", 0, true, {}};
		if (!threadWritten) state[threadReg] = Origin{"thread", 0, true, {}};
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
					edges.push_back(std::move(edge));
				}
			} else if (target.type == ARM64_OP_REG) {
				Edge edge{instruction.address, payload.start, call ? "indirect_call" : "indirect_jump", {}, {}, "", RegName(target.reg), "", {}, {}};
				const int reg = RegNumber(target.reg);
				if (reg >= 0 && state[reg] && !state[reg]->address) {
					edge.viaKind = state[reg]->kind;
					edge.viaOffset = state[reg]->offset;
					edge.proof = state[reg]->proof;
				}
				note(std::format("{} via {} [target unresolved]", edge.kind, edge.targetRegister));
				if (edge.viaOffset) note(std::format("register loaded from {}+{:#x}", edge.viaKind, *edge.viaOffset));
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
				if (base >= 0 && memory.index == ARM64_REG_INVALID && state[base] && state[base]->address) {
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
		for (const int reg : Written(instruction)) state[reg].reset();
		if (produced && destination >= 0) state[destination] = std::move(produced);
		for (auto& [reg, origin] : loaded) state[reg] = std::move(origin);
		afterTransfer = Transfer(instruction);
	}
	return comments;
}

void Analyzer::Write(const std::string& filename) const
{
	std::ofstream out(filename);
	if (!out) throw std::runtime_error("Cannot create snapshot call graph");
	out << "{\"format\":1,\"address_basis\":\"ELF virtual addresses\",\"profile\":{\"name\":" << Quoted(profile.name)
		<< ",\"pool_register\":" << Quoted(RegName(profile.poolRegister)) << ",\"thread_register\":" << Quoted(RegName(profile.threadRegister))
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
		Proof(out, edge.proof); out << '}';
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
		out << "{\"index\":" << index << ",\"kind\":" << Quoted(slot.kind) << ",\"description\":" << Quoted(slot.description) << '}';
	}
	out << "],\"thread_catalog\":[";
	comma = false;
	for (const auto& [offset, name] : profile.threadFields) {
		if (comma) out << ',';
		comma = true;
		out << "{\"offset\":" << offset << ",\"name\":" << Quoted(name) << '}';
	}
	out << "],\"limits\":\"Static instruction references only. Indirect targets, absent names/types and high-level Dart semantics remain unknown. Alias tracking stops at transfers and known joins; unknown indirect entries are not a dominance proof. Payloads that write an ABI base register do not assume that base.\"}\n";
}
}
