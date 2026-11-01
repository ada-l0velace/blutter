#include "RegisterContexts.h"
#include "CallEffects.h"
#include <algorithm>
#include <deque>
#include <memory>
#include <stdexcept>
#include <tuple>

namespace SnapshotAnalysis {
namespace {
constexpr uint32_t InputsMask = (1U << 15)-1;
int InputRegister(arm64_reg reg) {
	if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X14) return reg-ARM64_REG_X0;
	if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W14) return reg-ARM64_REG_W0;
	return -1;
}
// Backward liveness selects useful bindings; it grants no type or effect.
// Unsupported decoding/work limits retain every candidate register instead.
uint32_t EntryInputs(csh decoder, uint64_t entry, const std::vector<uint8_t>& bytes,
	const Profile& profile, size_t& steps)
{
	if (bytes.empty() || bytes.size()%4 || bytes.size()/4 > 16384 || entry > UINT64_MAX-bytes.size() || steps >= 2000000) return InputsMask;
	cs_insn* raw = nullptr;
	const auto count = cs_disasm(decoder, bytes.data(), bytes.size(), entry, 0, &raw);
	const std::shared_ptr<cs_insn> owner(raw, [count](cs_insn* p) { cs_free(p, count); });
	if (count*4 != bytes.size()) return InputsMask;
	std::vector<uint32_t> uses(count), definitions(count), incoming(count);
	std::vector<std::vector<size_t>> successors(count), predecessors(count);
	for (size_t n = 0; n < count; ++n) {
		const auto& i = raw[n]; const auto& d = i.detail->arm64;
		cs_regs read{}, written{}; uint8_t readCount = 0, writtenCount = 0;
		if (cs_regs_access(decoder, &i, read, &readCount, written, &writtenCount) != CS_ERR_OK) return InputsMask;
		const bool flags = i.id == ARM64_INS_CMP || i.id == ARM64_INS_CMN || i.id == ARM64_INS_TST || i.id == ARM64_INS_CCMP || i.id == ARM64_INS_CCMN;
		auto use = [&](arm64_reg reg) { if (const auto r = InputRegister(reg); r >= 0) uses[n] |= 1U << r; };
		auto define = [&](arm64_reg reg) { if (const auto r = InputRegister(reg); r >= 0) definitions[n] |= 1U << r; };
		for (unsigned k = 0; k < readCount; ++k) use(static_cast<arm64_reg>(read[k]));
		if (!flags) for (unsigned k = 0; k < writtenCount; ++k) define(static_cast<arm64_reg>(written[k]));
		for (unsigned k = 0; k < d.op_count; ++k) {
			const auto& op = d.operands[k];
			if (op.type == ARM64_OP_REG) {
				if (flags || op.access & CS_AC_READ || i.id == ARM64_INS_MOVK) use(op.reg);
				if (!flags && op.access & CS_AC_WRITE) define(op.reg);
			} else if (op.type == ARM64_OP_MEM) { use(op.mem.base); use(op.mem.index); if (d.writeback) define(op.mem.base); }
		}
		if (i.id == ARM64_INS_RET) uses[n] |= 1U; // Physical result observed by the caller.
		if (i.id == ARM64_INS_BL && d.op_count == 1 && d.operands[0].type == ARM64_OP_IMM) {
			const auto target = static_cast<uint64_t>(d.operands[0].imm);
			uint32_t preserved = 0;
			if (profile.preservedCallRegisters.contains(target)) preserved = profile.preservedCallRegisters.at(target);
			if (profile.arrayLengthEffects.contains(target)) preserved |= ~profile.arrayLengthEffects.at(target).writtenRegisters;
			definitions[n] |= InputsMask & ~preserved;
		}
		auto append = [&](uint64_t target) {
			if (target >= entry && target-entry < bytes.size() && (target-entry)%4 == 0) successors[n].push_back((target-entry)/4);
		};
		if (i.id == ARM64_INS_RET || i.id == ARM64_INS_BRK || i.id == ARM64_INS_HLT ||
			(i.id == ARM64_INS_BL && d.op_count == 1 && d.operands[0].type == ARM64_OP_IMM && profile.nonReturningCalls.contains(d.operands[0].imm))) continue;
		const bool branch = i.id == ARM64_INS_B || i.id == ARM64_INS_CBZ || i.id == ARM64_INS_CBNZ || i.id == ARM64_INS_TBZ || i.id == ARM64_INS_TBNZ;
		if (branch) {
			if (!d.op_count || d.operands[d.op_count-1].type != ARM64_OP_IMM) return InputsMask;
			append(d.operands[d.op_count-1].imm);
			if (i.id != ARM64_INS_B || (d.cc != ARM64_CC_INVALID && d.cc != ARM64_CC_AL)) append(i.address+4);
		} else if (i.id == ARM64_INS_BR) return InputsMask;
		else append(i.address+4);
		for (const auto next : successors[n]) predecessors[next].push_back(n);
	}
	std::deque<size_t> pending;
	std::vector<bool> queued(count, true);
	for (size_t n = count; n; --n) pending.push_back(n-1);
	while (!pending.empty()) {
		if (steps >= 2000000) return InputsMask;
		++steps;
		const auto n = pending.front(); pending.pop_front(); queued[n] = false;
		uint32_t outgoing = 0;
		for (const auto next : successors[n]) outgoing |= incoming[next];
		const auto value = uses[n] | (outgoing & ~definitions[n]);
		if (incoming[n] == value) continue;
		incoming[n] = value;
		for (const auto previous : predecessors[n]) if (!queued[previous]) { pending.push_back(previous); queued[previous] = true; }
	}
	return incoming[0];
}
}
RegisterContextResult AnalyzeRegisterContexts(const std::vector<Edge>& edges,
	const std::map<uint64_t, std::vector<uint8_t>>& bytes, Profile profile,
	const std::set<uint64_t>& externalEntries, const std::vector<EntryStackLoad>& entryLoads)
{
	RegisterContextResult result;
	if (profile.wordReturnRegister != ARM64_REG_X0) return result;
	struct Decoder { csh handle = 0; ~Decoder() { if (handle) cs_close(&handle); } } decoder;
	if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &decoder.handle) != CS_ERR_OK ||
		cs_option(decoder.handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) throw std::runtime_error("Cannot initialize register-context decoder");
	std::map<uint64_t, uint32_t> entryInputs;
	std::map<uint64_t, std::set<int64_t>> stackInputs, narrowStackInputs;
	for (const auto& load : entryLoads) {
		if (load.width == 8) stackInputs[load.payload].insert(load.entrySpOffset);
		if (load.width == 4) narrowStackInputs[load.payload].insert(load.entrySpOffset);
	}
	using StackBindings = std::vector<std::tuple<int64_t, std::string, uint64_t>>;
	using Registers = std::vector<std::pair<unsigned, uint32_t>>;
	using Key = std::tuple<uint64_t, StackBindings, Registers>;
	std::map<Key, std::vector<uint64_t>> groups;
	std::map<uint64_t, const Edge*> bySite;
	for (const auto& edge : edges) {
		bySite.emplace(edge.site, &edge);
		if (edge.kind != "call" || !edge.target || !bytes.contains(*edge.target) || edge.registerInputs.empty() || edge.stackInputs.size() > 32) continue;
		if (!entryInputs.contains(*edge.target)) entryInputs[*edge.target] = EntryInputs(decoder.handle, *edge.target, bytes.at(*edge.target), profile, result.bindingSteps);
		StackBindings stack; Registers registers;
		// Caller locals can share the recent-store window with arguments. Bind
		// only slots with an independently observed full-width callee load.
		for (const auto& input : edge.stackInputs)
			if (stackInputs[*edge.target].contains(input.spOffset) || (input.kind == "word" && narrowStackInputs[*edge.target].contains(input.spOffset)))
				stack.emplace_back(input.spOffset, input.kind, input.value);
		for (const auto& input : edge.registerInputs) if (input.reg < 15 && entryInputs.at(*edge.target) & (1U << input.reg)) registers.emplace_back(input.reg, input.classId);
		if (registers.empty()) continue;
		std::sort(stack.begin(), stack.end()); std::sort(registers.begin(), registers.end());
		Key key{*edge.target, std::move(stack), std::move(registers)};
		// Bound both retained groups and analysis work before publication.
		if (groups.size() < 4096 || groups.contains(key)) groups[std::move(key)].push_back(edge.site);
		else ++result.droppedCallers;
	}
	result.candidateGroups = groups.size();
	if (groups.empty()) return result;
	std::set<uint64_t> requested;
	std::set<uint64_t> dispatchEntries;
	for (const auto entry : profile.dispatchEntries) if (entry) dispatchEntries.insert(*entry);
	size_t remaining = 20000000;
	for (const auto& [key, callers] : groups) {
		if (!remaining) break;
		++result.attempted;
		const auto& [entry, stack, registers] = key;
		const auto& body = bytes.at(entry);
		cs_insn* raw = nullptr;
		const auto count = cs_disasm(decoder.handle, body.data(), body.size(), entry, 0, &raw);
		const std::shared_ptr<cs_insn> owner(raw, [count](cs_insn* p) { cs_free(p, count); });
		if (count * 4 != body.size()) continue;
		std::vector<StackInput> inputs;
		std::vector<RegisterInput> registerInputs;
		for (const auto& [offset, kind, value] : stack) inputs.push_back({offset, kind, value, {}});
		for (const auto& [reg, cid] : registers) registerInputs.push_back({reg, cid, {}});
		ReceiverAnalysisResult analysis;
		for (unsigned round = 0; round < 3 && remaining; ++round) {
			analysis = AnalyzeReceivers(raw, count, profile, externalEntries, &inputs, &remaining,
				nullptr, nullptr, false, false, false, &registerInputs);
			if (round == 2 || result.effectAttempts >= 128) break;
			std::set<uint64_t> targets;
			for (const auto& [site, resolution] : analysis.resolutions) targets.insert(resolution.snapshotTarget);
			for (size_t n = 0; n < count; ++n) {
				const auto& i = raw[n]; const auto& d = i.detail->arm64;
				if (i.id == ARM64_INS_BL && d.op_count == 1 && d.operands[0].type == ARM64_OP_IMM) targets.insert(d.operands[0].imm);
			}
			bool changed = false;
			for (const auto target : targets) {
				if (result.effectAttempts >= 128) break;
				if (profile.frameSafeCallees.contains(target) || profile.allocationReturns.contains(target) ||
					profile.framePreservingCalls.contains(target) || profile.nonReturningCalls.contains(target) || !requested.insert(target).second || target % 4) continue;
				auto container = bytes.upper_bound(target);
				if (container == bytes.begin()) continue;
				--container;
				const auto [parent, contents] = std::tie(container->first, container->second);
				if (target < parent || target-parent >= contents.size() || (target-parent)%4 || contents.size()-(target-parent) > 256 ||
					(target != parent && !dispatchEntries.contains(target))) continue;
				const std::vector<uint8_t> suffix(contents.begin()+(target-parent), contents.end());
				++result.effectAttempts;
				const auto effects = AnalyzeCallEffects({{target, suffix}}, profile);
				result.effectSteps += effects.steps;
				if (!effects.certificates.contains(target)) continue;
				auto certificate = effects.certificates.at(target);
				if (target != parent) certificate.insert(certificate.size()-1, ",\"containing_payload\":" + std::to_string(parent));
				result.effects.emplace(target, std::move(certificate));
				profile.frameSafeCallees.insert(target);
				if (effects.forwardedInputs.contains(target)) {
					profile.forwardedReturnInputs[target] = effects.forwardedInputs.at(target);
					result.forwardedInputs[target] = effects.forwardedInputs.at(target);
				}
				changed = true;
			}
			if (!changed) break;
		}
		if (analysis.certificate.empty()) continue;
		for (auto it = analysis.resolutions.begin(); it != analysis.resolutions.end();) {
			const auto old = bySite.find(it->first);
			if (old != bySite.end() && old->second->staticDispatch && old->second->staticDispatch->snapshotTarget == it->second.snapshotTarget) it = analysis.resolutions.erase(it);
			else ++it;
		}
		bool newStack = false;
		for (const auto& [site, values] : analysis.stackInputs) {
			const auto old = bySite.find(site);
			if (old == bySite.end()) continue;
			for (const auto& value : values)
				if (std::none_of(old->second->stackInputs.begin(), old->second->stackInputs.end(), [&](const auto& item) {
					return item.spOffset == value.spOffset && item.kind == value.kind && item.value == value.value;
				})) newStack = true;
		}
		const bool newReturn = analysis.normalReturnClass && !profile.provedReturnClasses.contains(entry);
		if (analysis.resolutions.empty() && analysis.forwardedReturns.empty() && !newReturn && !newStack) continue;
		result.contexts.push_back({entry, callers, std::move(inputs), std::move(registerInputs), std::move(analysis)});
	}
	result.steps = 20000000-remaining;
	return result;
}
}
