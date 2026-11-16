#include "FieldBranchUses.h"
#include "Arm64Decode.h"
#include "SnapshotCodeAnalysis.h"
#include "WordOrigins.h"
#include <algorithm>
#include <format>
#include <memory>
#include <ostream>
#include <stdexcept>

namespace SnapshotAnalysis
{
FieldBranchUsesResult DescribeFieldBranches(const Profile &profile,
                                            const JoinedReferencesResult &joined,
                                            const AsyncFieldsResult &fields,
                                            const std::map<uint64_t, std::vector<uint8_t>> &bytes,
                                            const std::set<uint64_t> &entries)
{
    FieldBranchUsesResult result;
    if (profile.heapBitsRegister != ARM64_REG_X28)
	return result;

    std::map<uint64_t, std::vector<size_t>> contexts;
    for (size_t i = 0; i < joined.contexts.size(); ++i)
    {
	const auto &context = joined.contexts[i];
	if (context.observations.empty())
	    continue;
	const auto layout = fields.layouts.find(context.classId);
	if (layout != fields.layouts.end() && layout->second.kind == "instance" &&
	    layout->second.slotBytes == 4)
	    contexts[context.payload].push_back(i);
    }
    if (contexts.empty())
	return result;

    struct Decoder
    {
	csh handle = 0;
	~Decoder()
	{
	    if (handle)
		cs_close(&handle);
	}
    } decoder;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &decoder.handle) != CS_ERR_OK ||
        cs_option(decoder.handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
	throw std::runtime_error("Cannot initialize field-branch decoder");

    for (const auto &[payload, indices] : contexts)
    {
	const auto &code = bytes.at(payload);
	const auto [raw, count] =
	    DecodeArm64Instructions(decoder.handle, code.data(), code.size(), payload);
	auto release = [count](cs_insn *p) { cs_free(p, count); };
	const std::unique_ptr<cs_insn, decltype(release)> owner(raw, release);
	if (!raw || count * 4 != code.size())
	    throw std::runtime_error("Cannot decode field-branch caller");
	result.bytes += code.size();
	const uint64_t end = payload + code.size();

	std::set<uint64_t> targets(entries.lower_bound(payload), entries.lower_bound(end));
	if (const auto body = profile.completionBodies.find(payload);
	    body != profile.completionBodies.end())
	    targets.insert(body->second.handlers.begin(), body->second.handlers.end());
	const auto external = targets;
	std::map<uint64_t, std::set<uint64_t>> incoming;
	for (size_t i = 0; i < count; ++i)
	{
	    const auto &detail = *raw[i].detail;
	    const auto &arm = detail.arm64;
	    if (arm.op_count && arm.operands[arm.op_count - 1].type == ARM64_OP_IMM &&
	        (std::count(detail.groups, detail.groups + detail.groups_count, CS_GRP_JUMP) ||
	         std::count(detail.groups, detail.groups + detail.groups_count, CS_GRP_CALL)))
	    {
		targets.insert(arm.operands[arm.op_count - 1].imm);
		incoming[arm.operands[arm.op_count - 1].imm].insert(raw[i].address);
	    }
	}

	for (size_t i : indices)
	{
	    const auto &context = joined.contexts[i];
	    const auto &layout = fields.layouts.at(context.classId);
	    for (size_t j = 0; j < context.observations.size(); ++j)
	    {
		++result.candidates;
		const auto &reference = context.observations[j];
		const auto field = reference.site + 4;
		if (field + 12 >= end || targets.contains(field) || targets.contains(field + 4) ||
		    targets.contains(field + 8))
		    continue;

		const auto *window = raw + (field - payload) / 4;
		const auto &branch = window[2];
		const bool nonzero = branch.id == ARM64_INS_TBNZ;
		if (!nonzero && branch.id != ARM64_INS_TBZ)
		    continue;
		const auto &arm = branch.detail->arm64;
		if (arm.op_count != 3 || arm.operands[0].type != ARM64_OP_REG ||
		    arm.operands[0].reg < ARM64_REG_W0 || arm.operands[0].reg > ARM64_REG_W30 ||
		    arm.operands[1].type != ARM64_OP_IMM || arm.operands[1].imm < 0 ||
		    arm.operands[1].imm >= 32 || arm.operands[2].type != ARM64_OP_IMM)
		    continue;
		const auto target = static_cast<uint64_t>(arm.operands[2].imm);
		if (target < payload || target >= end || target % 4)
		    continue;

		const auto reg = static_cast<uint16_t>(arm.operands[0].reg - ARM64_REG_W0);
		AsyncFieldContext slot{payload,       context.sourceAwait, field,
		                       reference.reg, context.classId,     "joined_reference"};
		size_t remaining = 1;
		AnalyzeFieldAccesses(window, 1, layout, {}, slot, remaining);
		if (slot.accesses.size() != 1 || slot.accesses.front().access != "read" ||
		    slot.accesses.front().reg != reg)
		    continue;

		// The shared tracer verifies the SDK's exact ADD and its load definition.
		// Adding a multiple of 2^32 preserves the bits selected by this W test.
		const auto origin = TraceWordInput(window, 3, 2, {reg, {}}, profile);
		if (origin.stop != "load_endpoint" || !origin.source ||
		    origin.source->kind != "load_compressed" || origin.source->site != field)
		    continue;
		const auto fallthrough = branch.address + 4;
		result.uses.push_back({i, j, branch.address, nonzero ? target : fallthrough,
		                       nonzero ? fallthrough : target, slot.accesses.front().offset,
		                       static_cast<unsigned>(arm.operands[1].imm)});
		if (auto decision = AnalyzeFieldDecision(raw, count, profile, reference, layout,
		                                         result.uses.size() - 1, result.uses.back(),
		                                         external, incoming))
		    result.decisions.push_back(*decision);
	    }
	}
    }
    return result;
}

std::string FieldBranchNote(const JoinedReferencesResult &joined, const FieldBranchUse &use)
{
    const auto &context = joined.contexts.at(use.context);
    const auto &reference = context.observations.at(use.reference);
    return std::format(
        "field bit test: bit {} of word loaded at {:#x} from class {:#x} instance slot "
        "{:#x}; set -> {:#x}, clear -> {:#x} [conditional on joined reload {:#x} "
        "from await {:#x}]",
        use.bit, reference.site + 4, context.classId, use.offset, use.setTarget, use.clearTarget,
        reference.site, context.sourceAwait);
}

void WriteFieldBranches(std::ostream &out, const FieldBranchUsesResult &result)
{
    out << ",\"field_branch_uses\":[";
    bool comma = false;
    for (const auto &use : result.uses)
    {
	if (comma)
	    out << ',';
	comma = true;
	out << "{\"context\":" << use.context << ",\"reference\":" << use.reference
	    << ",\"site\":" << use.site << ",\"offset\":" << use.offset << ",\"bit\":" << use.bit
	    << ",\"set_target\":" << use.setTarget << ",\"clear_target\":" << use.clearTarget
	    << '}';
    }
    out << "],\"field_branch_work\":{\"candidates\":" << result.candidates
        << ",\"bytes\":" << result.bytes << '}';
}
} // namespace SnapshotAnalysis
