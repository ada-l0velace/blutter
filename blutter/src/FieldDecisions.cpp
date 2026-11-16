#include "FieldBranchUses.h"
#include "SnapshotCodeAnalysis.h"
#include "WordOrigins.h"
#include <format>
#include <ostream>

namespace SnapshotAnalysis
{
namespace
{
int Wide(arm64_reg reg)
{
    return reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28 ? reg - ARM64_REG_X0 : -1;
}

std::optional<bool> Constant(const cs_insn &i, const Profile &p)
{
    const auto &a = i.detail->arm64;
    if (i.id != ARM64_INS_ADD || a.op_count != 3 || a.update_flags || a.writeback ||
        a.operands[0].type != ARM64_OP_REG || Wide(a.operands[0].reg) < 0 ||
        a.operands[0].reg == p.nullRegister || a.operands[1].type != ARM64_OP_REG ||
        a.operands[1].reg != p.nullRegister || a.operands[2].type != ARM64_OP_IMM ||
        a.operands[2].shift.value)
	return {};
    const auto value = a.operands[2].imm;
    if (value == p.fieldDecisionAbi.trueOffset)
	return true;
    if (value == p.fieldDecisionAbi.falseOffset)
	return false;
    return {};
}
} // namespace

std::optional<FieldDecision>
AnalyzeFieldDecision(const cs_insn *raw, size_t count, const Profile &p,
                     const JoinedReference &reference, const InstanceLayout &layout,
                     size_t branchUse, const FieldBranchUse &use,
                     const std::set<uint64_t> &externalEntries,
                     const std::map<uint64_t, std::set<uint64_t>> &incoming)
{
    if (!p.fieldDecisionAbi.supported || p.nullRegister != ARM64_REG_X22 ||
        p.fieldDecisionAbi.trueOffset <= 0 || p.fieldDecisionAbi.falseOffset <= 0 ||
        p.fieldDecisionAbi.trueOffset == p.fieldDecisionAbi.falseOffset || !raw || !count ||
        use.site < raw[0].address || use.site % 4)
	return {};
    const size_t at = (use.site - raw[0].address) / 4;
    if (at >= count || count - at < 11)
	return {};
    const auto *i = raw + at;
    const bool onSet = use.setTarget == i[9].address && use.clearTarget == i[1].address;
    const bool onClear = use.clearTarget == i[9].address && use.setTarget == i[1].address;
    if (!onSet && !onClear)
	return {};

    // All paths into this small diamond must pass the already checked reload.
    // Only its own short-circuit edge and join edge may enter the tail.
    for (size_t n = 1; n <= 10; ++n)
    {
	if (externalEntries.contains(i[n].address))
	    return {};
	if (const auto entry = incoming.find(i[n].address); entry != incoming.end())
	{
	    const std::set<uint64_t> allowed = n == 9    ? std::set<uint64_t>{i[0].address}
	                                       : n == 10 ? std::set<uint64_t>{i[8].address}
	                                                 : std::set<uint64_t>{};
	    if (entry->second != allowed)
		return {};
	}
    }
    const auto &test = i[0].detail->arm64;
    if (test.operands[0].reg == ARM64_REG_W22 ||
        test.operands[0].reg == ARM64_REG_W0 + reference.reg)
	return {};

    AsyncFieldContext field{raw[0].address,    0, i[1].address, reference.reg, layout.classId,
                            "joined_reference"};
    size_t remaining = 1;
    AnalyzeFieldAccesses(i + 1, 1, layout, {}, field, remaining);
    if (field.accesses.size() != 1 || field.accesses[0].access != "read" ||
        field.accesses[0].reg == 22)
	return {};
    const auto reg = field.accesses[0].reg;
    const auto origin = TraceWordInput(i + 1, 3, 2, {static_cast<uint16_t>(reg), {}}, p);
    if (origin.stop != "load_endpoint" || !origin.source ||
        origin.source->kind != "load_compressed" || origin.source->site != i[1].address)
	return {};
    const auto &cmp = i[3].detail->arm64;
    if (i[3].id != ARM64_INS_CMP || cmp.op_count != 2 || cmp.operands[0].type != ARM64_OP_REG ||
        cmp.operands[0].reg != ARM64_REG_W0 + reg || cmp.operands[1].type != ARM64_OP_REG ||
        cmp.operands[1].reg != ARM64_REG_W22 || cmp.operands[1].shift.value ||
        cmp.operands[1].ext != ARM64_EXT_INVALID)
	return {};

    const auto first = Constant(i[4], p), second = Constant(i[5], p), fallback = Constant(i[9], p);
    if (!first || !second || !fallback || *first == *second || *fallback)
	return {};
    const auto &a = i[4].detail->arm64, &b = i[5].detail->arm64;
    const auto &select = i[6].detail->arm64;
    if (a.operands[0].reg == b.operands[0].reg || i[6].id != ARM64_INS_CSEL ||
        select.op_count != 3 || select.operands[0].type != ARM64_OP_REG ||
        Wide(select.operands[0].reg) < 0 || select.operands[1].type != ARM64_OP_REG ||
        select.operands[1].reg != a.operands[0].reg || select.operands[2].type != ARM64_OP_REG ||
        select.operands[2].reg != b.operands[0].reg ||
        (select.cc != ARM64_CC_NE && select.cc != ARM64_CC_EQ))
	return {};
    const auto &move = i[7].detail->arm64;
    if (i[7].id != ARM64_INS_MOV || move.op_count != 2 || move.operands[0].type != ARM64_OP_REG ||
        Wide(move.operands[0].reg) < 0 || move.operands[1].type != ARM64_OP_REG ||
        move.operands[1].reg != select.operands[0].reg ||
        move.operands[0].reg != i[9].detail->arm64.operands[0].reg)
	return {};
    const auto &jump = i[8].detail->arm64;
    if (i[8].id != ARM64_INS_B || jump.cc != ARM64_CC_INVALID || jump.op_count != 1 ||
        jump.operands[0].type != ARM64_OP_IMM ||
        static_cast<uint64_t>(jump.operands[0].imm) != i[10].address)
	return {};
    const auto &store = i[10].detail->arm64;
    if (i[10].id != ARM64_INS_STUR || store.op_count != 2 || store.writeback ||
        store.operands[0].type != ARM64_OP_REG || store.operands[0].reg != move.operands[0].reg ||
        store.operands[1].type != ARM64_OP_MEM || store.operands[1].mem.base != ARM64_REG_X29 ||
        store.operands[1].mem.index != ARM64_REG_INVALID || store.operands[1].mem.disp >= 0 ||
        store.operands[1].mem.disp < -4096 || store.operands[1].mem.disp % 8)
	return {};
    return FieldDecision{branchUse,
                         i[1].address,
                         i[10].address,
                         field.accesses[0].offset,
                         store.operands[1].mem.disp,
                         static_cast<unsigned>(Wide(move.operands[0].reg)),
                         onSet,
                         select.cc == ARM64_CC_NE ? *first : *second};
}

std::string FieldDecisionNote(const JoinedReferencesResult &joined,
                              const FieldBranchUsesResult &result, const FieldDecision &decision)
{
    const auto &use = result.uses.at(decision.branchUse);
    const auto &context = joined.contexts.at(use.context);
    const auto &reference = context.observations.at(use.reference);
    return std::format("field decision: (bit {} of read {:#x} {}) && (read {:#x} {} null); "
                       "Boolean X{} saved to FP{:+} [conditional on joined reload {:#x}]",
                       use.bit, reference.site + 4, decision.onSet ? "clear" : "set", decision.load,
                       decision.nonNullTrue ? "!=" : "==", decision.reg, decision.fpOffset,
                       reference.site);
}

void WriteFieldDecisions(std::ostream &out, const Profile &p, const FieldBranchUsesResult &result)
{
    const auto &abi = p.fieldDecisionAbi;
    out << R"(,"field_decision_abi":{"supported":)" << (abi.supported ? "true" : "false")
        << R"(,"true_offset":)" << abi.trueOffset << R"(,"false_offset":)" << abi.falseOffset
        << R"(},"field_decisions":[)";
    bool comma = false;
    for (const auto &d : result.decisions)
    {
	if (comma)
	    out << ',';
	comma = true;
	out << "{\"branch_use\":" << d.branchUse << ",\"load\":" << d.load << ",\"site\":" << d.site
	    << ",\"offset\":" << d.offset << ",\"fp_offset\":" << d.fpOffset
	    << ",\"register\":" << d.reg << ",\"on_set\":" << (d.onSet ? "true" : "false")
	    << ",\"non_null_true\":" << (d.nonNullTrue ? "true" : "false") << '}';
    }
    out << ']';
}
} // namespace SnapshotAnalysis
