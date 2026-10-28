#include "pch.h"
#include "Arm64ClassIdAnalysis.h"
#include "AnalysisDiagnostics.h"
#include <limits>

#ifndef NO_CODE_ANALYSIS
namespace arm64_analysis {

std::unique_ptr<LoadTaggedClassIdMayBeSmiInstr> TryTaggedClassId(AsmIterator& insn,
	std::vector<std::unique_ptr<ILInstr>>& il)
{
	// An empty/short history is ordinary at function entry. Inspect it only after
	// proving that the complete three-node combination can exist.
	if (il.size() < 3 || insn.id() != ARM64_INS_LSL || insn.op_count() != 3 ||
		insn.ops(0).type != ARM64_OP_REG || insn.ops(1).type != ARM64_OP_REG ||
		insn.ops(2).type != ARM64_OP_IMM || insn.ops(0).reg != insn.ops(1).reg ||
		insn.ops(2).imm != dart::kSmiTagSize || il.back()->Kind() != ILInstr::LoadClassId)
		return nullptr;
	auto* load = static_cast<LoadClassIdInstr*>(il.back().get());
	if (load->cidReg != A64::Register{insn.ops(0).reg} || il[il.size() - 2]->Kind() != ILInstr::BranchIfSmi)
		return nullptr;
	auto* branch = static_cast<BranchIfSmiInstr*>(il[il.size() - 2].get());
	auto* initial = il[il.size() - 3].get();
	if (insn.address() > std::numeric_limits<uint64_t>::max() - 4 ||
		static_cast<uint64_t>(branch->branchAddr) != insn.address() + 4 ||
		initial->End() != branch->Start() || branch->End() != load->Start() || load->End() != insn.address())
		return nullptr;
	if (branch->objReg != load->objReg || initial->Kind() != ILInstr::LoadValue)
		throw AnalysisIssue("instruction-mismatch", insn.address(),
			"Tagged class-ID combination has inconsistent object or constant-producing IL.");
	auto* constant = static_cast<LoadValueInstr*>(initial);
	if (constant->dstReg != load->cidReg || !constant->val.Storage().IsImmediate() ||
		!constant->val.Value() || constant->val.Value()->RawTypeId() != dart::kIntegerCid ||
		!constant->val.Value()->HasValue() || constant->val.Get<VarInteger>()->Value() != dart::Smi::RawValue(dart::kSmiCid))
		throw AnalysisIssue("instruction-mismatch", insn.address(),
			"Tagged class-ID combination requires a known Smi class-ID constant.");
	const auto start = constant->Start();
	// The new-expression allocates before transferring the three owned nodes.
	std::unique_ptr<LoadTaggedClassIdMayBeSmiInstr> result(new LoadTaggedClassIdMayBeSmiInstr(
		AddrRange{start, insn.address() + 4},
		std::unique_ptr<LoadValueInstr>(static_cast<LoadValueInstr*>(il[il.size() - 3].release())),
		std::unique_ptr<BranchIfSmiInstr>(static_cast<BranchIfSmiInstr*>(il[il.size() - 2].release())),
		std::unique_ptr<LoadClassIdInstr>(static_cast<LoadClassIdInstr*>(il.back().release()))));
	il.resize(il.size() - 3);
	++insn;
	return result;
}

}
#endif
