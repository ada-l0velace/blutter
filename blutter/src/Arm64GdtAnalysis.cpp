#include "pch.h"
#include "Arm64GdtAnalysis.h"
#include "Arm64Patterns.h"
#include "AnalysisDiagnostics.h"

#ifndef NO_CODE_ANALYSIS

namespace arm64_analysis {

std::unique_ptr<GdtCallInstr> TryGdtCall(AsmIterator& insn, AsmInstructions& instructions,
	std::vector<std::unique_ptr<ILInstr>>& il)
{
	// Fold only proven index arithmetic and commit iterator/IL changes after the full call matches.
	auto* current = insn.Current();
	std::optional<int64_t> tmpValue;
	LoadValueInstr* previousLoad = nullptr;
	if (!il.empty() && current > instructions.FirstPtr()) {
		auto* previousAsm = current - 1;
		if (previousAsm->id == ARM64_INS_NOP && previousAsm > instructions.FirstPtr())
			--previousAsm;
		auto* previous = il.back().get();
		// A store currently shares the LoadValue kind; require a constant-producing opcode before casting.
		const bool constantWriter = previousAsm->id == ARM64_INS_MOV || previousAsm->id == ARM64_INS_MOVZ ||
			previousAsm->id == ARM64_INS_MOVK || previousAsm->id == ARM64_INS_MOVN ||
			previousAsm->id == ARM64_INS_ORR || previousAsm->id == ARM64_INS_EOR;
		if (constantWriter && previous->Kind() == ILInstr::LoadValue && previous->End() == insn.address()) {
			auto* load = static_cast<LoadValueInstr*>(previous);
			if (load->dstReg == A64::TMP2_REG && load->val.Storage().IsImmediate() && load->val.Value() &&
				load->val.Value()->RawTypeId() == dart::kIntegerCid && load->val.Value()->HasValue()) {
				tmpValue = load->val.Get<VarInteger>()->Value();
				previousLoad = load;
			}
		}
	}
	auto match = arm64_patterns::GdtCall(
		std::span<const cs_insn>(current, instructions.LastPtr() - current + 1),
		ToCapstoneReg(dart::DispatchTableNullErrorABI::kClassIdReg), CSREG_DART_DISPATCH_TABLE,
		CSREG_DART_TMP2, tmpValue);
	if (!match) {
		if (arm64_patterns::IsDispatchCall(
			std::span<const cs_insn>(current, instructions.LastPtr() - current + 1), CSREG_DART_DISPATCH_TABLE))
			throw AnalysisIssue("unsupported-gdt-index", insn.address(),
				"Dispatch-table call identified, but its index construction is not recognized.");
		return nullptr;
	}
	const auto start = match->usesTemporary ? previousLoad->Start() : insn.address();
	if (match->usesTemporary)
		il.pop_back();
	insn.SetCurrent(current + match->callIndex);
	++insn;
	return std::make_unique<GdtCallInstr>(insn.Wrap(start), match->offset);
}

}

#endif
