#include "pch.h"
#include "Arm64GdtAnalysis.h"
#include "Arm64Patterns.h"
#include "AnalysisDiagnostics.h"
#include "Arm64Constants.h"
#include "DartApp.h"
#include <bit>

#ifndef NO_CODE_ANALYSIS

namespace arm64_analysis {

std::unique_ptr<GdtCallInstr> TryGdtCall(AsmIterator& insn, AsmInstructions& instructions,
	std::vector<std::unique_ptr<ILInstr>>& il, const DartApp* app)
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
	std::optional<size_t> constantStart;
	size_t firstConstantIL = il.size();
	if (!match) {
		const auto function = std::span<const cs_insn>(instructions.FirstPtr(), instructions.Count());
		const auto index = static_cast<size_t>(current - instructions.FirstPtr());
		if (auto constant = arm64_patterns::IntegerConstantSuffix(function, index, CSREG_DART_TMP2);
			constant && index - constant->startIndex > 1) {
			auto candidate = arm64_patterns::GdtCall(function.subspan(index),
				ToCapstoneReg(dart::DispatchTableNullErrorABI::kClassIdReg), CSREG_DART_DISPATCH_TABLE,
				CSREG_DART_TMP2, std::bit_cast<int64_t>(constant->value));
			if (candidate && candidate->usesTemporary) {
				const auto begin = function[constant->startIndex].address;
				uint64_t boundary = current->address;
				while (firstConstantIL > 0 && il[firstConstantIL - 1]->End() == boundary && boundary > begin) {
					boundary = il[--firstConstantIL]->Start();
				}
				const auto targets = arm64_patterns::DirectBranchTargets(function);
				bool entered = false;
				for (size_t i = constant->startIndex + 1; i <= index + candidate->callIndex; ++i)
					entered |= std::binary_search(targets.begin(), targets.end(), function[i].address) ||
						(app && app->HasFunctionAt(function[i].address));
				if (boundary == begin && !entered) { match = candidate; constantStart = constant->startIndex; }
			}
		}
	}
	if (!match) {
		if (arm64_patterns::IsDispatchCall(
			std::span<const cs_insn>(current, instructions.LastPtr() - current + 1), CSREG_DART_DISPATCH_TABLE))
			throw AnalysisIssue("unsupported-gdt-index", insn.address(),
				"Dispatch-table call identified, but its index construction is not recognized.");
		return nullptr;
	}
	const auto start = constantStart ? instructions.Ptr(*constantStart)->address :
		match->usesTemporary ? previousLoad->Start() : insn.address();
	if (constantStart)
		il.erase(il.begin() + firstConstantIL, il.end());
	else if (match->usesTemporary)
		il.pop_back();
	insn.SetCurrent(current + match->callIndex);
	++insn;
	return std::make_unique<GdtCallInstr>(insn.Wrap(start), match->offset);
}

}

#endif
