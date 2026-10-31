#pragma once
#include "NativeIr.h"
#include <capstone.h>

namespace SnapshotAnalysis {
// Missing detail, non-word sizes and oversized lists have no IR. Unmodeled
// operand shapes retain the original word/address with unknown effects.
std::optional<NativeIr::Instruction> LowerArm64(const cs_insn& instruction);
// Only an immediately preceding plain CMP and concrete word operands qualify.
std::optional<bool> EvaluateArm64Condition(const cs_insn& branch, const cs_insn& compare,
	const NativeIr::ReadRegister& read);
}
