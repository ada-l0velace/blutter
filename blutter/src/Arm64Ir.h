#pragma once
#include "NativeIr.h"
#include <capstone.h>

namespace SnapshotAnalysis {
// Missing detail, non-word sizes and oversized lists have no IR. Unmodeled
// operand shapes retain the original word/address with unknown effects.
std::optional<NativeIr::Instruction> LowerArm64(const cs_insn& instruction);
}
