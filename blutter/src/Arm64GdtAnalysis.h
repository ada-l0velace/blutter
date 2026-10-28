#pragma once
#include "il.h"
#include <memory>
#include <vector>

class DartApp;

namespace arm64_analysis {

std::unique_ptr<GdtCallInstr> TryGdtCall(AsmIterator& insn, AsmInstructions& instructions,
	std::vector<std::unique_ptr<ILInstr>>& il, const DartApp* app = nullptr);

}
