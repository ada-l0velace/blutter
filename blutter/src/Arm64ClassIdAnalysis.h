#pragma once
#include "il.h"
#include <memory>
#include <vector>

namespace arm64_analysis {
std::unique_ptr<LoadTaggedClassIdMayBeSmiInstr> TryTaggedClassId(AsmIterator& insn,
	std::vector<std::unique_ptr<ILInstr>>& il);
}
