#include "pch.h"
#include "Disassembler.h"
#include "Arm64Decode.h"

AsmInstructions Disassembler::Disasm(const uint8_t* code, size_t code_size, uint64_t address, size_t max_count)
{
    const auto [instructions, count] = SnapshotAnalysis::DecodeArm64Instructions(cshandle, code, code_size, address, max_count);
    return AsmInstructions(instructions, count);
}
