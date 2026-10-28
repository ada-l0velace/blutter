#include "pch.h"
#include "Disassembler.h"
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <vector>

namespace {

struct UnprivilegedLoad {
	unsigned unscaledId;
	unsigned id;
	const char* mnemonic;
};

uint32_t ReadWord(const uint8_t* code)
{
	return uint32_t{code[0]} | (uint32_t{code[1]} << 8) |
		(uint32_t{code[2]} << 16) | (uint32_t{code[3]} << 24);
}

std::optional<UnprivilegedLoad> RejectedUnprivilegedLoad(uint32_t word)
{
	const auto rt = word & 31;
	const auto rn = (word >> 5) & 31;
	if (rt != rn || rn == 31)
		return std::nullopt;
	// Capstone 5 treats mode 10 (unprivileged, no writeback) as indexed writeback.
	// Restrict recovery to allocated integer loads; never accept pre/post-index overlap.
	switch (word & 0xffe00c00) {
	case 0xb8400800: case 0xf8400800: return UnprivilegedLoad{ARM64_INS_LDUR, ARM64_INS_LDTR, "ldtr"};
	case 0x38400800: return UnprivilegedLoad{ARM64_INS_LDURB, ARM64_INS_LDTRB, "ldtrb"};
	case 0x78400800: return UnprivilegedLoad{ARM64_INS_LDURH, ARM64_INS_LDTRH, "ldtrh"};
	case 0x38800800: case 0x38c00800: return UnprivilegedLoad{ARM64_INS_LDURSB, ARM64_INS_LDTRSB, "ldtrsb"};
	case 0x78800800: case 0x78c00800: return UnprivilegedLoad{ARM64_INS_LDURSH, ARM64_INS_LDTRSH, "ldtrsh"};
	case 0xb8800800: return UnprivilegedLoad{ARM64_INS_LDURSW, ARM64_INS_LDTRSW, "ldtrsw"};
	default: return std::nullopt;
	}
}

}

AsmInstructions Disassembler::Disasm(const uint8_t* code, size_t code_size, uint64_t address, size_t max_count)
{
	cs_insn* insns = nullptr;
	const auto count = cs_disasm(cshandle, code, code_size, address, max_count, &insns);
	auto freeOriginal = [count](cs_insn* data) { if (data) cs_free(data, count); };
	std::unique_ptr<cs_insn, decltype(freeOriginal)> original(insns, freeOriginal);
	if (count >= code_size / 4 || (max_count && count >= max_count) ||
		!RejectedUnprivilegedLoad(ReadWord(code + count * 4)))
		return AsmInstructions(original.release(), count);

	// Decode an operand-equivalent unscaled form in a private copy, then restore the
	// original opcode, mnemonic and bytes. Target memory is never changed and LDTR
	// remains LDTR in the analyzer; its privilege semantics are not replaced by LDUR.
	std::vector<uint8_t> proxy(code, code + code_size);
	for (size_t offset = count * 4; offset + 4 <= code_size; offset += 4) {
		if (RejectedUnprivilegedLoad(ReadWord(code + offset)))
			proxy[offset + 1] &= ~uint8_t{0x0c};
	}
	cs_insn* decoded = nullptr;
	const auto recoveredCount = cs_disasm(cshandle, proxy.data(), proxy.size(), address, max_count, &decoded);
	auto freeRecovered = [recoveredCount](cs_insn* data) { if (data) cs_free(data, recoveredCount); };
	std::unique_ptr<cs_insn, decltype(freeRecovered)> recovered(decoded, freeRecovered);
	if (recoveredCount <= count)
		return AsmInstructions(original.release(), count);
	for (size_t i = count; i < recoveredCount; ++i) {
		const auto load = RejectedUnprivilegedLoad(ReadWord(code + i * 4));
		if (!load)
			continue;
		if (decoded[i].size != 4 || decoded[i].id != load->unscaledId)
			return AsmInstructions(original.release(), count);
		decoded[i].id = load->id;
		std::snprintf(decoded[i].mnemonic, sizeof(decoded[i].mnemonic), "%s", load->mnemonic);
		std::memcpy(decoded[i].bytes, code + i * 4, 4);
	}
	return AsmInstructions(recovered.release(), recoveredCount);
}
