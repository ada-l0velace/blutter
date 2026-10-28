#pragma once
#include "CodeAnalyzer.h"
#include <cstdio>
#include <limits>
#include <span>

// Display every original word when semantic analysis of a function is unsafe.
// Decodable words remain instructions; undecodable words are explicit data, never guessed IL.
inline AsmTexts DisassembleRawWords(std::span<const uint8_t> bytes, uint64_t address)
{
	if (bytes.empty() || bytes.size() % 4 || address % 4 ||
		bytes.size() > std::numeric_limits<uint64_t>::max() - address)
		throw std::invalid_argument("Invalid raw ARM64 instruction span");
	Disassembler decoder;
	std::vector<AsmText> texts;
	for (size_t offset = 0; offset < bytes.size(); offset += 4) {
		AsmText text{};
		text.addr = address + offset;
		auto decoded = decoder.Disasm(bytes.data() + offset, 4, text.addr);
		if (decoded.Count() == 1) {
			auto* instruction = decoded.FirstPtr();
			std::snprintf(text.text, sizeof(text.text), "%-16s%s", instruction->mnemonic, instruction->op_str);
		}
		else {
			const uint32_t word = static_cast<uint32_t>(bytes[offset]) |
				(static_cast<uint32_t>(bytes[offset + 1]) << 8) |
				(static_cast<uint32_t>(bytes[offset + 2]) << 16) |
				(static_cast<uint32_t>(bytes[offset + 3]) << 24);
			std::snprintf(text.text, sizeof(text.text), "%-16s0x%08x", ".word", word);
		}
		texts.push_back(text);
	}
	return AsmTexts(std::move(texts), 0, 0);
}
