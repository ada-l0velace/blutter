#pragma once
#include "CodeAnalyzer.h"
#include <cstdio>
#include <limits>
#include <span>
#include <format>
#include <ostream>
#include <string_view>
#include <stdexcept>

// Render original instructions and addressed observations without inventing IL.
// Decode a complete suffix at a time; fall back by one word only on a real gap.
template <typename Annotation, typename Undecoded>
void WriteRawAssembly(std::ostream& output, Disassembler& decoder,
	std::span<const uint8_t> bytes, uint64_t address, Annotation&& annotation, Undecoded&& undecoded)
{
	if (bytes.empty() || bytes.size() % 4 || address % 4 ||
		bytes.size() > std::numeric_limits<uint64_t>::max() - address)
		throw std::invalid_argument("Invalid raw ARM64 instruction span");
	size_t offset = 0;
	while (offset < bytes.size()) {
		auto instructions = decoder.Disasm(bytes.data() + offset, bytes.size() - offset, address + offset);
		if (instructions.Count() == 0) {
			undecoded(address + offset);
			const uint32_t word = static_cast<uint32_t>(bytes[offset]) |
				(static_cast<uint32_t>(bytes[offset + 1]) << 8) |
				(static_cast<uint32_t>(bytes[offset + 2]) << 16) |
				(static_cast<uint32_t>(bytes[offset + 3]) << 24);
			const std::string_view note = annotation(address + offset);
			output << std::format("    // {:#x}: .word {:#010x} ; undecoded word", address + offset, word);
			if (!note.empty()) output << " | " << note;
			output << '\n';
			offset += 4;
			continue;
		}
		for (size_t index = 0; index < instructions.Count(); ++index) {
			const auto* instruction = instructions.Ptr(index);
			if (instruction->size != 4 || instruction->address != address + offset)
				throw std::runtime_error("Invalid raw ARM64 decoder range");
			const std::string_view note = annotation(instruction->address);
			output << std::format("    // {:#x}: {} {}", instruction->address,
				instruction->mnemonic, instruction->op_str);
			if (!note.empty()) output << " ; " << note;
			output << '\n';
			offset += 4;
		}
	}
}

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
