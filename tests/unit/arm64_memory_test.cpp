#include "Arm64Memory.h"
#include <array>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
size_t checks = 0;
void Check(bool ok, const char* reason) {
	++checks;
	if (!ok) throw std::runtime_error(reason);
}
constexpr uint64_t Address = 0x1000;
constexpr int64_t TableOffset = 0x188; // Authored layout, independent of any runtime.
constexpr std::array Bases{ARM64_REG_X29, ARM64_REG_X15, ARM64_REG_X26, ARM64_REG_X27, ARM64_REG_X21, ARM64_REG_SP};
uint32_t Add(unsigned dst, unsigned src, unsigned value, bool sub = false, bool shifted = false) {
	return (sub ? 0xd1000000u : 0x91000000u) | (shifted ? 1u << 22 : 0) | (value << 10) | (src << 5) | dst;
}
uint32_t Move(unsigned dst, unsigned src) { return 0xaa0003e0u | (src << 16) | dst; }
uint32_t Memory(unsigned reg, unsigned base, int offset, bool load = true, bool wide = true, bool scaled = false) {
	const auto op = scaled ? (load ? 0xf9400000u : 0xf9000000u) : (load ? 0xf8400000u : 0xf8000000u);
	return (wide ? op : op & ~(1u << 30)) | (scaled ? (offset / (wide ? 8 : 4)) << 10 :
		(static_cast<uint32_t>(offset) & 0x1ff) << 12) | (base << 5) | reg;
}
uint32_t IndexedAdd(unsigned dst, unsigned index, bool signedIndex) {
	return 0x8b200000u | (index << 16) | ((signedIndex ? 6u : 2u) << 13) | (2u << 10) | (dst << 5) | dst;
}
struct Decoder {
	csh handle = 0;
	Decoder() {
		Check(cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) == CS_ERR_OK, "open decoder");
		Check(cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK, "enable details");
	}
	~Decoder() { cs_close(&handle); }
};
struct Decoded {
	cs_insn* instructions = nullptr;
	size_t count;
	Decoded(Decoder& decoder, const std::vector<uint32_t>& words) {
		std::vector<uint8_t> bytes;
		for (auto word : words) for (unsigned bit = 0; bit < 32; bit += 8) bytes.push_back(static_cast<uint8_t>(word >> bit));
		count = cs_disasm(decoder.handle, bytes.data(), bytes.size(), Address, 0, &instructions);
		Check(count == words.size(), "authored sequence decodes completely");
	}
	~Decoded() { cs_free(instructions, count); }
	std::span<const cs_insn> Span() const { return {instructions, count}; }
};

void ScalarAndOrigins(Decoder& decoder) {
	for (unsigned base : {15u, 21u, 26u, 27u, 29u, 31u})
		for (bool load : {false, true}) for (bool wide : {false, true}) for (bool scaled : {false, true}) {
			const int offset = scaled ? 0x48 : -0x20;
			Decoded d(decoder, {Memory(5, base, offset, load, wide, scaled)});
			const auto match = arm64_patterns::BasedMemoryAccess(d.Span(), Bases);
			Check(match && match->lastIndex == 0 && match->offset == offset && match->isLoad == load &&
				match->bytes == (wide ? 8u : 4u), "direct native base, width and signed byte offset");
		}
	for (unsigned base : {0u, 1u, 12u}) {
		Decoded d(decoder, {Memory(5, base, 7)});
		Check(!arm64_patterns::BasedMemoryAccess(d.Span(), Bases), "unknown/heap base keeps its existing recognizer");
	}
	for (bool load : {false, true}) for (bool wide : {false, true}) for (unsigned temporary : {6u, 9u, 17u}) {
		Decoded d(decoder, {Add(temporary, 29, 0x50), Add(temporary, temporary, 0x70),
			Add(temporary, temporary, 0xe0, true), Memory(3, temporary, -0x10, load, wide)});
		const auto match = arm64_patterns::BasedMemoryAccess(d.Span(), Bases);
		Check(match && match->base == ARM64_REG_X29 && match->offset == -0x30 && match->lastIndex == 3 &&
			match->isLoad == load && match->bytes == (wide ? 8u : 4u), "computed frame access survives equivalent arithmetic/register allocation");
	}
	Decoded copy(decoder, {Move(8, 26), Memory(4, 8, 0)});
	const auto copied = arm64_patterns::BasedMemoryAccess(copy.Span(), Bases);
	Check(copied && copied->base == ARM64_REG_X26 && copied->offset == 0, "full-width copied thread base");
	Decoded shifted(decoder, {Add(8, 27, 3, false, true), Add(8, 8, 0x48, true), Memory(8, 8, 0x18)});
	const auto large = arm64_patterns::BasedMemoryAccess(shifted.Span(), Bases);
	Check(large && large->offset == 0x2fd0 && large->base == ARM64_REG_X27, "shifted pool byte offset");
	for (bool signedIndex : {false, true}) {
		Decoded d(decoder, {Add(8, 29, 0x40), IndexedAdd(8, 2, signedIndex), Memory(5, 8, -0x20)});
		const auto match = arm64_patterns::BasedMemoryAccess(d.Span(), Bases);
		Check(match && match->offset == 0x20 && match->index == ARM64_REG_W2 && match->shift == 2 &&
			match->extension == (signedIndex ? ARM64_EXT_SXTW : ARM64_EXT_UXTW), "index extension and scale stay explicit");
	}
}

void Refusals(Decoder& decoder) {
	const std::vector<uint32_t> valid{Add(8, 29, 0x40), Add(8, 8, 0x20, true), Memory(3, 8, -0x10, false)};
	Decoded original(decoder, valid);
	for (size_t length = 0; length < valid.size(); ++length)
		Check(!arm64_patterns::BasedMemoryAccess(original.Span().first(length), Bases), "incomplete sequence has no proof");
	for (size_t i = 1; i < valid.size(); ++i) {
		const std::array entries{Address + i * 4};
		Check(!arm64_patterns::BasedMemoryAccess(original.Span(), Bases, entries), "interior entry blocks folding");
	}
	const std::array firstEntry{Address};
	Check(arm64_patterns::BasedMemoryAccess(original.Span(), Bases, firstEntry).has_value(), "entry at first instruction is allowed");
	for (auto operation : {0x14000001u, 0x94000001u, 0xd63f0120u, 0xd65f03c0u, 0xd503201fu,
		Move(8, 0), Add(8, 8, 1) & ~(1u << 31), Add(8, 8, 1) | (1u << 29),
		Memory(8, 15, 0), Add(9, 8, 1), IndexedAdd(8, 8, true)}) {
		Decoded d(decoder, {valid[0], operation, valid[1], valid[2]});
		Check(!arm64_patterns::BasedMemoryAccess(d.Span(), Bases), "unmodeled instruction or changed address invalidates proof");
	}
	for (uint32_t word : {Memory(3, 8, -0x10, false) | 0x400u, // post-index store
		Memory(3, 8, -0x10, false) | 0xc00u, // pre-index store
		0xfd400103u, // floating-point load
		0x39400103u, // byte load
		0xf8626903u}) { // register-indexed load
		Decoded d(decoder, {valid[0], word});
		Check(!arm64_patterns::BasedMemoryAccess(d.Span(), Bases), "unmodeled memory form has no scalar proof");
	}
	for (auto words : {std::vector{Add(29, 29, 0x40), Memory(3, 29, 0)},
		std::vector{Move(8, 29) & ~(1u << 31), Memory(3, 8, 0)},
		std::vector{Add(8, 0, 0x40), Memory(3, 8, 0)}}) {
		Decoded d(decoder, words);
		Check(!arm64_patterns::BasedMemoryAccess(d.Span(), Bases), "invalid initial address origin");
	}
	std::vector<uint32_t> limit(8, Add(8, 8, 0xfff, false, true));
	limit[0] = Add(8, 29, 0xfff, false, true); limit.push_back(Memory(4, 8, 0xff));
	Decoded bounded(decoder, limit);
	const auto folded = arm64_patterns::BasedMemoryAccess(bounded.Span(), Bases);
	Check(folded && folded->offset == int64_t{8} * 0xfff000 + 0xff, "largest bounded offset has no signed overflow");
	limit.insert(limit.begin() + 1, Add(8, 8, 1));
	Decoded excess(decoder, limit);
	Check(!arm64_patterns::BasedMemoryAccess(excess.Span(), Bases), "work bound rejects a longer expression");
	original.instructions[1].address += 4;
	Check(!arm64_patterns::BasedMemoryAccess(original.Span(), Bases), "address gap blocks folding");
	original.instructions[1].address -= 4;
	auto* detail = original.instructions[1].detail;
	original.instructions[1].detail = nullptr;
	Check(!arm64_patterns::BasedMemoryAccess(original.Span(), Bases), "missing instruction detail has no proof");
	original.instructions[1].detail = detail;
	detail->arm64.op_count = 255;
	Check(!arm64_patterns::BasedMemoryAccess(original.Span(), Bases), "oversized operand list is refused before indexing");
	detail->arm64.op_count = 3;
	detail->arm64.operands[2].ext = ARM64_EXT_UXTW;
	Check(!arm64_patterns::BasedMemoryAccess(original.Span(), Bases), "unexpected arithmetic extension is refused");
	detail->arm64.operands[2].ext = ARM64_EXT_INVALID;
	Check(arm64_patterns::BasedMemoryAccess(original.Span(), Bases).has_value(), "negative controls leave valid input usable");
}

void StaticTable(Decoder& decoder) {
	for (bool load : {false, true}) for (bool computed : {false, true}) {
		std::vector<uint32_t> words{Add(8, 26, 0x200), Memory(8, 8, -0x78)};
		if (computed) { words.push_back(Add(8, 8, 1, false, true)); words.push_back(Add(8, 8, 0x80, true)); }
		words.push_back(Memory(3, 8, 0x40, load));
		Decoded d(decoder, words);
		const auto first = arm64_patterns::BasedMemoryAccess(d.Span(), Bases);
		Check(first && first->offset == TableOffset, "exact synthetic thread table slot");
		const auto follow = arm64_patterns::FollowFieldTableAccess(d.Span(), *first, ARM64_REG_X26, TableOffset);
		Check(follow && follow->lastIndex == words.size() - 1 && follow->offset == (computed ? 0xfc0 : 0x40) &&
			follow->isLoad == load && follow->bytes == 8, "loaded table pointer establishes byte-addressed access");
		Check(!arm64_patterns::FollowFieldTableAccess(d.Span(), *first, ARM64_REG_X26, TableOffset + 8), "different runtime slot is not a static table");
		Check(!arm64_patterns::FollowFieldTableAccess(d.Span(), *first, ARM64_REG_X27, TableOffset), "different runtime register is not a thread table");
		for (size_t i = 2; i < words.size(); ++i) {
			const std::array entries{Address + i * 4};
			Check(!arm64_patterns::FollowFieldTableAccess(d.Span(), *first, ARM64_REG_X26, TableOffset, entries), "incoming table access path is not folded");
		}
		for (unsigned defect = 0; defect < 4; ++defect) {
			auto changed = *first;
			if (defect == 0) changed.isLoad = false;
			if (defect == 1) changed.bytes = 4;
			if (defect == 2) changed.index = ARM64_REG_W2;
			if (defect == 3) changed.lastIndex = d.count;
			Check(!arm64_patterns::FollowFieldTableAccess(d.Span(), changed, ARM64_REG_X26, TableOffset), "incomplete table provenance is refused");
		}
		for (uint32_t operation : {0x94000001u, Move(8, 0), Add(8, 8, 1) & ~(1u << 31)}) {
			auto changed = words; changed.insert(changed.begin() + 2, operation);
			Decoded bad(decoder, changed);
			Check(!arm64_patterns::FollowFieldTableAccess(bad.Span(), *first, ARM64_REG_X26, TableOffset), "call, redefinition or narrow arithmetic loses table origin");
		}
		d.instructions[2].address += 4;
		Check(!arm64_patterns::FollowFieldTableAccess(d.Span(), *first, ARM64_REG_X26, TableOffset), "gap after table producer is refused");
	}
}
}

int main() {
	try {
		Decoder decoder;
		ScalarAndOrigins(decoder);
		Refusals(decoder);
		StaticTable(decoder);
		std::cout << "ARM64 memory checks passed: " << checks << '\n';
		return 0;
	} catch (const std::exception& error) {
		std::cerr << "ARM64 memory check failed: " << error.what() << '\n';
		return 1;
	}
}
