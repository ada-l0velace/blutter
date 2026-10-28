#include "Arm64Patterns.h"
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

static size_t checks = 0;
static void Check(bool value, const std::string& name)
{
	++checks;
	if (!value)
		throw std::runtime_error(name);
}

// Authored ARM64 encodings; no target binaries are required.
static uint32_t Add(unsigned dst, unsigned src, unsigned imm, bool sub = false, bool shifted = false)
{
	return (sub ? 0xd1000000u : 0x91000000u) | (shifted ? 1u << 22 : 0) | (imm << 10) | (src << 5) | dst;
}
static uint32_t AddReg(unsigned dst, unsigned src, unsigned rhs)
{
	return 0x8b000000u | (rhs << 16) | (src << 5) | dst;
}
static uint32_t Load(unsigned dst = 30, unsigned base = 21, unsigned index = 30, unsigned extension = 3, bool scaled = true)
{
	return 0xf8600800u | (index << 16) | (extension << 13) | (scaled ? 1u << 12 : 0) | (base << 5) | dst;
}
static uint32_t Call(unsigned reg = 30) { return 0xd63f0000u | (reg << 5); }

class Decoded {
public:
	cs_insn* insns = nullptr;
	size_t count = 0;
	Decoded(csh handle, const std::vector<uint32_t>& words) {
		std::vector<uint8_t> bytes;
		for (auto word : words)
			for (unsigned i = 0; i < 4; ++i)
				bytes.push_back(static_cast<uint8_t>(word >> (i * 8)));
		count = cs_disasm(handle, bytes.data(), bytes.size(), 0x1000, 0, &insns);
		Check(count == words.size(), "authored instructions decode completely");
	}
	~Decoded() { cs_free(insns, count); }
	std::span<const cs_insn> Span() const { return { insns, count }; }
};

int main()
{
	csh handle;
	if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK)
		return 2;
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	try {
		auto gdt = [&](const std::string& name, std::vector<uint32_t> words,
			std::optional<int64_t> expected, std::optional<int64_t> tmp = std::nullopt, bool usesTmp = false) {
			Decoded decoded(handle, words);
			auto match = arm64_patterns::GdtCall(decoded.Span(), ARM64_REG_X0, ARM64_REG_X21, ARM64_REG_X17, tmp);
			Check(match.has_value() == expected.has_value(), name);
			if (match) {
				Check(match->offset == *expected, name + " offset");
				Check(match->usesTemporary == usesTmp, name + " temporary provenance");
				Check(decoded.insns[match->callIndex].id == ARM64_INS_BLR, name + " complete call");
			}
		};
		gdt("legacy subtract", { Add(30, 0, 0x200, true), Load(), Call() }, -0x200);
		gdt("legacy add", { Add(30, 0, 0x100), Load(), Call() }, 0x100);
		gdt("zero offset", { Add(30, 0, 0), Load(), Call() }, 0);
		gdt("shifted immediate", { Add(30, 0, 2, false, true), Load(), Call() }, 0x2000);
		gdt("split immediate", { Add(30, 0, 0x200, true), Add(30, 30, 0x40), Load(), Call() }, -0x1c0);
		gdt("signed index extension", { Add(30, 0, 0x200, true), Load(30, 21, 30, 7), Call() }, -0x200);
		gdt("existing single NOP handling", { Add(30, 0, 0x100), 0xd503201f, Load(), 0xd503201f, Call() }, 0x100);
		gdt("known temporary", { AddReg(30, 0, 17), Load(), Call() }, -0x2222, -0x2222, true);
		gdt("unknown temporary", { AddReg(30, 0, 17), Load(), Call() }, std::nullopt);
		gdt("wrong temporary", { AddReg(30, 0, 16), Load(), Call() }, std::nullopt, 5);
		gdt("wrong table", { Add(30, 0, 1), Load(30, 20), Call() }, std::nullopt);
		gdt("wrong index", { Add(30, 0, 1), Load(30, 21, 17), Call() }, std::nullopt);
		gdt("wrong destination", { Add(30, 0, 1), Load(16), Call() }, std::nullopt);
		gdt("wrong scale", { Add(30, 0, 1), Load(30, 21, 30, 3, false), Call() }, std::nullopt);
		gdt("narrow signed index", { Add(30, 0, 1), Load(30, 21, 30, 6), Call() }, std::nullopt);
		gdt("wrong call register", { Add(30, 0, 1), Load(), Call(16) }, std::nullopt);
		gdt("intervening branch", { Add(30, 0, 1), 0x14000001, Load(), Call() }, std::nullopt);
		gdt("different class-id register", { Add(30, 1, 1), Load(), Call() }, std::nullopt);
		gdt("changed intermediate source", { Add(30, 0, 1), Add(30, 1, 1), Load(), Call() }, std::nullopt);
		gdt("condition flags", { Add(30, 0, 1) | 0x20000000, Load(), Call() }, std::nullopt);
		gdt("truncated call", { Add(30, 0, 1), Load() }, std::nullopt);
		gdt("truncated load", { Add(30, 0, 1) }, std::nullopt);
		gdt("positive overflow", { AddReg(30, 0, 17), Add(30, 30, 1), Load(), Call() },
			std::nullopt, std::numeric_limits<int64_t>::max());
		gdt("negative overflow", { AddReg(30, 0, 17), Add(30, 30, 1, true), Load(), Call() },
			std::nullopt, std::numeric_limits<int64_t>::min());
		std::vector<uint32_t> bounded{ Add(30, 0, 1) };
		for (unsigned i = 0; i < 7; ++i)
			bounded.push_back(Add(30, 30, 1));
		bounded.push_back(Load()); bounded.push_back(Call());
		gdt("arithmetic bound", bounded, 8);
		bounded.insert(bounded.begin() + 1, Add(30, 30, 1));
		gdt("excess arithmetic", bounded, std::nullopt);
		Decoded ordinary(handle, { Add(30, 0, 1), Load(), Call() });
		Check(!arm64_patterns::GdtCall({}, ARM64_REG_X0, ARM64_REG_X21, ARM64_REG_X17), "empty input");
		ordinary.insns[1].address += 4;
		Check(!arm64_patterns::GdtCall(ordinary.Span(), ARM64_REG_X0, ARM64_REG_X21, ARM64_REG_X17), "address gap");
		auto boolean = [&](uint32_t word, std::optional<bool> expected) {
			Decoded decoded(handle, { word });
			Check(arm64_patterns::NullBoolean(decoded.insns[0], ARM64_REG_X22, 0x40, 0x60) == expected, "null/boolean classification");
		};
		boolean(Add(4, 22, 0x40), true);
		boolean(Add(4, 22, 0x60), false);
		boolean(Add(4, 22, 0x44), std::nullopt);
		boolean(Add(4, 21, 0x40), std::nullopt);
		boolean(AddReg(4, 22, 3), std::nullopt);
		boolean(Add(4, 22, 0x40, false, true), std::nullopt);
		boolean(Add(4, 22, 0x40) | 0x20000000, std::nullopt);
	}
	catch (const std::exception& error) {
		cs_close(&handle);
		std::cerr << "ARM64 pattern check failed: " << error.what() << '\n';
		return 1;
	}
	cs_close(&handle);
	std::cout << "ARM64 pattern checks passed: " << checks << '\n';
	return 0;
}
