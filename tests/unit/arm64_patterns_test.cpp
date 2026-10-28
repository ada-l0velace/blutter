#include "Arm64Patterns.h"
#include "Arm64Constants.h"
#include "Arm64Memory.h"
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
		gdt("zero offset register move", { 0xaa0003fe, Load(), Call() }, 0);
		gdt("wrong zero offset source", { 0xaa0103fe, Load(), Call() }, std::nullopt);
		gdt("identical conditional sources", {0x9a80001e, Load(), Call()}, 0);
		gdt("different conditional sources", {0x9a81001e, Load(), Call()}, std::nullopt);
		gdt("shifted immediate", { Add(30, 0, 2, false, true), Load(), Call() }, 0x2000);
		gdt("split immediate", { Add(30, 0, 0x200, true), Add(30, 30, 0x40), Load(), Call() }, -0x1c0);
		gdt("signed index extension", { Add(30, 0, 0x200, true), Load(30, 21, 30, 7), Call() }, -0x200);
		gdt("existing single NOP handling", { Add(30, 0, 0x100), 0xd503201f, Load(), 0xd503201f, Call() }, 0x100);
		gdt("known temporary", { AddReg(30, 0, 17), Load(), Call() }, -0x2222, -0x2222, true);
		gdt("temporary inside index arithmetic", {Add(30, 0, 0x80), AddReg(30, 30, 17), Add(30, 30, 0x80, true), Load(), Call()}, -0x20, -0x20, true);
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
		Check(arm64_patterns::IsDispatchCall(ordinary.Span().subspan(1), ARM64_REG_X21), "dispatch suffix identified independently");
		Check(!arm64_patterns::IsDispatchCall(ordinary.Span(), ARM64_REG_X21), "arithmetic alone is not a dispatch suffix");
		Check(!arm64_patterns::IsDispatchCall(ordinary.Span().subspan(1), ARM64_REG_X20), "ordinary other-base load is not a dispatch");
		Check(!arm64_patterns::IsDispatchCall(ordinary.Span().subspan(1, 1), ARM64_REG_X21), "load alone does not prove a dispatch");
		Decoded withNop(handle, { Load(), 0xd503201f, Call() });
		Check(arm64_patterns::IsDispatchCall(withNop.Span(), ARM64_REG_X21), "dispatch suffix can contain a NOP");
		Decoded otherCall(handle, { Load(), Call(16) });
		Check(!arm64_patterns::IsDispatchCall(otherCall.Span(), ARM64_REG_X21), "unrelated indirect call is not a dispatch");
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

		auto booleanLoad = [&](const std::string& name, std::vector<uint32_t> words,
			std::optional<bool> expected, size_t last = 0, std::vector<uint64_t> entries = {}) {
			Decoded decoded(handle, words);
			auto match = arm64_patterns::NullBooleanLoad(decoded.Span(), ARM64_REG_X22, 0x40, 0x60, entries);
			Check(match.has_value() == expected.has_value(), name);
			if (match) {
				Check(match->value == *expected, name + " value");
				Check(match->lastIndex == last, name + " definition instruction");
			}
		};
		booleanLoad("canonical true remains one instruction", {Add(4, 22, 0x40), Add(4, 4, 1)}, true);
		booleanLoad("canonical false remains one instruction", {Add(4, 22, 0x60)}, false);
		booleanLoad("split true", {Add(4, 22, 0x180), Add(4, 4, 0x140, true)}, true, 1);
		booleanLoad("split false", {Add(4, 22, 0x180), Add(4, 4, 0x120, true)}, false, 1);
		booleanLoad("two additions", {Add(4, 22, 0x20), Add(4, 4, 0x20)}, true, 1);
		booleanLoad("shifted first immediate", {Add(4, 22, 1, false, true), Add(4, 4, 0xfc0, true)}, true, 1);
		booleanLoad("jump to pair start", {Add(4, 22, 0x180), Add(4, 4, 0x140, true)}, true, 1, {0x1000});
		booleanLoad("jump into pair", {Add(4, 22, 0x180), Add(4, 4, 0x140, true)}, std::nullopt, 0, {0x1004});
		booleanLoad("unknown final value", {Add(4, 22, 0x180), Add(4, 4, 1)}, std::nullopt);
		booleanLoad("unknown single value", {Add(4, 22, 0x180)}, std::nullopt);
		booleanLoad("wrong initial base", {Add(4, 21, 0x180), Add(4, 4, 0x140, true)}, std::nullopt);
		booleanLoad("changed destination", {Add(4, 22, 0x180), Add(5, 4, 0x140, true)}, std::nullopt);
		booleanLoad("changed source", {Add(4, 22, 0x180), Add(4, 5, 0x140, true)}, std::nullopt);
		booleanLoad("null register overwrite", {Add(22, 22, 0x180), Add(22, 22, 0x140, true)}, std::nullopt);
		booleanLoad("stack pointer destination", {Add(31, 22, 0x180), Add(31, 31, 0x140, true)}, std::nullopt);
		booleanLoad("register adjustment", {Add(4, 22, 0x180), AddReg(4, 4, 5)}, std::nullopt);
		booleanLoad("flag-setting initial addition", {Add(4, 22, 0x180) | 0x20000000, Add(4, 4, 0x140, true)}, std::nullopt);
		booleanLoad("flag-setting adjustment", {Add(4, 22, 0x180), Add(4, 4, 0x140, true) | 0x20000000}, std::nullopt);
		booleanLoad("32-bit adjustment", {Add(4, 22, 0x180), Add(4, 4, 0x140, true) & ~0x80000000u}, std::nullopt);
		booleanLoad("intervening branch", {Add(4, 22, 0x180), 0x14000001, Add(4, 4, 0x140, true)}, std::nullopt);
		booleanLoad("intervening call", {Add(4, 22, 0x180), Call(), Add(4, 4, 0x140, true)}, std::nullopt);
		booleanLoad("intervening read", {Add(4, 22, 0x180), Load(5, 4), Add(4, 4, 0x140, true)}, std::nullopt);
		booleanLoad("intervening NOP remains unproven", {Add(4, 22, 0x180), 0xd503201f, Add(4, 4, 0x140, true)}, std::nullopt);
		booleanLoad("longer sequence remains unproven", {Add(4, 22, 0x180), Add(4, 4, 0x100, true), Add(4, 4, 0x40, true)}, std::nullopt);
		Check(!arm64_patterns::NullBooleanLoad({}, ARM64_REG_X22, 0x40, 0x60), "empty boolean input");
		Decoded pair(handle, {Add(4, 22, 0x180), Add(4, 4, 0x140, true)});
		pair.insns[1].address += 4;
		Check(!arm64_patterns::NullBooleanLoad(pair.Span(), ARM64_REG_X22, 0x40, 0x60), "boolean address gap");
		pair.insns[0].address = std::numeric_limits<uint64_t>::max() - 3;
		pair.insns[1].address = 0;
		Check(!arm64_patterns::NullBooleanLoad(pair.Span(), ARM64_REG_X22, 0x40, 0x60), "boolean address wraparound");
		for (uint32_t branch : {0x14000002u, 0x54000040u, 0xb4000043u, 0x36100043u, 0x94000002u}) {
			Decoded joined(handle, {branch, Add(4, 22, 0x180), Add(4, 4, 0x140, true)});
			auto targets = arm64_patterns::DirectBranchTargets(joined.Span());
			Check(targets == std::vector<uint64_t>{0x1008}, "direct branch/call records only its target operand");
			Check(!arm64_patterns::NullBooleanLoad(joined.Span().subspan(1), ARM64_REG_X22, 0x40, 0x60, targets),
				"actual incoming branch/call prevents boolean folding");
		}
		Decoded backward(handle, {Add(4, 22, 0x180), Add(4, 4, 0x140, true), 0x17ffffff});
		auto backwardTargets = arm64_patterns::DirectBranchTargets(backward.Span());
		Check(!arm64_patterns::NullBooleanLoad(backward.Span(), ARM64_REG_X22, 0x40, 0x60, backwardTargets),
			"backward branch into pair prevents folding");
		Decoded atStart(handle, {0x14000001, Add(4, 22, 0x180), Add(4, 4, 0x140, true)});
		auto startTargets = arm64_patterns::DirectBranchTargets(atStart.Span());
		Check(arm64_patterns::NullBooleanLoad(atStart.Span().subspan(1), ARM64_REG_X22, 0x40, 0x60, startTargets).has_value(),
			"branch to pair start preserves a fresh null-relative proof");
		Decoded indirect(handle, {Call(4)});
		Check(arm64_patterns::DirectBranchTargets(indirect.Span()).empty(), "indirect call has no invented direct target");
		cs_insn missing{};
		bool rejected = false;
		try { arm64_patterns::DirectBranchTargets(std::span<const cs_insn>(&missing, 1)); }
		catch (const std::invalid_argument&) { rejected = true; }
		Check(rejected, "missing branch metadata must not imply absence of incoming edges");
		const uint64_t seed = 0xff005520abcd1234ULL;
		std::vector<uint32_t> constantWords{0xd2800000u | (0x1234 << 5) | 17,
			0xf2a00000u | (0xabcd << 5) | 17, 0xf2c00000u | (0x5520 << 5) | 17,
			0xf2e00000u | (0xff00 << 5) | 17, 0xd2009e31, 0xd2003e31};
		Decoded constant(handle, constantWords);
		auto folded = arm64_patterns::IntegerConstantSuffix(constant.Span(), constant.count, ARM64_REG_X17);
		Check(folded && folded->startIndex == 0 && folded->value == (seed ^ 0x00ff00ff00ff00ffULL ^ 0x0000ffff0000ffffULL),
			"complete masked 64-bit constant");
		Check(!arm64_patterns::IntegerConstantSuffix(constant.Span(), constant.count, ARM64_REG_X16), "constant destination is required");
		Check(!arm64_patterns::IntegerConstantSuffix(constant.Span().subspan(1), constant.count - 1, ARM64_REG_X17), "MOVK does not seed an unknown value");
		Decoded overwritten(handle, {constantWords[0], 0x8b000231});
		Check(!arm64_patterns::IntegerConstantSuffix(overwritten.Span(), overwritten.count, ARM64_REG_X17), "unknown register input invalidates a constant");
		constant.insns[2].address += 4;
		Check(!arm64_patterns::IntegerConstantSuffix(constant.Span(), constant.count, ARM64_REG_X17), "constant cannot cross an address gap");
		const std::vector<arm64_reg> bases{ARM64_REG_X15, ARM64_REG_X29, ARM64_REG_X26};
		auto load = [](unsigned reg, int offset = -1) {
			return 0xf8400000u | ((static_cast<uint32_t>(offset) & 0x1ff) << 12) | (reg << 5) | reg;
		};
		auto computed = [&](const char* name, std::vector<uint32_t> words, std::optional<int64_t> expected,
			arm64_reg base = ARM64_REG_X29, arm64_reg index = ARM64_REG_INVALID) {
			Decoded decoded(handle, words);
			auto match = arm64_patterns::ComputedBaseLoad(decoded.Span(), bases);
			Check(match.has_value() == expected.has_value(), name);
			if (match) {
				Check(match->offset == *expected && match->base == base && match->index == index, "computed memory address");
				Check(match->lastIndex == words.size() - 1 && match->destination == ARM64_REG_X8, "complete computed memory load");
			}
		};
		computed("frame argument", {Add(8, 29, 0x80, true), Add(8, 8, 0x91), load(8)}, 0x10);
		computed("thread slot", {Add(8, 26, 0x100), Add(8, 8, 0xb7, true), load(8)}, 0x48, ARM64_REG_X26);
		computed("stack load", {Add(8, 15, 0x20), Add(8, 8, 7, true), load(8)}, 0x18, ARM64_REG_X15);
		const uint32_t index = 0x8b200000u | (3 << 16) | (6 << 13) | (2 << 10) | (8 << 5) | 8;
		computed("indexed frame argument", {Add(8, 29, 0x81), index, Add(8, 8, 0x80, true), load(8)}, 0, ARM64_REG_X29, ARM64_REG_W3);
		computed("heap base is not a proven frame/thread address", {Add(8, 0, 0x81), Add(8, 8, 0x80, true), load(8)}, std::nullopt);
		computed("frame overwrite", {Add(29, 29, 0x81), load(29)}, std::nullopt);
		computed("different load displacement", {Add(8, 29, 0x81), load(8, 1)}, std::nullopt);
		computed("narrow load does not prove a 64-bit value", {Add(8, 29, 0x81), load(8) & ~0x40000000u}, std::nullopt);
		computed("flag update invalidates computed load", {Add(8, 29, 0x81) | 0x20000000, load(8)}, std::nullopt);
		computed("intervening call invalidates computed load", {Add(8, 29, 0x81), Call(), load(8)}, std::nullopt);
		computed("index aliases the changing address", {Add(8, 29, 0x81), (index & ~(31u << 16)) | (8 << 16), load(8)}, std::nullopt);
		Decoded joinedMemory(handle, {0x14000002, Add(8, 29, 0x81), Add(8, 8, 0x80, true), load(8)});
		auto memoryEntries = arm64_patterns::DirectBranchTargets(joinedMemory.Span());
		Check(!arm64_patterns::ComputedBaseLoad(joinedMemory.Span().subspan(1), bases, memoryEntries), "incoming branch blocks memory-address folding");
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
