#include "pch.h"
#include "Arm64GdtAnalysis.h"
#include "CodeAnalyzer.h"
#include <stdexcept>

static size_t checks = 0;
static void Check(bool value, const std::string& name)
{
	++checks;
	if (!value)
		throw std::runtime_error(name);
}

// Authored ARM64 encodings, decoded by the same disassembler as the analyzer.
static uint32_t Add(unsigned dst, unsigned src, unsigned imm, bool sub = false)
{
	return (sub ? 0xd1000000u : 0x91000000u) | (imm << 10) | (src << 5) | dst;
}
static uint32_t Load(unsigned base = 21)
{
	return 0xf8600800u | (30u << 16) | (3u << 13) | (1u << 12) | (base << 5) | 30u;
}
static constexpr uint32_t AddTemporary = 0x8b11001e;
static constexpr uint32_t Call = 0xd63f03c0;
static constexpr uint32_t MoveTemporary = 0xd2802411; // mov x17, #0x120
static constexpr uint32_t Ret = 0xd65f03c0;
static constexpr uint32_t Nop = 0xd503201f;
static constexpr uint64_t Base = 0x1000;

static AsmInstructions Decode(Disassembler& decoder, const std::vector<uint32_t>& words)
{
	std::vector<uint8_t> bytes;
	for (auto word : words)
		for (unsigned i = 0; i < 4; ++i)
			bytes.push_back(static_cast<uint8_t>(word >> (i * 8)));
	auto result = decoder.Disasm(bytes.data(), bytes.size(), Base);
	Check(result.Count() == words.size(), "authored instructions decode completely");
	return result;
}

struct TrackedInteger : VarInteger {
	TrackedInteger(int& destroyed) : VarInteger(int64_t{0x120}, VarValue::NativeInt), destroyed(destroyed) {}
	~TrackedInteger() override { ++destroyed; }
	int& destroyed;
};

struct Fixture {
	int destroyed = 0;
	Disassembler decoder;
	AsmInstructions instructions;
	AsmIterator cursor;
	std::vector<AsmText> texts;
	std::vector<std::unique_ptr<ILInstr>> il;
	LoadValueInstr* priorLoad = nullptr;

	Fixture(std::vector<uint32_t> words, size_t start = 0)
		: instructions(Decode(decoder, words)), cursor(instructions.FirstPtr(), instructions.LastPtr())
	{
		cursor.SetCurrent(instructions.Ptr(start));
		for (size_t i = 0; i < instructions.Count(); ++i) {
			AsmText text{};
			text.addr = instructions.Ptr(i)->address;
			texts.push_back(text);
		}
		il.push_back(std::make_unique<ReturnInstr>(AddrRange{Base - 4, Base}));
	}

	void SeedLoad(VarValue* value, A64::Register reg = A64::TMP2_REG,
		VarStorage storage = VarStorage::NewImmediate(), uint64_t end = Base + 4)
	{
		auto load = std::make_unique<LoadValueInstr>(AddrRange{Base, end}, reg, VarItem{storage, value});
		priorLoad = load.get();
		il.push_back(std::move(load));
	}
	void SeedConstant() { SeedLoad(new TrackedInteger(destroyed)); }
	std::unique_ptr<GdtCallInstr> Try() { return arm64_analysis::TryGdtCall(cursor, instructions, il); }
};

static void RejectUnchanged(Fixture& fixture, const std::string& name)
{
	auto* cursor = fixture.cursor.Current();
	std::vector<ILInstr*> nodes;
	std::vector<std::pair<uint64_t, uint64_t>> ranges;
	for (const auto& node : fixture.il) {
		nodes.push_back(node.get());
		ranges.emplace_back(node->Start(), node->End());
	}
	auto* priorValue = fixture.priorLoad ? fixture.priorLoad->val.Value() : nullptr;
	const auto priorText = priorValue ? priorValue->ToString() : "";
	std::vector<uint8_t> originalBytes;
	for (size_t i = 0; i < fixture.instructions.Count(); ++i) {
		const auto* instruction = fixture.instructions.Ptr(i);
		originalBytes.insert(originalBytes.end(), instruction->bytes, instruction->bytes + instruction->size);
	}

	auto match = fixture.Try();
	Check(!match, name + ": no GDT annotation");
	Check(fixture.cursor.Current() == cursor, name + ": cursor unchanged");
	Check(fixture.destroyed == 0, name + ": preceding constant not destroyed");
	Check(fixture.il.size() == nodes.size(), name + ": IL count unchanged");
	for (size_t i = 0; i < nodes.size(); ++i) {
		Check(fixture.il[i].get() == nodes[i], name + ": IL identity/order unchanged");
		Check(fixture.il[i]->Start() == ranges[i].first && fixture.il[i]->End() == ranges[i].second,
			name + ": IL range unchanged");
	}
	if (fixture.priorLoad) {
		Check(fixture.priorLoad->val.Value() == priorValue, name + ": value identity unchanged");
		Check(!priorValue || fixture.priorLoad->val.Value()->ToString() == priorText,
			name + ": value unchanged");
	}
	size_t offset = 0;
	for (size_t i = 0; i < fixture.instructions.Count(); ++i) {
		const auto* instruction = fixture.instructions.Ptr(i);
		Check(std::equal(instruction->bytes, instruction->bytes + instruction->size,
			originalBytes.begin() + offset), name + ": instruction bytes retained");
		offset += instruction->size;
	}
}

static void Accepted(bool split, bool temporary, bool trailingNop)
{
	std::vector<uint32_t> words;
	if (temporary)
		words.push_back(MoveTemporary);
	words.push_back(temporary ? AddTemporary : Add(30, 0, 0x200, true));
	if (split)
		words.push_back(Add(30, 30, 0x40));
	words.push_back(Load());
	words.push_back(Call);
	if (trailingNop)
		words.push_back(Nop);
	words.push_back(Ret);
	Fixture fixture(words, temporary ? 1 : 0);
	if (temporary)
		fixture.SeedConstant();
	const auto* sentinel = fixture.il.front().get();
	auto match = fixture.Try();
	Check(match && match->Kind() == ILInstr::GdtCall, "complete GDT annotation");
	const int64_t expected = (temporary ? 0x120 : -0x200) + (split ? 0x40 : 0);
	Check(match->ToString() == std::format("r0 = GDT[cid_x0 + {:#x}]()", expected), "dispatch offset");
	Check(match->Start() == Base && match->End() == Base + (words.size() - 1) * 4, "complete annotation range");
	Check(fixture.cursor.Current() == fixture.instructions.LastPtr(), "following return remains available");
	Check(fixture.il.size() == 1 && fixture.il.front().get() == sentinel, "unrelated preceding IL retained");
	Check(fixture.destroyed == (temporary ? 1 : 0), "only consumed temporary is destroyed");
	fixture.il.push_back(std::move(match));
	Check(fixture.cursor.id() == ARM64_INS_RET, "following instruction is still RET");
}

static void FallbackScan()
{
	Fixture fixture({MoveTemporary, AddTemporary, Load(20), Call,
		Add(30, 0, 0x80), Load(), Call, Ret}, 1);
	fixture.SeedConstant();
	RejectUnchanged(fixture, "rejected call before valid call");
	size_t matched = 0;
	// Exercise the shared GDT path with raw-IL fallback; this is not the entire matcher pipeline.
	while (!fixture.cursor.IsEnd()) {
		auto match = fixture.Try();
		if (match) {
			++matched;
			fixture.il.push_back(std::move(match));
		}
		else {
			auto* instruction = fixture.cursor.Current();
			fixture.il.push_back(std::make_unique<UnknownInstr>(instruction, fixture.texts[(instruction->address - Base) / 4]));
			++fixture.cursor;
		}
	}
	Check(matched == 1, "later valid dispatcher remains recognized");
	Check(fixture.destroyed == 0, "rejected dispatch does not consume earlier temporary");
	Check(fixture.il[1].get() == fixture.priorLoad, "temporary remains in its original position");
	Check(fixture.il.back()->Kind() == ILInstr::Unknown && fixture.il.back()->Start() == Base + 28,
		"following return remains in raw fallback");
	for (size_t i = 0; i < fixture.instructions.Count(); ++i) {
		const auto address = fixture.instructions.Ptr(i)->address;
		size_t owners = 0;
		for (const auto& node : fixture.il)
			owners += node->Range().Has(address);
		Check(owners == 1, "every instruction covered exactly once by retained IL");
	}
}

int main()
{
	try {
		for (bool split : {false, true})
			for (bool temporary : {false, true})
				for (bool trailingNop : {false, true})
					Accepted(split, temporary, trailingNop);
		for (auto tail : std::vector<std::vector<uint32_t>>{{}, {Load()}, {Load(), Ret}, {Load(20), Call}}) {
			std::vector<uint32_t> words{MoveTemporary, AddTemporary};
			words.insert(words.end(), tail.begin(), tail.end());
			Fixture fixture(words, 1);
			fixture.SeedConstant();
			RejectUnchanged(fixture, "incomplete or wrong temporary call");
		}
		for (int kind = 0; kind < 7; ++kind) {
			Fixture fixture({MoveTemporary, AddTemporary, Load(), Call}, 1);
			switch (kind) {
			case 0: break; // no preceding load
			case 1: fixture.SeedLoad(new VarInteger(int64_t{0x120}), A64::Register::R16); break;
			case 2: fixture.SeedLoad(new VarInteger(int64_t{0x120}), A64::TMP2_REG, VarStorage::NewPool(16)); break;
			case 3: fixture.SeedLoad(new VarInteger()); break;
			case 4: fixture.SeedLoad(new VarBoolean(true)); break;
			case 5: fixture.SeedLoad(nullptr); break;
			case 6: fixture.SeedLoad(new VarInteger(int64_t{0x120}), A64::TMP2_REG,
				VarStorage::NewImmediate(), Base); break;
			}
			RejectUnchanged(fixture, "unproven preceding value " + std::to_string(kind));
		}
		{
			Fixture fixture({AddTemporary, Load(), Call});
			fixture.il.clear();
			RejectUnchanged(fixture, "empty preceding IL");
		}
		{
			Fixture fixture({0xf9000371, AddTemporary, Load(), Call}, 1); // str x17, [x27]
			fixture.il.push_back(std::make_unique<StoreObjectPoolInstr>(AddrRange{Base, Base + 4}, A64::TMP2_REG, 16));
			RejectUnchanged(fixture, "store sharing the load IL kind");
		}
		{
			Fixture fixture({MoveTemporary, Nop, AddTemporary, Load(20), Call}, 2);
			fixture.SeedLoad(new TrackedInteger(fixture.destroyed), A64::TMP2_REG,
				VarStorage::NewImmediate(), Base + 8);
			RejectUnchanged(fixture, "NOP before rejected dispatch");
		}
		{
			Fixture fixture({MoveTemporary, Add(30, 0, 0x80), Load(), Call}, 1);
			fixture.SeedConstant();
			auto* previous = fixture.priorLoad;
			auto match = fixture.Try();
			Check(match && fixture.il.back().get() == previous && fixture.destroyed == 0,
				"immediate call retains an unused temporary");
			Check(match->Start() == Base + 4, "unused constant excluded from call range");
		}
		FallbackScan();
	}
	catch (const std::exception& error) {
		std::cerr << "ARM64 analyzer check failed: " << error.what() << '\n';
		return 1;
	}
	std::cout << "ARM64 analyzer checks passed: " << checks << '\n';
	return 0;
}
