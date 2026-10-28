#include "pch.h"
#include "Disassembler.h"
#include <cstring>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <vector>

static size_t checks = 0;
static void Check(bool value, const char* message)
{
	++checks;
	if (!value)
		throw std::runtime_error(message);
}

static std::vector<uint8_t> Bytes(std::initializer_list<uint32_t> words)
{
	std::vector<uint8_t> bytes;
	for (auto word : words)
		for (unsigned i = 0; i < 4; ++i)
			bytes.push_back(static_cast<uint8_t>(word >> (8 * i)));
	return bytes;
}

static uint32_t Load(uint32_t encoding, int offset, unsigned dst = 7, unsigned base = 7)
{
	return encoding | ((static_cast<uint32_t>(offset) & 0x1ff) << 12) | (base << 5) | dst;
}

static void ValidUnprivilegedLoads()
{
	struct Encoding { uint32_t word; unsigned id; const char* name; arm64_reg destination; };
	const Encoding variants[]{
		{0x38400800, ARM64_INS_LDTRB, "ldtrb", ARM64_REG_W7},
		{0x78400800, ARM64_INS_LDTRH, "ldtrh", ARM64_REG_W7},
		{0xb8400800, ARM64_INS_LDTR, "ldtr", ARM64_REG_W7},
		{0xf8400800, ARM64_INS_LDTR, "ldtr", ARM64_REG_X7},
		{0x38800800, ARM64_INS_LDTRSB, "ldtrsb", ARM64_REG_X7},
		{0x38c00800, ARM64_INS_LDTRSB, "ldtrsb", ARM64_REG_W7},
		{0x78800800, ARM64_INS_LDTRSH, "ldtrsh", ARM64_REG_X7},
		{0x78c00800, ARM64_INS_LDTRSH, "ldtrsh", ARM64_REG_W7},
		{0xb8800800, ARM64_INS_LDTRSW, "ldtrsw", ARM64_REG_X7},
	};
	Disassembler decoder;
	for (const auto& variant : variants) {
		for (int offset : {-256, -1, 0, 1, 255}) {
			auto bytes = Bytes({Load(variant.word, offset)});
			const auto original = bytes;
			auto decoded = decoder.Disasm(bytes.data(), bytes.size(), 0x1000);
			Check(decoded.Count() == 1, "valid same-register load must decode");
			auto* instruction = decoded.FirstPtr();
			Check(instruction->id == variant.id && std::strcmp(instruction->mnemonic, variant.name) == 0,
				"unprivileged identity must be retained");
			Check(instruction->address == 0x1000 && instruction->size == 4, "instruction range must be retained");
			Check(std::memcmp(instruction->bytes, original.data(), 4) == 0 && bytes == original,
				"instruction and input bytes must be retained");
			auto& detail = instruction->detail->arm64;
			Check(detail.op_count == 2 && !detail.writeback, "unprivileged load has no writeback");
			Check(detail.operands[0].type == ARM64_OP_REG && detail.operands[0].reg == variant.destination,
				"destination width must be retained");
			Check(detail.operands[1].type == ARM64_OP_MEM && detail.operands[1].mem.base == ARM64_REG_X7 &&
				detail.operands[1].mem.disp == offset && detail.operands[1].mem.index == ARM64_REG_INVALID,
				"memory operands must be retained");
			Check(detail.operands[0].access == CS_AC_WRITE && detail.operands[1].access == CS_AC_READ,
				"operand read/write access must be retained");

			// A non-overlapping instruction already supported by Capstone supplies a metadata control.
			auto controlBytes = Bytes({Load(variant.word, offset, 7, 6)});
			auto control = decoder.Disasm(controlBytes.data(), controlBytes.size(), 0x1000);
			Check(control.Count() == 1, "non-overlapping control must decode");
			auto* expected = control.FirstPtr()->detail;
			Check(instruction->detail->groups_count == expected->groups_count &&
				std::memcmp(instruction->detail->groups, expected->groups, expected->groups_count) == 0 &&
				instruction->detail->regs_read_count == expected->regs_read_count &&
				instruction->detail->regs_write_count == expected->regs_write_count,
				"implicit register and group metadata must agree with unprivileged control");
		}
	}
	std::vector<uint8_t> mixed;
	for (const auto& variant : variants) {
		auto bytes = Bytes({Load(variant.word, -1)});
		mixed.insert(mixed.end(), bytes.begin(), bytes.end());
	}
	auto decoded = decoder.Disasm(mixed.data(), mixed.size(), 0x1000);
	Check(decoded.Count() == std::size(variants), "mixed load families must decode in one retry");
	for (size_t i = 0; i < std::size(variants); ++i)
		Check(decoded.Ptr(i)->id == variants[i].id &&
			std::memcmp(decoded.Ptr(i)->bytes, mixed.data() + i * 4, 4) == 0,
			"retry must restore each load family without changing its bytes");
}

static void StreamAndBoundaries()
{
	constexpr uint32_t ret = 0xd65f03c0;
	const auto word = Load(0xf8400800, -1);
	auto bytes = Bytes({ret, word, word, ret});
	Disassembler decoder;
	auto all = decoder.Disasm(bytes.data(), bytes.size(), 0x1000);
	Check(all.Count() == 4 && all.Ptr(3)->id == ARM64_INS_RET, "recovery must retain subsequent instructions");
	for (size_t limit : {size_t{1}, size_t{2}, size_t{3}}) {
		auto limited = decoder.Disasm(bytes.data(), bytes.size(), 0x1000, limit);
		Check(limited.Count() == limit, "maximum instruction count must be respected");
	}
	Disassembler withoutDetail(false);
	auto plain = withoutDetail.Disasm(bytes.data(), bytes.size(), 0x1000);
	Check(plain.Count() == 4 && plain.Ptr(1)->id == ARM64_INS_LDTR && plain.Ptr(1)->detail == nullptr,
		"recovery must also support detail-disabled decoding");
	for (size_t size : {size_t{0}, size_t{1}, size_t{2}, size_t{3}}) {
		auto truncated = decoder.Disasm(bytes.data() + 4, size, 0x1000);
		Check(truncated.Count() == 0, "truncated words must not be recovered");
	}
	auto invalid = Bytes({word, 0xffffffff, ret});
	auto prefix = decoder.Disasm(invalid.data(), invalid.size(), 0x1000);
	Check(prefix.Count() == 1, "recovery must stop at unrelated invalid encodings");
	for (uint32_t mode : {0x400u, 0xc00u}) {
		auto indexed = Bytes({(word & ~0xc00u) | mode});
		auto rejected = decoder.Disasm(indexed.data(), indexed.size(), 0x1000);
		Check(rejected.Count() == 0, "writeback overlap must remain rejected");
	}
	auto zeroSp = Bytes({Load(0xf8400800, 0, 31, 31)});
	auto distinct = decoder.Disasm(zeroSp.data(), zeroSp.size(), 0x1000);
	Check(distinct.Count() == 1 && distinct.FirstPtr()->detail->arm64.operands[0].reg == ARM64_REG_XZR &&
		distinct.FirstPtr()->detail->arm64.operands[1].mem.base == ARM64_REG_SP, "zero register and SP remain distinct");
}

int main()
{
	try {
		ValidUnprivilegedLoads();
		StreamAndBoundaries();
		std::cout << "ARM64 decoder checks passed: " << checks << '\n';
		return 0;
	}
	catch (const std::exception& error) {
		std::cerr << "ARM64 decoder check failed: " << error.what() << '\n';
		return 2;
	}
}
