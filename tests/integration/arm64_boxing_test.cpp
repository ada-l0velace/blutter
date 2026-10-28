#include "pch.h"
#include "Disassembler.h"
#include "Arm64Boxing.h"
#include <iostream>
#include <stdexcept>
#include <vector>

static size_t checks = 0;
static void Check(bool value, const char* reason)
{
	++checks;
	if (!value) throw std::runtime_error(reason);
}

static constexpr uint64_t Base = 0x1000, Allocator = 0x1800;
static const arm64_patterns::BoxingAbi Abi{ARM64_REG_X15, ARM64_REG_X29, ARM64_REG_X30,
	ARM64_REG_X27, ARM64_REG_X0, (uint32_t{1} << 3) | (uint32_t{1} << 6), 7, 7, 1};
static uint32_t Add(unsigned dst, unsigned src, unsigned value, bool subtract = false)
{
	return (subtract ? 0xd1000000u : 0x91000000u) | (value << 10) | (src << 5) | dst;
}
static uint32_t Mem(unsigned reg, unsigned base, int offset, bool store, bool unscaled = false)
{
	if (unscaled) return (store ? 0xf8000000u : 0xf8400000u) |
		((static_cast<uint32_t>(offset) & 0x1ff) << 12) | (base << 5) | reg;
	return (store ? 0xf9000000u : 0xf9400000u) | ((offset / 8) << 10) | (base << 5) | reg;
}
static uint32_t Copy(unsigned dst, unsigned src, unsigned condition = 0)
{
	return 0x9a800000u | (src << 16) | (condition << 12) | (src << 5) | dst;
}

struct Fixture {
	std::vector<uint32_t> words;
	size_t start, call, store, body, end;
	Fixture(bool framed, bool pool, bool unprivileged = false, bool positiveBias = true,
		bool wordMove = false, unsigned extension = 3, size_t prefix = 0) : words(prefix, 0xd503201f), start(prefix)
	{
		words.insert(words.end(), {0x937f7860, 0xeb80047f, 0x54000041, 0});
		body = words.size();
		if (framed) words.insert(words.end(), {Add(15, 15, 0x80, true), Mem(29, 15, 0x70, true),
			Mem(30, 15, 0x78, true), Add(15, 15, 0x70), Copy(29, 15, 10)});
		if (pool) {
			words.push_back((wordMove ? 0x52800000u : 0xd2800000u) | (0x80 << 5) | 30);
			words.push_back(0xf8600800u | (30 << 16) | (extension << 13) | (27 << 5) | 30);
			words.push_back(Mem(30, 30, 7, false, true) | (unprivileged ? 0x800 : 0));
			call = words.size(); words.push_back(0xd63f03c0);
		}
		else {
			call = words.size();
			words.push_back(0x94000000u | ((Allocator - (Base + call * 4)) / 4));
		}
		if (framed) words.insert(words.end(), {Copy(15, 29, 3), Add(15, 15, 0x60, true),
			Mem(29, 15, 0x60, false), Mem(30, 15, 0x68, false), Add(15, 15, 0x70)});
		words.push_back(Add(0, 0, 0x20, !positiveBias));
		store = words.size(); words.push_back(Mem(3, 0, positiveBias ? -0x19 : 0x27, true, true));
		words.push_back(Add(0, 0, 0x20, positiveBias));
		end = words.size(); words.push_back(0xd65f03c0);
		words[start + 3] = 0x3600001fu | (5 << 19) | ((end - (start + 3)) << 5);
	}
};

static void Run(const Fixture& fixture, bool expected, bool allowAllocator = true, uint64_t entry = 0)
{
	std::vector<uint8_t> bytes;
	for (auto word : fixture.words)
		for (unsigned shift = 0; shift < 32; shift += 8) bytes.push_back(static_cast<uint8_t>(word >> shift));
	const auto original = bytes;
	Disassembler decoder;
	auto instructions = decoder.Disasm(bytes.data(), bytes.size(), Base);
	Check(instructions.Count() == fixture.words.size(), "authored boxing words must decode");
	size_t verifications = 0;
	auto match = arm64_patterns::InvertedBoxInt64(
		std::span<const cs_insn>(instructions.FirstPtr(), instructions.Count()), fixture.start, Abi,
		[&](const arm64_patterns::BoxingCall& call) {
			++verifications;
			return allowAllocator && ((call.target && *call.target == Allocator) || (call.poolOffset && *call.poolOffset == 0x80));
		}, [&](uint64_t address) { return address == entry; });
	Check(match.has_value() == expected, "boxing recognition result");
	Check(bytes == original, "boxing recognition must not modify original bytes");
	if (match) {
		Check(match->endIndex == fixture.end && match->call.instruction == fixture.call, "complete boxing span and call");
		Check(match->source == ARM64_REG_X3 && match->result == ARM64_REG_X0, "boxing input and result");
		Check(verifications == 1, "allocator proof required before accepting boxing");
	}
}

int main()
{
	try {
		for (bool framed : {false, true}) for (bool pool : {false, true})
			for (bool unprivileged : {false, true}) for (bool positiveBias : {false, true})
				Run(Fixture(framed, pool, unprivileged, positiveBias), true);
		for (unsigned extension : {2u, 3u, 6u, 7u}) Run(Fixture(true, true, true, true, true, extension), true);
		Fixture valid(true, true);
		Run(valid, false, false);
		Run(valid, false, true, Base + valid.body * 4);
		Run(valid, true, true, Base + valid.start * 4);
		for (int defect = 0; defect < 20; ++defect) {
			Fixture bad(true, true);
			switch (defect) {
			case 0: bad.words[bad.start + 2] ^= 1; break; // wrong condition
			case 1: bad.words[bad.start + 2] += 0x20; break; // wrong allocation entry
			case 2: bad.words[bad.start + 3] &= ~31u; break; // skip depends on unknown register
			case 3: bad.words[bad.start + 1] ^= 1u << 5; break; // wrong comparison input
			case 4: bad.words[bad.body + 1] += 1u << 10; break; // wrong frame slot
			case 5: bad.words[bad.body + 2] ^= 1; break; // wrong saved link
			case 6: bad.words[bad.body + 3] += 1u << 10; break; // unbalanced frame
			case 7: bad.words[bad.body + 4] ^= 1u << 16; break; // conditional frame value
			case 8: bad.words[bad.call - 2] ^= 1u << 5; break; // wrong pool base
			case 9: bad.words[bad.call - 2] |= 1u << 12; break; // scaled pool index
			case 10: bad.words[bad.call - 1] += 1u << 12; break; // wrong Code entry field
			case 11: bad.words[bad.call] ^= 1u << 5; break; // wrong called register
			case 12: bad.words[bad.call + 1] ^= 1u << 16; break; // conditional SP restoration
			case 13: bad.words[bad.call + 3] += 1u << 10; break; // wrong restored frame slot
			case 14: bad.words[bad.call + 5] += 1u << 10; break; // unbalanced final SP
			case 15: bad.words[bad.store] ^= 1; break; // wrong stored integer
			case 16: bad.words[bad.store] += 1u << 12; break; // wrong effective value field
			case 17: bad.words[bad.store + 1] += 1u << 10; break; // result pointer not restored
			case 18: // Keep all uses consistent, but use an allocator-clobbered input.
				bad.words[bad.start] = (bad.words[bad.start] & ~(31u << 5)) | (1u << 5);
				bad.words[bad.start + 1] = (bad.words[bad.start + 1] & ~(31u << 5)) | (1u << 5);
				bad.words[bad.store] = (bad.words[bad.store] & ~31u) | 1;
				break;
			case 19: bad.words[bad.call - 3] += 1u << 5; break; // unverified pool offset
			}
			Run(bad, false);
		}
		for (size_t length = 1; length < valid.end; ++length) {
			auto truncated = valid;
			truncated.words.resize(length);
			Run(truncated, false);
		}
		Fixture incoming(true, false, false, true, false, 3, 1);
		incoming.words[0] = 0x14000000u | static_cast<uint32_t>(incoming.body);
		Run(incoming, false);
		incoming.words[0] = 0x14000001;
		Run(incoming, true);
		Fixture backward(false, false);
		const auto pc = backward.words.size();
		backward.words.push_back(0x14000000u | (static_cast<uint32_t>(static_cast<int64_t>(backward.body) - pc) & 0x3ffffff));
		Run(backward, false);
		std::cout << "ARM64 boxing checks passed: " << checks << '\n';
		return 0;
	}
	catch (const std::exception& error) {
		std::cerr << "ARM64 boxing check failed: " << error.what() << '\n';
		return 2;
	}
}
