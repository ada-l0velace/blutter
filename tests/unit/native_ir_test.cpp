#include "NativeIr.h"
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace SnapshotAnalysis::NativeIr;
namespace {
unsigned checks = 0;
void Check(bool condition, std::string_view name) {
	++checks;
	if (!condition) throw std::runtime_error(std::string(name));
}
RegisterWrite X(uint16_t id = 0) { return {id, 64, 64, Extension::None}; }
RegisterWrite W(uint16_t id = 0) { return {id, 32, 64, Extension::Zero}; }
void Value(Operation operation, uint64_t expected, const ReadRegister& read = {}) {
	const Instruction instruction{{0x1000, 0}, operation};
	Check(Evaluate(instruction, read) == expected, "IR value differs from authored expectation");
	const auto effect = GetEffects(instruction);
	Check(effect.destination.has_value() && !effect.unlistedRegistersMayChange && effect.memory == MemoryEffect::None &&
		effect.control == ControlEffect::Fallthrough && effect.flags == FlagsEffect::Preserved && effect.fault == FaultEffect::None, "Pure operation has wrong effects");
}
void Unknown(Operation operation) {
	unsigned reads = 0, memoryReads = 0;
	const Instruction instruction{{0x1000, 0}, operation};
	Check(!Evaluate(instruction, [&](RegisterView) { ++reads; return std::optional<uint64_t>{0}; },
		[&](uint64_t, unsigned) { ++memoryReads; return std::optional<uint64_t>{0}; }), "Malformed/opaque operation acquired a value");
	Check(reads == 0 && memoryReads == 0, "Malformed operation requested inputs before validation");
	const auto effect = GetEffects(instruction);
	Check(!effect.destination && effect.unlistedRegistersMayChange && effect.memory == MemoryEffect::Unknown &&
		effect.control == ControlEffect::Unknown && effect.flags == FlagsEffect::Unknown && effect.fault == FaultEffect::Unknown,
		"Malformed/opaque operation acquired known effects");
}
void MemoryAndReturnCases() {
	unsigned registerReads = 0, memoryReads = 0;
	const ReadRegister read = [&](RegisterView reg) -> std::optional<uint64_t> {
		++registerReads;
		Check(reg.bits == 64, "Address base was narrowed");
		if (reg.id == 1) return 0x2000;
		if (reg.id == 31) return 0;
		return {};
	};
	const Instruction narrow{{0x1000, 0}, Load{W(), {{1, 64}, -1}, 4}};
	const auto effect = GetEffects(narrow);
	Check(effect.destination && effect.destination->valueBits == 32 && effect.destination->storageBits == 64 &&
		effect.destination->extension == Extension::Zero && !effect.unlistedRegistersMayChange &&
		effect.memory == MemoryEffect::Read && effect.control == ControlEffect::Fallthrough &&
		effect.flags == FlagsEffect::Preserved && effect.fault == FaultEffect::MayFault, "Load effects lost memory read or possible fault");
	Check(Evaluate(narrow, read, [&](uint64_t address, unsigned bytes) {
		++memoryReads;
		Check(address == 0x1fff && bytes == 4, "Load address or width differs");
		return std::optional<uint64_t>{0xabcdef01ffffffff};
	}) == 0xffffffff, "Word load failed to zero-extend");
	Check(registerReads == 1 && memoryReads == 1, "Load made unexpected input requests");
	const Instruction wide{{0x1004, 0}, Load{X(2), {{31, 64}, 0}, 8}};
	Check(Evaluate(wide, read, [](uint64_t address, unsigned bytes) {
		Check(address == 0 && bytes == 8, "Zero address was not passed to the memory policy");
		return std::optional<uint64_t>{0x8877665544332211};
	}) == 0x8877665544332211, "Full load was truncated");
	const auto before = registerReads;
	Check(!Evaluate(narrow, read), "Missing memory policy acquired a value");
	Check(registerReads == before, "Missing memory policy unnecessarily requested a base");
	Check(!Evaluate(narrow, read, [](uint64_t, unsigned) { return std::optional<uint64_t>{}; }), "Unknown memory acquired a value");
	Check(GetEffects(narrow).memory == MemoryEffect::Read, "Unknown value changed load effects");
	const auto memoryBefore = memoryReads;
	Check(!Evaluate(Instruction{{0x1008, 0}, Load{X(), {{7, 64}, 8}, 8}}, read,
		[&](uint64_t, unsigned) { ++memoryReads; return std::optional<uint64_t>{1}; }), "Unknown base acquired a load value");
	Check(memoryReads == memoryBefore, "Unknown base requested memory");
	Check(EvaluateAddress({{1, 64}, -0x2001}, read) == UINT64_MAX, "Negative displacement did not wrap at address width");
	Check(EvaluateAddress({{1, 64}, 1}, [](RegisterView) { return std::optional<uint64_t>{UINT64_MAX}; }) == 0,
		"Positive displacement did not wrap at address width");
	Check(EvaluateAddress({{1, 64}, INT64_MIN}, [](RegisterView) { return std::optional<uint64_t>{0}; }) == (uint64_t{1} << 63),
		"Most negative displacement caused signed arithmetic");
	Check(!EvaluateAddress({{1, 32}, 0}, read), "Narrow address base accepted");
	Check(!EvaluateAddress({{1, 64}, 0}), "Address acquired an absent base");
	unsigned supplied = 0;
	const ReadMemory changing = [&](uint64_t, unsigned) { return std::optional<uint64_t>{++supplied}; };
	Check(Evaluate(narrow, read, changing) == 1 && Evaluate(narrow, read, changing) == 2,
		"Load evaluator cached a memory value across instructions");
	const Instruction ret{{0x100c, 0}, Return{{30, 64}}};
	const auto returns = GetEffects(ret);
	Check(!returns.destination && !returns.unlistedRegistersMayChange && returns.memory == MemoryEffect::None &&
		returns.control == ControlEffect::Return && returns.flags == FlagsEffect::Preserved && returns.fault == FaultEffect::MayFault,
		"Return effects differ from an unchecked control transfer");
	const auto readsBeforeReturn = registerReads;
	Check(!Evaluate(ret, read, changing), "Return was evaluated as an ABI result or branch address");
	Check(registerReads == readsBeforeReturn && supplied == 2, "Return value evaluator requested an input");
	for (const auto bytes : {0U, 1U, 2U, 8U, 16U}) Unknown(Load{W(), {{1, 64}, 0}, bytes});
	Unknown(Load{X(), {{1, 64}, 0}, 4});
	Unknown(Load{W(), {{1, 32}, 0}, 4});
	Unknown(Load{{0, 32, 64, Extension::None}, {{1, 64}, 0}, 4});
	Unknown(Return{{30, 32}});
}
}
int main() {
	try {
		Value(Assign{X(), Literal{0}}, 0);
		Value(Assign{X(), Literal{UINT64_MAX}}, UINT64_MAX);
		Value(Assign{W(), Literal{UINT64_MAX}}, 0xffffffff);
		Value(Assign{W(), RegisterView{1, 32}}, 0xfedcba98, [](RegisterView reg) {
			Check(reg.id == 1 && reg.bits == 32, "Narrow source view was lost");
			return std::optional<uint64_t>{0x12345678fedcba98};
		});
		const ReadRegister ones = [](RegisterView) { return std::optional<uint64_t>{UINT64_MAX}; };
		Value(Binary{W(), BinaryKind::Add, RegisterView{1, 32}, Literal{1}}, 0, ones);
		Value(Binary{X(), BinaryKind::Add, RegisterView{1, 64}, Literal{1}}, 0, ones);
		Value(Binary{W(), BinaryKind::Subtract, Literal{0}, Literal{1}}, 0xffffffff);
		Value(Binary{X(), BinaryKind::Subtract, Literal{0}, Literal{1}}, UINT64_MAX);
		Value(Binary{X(), BinaryKind::Add, Literal{0x8000000000000000}, Literal{0x8000000000000000}}, 0);
		Value(Binary{W(), BinaryKind::Subtract, Literal{0x80000000}, Literal{1}}, 0x7fffffff);
		Value(InsertBits{X(), {0, 64}, 0xabcd00000000, 0xffff00000000}, 0x1122abcd55667788,
			[](RegisterView) { return std::optional<uint64_t>{0x1122334455667788}; });
		Value(InsertBits{W(), {0, 32}, 0x12340000, 0xffff0000}, 0x12349988,
			[](RegisterView) { return std::optional<uint64_t>{0xffeeddccbbaa9988}; });
		Value(ExtractUnsigned{X(), RegisterView{1, 64}, 8, 16}, 0x6677,
			[](RegisterView) { return std::optional<uint64_t>{0x1122334455667788}; });
		Value(ExtractUnsigned{W(), RegisterView{1, 32}, 4, 12}, 0x778,
			[](RegisterView) { return std::optional<uint64_t>{0x1122334455667788}; });
		Value(ExtractUnsigned{X(), RegisterView{1, 64}, 0, 64}, 0x1122334455667788,
			[](RegisterView) { return std::optional<uint64_t>{0x1122334455667788}; });
		Value(Assign{{0, 32, 32, Extension::None}, Literal{UINT64_MAX}}, 0xffffffff);
		const Instruction missing{{0x1000, 0}, Assign{X(), RegisterView{7, 64}}};
		Check(!Evaluate(missing), "Missing register acquired a value");
		Check(GetEffects(missing).memory == MemoryEffect::None, "Missing value changed instruction effects");
		Unknown(Opaque{});
		Unknown(Assign{{0, 16, 64, Extension::Zero}, Literal{1}});
		Unknown(Assign{{0, 32, 0, Extension::None}, Literal{1}});
		Unknown(Assign{{0, 64, 32, Extension::None}, Literal{1}});
		Unknown(Assign{{0, 32, 64, Extension::None}, Literal{1}});
		Unknown(Assign{{0, 64, 64, Extension::Zero}, Literal{1}});
		Unknown(Assign{X(), RegisterView{1, 32}});
		Unknown(Binary{X(), BinaryKind::Add, RegisterView{1, 32}, Literal{1}});
		Unknown(Binary{X(), static_cast<BinaryKind>(99), Literal{0}, Literal{1}});
		Unknown(InsertBits{X(), {0, 64}, 0, 0});
		Unknown(InsertBits{W(), {0, 32}, 0, 0xffff00000000});
		Unknown(InsertBits{W(), {0, 32}, 1, 0xffff0000});
		Unknown(InsertBits{W(), {0, 64}, 0, 0xffff0000});
		Unknown(ExtractUnsigned{X(), RegisterView{1, 64}, 0, 0});
		Unknown(ExtractUnsigned{X(), RegisterView{1, 64}, 0, 65});
		Unknown(ExtractUnsigned{X(), RegisterView{1, 64}, 64, 1});
		Unknown(ExtractUnsigned{W(), RegisterView{1, 32}, 32, 1});
		Unknown(ExtractUnsigned{W(), RegisterView{1, 32}, 16, 17});
		MemoryAndReturnCases();
		std::cout << "Native IR checks passed: " << checks << '\n';
		return 0;
	} catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
