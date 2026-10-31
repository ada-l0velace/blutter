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
		effect.control == ControlEffect::Fallthrough && effect.flags == FlagsEffect::Preserved, "Pure operation has wrong effects");
}
void Unknown(Operation operation) {
	unsigned reads = 0;
	const Instruction instruction{{0x1000, 0}, operation};
	Check(!Evaluate(instruction, [&](RegisterView) { ++reads; return std::optional<uint64_t>{0}; }), "Malformed/opaque operation acquired a value");
	Check(reads == 0, "Malformed operation read a register before validation");
	const auto effect = GetEffects(instruction);
	Check(!effect.destination && effect.unlistedRegistersMayChange && effect.memory == MemoryEffect::Unknown &&
		effect.control == ControlEffect::Unknown && effect.flags == FlagsEffect::Unknown, "Malformed/opaque operation acquired pure effects");
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
		std::cout << "Native IR checks passed: " << checks << '\n';
		return 0;
	} catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
