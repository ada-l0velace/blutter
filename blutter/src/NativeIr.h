#pragma once
#include <cstdint>
#include <functional>
#include <optional>
#include <variant>

namespace SnapshotAnalysis::NativeIr {
// Physical register identifiers are assigned by the target lowerer. A view
// selects bits to read; a write separately describes the full storage update.
struct RegisterView {
	uint16_t id;
	unsigned bits;
};
enum class Extension { None, Zero };
struct RegisterWrite {
	uint16_t id;
	unsigned valueBits, storageBits;
	Extension extension;
};
struct Literal { uint64_t value; };
using Operand = std::variant<RegisterView, Literal>;
struct Opaque {};
struct Assign { RegisterWrite target; Operand value; };
struct InsertBits {
	RegisterWrite target;
	RegisterView previous;
	uint64_t value, mask;
};
enum class BinaryKind { Add, Subtract };
struct Binary { RegisterWrite target; BinaryKind kind; Operand left, right; };
struct ExtractUnsigned { RegisterWrite target; Operand value; unsigned lsb, bits; };
using Operation = std::variant<Opaque, Assign, InsertBits, Binary, ExtractUnsigned>;
struct Source { uint64_t address; uint32_t word; };
struct Instruction { Source source; Operation operation = Opaque{}; };

enum class MemoryEffect { None, Unknown };
enum class ControlEffect { Fallthrough, Unknown };
enum class FlagsEffect { Preserved, Unknown };
struct Effects {
	std::optional<RegisterWrite> destination;
	bool unlistedRegistersMayChange = true;
	MemoryEffect memory = MemoryEffect::Unknown;
	ControlEffect control = ControlEffect::Unknown;
	FlagsEffect flags = FlagsEffect::Unknown;
};
using ReadRegister = std::function<std::optional<uint64_t>(RegisterView)>;

// This first word-operation subset has no memory/branch/call semantics.
// Unsupported or malformed operations retain unknown effects and no value.
Effects GetEffects(const Instruction& instruction);
std::optional<uint64_t> Evaluate(const Instruction& instruction, const ReadRegister& read = {});
}
