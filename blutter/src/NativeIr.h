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
struct ExtractSigned { RegisterWrite target; Operand value; unsigned lsb, bits, leftShift; };
// Address arithmetic is modulo 64 bits. No alignment, object identity or
// memory lifetime is implied by a base plus displacement.
struct Address { RegisterView base; int64_t displacement; };
struct Load { RegisterWrite target; Address address; unsigned bytes; };
// The branch target is distinct from an ABI's returned-value register(s).
struct Return { RegisterView address; };
using Operation = std::variant<Opaque, Assign, InsertBits, Binary, ExtractUnsigned, ExtractSigned, Load, Return>;
struct Source { uint64_t address; uint32_t word; };
struct Instruction { Source source; Operation operation = Opaque{}; };

enum class MemoryEffect { None, Read, Unknown };
enum class ControlEffect { Fallthrough, Return, Unknown };
enum class FlagsEffect { Preserved, Unknown };
enum class FaultEffect { None, MayFault, Unknown };
struct Effects {
	std::optional<RegisterWrite> destination;
	bool unlistedRegistersMayChange = true;
	MemoryEffect memory = MemoryEffect::Unknown;
	ControlEffect control = ControlEffect::Unknown;
	FlagsEffect flags = FlagsEffect::Unknown;
	FaultEffect fault = FaultEffect::Unknown;
};
using ReadRegister = std::function<std::optional<uint64_t>(RegisterView)>;
// Supplies a checked value for this read, not a persistent memory fact. The
// callback owns mapping, lifetime and alias policy; the evaluator never
// dereferences a host pointer. Bits are in the target's loaded integer order.
using ReadMemory = std::function<std::optional<uint64_t>(uint64_t address, unsigned bytes)>;

// Unsupported or malformed operations retain unknown effects and no value.
Effects GetEffects(const Instruction& instruction);
std::optional<uint64_t> EvaluateAddress(const Address& address, const ReadRegister& read = {});
// Return describes control transfer and never evaluates to a returned value.
std::optional<uint64_t> Evaluate(const Instruction& instruction, const ReadRegister& read = {}, const ReadMemory& memory = {});
}
