#include "NativeIr.h"
#include <type_traits>

namespace SnapshotAnalysis::NativeIr {
namespace {
bool WordWidth(unsigned bits) { return bits == 32 || bits == 64; }
uint64_t Mask(unsigned bits) { return bits == 64 ? UINT64_MAX : (uint64_t{1} << bits) - 1; }
bool Valid(RegisterWrite target) {
	return WordWidth(target.valueBits) && WordWidth(target.storageBits) && target.valueBits <= target.storageBits &&
		target.extension == (target.valueBits < target.storageBits ? Extension::Zero : Extension::None);
}
bool Valid(const Operand& operand, unsigned bits) {
	const auto* reg = std::get_if<RegisterView>(&operand);
	return !reg || reg->bits == bits;
}
bool Valid(const Address& address) { return address.base.bits == 64; }
bool Valid(const Operation& operation) {
	return std::visit([](const auto& op) {
		using T = std::decay_t<decltype(op)>;
		if constexpr (std::is_same_v<T, Opaque>) return false;
		else if constexpr (std::is_same_v<T, Return>) return op.address.bits == 64;
		else {
			if (!Valid(op.target)) return false;
			const auto bits = op.target.valueBits;
			if constexpr (std::is_same_v<T, Assign>) return Valid(op.value, bits);
			else if constexpr (std::is_same_v<T, InsertBits>)
				return op.previous.bits == bits && op.mask && !(op.mask & ~Mask(bits)) && !(op.value & ~op.mask);
			else if constexpr (std::is_same_v<T, Binary>)
				return (op.kind == BinaryKind::Add || op.kind == BinaryKind::Subtract) && Valid(op.left, bits) && Valid(op.right, bits);
			else if constexpr (std::is_same_v<T, Load>) return Valid(op.address) && op.bytes == bits / 8;
			else {
				const bool valid = Valid(op.value, bits) && op.bits > 0 && op.bits <= bits && op.lsb <= bits - op.bits;
				if constexpr (std::is_same_v<T, ExtractSigned>) return valid && op.leftShift <= bits - op.bits;
				else return valid;
			}
		}
	}, operation);
}
std::optional<uint64_t> Read(const Operand& operand, unsigned bits, const ReadRegister& read) {
	if (const auto* value = std::get_if<Literal>(&operand)) return value->value & Mask(bits);
	if (!read) return {};
	const auto value = read(std::get<RegisterView>(operand));
	return value ? std::optional<uint64_t>{*value & Mask(bits)} : std::nullopt;
}
}
Effects GetEffects(const Instruction& instruction) {
	if (!Valid(instruction.operation)) return {};
	return std::visit([](const auto& op) -> Effects {
		using T = std::decay_t<decltype(op)>;
		if constexpr (std::is_same_v<T, Opaque>) return {};
		else if constexpr (std::is_same_v<T, Return>)
			return {{}, false, MemoryEffect::None, ControlEffect::Return, FlagsEffect::Preserved, FaultEffect::MayFault};
		else if constexpr (std::is_same_v<T, Load>)
			return {op.target, false, MemoryEffect::Read, ControlEffect::Fallthrough, FlagsEffect::Preserved, FaultEffect::MayFault};
		else return {op.target, false, MemoryEffect::None, ControlEffect::Fallthrough, FlagsEffect::Preserved, FaultEffect::None};
	}, instruction.operation);
}
std::optional<uint64_t> EvaluateAddress(const Address& address, const ReadRegister& read) {
	if (!Valid(address) || !read) return {};
	const auto base = read(address.base);
	return base ? std::optional<uint64_t>{*base + static_cast<uint64_t>(address.displacement)} : std::nullopt;
}
std::optional<uint64_t> Evaluate(const Instruction& instruction, const ReadRegister& read, const ReadMemory& memory) {
	if (!Valid(instruction.operation)) return {};
	return std::visit([&](const auto& op) -> std::optional<uint64_t> {
		using T = std::decay_t<decltype(op)>;
		if constexpr (std::is_same_v<T, Opaque> || std::is_same_v<T, Return>) return {};
		else {
			const auto bits = op.target.valueBits;
			std::optional<uint64_t> value;
			if constexpr (std::is_same_v<T, Assign>) value = Read(op.value, bits, read);
			else if constexpr (std::is_same_v<T, InsertBits>) {
				if (const auto old = Read(op.previous, bits, read)) value = (*old & ~op.mask) | op.value;
			} else if constexpr (std::is_same_v<T, Binary>) {
				const auto left = Read(op.left, bits, read), right = Read(op.right, bits, read);
				if (left && right) value = op.kind == BinaryKind::Add ? *left + *right : *left - *right;
			} else if constexpr (std::is_same_v<T, Load>) {
				if (memory) if (const auto address = EvaluateAddress(op.address, read)) value = memory(*address, op.bytes);
			} else if (const auto source = Read(op.value, bits, read)) {
				value = (*source >> op.lsb) & Mask(op.bits);
				if constexpr (std::is_same_v<T, ExtractSigned>) {
					const auto sign = uint64_t{1} << (op.bits - 1);
					value = ((*value ^ sign) - sign) << op.leftShift;
				}
			}
			// The supported narrow-storage extension is explicitly zero, so no
			// old upper storage bits survive a 32-bit definition.
			return value ? std::optional<uint64_t>{*value & Mask(bits)} : std::nullopt;
		}
	}, instruction.operation);
}
}
