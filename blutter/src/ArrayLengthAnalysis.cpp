#include "ArrayLengthAnalysis.h"
#include "Arm64Ir.h"
#include <array>

namespace SnapshotAnalysis {
std::optional<ArrayLengthSummary> ProveArrayLength(const cs_insn* code, size_t count, const Profile& profile) {
	if (!code || count < 3 || count > 32 || !profile.arrayLengthLayout || profile.wordReturnRegister != ARM64_REG_X0) return {};
	const auto& layout = *profile.arrayLengthLayout;
	if (!layout.classId || layout.displacement < 0 || layout.displacement > (1 << 20) - 8 ||
		(layout.bytes != 4 && layout.bytes != 8) || layout.smiShift != 1) return {};
	// These are symbolic input relations, never concrete pointer bits.
	enum Kind { Unknown, Stack, Input, Length };
	struct Value { Kind kind = Unknown; int64_t slot = 0; };
	std::array<Value, 31> regs;
	regs[15] = {Stack};
	ArrayLengthSummary summary{};
	for (size_t n = 0; n < count; ++n) {
		if (code[n].address < code[0].address || code[n].address - code[0].address != n * 4) return {};
		const auto instruction = LowerArm64(code[n]);
		if (!instruction) return {};
		summary.proof.push_back(instruction->source.address);
		if (instruction->source.word == 0xd503201f) continue; // Architectural NOP only.
		if (const auto* ret = std::get_if<NativeIr::Return>(&instruction->operation)) {
			if (ret->address.id != 30 || n + 1 != count || regs[0].kind != Length) return {};
			summary.arraySpOffset = regs[0].slot;
			return summary;
		}
		const auto effects = NativeIr::GetEffects(*instruction);
		if (!effects.destination || effects.destination->id >= 31 || effects.unlistedRegistersMayChange ||
			effects.control != NativeIr::ControlEffect::Fallthrough || effects.flags != NativeIr::FlagsEffect::Preserved) return {};
		const auto dst = effects.destination->id;
		// Keep entry SP, caller FP/LR and reserved Dart registers unchanged.
		if (dst == 15 || dst == 21 || dst == 22 || dst == 26 || dst == 27 || dst == 28 || dst == 29 || dst == 30) return {};
		summary.writtenRegisters |= 1U << dst;
		Value value;
		if (const auto* load = std::get_if<NativeIr::Load>(&instruction->operation)) {
			const auto base = load->address.base.id;
			if (base >= 31) return {};
			const auto source = regs[base];
			const auto offset = load->address.displacement;
			if (source.kind == Stack && load->bytes == 8 && offset >= 0 && offset <= 248 && offset % 8 == 0)
				value = {Input, offset};
			else if (source.kind == Input && load->bytes == layout.bytes && offset == layout.displacement)
				value = {Length, source.slot};
			else return {};
		} else if (const auto* assign = std::get_if<NativeIr::Assign>(&instruction->operation)) {
			const auto* source = std::get_if<NativeIr::RegisterView>(&assign->value);
			if (!source || source->id >= 31) return {};
			value = regs[source->id];
			if (source->bits != 64 && !(source->bits == 32 && layout.bytes == 4 && value.kind == Length)) value = {};
		} else return {};
		regs[dst] = value;
	}
	return {};
}
}
