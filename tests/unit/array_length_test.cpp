#include "ArrayLengthAnalysis.h"
#include <array>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace SnapshotAnalysis;
namespace {
unsigned checks = 0;
void Check(bool value, std::string_view message) {
	++checks;
	if (!value) throw std::runtime_error(std::string(message));
}
struct Decoder {
	csh handle = 0;
	Decoder() {
		if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK ||
			cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) throw std::runtime_error("Cannot initialize decoder");
	}
	~Decoder() { if (handle) cs_close(&handle); }
};
std::optional<ArrayLengthSummary> Prove(csh handle, const std::vector<uint32_t>& words, const Profile& profile) {
	std::vector<uint8_t> bytes;
	for (const auto word : words) for (unsigned shift = 0; shift < 32; shift += 8) bytes.push_back(static_cast<uint8_t>(word >> shift));
	cs_insn* raw = nullptr;
	const auto count = cs_disasm(handle, bytes.data(), bytes.size(), 0x1000, 0, &raw);
	const std::shared_ptr<cs_insn> owner(raw, [count](cs_insn* p) { cs_free(p, count); });
	return count * 4 == bytes.size() ? ProveArrayLength(raw, count, profile) : std::nullopt;
}
}
int main() {
	try {
		Decoder decoder;
		Profile profile{"synthetic", ARM64_REG_X27, ARM64_REG_X26, 16, 8, 0, {}, {}};
		profile.wordReturnRegister = ARM64_REG_X0;
		profile.arrayLengthLayout = ArrayLengthLayout{2, 7, 4, 1};
		// Authored words: entry-slot load, four-byte selected field, return.
		const std::vector<uint32_t> plain{0xf94009e3, 0xb8407060, 0xd65f03c0};
		const auto value = Prove(decoder.handle, plain, profile);
		Check(value && value->arraySpOffset == 16, "Selected input relation was not proved");
		Check(value->proof == std::vector<uint64_t>{0x1000, 0x1004, 0x1008}, "Proof does not cover the checked body");
		Check(value->writtenRegisters == ((1U << 3) | 1U), "Leaf write mask omits or invents a register definition");
		Check(Prove(decoder.handle, {0xf94009e0, 0xb8407000, 0xd65f03c0}, profile).has_value(), "Overlapping base/result load rejected");
		Check(Prove(decoder.handle, {0xaa0f03e5, 0xf94008a3, 0xb8407060, 0x2a0003e2, 0xaa0203e0, 0xd65f03c0}, profile).has_value(),
			"Stack alias or zero-extended length copy was lost");
		auto padded = plain; padded.insert(padded.begin(), 0xd503201f);
		Check(Prove(decoder.handle, padded, profile).has_value(), "Architectural NOP rejected");
		auto wide = profile; wide.arrayLengthLayout->bytes = 8;
		Check(Prove(decoder.handle, {0xf94009e3, 0xf8407060, 0xd65f03c0}, wide).has_value(), "Eight-byte field rejected");
		Check(!Prove(decoder.handle, {0xf94009e3, 0xf8407060, 0x2a0003e0, 0xd65f03c0}, wide), "Narrowed full-word length accepted");
		for (const auto replacement : {0xb840b060U, 0xf8407060U, 0xb8807060U, 0x38407060U, 0x78407060U,
			0xb8407c60U, 0xb8407460U, 0xb9400060U, 0xf9000060U, 0xb8007069U, 0xd5033bbfU, 0x94000001U}) {
			auto changed = plain; changed[1] = replacement;
			Check(!Prove(decoder.handle, changed, profile), "Wrong load or unsupported effect accepted");
		}
		for (const auto words : std::vector<std::vector<uint32_t>>{
			{0xf94009e3, 0x2a0303e3, 0xb8407060, 0xd65f03c0},
			{0xf94009e3, 0xb8407060, 0xaa0903e0, 0xd65f03c0},
			{0xf94009e3, 0xb8407060, 0x91000400, 0xd65f03c0},
			{0xf94009e3, 0xb8407060, 0xd2800000, 0xd65f03c0},
			{0xf94009e3, 0xb8407060, 0xd65f0260},
			{0xf94009e3, 0xb8407060, 0x14000001, 0xd65f03c0},
			{0xf94009e3, 0xb8407060, 0xd65f03c0, 0xd503201f},
			{0xf94009e3, 0xb8407060, 0xf90001e0, 0xd65f03c0},
			{0xf94009e3, 0xb8407060, 0xd4200000},
			{0xf9400be3, 0xb8407060, 0xd65f03c0},
			{0xf94009e3, 0xb8407060, 0xaa0003e4},
			{0xf94009e3, 0xd65f03c0}})
			Check(!Prove(decoder.handle, words, profile), "Unsupported body/return accepted");
		for (const auto dst : {15U, 21U, 22U, 26U, 27U, 28U, 29U, 30U, 31U}) {
			auto changed = plain; changed.insert(changed.begin()+2, 0xaa0003e0 | dst);
			Check(!Prove(decoder.handle, changed, profile), "Reserved/frame destination accepted");
		}
		for (unsigned defect = 0; defect < 7; ++defect) {
			auto changed = profile;
			switch (defect) {
			case 0: changed.arrayLengthLayout.reset(); break;
			case 1: changed.arrayLengthLayout->classId = 0; break;
			case 2: changed.arrayLengthLayout->displacement = -1; break;
			case 3: changed.arrayLengthLayout->displacement = INT64_MAX; break;
			case 4: changed.arrayLengthLayout->bytes = 2; break;
			case 5: changed.arrayLengthLayout->smiShift = 2; break;
			case 6: changed.wordReturnRegister = ARM64_REG_INVALID; break;
			}
			Check(!Prove(decoder.handle, plain, changed), "Invalid layout or result ABI accepted");
		}
		auto limit = plain; limit.insert(limit.begin(), 29, 0xd503201f);
		Check(Prove(decoder.handle, limit, profile).has_value(), "Exact instruction limit rejected");
		limit.insert(limit.begin(), 0xd503201f);
		Check(!Prove(decoder.handle, limit, profile), "Instruction budget exceeded");
		Check(!ProveArrayLength(nullptr, 3, profile), "Missing instructions accepted");
		const uint8_t bytes[] = {0xe3, 0x09, 0x40, 0xf9, 0x60, 0x70, 0x40, 0xb8, 0xc0, 0x03, 0x5f, 0xd6};
		cs_insn* raw = nullptr;
		const auto count = cs_disasm(decoder.handle, bytes, sizeof(bytes), 0x1000, 0, &raw);
		const std::shared_ptr<cs_insn> owner(raw, [count](cs_insn* p) { cs_free(p, count); });
		Check(count == 3, "Authored malformed-record control did not decode");
		std::array<cs_insn, 3> malformed{raw[0], raw[1], raw[2]};
		malformed[1].address += 1;
		Check(!ProveArrayLength(malformed.data(), malformed.size(), profile), "Noncontiguous source records accepted");
		malformed[1] = raw[1]; malformed[1].detail = nullptr;
		Check(!ProveArrayLength(malformed.data(), malformed.size(), profile), "Missing detail accepted");
		std::cout << "Array length checks passed: " << checks << '\n';
		return 0;
	} catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
