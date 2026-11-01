#include "NativeReturnContracts.h"
#include "ReceiverAnalysis.h"
#include "CallEffects.h"
#include <iostream>
#include <memory>
#include <stdexcept>

using namespace SnapshotAnalysis;
namespace {
unsigned checks = 0;
void Check(bool value, const char* message) {
	++checks;
	if (!value) throw std::runtime_error(message);
}
NativeReturnIdentity Identity(bool two = false) {
	return {0x4000, 0x4000, 0x4000, 0x4004, true, true,
		two ? NativeReturnKind::TwoByteString : NativeReturnKind::OneByteString,
		two ? "Internal_allocateTwoByteString" : "Internal_allocateOneByteString", "dart:_internal"};
}
Profile MakeProfile() {
	Profile p{"synthetic", ARM64_REG_X27, ARM64_REG_X26, 16, 8, 8, {}, {}};
	p.wordReturnRegister = ARM64_REG_X0;
	p.dispatchRegister = ARM64_REG_X21;
	p.classIdShift = 8; p.classIdBits = 16;
	p.nullRegister = ARM64_REG_X22; p.nullClassId = 1;
	p.dispatchEntries.resize(16);
	p.dispatchEntries[7] = 0x3000; p.dispatchEntries[8] = 0x3010; p.dispatchEntries[3] = 0x3020;
	p.nativeReturnClasses = {{0x4000, {7, "allocate_one_byte_string"}}, {0x5000, {8, "allocate_two_byte_string"}}};
	p.poolHeapClass = [](int64_t index) -> std::optional<uint32_t> { return index == 3 ? std::optional<uint32_t>{3} : std::nullopt; };
	return p;
}
uint32_t Call(uint64_t site, uint64_t target) { return 0x94000000U | ((target - site) / 4 & 0x3ffffff); }
// Independently assembled ARM64: header load, class extraction, table load, BLR.
const std::vector<uint32_t> dispatch{0xb85ff001, 0xd3485c21, 0xf8617abe, 0xd63f03c0};
std::vector<uint8_t> Bytes(const std::vector<uint32_t>& words) {
	std::vector<uint8_t> out;
	for (const auto word : words) for (unsigned j = 0; j < 4; ++j) out.push_back(word >> (8 * j));
	return out;
}
ReceiverAnalysisResult Analyze(const std::vector<uint32_t>& prefix, const Profile& profile,
	const std::vector<StackInput>* inputs = nullptr) {
	auto words = prefix; words.insert(words.end(), dispatch.begin(), dispatch.end());
	const auto bytes = Bytes(words); csh handle = 0;
	if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK) throw std::runtime_error("decoder");
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_insn* raw = nullptr; const auto count = cs_disasm(handle, bytes.data(), bytes.size(), 0x1000, 0, &raw);
	Check(count == words.size(), "Fixture must decode completely");
	auto result = AnalyzeReceivers(raw, count, profile, {}, inputs);
	cs_free(raw, count); cs_close(&handle); return result;
}
}
int main() {
	try {
		Check(MatchNativeReturn(Identity(), 7, 8) == NativeReturnContract{7, "allocate_one_byte_string"}, "one-byte identity");
		Check(MatchNativeReturn(Identity(true), 7, 8) == NativeReturnContract{8, "allocate_two_byte_string"}, "two-byte identity");
		for (unsigned defect = 0; defect < 9; ++defect) {
			auto id = Identity();
			switch (defect) {
			case 0: id.isNative = false; break;
			case 1: id.ownsCode = false; break;
			case 2: id.recognized = NativeReturnKind::Unknown; break;
			case 3: id.nativeName = "Internal_allocateTwoByteString"; break;
			case 4: id.libraryUri = "package:fixture/main.dart"; break;
			case 5: id.entry += 2; break;
			case 6: id.codeEntry += 4; break;
			case 7: id.payload += 4; break;
			case 8: id.end = id.entry; break;
			}
			Check(!MatchNativeReturn(id, 7, 8), "Mismatched metadata must not select a contract");
		}
		Check(!MatchNativeReturn(Identity(), 7, 7), "String classes must be distinct");
		Check(!MatchNativeReturn(Identity(), 0, 8), "Missing class layout");
		Check(NativeReturnContracts({Identity(), Identity()}, 7, 8).size() == 1, "Duplicate compatible identities");
		Check(NativeReturnContracts({Identity(), Identity(true)}, 7, 8).empty(), "Conflicting aliases");
		auto invalid = Identity(); invalid.ownsCode = false;
		Check(NativeReturnContracts({invalid, Identity(), Identity()}, 7, 8).empty(), "Rejected entry cannot be revived");
		Check(NativeReturnContracts({Identity(), invalid, Identity()}, 7, 8).empty(), "Late conflicting alias");
		for (const auto target : {0x4000, 0x5000}) {
			const auto result = Analyze({Call(0x1000, target)}, MakeProfile());
			Check(result.resolutions.size() == 1, "Native returned class reaches dispatch");
			Check(result.resolutions.begin()->second.snapshotTarget == (target == 0x4000 ? 0x3000 : 0x3010), "Correct concrete class target");
		}
		Check(Analyze({Call(0x1000, 0x4000), 0xaa0203e0}, MakeProfile()).resolutions.empty(), "Overwrite kills result");
		Check(Analyze({Call(0x1000, 0x4000), Call(0x1004, 0x6000)}, MakeProfile()).resolutions.empty(), "Unknown call kills result");
		Check(Analyze({Call(0x1000, 0x6000)}, MakeProfile()).resolutions.empty(), "Unknown target has no contract");
		Check(Analyze({Call(0x1000, 0x4000), 0xd4000001}, MakeProfile()).resolutions.empty(), "Trap does not inherit a normal result");
		Check(Analyze({0xb4000082, Call(0x1004, 0x4000), 0x14000003, 0xd503201f, Call(0x1010, 0x5000)}, MakeProfile()).resolutions.empty(), "Different return classes do not survive a join");
		// Establish a real negative caller frame and spill an independent object.
		const std::vector<uint32_t> frame{0xa9bf79fd, 0xaa0f03fd, 0xd10081ef};
		auto spill = frame; spill.insert(spill.end(), {0xf9401760, 0xf81f83a0, Call(0x1014, 0x4000), 0xf85f83a0});
		Check(Analyze(spill, MakeProfile()).resolutions.empty(), "Return-only contract cannot preserve caller spill");
		auto input = frame; input.insert(input.end(), {Call(0x100c, 0x4000), 0xf9400ba0});
		const std::vector<StackInput> inputs{{0, "heap_class", 3, {}}};
		Check(Analyze(input, MakeProfile(), &inputs).resolutions.empty(), "Return-only contract cannot preserve input bindings");
		auto abi = MakeProfile(); abi.wordReturnRegister = ARM64_REG_INVALID;
		Check(Analyze({Call(0x1000, 0x4000)}, abi).resolutions.empty(), "Unconfigured return ABI");
		auto overlap = MakeProfile(); overlap.allocationReturns[0x4000] = 7;
		Check(Analyze({Call(0x1000, 0x4000)}, overlap).certificate.empty(), "Return-only entry cannot silently become an allocator effect");
		const auto caller = Bytes({0xa9bf79fd, 0xaa0f03fd, Call(0x1008, 0x4000), 0xaa1d03ef, 0xa8c179fd, 0xd65f03c0});
		Check(AnalyzeCallEffects({{0x1000, caller}}, MakeProfile()).certificates.empty(), "Return-only identity cannot admit a frame-safe callee");
		std::cout << checks << " native return checks passed\n";
	} catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
