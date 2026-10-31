#include "Arm64Ir.h"
#include <array>
#include <bit>
#include <iostream>
#include <memory>
#include <stdexcept>
using namespace SnapshotAnalysis;
namespace {
unsigned checks = 0;
void Check(bool ok, const char* reason) { ++checks; if (!ok) throw std::runtime_error(reason); }
struct Decoder {
	csh handle = 0;
	Decoder() {
		if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK || cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
			throw std::runtime_error("Decoder unavailable");
	}
	~Decoder() { cs_close(&handle); }
};
std::shared_ptr<cs_insn> Decode(csh handle, uint32_t word, uint64_t address = 0x1000) {
	std::array<uint8_t,4> bytes{};
	for (unsigned n=0; n<4; ++n) bytes[n]=static_cast<uint8_t>(word >> (n*8));
	cs_insn* raw = nullptr; const auto count = cs_disasm(handle, bytes.data(), 4, address, 0, &raw);
	if (count != 1) throw std::runtime_error("Invalid authored instruction");
	return {raw, [](cs_insn* p) { cs_free(p,1); }};
}
}
int main() {
	try {
		Decoder decoder;
		for (auto bits : {32U,64U}) {
			const auto mask = bits == 64 ? UINT64_MAX : uint64_t{UINT32_MAX};
			for (auto left : {uint64_t{0},uint64_t{1},mask,mask >> 1,(mask >> 1)+1})
			for (auto right : {uint64_t{0},uint64_t{1},mask,mask >> 1,(mask >> 1)+1}) {
				const auto cmp = Decode(decoder.handle, bits == 64 ? 0xeb0900ff : 0x6b0900ff);
				const auto read = [&](NativeIr::RegisterView r) -> std::optional<uint64_t> { return r.id == 7 ? left : r.id == 9 ? std::optional<uint64_t>{right} : std::nullopt; };
				const auto sl = bits == 64 ? std::bit_cast<int64_t>(left) : int64_t{std::bit_cast<int32_t>(static_cast<uint32_t>(left))};
				const auto sr = bits == 64 ? std::bit_cast<int64_t>(right) : int64_t{std::bit_cast<int32_t>(static_cast<uint32_t>(right))};
				const auto difference = (left-right)&mask;
				const bool n = difference & (uint64_t{1} << (bits-1));
				const bool v = bits == 32 ? sl-sr < INT32_MIN || sl-sr > INT32_MAX :
					(sr > 0 ? sl < INT64_MIN+sr : sr < 0 && sl > INT64_MAX+sr);
				const std::array expected{left==right,left!=right,left>=right,left<right,n,!n,v,!v,left>right,left<=right,sl>=sr,sl<sr,sl>sr,sl<=sr};
				for (unsigned cc=0;cc<14;++cc) {
					const auto branch=Decode(decoder.handle,0x54000080|cc,0x1004);
					Check(EvaluateArm64Condition(*branch,*cmp,read)==expected[cc],"Concrete comparison disagrees with integer reference");
				}
			}
		}
		for (auto word : {0x93417d27U,0x937f7927U,0x13013d27U,0x131f3927U}) {
			const auto ins=Decode(decoder.handle,word); const auto ir=LowerArm64(*ins);
			Check(ir && std::holds_alternative<NativeIr::ExtractSigned>(ir->operation),"Signed field was not normalized");
			Check(NativeIr::Evaluate(*ir,[](auto)->std::optional<uint64_t>{return 0;})==0,"Signed zero changed");
		}
		const auto extract=LowerArm64(*Decode(decoder.handle,0x93417d27));
		Check(NativeIr::Evaluate(*extract,[](auto)->std::optional<uint64_t>{return 4;})==2,"Tagged length did not untag");
		Check(NativeIr::Evaluate(*extract,[](auto)->std::optional<uint64_t>{return UINT64_MAX;})==UINT64_MAX,"Signed extraction lost sign extension");
		Check(!NativeIr::Evaluate(*extract),"Unknown operand acquired a value");
		const auto cmp=Decode(decoder.handle,0xeb8904ff); // CMP X7,X9,ASR #1.
		const auto eq=Decode(decoder.handle,0x54000080,0x1004);
		Check(EvaluateArm64Condition(*eq,*cmp,[](auto)->std::optional<uint64_t>{return 0;} )==true,"Shifted boxing equality failed");
		Check(!EvaluateArm64Condition(*eq,*cmp,{}),"Absent word reader accepted");
		Check(!EvaluateArm64Condition(*Decode(decoder.handle,0x54000080,0x1008),*cmp,[](auto)->std::optional<uint64_t>{return 0;}),"Nonadjacent comparison accepted");
		std::cout<<checks<<" entry-predicate checks passed\n";
	} catch (const std::exception& e) { std::cerr<<e.what()<<'\n';return 1; }
}
