#pragma once
#include "Arm64Decode.h"
#include "SavedAsyncReferences.h"
#include "SnapshotCodeAnalysis.h"
#include <stdexcept>

namespace AsyncReferenceTests
{
using namespace SnapshotAnalysis;
constexpr uint64_t Start = 0x5000, Init = 0x11000, Await = 0x12000, Complete = 0x14000;
constexpr uint64_t Resume = Start + 28;
inline uint32_t Branch(uint64_t pc, uint64_t target, bool call = true)
{
    return (call ? 0x94000000U : 0x14000000U) | ((target - pc) / 4 & 0x3ffffff);
}
inline uint32_t ZeroBranch(uint64_t pc, uint64_t target)
{
    return 0xb4000001U | (((target - pc) / 4 & 0x7ffff) << 5);
}
struct Fixture
{
    Profile p{};
    FutureBindingsResult bindings;
    std::vector<CompletionSummary> summaries;
    std::map<uint64_t, std::vector<uint8_t>> bytes;
    SavedReferencesResult old;
    bool available = true, pointer = true;
    Fixture()
    {
	p.wordReturnRegister = ARM64_REG_X0;
	p.nullRegister = ARM64_REG_X22;
	p.nullClassId = 1;
	p.futureBindingAbi = {true, -8};
	p.savedFrameAbi = {true, -8};
	p.asyncContracts = {{Init, {AsyncOperation::Init, Init + 4}},
	                    {Await, {AsyncOperation::Await, Await + 4}},
	                    {Complete, {AsyncOperation::CompleteValue, Complete + 4}}};
	p.describeSavedStackMap = [this](uint64_t payload, uint64_t site)
	{
	    SavedStackMap m{payload, site};
	    m.available = available;
	    if (available)
	    {
		m.spillSlots = 32;
		if (pointer)
		    m.objects = {-16, -8};
	    }
	    return m;
	};
    }
    JoinedReferencesResult Run(const std::vector<uint32_t> &middle)
    {
	std::vector<uint32_t> words{0xa9bf79fd,
	                            0xaa0f03fd,
	                            0xd10401ef,
	                            0xf81f83b6,
	                            0xaa1603e0,
	                            Branch(Start + 20, Init),
	                            Branch(Start + 24, Await)};
	words.insert(words.end(), middle.begin(), middle.end());
	for (size_t n = 7; n < words.size(); ++n)
	    if (!words[n])
		words[n] = Branch(Start + n * 4, Await);
	words.push_back(0xaa1603e0);
	words.push_back(Branch(Start + words.size() * 4, Complete, false));
	std::vector<uint8_t> code;
	for (auto word : words)
	    for (unsigned b = 0; b < 4; ++b)
		code.push_back(word >> (b * 8));
	csh decoder;
	if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &decoder) != CS_ERR_OK)
	    throw std::runtime_error("Authored decoder failed");
	cs_option(decoder, CS_OPT_DETAIL, CS_OPT_ON);
	const auto [raw, count] = DecodeArm64Instructions(decoder, code.data(), code.size(), Start);
	CompletionBody body{Start + code.size(), true, true, {}};
	size_t remaining = 2000000;
	auto summary = AnalyzeCompletions(raw, count, p, body, {Start}, {}, remaining);
	cs_free(raw, count);
	cs_close(&decoder);
	if (!summary)
	    throw std::runtime_error("Authored completion body failed");
	AwaitFutureBinding seed;
	seed.status = "conditional_delivery";
	seed.classId = 7;
	seed.value = "heap_class";
	seed.input.boundary = {AsyncOperation::Await, Start + 24, Start, Await, Resume};
	seed.input.body = body;
	bindings.bindings = {seed};
	summaries = {*summary};
	bytes = {{Start, std::move(code)}};
	old = RestoreAsyncReferences(p, bindings, summaries, bytes, {Start});
	return RestoreJoinedReferences(p, bindings, old, bytes, {Start});
    }
};
} // namespace AsyncReferenceTests
