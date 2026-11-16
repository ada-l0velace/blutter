#include "Arm64Decode.h"
#include "SavedAsyncReferences.h"
#include "SnapshotCodeAnalysis.h"
#include <iostream>
#include <limits>
#include <stdexcept>

using namespace SnapshotAnalysis;
namespace
{
unsigned checks = 0;
void Check(bool value, const char *why)
{
	++checks;
	if (!value)
		throw std::runtime_error(why);
}
constexpr uint64_t Start = 0x5000, Init = 0x11000, Await = 0x12000, Complete = 0x14000;
uint32_t Branch(uint64_t pc, uint64_t target, bool call = true)
{
	return (call ? 0x94000000U : 0x14000000U) | ((target - pc) / 4 & 0x3ffffff);
}
struct Fixture {
	Profile profile{};
	std::vector<uint32_t> words;
	FutureBindingsResult inputs;
	bool pointer = true, available = true;
	Fixture()
	{
		profile.wordReturnRegister = ARM64_REG_X0;
		profile.nullRegister = ARM64_REG_X22;
		profile.nullClassId = 1;
		profile.futureBindingAbi = {true, -8};
		profile.savedFrameAbi = {true, -8};
		profile.asyncContracts = {{Init, {AsyncOperation::Init, Init + 4}},
		                          {Await, {AsyncOperation::Await, Await + 4}},
		                          {Complete, {AsyncOperation::CompleteValue, Complete + 4}}};
		profile.describeSavedStackMap = [this](uint64_t payload, uint64_t site) {
			SavedStackMap map{payload, site};
			map.available = available;
			if (available) {
				map.spillSlots = 32;
				if (pointer)
					map.objects = {-16, -8};
			}
			return map;
		};
		words = {0xa9bf79fd, 0xaa0f03fd, 0xd10401ef, 0xf81f83b6, 0xaa1603e0};
		Call(Init);
		Call(Await);
	}
	void Call(uint64_t target)
	{
		words.push_back(Branch(Start + words.size() * 4, target));
	}
	SavedReferencesResult Run(std::vector<uint32_t> middle = {0xf81f03a0, 0xaa1603e0, 0, 0xf85f03a2})
	{
		const auto base = words.size();
		words.insert(words.end(), middle.begin(), middle.end());
		for (size_t n = base; n < words.size(); ++n)
			if (words[n] == 0)
				words[n] = Branch(Start + n * 4, Await);
		words.push_back(0xaa1603e0);
		words.push_back(Branch(Start + words.size() * 4, Complete, false));
		std::vector<uint8_t> bytes;
		for (auto w : words)
			for (unsigned n = 0; n < 4; ++n)
				bytes.push_back(w >> (n * 8));
		csh decoder;
		Check(cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &decoder) == CS_ERR_OK, "decoder opens");
		cs_option(decoder, CS_OPT_DETAIL, CS_OPT_ON);
		const auto [raw, count] = DecodeArm64Instructions(decoder, bytes.data(), bytes.size(), Start);
		Check(count == words.size(), "authored words decode");
		CompletionBody body{Start + words.size() * 4, true, true, {}};
		size_t remaining = 2000000;
		auto summary = AnalyzeCompletions(raw, count, profile, body, {Start}, {}, remaining);
		cs_free(raw, count);
		cs_close(&decoder);
		Check(summary.has_value(), "authored completion body");
		AwaitFutureBinding seed;
		seed.status = "conditional_delivery";
		seed.classId = 7;
		seed.value = "heap_class";
		seed.input.boundary = {AsyncOperation::Await, Start + 6 * 4, Start, Await, Start + 7 * 4};
		seed.input.body = body;
		inputs.bindings = {seed};
		return RestoreAsyncReferences(profile, inputs, {*summary}, {{Start, std::move(bytes)}}, {Start});
	}
};
} // namespace
int main()
{
	try {
		Fixture basic;
		auto result = basic.Run();
		Check(result.contexts.size() == 1, "one conditional seed");
		Check(result.contexts[0].status == "checked", "context reaches a fixed point");
		Check(result.contexts[0].observations.size() == 1, "saved reference restored after suspension");
		const auto &ref = result.contexts[0].observations[0];
		Check(ref.slot == -16 && ref.reg == 2 && ref.suspension == Start + 9 * 4,
		      "physical slot and continuation");
		Check(result.steps + result.remaining == 2000000, "separate bounded work");
		const auto text =
		    RestoredReferenceNote(result.contexts[0], ref, [](uint32_t) { return "Example\"\n"; });
		Check(text.find("conditional:") != std::string::npos &&
		          text.find("reference only") != std::string::npos,
		      "scope is visible");
		Check(text.find('\n') == std::string::npos && text.find("\\x0a") != std::string::npos,
		      "metadata is escaped");
		Fixture missing;
		missing.available = false;
		result = missing.Run();
		Check(result.contexts[0].observations.empty(), "missing GC map grants no restoration");
		Fixture unboxed;
		unboxed.pointer = false;
		result = unboxed.Run();
		Check(result.contexts[0].observations.empty(), "unboxed slot does not preserve a root");
		Fixture overwritten;
		result = overwritten.Run({0xf81f03a0, 0xf81f03a1, 0xaa1603e0, 0, 0xf85f03a2});
		Check(result.contexts[0].observations.empty(), "overwrite kills the saved reference");
		Fixture noAwait;
		result = noAwait.Run({0xf81f03a0, 0xf85f03a2});
		Check(result.contexts[0].observations.empty(), "ordinary spill is not a suspend proof");
		Fixture nativeStack;
		result = nativeStack.Run({0xf81f03a0, 0x910003e1, 0xaa1603e0, 0, 0xf85f03a2});
		Check(result.contexts[0].status == "native_stack_access" && result.contexts[0].observations.empty(),
		      "hardware SP does not receive a Dart frame preservation contract");
		Fixture unsupported;
		unsupported.profile.savedFrameAbi = {};
		result = unsupported.Run();
		Check(result.contexts.empty() && result.steps == 0, "unsupported ABI keeps the phase empty");
		Fixture invalid;
		invalid.profile.describeSavedStackMap = [](uint64_t p, uint64_t s) {
			return SavedStackMap{p, s, true, 32, {std::numeric_limits<int64_t>::min()}};
		};
		bool refused = false;
		try {
			invalid.Run();
		} catch (const std::runtime_error &) {
			refused = true;
		}
		Check(refused, "extreme object offsets are refused before arithmetic");
		Fixture large;
		std::vector<uint32_t> nops(2100, 0xd503201f);
		result = large.Run(nops);
		Check(result.contexts[0].status == "region_limit" && result.contexts[0].observations.empty(),
		      "unfinished region publishes no observations");
		std::cout << checks << " saved-reference checks passed\n";
	} catch (const std::exception &error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
}
