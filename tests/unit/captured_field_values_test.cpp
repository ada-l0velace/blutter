#include "CapturedFieldValues.h"
#include "SnapshotCodeAnalysis.h"
#include <iostream>
#include <sstream>
#include <stdexcept>

using namespace SnapshotAnalysis;
namespace
{
int checks = 0;
void Check(bool yes, const char *message)
{
	++checks;
	if (!yes)
		throw std::runtime_error(message);
}
struct Fixture {
	Profile profile{"authored", ARM64_REG_X27, ARM64_REG_X26, 16, 8, 32, {}, {}};
	AsyncFieldsResult fields;
	SavedReferencesResult saved;
	std::vector<uint32_t> words{
	    0xb8407001, // ldur w1, [x0, #7]
	    0x8b1c8021, // add x1, x1, x28, lsl #32
	    0xf81f03a1, // stur x1, [fp, #-16]
	    0x940003fd, // bl 0x2000
	    0xf85f03a3, // ldur x3, [fp, #-16]
	    0xd65f03c0  // ret
	};
	std::set<uint64_t> entries;
	bool mapAvailable = true, object = true, exactSp = true;
	int64_t sp = -128;
	unsigned spillSlots = 16;
	std::optional<uint32_t> registerSlots;
	std::optional<uint64_t> missingPoint;
	Fixture()
	{
		profile.savedFrameAbi = {true, -8};
		profile.futureBindingAbi = {true, -8};
		profile.heapBitsRegister = ARM64_REG_X28;
		profile.allocationReturns = {{0x2000, 7}};
		fields.supported = true;
		InstanceLayout layout;
		layout.classId = 7;
		layout.kind = "instance";
		layout.tag = 1;
		layout.slotBytes = 4;
		fields.layouts[7] = layout;
		AsyncFieldContext c{0x1000, 0xffc, 0x1000, 0, 7, "await_delivery", "registers_lost", 1};
		c.accesses = {{0x1000, 0, 1, 4, 8, "read", "instance_slot", {}}};
		fields.contexts = {c};
		saved.frames = {{0x1000, "matched_async_frame", 6, {}}};
	}
	CapturedFieldsResult Run()
	{
		std::vector<uint8_t> code;
		for (size_t n = 0; n < words.size(); ++n) {
			auto word = words[n];
			if ((word & 0xfc000000) == 0x94000000)
				word = 0x94000000 + ((0x2000 - 0x1000 - n * 4) / 4);
			for (unsigned k = 0; k < 4; ++k)
				code.push_back(word >> (k * 8));
		}
		saved.frames[0].points.clear();
		for (size_t n = 0; n < words.size(); ++n)
			if (missingPoint != 0x1000 + n * 4)
				saved.frames[0].points.push_back({0x1000 + n * 4, sp, exactSp});
		profile.describeSavedStackMap = [&](uint64_t payload, uint64_t site) {
			return SavedStackMap{payload,
			                     site,
			                     mapAvailable,
			                     mapAvailable ? spillSlots : 0U,
			                     mapAvailable && object ? std::vector<int64_t>{-16} : std::vector<int64_t>{},
			                     mapAvailable ? registerSlots : std::nullopt};
		};
		return PreserveCapturedFields(profile, fields, saved, {{0x1000, code}}, entries);
	}
};
} // namespace
int main()
{
	try {
		Fixture f;
		auto r = f.Run();
		Check(r.contexts.size() == 1 && r.contexts[0].reloads.size() == 1,
		      "saved tagged value survives reviewed allocator");
		const auto &v = r.contexts[0].reloads[0];
		Check(v.site == 0x1010 && v.reg == 3 && v.slot == -16 && v.store == 0x1008 && v.call == 0x100c &&
		          v.target == 0x2000,
		      "complete reload witness");
		Check(r.steps == 4 && r.remaining == 199996 && r.maps.size() == 1 && r.complete,
		      "independent work and map cache");
		const auto text = CapturedFieldNote(f.fields, r.contexts[0], v);
		Check(text.find("current field contents/type unknown") != std::string::npos &&
		          text.find("conditional:") != std::string::npos,
		      "no field type or stability claim");
		std::ostringstream out;
		WriteCapturedFields(out, r);
		Check(out.str().find("conditional_captured_value_only") != std::string::npos,
		      "structured scope retained");
		f.mapAvailable = false;
		Check(f.Run().contexts[0].reloads.empty() && f.Run().contexts[0].status == "missing_stack_map",
		      "missing GC map refused");
		f = Fixture{};
		f.object = false;
		Check(f.Run().contexts[0].reloads.empty(), "unboxed spill is not a root");
		f = Fixture{};
		f.object = false;
		f.spillSlots = 0;
		f.registerSlots = 0;
		Check(f.Run().contexts[0].reloads.size() == 1, "full map admits the VM tagged gap below spills");
		f.registerSlots.reset();
		Check(f.Run().contexts[0].reloads.empty(), "missing map extent cannot grant implicit roots");
		f.registerSlots = 1;
		Check(f.Run().contexts[0].reloads.empty(),
		      "saved-register area needs additional bounds, not guessed roots");
		f.registerSlots = 0;
		f.spillSlots = 2;
		Check(f.Run().contexts[0].reloads.empty(),
		      "unmarked explicit spill stays unboxed even with a tagged gap");
		f = Fixture{};
		f.saved.frames[0].status = "frame_address_escapes";
		Check(f.Run().contexts[0].status == "unproved_owned_frame" && f.Run().steps == 0,
		      "escaped frame refused");
		f = Fixture{};
		f.saved.frames.clear();
		// Run constructs points in the fixture frame, so test a missing frame directly.
		Check(PreserveCapturedFields(f.profile, f.fields, f.saved, {}, {}).contexts[0].reloads.empty(),
		      "missing ownership certificate refused");
		for (auto word : {0x381f13a2U, 0xb81f43a2U, 0xf81f03a2U, 0x3c9f03a0U}) {
			f = Fixture{};
			f.words.insert(f.words.begin() + 3, word);
			Check(f.Run().contexts[0].reloads.empty(),
			      "overlapping byte/word/full/SIMD store kills saved definition");
		}
		f = Fixture{};
		f.words.insert(f.words.begin() + 4, 0xf81f03a2);
		Check(f.Run().contexts[0].reloads.empty(), "post-call overwrite refused");
		f = Fixture{};
		f.words[2] = 0xb81f03a1;
		Check(f.Run().contexts[0].reloads.empty(), "compressed-only spill refused");
		f = Fixture{};
		f.words[1] = 0xd503201f;
		Check(f.Run().contexts[0].status == "unproved_reconstruction", "missing full Dart value refused");
		f = Fixture{};
		f.profile.heapBitsRegister = ARM64_REG_INVALID;
		Check(f.Run().contexts[0].reloads.empty(), "unknown heap-bits ABI refused");
		f = Fixture{};
		f.entries = {0x1004};
		Check(f.Run().contexts[0].reloads.empty(), "alternate entry during reconstruction refused");
		for (auto pc : {0x1008U, 0x100cU, 0x1010U}) {
			f = Fixture{};
			f.entries = {pc};
			Check(f.Run().contexts[0].reloads.empty(), "alternate entry stops linear proof");
		}
		f = Fixture{};
		f.profile.allocationReturns.clear();
		f.profile.nativeReturnClasses = {{0x2000, {7, "authored_result_only"}}};
		Check(f.Run().contexts[0].status == "unmatched_call",
		      "result-only native contract is not frame preservation");
		f = Fixture{};
		f.words[3] = 0xd63f0080;
		Check(f.Run().contexts[0].reloads.empty(), "indirect call refused");
		f = Fixture{};
		f.words.insert(f.words.begin() + 3, 0x14000001);
		Check(f.Run().contexts[0].reloads.empty(), "branch boundary refused");
		f = Fixture{};
		f.missingPoint = 0x100c;
		Check(f.Run().contexts[0].status == "unproved_active_frame", "missing active frame refused");
		f = Fixture{};
		f.sp = -8;
		Check(f.Run().contexts[0].reloads.empty(), "inactive local refused");
		f = Fixture{};
		f.words.insert(f.words.begin() + 3, 0xf90001e2);
		f.sp = -16;
		Check(f.Run().contexts[0].reloads.empty(), "Dart SP alias overwrites FP local");
		f = Fixture{};
		f.words.insert(f.words.begin() + 3, 0xf90001e2);
		f.exactSp = false;
		Check(f.Run().contexts[0].reloads.empty(), "inexact SP write invalidates locals");
		f = Fixture{};
		f.words.insert(f.words.begin() + 2, 0x2a0203e1);
		Check(f.Run().contexts[0].reloads.empty(), "narrow register overwrite kills Dart value");
		f = Fixture{};
		f.words.insert(f.words.begin() + 2, 0xaa0103e4);
		f.words[3] = 0xf81f03a4;
		Check(f.Run().contexts[0].reloads.size() == 1, "full register copies accepted");
		f = Fixture{};
		f.words.insert(f.words.begin() + 4, 0x94000000);
		Check(f.Run().contexts[0].status == "second_call" && f.Run().contexts[0].reloads.empty(),
		      "one allocation boundary only");
		f = Fixture{};
		f.words.insert(f.words.begin() + 3, 64, 0xd503201f);
		Check(f.Run().contexts[0].status == "region_limit", "bounded linear region");
		f = Fixture{};
		f.fields.contexts.resize(4097, f.fields.contexts[0]);
		r = f.Run();
		Check(!r.complete && r.contexts.size() == 4096, "context cap reported");
		f = Fixture{};
		f.words.insert(f.words.begin() + 3, 64, 0xd503201f);
		f.fields.contexts.resize(4096, f.fields.contexts[0]);
		r = f.Run();
		Check(!r.complete && !r.remaining && r.steps == 200000 && r.contexts.back().status == "step_limit",
		      "shared phase budget reported");
		f = Fixture{};
		f.fields.supported = false;
		Check(f.Run().contexts.empty(), "unsupported layout adapter grants no value");
		f = Fixture{};
		f.fields.contexts[0].accesses[0].access = "write";
		Check(f.Run().contexts.empty(), "a field store is not a captured read");
		f = Fixture{};
		f.fields.contexts[0].accesses[0].reg = 2;
		bool rejected = false;
		try {
			f.Run();
		} catch (const std::runtime_error &) {
			rejected = true;
		}
		Check(rejected, "contradictory byte evidence stays fatal");
		std::cout << checks << " captured field checks passed\n";
	} catch (const std::exception &error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
}
