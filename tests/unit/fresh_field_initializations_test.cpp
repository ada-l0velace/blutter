#include "FreshFieldInitializations.h"
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
	Profile p{"authored", ARM64_REG_X27, ARM64_REG_X26, 16, 8, 32, {}, {}};
	AsyncFieldsResult fields;
	CapturedFieldsResult captures;
	std::set<uint64_t> entries;
	std::vector<uint32_t> words{
	    0xd28000c2, // mov x2, #6 (Smi length 3)
	    0x940003ff, // bl 0x2000
	    0xaa0003e2, // mov x2, x0 (fresh result)
	    0xf85f03a1, // ldur x1, [fp, #-16] (trusted captured seed)
	    0xb800f041, // stur w1, [x2, #15]
	    0xd65f03c0  // ret
	};
	Fixture()
	{
		p.allocationReturns = {{0x2000, 2}};
		p.arrayBodyContract = {0x2000, 2, 15, 4, 1};
		p.arrayLengthLayout = ArrayLengthLayout{2, 7, 4, 1};
		AsyncFieldContext c{0x1000, 0xe00, 0xf00, 0, 11, "await_delivery", "registers_lost", 1};
		c.accesses = {{0xf00, 0, 1, 4, 8, "read", "instance_slot", {}}};
		fields.contexts = {c};
		CapturedFieldContext capture{0, 0, "control_boundary", 4, {{0x100c, 0xfc0, 0x1004, 0x2000, -16, 1}}};
		captures.contexts = {capture};
	}
	void Object()
	{
		p.arrayBodyContract.clear();
		p.allocationReturns[0x2000] = 7;
		p.allocationBodyBounds = {{0x2000, {7, 31}}};
		words[4] = 0xb8007041;
		p.describeInstanceLayout = [](uint32_t cid) {
			InstanceLayout l;
			l.classId = cid;
			l.kind = "instance";
			l.header = 8;
			l.end = 32;
			l.tag = 1;
			l.slotBytes = 4;
			l.excluded = {16};
			l.unboxed = {24, 28};
			return l;
		};
	}
	FreshFieldsResult Run()
	{
		std::vector<uint8_t> code;
		for (auto word : words)
			for (unsigned b = 0; b < 4; ++b)
				code.push_back(word >> (8 * b));
		return DescribeFreshFieldWrites(p, fields, captures, {{0x1000, code}}, entries);
	}
	bool Matched()
	{
		const auto r = Run();
		return r.contexts.size() == 1 && r.contexts[0].write.has_value();
	}
};
} // namespace
int main()
{
	try {
		Fixture f;
		auto result = f.Run();
		Check(result.contexts[0].write && result.contexts[0].length == 3,
		      "bounded fresh array write linked to captured value");
		const auto &c = result.contexts[0];
		Check(c.write->index == 0 && c.write->offset == 16 && c.write->reg == 1 && c.write->base == 2,
		      "array element location and registers");
		Check(result.steps == c.steps + c.lengthSteps && result.remaining + result.steps == 200000,
		      "separate work includes length proof");
		Check(FreshFieldNote(f.fields, f.captures, c).find("first explicit write only") != std::string::npos,
		      "write-event scope excludes persistent heap facts");
		std::ostringstream out;
		WriteFreshFields(out, result);
		Check(out.str().find("conditional_first_write_only") != std::string::npos,
		      "structured scope serialized");
		f.Object();
		result = f.Run();
		Check(result.contexts[0].write && !result.contexts[0].write->index && result.layouts.size() == 1,
		      "boxed instance field needs matched class layout and bounds");
		f = Fixture{};
		f.words[0] = 0xd2800002;
		Check(!f.Matched(), "zero-length array cannot receive element zero");
		f = Fixture{};
		f.words[0] = 0xd28000e2;
		Check(!f.Matched(), "odd raw word is not a Smi length");
		f = Fixture{};
		f.words[0] = 0xaa0403e2;
		Check(!f.Matched(), "unknown length refused");
		f = Fixture{};
		f.words[4] = 0xb801c041;
		Check(!f.Matched(), "element beyond length refused");
		f = Fixture{};
		f.words[4] = 0xf800f041;
		Check(!f.Matched(), "wide store into compressed array refused");
		f = Fixture{};
		f.words[2] = 0xaa0403e2;
		Check(!f.Matched(), "unknown destination pointer is not the fresh allocation");
		f = Fixture{};
		f.words[2] = 0x2a0003e2;
		Check(!f.Matched(), "narrow copy loses full object identity");
		f = Fixture{};
		f.words[2] = 0xf81f03a0;
		Check(!f.Matched(), "even a local spill is an unsupported fresh-pointer escape in this subset");
		f = Fixture{};
		f.words[4] = 0xf8007042;
		Check(!f.Matched(), "storing a fresh pointer escapes it");
		f = Fixture{};
		f.words.insert(f.words.begin() + 4, 0xb8007085);
		Check(!f.Matched() && f.Run().contexts[0].status == "unproved_alias_write",
		      "untracked store may alias the new object");
		f = Fixture{};
		f.words.insert(f.words.begin() + 4, 0x94000001);
		Check(!f.Matched(), "no call crossed after allocation");
		f = Fixture{};
		f.entries = {0x1008};
		Check(!f.Matched(), "alternate allocation-return entry refused");
		f = Fixture{};
		f.entries = {0x1010};
		Check(!f.Matched(), "alternate write entry refused");
		f = Fixture{};
		f.words.insert(f.words.begin() + 4, 0x14000001);
		Check(!f.Matched(), "branch before write refused");
		f = Fixture{};
		f.words.insert(f.words.begin() + 4, 0xb800f044);
		Check(!f.Matched(), "prior explicit write to same element blocks initialization claim");
		f = Fixture{};
		f.words.insert(f.words.begin() + 4, 0xb8013044);
		Check(f.Matched(), "earlier write to distinct element does not initialize the selected element");
		f = Fixture{};
		f.words.insert(f.words.begin() + 4, 0x2a0403e1);
		Check(!f.Matched(), "narrow value overwrite kills captured identity");
		f = Fixture{};
		f.words.insert(f.words.begin() + 4, 64, 0xd503201f);
		Check(f.Run().contexts[0].status == "region_limit", "linear proof bounded");
		f = Fixture{};
		f.Object();
		f.words[4] = 0xb800f041;
		Check(!f.Matched(), "type-argument field excluded");
		f = Fixture{};
		f.Object();
		f.words[4] = 0xb8017041;
		Check(!f.Matched(), "unboxed field excluded");
		f = Fixture{};
		f.Object();
		f.p.allocationBodyBounds.clear();
		Check(!f.Matched(), "return class alone grants no fresh writable layout");
		f = Fixture{};
		f.Object();
		f.p.describeInstanceLayout = {};
		Check(!f.Matched(), "missing boxed layout refused");
		f = Fixture{};
		f.p.allocationResultRegister = ARM64_REG_INVALID;
		Check(f.Run().contexts.empty(), "unsupported result ABI grants no seed");
		f = Fixture{};
		f.captures.contexts.resize(4097, f.captures.contexts[0]);
		result = f.Run();
		Check(result.contexts.size() == 4096 && !result.complete, "context cap reported");
		f = Fixture{};
		f.words.insert(f.words.begin() + 4, 64, 0xd503201f);
		f.captures.contexts.resize(4096, f.captures.contexts[0]);
		result = f.Run();
		Check(!result.complete && result.remaining == 0 && result.steps == 200000,
		      "shared transfer budget reports incomplete work");
		f = Fixture{};
		f.p.arrayBodyContract[3] = 3;
		bool rejected = false;
		try {
			f.Run();
		} catch (const std::runtime_error &) {
			rejected = true;
		}
		Check(rejected, "contradictory mandatory array contract stays fatal");
		std::cout << checks << " fresh initialization checks passed\n";
	} catch (const std::exception &e) {
		std::cerr << e.what() << '\n';
		return 1;
	}
}
