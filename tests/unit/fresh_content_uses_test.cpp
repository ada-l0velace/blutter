#include "FreshContentUses.h"
#include "SnapshotCodeAnalysis.h"
#include <iostream>
#include <sstream>
#include <stdexcept>
using namespace SnapshotAnalysis;
namespace
{
int checks = 0;
void Check(bool condition, const char *message)
{
    ++checks;
    if (!condition)
	throw std::runtime_error(message);
}
uint32_t Branch(uint64_t from, uint64_t to, bool call = false)
{
    return (call ? 0x94000000 : 0x14000000) | ((to - from) / 4 & 0x3ffffff);
}
struct Fixture
{
    Profile p{"authored", ARM64_REG_X27, ARM64_REG_X26, 16, 8, 32, {}, {}};
    AsyncFieldsResult fields;
    CapturedFieldsResult captures;
    FreshFieldsResult fresh;
    std::set<uint64_t> entries;
    std::vector<uint32_t> words{0xb800f041, 0xaa0203e0, 0};
    bool role = true;
    Fixture()
    {
	p.callInputAbi = {true, 4, 8};
	p.arrayBodyContract = {0x2000, 2, 15, 4, 1};
	p.asyncContracts[0x3000] = {AsyncOperation::CompleteValue, 0x3004};
	p.allocationReturns[0x2500] = 3;
	p.allocationBodyBounds[0x2500] = {7, 15};
	p.preservedCallRegisters[0x2500] = 1U << 2;
	p.freshContentAllocators.insert(0x2500);
	AsyncFieldContext field{0x1000, 0xe00, 0xf00, 0, 11, "await_delivery", "registers_lost", 1};
	field.accesses = {{0xf00, 0, 1, 4, 8, "read", "instance_slot", {}}};
	fields.contexts = {field};
	captures.contexts = {
	    {0, 0, "control_boundary", 4, {{0xff0, 0xfc0, 0xfe0, 0x2000, -16, 1}}}};
	FreshFieldContext f{0, 0};
	f.classId = 2;
	f.kind = "array_element";
	f.status = "matched_initialization";
	f.length = 3;
	f.write = FreshFieldWrite{0x1000, 2, 1, 4, 16, 0};
	fresh.contexts = {f};
    }
    FreshContentResult Run()
    {
	words.back() = Branch(0x1000 + 4 * (words.size() - 1), 0x3000);
	std::vector<uint8_t> code;
	for (auto w : words)
	    for (unsigned b = 0; b < 4; ++b)
		code.push_back(w >> (8 * b));
	const uint64_t site = 0x1000 + (words.size() - 1) * 4;
	std::vector<CallInputOrigin> origins{
	    {site, 0x1000, role ? "completion_operand" : "register_observation", {}, 0, {}, {}}};
	Edge edge{};
	edge.site = site;
	edge.source = 0x1000;
	edge.target = 0x3000;
	edge.kind = "jump";
	return DescribeFreshContentUses(p, fields, captures, fresh, {{0x1000, code}}, entries,
	                                origins, {edge}, {});
    }
    bool Matched()
    {
	const auto r = Run();
	return !r.contexts.empty() && r.contexts[0].status == "matched_container_input";
    }
};
} // namespace
int main()
{
    try
    {
	Fixture f;
	auto r = f.Run();
	Check(f.Matched(), "role-proven container at async completion");
	Check(r.contexts[0].inputs == std::vector<size_t>{0}, "input identity retained");
	Check(r.steps == 2 && r.remaining + r.steps == 200000, "independent work accounting");
	std::ostringstream out;
	WriteFreshContentUses(out, f.p, r);
	Check(out.str().find("conditional_container_contents_at_transfer") != std::string::npos,
	      "scope serialized");
	f.role = false;
	r = f.Run();
	Check(r.contexts[0].status == "consumer_role_unproved" && r.contexts[0].transfer &&
	          r.contexts[0].inputs.empty(),
	      "survival grants no parameter role");
	f = Fixture{};
	f.words.insert(f.words.begin() + 1, 0xb800f044);
	Check(!f.Matched(), "selected element overwritten");
	f = Fixture{};
	f.words.insert(f.words.begin() + 1, 0xb8013044);
	Check(f.Matched(), "distinct in-bounds element write permitted");
	f = Fixture{};
	f.words.insert(f.words.begin() + 1, 0xb8007084);
	Check(!f.Matched(), "untracked-address store may alias selected contents");
	f = Fixture{};
	f.words.insert(f.words.begin() + 1, 0xb8007082);
	Check(!f.Matched(), "container published to heap stops lifetime");
	f = Fixture{};
	f.words.insert(f.words.begin() + 1, 0xb801b044);
	Check(!f.Matched(), "out-of-bounds neighboring write refused");
	f = Fixture{};
	f.words = {0xb800f041, 0xb4000043, 0xb8013044, 0xaa0203e0, 0};
	Check(f.Matched(), "forward diamond retains common selected contents");
	f.words[2] = 0xb800f044;
	Check(!f.Matched(), "overwrite on either branch invalidates claim");
	f.words[2] = 0xaa0403e2;
	Check(!f.Matched(), "object identity must reach consumer on all paths");
	f = Fixture{};
	f.words = {0xb800f041, 0xb4000063, Branch(0x1008, 0x2500, true), 0xf8007003, 0xaa0203e0, 0};
	Check(f.Matched(), "reviewed allocator and write to disjoint new allocation");
	f.p.freshContentAllocators.clear();
	Check(!f.Matched(), "preserved registers and fresh result alone grant no heap effect");
	f.p.freshContentAllocators.insert(0x2500);
	f.words[3] = 0xf8007083;
	Check(!f.Matched(), "allocator does not authorize an unrelated store address");
	f = Fixture{};
	f.words[1] = 0x2a0203e0;
	Check(!f.Matched(), "narrow container copy is not full identity");
	f = Fixture{};
	f.entries = {0x1004};
	Check(!f.Matched(), "external entry bypasses initialized state");
	f = Fixture{};
	f.words = {0xb800f041, 0xb4ffffe3, 0xaa0203e0, 0};
	Check(!f.Matched(), "backward branch is outside bounded DAG subset");
	f = Fixture{};
	f.words.insert(f.words.begin() + 1, 128, 0xd503201f);
	Check(f.Run().contexts[0].status == "region_limit", "region limit refuses publication");
	f = Fixture{};
	f.words[0] = 0xb8013041;
	bool threw = false;
	try
	{
	    f.Run();
	}
	catch (const std::runtime_error &)
	{
	    threw = true;
	}
	Check(threw, "contradictory mandatory original bytes remain errors");
	f = Fixture{};
	f.fresh.contexts.resize(4100, f.fresh.contexts[0]);
	r = f.Run();
	Check(r.contexts.size() == 4096 && !r.complete, "context bound explicit");
	std::cout << checks << " selected-content checks passed\n";
    }
    catch (const std::exception &e)
    {
	std::cerr << e.what() << '\n';
	return 1;
    }
}
