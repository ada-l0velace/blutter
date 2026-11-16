#include "CalleeEntryReads.h"
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
std::vector<uint8_t> Bytes(const std::vector<uint32_t> &words)
{
    std::vector<uint8_t> code;
    for (auto w : words)
	for (unsigned n = 0; n < 4; ++n)
	    code.push_back(w >> (8 * n));
    return code;
}
struct Fixture
{
    Profile p{"authored", ARM64_REG_X27, ARM64_REG_X26, 16, 8, 32, {}, {}};
    std::vector<uint32_t> words{0xa9bf79fd, 0xaa0f03fd, 0xd10081ef, 0xf9400ba1, 0xd65f03c0};
    Fixture() { p.callInputAbi = {true, 4, 8}; }
    CalleeEntryContract Run(size_t budget = 200000)
    {
	return ProveCalleeEntryReads(0x2000, Bytes(words), p, budget);
    }
};
} // namespace
int main()
{
    try
    {
	// Authored: save FP/LR on Dart SP, establish FP, reserve frame, load FP+16.
	Fixture f;
	const auto frame = f.words[0];
	auto r = f.Run();
	Check(r.reads.size() == 1 && r.reads[0].offset == 0, "derived FP+16 is entry SP+0");
	Check(r.reads[0].site == 0x200c && r.reads[0].reg == 1, "read location and destination");
	Check(r.stop == "call_or_return" && r.prefix.size() == 4, "return excluded from prefix");
	Check(r.decoded == 5 && r.steps == 5, "decode and prefix work charged");
	f.words = {0xf94001e2, 0xd65f03c0};
	Check(f.Run().reads[0].offset == 0, "frameless incoming read");
	f.words = {0xb94001e2, 0xd65f03c0};
	Check(f.Run().reads.empty(), "narrow read grants no pointer role");
	f.words = {0xf90001e2, 0xf94001e2, 0xd65f03c0};
	Check(f.Run().reads.empty(), "incoming overwrite blocks subsequent read");
	f.words = {0xf94001e2, 0xf90001e3, 0xd65f03c0};
	Check(f.Run().reads.size() == 1, "earlier read survives later incoming overwrite");
	f.words = {0xf9000082, 0xf94001e2, 0xd65f03c0};
	Check(f.Run().reads.empty(), "unknown-address store blocks read");
	f.words = {0x94000040, 0xf94001e2, 0xd65f03c0};
	Check(f.Run().reads.empty(), "ordinary call blocks entry prefix");
	f.words = {0x14000001, 0xf94001e2, 0xd65f03c0};
	Check(f.Run().reads.empty(), "unproved branch blocks entry prefix");
	f.words = {0xaa0f03e3, 0xa9400863, 0xd65f03c0};
	r = f.Run();
	Check(r.reads.size() == 2 && r.reads[0].offset == 0 && r.reads[1].offset == 8,
	      "aliased LDP uses original base twice");
	Check(r.reads[0].reg == 3 && r.reads[1].reg == 2, "LDP physical destinations");
	f.words = {0xa94079e1, 0xd65f03c0};
	Check(f.Run().reads.size() == 1, "LR is not a parameter-register role");
	f.words = {0xa94075e1, 0xd65f03c0};
	Check(f.Run().reads.empty(), "invalid FP destination refuses whole pair");
	f.words = {0xa94005e1, 0xd65f03c0};
	bool duplicateThrew = false;
	try
	{
	    f.Run();
	}
	catch (const std::runtime_error &)
	{
	    duplicateThrew = true;
	}
	Check(duplicateThrew, "undecodable duplicate LDP remains an error");
	f.words = {0xaa0f03e3, 0x2a0303e3, 0xf9400061, 0xd65f03c0};
	Check(f.Run().reads.empty(), "narrowing destroys stack coordinate");
	f.words = {0xd10041e3, 0xf9400861, 0xd65f03c0};
	Check(f.Run().reads.size() == 1, "arithmetic stack alias independently derived");
	f.words = {frame, 0xaa0f03fd, 0xd10081ef, 0xf90001e2, 0xf9400ba1, 0xd65f03c0};
	Check(f.Run().reads.size() == 1, "store confined to own reserved frame");
	f.words = {0xf94001e2, 0xd65f03c0};
	Check(f.Run(1).reads.empty() && f.Run(1).stop == "step_limit",
	      "insufficient decode budget");
	Check(f.Run(3).reads.empty(), "prefix budget exhaustion withdraws reads");
	f.words.assign(65, 0xd503201f);
	f.words.push_back(0xf94001e1);
	Check(f.Run().stop == "prefix_limit" && f.Run().reads.empty(), "prefix bound explicit");
	f.words.assign(15, 0xf94001e1);
	f.words.push_back(0xa94009e1);
	f.words.push_back(0xd65f03c0);
	Check(f.Run().reads.size() == 16 && f.Run().stop == "read_limit",
	      "pair cannot exceed exact read limit");
	f.words = {0xffffffff};
	bool threw = false;
	try
	{
	    f.Run();
	}
	catch (const std::runtime_error &)
	{
	    threw = true;
	}
	Check(threw, "undecodable required bytes remain an error");
	f = Fixture{};
	f.p.callInputAbi.supported = false;
	Check(f.Run().stop == "unsupported_abi", "unsupported ABI grants no role");
	f = Fixture{};
	f.words = {0xf94001e1, 0xd65f03c0};
	auto code = Bytes(f.words);
	f.p.readInputCode = [code](uint64_t, size_t) { return code; };
	FreshContentResult contents;
	FreshContentContext c{};
	c.transfer = 0x1004;
	contents.contexts.push_back(c);
	contents.stackLocations[0] = {0};
	Edge e{};
	e.site = 0x1004;
	e.kind = "call";
	e.target = 0x2000;
	auto linked = LinkContainerEntryReads(f.p, contents, {{0x2000, 0x2008}}, {e});
	Check(linked.links.size() == 1 && linked.contracts.size() == 1,
	      "direct target and matching handoff joined");
	Check(linked.steps == 4 && linked.bytes == 8, "link work accounting");
	contents.stackLocations[0] = {8};
	Check(LinkContainerEntryReads(f.p, contents, {{0x2000, 0x2008}}, {e}).links.empty(),
	      "different incoming word is not a link");
	contents.stackLocations[0] = {0};
	e.target = 0x2004;
	Check(LinkContainerEntryReads(f.p, contents, {{0x2000, 0x2008}}, {e}).links.empty(),
	      "interior target not treated as function entry");
	e.target = 0x2000;
	e.kind = "jump";
	Check(LinkContainerEntryReads(f.p, contents, {{0x2000, 0x2008}}, {e}).links.empty(),
	      "tail transfer deliberately excluded");
	e.kind = "call";
	contents.contexts.push_back(c);
	contents.stackLocations[1] = {0};
	linked = LinkContainerEntryReads(f.p, contents, {{0x2000, 0x2008}}, {e});
	Check(linked.links.size() == 2 && linked.contracts.size() == 1,
	      "multiple contexts reuse byte-checked callee contract");
	std::ostringstream out;
	WriteCalleeEntryReads(out, linked);
	Check(out.str().find("conditional_callee_entry_read") != std::string::npos,
	      "physical read scope serialized");
	f.p.readInputCode = [](uint64_t, size_t) { return std::vector<uint8_t>{}; };
	Check(LinkContainerEntryReads(f.p, contents, {{0x2000, 0x2008}}, {e}).links.empty(),
	      "missing optional bytes grant no role");
	std::cout << checks << " callee-entry checks passed\n";
    }
    catch (const std::exception &e)
    {
	std::cerr << e.what() << '\n';
	return 1;
    }
}
