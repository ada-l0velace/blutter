#include "../fixtures/async_reference_fixture.h"
#include <iostream>
#include <sstream>

using namespace AsyncReferenceTests;
namespace
{
int checks = 0;
void Check(bool value, const char *why)
{
    ++checks;
    if (!value)
	throw std::runtime_error(why);
}
size_t Count(const JoinedReferencesResult &r)
{
    size_t n = 0;
    for (const auto &c : r.contexts)
	n += c.observations.size();
    return n;
}
std::vector<uint32_t> Optional()
{
    return {0xf81f03a0, ZeroBranch(Resume + 4, Resume + 16), 0xaa1603e0, 0, 0xf85f03a2};
}
} // namespace
int main()
{
    try
    {
	Fixture f;
	auto r = f.Run(Optional());
	Check(r.contexts.size() == 1 && r.contexts[0].status == "checked",
	      "checked nonnull parent");
	Check(Count(r) == 1, "optional suspension join publishes one reference");
	Check(f.old.contexts[0].observations.empty(), "legacy certificate remains unchanged");
	const auto &o = r.contexts[0].observations[0];
	Check(o.site == Resume + 16 && o.store == Resume && o.slot == -16 && o.reg == 2,
	      "exact reload and reaching save");
	Check(o.lastSuspensions == std::set<uint64_t>{0, Resume + 12},
	      "no-extra-await is a distinct alternative");
	Check(r.steps + r.remaining == 200000 && r.complete, "separate bounded work");
	Check(r.bytes == f.bytes.at(Start).size(), "source decoding accounting");
	auto text = JoinedReferenceNote(r.contexts[0], o);
	Check(text.find("no additional await") != std::string::npos &&
	          text.find("reference only") != std::string::npos,
	      "scope and alternatives visible");
	std::ostringstream out;
	WriteJoinedReferences(out, r);
	Check(out.str().find("null,") != std::string::npos, "JSON no-await is null, not unknown");
	Fixture ordinary;
	r = ordinary.Run({0xf81f03a0, 0xf85f03a2});
	Check(Count(r) == 0, "ordinary spill alone is not a joined async certificate");
	Fixture single;
	r = single.Run({0xf81f03a0, 0xaa1603e0, 0, 0xf85f03a2});
	Check(Count(r) == 0 && single.old.contexts[0].observations.size() == 1,
	      "single suspension retains the original certificate");
	Fixture missing;
	missing.available = false;
	r = missing.Run(Optional());
	Check(Count(r) == 0, "one path without its GC map invalidates the join");
	Fixture unboxed;
	unboxed.pointer = false;
	r = unboxed.Run(Optional());
	Check(Count(r) == 0, "unboxed slot grants no joined reference");
	Fixture overwritten;
	auto middle = Optional();
	middle[2] = 0xf81f03a1;
	r = overwritten.Run(middle);
	Check(Count(r) == 0, "one-path overwrite loses the saved definition");
	Fixture narrow;
	middle = Optional();
	middle[2] = 0xb81f03a1;
	r = narrow.Run(middle);
	Check(Count(r) == 0, "partial one-path overwrite invalidates full word");
	Fixture two;
	middle = {0xf81f03a0,
	          ZeroBranch(Resume + 4, Resume + 20),
	          0xaa1603e0,
	          0,
	          Branch(Resume + 16, Resume + 28, false),
	          0xaa1603e0,
	          0,
	          0xf85f03a2};
	r = two.Run(middle);
	Check(Count(r) == 1 && r.contexts[0].observations[0].lastSuspensions ==
	                           std::set<uint64_t>{Resume + 12, Resume + 24},
	      "two distinct suspension sites are preserved");
	Fixture separate;
	middle = {
	    0xf81f03a0, ZeroBranch(Resume + 4, Resume + 24), 0xf85f03a0, 0xf81f03a0, 0xaa1603e0, 0,
	    0xf85f03a2};
	r = separate.Run(middle);
	Check(Count(r) == 0, "different save definitions cannot be coalesced by class");
	Fixture many;
	middle = {0xf81f03a0};
	for (unsigned n = 0; n < 9; ++n)
	{
	    auto pc = Resume + middle.size() * 4;
	    middle.push_back(ZeroBranch(pc, pc + 12));
	    middle.push_back(0xaa1603e0);
	    middle.push_back(0);
	}
	middle.push_back(0xf85f03a2);
	r = many.Run(middle);
	Check(r.historyOverflows > 0 && Count(r) == 0, "bounded history overflow is unknown");
	Fixture reset;
	middle.insert(middle.end() - 1, {0xaa1603e0, 0});
	r = reset.Run(middle);
	Check(Count(r) == 0 && !reset.old.contexts[0].observations.empty(),
	      "later mandatory suspension returns to the original single-site certificate");
	Fixture external;
	r = external.Run(Optional());
	r = RestoreJoinedReferences(external.p, external.bindings, external.old, external.bytes,
	                            {Start, Resume + 16});
	Check(Count(r) == 0, "alternate entry at reload discards the reference");
	Fixture invalid;
	r = invalid.Run(Optional());
	invalid.old.maps[0].payload += 4;
	bool threw = false;
	try
	{
	    RestoreJoinedReferences(invalid.p, invalid.bindings, invalid.old, invalid.bytes,
	                            {Start});
	}
	catch (const std::runtime_error &)
	{
	    threw = true;
	}
	Check(threw, "contradictory map ownership remains an error");
	invalid.old.maps[0].payload -= 4;
	invalid.bytes[Start] = {255, 255, 255, 255};
	threw = false;
	try
	{
	    RestoreJoinedReferences(invalid.p, invalid.bindings, invalid.old, invalid.bytes,
	                            {Start});
	}
	catch (const std::runtime_error &)
	{
	    threw = true;
	}
	Check(threw, "undecodable original bytes remain an error");
	Fixture unsupported;
	unsupported.p.savedFrameAbi.supported = false;
	r = unsupported.Run(Optional());
	Check(r.contexts.empty() && r.steps == 0, "unsupported ABI retains an empty phase");
	std::cout << checks << " joined-reference checks passed\n";
    }
    catch (const std::exception &e)
    {
	std::cerr << e.what() << '\n';
	return 1;
    }
}
