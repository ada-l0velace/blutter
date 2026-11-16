#include "Arm64Decode.h"
#include "AsyncFieldAccesses.h"
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>

using namespace SnapshotAnalysis;
namespace
{
int checks = 0;
void Check(bool value, const char *message)
{
	++checks;
	if (!value)
		throw std::runtime_error(message);
}
constexpr uint64_t Start = 0x1000;
InstanceLayout Layout()
{
	InstanceLayout l;
	l.classId = 7;
	l.kind = "instance";
	l.header = 8;
	l.end = 32;
	l.tag = 1;
	l.slotBytes = 4;
	l.excluded = {16};
	l.unboxed = {24, 28};
	l.fields = {{8, 6, "enabled", "bool?"}};
	return l;
}
AsyncFieldContext Run(std::vector<uint32_t> words, InstanceLayout layout = Layout(),
                      std::set<uint64_t> entries = {}, size_t budget = 200000)
{
	std::vector<uint8_t> bytes;
	for (auto word : words)
		for (unsigned n = 0; n < 4; ++n)
			bytes.push_back(word >> (8 * n));
	csh decoder;
	Check(cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &decoder) == CS_ERR_OK, "decoder opens");
	cs_option(decoder, CS_OPT_DETAIL, CS_OPT_ON);
	const auto [raw, count] = DecodeArm64Instructions(decoder, bytes.data(), bytes.size(), Start);
	Check(count == words.size(), "authored words decode");
	AsyncFieldContext context{Start, 0xffc, Start, 0, 7, "await_delivery"};
	try {
		AnalyzeFieldAccesses(raw, count, layout, entries, context, budget);
	} catch (...) {
		cs_free(raw, count);
		cs_close(&decoder);
		throw;
	}
	cs_free(raw, count);
	cs_close(&decoder);
	return context;
}
} // namespace
int main()
{
	try {
		auto c = Run({0xb8407001, 0xb800b002, 0xd65f03c0});
		Check(c.accesses.size() == 2 && c.accesses[0].offset == 8 && c.accesses[0].base == 0,
		      "tagged owner identifies a boxed read and a write");
		Check(c.accesses[1].access == "write" && c.status == "control_boundary",
		      "writes do not imply values");
		auto note = AsyncFieldAccessNote(c, c.accesses[0], Layout(), [](uint32_t) { return "Example"; });
		Check(note.find("field \"enabled\"") != std::string::npos &&
		          note.find("declared type \"bool?\"") != std::string::npos,
		      "retained inherited declaration is separate from runtime value");
		Check(note.find("field value unknown") != std::string::npos &&
		          note.find("conditional:") != std::string::npos,
		      "conditional identity-only scope is explicit");
		Check(Run({0xaa0003e2, 0xb8407041}).accesses.size() == 1, "full reference copy");
		Check(Run({0x2a0003e0, 0xb8407001}).accesses.empty(), "narrow copy loses the pointer");
		Check(Run({0xb8407000, 0xb8407001}).accesses.size() == 1,
		      "loaded value does not inherit owner class");
		for (auto word :
		     {0xb85ff001U, 0xb8408001U, 0xb840f001U, 0xb8417001U, 0xb841f001U, 0xf8407001U, 0x38407001U})
			Check(Run({word}).accesses.empty(),
			      "header, misalignment, type arguments, unboxed, padding or width refused");
		Check(Run({0xb8407001, 0xb840b002}).accesses.size() == 2, "independent loads keep owner");
		Check(Run({0xf8008401, 0xb8407001}).accesses.empty(), "writeback cannot preserve an owner register");
		Check(Run({0xca010000, 0xb8407001}).accesses.empty(), "unsupported arithmetic loses owner");
		Check(Run({0x94000400, 0xb8407001}).accesses.empty(), "call boundary stops propagation");
		Check(Run({0xb4000042, 0xb8407001, 0xd503201f}).accesses.empty(),
		      "branch boundary stops propagation");
		Check(Run({0xb8407001}, Layout(), {Start}).accesses.empty(), "alternate seed entry refuses owner");
		Check(Run({0xd503201f, 0xb8407001}, Layout(), {Start + 4}).accesses.empty(),
		      "alternate entry stops propagation");
		Check(Run({0xd503201f, 0xb8407001}, Layout(), {}, 1).status == "work_limit",
		      "global work remains bounded");
		std::vector<uint32_t> large(70, 0xd503201f);
		Check(Run(large).status == "local_limit", "local region remains bounded");
		auto context = Layout();
		context.kind = "context";
		context.contextParent = 8;
		context.contextData = 16;
		context.end = 16;
		context.fields.clear();
		context.excluded.clear();
		context.unboxed.clear();
		c = Run({0xb8407001, 0xb8413002}, context);
		Check(c.accesses.size() == 2 && c.accesses[0].kind == "context_parent" &&
		          c.accesses[1].kind == "context_slot" && c.accesses[1].index == 1,
		      "context layout distinguishes parent and capture slot");
		Check(AsyncFieldAccessNote(c, c.accesses[1], context).find("bounds unknown") != std::string::npos,
		      "capture index grants no variable name or bounds");
		auto unsupported = Layout();
		unsupported.kind = "unsupported";
		Check(Run({0xb8407001}, unsupported).status == "unsupported_layout",
		      "missing layout remains unknown");
		auto bad = Layout();
		bad.fields.push_back(bad.fields.front());
		bool rejected = false;
		try {
			Run({0xb8407001}, bad);
		} catch (const std::runtime_error &) {
			rejected = true;
		}
		Check(rejected, "contradictory retained field metadata remains fatal");
		bad = context;
		bad.contextParent = std::numeric_limits<int64_t>::max();
		rejected = false;
		try {
			Run({0xb8407001}, bad);
		} catch (const std::runtime_error &) {
			rejected = true;
		}
		Check(rejected, "extreme layout is refused before arithmetic");
		auto escaped = Layout();
		escaped.fields[0].name = "quoted\"\n";
		c = Run({0xb8407001}, escaped);
		note = AsyncFieldAccessNote(c, c.accesses[0], escaped);
		Check(note.find('\n') == std::string::npos && note.find("\\u000a") != std::string::npos,
		      "metadata cannot break comment attachment");
		AsyncFieldsResult result;
		result.layouts.emplace(7, escaped);
		result.contexts = {c};
		std::ostringstream out;
		WriteAsyncFields(out, result);
		Check(out.str().find("conditional_layout_only") != std::string::npos &&
		          out.str().find("\\u000a") != std::string::npos,
		      "structured evidence preserves scope and escaping");
		std::cout << checks << " async field checks passed\n";
	} catch (const std::exception &error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
}
