#include "FieldInputOrigins.h"
#include "SnapshotCodeAnalysis.h"
#include <iostream>
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
struct Fixture {
	AsyncFieldsResult fields;
	std::vector<CallInputOrigin> origins;
	Profile profile{"authored", ARM64_REG_X27, ARM64_REG_X26, 16, 8, 32, {}, {}};
	std::vector<Edge> edges{{0x100c, 0x1000, "call", 0x2000}};
	CallInputShapes shapes;
	Fixture()
	{
		fields.supported = true;
		profile.callInputAbi = {true, 4, 8, "verified_compiler_policy"};
		profile.stubInputContracts = {
		    {0x2000,
		     {0x2004,
		      StubInputKind::Array,
		      {{2, StubInputRole::ArrayLength}, {1, StubInputRole::ArrayTypeArguments}}}}};
		InstanceLayout layout;
		layout.classId = 7;
		layout.kind = "instance";
		layout.header = 8;
		layout.end = 16;
		layout.tag = 1;
		layout.slotBytes = 4;
		fields.layouts.emplace(7, layout);
		AsyncFieldContext context{0x1000, 0xffc, 0x1000, 0, 7, "await_delivery", "registers_lost", 1};
		context.accesses = {{0x1000, 0, 1, 4, 8, "read", "instance_slot", {}}};
		fields.contexts = {context};
		WordOrigin value{"load_compressed",
		                 0x1000,
		                 {},
		                 {},
		                 NativeIr::Address{{0, 64}, 7},
		                 {0x1000, 0x1004, 0x1008, 0x100c}};
		origins = {{0x100c,
		            0x1000,
		            "array_type_arguments",
		            {},
		            1,
		            {},
		            {{"input", {"load_endpoint", value, 3}, {}}}}};
	}
	FieldInputLinksResult Run()
	{
		return LinkFieldInputs(fields, origins, profile, edges, shapes);
	}
	WordOrigin &Source()
	{
		return *origins[0].chain[0].origin.source;
	}
};
} // namespace
int main()
{
	try {
		Fixture f;
		auto result = f.Run();
		Check(result.links == std::vector<FieldInputLink>{{0, 0, 0}},
		      "direct field word joins its verified input source");
		Check(result.candidates == 1 && result.remaining == 199999 && result.complete,
		      "independent bounded join work");
		auto text = FieldInputNote(f.fields, f.origins, result.links[0], [](uint32_t) { return "Example"; });
		Check(text.find("array type arguments (X1)") != std::string::npos, "SDK input role retained");
		Check(text.find("field value/type unknown") != std::string::npos &&
		          text.find("conditional:") != std::string::npos,
		      "owner identity grants no field value or type");
		f.origins[0].index = 0;
		f.origins[0].reg.reset();
		f.origins[0].spOffset = 8;
		f.origins[0].role = "supplied_input";
		f.shapes.emplace(0x100c, CallInputShape{0x100c, 0x1000, 0x2000, 0x1008, 0, 2, 8, {0x1008, 0x100c}});
		Check(f.Run().links.size() == 1 &&
		          FieldInputNote(f.fields, f.origins, {0, 0, 0}).find("supplied input[0] (SP+0x8)") !=
		              std::string::npos,
		      "descriptor-backed stack input retains supplied order");
		f = Fixture{};
		f.fields.contexts[0].accesses[0].access = "write";
		Check(f.Run().links.empty(), "a store is not an input value definition");
		f = Fixture{};
		f.origins[0].chain[0].relation = "load_base";
		Check(f.Run().links.empty(), "an input's base is not its value");
		f = Fixture{};
		f.origins[0].chain[0].poolIndex = 1;
		Check(f.Run().links.empty(), "pool metadata is not an instance field");
		f = Fixture{};
		f.origins[0].chain[0].origin.stop = "call_barrier";
		Check(f.Run().links.empty(), "partial fallback across a call is not complete provenance");
		f = Fixture{};
		f.Source().kind = "post_call_x0";
		Check(f.Run().links.empty(), "a call result cannot masquerade as a field read");
		f = Fixture{};
		f.Source().load->base.id = 2;
		Check(f.Run().links.empty(), "wrong owner register refused");
		f = Fixture{};
		f.Source().load->displacement = 11;
		Check(f.Run().links.empty(), "wrong field offset refused");
		f = Fixture{};
		f.Source().kind = "load";
		Check(f.Run().links.empty(), "a compressed field needs full-word reconstruction");
		f = Fixture{};
		f.Source().proof.erase(f.Source().proof.begin() + 1);
		Check(f.Run().links.empty(), "gapped proof refused");
		f = Fixture{};
		f.origins[0].payload = 0x800;
		Check(f.Run().links.empty(), "different payload refused");
		f = Fixture{};
		f.profile.stubInputContracts.clear();
		Check(f.Run().links.empty(), "physical register without a matched role is not an input");
		f = Fixture{};
		f.origins[0].role = "physical_register";
		Check(f.Run().links.empty(), "unknown role cannot promote a register observation");
		f = Fixture{};
		f.profile.callInputAbi.supported = false;
		Check(f.Run().links.empty(), "unsupported SDK input policy refused");
		f = Fixture{};
		f.profile.stubInputContracts.at(0x2000).inputs.clear();
		bool rejected = false;
		try {
			f.Run();
		} catch (const std::runtime_error &) {
			rejected = true;
		}
		Check(rejected, "contradictory mandatory SDK role contracts remain fatal");
		f = Fixture{};
		f.fields.layouts[7].kind = "context";
		f.fields.layouts[7].contextParent = 8;
		f.fields.layouts[7].contextData = 16;
		f.fields.contexts[0].accesses[0].offset = 20;
		f.fields.contexts[0].accesses[0].kind = "context_slot";
		f.fields.contexts[0].accesses[0].index = 1;
		f.Source().load->displacement = 19;
		Check(f.Run().links.size() == 1 &&
		          FieldInputNote(f.fields, f.origins, {0, 0, 0}).find("bounds unknown") != std::string::npos,
		      "captured storage origins do not grant capture names or bounds");
		f = Fixture{};
		f.fields.contexts[0].seed = 0x1004;
		Check(f.Run().links.empty(), "read before its owner seed refused");
		f = Fixture{};
		f.fields.supported = false;
		Check(f.Run().links.empty() && f.Run().originsExamined == 0, "absent adapter grants no joins");
		f = Fixture{};
		f.fields.layouts[7].fields = {{8, 7, "quoted\"\n", "bool?"}};
		text = FieldInputNote(f.fields, f.origins, {0, 0, 0});
		Check(text.find('\n') == std::string::npos && text.find("\\u000a") != std::string::npos,
		      "metadata stays on one comment line");
		std::ostringstream out;
		WriteFieldInputs(out, f.Run());
		Check(out.str().find("conditional_loaded_word_only") != std::string::npos,
		      "structured relation carries scope");
		f = Fixture{};
		f.origins.resize(4097, f.origins.front());
		result = f.Run();
		Check(result.links.size() == 4096 && !result.complete,
		      "bounded publication records unfinished joins");
		std::cout << checks << " field input checks passed\n";
	} catch (const std::exception &error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
}
