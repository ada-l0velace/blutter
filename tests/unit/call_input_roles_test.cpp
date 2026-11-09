#include "CallInputAbi.h"
#include "CallResultAnnotations.h"
#include "CallResultContexts.h"
#include <iostream>
#include <stdexcept>
using namespace SnapshotAnalysis;
namespace {
unsigned checks = 0;
void Check(bool value, const char *message) {
	++checks;
	if (!value)
		throw std::runtime_error(message);
}
struct Array {
	static constexpr unsigned kLengthReg = 2, kTypeArgumentsReg = 1;
};
struct OldClosure {
	static constexpr unsigned kFunctionReg = 1, kContextReg = 2, kInstantiatorTypeArgsReg = 3;
};
struct NewClosure {
	static constexpr unsigned kFunctionReg = 1, kContextReg = 3, kLengthAndFlagsReg = 2;
};
struct OtherRegisters {
	static constexpr unsigned kLengthReg = 6, kTypeArgumentsReg = 7;
};
struct Missing {};
struct Mixed : NewClosure {
	static constexpr unsigned kInstantiatorTypeArgsReg = 4;
};
struct Invalid {
	static constexpr unsigned kLengthReg = 15, kTypeArgumentsReg = 1;
};
bool Has(const AssemblyNotes &notes, const std::string &text) {
	for (const auto &[_, lines] : notes)
		for (const auto &line : lines)
			if (line.find(text) != std::string::npos)
				return true;
	return false;
}
} // namespace
int main() {
	try {
		using K = StubInputKind;
		using R = StubInputRole;
		const auto old = ReadStubInputAbis<Array, OldClosure>(), modern = ReadStubInputAbis<Array, NewClosure>();
		Check(old.size() == 2 && old.contains(K::Closure) && !old.contains(K::Closure1),
			  "Old ABI admits the plain stub only");
		Check(old.at(K::Closure).size() == 2, "Plain old closure does not consume instantiator type arguments");
		Check(modern.size() == 5 && !modern.contains(K::Closure), "Reviewed numbered generators use the new layout");
		for (auto k : {K::Closure1, K::Closure2, K::Closure3, K::Closure4})
			Check(modern.at(k) == modern.at(K::Closure1), "Numbered stubs share verified inputs");
		Check(ReadStubInputAbis<Missing, Missing>().empty(), "Absent SDK features grant no contract");
		Check(ReadStubInputAbis<Array, Mixed>().size() == 1, "Mixed closure layouts are unsupported");
		Check(ReadStubInputAbis<Invalid, Missing>().empty(), "Unsupported register numbers are rejected");
		Check(ReadStubInputAbis<OtherRegisters, Missing>().at(K::Array)[0].reg == 6,
			  "Registers come from SDK members, not fixed numbers");
		const std::map<uint64_t, uint64_t> bounds{{0x2000, 0x2010}};
		const std::vector<StubInputIdentity> identities{{0x2000, 0x2000, 0x2010, K::Array, true}};
		const auto contracts = SelectStubInputContracts(identities, modern, bounds, true);
		Check(contracts.size() == 1, "Exact reference and payload identity admit a contract");
		Check(FindStubInputRole(contracts.at(0x2000), 2) == R::ArrayLength, "Role lookup retains physical register");
		Check(!FindStubInputRole(contracts.at(0x2000), 0), "Output register is not inferred as an input");
		Check(SelectStubInputContracts(identities, modern, bounds, false).empty(), "Unsupported ABI has no roles");
		Check(SelectStubInputContracts(identities, {}, bounds, true).empty(), "Missing ABI has no roles");
		for (unsigned defect = 0; defect < 9; ++defect) {
			auto ids = identities;
			if (defect == 0)
				ids[0].matchesReference = false;
			if (defect == 1)
				ids[0].payload += 4;
			if (defect == 2)
				ids[0].end += 4;
			if (defect == 3)
				ids[0].entry += 1;
			if (defect == 4)
				ids[0].kind = K::Unknown;
			if (defect == 5)
				ids.push_back({0x2000, 0x2000, 0x2010, K::Closure1, true});
			if (defect == 6)
				ids.push_back({0x2000, 0x2000, 0x2010, K::Array, false});
			if (defect == 7)
				ids[0].end = ids[0].entry;
			if (defect == 8)
				ids[0].end = 0x200000;
			Check(SelectStubInputContracts(ids, modern, bounds, true).empty(),
				  "Mismatched, conflicting and invalid identities grant no roles");
		}
		auto duplicate = identities;
		duplicate.push_back(identities.front());
		Check(SelectStubInputContracts(duplicate, modern, bounds, true) == contracts,
			  "Identical repeated identities are harmless");
		Edge edge{};
		edge.source = 0x1000;
		edge.site = 0x1008;
		edge.kind = "call";
		edge.target = 0x2000;
		edge.registerInputs = {{1, 7, {0x1000}}};
		edge.registerConstants = {{"x2", 6, {0x1004}}};
		auto notes = BuildCallInputNotes(
			{edge}, [](uint32_t) { return "Type\"\\\n"; }, contracts);
		Check(Has(notes, "array type arguments (X1) -> class 0x7"), "Known class receives its SDK input role");
		Check(Has(notes, "array length (X2) -> raw word 0x6 [stub 0x2000; partial; normal flow]"),
			  "Raw word is not unboxed or relabeled as a source parameter");
		Check(Has(notes, "\\x0a"), "Role metadata cannot inject newlines");
		edge.registerConstants.clear();
		Check(Has(BuildCallInputNotes({edge}, {}, contracts), "array length (X2) -> value unknown"),
			  "A known role does not invent a value");
		edge.target = 0x2004;
		Check(Has(BuildCallInputNotes({edge}, {}, contracts), "physical x1"),
			  "Interior entry does not inherit a contract");
		edge.kind = "indirect_call";
		edge.target.reset();
		Check(Has(BuildCallInputNotes({edge}, {}, contracts), "physical x1"), "Unresolved indirect target has no role");
		edge.staticDispatch = StaticDispatch{0x1004, 0, 0, 0x2000, {0x1004}};
		Check(Has(BuildCallInputNotes({edge}, {}, contracts), "array type arguments (X1)"),
			  "Proved ordinary indirect target can receive a role");
		edge.staticDispatch.reset();
		CallResultContext context{};
		context.payload = 0x1000;
		context.bindings = {{0x1000, 0x3000, 9, false}};
		context.analysis.resolutions[0x1008] = {0x1004, 0, 0, 0x2000, {0x1004}};
		context.analysis.registerInputs[0x1008] = {{1, 7, {0x1000}}};
		Edge producer{};
		producer.source = 0x1000;
		producer.site = 0x1000;
		producer.kind = "call";
		producer.target = 0x3000;
		CallResultContextResult result;
		result.contexts.push_back(context);
		notes = BuildCallResultNotes(result, {producer, edge}, {}, contracts);
		Check(Has(notes, "array type arguments (X1) -> class 0x7 [stub 0x2000; partial; under result bindings "
						 "0x1000@0x3000=0x9]"),
			  "A conditional target retains its binding even for an existing class");
		Check(!Has(notes, "value unknown"), "Conditional targets do not invent unobserved values");
		edge.staticDispatch = context.analysis.resolutions.at(0x1008);
		Check(!Has(BuildCallResultNotes(result, {producer, edge}, {}, contracts), "call-input"),
			  "Existing class and target are not duplicated conditionally");
		for (unsigned defect = 0; defect < 4; ++defect) {
			auto bad = contracts;
			if (defect == 0)
				bad.at(0x2000).inputs[0].reg = 15;
			if (defect == 1)
				bad.at(0x2000).end = 0x2000;
			if (defect == 2)
				bad.at(0x2000).inputs[0].role = R::Unknown;
			if (defect == 3)
				bad.at(0x2000).inputs[1].reg = bad.at(0x2000).inputs[0].reg;
			bool rejected = false;
			try {
				BuildCallInputNotes({edge}, {}, bad);
			} catch (const std::runtime_error &) {
				rejected = true;
			}
			Check(rejected, "Malformed mandatory role evidence fails visibly");
		}
		std::cout << checks << " stub input role checks passed\n";
	} catch (const std::exception &error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
}
