#include "CallInputShapes.h"
#include "CallResultAnnotations.h"
#include "CallResultContexts.h"
#include <iostream>
#include <stdexcept>
using namespace SnapshotAnalysis;
namespace {
unsigned checks = 0;
void Check(bool condition, const char* why) { ++checks; if (!condition) throw std::runtime_error(why); }
bool Has(const AssemblyNotes& notes, const std::string& text) {
	for (const auto& [_, lines] : notes) for (const auto& line : lines) if (line.find(text) != std::string::npos) return true;
	return false;
}
}
int main() {
	try {
		CallInputAbi abi{true, 4, 8, "verified_compiler_policy"};
		CallInputModel model{0x2000, 3, 0, 2, "authored\"\n", {"Object", "Object", "Object"}};
		CallInputDescriptor descriptor{6, 2, 3, 3, 3};
		DescriptorLoad load{0x1008, 6, 0x40, 8, 27, {0x1008}};
		const uint32_t ldr = 0xf9400000U | (8 << 10) | (27 << 5) | 4;
		const uint32_t bl = 0x94000000U | ((0x2000 - 0x100c) / 4);
		std::string why;
		auto choose = [&](const auto& a, const auto& m, const auto& d, const auto& l, uint32_t word, uint32_t call, bool bypass = false) {
			return SelectCallInputShape(a, m, d, l, 0x100c, 0x1000, 0x1020, word, call, bypass, why);
		};
		auto shape = choose(abi, model, descriptor, load, ldr, bl);
		Check(shape && why.empty(), "Checked typed descriptor and immediate load admit a shape");
		Check(SuppliedInputIndex(*shape, 16) == 0 && SuppliedInputIndex(*shape, 8) == 1 && SuppliedInputIndex(*shape, 0) == 2,
			"Three supplied inputs reverse stack offsets");
		for (int64_t offset : {-8, 1, 4, 24, 32}) Check(!SuppliedInputIndex(*shape, offset), "Outside, truncated and vector slots have no input ordinal");
		for (unsigned count = 1; count <= 32; ++count) {
			auto m = model; m.fixed = count; m.declaredTypes.resize(count);
			auto d = descriptor; d.count = d.size = d.positional = count;
			const auto accepted = choose(abi, m, d, load, ldr, bl);
			Check(accepted.has_value(), "All bounded arities are supported");
			for (unsigned i = 0; i < count; ++i) Check(SuppliedInputIndex(*accepted, (count-1-i)*8) == i, "Every bounded ordinal has the correct physical slot");
		}
		for (unsigned defect = 0; defect < 16; ++defect) {
			auto a = abi; auto d = descriptor; auto l = load; auto word = ldr, call = bl;
			if (defect == 0) a.supported = false;
			if (defect == 1) a.wordBytes = 4;
			if (defect == 2) word &= ~(1U << 30); // W load
			if (defect == 3) word = (word & ~31U) | 3;
			if (defect == 4) word = 0xd503201fU; // shuffle/clobber
			if (defect == 5) call = 0xd63f0080U; // BLR
			if (defect == 6) call += 1; // wrong target
			if (defect == 7) l.site -= 4;
			if (defect == 8) l.width = 4;
			if (defect == 9) l.poolIndex += 1;
			if (defect == 10) l.proof.clear();
			if (defect == 11) d.size = 2;
			if (defect == 12) d.positional = 2;
			if (defect == 13) d.count = d.size = d.positional = 0;
			if (defect == 14) d.count = d.size = d.positional = 33;
			if (defect == 15) d.typeArguments = 1;
			Check(!choose(a, model, d, l, word, call) && !why.empty(), "Unsupported original words, widths and descriptor fields are rejected explicitly");
		}
		Check(!choose(abi, model, descriptor, load, ldr, bl, true) && why == "descriptor_load_bypass", "Known entry at BL bypasses load proof");
		descriptor.typeArguments = 0;
		Check(choose(abi, model, descriptor, load, ldr, bl).has_value(), "An absent type vector does not shift inputs");
		model.implicit = 1;
		Check(choose(abi, model, descriptor, load, ldr, bl).has_value(), "Implicit input is counted without a receiver-name assertion");
		Edge edge{}; edge.site = 0x100c; edge.source = 0x1000; edge.kind = "call"; edge.target = 0x2000;
		edge.stackInputs = {{16, "heap_class", 7, {0x1000}}, {0, "word", 0x28, {0x1004}}};
		CallInputShapes shapes{{edge.site, *shape}};
		auto notes = BuildCallInputNotes({edge}, [](uint32_t) { return "Type\"\n"; }, {}, shapes);
		Check(Has(notes, "supplied input[0] (Dart SP+16) -> class 0x7"), "Known heap class is placed in supplied order");
		Check(Has(notes, "supplied input[2] (Dart SP+0) -> raw word 0x28"), "Words are not decoded as tagged values");
		Check(!Has(notes, "input[1]") && Has(notes, "\\x0a"), "Unknown slots have no invented value and names are escaped");
		CallResultContext context{}; context.payload = edge.source;
		context.bindings = {{0x1000, 0x3000, 9, false}};
		context.analysis.stackInputs[edge.site] = edge.stackInputs;
		context.analysis.stackInputs[edge.site].push_back({8, "heap_class", 11, {0x1000, 0x1004}});
		CallResultContextResult result; result.contexts.push_back(context);
		Edge producer{}; producer.source = 0x1000; producer.site = 0x1000; producer.kind = "call"; producer.target = 0x3000;
		notes = BuildCallResultNotes(result, {producer, edge}, {}, {}, shapes);
		Check(Has(notes, "input[1] (Dart SP+8) -> class 0xb [descriptor load 0x1008; fixed stack; partial; under result bindings 0x1000@0x3000=0x9]"), "Conditional values retain complete result bindings");
		Check(!Has(notes, "supplied input[0]") && !Has(notes, "supplied input[2]"), "Ordinary facts are not duplicated conditionally");
		auto bad = shapes; bad.begin()->second.count = 0; bool failed = false;
		try { BuildCallInputNotes({edge}, {}, {}, bad); } catch (const std::runtime_error&) { failed = true; }
		Check(failed, "Malformed admitted evidence fails visibly");
		// Separate GPR/FPU allocation does not establish source order: sorting
		// {X1,V0} yields the same register set for either source parameter order.
		Check(BuildCallInputNotes({edge}).empty(), "Physical register ordering grants no stack shape");
		std::cout << checks << " supplied-input checks passed\n";
	} catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
