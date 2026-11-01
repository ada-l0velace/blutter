#include "CallResultAnnotations.h"
#include "CallResultContexts.h"
#include <iostream>
#include <stdexcept>

using namespace SnapshotAnalysis;
namespace {
unsigned checks = 0;
void Check(bool value, const char* message) { ++checks; if (!value) throw std::runtime_error(message); }
bool Has(const AssemblyNotes& notes, uint64_t site, const std::string& text) {
	if (!notes.contains(site)) return false;
	for (const auto& line : notes.at(site)) if (line.find(text) != std::string::npos) return true;
	return false;
}
}
int main()
{
	try {
		Edge producer{}; producer.site=0x1004;producer.source=0x1000;producer.kind="call";producer.target=0x2000;
		Edge consumer{}; consumer.site=0x1010;consumer.source=0x1000;consumer.kind="call";consumer.target=0x3000;
		consumer.stackInputs={{8,"word",42,{}}};
		consumer.arrayArguments={{16,0x1008,2,{{1,8}}, {}}};
		Edge dispatch{};dispatch.site=0x1014;dispatch.source=0x1000;dispatch.kind="indirect_call";
		std::vector<Edge> edges{producer,consumer,dispatch};
		CallResultContext context{};context.payload=0x1000;context.bindings={{0x1004,0x2000,7,false}};
		context.analysis.stackInputs[0x1010]={{0,"heap_class",7,{}},{8,"word",42,{}},{24,"word",99,{}}};
		context.analysis.arrayArguments[0x1010]={{16,0x1008,2,{{0,7},{1,8}}, {}}};
		context.analysis.resolutions[0x1014]={0x100c,0,0,0x4000,{}};
		context.analysis.returnClasses[0x1018]={7,{}};
		CallResultContextResult result;result.contexts.push_back(context);
		const auto notes=BuildCallResultNotes(result,edges,[](uint32_t cid) { return cid==7 ? "ExampleWidget" : "OtherWidget"; });
		Check(Has(notes,0x1004,"normal-return X0 -> class 0x7 (\"ExampleWidget\") [callee summary]"),"Normal-result class and metadata name are explicit");
		Check(Has(notes,0x1010,"stack Dart SP+0 -> class 0x7"),"New physical stack class appears at its consuming call");
		Check(Has(notes,0x1010,"stack Dart SP+24 -> word 0x63"),"Known words are not presented as object classes");
		Check(!Has(notes,0x1010,"stack Dart SP+8"),"Unchanged ordinary stack facts are not repeated");
		Check(Has(notes,0x1010,"allocation 0x1008, length 2, element[0] -> class 0x7"),"Array identity, length and known cell remain explicit");
		Check(!Has(notes,0x1010,"element[1]"),"Unchanged ordinary array cells are not repeated");
		Check(Has(notes,0x1014,"snapshot dispatch -> 0x4000"),"Dispatch remains a snapshot observation");
		Check(Has(notes,0x1018,"physical X0 at RET -> class 0x7"),"Physical returns do not become source signatures");
		auto tail=edges;tail[2].kind="indirect_jump";
		Check(Has(BuildCallResultNotes(result,tail),0x1014,"snapshot dispatch -> 0x4000"),"Tail dispatches retain their original transfer kind");
		for (const auto& [site,lines] : notes) for (const auto& line : lines)
			Check(line.starts_with("caller-result @") && line.find("[payload 0x1000]")!=std::string::npos,"Every note retains its original caller scope");
		Check(!Has(BuildCallResultNotes(result,edges),0x1004,"ExampleWidget"),"Absent metadata leaves the numeric class intact");
		result.contexts[0].bindings[0].basis=ResultBindingBasis::RegisterContext;
		Check(Has(BuildCallResultNotes(result,edges),0x1004,"[caller-bound helper]"),"Conditional helper evidence is not labeled a global callee summary");
		const auto escaped=BuildCallResultNotes(result,edges,[](uint32_t) { return "Quoted\"\\\nName"; });
		Check(Has(escaped,0x1004,"\\x0a"),"Metadata newlines cannot inject assembly lines");
		for (const auto& [site,lines] : escaped) for (const auto& line : lines)
			Check(line.find('\n')==std::string::npos && line.find('\r')==std::string::npos,"Every generated annotation stays on one line");
		for (unsigned defect=0;defect<4;++defect) {
			auto bad=result;
			if(defect==0)bad.contexts[0].payload=0x3000;
			if(defect==1)bad.contexts[0].bindings[0].callee=0x4000;
			if(defect==2)bad.contexts[0].analysis.stackInputs[0x1010][0].kind="source_parameter";
			if(defect==3)bad.contexts[0].analysis.stackInputs[0x1010][0].value=uint64_t{1}<<32;
			bool rejected=false;try {BuildCallResultNotes(bad,edges);}catch(const std::runtime_error&){rejected=true;}
			Check(rejected,"Malformed scope, producer or class information is rejected");
		}
		Check(BuildCallResultNotes({},edges).empty(),"Absent proofs create no annotations");
		std::cout<<checks<<" caller-result annotation checks passed\n";
	} catch(const std::exception& error) {std::cerr<<error.what()<<'\n';return 1;}
}
