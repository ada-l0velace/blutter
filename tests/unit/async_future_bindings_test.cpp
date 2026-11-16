#include "AsyncFutureBindings.h"
#include "SnapshotCodeAnalysis.h"
#include "Arm64Decode.h"
#include <iostream>
#include <stdexcept>

using namespace SnapshotAnalysis;
namespace {
unsigned checks=0;
void Check(bool value, const char* why) { ++checks; if(!value) throw std::runtime_error(why); }
constexpr uint64_t Init=0x11000,Await=0x12000,Typed=0x13000,Value=0x14000,Forward=0x15000,Alloc=0x18000,Other=0x18100;
uint32_t Transfer(uint64_t pc,uint64_t target,bool call=true) { return (call?0x94000000U:0x14000000U)|((target-pc)/4&0x3ffffff); }
std::vector<uint32_t> Producer(uint64_t start,uint64_t allocation=Alloc,uint64_t complete=Value)
{
	return {0xa9bf79fdU,0xaa0f03fdU,0xa9bf59f6U,Transfer(start+12,Init),Transfer(start+16,allocation),Transfer(start+20,complete,false)};
}
struct Decoded {
	csh handle=0; cs_insn* raw=nullptr; size_t count=0;
	Decoded(const std::vector<uint8_t>& bytes,uint64_t start) {
		Check(cs_open(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN,&handle)==CS_ERR_OK,"decoder opens");cs_option(handle,CS_OPT_DETAIL,CS_OPT_ON);
		const auto decoded=DecodeArm64Instructions(handle,bytes.data(),bytes.size(),start);raw=decoded.first;count=decoded.second;
		Check(count*4==bytes.size(),"authored words decode");
	}
	~Decoded(){cs_free(raw,count);if(handle)cs_close(&handle);}
};
std::vector<uint8_t> Bytes(const std::vector<uint32_t>& words) {
	std::vector<uint8_t> bytes;for(auto w:words)for(unsigned n=0;n<4;++n)bytes.push_back(static_cast<uint8_t>(w>>(n*8)));return bytes;
}
struct Module {
	Profile p{};
	std::map<uint64_t,std::vector<uint8_t>> bytes;
	std::vector<CompletionSummary> summaries;
	std::vector<AwaitFutureInput> inputs;
	size_t remaining=2000000;
	Module() {
		p.wordReturnRegister=ARM64_REG_X0;p.nullRegister=ARM64_REG_X22;p.nullClassId=1;p.futureBindingAbi={true,-8};
		p.asyncContracts={{Init,{AsyncOperation::Init,Init+4}},{Await,{AsyncOperation::Await,Await+4}},
			{Typed,{AsyncOperation::AwaitWithTypeCheck,Typed+4}},{Value,{AsyncOperation::CompleteValue,Value+4}},
			{Forward,{AsyncOperation::CompleteValueOrFuture,Forward+4}}};
		p.allocationReturns={{Alloc,7},{Other,8}};
	}
	void Add(uint64_t start,std::vector<uint32_t> words) {
		bytes[start]=Bytes(words);Decoded d(bytes.at(start),start);
		p.completionBodies[start]={start+words.size()*4,true,true,{}};
		size_t budget=2000000;auto summary=AnalyzeCompletions(d.raw,d.count,p,p.completionBodies.at(start),{}, {},budget);
		Check(summary.has_value(),"authored producer has completion sites");summaries.push_back(*summary);
	}
	void Caller(std::vector<uint32_t> words, uint64_t awaitSite, uint64_t helper=Await,std::set<uint64_t> entries={}) {
		const auto code=Bytes(words);Decoded d(code,0x1000);CompletionBody body{0x1000+words.size()*4,true,true,{}};
		auto boundary=DescribeAsyncBoundary("call",awaitSite,0x1000,body.end,helper,p.asyncContracts);
		Check(boundary.has_value(),"authored await boundary");
		inputs.push_back(ObserveAwaitFuture(d.raw,d.count,(awaitSite-0x1000)/4,*boundary,p,body,[&](uint64_t pc){return entries.contains(pc);},remaining));
	}
	FutureBindingsResult Run() {return BindAwaitFutures(p,summaries,inputs,bytes,remaining);}
};
FutureProducer Probe(std::vector<uint32_t> words,const std::function<void(Module&)>& configure={},uint64_t entry=0x5000,size_t budget=2000000)
{
	Module m;m.Add(0x5000,std::move(words));if(configure)configure(m);Decoded d(m.bytes.at(0x5000),0x5000);
	return CheckFutureProducer(d.raw,d.count,entry,m.p,m.summaries[0],m.p.completionBodies.at(0x5000),budget);
}
}
int main() {
	try {
		auto producer=Probe(Producer(0x5000));Check(producer.status=="matched_async_frame",std::format("matched frame and init dominate normal returns: {}",producer.status).c_str());
		auto uncleared=Producer(0x5000);uncleared[2]=0xd10041efU;
		producer=Probe(uncleared);Check(producer.status=="uninitialized_suspend_state","an allocated slot is not an initialized null slot");
		auto corruptControl=Producer(0x5000);corruptControl.insert(corruptControl.begin()+3,0xf90003a0U);
		corruptControl[4]=Transfer(0x5010,Init);corruptControl[5]=Transfer(0x5014,Alloc);corruptControl[6]=Transfer(0x5018,Value,false);
		producer=Probe(corruptControl);Check(producer.status=="frame_control_overwritten","saved frame control cannot be changed before initialization");
		auto missingSave=Producer(0x5000);missingSave[0]=0xd503201fU;
		producer=Probe(missingSave);Check(producer.status=="unproved_frame_anchor","frame pointer assignment alone does not prove an owned frame");
		producer=Probe(Producer(0x5000),{},0x5010);Check(producer.status=="uninitialized_suspend_state","alternate entry cannot bypass initialization");
		producer=Probe(Producer(0x5000),[](Module& m){m.p.futureBindingAbi={};});Check(producer.status=="unsupported_abi","unknown frame ABI grants no Future contract");
		producer=Probe(Producer(0x5000),[](Module& m){m.p.completionBodies.at(0x5000).available=false;});Check(producer.status=="missing_producer_metadata","missing handlers cannot establish producer contract");
		producer=Probe(Producer(0x5000),{},0x5000,0);Check(producer.status=="step_limit","budget exhaustion remains unknown");
		auto overwrite=Producer(0x5000);overwrite.insert(overwrite.begin()+4,0xf81f83b6U);overwrite[5]=Transfer(0x5014,Alloc);overwrite[6]=Transfer(0x5018,Value,false);
		producer=Probe(overwrite);Check(producer.status=="suspend_state_overwritten","reserved frame slot cannot be replaced");
		auto escape=Producer(0x5000);escape.insert(escape.begin()+4,0xaa1d03e1U);escape[5]=Transfer(0x5014,Alloc);escape[6]=Transfer(0x5018,Value,false);
		producer=Probe(escape);Check(producer.status=="frame_address_escapes","frame aliases are refused");
		auto stackOverwrite=Producer(0x5000);stackOverwrite.insert(stackOverwrite.begin()+4,0xf9000df6U);
		stackOverwrite[5]=Transfer(0x5014,Alloc);stackOverwrite[6]=Transfer(0x5018,Value,false);
		producer=Probe(stackOverwrite);Check(producer.status=="unproved_stack_write","SP-relative writes cannot replace reserved state");
		auto atomic=Producer(0x5000);atomic.insert(atomic.begin()+4,0xc89ffde0U);
		atomic[5]=Transfer(0x5014,Alloc);atomic[6]=Transfer(0x5018,Value,false);
		producer=Probe(atomic);Check(producer.status=="unsupported_frame_memory","unmodeled frame stores do not evade reserved-slot checks");
		producer=Probe(Producer(0x5000),[](Module& m){m.p.completionBodies.at(0x5000).handlers={0x5010};});
		Check(producer.status=="uninitialized_suspend_state","handler roots cannot inherit unproved initialization");
		producer=Probe(Producer(0x5000),[](Module& m){m.summaries[0].initializations.push_back(0x5010);});
		Check(producer.status=="ambiguous_initialization","multiple initializer identities are refused");
		auto arguments=Producer(0x5000);arguments.insert(arguments.begin()+3,{0x8b23cba0U,0xf9400400U});
		arguments[5]=Transfer(0x5014,Init);arguments[6]=Transfer(0x5018,Alloc);arguments[7]=Transfer(0x501c,Value,false);
		producer=Probe(arguments);Check(producer.status=="matched_async_frame","adjacent argument address/load consumes the frame pointer temporary");
		auto escapedArgument=arguments;escapedArgument[4]=0xf9400401U;
		producer=Probe(escapedArgument);Check(producer.status=="frame_address_escapes","argument address left live remains an escape");
		Module m;m.Add(0x5000,Producer(0x5000));m.Caller({Transfer(0x1000,0x5000),Transfer(0x1004,Await),0xd65f03c0},0x1004);
		auto result=m.Run();Check(result.bindings[0].status=="conditional_delivery" && result.bindings[0].classId==7,"direct producer to successful await relation");
		Check(AwaitFutureBindingNote(result.bindings[0]).find("value/error-preserving callbacks")!=std::string::npos,"delivery is explicitly conditional on SDK callbacks");
		const auto quoted=AwaitFutureBindingNote(result.bindings[0],[](uint32_t){return std::string{"authored\"\\\n"};});
		Check(quoted.find('\n')==std::string::npos && quoted.find("\\x0a")!=std::string::npos,"class names remain quoted single-line data");
		m.inputs.clear();m.Caller({Transfer(0x1000,0x5000),0xaa0003e8U,0xaa0803e0U,Transfer(0x100c,Await),0xd65f03c0},0x100c);
		Check(m.Run().bindings[0].status=="conditional_delivery","full-register copies preserve the Future reference");
		m.inputs.clear();m.Caller({Transfer(0x1000,0x5000),0xd2800000U,Transfer(0x1008,Await),0xd65f03c0},0x1008);
		Check(m.Run().bindings[0].status=="producer_origin_unproved","overwritten Future is not linked to original call");
		m.inputs.clear();m.Caller({Transfer(0x1000,0x5000),Transfer(0x1004,Typed),0xd65f03c0},0x1004,Typed);
		Check(m.Run().bindings[0].status=="typed_await_delivery_unproved","unchecked generic Future acceptance is not assumed");
		m.inputs.clear();m.Caller({Transfer(0x1000,0x5000),Transfer(0x1004,Await),0xd65f03c0},0x1004,Await,{0x1004});
		Check(m.Run().bindings[0].status=="producer_origin_unproved","known entry can bypass producer call");
		Module chain;chain.Add(0x6000,Producer(0x6000));chain.Add(0x5000,Producer(0x5000,0x6000,Forward));
		chain.Caller({Transfer(0x1000,0x5000),Transfer(0x1004,Await),0xd65f03c0},0x1004);
		result=chain.Run();Check(result.bindings[0].classId==7 && result.producers.size()==2,"known Future completion chains resolve without aliasing Future instances");
		Check(result.bindings[0].producer==0x5000 && result.producers[0].forwards[0].producer==0x6000,"outer Future and forwarded Future keep separate producer identities");
		Module cycle;cycle.Add(0x5000,Producer(0x5000,0x5000,Forward));cycle.Caller({Transfer(0x1000,0x5000),Transfer(0x1004,Await),0xd65f03c0},0x1004);
		Check(!cycle.Run().bindings[0].classId,"cyclic Future forwarding does not invent a value type");
		Module many;
		for(size_t n=0;n<4097;++n) {
			AwaitFutureInput input{};input.status="observed";input.origin.source=WordOrigin{"post_call_x0",0x1000,0x20000+n*4,{}, {},{0x1000,0x1004}};
			many.inputs.push_back(input);
		}
		result=many.Run();Check(result.producers.size()==4096 && result.bindings.back().status=="producer_limit","producer bound is explicit and grants no missing-target facts");
		std::cout<<checks<<" Future binding checks passed\n";return 0;
	}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
