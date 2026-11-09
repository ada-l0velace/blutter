#include "AsyncOrigins.h"
#include "SnapshotCodeAnalysis.h"
#include "Arm64Decode.h"
#include <iostream>
#include <memory>
#include <stdexcept>
#include <set>

using namespace SnapshotAnalysis;
namespace {
unsigned checks = 0;
void Check(bool yes, const char* why) { ++checks; if (!yes) throw std::runtime_error(why); }
uint32_t Call(uint64_t site, uint64_t target) { return 0x94000000U | ((target-site)/4 & 0x3ffffff); }
uint32_t Move(unsigned to, unsigned from) { return 0xaa0003e0U | (from<<16) | to; }
uint32_t Store(unsigned from, int offset, unsigned base=29, bool narrow=false) {
	return (narrow ? 0xb8000000U : 0xf8000000U) | ((static_cast<unsigned>(offset)&511)<<12) | (base<<5) | from;
}
uint32_t Load(unsigned to, int offset, unsigned base=29) { return 0xf8400000U | ((static_cast<unsigned>(offset)&511)<<12) | (base<<5) | to; }
Profile Config() {
	Profile p{};
	p.name = "synthetic";
	p.poolRegister = ARM64_REG_X27;
	p.threadRegister = ARM64_REG_X26;
	p.poolDataOffset = 16;
	p.poolSlotSize = 8;
	p.poolLength = 8;
	p.wordReturnRegister=ARM64_REG_X0;
	p.asyncContracts={{0x8000,{AsyncOperation::Await,0x8004}}, {0x8100,{AsyncOperation::CompleteValue,0x8104}},
		{0x8200,{AsyncOperation::CompleteValueOrFuture,0x8204}}, {0x8300,{AsyncOperation::AwaitWithTypeCheck,0x8304}}};
	p.nonReturningCalls={{0x7000,"synthetic_fatal"}};
	return p;
}
AsyncInput Run(std::vector<uint32_t> words, std::set<uint64_t> entries={}, size_t limit=64,
	AsyncOperation operation=AsyncOperation::Await, bool validAbi=true,
	const std::function<void(cs_insn*,size_t)>& mutate={}) {
	const bool await=operation==AsyncOperation::Await || operation==AsyncOperation::AwaitWithTypeCheck;
	const auto target=operation==AsyncOperation::CompleteValue?0x8100:operation==AsyncOperation::CompleteValueOrFuture?0x8200:operation==AsyncOperation::AwaitWithTypeCheck?0x8300:0x8000;
	const auto at=0x1000+words.size()*4;
	words.push_back(Call(at,target) - (await?0U:0x80000000U));
	std::vector<uint8_t> bytes;
	for (const auto word:words) for(unsigned i=0;i<4;++i) bytes.push_back(static_cast<uint8_t>(word>>(i*8)));
	csh handle=0;
	Check(cs_open(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN,&handle)==CS_ERR_OK,"Decoder opens");
	cs_option(handle,CS_OPT_DETAIL,CS_OPT_ON);
	const auto [raw,count]=DecodeArm64Instructions(handle,bytes.data(),bytes.size(),0x1000);
	Check(count==words.size(),"Authored words decode");
	if (mutate) mutate(raw,count);
	auto p=Config(); if (!validAbi) p.wordReturnRegister=ARM64_REG_INVALID;
	AsyncBoundary boundary{operation,at,0x1000,static_cast<uint64_t>(target),{}};
	const auto value=TraceAsyncInput(raw,count,count-1,boundary,p,[&](uint64_t a){return entries.contains(a);},limit);
	cs_free(raw,count);cs_close(&handle);
	return value;
}
void Source(const AsyncInput& input, const char* kind, uint64_t site) {
	if (!input.source || input.source->kind!=kind || input.source->site!=site)
		std::cerr<<"Expected "<<kind<<" at "<<std::hex<<site<<", got "<<(input.source?input.source->kind:input.stop)
			<<" at "<<(input.source?input.source->site:0)<<", stop "<<input.stop<<std::dec<<'\n';
	Check(input.source && input.source->kind==kind && input.source->site==site,"Expected physical word source");
	Check(input.source->proof.front()==site && input.source->proof.back()==input.site,"Proof includes source and consumer");
	Check(input.source->proof.size()<=65 && input.steps<=64,"Work and proof remain bounded");
}
}
int main() {
	try {
		Source(Run({Call(0x1000,0x4000)}),"post_call_x0",0x1000);
		Source(Run({Call(0x1000,0x4000)}, {},64,AsyncOperation::AwaitWithTypeCheck),"post_call_x0",0x1000);
		for(unsigned r=1;r<29;++r) Source(Run({Call(0x1000,0x4000),Move(r,0),Move(0,r)}),"post_call_x0",0x1000);
		Source(Run({Call(0x1000,0x4000),Move(1,0),Store(1,-8)}),"post_call_x0",0x1000);
		Source(Run({Call(0x1000,0x4000),0xd28000e1}),"post_call_x0",0x1000); // mov x1,#7
		Source(Run({Call(0x1000,0x4000),Call(0x1004,0x5000)}),"post_call_x0",0x1004);
		Source(Run({0xd63f0200}),"post_call_x0",0x1000); // blr x16
		Source(Run({Call(0x1000,0x8000)}),"await_delivery",0x1000);
		Source(Run({Call(0x1000,0x8300)}),"await_delivery",0x1000);
		for(auto op:{AsyncOperation::CompleteValue,AsyncOperation::CompleteValueOrFuture}) {
			auto input=Run({Call(0x1000,0x4000)}, {},64,op);
			Source(input,"post_call_x0",0x1000);
			Check(input.role=="completion_operand","Completion source is not a normal-return summary");
			Source(Run({Call(0x1000,0x8000)}, {},64,op),"await_delivery",0x1000);
		}
		const auto literal=Run({0xd28000e0}); // mov x0,#7
		Source(literal,"literal",0x1000);Check(literal.source->bits==7,"Literal bits retained without Dart type");
		const auto spill=std::vector<uint32_t>{Call(0x1000,0x4000),Store(0,-8),0xd28000e0,Load(0,-8)};
		Source(Run(spill),"post_call_x0",0x1000);
		const auto zeroSpill = Run({Store(31,-8),Load(0,-8)});
		Source(zeroSpill,"literal",0x1000);
		Check(zeroSpill.source->bits==0 && AsyncInputNote(zeroSpill).find("word 0x0")!=std::string::npos,"Zero-register spill preserves exact word bits");
		// Nonoverlapping stores through the same base preserve the local copy.
		auto other=spill;other.insert(other.begin()+2,Store(1,-24,29,true));Source(Run(other),"post_call_x0",0x1000);
		for(const auto& [word,reason]:std::vector<std::pair<uint32_t,std::string>>{
			{Store(1,-8,29,true),"partial_spill_write"},{Store(1,-8,8),"possible_alias_write"},
			{Move(29,8),"load_base_changed"},{Call(0x1008,0x5000),"call_barrier"}}) {
			auto body=spill;body.insert(body.begin()+2,word);const auto input=Run(body);
			Source(input,"load",0x1010);Check(input.stop==reason,"Unproved memory producer stays a load");
			Check(AsyncInputNote(input).find("content origin unproved")!=std::string::npos,"Memory gap remains visible");
		}
		Source(Run({Call(0x1000,0x4000),Move(2,0),0xa93f0ba1,0xd28000e0,Load(0,-8)}),"post_call_x0",0x1000); // stp x1,x2,[fp,-16]
		Source(Run({Load(0,8,2)}),"load",0x1000);
		for(const auto& [body,reason]:std::vector<std::pair<std::vector<uint32_t>,std::string>>{
			{{Call(0x1000,0x4000),0x2a0103e0},"narrow_definition"}, // mov w0,w1
			{{Call(0x1000,0x4000),0x91000400},"computed_definition"}, // add x0,x0,#1
			{{Call(0x1000,0x4000),Move(1,0),Call(0x1008,0x5000),Move(0,1)},"call_barrier"},
			{{Call(0x1000,0x4000),0xd65f03c0},"control_transfer"},
			{{Call(0x1000,0x4000),0xd4000001},"control_transfer"},
			{{Call(0x1000,0x4000),0xb4000021},"control_transfer"},
			{{Call(0x1000,0x4000),0x8a040062},"unknown_effects"}, // and x2,x3,x4
			{{Call(0x1000,0x7000)},"nonreturning_call"}}) {
			const auto input=Run(body);Check(!input.source && input.stop==reason,"Unknown path cannot revive earlier call result");
		}
		Check(!Run({Call(0x1000,0x4000)}, {0x1004}).source,"Consumer with another entry has no preceding source");
		Check(!Run({Call(0x1000,0x4000),Move(1,0),Move(0,1)}, {0x1008}).source,"Interior entry blocks backward copy proof");
		Source(Run({Call(0x1000,0x4000)}, {0x1000}),"post_call_x0",0x1000);
		Check(!Run({}, {},64,AsyncOperation::Await,false).source,"Unsupported ABI has no source");
		Check(Run({Call(0x1000,0x4000)}, {},0).stop=="lookback_limit","Zero budget is explicit");
		std::vector<uint32_t> longBody{Call(0x1000,0x4000)};longBody.resize(64,0xd503201f);
		Source(Run(longBody),"post_call_x0",0x1000);
		longBody.push_back(0xd503201f);Check(Run(longBody,{},100).stop=="lookback_limit","Caller cannot remove hard limit");
		Check(Run({}).stop=="payload_entry","Incoming word remains unknown");
		Check(Run({Call(0x1000,0x4000),0xd503201f}, {},64,AsyncOperation::Await,true,
			[](cs_insn* raw,size_t){raw[1].address+=4;}).stop=="instruction_gap","Address gap rejects proof");
		Check(Run({Call(0x1000,0x4000)}, {},64,AsyncOperation::Await,true,
			[](cs_insn* raw,size_t){raw[0].detail->groups_count=255;}).stop=="instruction_gap","Malformed detail rejects proof safely");
		std::cout<<checks<<" async origin checks passed\n";
	} catch(const std::exception& e) {std::cerr<<e.what()<<'\n';return 1;}
}
