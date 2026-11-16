#include "CompletionAnalysis.h"
#include "SnapshotCodeAnalysis.h"
#include "Arm64Decode.h"
#include <iostream>
#include <stdexcept>
using namespace SnapshotAnalysis;
namespace {
unsigned checks=0;
void Check(bool ok,const char* why) {++checks;if(!ok)throw std::runtime_error(why);}
constexpr uint64_t Start=0x1000,Init=0x7000,Value=0x7100,Forward=0x7200,Await=0x7300,Alloc=0x8000,Other=0x8100,Error=0x7500;
uint32_t Transfer(size_t n,uint64_t target,bool call=true) {return (call?0x94000000U:0x14000000U)|((target-(Start+n*4))/4&0x3ffffff);}
uint32_t Cbz(size_t from,size_t to) {return 0xb4000001U|(((to-from)&0x7ffff)<<5);}
Profile Config() {
	Profile p{};p.wordReturnRegister=ARM64_REG_X0;p.nullRegister=ARM64_REG_X22;p.nullClassId=1;
	p.poolRegister=ARM64_REG_X27;p.poolDataOffset=16;p.poolSlotSize=8;p.poolLength=8;
	p.allocationReturns={{Alloc,7},{Other,8}};
	p.asyncContracts={{Init,{AsyncOperation::Init,Init+4}},{Value,{AsyncOperation::CompleteValue,Value+4}},
		{Forward,{AsyncOperation::CompleteValueOrFuture,Forward+4}},{Await,{AsyncOperation::Await,Await+4}}};
	p.completionExceptions={{Error,{Error+4,"null_cast_without_fpu",false}}};return p;
}
CompletionSummary Run(std::vector<uint32_t> words,std::vector<uint64_t> handlers={},std::set<uint64_t> entries={},
	bool metadata=true,size_t budget=2000000,const std::function<void(Profile&)>& configure={},
	const std::function<void(cs_insn*,size_t)>& mutate={}) {
	std::vector<uint8_t> bytes;for(auto w:words)for(unsigned i=0;i<4;++i)bytes.push_back(static_cast<uint8_t>(w>>(i*8)));
	csh handle=0;Check(cs_open(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN,&handle)==CS_ERR_OK,"decoder opens");cs_option(handle,CS_OPT_DETAIL,CS_OPT_ON);
	const auto [raw,count]=DecodeArm64Instructions(handle,bytes.data(),bytes.size(),Start);
	Check(count==words.size(),"authored instructions decode");auto p=Config();if(configure)configure(p);if(mutate)mutate(raw,count);
	CompletionBody body{Start+words.size()*4,metadata,true,handlers};
	auto value=AnalyzeCompletions(raw,count,p,body,entries,{},budget);cs_free(raw,count);cs_close(&handle);
	Check(value.has_value(),"completion candidate retained");return *value;
}
std::vector<uint32_t> Direct(uint64_t allocation=Alloc,uint64_t completion=Value) {return {Transfer(0,Init),Transfer(1,allocation),Transfer(2,completion,false)};}
}
int main() {
	try {
		auto s=Run(Direct());Check(s.status=="exact_heap_class" && s.exactClass==7 && s.closed,"direct completion class is distinct from Future return");
		s=Run(Direct(),{}, {},true,2000000,[](Profile& p){p.allocationResultRegister=ARM64_REG_X1;});Check(s.status=="unknown_value","allocation result requires matching ABI");
		s=Run({Transfer(0,Init),0xaa1603e0U,Transfer(2,Value,false)});Check(s.status=="null_only" && s.mayBeNull && !s.exactClass,"SDK null is not an invented heap-class success");
		s=Run({Transfer(0,Init),0xd2800000U,Transfer(2,Value,false)});Check(s.status=="unknown_value" && !s.mayBeNull,"raw zero is not null");
		s=Run(Direct(Alloc,Forward));Check(s.status=="value_or_future" && !s.exactClass && s.completions[0].classId==7,"generic completion input class is not delivered class");
		s=Run({Transfer(0,Init),Transfer(1,Await),Transfer(2,Value,false)});Check(s.status=="unknown_value","await delivery needs its own producer binding");
		s=Run(Direct(0x9000));Check(s.status=="unknown_value","unmodeled ordinary result remains unknown");
		const std::vector<uint32_t> branch={Transfer(0,Init),Cbz(1,4),Transfer(2,Alloc),Transfer(3,Value,false),Transfer(4,Alloc),Transfer(5,Value,false)};
		s=Run(branch);Check(s.exactClass==7 && s.completions.size()==2,"both explicit completion paths covered");
		auto conflict=branch;conflict[4]=Transfer(4,Other);s=Run(conflict);Check(s.status=="mixed_classes" && !s.exactClass,"conflicting completed classes refused");
		auto nullable=branch;nullable[4]=0xaa1603e0U;s=Run(nullable);Check(s.status=="nullable_class" && !s.exactClass,"null branch prevents exact nonnull class");
		s=Run(Direct(),{}, {},false);Check(s.status=="missing_exception_metadata" && !s.exactClass,"missing retained handler metadata refuses summary");
		s=Run(Direct(),{Start+100});Check(s.status=="missing_exception_metadata","invalid handler entry refused");
		s=Run(Direct(),{Start+8});Check(s.status=="unknown_value","handler can bypass the allocation");
		s=Run(conflict,{Start+16});Check(s.status=="mixed_classes","catch completion participates in agreement");
		s=Run(Direct(),{}, {Start+8});Check(!s.exactClass,"alternate entry bypasses local value proof");
		auto open=branch;open[5]=Transfer(5,0xa000,false);s=Run(open);Check(s.status=="open_control_flow","escaping branch prevents closed summary");
		auto ret=branch;ret[5]=0xd65f03c0U;s=Run(ret);Check(s.status=="open_control_flow","ordinary return is not async completion");
		auto error=branch;error[4]=Transfer(4,Error);error.resize(5);s=Run(error);Check(s.exactClass==7 && s.exits.size()==1,"matched error exit is separate from successful completion");
		s=Run(Direct(),{}, {},true,0);Check(s.status=="step_limit" && !s.exactClass,"budget exhaustion never publishes exact class");
		s=Run(Direct(),{}, {},true,2000000,[](Profile& p){p.completionExceptions.clear();});Check(s.exactClass==7,"irrelevant error contracts grant no type facts");
		auto clobber=Direct();clobber[1]=0xd2800016U;clobber.insert(clobber.end()-1,0xaa1603e0U);clobber.back()=Transfer(3,Value,false);
		s=Run(clobber);Check(s.status=="unknown_value","written null register invalidates canonical-null proof");
		Check(CompletionSummaryNote(s).find("no machine-return or await binding")!=std::string::npos,"presentation states missing consumer binding");
		std::cout<<checks<<" completion checks passed\n";return 0;
	}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
