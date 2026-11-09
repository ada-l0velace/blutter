#include "WordOrigins.h"
#include "CallInputOrigins.h"
#include "SnapshotCodeAnalysis.h"
#include "Arm64Decode.h"
#include <iostream>
#include <stdexcept>
using namespace SnapshotAnalysis;
namespace {
unsigned checks=0;
void Check(bool ok, const char* why) { ++checks; if (!ok) throw std::runtime_error(why); }
WordOriginResult Run(std::vector<uint32_t> words, WordLocation location, size_t limit=64,
    const std::function<void(cs_insn*,size_t)>& mutate={}) {
    words.push_back(0x94000400U); // authored consumer BL
    std::vector<uint8_t> bytes;
    for (auto word:words) for(unsigned i=0;i<4;++i) bytes.push_back(static_cast<uint8_t>(word>>(i*8)));
    csh handle=0;Check(cs_open(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN,&handle)==CS_ERR_OK,"decoder opens");
    cs_option(handle,CS_OPT_DETAIL,CS_OPT_ON);
    const auto [raw,count]=DecodeArm64Instructions(handle,bytes.data(),bytes.size(),0x1000);
    Check(count==words.size(),"all authored words decode");
    if (mutate) mutate(raw,count);
    Profile p{};p.wordReturnRegister=ARM64_REG_X0;p.heapBitsRegister=ARM64_REG_X28;
    auto result=TraceWordInput(raw,count,count-1,location,p,{},limit);
    cs_free(raw,count);cs_close(&handle);return result;
}
}
int main() {
    try {
        const WordLocation slot{0,NativeIr::Address{{15,64},0}};
        auto value=Run({0xd28000e0U,0xf81f8de0U},slot); // mov x0,#7; str x0,[x15,#-8]!
        Check(value.source && value.source->kind=="literal" && value.source->bits==7,"pre-index stack store");
        value=Run({0xd28000e0U,0xa9bf85e0U},slot); // stp x0,x1,[x15,#-8]!
        Check(value.source && value.source->bits==7,"pre-index pair first word");
        value=Run({0xd28000e0U,0xf90001e0U,0xd10021efU},{0,NativeIr::Address{{15,64},8}}); // str x0,[x15]; sub x15,x15,#8
        Check(value.source && value.source->bits==7,"backward stack adjustment");
        value=Run({0xd28000e0U,0xf90001e0U},slot,1);
        Check(!value.source && value.stop=="lookback_limit","bounded work stops before producer");
        value=Run({0xd503201fU},{31,{}});
        Check(!value.source && value.stop=="unsupported_input","invalid physical register");
        value=Run({0xf90001e0U},{0,NativeIr::Address{{15,64},INT64_MAX}});
        Check(!value.source && value.stop=="address_overflow","overflow rejected before interval arithmetic");
        value=Run({0xd503201fU},{1,{}},64,[](cs_insn* raw,size_t){raw[0].detail->arm64.op_count=255;});
        Check(!value.source && value.stop=="instruction_gap","malformed decoder operands rejected");
        value=Run({0xd503201fU},{1,{}});
        Check(value.source && value.source->kind=="entry_register" && value.source->bits==1,"entry register has no source parameter claim");
        CallInputOrigin note{0x1000,0x1000,"supplied_input",0,{},0,
            {{"input",{"load_endpoint",WordOrigin{"load",0x1000,{},{},NativeIr::Address{{27,64},40},{0x1000}},1},3}}};
        value=Run({0xaa1f03e0U},{0,{}});
        Check(value.source && value.source->bits==0,"zero-register literal");
        value=Run({0x92e00000U|(123U<<5)},{0,{}});
        Check(value.source && value.source->bits==~(uint64_t{123}<<48),"wide negative literal");
        const auto text=CallInputOriginNote(note,{{3,{"string_preview","a\nb\"",{}}}});
        Check(text.find("supplied input[0]")!=std::string::npos && text.find("\\x0a")!=std::string::npos && text.find('\n')==std::string::npos,"comment previews escape embedded newlines");
        std::cout<<checks<<" word-origin checks passed\n";return 0;
    } catch(const std::exception& error) { std::cerr<<error.what()<<'\n';return 1; }
}
