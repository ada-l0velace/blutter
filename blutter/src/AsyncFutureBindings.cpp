#include "AsyncFutureBindings.h"
#include "SnapshotCodeAnalysis.h"
#include "Arm64Decode.h"
#include <algorithm>
#include <deque>
#include <iterator>
#include <memory>
#include <stdexcept>

namespace SnapshotAnalysis {
namespace {
constexpr size_t WorkLimit = 2000000, ProducerLimit = 4096, ChainLimit = 8;
bool Valid(const cs_insn& i)
{
	return i.detail && i.size == 4 && i.detail->groups_count <= std::size(i.detail->groups) &&
		i.detail->regs_write_count <= std::size(i.detail->regs_write) &&
		i.detail->arm64.op_count <= std::size(i.detail->arm64.operands);
}
bool Group(const cs_insn& i, unsigned group)
{
	return std::find(i.detail->groups, i.detail->groups+i.detail->groups_count, group) != i.detail->groups+i.detail->groups_count;
}
int Number(arm64_reg reg)
{
	if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) return reg-ARM64_REG_X0;
	if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) return reg-ARM64_REG_W0;
	if (reg == ARM64_REG_X29 || reg == ARM64_REG_X30) return reg == ARM64_REG_X29 ? 29 : 30;
	return -1;
}
std::optional<uint64_t> Target(const cs_insn& i)
{
	const auto& d = i.detail->arm64;
	if (!d.op_count || d.operands[d.op_count-1].type != ARM64_OP_IMM) return {};
	return static_cast<uint64_t>(d.operands[d.op_count-1].imm);
}
bool Unconditional(const cs_insn& i)
{
	return i.id == ARM64_INS_B && (i.detail->arm64.cc == ARM64_CC_INVALID || i.detail->arm64.cc == ARM64_CC_AL);
}
bool Metadata(const CompletionBody& body, uint64_t start, uint64_t end)
{
	return body.available && body.end == end && body.handlers.size() <= 1024 &&
		std::is_sorted(body.handlers.begin(), body.handlers.end()) &&
		std::adjacent_find(body.handlers.begin(), body.handlers.end()) == body.handlers.end() &&
		std::all_of(body.handlers.begin(), body.handlers.end(), [&](auto pc) { return pc >= start && pc < end && pc%4 == 0; });
}
bool Abi(const Profile& p)
{
	const auto offset = p.futureBindingAbi.suspendStateOffset;
	return p.futureBindingAbi.supported && p.wordReturnRegister == ARM64_REG_X0 &&
		offset >= -4096 && offset <= -8 && offset%8 == 0;
}
bool Candidate(const CompletionSummary& s)
{
	return s.closed && (s.status == "exact_heap_class" || s.status == "null_only" || s.status == "value_or_future");
}
std::optional<int64_t> Add(int64_t a, int64_t b)
{
	if ((b > 0 && a > INT64_MAX-b) || (b < 0 && a < INT64_MIN-b)) return {};
	return a+b;
}
unsigned Width(arm64_reg reg)
{
	if ((reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) || reg == ARM64_REG_X29 || reg == ARM64_REG_X30 || reg == ARM64_REG_XZR) return 8;
	if ((reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) || reg == ARM64_REG_WZR) return 4;
	if (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31) return 16;
	if (reg >= ARM64_REG_D0 && reg <= ARM64_REG_D31) return 8;
	if (reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31) return 4;
	return 0;
}
std::string QuotedName(const std::string& name)
{
	std::string text="\"";
	for (const unsigned char c:name) {
		if (c=='"' || c=='\\') {text+='\\';text+=c;}
		else if(c<32 || c==127) text+=std::format("\\x{:02x}",c);
		else text+=c;
	}
	return text+'"';
}
// Optional-argument prologues use an untagged address for exactly one load.
// The same register must be overwritten immediately; no pointer survives a
// call, store or intervening instruction. This admits no frame-address escape.
bool ConsumedFrameArgumentAddress(const cs_insn& add, const cs_insn& load)
{
	const auto& a=add.detail->arm64;const auto& l=load.detail->arm64;
	if (add.id!=ARM64_INS_ADD || a.op_count!=3 || a.writeback || a.update_flags ||
		a.operands[0].type!=ARM64_OP_REG || a.operands[1].type!=ARM64_OP_REG || a.operands[2].type!=ARM64_OP_REG ||
		a.operands[0].reg<ARM64_REG_X0 || a.operands[0].reg>ARM64_REG_X14 || a.operands[1].reg!=ARM64_REG_X29 ||
		a.operands[2].reg<ARM64_REG_W0 || a.operands[2].reg>ARM64_REG_W14 || a.operands[2].ext!=ARM64_EXT_SXTW ||
		a.operands[2].shift.type!=ARM64_SFT_LSL || a.operands[2].shift.value!=2) return false;
	return (load.id==ARM64_INS_LDR || load.id==ARM64_INS_LDUR) && l.op_count==2 && !l.writeback && !l.update_flags &&
		l.operands[0].type==ARM64_OP_REG && l.operands[0].reg==a.operands[0].reg && l.operands[1].type==ARM64_OP_MEM &&
		l.operands[1].mem.base==a.operands[0].reg && l.operands[1].mem.index==ARM64_REG_INVALID &&
		l.operands[1].mem.disp>=0 && l.operands[1].mem.disp<=4096 && l.operands[1].mem.disp%8==0;
}
struct Frame {
	bool anchored = false;
	// Highest possible SP offset from FP. A merge takes the maximum; an
	// unknown predecessor stays unknown. SP stores must be entirely below
	// the reserved slot for every represented stack depth.
	std::optional<int64_t> sp;
	bool savedFrame = false, spExact = false, cleared = false;
	bool operator==(const Frame&) const = default;
};
// This is the reserved compiler frame slot, not an application heap field.
// Reject escaping frame addresses; ordinary Dart calls must obey the matched
// frame ABI. No caller-frame preservation fact is granted to other analyses.
std::string FrameStep(const cs_insn& i, bool initialized, int64_t slot, Frame& frame)
{
	const auto& d = i.detail->arm64;
	const bool anchor = i.id == ARM64_INS_MOV && d.op_count == 2 && !d.writeback && !d.update_flags &&
		d.operands[0].type == ARM64_OP_REG && d.operands[0].reg == ARM64_REG_X29 &&
		d.operands[1].type == ARM64_OP_REG && d.operands[1].reg == ARM64_REG_X15;
	if (anchor) {
		if (initialized) return "frame_register_modified";
		if (!frame.savedFrame) return "unproved_frame_anchor";
		frame = {true, 0, true, true, false}; return {};
	}
	if (i.id==ARM64_INS_STP && d.op_count==3 && d.writeback && !d.update_flags &&
		d.operands[0].type==ARM64_OP_REG && d.operands[0].reg==ARM64_REG_X29 &&
		d.operands[1].type==ARM64_OP_REG && d.operands[1].reg==ARM64_REG_X30 &&
		d.operands[2].type==ARM64_OP_MEM && d.operands[2].mem.base==ARM64_REG_X15 &&
		d.operands[2].mem.index==ARM64_REG_INVALID && d.operands[2].mem.disp==-16) {
		if (initialized) return "nested_frame";
		frame = {false,{},true}; return {};
	}
	if (Group(i, CS_GRP_CALL) || Group(i, CS_GRP_JUMP) || i.id == ARM64_INS_NOP ||
		i.id == ARM64_INS_CMP || i.id == ARM64_INS_CMN || i.id == ARM64_INS_TST) return {};
	bool fpWrite = false, spWrite = false;
	for (unsigned n = 0; n < i.detail->regs_write_count; ++n) {
		fpWrite |= Number(static_cast<arm64_reg>(i.detail->regs_write[n])) == 29;
		spWrite |= Number(static_cast<arm64_reg>(i.detail->regs_write[n])) == 15;
	}
	for (unsigned n = 0; n < d.op_count; ++n) {
		const auto& op = d.operands[n];
		if (op.type == ARM64_OP_REG && (op.access&CS_AC_WRITE)) {
			fpWrite |= Number(op.reg) == 29;
			spWrite |= Number(op.reg) == 15;
		}
		if (op.type == ARM64_OP_MEM && d.writeback) {
			fpWrite |= Number(op.mem.base) == 29;
			spWrite |= Number(op.mem.base) == 15;
		}
	}
	for(unsigned n=0;n<d.op_count;++n) if(d.operands[n].type==ARM64_OP_REG && (d.operands[n].access&CS_AC_WRITE) && Number(d.operands[n].reg)==22)
		return "runtime_null_register_modified";
	for(unsigned n=0;n<i.detail->regs_write_count;++n) if(Number(static_cast<arm64_reg>(i.detail->regs_write[n]))==22)
		return "runtime_null_register_modified";
	if (fpWrite) {
		if (initialized) return "frame_register_modified";
		frame = {};
	}
	const bool adjust = (i.id == ARM64_INS_ADD || i.id == ARM64_INS_SUB) && d.op_count == 3 &&
		!d.writeback && !d.update_flags && d.operands[0].type == ARM64_OP_REG && d.operands[0].reg == ARM64_REG_X15 &&
		d.operands[1].type == ARM64_OP_REG && d.operands[1].reg == ARM64_REG_X15 &&
		d.operands[2].type == ARM64_OP_IMM && d.operands[2].imm >= 0 && d.operands[2].imm <= 1048576 && !d.operands[2].shift.value;
	if (adjust) {
		if(!frame.anchored)frame.savedFrame=false;
		if (frame.sp) frame.sp = Add(*frame.sp, d.operands[2].imm*(i.id == ARM64_INS_SUB ? -1 : 1));
		return {};
	}
	const bool pair = i.id == ARM64_INS_STP;
	const bool store = pair || i.id == ARM64_INS_STR || i.id == ARM64_INS_STUR || i.id == ARM64_INS_STRB ||
		i.id == ARM64_INS_STURB || i.id == ARM64_INS_STRH || i.id == ARM64_INS_STURH;
	if (store) {
		if (d.op_count != (pair ? 3 : 2) || d.operands[d.op_count-1].type != ARM64_OP_MEM) return "unsupported_frame_store";
		const auto& mem = d.operands[d.op_count-1].mem;
		const auto base = Number(mem.base);
		for (unsigned n = 0; n < d.op_count-1; ++n) {
			if (d.operands[n].type != ARM64_OP_REG) return "unsupported_frame_store";
			if (frame.anchored && (Number(d.operands[n].reg) == 29 || Number(d.operands[n].reg) == 15)) return "frame_address_escapes";
		}
		if (base == 29 || base == 15) {
			if (mem.index != ARM64_REG_INVALID || (d.writeback && base != 15)) return "unsupported_frame_store";
			const auto size = i.id == ARM64_INS_STRB || i.id == ARM64_INS_STURB ? 1U :
				i.id == ARM64_INS_STRH || i.id == ARM64_INS_STURH ? 2U : Width(d.operands[0].reg);
			if (!size || (pair && Width(d.operands[1].reg) != size)) return "unsupported_frame_store";
			if (!initialized && base==15 && !frame.spExact) frame.cleared=false;
			if (!initialized && (base==29 || frame.spExact)) {
				const auto begin=base==29?std::optional<int64_t>{mem.disp}:frame.sp?Add(*frame.sp,mem.disp):std::nullopt;
				if(begin) for(unsigned part=0;part<(pair?2U:1U);++part) {
					const auto at=Add(*begin,part*size);if(!at)continue;
					const auto stop=Add(*at,size);if(!stop)return "unknown_stack_address";
					if(*at<slot+8 && *stop>slot)
						frame.cleared=*at==slot && size==8 && d.operands[part].reg==ARM64_REG_X22;
				}
			}
			const auto controlEnd=Add(mem.disp,size*(pair?2:1));
			if (!controlEnd) return "unknown_stack_address";
			if (frame.anchored && base==29 && mem.disp<16 && *controlEnd>0)
				return "frame_control_overwritten";
			if (initialized) {
				const auto offset = base == 29 ? std::optional<int64_t>{mem.disp} : frame.sp ? Add(*frame.sp, mem.disp) : std::nullopt;
				if (!offset) return "unknown_stack_address";
				const auto stop = Add(*offset, size*(pair ? 2 : 1));
				if (!stop) return "unknown_stack_address";
				if (base==15 && *stop>slot) return "unproved_stack_write";
				if (base==29 && *offset<slot+8 && *stop>slot) return "suspend_state_overwritten";
			}
			if (d.writeback) {
				if (mem.disp >= 0 || mem.disp < -256 || mem.disp%8) return "unsupported_stack_update";
				if (frame.sp) frame.sp = Add(*frame.sp, mem.disp);
			}
		}
		return {};
	}
	for (unsigned n = 0; n < d.op_count; ++n) if (d.operands[n].type == ARM64_OP_MEM &&
		(Number(d.operands[n].mem.base) == 29 || Number(d.operands[n].mem.base) == 15)) {
		const bool load = i.id == ARM64_INS_LDR || i.id == ARM64_INS_LDUR || i.id == ARM64_INS_LDP ||
			i.id == ARM64_INS_LDRB || i.id == ARM64_INS_LDURB || i.id == ARM64_INS_LDRH || i.id == ARM64_INS_LDURH ||
			i.id == ARM64_INS_LDRSB || i.id == ARM64_INS_LDURSB || i.id == ARM64_INS_LDRSH || i.id == ARM64_INS_LDURSH ||
			i.id == ARM64_INS_LDRSW || i.id == ARM64_INS_LDURSW || i.id == ARM64_INS_LDTR ||
			i.id == ARM64_INS_LDTRB || i.id == ARM64_INS_LDTRH || i.id == ARM64_INS_LDTRSB ||
			i.id == ARM64_INS_LDTRSH || i.id == ARM64_INS_LDTRSW;
		if (!load || d.writeback) return "unsupported_frame_memory";
	}
	if (frame.anchored) {
		for (unsigned n = 0; n < d.op_count; ++n) {
			const auto& op = d.operands[n];
			if (op.type == ARM64_OP_REG && (op.access&CS_AC_READ) && (Number(op.reg) == 29 || Number(op.reg) == 15))
				return "frame_address_escapes";
		}
	}
	if (spWrite) {frame.sp.reset();frame.spExact=false;if(!frame.anchored)frame.savedFrame=false;}
	return {};
}
}
AwaitFutureInput ObserveAwaitFuture(const cs_insn* raw, size_t count, size_t consumer,
	const AsyncBoundary& boundary, const Profile& p, const CompletionBody& body,
	const std::function<bool(uint64_t)>& entryBoundary, size_t& remaining)
{
	AwaitFutureInput result{boundary, body, {"unknown", {}, 0}, "unknown"};
	if (!Abi(p)) { result.status = "unsupported_abi"; return result; }
	if (!raw || !count || count > 16384 || consumer >= count || !Valid(raw[consumer]) ||
		raw[consumer].address != boundary.site || raw[0].address != boundary.payload) {
		result.status = "unsupported_input"; return result;
	}
	if (boundary.payload>UINT64_MAX-count*4) {result.status="unsupported_input";return result;}
	if (!Metadata(body,boundary.payload,boundary.payload+count*4)) {result.status="missing_caller_metadata";return result;}
	const auto& call=raw[consumer];
	const auto described=DescribeAsyncBoundary("call",boundary.site,boundary.payload,body.end,boundary.callee,p.asyncContracts);
	if (call.id!=ARM64_INS_BL || call.detail->arm64.op_count!=1 || Target(call)!=boundary.callee || !described ||
		described->operation!=boundary.operation || described->resumeSite!=boundary.resumeSite ||
		(boundary.operation!=AsyncOperation::Await && boundary.operation!=AsyncOperation::AwaitWithTypeCheck) ||
		boundary.payload>UINT64_MAX-count*4) { result.status="unsupported_input"; return result; }
	if (!boundary.resumeSite) { result.status = "no_successful_continuation"; return result; }
	if (!remaining) { result.status = "step_limit"; return result; }
	result.origin = TraceWordInput(raw, count, consumer, {0, {}}, p, [&](uint64_t pc) {
		return entryBoundary(pc) || std::binary_search(body.handlers.begin(), body.handlers.end(), pc);
	}, std::min(size_t{64}, remaining));
	if (result.origin.steps > remaining) throw std::runtime_error("Future input exceeded its work bound");
	remaining -= result.origin.steps;
	result.status = "observed";
	return result;
}
static FutureProducer CheckFrameProtocol(const cs_insn* raw, size_t count, uint64_t entry,
	const Profile& p, const CompletionSummary& summary, const CompletionBody& body, size_t& remaining,
	bool requireValueCandidate, const std::set<uint64_t>& extraEntries, std::vector<AsyncFramePoint>* points)
{
	FutureProducer result; result.entry = entry; result.payload = summary.payload; result.end = summary.end;
	auto fail = [&](std::string status) { result.status = std::move(status); return result; };
	if (!Abi(p)) return fail("unsupported_abi");
	if (requireValueCandidate ? !Candidate(summary) : !summary.closed) return fail("completion_unproved");
	if (!Metadata(body, summary.payload, summary.end)) return fail("missing_producer_metadata");
	if (summary.initializations.size() != 1) return fail("ambiguous_initialization");
	if (!raw || !count || count > 16384 || summary.end<=summary.payload || summary.payload%4 || summary.end%4 || raw[0].address != summary.payload || count*4 != summary.end-summary.payload ||
		entry < summary.payload || entry >= summary.end || entry%4) return fail("unsupported_entry");
	for (size_t n = 0; n < count; ++n)
		if (!Valid(raw[n]) || raw[n].address != summary.payload+n*4) return fail("invalid_decode");
	using Key = std::pair<size_t, bool>;
	std::map<Key, Frame> incoming;
	std::deque<Key> work;
	auto push = [&](uint64_t pc, bool initialized, Frame frame) {
		if (pc < summary.payload || pc >= summary.end || pc%4) return false;
		Key key{(pc-summary.payload)/4, initialized};
		const auto [found, fresh] = incoming.emplace(key, frame);
		if (fresh) work.push_back(key);
		else {
			Frame merged{found->second.anchored && frame.anchored,
				found->second.sp && frame.sp ? std::optional<int64_t>{std::max(*found->second.sp,*frame.sp)} : std::nullopt,
				found->second.savedFrame && frame.savedFrame,
				found->second.spExact && frame.spExact && found->second.sp==frame.sp,
				found->second.cleared && frame.cleared};
			if (merged != found->second) { found->second = merged; work.push_back(key); }
		}
		return true;
	};
	push(entry, false, {});
	for (auto pc:extraEntries) if(pc>=summary.payload && pc<summary.end) push(pc,false,{});
	for (auto handler : body.handlers) push(handler, false, {true, {}});
	std::set<uint64_t> before, after, traps;
	std::map<uint64_t, std::string> boundaries;
	while (!work.empty()) {
		if (!remaining) return fail("step_limit");
		--remaining; ++result.steps;
		const auto [n, initialized] = work.front(); work.pop_front();
		auto frame = incoming.at({n, initialized});
		const auto& i = raw[n]; const auto target = Target(i);
		if(!initialized && !frame.cleared && Group(i,CS_GRP_CALL)) return fail("uninitialized_suspend_state");
		if(i.id==ARM64_INS_BRK) {traps.insert(i.address);continue;}
		(initialized ? after : before).insert(i.address);
		const auto exceptional = target ? p.completionExceptions.find(*target) : p.completionExceptions.end();
		if ((Group(i, CS_GRP_CALL) || Unconditional(i)) && exceptional != p.completionExceptions.end() &&
			(!exceptional->second.tailOnly || Unconditional(i))) continue;
		if (target && Group(i, CS_GRP_CALL) && p.nonReturningCalls.contains(*target)) continue;
		const auto op = target && p.asyncContracts.contains(*target) ? p.asyncContracts.at(*target).operation : AsyncOperation::Unknown;
		if (Group(i, CS_GRP_CALL) && op == AsyncOperation::Init) {
			if (i.address != summary.initializations[0] || initialized) return fail("repeated_initialization");
			if (!frame.anchored || !frame.sp || *frame.sp > p.futureBindingAbi.suspendStateOffset) return fail("unproved_frame_anchor");
			if (n+1 == count) return fail("escaping_control_flow");
			push(i.address+4, true, frame); continue;
		}
		if ((Unconditional(i) && (op == AsyncOperation::CompleteValue || op == AsyncOperation::CompleteValueOrFuture)) ||
			(Group(i, CS_GRP_CALL) && (op == AsyncOperation::Await || op == AsyncOperation::AwaitWithTypeCheck))) {
			if (!initialized) return fail("initialization_bypassed");
			if (!frame.anchored || !frame.sp || *frame.sp > p.futureBindingAbi.suspendStateOffset) return fail("unproved_stack_boundary");
			boundaries.emplace(i.address, AsyncOperationName(op));
			if (Unconditional(i)) continue;
		}
		if (initialized || n+1==count || !ConsumedFrameArgumentAddress(i,raw[n+1])) {
			if (const auto invalid=FrameStep(i,initialized,p.futureBindingAbi.suspendStateOffset,frame);!invalid.empty()) return fail(invalid);
		}
		if (Group(i, CS_GRP_RET) || Group(i, CS_GRP_INT) || i.id == ARM64_INS_UDF) return fail("unmodeled_exit");
		if (Group(i, CS_GRP_JUMP) && !Group(i, CS_GRP_CALL)) {
			if (!target || !push(*target, initialized, frame)) return fail("escaping_control_flow");
			if (Unconditional(i)) continue;
		}
		if (n+1 == count) return fail("escaping_control_flow");
		push(i.address+4, initialized, frame);
	}
	if (boundaries.empty()) return fail("no_return_boundary");
	result.beforeInit.assign(before.begin(), before.end()); result.afterInit.assign(after.begin(), after.end());
	result.traps.assign(traps.begin(),traps.end());
	for (const auto& [pc, operation] : boundaries) result.boundaries.push_back({pc, operation});
	if (points) for (const auto& [key, frame] : incoming) {
		if (key.second && frame.anchored && frame.sp && !incoming.contains({key.first,false}))
			points->push_back({raw[key.first].address,*frame.sp,frame.spExact});
	}
	result.status = "matched_async_frame";
	return result;
}
FutureProducer CheckFutureProducer(const cs_insn* raw,size_t count,uint64_t entry,const Profile& p,
	const CompletionSummary& summary,const CompletionBody& body,size_t& remaining)
{
	return CheckFrameProtocol(raw,count,entry,p,summary,body,remaining,true,{},nullptr);
}
AsyncReferenceFrame CheckAsyncReferenceFrame(const cs_insn* raw,size_t count,const Profile& p,
	const CompletionSummary& summary,const CompletionBody& body,const std::set<uint64_t>& entries,size_t& remaining)
{
	AsyncReferenceFrame result;
	if (!body.asyncErrorHandler) { result.protocol.payload=summary.payload;result.protocol.status="missing_async_handler";return result; }
	// Native SP may alias a Dart frame during native transitions. This phase
	// does not prove native-stack addressing or expose it to opaque callees.
	for(size_t n=0;raw && count<=16384 && n<count;++n) if(Valid(raw[n])) {
		const auto& d=raw[n].detail->arm64;
		for(unsigned k=0;k<d.op_count;++k) {
			const auto& op=d.operands[k];
			if((op.type==ARM64_OP_REG && (op.reg==ARM64_REG_SP || op.reg==ARM64_REG_WSP)) ||
				(op.type==ARM64_OP_MEM && op.mem.base==ARM64_REG_SP)) {
				result.protocol.payload=summary.payload;result.protocol.status="native_stack_access";return result;
			}
		}
	}
	result.protocol=CheckFrameProtocol(raw,count,summary.payload,p,summary,body,remaining,false,entries,&result.points);
	return result;
}
FutureBindingsResult BindAwaitFutures(const Profile& p, const std::vector<CompletionSummary>& summaries,
	const std::vector<AwaitFutureInput>& inputs, const std::map<uint64_t, std::vector<uint8_t>>& bytes, size_t remaining)
{
	if (remaining>WorkLimit) throw std::runtime_error("Invalid future-binding work bound");
	FutureBindingsResult result; result.remaining = remaining;
	std::map<uint64_t, const CompletionSummary*> index;
	for (const auto& s : summaries) index.emplace(s.payload, &s);
	auto summaryAt = [&](uint64_t entry) -> const CompletionSummary* {
		auto found = index.upper_bound(entry);
		if (found == index.begin()) return nullptr;
		--found;
		return entry < found->second->end ? found->second : nullptr;
	};
	struct Decoder { csh handle = 0; ~Decoder() { if (handle) cs_close(&handle); } } decoder;
	if (Abi(p) && !inputs.empty() && (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &decoder.handle) != CS_ERR_OK ||
		cs_option(decoder.handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)) throw std::runtime_error("Cannot initialize future-binding decoder");
	std::map<uint64_t, FutureProducer> producers;
	std::set<uint64_t> pending;
	for (const auto& input : inputs) if (input.origin.source && input.origin.source->kind == "post_call_x0" && input.origin.source->callee)
		pending.insert(*input.origin.source->callee);
	while (!pending.empty() && producers.size() < ProducerLimit) {
		const auto entry = *pending.begin(); pending.erase(pending.begin());
		if (producers.contains(entry)) continue;
		FutureProducer producer; producer.entry = entry;
		const auto* s = summaryAt(entry);
		if (!s) producer.status = "no_completion_summary";
		else {
			producer.payload = s->payload; producer.end = s->end;
			if (!Abi(p)) producer.status = "unsupported_abi";
			else if (!Candidate(*s)) producer.status = "completion_unproved";
			else if (!bytes.contains(s->payload)) producer.status = "producer_byte_limit";
			else if (!p.completionBodies.contains(s->payload)) producer.status = "missing_producer_metadata";
			else {
				const auto& code = bytes.at(s->payload);
				const auto [raw, count] = DecodeArm64Instructions(decoder.handle, code.data(), code.size(), s->payload);
				const std::shared_ptr<cs_insn> owner(raw, [count](cs_insn* v) { cs_free(v, count); });
				producer = CheckFutureProducer(raw, count, entry, p, *s, p.completionBodies.at(s->payload), result.remaining);
				if (producer.status == "matched_async_frame") {
					for (const auto& v : s->completions) if (v.operation == AsyncOperation::CompleteValueOrFuture && v.origin.source &&
						v.origin.source->kind == "post_call_x0" && v.origin.source->callee) {
						producer.forwards.push_back({v.site, v.origin.source->site, *v.origin.source->callee});
						if (!producers.contains(*v.origin.source->callee)) pending.insert(*v.origin.source->callee);
					}
				}
			}
		}
		producers.emplace(entry, std::move(producer));
	}
	// Separate Future instances may chain completion values. Never make the
	// outer and inner Future aliases, or promote this into an ordinary return.
	std::set<uint64_t> visiting;
	std::function<bool(uint64_t, size_t)> resolve = [&](uint64_t entry, size_t depth) {
		if (!producers.contains(entry)) return false;
		auto& producer = producers.at(entry);
		if (producer.status != "matched_async_frame") return false;
		if (producer.valueStatus != "unknown") return producer.valueStatus == "conditional_value";
		if (!result.remaining) { producer.valueStatus = "step_limit"; return false; }
		--result.remaining;
		if (depth >= ChainLimit) { producer.valueStatus = "chain_limit"; return false; }
		if (!visiting.insert(entry).second) { producer.valueStatus = "cyclic_forwarding"; return false; }
		const auto* s = summaryAt(entry);
		std::optional<uint32_t> agreed;
		std::string status = "conditional_value";
		for (const auto& v : s->completions) {
			if (!result.remaining) { status = "step_limit"; break; }
			--result.remaining;
			std::optional<uint32_t> cid;
			if (v.operation == AsyncOperation::CompleteValue && v.classId) cid = v.classId;
			else if (v.operation == AsyncOperation::CompleteValueOrFuture && v.value == "null" && v.classId == p.nullClassId) cid = v.classId;
			else if (const auto forward = std::find_if(producer.forwards.begin(), producer.forwards.end(), [&](const auto& f) { return f.completion == v.site; }); forward != producer.forwards.end()) {
				if (resolve(forward->producer, depth+1)) cid = producers.at(forward->producer).classId;
			}
			if (!cid) { status = "completion_value_unproved"; break; }
			if (agreed && agreed != cid) { status = "conflicting_completion_values"; break; }
			agreed = cid;
		}
		visiting.erase(entry);
		producer.valueStatus = status;
		if (status == "conditional_value" && agreed) { producer.classId = agreed; producer.nullValue = agreed == p.nullClassId; return true; }
		return false;
	};
	for (auto& [entry, producer] : producers) resolve(entry, 0);
	for (const auto& input : inputs) {
		AwaitFutureBinding binding; binding.input = input; binding.status = input.status;
		if (input.status == "observed") {
			const auto& source = input.origin.source;
			if (!source || source->kind != "post_call_x0" || !source->callee) binding.status = "producer_origin_unproved";
			else {
				binding.call = source->site; binding.producer = source->callee;
				if (!producers.contains(*source->callee)) binding.status = "producer_limit";
				else {
					const auto& producer = producers.at(*source->callee);
					if (producer.payload) binding.producerPayload = producer.payload;
					if (producer.status != "matched_async_frame") binding.status = producer.status;
					else if (input.boundary.operation == AsyncOperation::AwaitWithTypeCheck) binding.status = "typed_await_delivery_unproved";
					else if (producer.valueStatus != "conditional_value") binding.status = producer.valueStatus;
					else {
						binding.status = "conditional_delivery"; binding.classId = producer.classId;
						binding.value = producer.nullValue ? "null" : "heap_class";
					}
				}
			}
		}
		result.bindings.push_back(std::move(binding));
	}
	for (auto& [entry, producer] : producers) result.producers.push_back(std::move(producer));
	result.steps = WorkLimit-result.remaining;
	return result;
}
std::string AwaitFutureBindingNote(const AwaitFutureBinding& b, const std::function<std::string(uint32_t)>& className)
{
	if (b.status != "conditional_delivery" || !b.classId || !b.call || !b.producer) return {};
	const auto name = className ? className(*b.classId) : std::string{};
	const auto value = b.value == "null" ? std::string{"null"} : std::format("heap class {:#x}", *b.classId);
	return std::format("async delivered-value: X0 {}{} [conditional: Future from call {:#x} to {:#x}; await {:#x}; successful SDK resume; value/error-preserving callbacks; no ordinary return claim]",
		value, name.empty() ? "" : std::format(" ({})", QuotedName(name)), *b.call, *b.producer, b.input.boundary.site);
}
}
