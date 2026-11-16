#include "CompletionAnalysis.h"
#include "SnapshotCodeAnalysis.h"
#include <algorithm>
#include <deque>
#include <format>
#include <iterator>
#include <stdexcept>

namespace SnapshotAnalysis {
namespace {
bool Valid(const cs_insn& i) {
	return i.detail && i.size == 4 && i.detail->groups_count <= std::size(i.detail->groups) &&
		i.detail->regs_write_count <= std::size(i.detail->regs_write) && i.detail->arm64.op_count <= std::size(i.detail->arm64.operands);
}
bool Group(const cs_insn& i, unsigned group) {
	return std::find(i.detail->groups, i.detail->groups+i.detail->groups_count, group) != i.detail->groups+i.detail->groups_count;
}
int Number(arm64_reg reg) {
	if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) return reg-ARM64_REG_X0;
	if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) return reg-ARM64_REG_W0;
	if (reg == ARM64_REG_X29 || reg == ARM64_REG_X30) return reg == ARM64_REG_X29 ? 29 : 30;
	return -1;
}
std::optional<uint64_t> Target(const cs_insn& i) {
	const auto& d=i.detail->arm64;
	if (!d.op_count || d.operands[d.op_count-1].type != ARM64_OP_IMM) return {};
	return static_cast<uint64_t>(d.operands[d.op_count-1].imm);
}
bool Unconditional(const cs_insn& i) {
	return i.id == ARM64_INS_B && (i.detail->arm64.cc == ARM64_CC_INVALID || i.detail->arm64.cc == ARM64_CC_AL);
}
bool Completion(AsyncOperation op) { return op == AsyncOperation::CompleteValue || op == AsyncOperation::CompleteValueOrFuture; }
}
std::optional<CompletionSummary> AnalyzeCompletions(const cs_insn* raw, size_t count,
	const Profile& p, const CompletionBody& body, const std::set<uint64_t>& externalEntries,
	const std::map<uint64_t,int64_t>& poolLoads, size_t& remaining)
{
	if (!raw || !count || count > 16384 || p.wordReturnRegister != ARM64_REG_X0 || !raw[0].address ||
		raw[0].address%4 || raw[0].address > UINT64_MAX-count*4) return {};
	const uint64_t start=raw[0].address,end=start+count*4;
	std::map<size_t,AsyncOperation> sites;
	for (size_t n=0;n<count;++n) {
		if (!Valid(raw[n]) || raw[n].address != start+n*4) return {};
		if (!Unconditional(raw[n])) continue;
		const auto target=Target(raw[n]);
		if (target && p.asyncContracts.contains(*target) && Completion(p.asyncContracts.at(*target).operation))
			sites.emplace(n,p.asyncContracts.at(*target).operation);
	}
	if (sites.empty()) return {};
	CompletionSummary result{start,end};
	auto step=[&]() { if (!remaining) { result.status="step_limit";return false; } --remaining;++result.steps;return true; };
	std::set<uint64_t> entries=externalEntries;
	bool canonicalNull=p.nullRegister == ARM64_REG_X22 && p.nullClassId != 0;
	for (size_t n=0;n<count;++n) {
		if (!step()) return result;
		const auto& i=raw[n];const auto& d=i.detail->arm64;
		for (unsigned k=0;k<i.detail->regs_write_count;++k)
			if (Number(static_cast<arm64_reg>(i.detail->regs_write[k])) == 22) canonicalNull=false;
		for (unsigned k=0;k<d.op_count;++k) {
			const auto& o=d.operands[k];
			if ((o.type==ARM64_OP_REG && (o.access&CS_AC_WRITE) && Number(o.reg)==22) ||
				(o.type==ARM64_OP_MEM && d.writeback && Number(o.mem.base)==22)) canonicalNull=false;
		}
		if (Group(i,CS_GRP_JUMP) || Group(i,CS_GRP_CALL)) if (const auto target=Target(i)) entries.insert(*target);
	}
	bool metadata=body.available && body.end==end && body.handlers.size()<=1024 &&
		std::is_sorted(body.handlers.begin(),body.handlers.end()) && std::adjacent_find(body.handlers.begin(),body.handlers.end())==body.handlers.end();
	for (auto pc:body.handlers) if (pc<start || pc>=end || pc%4) metadata=false;
	if (metadata) entries.insert(body.handlers.begin(),body.handlers.end());
	for (auto pc:entries) if (pc>=start && pc<end && pc%4==0) result.entries.push_back(pc);
	if (!std::binary_search(result.entries.begin(),result.entries.end(),start)) result.entries.insert(result.entries.begin(),start);
	for (const auto& [n,op]:sites) {
		CompletionObservation value{raw[n].address,*Target(raw[n]),op};
		if (!remaining) { result.status="step_limit";return result; }
		value.origin=TraceWordInput(raw,count,n,{0,{}},p,[&](uint64_t pc){return entries.contains(pc);},std::min(remaining,size_t{64}),true,
			canonicalNull ? std::optional<uint16_t>{22} : std::nullopt);
		if (value.origin.steps>remaining) throw std::runtime_error("Completion origin exceeded its work bound");
		remaining-=value.origin.steps;result.steps+=value.origin.steps;
		if (value.origin.source) {
			const auto& source=*value.origin.source;
			if (source.kind=="runtime_null") { value.value="null";value.basis="sdk_null_register";value.classId=p.nullClassId; }
			else if (source.kind=="literal") { value.value="word";value.basis="original_word"; }
			else if (source.kind=="post_call_x0" && source.callee) {
				if (const auto found=p.allocationReturns.find(*source.callee);found!=p.allocationReturns.end() && p.allocationResultRegister==ARM64_REG_X0) {value.classId=found->second;value.basis="allocation";}
				else if (const auto found=p.nativeReturnClasses.find(*source.callee);found!=p.nativeReturnClasses.end()) {value.classId=found->second.classId;value.basis="sdk_native_result";}
				else if (const auto found=p.sdkStubReturnClasses.find(*source.callee);found!=p.sdkStubReturnClasses.end()) {value.classId=found->second.classId;value.basis="sdk_stub_result";}
			} else if (source.kind=="load" && poolLoads.contains(source.site) && p.poolHeapClass) {
				value.poolIndex=poolLoads.at(source.site);value.classId=p.poolHeapClass(*value.poolIndex);value.basis="checked_pool_object";
			}
			if (value.classId) {
				if (!*value.classId) throw std::runtime_error("Invalid completion heap class");
				value.value=*value.classId==p.nullClassId ? "null" : "heap_class";
			}
		}
		result.completions.push_back(std::move(value));
	}
	std::deque<size_t> work;std::vector<bool> seen(count);
	for (auto pc:result.entries) work.push_back((pc-start)/4);
	bool closed=true;
	auto escape=[&](const cs_insn& i,std::string kind,std::optional<uint64_t> target={}) { result.exits.push_back({i.address,target,std::move(kind)});closed=false; };
	auto append=[&](const cs_insn& i,uint64_t target) { if (target>=start && target<end && (target-start)%4==0) work.push_back((target-start)/4);else escape(i,"escaping_branch",target); };
	while (!work.empty()) {
		const auto n=work.front();work.pop_front();if (seen[n]) continue;seen[n]=true;
		if (!step()) return result;
		const auto& i=raw[n];const auto target=Target(i);
		result.reached.push_back(i.address);
		const auto exceptional=target ? p.completionExceptions.find(*target) : p.completionExceptions.end();
		if ((Group(i,CS_GRP_CALL) || Unconditional(i)) && exceptional!=p.completionExceptions.end() && (!exceptional->second.tailOnly || Unconditional(i))) {
			result.exits.push_back({i.address,target,"exception:"+exceptional->second.kind});continue;
		}
		if (sites.contains(n)) continue;
		if (Group(i,CS_GRP_RET)) { escape(i,"ordinary_return");continue; }
		if (Group(i,CS_GRP_INT) || i.id==ARM64_INS_UDF) { escape(i,"unmodeled_terminal");continue; }
		if (Group(i,CS_GRP_CALL)) {
			if (target && p.asyncContracts.contains(*target)) {
				const auto op=p.asyncContracts.at(*target).operation;
				if (op==AsyncOperation::Init) result.initializations.push_back(i.address);
				else if (op!=AsyncOperation::Await && op!=AsyncOperation::AwaitWithTypeCheck) {escape(i,"unsupported_async_call",target);continue;}
			}
			if (target && p.nonReturningCalls.contains(*target)) {result.exits.push_back({i.address,target,"exception:matched_nonreturning"});continue;}
		} else if (Group(i,CS_GRP_JUMP)) {
			if (!target) {escape(i,"indirect_exit");continue;}
			append(i,*target);if (Unconditional(i)) continue;
		}
		if (n+1<count) work.push_back(n+1);else escape(i,"fallthrough_exit");
	}
	std::sort(result.reached.begin(),result.reached.end());
	std::sort(result.initializations.begin(),result.initializations.end());
	std::sort(result.exits.begin(),result.exits.end(),[](const auto& a,const auto& b){return a.site<b.site;});
	for (const auto& value:result.completions) {
		result.valueOrFuture|=value.operation==AsyncOperation::CompleteValueOrFuture;
		result.mayBeNull|=value.value=="null";
		if (value.value=="heap_class") result.observedClasses.insert(*value.classId);
		else if (value.value!="null") result.hasUnknownValue=true;
		if (!std::binary_search(result.reached.begin(),result.reached.end(),value.site)) closed=false;
	}
	result.closed=closed && metadata && !result.initializations.empty();
	if (!metadata) result.status="missing_exception_metadata";
	else if (result.initializations.empty()) result.status="no_matched_initialization";
	else if (!closed) result.status="open_control_flow";
	else if (result.valueOrFuture) result.status="value_or_future";
	else if (result.hasUnknownValue) result.status="unknown_value";
	else if (result.observedClasses.empty()) result.status="null_only";
	else if (result.observedClasses.size()>1) result.status="mixed_classes";
	else if (result.mayBeNull) result.status="nullable_class";
	else {result.status="exact_heap_class";result.exactClass=*result.observedClasses.begin();}
	return result;
}
std::string CompletionSummaryNote(const CompletionSummary& s) {
	return s.exactClass ? std::format("async completion summary: heap class {:#x} [covered entries and direct value completions; errors separate; no machine-return or await binding]",*s.exactClass) :
		std::format("async completion summary: {} [partial value evidence; no machine-return or await binding]",s.status);
}
std::string CompletionValueNote(const CompletionObservation& v) {
	const auto text=v.value=="heap_class" ? std::format("heap class {:#x}",*v.classId) : v.value;
	return std::format("async completion operand: X0 {} [{}; {}; successful value only; no ordinary return claim]",text,v.basis,
		v.operation==AsyncOperation::CompleteValue ? "direct value" : "value or Future; delivered class unproved");
}
}
