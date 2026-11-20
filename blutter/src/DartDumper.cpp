#include "pch.h"
#include "FieldInputOrigins.h"
#include "CapturedFieldValues.h"
#include "FreshFieldInitializations.h"
#include "FreshContentUses.h"
#include "CalleeEntryReads.h"
#include "DartDumper.h"
#include "ReadUnaligned.h"
#include <bit>
#include <cstring>
#include <fstream>
#include <format>
#include <set>
#include <ranges>
#include <iostream>
#include <sstream>
#include <numeric>
#ifdef HAS_INSTRUCTIONS_TABLE_RODATA
#include <vm/heap/safepoint.h>
#include <vm/stack_frame.h>
#include "SnapshotCodeAnalysis.h"
#include "SnapshotCodeRanges.h"
#include "CallResultAnnotations.h"
#include "CallInputAbi.h"
#ifdef BLUTTER_FIXED_STACK_INPUTS
#include <vm/dart_entry.h>
#include <vm/stack_frame.h>
#endif
#endif
#include "Disassembler.h"
#include "DartThreadInfo.h"
#include "CodeAnalyzer.h"
#include "RawAssembly.h"
#include "NativePayloadRouting.h"

// New engines split closure allocation into numbered stubs with a different
// ABI. Do not assign the older, reviewed contract to an unreviewed variant.
template <typename Stubs>
static const dart::Code* PlainClosureAllocationStub()
{
	if constexpr (requires { Stubs::AllocateClosure(); }) return &Stubs::AllocateClosure();
	else return nullptr;
}

// TODO: move arm64 specific code to *_arm64 file

static std::unordered_map<std::string, std::string> OP_MAP {
	{ "==", "eq" },
	{ "<", "lt" }, { ">", "gt" },
	{ "<=", "lte" }, { ">=", "gte" },
	{ "=", "assign" },
	{ "[]", "at" }, { "[]=", "at_assign" },
	{ "++", "increment" }, { "--", "decrement" },
	{ "+", "add" }, { "-", "sub" }, { "*", "mul" }, { "~/", "div" }, { "/", "divf" },
	{ "%", "mod" },
	{ "&", "LAnd" }, { "|", "LOr" }, { "^", "xor" }, { "~", "not" }, {">>", "shar"}, {"<<", "shal"}, {">>", "shr"}
};

// Names and pool comments are data, including backslashes and newlines.
// Emit a Python literal instead of inserting them into generated source.
static std::string pythonString(const std::string& value)
{
	std::string result = "\"";
	for (const unsigned char c : value) {
		if (c == '\\' || c == '"') {
			result += '\\';
			result += c;
		}
		else if (c < 0x20 || c == 0x7f) {
			result += std::format("\\x{:02x}", c);
		}
		else result += c;
	}
	return result + '"';
}

#ifdef HAS_INSTRUCTIONS_TABLE_RODATA
namespace {
template <typename Stubs>
static std::vector<std::pair<SnapshotAnalysis::StubInputKind, const dart::Code*>> InputRoleSdkReferences()
{
	using K = SnapshotAnalysis::StubInputKind;
	std::vector<std::pair<K, const dart::Code*>> result;
	if constexpr (requires { Stubs::AllocateArray(); }) result.emplace_back(K::Array, &Stubs::AllocateArray());
	if constexpr (requires { Stubs::AllocateClosure(); }) result.emplace_back(K::Closure, &Stubs::AllocateClosure());
	if constexpr (requires { Stubs::AllocateClosure1(); }) result.emplace_back(K::Closure1, &Stubs::AllocateClosure1());
	if constexpr (requires { Stubs::AllocateClosure2(); }) result.emplace_back(K::Closure2, &Stubs::AllocateClosure2());
	if constexpr (requires { Stubs::AllocateClosure3(); }) result.emplace_back(K::Closure3, &Stubs::AllocateClosure3());
	if constexpr (requires { Stubs::AllocateClosure4(); }) result.emplace_back(K::Closure4, &Stubs::AllocateClosure4());
	return result;
}
template <typename Closure, typename Abi>
static std::map<SnapshotAnalysis::StubInputKind,int64_t> ReadCaptureOffsets()
{
    using K = SnapshotAnalysis::StubInputKind;
    if constexpr (requires { Abi::kLengthAndFlagsReg; Closure::element_offset(0); })
        return {{K::Closure1, Closure::element_offset(0)-dart::kHeapObjectTag},
                {K::Closure2, Closure::element_offset(1)-dart::kHeapObjectTag},
                {K::Closure3, Closure::element_offset(2)-dart::kHeapObjectTag},
                {K::Closure4, Closure::element_offset(3)-dart::kHeapObjectTag}};
    else if constexpr (requires { Abi::kInstantiatorTypeArgsReg; Closure::context_offset(); })
        return {{K::Closure, Closure::context_offset()-dart::kHeapObjectTag}};
    return {};
}
static SnapshotAnalysis::ClosureCaptureLayout ReadClosureCaptureLayout()
{
    if constexpr (dart::kWordSize == 8 && dart::kCompressedWordSize == 4 &&
                  dart::kHeapObjectTag == 1 && dart::SP == dart::R15 && dart::FPREG == dart::R29)
        return {4,1,ReadCaptureOffsets<dart::Closure,dart::AllocateClosureABI>(),
            dart::runtime_frame_layout.first_local_from_fp*dart::kWordSize};
    return {};
}
static std::vector<SnapshotAnalysis::StubInputIdentity> ReadInputRoleIdentities(
	const std::vector<dart::CodePtr>& codes, uintptr_t base, uintptr_t begin, uintptr_t end)
{
	std::vector<SnapshotAnalysis::StubInputIdentity> result;
	auto* zone = dart::Thread::Current()->zone();
	auto& candidate = dart::Code::Handle(zone);
	auto& owner = dart::Object::Handle(zone);
	for (const auto& [kind, reference] : InputRoleSdkReferences<dart::StubCode>()) {
		if (reference->IsNull() || reference->Size() <= 0 || reference->Size() > (1 << 20)) continue;
		auto append = [&](const dart::Code& code) {
			const auto entry = code.EntryPoint(), payload = code.PayloadStart();
			if (code.Size() != reference->Size() || entry < begin || entry >= end || payload < begin || payload >= end ||
				static_cast<uint64_t>(code.Size()) > end-entry || static_cast<uint64_t>(code.Size()) > end-payload) return;
			if (std::memcmp(reinterpret_cast<const void*>(entry), reinterpret_cast<const void*>(reference->EntryPoint()), code.Size()) == 0)
				result.push_back({entry-base, payload-base, payload-base+code.Size(), kind, true});
		};
		append(*reference);
		for (const auto ptr : codes) {
			candidate = ptr;
			owner = candidate.owner();
			if (owner.IsNull()) append(candidate);
		}
	}
	return result;
}
static constexpr bool SupportedAsyncAbi()
{
	return dart::CallingConventions::kReturnReg == dart::R0 &&
		dart::SuspendStubABI::kArgumentReg == dart::R0 && dart::SuspendStubABI::kTypeArgsReg == dart::R1 &&
		dart::SuspendStubABI::kResumePcDistance == 0 && dart::InitSuspendableFunctionStubABI::kTypeArgsReg == dart::R0 &&
		dart::ReturnStubABI::kSuspendStateReg == dart::R2 && dart::ResumeStubABI::kSuspendStateReg == dart::R2 &&
		dart::ResumeStubABI::kResumePcReg == dart::R1 && dart::ResumeStubABI::kExceptionReg == dart::R3 &&
		dart::ResumeStubABI::kStackTraceReg == dart::R4;
}
static SnapshotAnalysis::FutureBindingAbi ReadFutureBindingAbi()
{
	if constexpr (dart::kWordSize == 8 && dart::FPREG == dart::R29 && dart::SP == dart::R15 && dart::NULL_REG == dart::R22) {
		if (!SupportedAsyncAbi()) return {};
		// The precompiled reader deliberately invalidates compiler::target's
		// frame layout. Its initialized runtime layout describes these AOT frames.
		const auto& layout=dart::runtime_frame_layout;
		if (layout.saved_caller_fp_from_fp!=0 || layout.saved_caller_pc_from_fp!=1 || layout.param_end_from_fp!=1) return {};
		const auto slot=layout.FrameSlotForVariableIndex(dart::SuspendState::kSuspendStateVarIndex);
		if (slot < -512 || slot >= 0) return {};
		return {true,slot*dart::kWordSize};
	}
	return {};
}
static SnapshotAnalysis::SavedFrameAbi ReadSavedFrameAbi()
{
	if (!ReadFutureBindingAbi().supported) return {};
	const auto& layout=dart::runtime_frame_layout;
	if (layout.last_param_from_entry_sp!=0 || layout.first_local_from_fp>=0 || layout.first_local_from_fp < -512) return {};
	return {true,layout.first_local_from_fp*dart::kWordSize};
}
static SnapshotAnalysis::SavedStackMap ReadSavedStackMap(const dart::InstructionsTable& table,
	uintptr_t base,uint64_t payload,uint64_t site)
{
	SnapshotAnalysis::SavedStackMap result{payload,site};
	const auto abi=ReadSavedFrameAbi();if(!abi.supported || site>UINTPTR_MAX-base-4)return result;
	dart::uword start=0;
	const auto* raw=dart::InstructionsTable::FindStackMap(table.ptr(),base+site+4,&start);
	if (!raw || start!=base+payload)return result;
	using Maps=dart::CompressedStackMaps;
	Maps::RawPayloadHandle maps,global;maps=raw;global=dart::InstructionsTable::GetCanonicalStackMap(table.ptr());
	if(maps.UsesGlobalTable() && global.IsNull())return result;
	Maps::Iterator<Maps::RawPayloadHandle> it(maps,global);
	if(!it.Find(base+site+4-start))return result;
	const auto spill=it.SpillSlotBitCount(),length=it.Length();
	if(spill<0 || spill>8192 || length<spill || length>16384)return result;
	result.available=true;result.spillSlots=static_cast<uint32_t>(spill);
	result.registerSlots=static_cast<uint32_t>(length-spill);
	for(intptr_t bit=spill;bit-->0;)if(it.IsObject(bit))result.objects.push_back(abi.firstLocalOffset-bit*8);
	return result;
}
template <typename Stubs>
static std::vector<std::pair<SnapshotAnalysis::AsyncOperation, const dart::Code*>> AsyncSdkReferences()
{
	using Op = SnapshotAnalysis::AsyncOperation;
	std::vector<std::pair<Op, const dart::Code*>> result;
	if constexpr (requires { Stubs::InitAsync(); }) result.emplace_back(Op::Init, &Stubs::InitAsync());
	if constexpr (requires { Stubs::Await(); }) result.emplace_back(Op::Await, &Stubs::Await());
	if constexpr (requires { Stubs::AwaitWithTypeCheck(); }) result.emplace_back(Op::AwaitWithTypeCheck, &Stubs::AwaitWithTypeCheck());
	if constexpr (requires { Stubs::ReturnAsyncNotFuture(); }) result.emplace_back(Op::CompleteValue, &Stubs::ReturnAsyncNotFuture());
	if constexpr (requires { Stubs::ReturnAsync(); }) result.emplace_back(Op::CompleteValueOrFuture, &Stubs::ReturnAsync());
	if constexpr (requires { Stubs::Resume(); }) result.emplace_back(Op::Resume, &Stubs::Resume());
	return result;
}
static std::vector<SnapshotAnalysis::AsyncStubIdentity> ReadAsyncStubIdentities(
	const std::vector<dart::CodePtr>& codes, uintptr_t base, uintptr_t begin, uintptr_t end)
{
	std::vector<SnapshotAnalysis::AsyncStubIdentity> result;
	auto* zone = dart::Thread::Current()->zone();
	auto& candidate = dart::Code::Handle(zone);
	auto& owner = dart::Object::Handle(zone);
	for (const auto& [operation, reference] : AsyncSdkReferences<dart::StubCode>()) {
		if (reference->IsNull() || reference->Size() <= 0 || reference->Size() > (1 << 20)) continue;
		auto append = [&](const dart::Code& code) {
			const auto entry = code.EntryPoint(), payload = code.PayloadStart();
			if (code.Size() != reference->Size() || entry < begin || entry >= end || payload < begin || payload >= end ||
				static_cast<uint64_t>(code.Size()) > end-entry || static_cast<uint64_t>(code.Size()) > end-payload) return;
			if (std::memcmp(reinterpret_cast<const void*>(entry), reinterpret_cast<const void*>(reference->EntryPoint()), code.Size()) == 0)
				result.push_back({entry-base, payload-base, payload-base+code.Size(), operation, true});
		};
		append(*reference);
		for (const auto ptr : codes) {
			candidate = ptr;
			owner = candidate.owner();
			if (owner.IsNull()) append(candidate);
		}
	}
	return result;
}
template <typename Stubs>
static std::vector<std::tuple<std::string,const dart::Code*,bool>> CompletionExceptionReferences()
{
	std::vector<std::tuple<std::string,const dart::Code*,bool>> result;
	if constexpr (requires { Stubs::NullCastErrorSharedWithoutFPURegs(); }) result.emplace_back("null_cast_without_fpu",&Stubs::NullCastErrorSharedWithoutFPURegs(),false);
	if constexpr (requires { Stubs::NullCastErrorSharedWithFPURegs(); }) result.emplace_back("null_cast_with_fpu",&Stubs::NullCastErrorSharedWithFPURegs(),false);
	if constexpr (requires { Stubs::Throw(); }) result.emplace_back("throw",&Stubs::Throw(),false);
	if constexpr (requires { Stubs::ReThrow(); }) result.emplace_back("rethrow",&Stubs::ReThrow(),false);
	if constexpr (requires { Stubs::AsyncExceptionHandler(); }) result.emplace_back("async_error",&Stubs::AsyncExceptionHandler(),true);
	return result;
}
static std::map<uint64_t,SnapshotAnalysis::CompletionException> ReadCompletionExceptions(
	const std::vector<dart::CodePtr>& codes, uintptr_t base, uintptr_t begin, uintptr_t end)
{
	std::map<uint64_t,SnapshotAnalysis::CompletionException> result;
	std::set<uint64_t> ambiguous;
	for (const auto& [kind,reference,tail]:CompletionExceptionReferences<dart::StubCode>()) {
		if (reference->IsNull() || reference->Size()<=0 || reference->Size()>(1<<20)) continue;
		auto append=[&](const dart::Code& code) {
			const auto start=code.PayloadStart();
			if (code.EntryPoint()!=start || start<begin || start>=end || code.Size()!=reference->Size() || static_cast<uint64_t>(code.Size())>end-start) return;
			if (std::memcmp(reinterpret_cast<const void*>(start),reinterpret_cast<const void*>(reference->EntryPoint()),code.Size())!=0 || ambiguous.contains(start-base)) return;
			const auto [found,inserted]=result.emplace(start-base,SnapshotAnalysis::CompletionException{start-base+code.Size(),kind,tail});
			if (!inserted && (found->second.kind!=kind || found->second.tailOnly!=tail)) {
				result.erase(found);ambiguous.insert(start-base);
			}
		};
		append(*reference);
		for (const auto ptr:codes) {
			const auto& code=dart::Code::Handle(ptr);
			if (code.owner()==dart::Object::null()) append(code);
		}
	}
	return result;
}
static SnapshotAnalysis::CompletionBody ReadCompletionBody(const dart::InstructionsTable& table,
	uintptr_t base,uint64_t payload,uint64_t end,size_t index)
{
	SnapshotAnalysis::CompletionBody result{end};
	const auto first=table.rodata()->first_entry_with_code;
	if (index<first) return result;
	const auto& codes=dart::Array::Handle(table.code_objects());
	if (index-first>=static_cast<uint64_t>(codes.Length())) return result;
	const auto& code=dart::Code::Handle(dart::Code::RawCast(codes.At(index-first)));
	if (code.IsNull() || code.IsUnknownDartCode() || code.PayloadStart()<base || code.PayloadStart()-base!=payload ||
		code.Size()<=0 || static_cast<uint64_t>(code.Size())!=end-payload) return result;
	const auto& handlers=dart::ExceptionHandlers::Handle(code.exception_handlers());
	if (handlers.IsNull() || handlers.num_entries()<0 || handlers.num_entries()>1024) return result;
	result.asyncErrorHandler=handlers.has_async_handler();
	for (intptr_t n=0;n<handlers.num_entries();++n) {
		const auto offset=handlers.HandlerPCOffset(n);
		if (offset==dart::ExceptionHandlers::kInvalidPcOffset) continue;
		if (offset>=end-payload || offset%4) return result;
		result.handlers.push_back(payload+offset);
	}
	std::sort(result.handlers.begin(),result.handlers.end());
	result.handlers.erase(std::unique(result.handlers.begin(),result.handlers.end()),result.handlers.end());
	result.available=true;return result;
}
struct VmNativeReturnRecord {
	SnapshotAnalysis::NativeReturnIdentity identity;
	uint32_t recognizedValue;
};
// Read retained fields before applying the independent identity selector.
// Include every alias at a candidate entry, including unsupported aliases.
static std::vector<VmNativeReturnRecord> ReadNativeReturnIdentities(
	const std::vector<dart::FunctionPtr>& functions, uintptr_t base)
{
	auto* zone = dart::Thread::Current()->zone();
	std::set<uintptr_t> candidates;
	for (const auto ptr : functions) {
		const auto& fn = dart::Function::Handle(zone, ptr);
		if (fn.recognized_kind() == dart::MethodRecognizer::kAllocateOneByteString ||
			fn.recognized_kind() == dart::MethodRecognizer::kAllocateTwoByteString) candidates.insert(fn.entry_point());
	}
	std::vector<VmNativeReturnRecord> result;
	for (const auto ptr : functions) {
		const auto& fn = dart::Function::Handle(zone, ptr);
		if (!candidates.contains(fn.entry_point()) || fn.entry_point() < base) continue;
		VmNativeReturnRecord record{{}, static_cast<uint32_t>(fn.recognized_kind())};
		auto& id = record.identity;
		id.entry = fn.entry_point() - base;
		id.isNative = fn.is_native();
		if (fn.recognized_kind() == dart::MethodRecognizer::kAllocateOneByteString) id.recognized = SnapshotAnalysis::NativeReturnKind::OneByteString;
		if (fn.recognized_kind() == dart::MethodRecognizer::kAllocateTwoByteString) id.recognized = SnapshotAnalysis::NativeReturnKind::TwoByteString;
		const auto& owner = dart::Class::Handle(zone, fn.Owner());
		if (!owner.IsNull()) {
			const auto& library = dart::Library::Handle(zone, owner.library());
			if (!library.IsNull()) {
				const auto& url = dart::String::Handle(zone, library.url());
				if (!url.IsNull()) id.libraryUri = url.ToCString();
			}
		}
		const auto& code = dart::Code::Handle(zone, fn.CurrentCode());
		if (!code.IsNull() && !code.IsUnknownDartCode() && code.EntryPoint() >= base && code.PayloadStart() >= base &&
			code.Size() > 0 && static_cast<uint64_t>(code.Size()) <= UINT64_MAX - code.PayloadStart()) {
			id.codeEntry = code.EntryPoint() - base;
			id.payload = code.PayloadStart() - base;
			id.end = id.payload + code.Size();
			id.ownsCode = code.owner() == fn.ptr();
		}
		if (id.isNative) {
			const auto& data = dart::Object::Handle(zone, fn.ptr()->untag()->data());
			if (data.IsArray() && dart::Array::Cast(data).Length() > 0) {
				const auto& name = dart::Object::Handle(zone, dart::Array::Cast(data).At(0));
				if (name.IsString()) id.nativeName = dart::String::Cast(name).ToCString();
			}
		}
		result.push_back(std::move(record));
	}
	return result;
}
// Legacy snapshots can retain byte-identical isolate copies of a VM stub.
// Select copies only by complete equality to the matched SDK reference, never
// by the display-name/partial-byte heuristics used for ordinary stub labels.
static std::vector<SnapshotAnalysis::SdkStubReturnIdentity> ReadSdkStubIdentities(
    const std::vector<dart::CodePtr>& codes, uintptr_t base, uintptr_t begin, uintptr_t end)
{
    std::vector<SnapshotAnalysis::SdkStubReturnIdentity> result;
    const auto& reference = dart::StubCode::AllocateGrowableArray();
    if (reference.IsNull() || reference.Size() <= 0 || reference.Size() > (1 << 20)) return result;
    auto* zone = dart::Thread::Current()->zone();
    auto append = [&](const dart::Code& code) {
        const auto entry = code.EntryPoint(), payload = code.PayloadStart();
        if (code.Size() != reference.Size() || entry < begin || entry >= end ||
            payload < begin || payload >= end || static_cast<uint64_t>(code.Size()) > end-entry ||
            static_cast<uint64_t>(code.Size()) > end-payload) return;
        const bool equal = std::memcmp(reinterpret_cast<const void*>(entry),
            reinterpret_cast<const void*>(reference.EntryPoint()), code.Size()) == 0;
        if (equal) result.push_back({entry-base, payload-base, payload-base+code.Size(),
            SnapshotAnalysis::SdkStubReturnKind::GrowableArray, true});
    };
    append(reference);
    for (const auto ptr : codes) {
        const auto& code = dart::Code::Handle(zone, ptr);
        const auto& owner = dart::Object::Handle(zone, code.owner());
        if (owner.IsNull()) append(code);
    }
    return result;
}
static std::string JsonNativeText(const std::string& value)
{
	std::string result = "\"";
	for (const unsigned char c : value) {
		if (c == '\\' || c == '"') { result += '\\'; result += c; }
		else if (c < 32) result += std::format("\\u{:04x}", c);
		else result += c;
	}
	return result + '"';
}
}
static SnapshotAnalysis::CallInputAbi ReadCallInputAbi()
{
#ifdef BLUTTER_FIXED_STACK_INPUTS
	if constexpr (dart::kWordSize == 8 && dart::SP == dart::R15 &&
		dart::compiler::target::kIntSpillFactor == 1 && dart::compiler::target::kDoubleSpillFactor == 1)
		return {true, static_cast<unsigned>(dart::ARGS_DESC_REG), dart::kWordSize, "verified_compiler_policy"};
#endif
	return {};
}
static SnapshotAnalysis::DescriptorPrologueAbi ReadDescriptorPrologueAbi()
{
#ifdef BLUTTER_DESCRIPTOR_PROLOGUE
	if (ReadCallInputAbi().supported && dart::kCompressedWordSize == 4 && dart::kSmiTagShift == 1) {
		SnapshotAnalysis::DescriptorPrologueAbi abi{true, static_cast<unsigned>(dart::ARGS_DESC_REG), dart::kCompressedWordSize, dart::kSmiTagShift,
			dart::ArgumentsDescriptor::type_args_len_offset()-dart::kHeapObjectTag,
			dart::ArgumentsDescriptor::size_offset()-dart::kHeapObjectTag,
			(dart::kParamEndSlotFromFp+1)*dart::kWordSize};
#ifdef BLUTTER_DESCRIPTOR_PARAMETERS
		abi.countOffset = dart::ArgumentsDescriptor::count_offset()-dart::kHeapObjectTag;
#endif
		return abi;
	}
#endif
	return {};
}
static std::map<int64_t, SnapshotAnalysis::CallInputDescriptor> ReadCallInputDescriptors(const dart::ObjectPool& pool)
{
	std::map<int64_t, SnapshotAnalysis::CallInputDescriptor> result;
#ifdef BLUTTER_FIXED_STACK_INPUTS
	// Validate storage before constructing the SDK wrapper; arbitrary Arrays
	// are not descriptors merely because their first elements are integers.
	if (!ReadCallInputAbi().supported) return result;
	if (dart::ArgumentsDescriptor::type_args_len_offset() != dart::Array::element_offset(0) ||
		dart::ArgumentsDescriptor::count_offset() != dart::Array::element_offset(1) ||
		dart::ArgumentsDescriptor::size_offset() != dart::Array::element_offset(2) ||
		dart::ArgumentsDescriptor::positional_count_offset() != dart::Array::element_offset(3) ||
		dart::ArgumentsDescriptor::first_named_entry_offset() != dart::Array::element_offset(4)) return result;
	auto& object = dart::Object::Handle();
	auto& item = dart::Object::Handle();
	for (intptr_t i = 0; i < pool.Length(); ++i) {
		if (pool.TypeAt(i) != dart::ObjectPool::EntryType::kTaggedObject) continue;
		object = pool.ObjectAt(i);
		if (!object.IsArray()) continue;
		const auto& array = dart::Array::Cast(object);
		if (array.Length() < 5 || array.Length() > 69 || array.Length()%2 != 1 || array.At(array.Length()-1) != dart::Object::null()) continue;
		bool valid = true;
		for (intptr_t n = 0; n < 4; ++n) {
			item = array.At(n);
			if (!item.IsSmi() || dart::Smi::Cast(item).Value() < 0) { valid = false; break; }
		}
		if (!valid) continue;
		const dart::ArgumentsDescriptor descriptor(array);
		SnapshotAnalysis::CallInputDescriptor value{i, descriptor.TypeArgsLen(), descriptor.Count(), descriptor.Size(), descriptor.PositionalCount()};
		const auto names = (array.Length()-5)/2;
		if (value.count < 1 || value.count > 32 || value.positional < 0 || value.positional > value.count || value.count-value.positional != names) continue;
		std::set<std::string> seen;
		for (intptr_t n = 0; n < names; ++n) {
			item = array.At(4+2*n);
			if (!item.IsString() || dart::String::Cast(item).Length() < 1 || dart::String::Cast(item).Length() > 1024) { valid = false; break; }
			bool embeddedNull = false;
			for (intptr_t k = 0; k < dart::String::Cast(item).Length(); ++k) if (dart::String::Cast(item).CharAt(k) == 0) { embeddedNull = true; break; }
			if (embeddedNull) { valid = false; break; }
			const std::string name = dart::String::Cast(item).ToCString();
			item = array.At(5+2*n);
			if (!item.IsSmi()) { valid = false; break; }
			const auto position = dart::Smi::Cast(item).Value();
			if (position < value.positional || position >= value.count || name.size() > 4096 || !seen.insert(name).second ||
				!value.named.emplace(static_cast<unsigned>(position), name).second) { valid = false; break; }
		}
		if (valid && SnapshotAnalysis::ValidCallInputDescriptor(value)) result.emplace(i, value);
	}
#endif
	return result;
}
static std::map<uint64_t, SnapshotAnalysis::CallInputModel> ReadCallInputModels(
	const std::vector<dart::FunctionPtr>& functions, uint64_t base,
	const std::map<uint64_t, uint64_t>& bounds, std::map<uint64_t, std::string>& rejections)
{
	std::map<uint64_t, SnapshotAnalysis::CallInputModel> result;
#ifdef BLUTTER_FIXED_STACK_INPUTS
	if (!ReadCallInputAbi().supported) return result;
	auto* zone = dart::Thread::Current()->zone();
	std::map<uint64_t, size_t> owners;
	for (auto ptr : functions) ++owners[dart::Function::Handle(zone, ptr).entry_point() - base];
	for (auto ptr : functions) {
		const auto& f = dart::Function::Handle(zone, ptr);
		const auto entry = f.entry_point() - base;
		if (f.kind() != dart::UntaggedFunction::kRegularFunction || !f.signature().IsHeapObject()) continue;
		const auto& signature = dart::FunctionType::Handle(zone, f.signature());
		if (signature.IsNull() || f.NumTypeParameters() <= 0) continue;
		auto reject = [&](const char* why) { rejections[entry] = why; };
		if (owners.at(entry) != 1) { reject("shared_retained_entry"); continue; }
		if (f.is_native() || f.is_abstract()) { reject("native_or_abstract_model"); continue; }
		if (signature.NumOptionalParameters() || f.NumParentTypeArguments()) { reject("unsupported_signature_model"); continue; }
		const auto implicit = signature.num_implicit_parameters();
		if (implicit != f.NumImplicitParameters() || implicit != (f.is_static() ? 0 : 1)) { reject("inconsistent_implicit_count"); continue; }
		auto range = bounds.upper_bound(entry);
		if (range == bounds.begin() || entry % 4 || entry >= std::prev(range)->second) { reject("unbounded_model_entry"); continue; }
		SnapshotAnalysis::CallInputModel model{entry, signature.num_fixed_parameters(), implicit,
			f.NumTypeParameters(), f.UserVisibleNameCString(), {}};
		if (model.fixed < 1 || model.fixed > 32 || signature.NumParameters() != model.fixed) { reject("unsupported_model_arity"); continue; }
		for (intptr_t i = 0; i < model.fixed; ++i) {
			const auto& type = dart::AbstractType::Handle(zone, signature.ParameterTypeAt(i));
			dart::ZoneTextBuffer text(zone); type.PrintName(dart::Object::kScrubbedName, &text);
			model.declaredTypes.emplace_back(text.buffer());
		}
		if (!SnapshotAnalysis::ValidCallInputModel(model)) throw std::runtime_error("Invalid SDK call-input model");
		result.emplace(entry, std::move(model));
	}
#endif
	return result;
}

static std::optional<SnapshotAnalysis::InputObject> ReadInputObject(const dart::ObjectPool& pool,
	int64_t index, uintptr_t base, uintptr_t codeStart, uintptr_t imageEnd)
{
		if (index < 0 || index >= pool.Length() || pool.TypeAt(index) != dart::ObjectPool::EntryType::kTaggedObject) return {};
		const auto& object = dart::Object::Handle(pool.ObjectAt(index));
		if (object.IsNull()) return SnapshotAnalysis::InputObject{"null", "null", {}};
		if (object.IsSmi()) return SnapshotAnalysis::InputObject{"smi", std::to_string(dart::Smi::Cast(object).Value()), {}};
		if (object.IsBool()) return SnapshotAnalysis::InputObject{"bool", object.ptr() == dart::Bool::True().ptr() ? "true" : "false", {}};
		if (object.IsString()) {
			const auto& text = dart::String::Cast(object);
			if (text.Length() > 1024) return {};
			// A bounded display preview, not an embedded-NUL-sensitive identity.
			return SnapshotAnalysis::InputObject{"string_preview", text.ToCString(), {}};
		}
		dart::FunctionPtr pointer;
		std::string kind;
		if (object.IsFunction()) { pointer = dart::Function::Cast(object).ptr(); kind = "function"; }
		else if (object.IsClosure()) { pointer = dart::Closure::Cast(object).function(); kind = "closure"; }
		else return {};
		const auto& function = dart::Function::Handle(pointer);
		if (function.IsNull()) return {};
		const auto entry = function.entry_point();
		if (entry < codeStart || entry >= imageEnd || (entry-base)%4) return {};
		std::string name = function.UserVisibleNameCString();
		if (name.size() > 4096) return {};
		SnapshotAnalysis::InputObject value{kind, std::move(name), entry-base};
        if (kind == "function" && function.kind() == dart::UntaggedFunction::kClosureFunction &&
            function.signature().IsHeapObject() && !function.is_native() && !function.is_abstract()) {
            const auto& signature = dart::FunctionType::Handle(function.signature());
            const auto& frame = dart::runtime_frame_layout;
            if (!signature.IsNull() && function.NumTypeParameters() == 0 &&
                signature.NumOptionalParameters() == 0 && function.NumImplicitParameters() == 1 &&
                signature.num_implicit_parameters() == 1 && signature.num_fixed_parameters() >= 1 &&
                signature.num_fixed_parameters() <= 32 &&
                signature.NumParameters() == signature.num_fixed_parameters() &&
                dart::kWordSize == 8 && dart::SP == dart::R15 && dart::FPREG == dart::R29 &&
                dart::compiler::target::kIntSpillFactor == 1 && dart::compiler::target::kDoubleSpillFactor == 1 &&
                frame.saved_caller_fp_from_fp == 0 && frame.saved_caller_pc_from_fp == 1 &&
                frame.last_param_from_entry_sp == 0) {
                const auto fixed = static_cast<unsigned>(signature.num_fixed_parameters());
                value.closureEntry = SnapshotAnalysis::ClosureEntryModel{entry-base,fixed,
                    static_cast<int64_t>((fixed-1)*dart::kWordSize)};
            }
        }
        return value;
}

// Optional numerical VM metadata audit, independent of IDA/asm exports.
void DartDumper::DumpCoverageAudit(const char* filename)
{
	std::ofstream of(filename);
	if (!of) throw std::runtime_error("Cannot create coverage audit");
	auto* thread = dart::Thread::Current();
	auto* zone = thread->zone();
	const auto& tables = dart::GrowableObjectArray::Handle(
		zone, thread->isolate_group()->object_store()->instructions_tables());
	of << "{\"tables\":[";
	for (intptr_t t = 0; !tables.IsNull() && t < tables.Length(); ++t) {
		if (t) of << ',';
		const auto& table = dart::InstructionsTable::Handle(
			zone, dart::InstructionsTable::RawCast(tables.At(t)));
		const auto& codes = dart::Array::Handle(zone, table.code_objects());
		const auto* data = table.rodata();
		const auto startPc = table.EntryPointAt(0) - data->entries()[0].pc_offset;
		of << std::format("{{\"index\":{},\"data_address\":{},\"start_pc\":{},\"count\":{},\"first_with_code\":{},\"retained_code_count\":{},\"entries\":[",
			t, reinterpret_cast<uintptr_t>(data) - app.base(), startPc - app.base(), data->length, data->first_entry_with_code, codes.Length());
		for (uint32_t i = 0; i < data->length; ++i) {
			if (i) of << ',';
			of << std::format("{{\"index\":{},\"entry\":{},\"pc_offset\":{},\"stack_map_offset\":{}",
				i, table.EntryPointAt(i) - app.base(), data->entries()[i].pc_offset, data->entries()[i].stack_map_offset);
			if (i >= data->first_entry_with_code) {
				const auto& code = dart::Code::Handle(zone,
					dart::Code::RawCast(codes.At(i - data->first_entry_with_code)));
				of << std::format(",\"code_entry\":{},\"payload\":{},\"size\":{},\"owner_cid\":{}",
					code.EntryPoint() - app.base(), code.PayloadStart() - app.base(), code.Size(), code.owner().GetClassId());
			}
			of << '}';
		}
		of << "]}";
	}
	of << "],\"known_functions\":[";
	bool comma = false;
	for (const auto& [address, fn] : app.functions) {
		if (comma) of << ','; comma = true;
		of << std::format("{{\"entry\":{},\"payload\":{},\"size\":{},\"native_library\":{},\"null_function\":{}}}",
			address, fn->PayloadAddress(), fn->Size(), &fn->Class().Library() == &app.nativeLib ? "true" : "false",
			fn->Ptr() == dart::Function::null() ? "true" : "false");
	}
	of << "],\"known_stubs\":[";
	comma = false;
	for (const auto& [address, stub] : app.stubs) {
		if (comma) of << ','; comma = true;
		of << std::format("{{\"entry\":{},\"size\":{}}}", address, stub->Size());
	}
	of << "],\"heap_functions\":[";
	class FunctionVisitor : public dart::ObjectVisitor {
	public:
		std::vector<dart::FunctionPtr> functions;
		std::vector<dart::CodePtr> codes;
		void VisitObject(dart::ObjectPtr object) override {
			if (object->IsFunction()) functions.push_back(dart::Function::RawCast(object));
			if (object->IsCode()) codes.push_back(dart::Code::RawCast(object));
		}
	} visitor;
	dart::HeapIterationScope iteration(thread);
	iteration.IterateOldObjects(&visitor);
	comma = false;
	for (const auto ptr : visitor.functions) {
		const auto& fn = dart::Function::Handle(zone, ptr);
		if (comma) of << ','; comma = true;
		const auto& code = dart::Code::Handle(zone, fn.CurrentCode());
		of << std::format("{{\"entry\":{},\"unknown_code\":{},\"has_code\":{}}}",
			fn.entry_point() - app.base(), code.IsUnknownDartCode() ? "true" : "false", fn.HasCode() ? "true" : "false");
	}
	of << "],\"function_metadata\":[";
	comma = false;
	for (const auto ptr : visitor.functions) {
		const auto& function = dart::Function::Handle(zone, ptr);
		const auto& owner = dart::Class::Handle(zone, function.Owner());
		const auto& code = dart::Code::Handle(zone, function.CurrentCode());
		std::string libraryUri;
		if (!owner.IsNull()) {
			const auto& library = dart::Library::Handle(zone, owner.library());
			if (!library.IsNull()) libraryUri = dart::String::Handle(zone, library.url()).ToCString();
		}
		if (comma) of << ','; comma = true;
		of << "{\"entry\":" << function.entry_point() - app.base()
			<< ",\"name\":" << JsonNativeText(function.UserVisibleNameCString())
			<< ",\"class_name\":" << JsonNativeText(owner.IsNull() || owner.IsTopLevel() ? "" : owner.ScrubbedNameCString())
			<< ",\"library_uri\":" << JsonNativeText(libraryUri)
			<< ",\"kind\":" << static_cast<int>(function.kind())
			<< ",\"registered_model\":" << (app.FindFunctionMetadata(ptr) ? "true" : "false")
			<< ",\"has_code\":" << (function.HasCode() ? "true" : "false")
			<< ",\"unknown_code\":" << (code.IsUnknownDartCode() ? "true" : "false");
#ifdef BLUTTER_FIXED_STACK_INPUTS
		const auto& sig = dart::FunctionType::Handle(zone, function.signature());
		of << ",\"call_input_model\":";
		if (sig.IsNull()) of << "null";
		else {
			of << "{\"fixed\":" << sig.num_fixed_parameters() << ",\"implicit\":" << sig.num_implicit_parameters()
			<< ",\"implicit_from_kind\":" << function.NumImplicitParameters() << ",\"optional\":" << sig.NumOptionalParameters()
			<< ",\"type_parameters\":" << function.NumTypeParameters() << ",\"parent_type_arguments\":" << function.NumParentTypeArguments()
			<< ",\"static\":" << (function.is_static() ? "true" : "false") << ",\"native\":" << (function.is_native() ? "true" : "false")
			<< ",\"abstract\":" << (function.is_abstract() ? "true" : "false") << ",\"declared_types\":[";
			for (intptr_t i = 0; i < sig.NumParameters(); ++i) {
				if (i) of << ',';
				const auto& type = dart::AbstractType::Handle(zone, sig.ParameterTypeAt(i));
				dart::ZoneTextBuffer text(zone); type.PrintName(dart::Object::kScrubbedName, &text);
				of << JsonNativeText(text.buffer());
			}
			of << "]}";
		}
#endif
		of << '}';
	}
	of << "],\"call_input_abi\":{\"supported\":" << (ReadCallInputAbi().supported ? "true" : "false")
		<< ",\"descriptor_register\":" << ReadCallInputAbi().descriptorRegister << ",\"word_bytes\":" << ReadCallInputAbi().wordBytes << "},\"call_input_descriptors\":[";
	comma = false;
	for (const auto& [index, d] : ReadCallInputDescriptors(app.GetObjectPool())) {
		if (comma) of << ','; comma = true;
		of << "{\"pool_index\":" << index << ",\"type_arguments\":" << d.typeArguments << ",\"count\":" << d.count
			<< ",\"size\":" << d.size << ",\"positional\":" << d.positional;
		if (!d.named.empty()) {
			of << ",\"named\":["; bool comma = false;
			for (const auto& [position, name] : d.named) { if (comma) of << ','; comma = true;
				of << "{\"index\":" << position << ",\"name\":" << JsonNativeText(name) << '}'; }
			of << ']';
		}
		of << '}';
	}
	of << "],\"descriptor_prologue_abi\":{\"supported\":" << (ReadDescriptorPrologueAbi().supported ? "true" : "false")
		<< ",\"descriptor_register\":" << ReadDescriptorPrologueAbi().descriptorRegister << ",\"field_bytes\":" << ReadDescriptorPrologueAbi().fieldBytes
		<< ",\"smi_shift\":" << ReadDescriptorPrologueAbi().smiShift << ",\"type_arguments_offset\":" << ReadDescriptorPrologueAbi().typeArgumentsOffset
		<< ",\"size_offset\":" << ReadDescriptorPrologueAbi().sizeOffset << ",\"frame_argument_base\":" << ReadDescriptorPrologueAbi().frameArgumentBase << ",\"count_offset\":" << ReadDescriptorPrologueAbi().countOffset << "},\"native_return_sdk\":[[" << dart::MethodRecognizer::kAllocateOneByteString << ',' << dart::kOneByteStringCid
		<< ",\"Internal_allocateOneByteString\",\"allocate_one_byte_string\"],[" << dart::MethodRecognizer::kAllocateTwoByteString << ',' << dart::kTwoByteStringCid
		<< ",\"Internal_allocateTwoByteString\",\"allocate_two_byte_string\"]],\"native_return_identities\":[";
	comma = false;
	for (const auto& record : ReadNativeReturnIdentities(visitor.functions, app.base())) {
		if (comma) of << ','; comma = true;
		const auto& id = record.identity;
		of << "{\"entry\":" << id.entry << ",\"code_entry\":" << id.codeEntry << ",\"payload\":" << id.payload << ",\"end\":" << id.end
			<< ",\"is_native\":" << (id.isNative ? "true" : "false") << ",\"owns_code\":" << (id.ownsCode ? "true" : "false")
			<< ",\"recognized_kind\":" << record.recognizedValue << ",\"native_name\":" << JsonNativeText(id.nativeName)
			<< ",\"library_uri\":" << JsonNativeText(id.libraryUri) << '}';
	}
	of << "],\"sdk_stub_return_sdk\":[[\"allocate_growable_array\",";
	const auto& growableClass = dart::Class::Handle(zone, thread->isolate_group()->class_table()->At(dart::kGrowableObjectArrayCid));
	of << growableClass.id() << "]],\"sdk_stub_return_reference\":";
	const auto& growableCode = dart::StubCode::AllocateGrowableArray();
	if (!growableCode.IsNull() && growableCode.Size() > 0) {
		of << "{\"entry\":" << growableCode.EntryPoint() - app.base()
			<< ",\"end\":" << growableCode.EntryPoint() - app.base() + growableCode.Size() << ",\"kind\":\"allocate_growable_array\"}";
	} else of << "null";
	of << ",\"sdk_stub_return_identities\":[";
	const auto image = reinterpret_cast<uintptr_t>(app.isolate_snapshot_instructions);
	const auto imageSize = *reinterpret_cast<const uintptr_t*>(image);
	if (imageSize > UINTPTR_MAX-image) throw std::runtime_error("Invalid instructions image size");
	comma = false;
	for (const auto& id : ReadSdkStubIdentities(visitor.codes, app.base(), image, image+imageSize)) {
		if (comma) of << ','; comma = true;
		of << "{\"entry\":" << id.entry << ",\"payload\":" << id.payload << ",\"end\":" << id.end << ",\"kind\":\"allocate_growable_array\"}";
	}
	of << "],\"completion_exception_references\":[";
	comma=false;
	for (const auto& [kind,reference,tail]:CompletionExceptionReferences<dart::StubCode>()) {
		if(reference->IsNull() || reference->Size()<=0 || reference->Size()>(1<<20))continue;
		if(comma)of<<',';comma=true;
		std::string bytes;const auto* raw=reinterpret_cast<const uint8_t*>(reference->EntryPoint());
		for(intptr_t n=0;n<reference->Size();++n)bytes+=std::format("{:02x}",raw[n]);
		of<<"{\"kind\":"<<JsonNativeText(kind)<<",\"tail_only\":"<<(tail?"true":"false")<<",\"bytes\":"<<JsonNativeText(bytes)<<'}';
	}
	of << "],\"completion_exception_identities\":[";comma=false;
	for(const auto& [entry,contract]:ReadCompletionExceptions(visitor.codes,app.base(),image,image+imageSize)) {
		if(comma)of<<',';comma=true;
		of<<"{\"entry\":"<<entry<<",\"end\":"<<contract.end<<",\"kind\":"<<JsonNativeText(contract.kind)<<",\"tail_only\":"<<(contract.tailOnly?"true":"false")<<'}';
	}
	of << "],\"completion_bodies\":[";comma=false;
	for(intptr_t t=0;!tables.IsNull() && t<tables.Length();++t) {
		const auto& table=dart::InstructionsTable::Handle(dart::InstructionsTable::RawCast(tables.At(t)));
		if(!table.rodata())continue;
		for(uint32_t n=table.rodata()->first_entry_with_code;n<table.rodata()->length;++n) {
			const auto start=table.EntryPointAt(n);
			const auto stop=n+1<table.rodata()->length?table.EntryPointAt(n+1):image+imageSize;
			const auto body=ReadCompletionBody(table,app.base(),start-app.base(),stop-app.base(),n);
			if(comma)of<<',';comma=true;
			of<<"{\"payload\":"<<start-app.base()<<",\"end\":"<<body.end<<",\"available\":"<<(body.available?"true":"false")
				<<",\"async_error_handler\":"<<(body.asyncErrorHandler?"true":"false")<<",\"handlers\":[";
			for(size_t k=0;k<body.handlers.size();++k){if(k)of<<',';of<<body.handlers[k];}of<<"]}";
		}
	}
	std::vector<std::pair<uint64_t,std::optional<uint32_t>>> capturedMapRegisters;
	of<<"],\"saved_reference_stack_maps\":[";comma=false;
	for(intptr_t t=0;!tables.IsNull() && t<tables.Length();++t) {
		const auto& table=dart::InstructionsTable::Handle(dart::InstructionsTable::RawCast(tables.At(t)));
		if(!table.rodata())continue;
		for(uint32_t n=table.rodata()->first_entry_with_code;n<table.rodata()->length;++n) {
			const auto start=table.EntryPointAt(n),stop=n+1<table.rodata()->length?table.EntryPointAt(n+1):image+imageSize;
			const auto body=ReadCompletionBody(table,app.base(),start-app.base(),stop-app.base(),n);
			if(!body.available || !body.asyncErrorHandler || stop<=start || stop-start>65536)continue;
			for(auto pc=start;pc+4<stop;pc+=4) {
				uint32_t word;std::memcpy(&word,reinterpret_cast<const void*>(pc),sizeof(word));
				if((word&0xfc000000U)!=0x94000000U && (word&0xfffffc1fU)!=0xd63f0000U)continue;
				const auto m=ReadSavedStackMap(table,app.base(),start-app.base(),pc-app.base());
				capturedMapRegisters.emplace_back(m.site,m.registerSlots);
				if(comma)of<<',';comma=true;of<<"{\"payload\":"<<m.payload<<",\"site\":"<<m.site<<",\"available\":"<<(m.available?"true":"false")<<",\"spill_slots\":"<<m.spillSlots<<",\"objects\":[";
				for(size_t k=0;k<m.objects.size();++k){if(k)of<<',';of<<m.objects[k];}of<<"]}";
			}
		}
	}
	of<<"],\"captured_field_register_slots\":[";
	for(size_t n=0;n<capturedMapRegisters.size();++n) {
		if(n)of<<',';const auto& [site,count]=capturedMapRegisters[n];
		of<<'['<<site<<','<<(count?std::to_string(*count):"null")<<']';
	}
	const auto savedAbi=ReadSavedFrameAbi();
	of<<"],\"saved_reference_abi\":{\"supported\":"<<(savedAbi.supported?"true":"false")<<",\"first_local_offset\":"<<savedAbi.firstLocalOffset<<'}';
	const auto futureAbi=ReadFutureBindingAbi();
	of << ",\"future_binding_abi\":{\"supported\":" << (futureAbi.supported?"true":"false")
		<< ",\"suspend_state_offset\":" << futureAbi.suspendStateOffset << '}';
	of << ",\"async_abi_supported\":" << (SupportedAsyncAbi() ? "true" : "false") << ",\"async_stub_references\":[";
	comma = false;
	for (const auto& [operation, reference] : AsyncSdkReferences<dart::StubCode>()) {
		if (reference->IsNull() || reference->Size() <= 0 || reference->Size() > (1 << 20)) continue;
		if (comma) of << ','; comma = true;
		std::string bytes;
		const auto* raw = reinterpret_cast<const uint8_t*>(reference->EntryPoint());
		for (intptr_t n = 0; n < reference->Size(); ++n) bytes += std::format("{:02x}", raw[n]);
		of << "{\"operation\":" << JsonNativeText(SnapshotAnalysis::AsyncOperationName(operation)) << ",\"bytes\":" << JsonNativeText(bytes) << '}';
	}
	of << "],\"async_stub_identities\":[";
	comma = false;
	for (const auto& id : ReadAsyncStubIdentities(visitor.codes, app.base(), image, image+imageSize)) {
		if (comma) of << ','; comma = true;
		of << "{\"entry\":" << id.entry << ",\"payload\":" << id.payload << ",\"end\":" << id.end
			<< ",\"operation\":" << JsonNativeText(SnapshotAnalysis::AsyncOperationName(id.operation)) << '}';
	}
	of << "],\"stub_input_abis\":[";
	comma = false;
	for (const auto& [kind, inputs] : SnapshotAnalysis::ReadStubInputAbis<dart::AllocateArrayABI, dart::AllocateClosureABI>()) {
		if (comma) of << ','; comma = true;
		of << "{\"kind\":" << JsonNativeText(SnapshotAnalysis::StubInputKindName(kind)) << ",\"inputs\":[";
		for (size_t n = 0; n < inputs.size(); ++n) {
			if (n) of << ',';
			of << "{\"register\":\"x" << inputs[n].reg << "\",\"role\":"
				<< JsonNativeText(SnapshotAnalysis::StubInputRoleName(inputs[n].role)) << '}';
		}
		of << "]}";
	}
	of << "],\"stub_input_references\":[";
	comma = false;
	for (const auto& [kind, reference] : InputRoleSdkReferences<dart::StubCode>()) {
		if (reference->IsNull() || reference->Size() <= 0 || reference->Size() > (1 << 20)) continue;
		if (comma) of << ','; comma = true;
		std::string bytes;
		const auto* raw = reinterpret_cast<const uint8_t*>(reference->EntryPoint());
		for (intptr_t n = 0; n < reference->Size(); ++n) bytes += std::format("{:02x}", raw[n]);
		of << "{\"kind\":" << JsonNativeText(SnapshotAnalysis::StubInputKindName(kind)) << ",\"bytes\":" << JsonNativeText(bytes) << '}';
	}
	of << "],\"stub_input_identities\":[";
	comma = false;
	for (const auto& id : ReadInputRoleIdentities(visitor.codes, app.base(), image, image+imageSize)) {
		if (comma) of << ','; comma = true;
		of << "{\"entry\":" << id.entry << ",\"payload\":" << id.payload << ",\"end\":" << id.end
			<< ",\"kind\":" << JsonNativeText(SnapshotAnalysis::StubInputKindName(id.kind)) << '}';
	}
	of << "],\"input_object_catalog\":[";
	comma = false;
	const auto& inputPool = app.GetObjectPool();
    std::vector<std::pair<int64_t,SnapshotAnalysis::ClosureEntryModel>> closureModels;
	for (intptr_t index = 0; index < inputPool.Length(); ++index) {
		const auto object = ReadInputObject(inputPool, index, app.base(), image, image+imageSize);
		if (!object) continue;
        if (object->closureEntry) closureModels.emplace_back(index,*object->closureEntry);
        if (comma) of << ','; comma = true;
		of << "{\"pool_index\":" << index << ",\"kind\":" << JsonNativeText(object->kind) << ",\"text\":" << JsonNativeText(object->text)
			<< ",\"entry\":" << (object->entry ? std::to_string(*object->entry) : "null") << '}';
	}
	of << R"(],"closure_capture_layout":)";
    SnapshotAnalysis::WriteClosureCaptureLayout(of,ReadClosureCaptureLayout());
    of << R"(,"closure_entry_models":[)";
    comma=false;
    std::set<uint64_t> closureEntries;
    for (const auto& [index,model] : closureModels) {
        if(comma)of<<',';comma=true;
        of << R"({"pool_index":)" << index << R"(,"entry":)" << model.entry
           << R"(,"fixed":)" << model.fixed << R"(,"entry_sp_offset":)" << model.entrySpOffset << '}';
        closureEntries.insert(model.entry);
    }
    of << R"(],"closure_capture_stack_maps":[)";comma=false;
    for (intptr_t t=0;!tables.IsNull() && t<tables.Length();++t) {
        const auto& table=dart::InstructionsTable::Handle(dart::InstructionsTable::RawCast(tables.At(t)));
        if(!table.rodata())continue;
        for(uint32_t n=0;n<table.rodata()->length;++n) {
            const auto start=table.EntryPointAt(n), stop=n+1<table.rodata()->length?table.EntryPointAt(n+1):image+imageSize;
            for(auto it=closureEntries.lower_bound(start-app.base());it!=closureEntries.end() && *it<stop-app.base();++it) {
                const auto end=std::min<uint64_t>(*it+64,stop-app.base());
                for(auto pc=*it;pc+4<=end;pc+=4) {
                    uint32_t word;std::memcpy(&word,reinterpret_cast<const void*>(app.base()+pc),4);
                    if((word&0xfc000000U)!=0x94000000U)continue;
                    const auto m=ReadSavedStackMap(table,app.base(),start-app.base(),pc);
                    if(comma)of<<',';comma=true;
                    of<<R"({"payload":)"<<m.payload<<R"(,"site":)"<<m.site<<R"(,"available":)"<<(m.available?"true":"false")
                      <<R"(,"spill_slots":)"<<m.spillSlots<<R"(,"register_slots":)"<<(m.registerSlots?std::to_string(*m.registerSlots):"null")<<R"(,"objects":[)";
                    for(size_t j=0;j<m.objects.size();++j){if(j)of<<',';of<<m.objects[j];}
                    of<<"]}";
                }
            }
        }
    }
    of << "],\"pool_heap_classes\":[";
	comma = false;
	const auto& pool = app.GetObjectPool();
	for (intptr_t i = 0; i < pool.Length(); ++i) if (pool.TypeAt(i) == dart::ObjectPool::EntryType::kTaggedObject) {
		const auto& object = dart::Object::Handle(zone, pool.ObjectAt(i));
		if (!object.IsSmi()) { if (comma) of << ','; comma = true; of << '[' << i << ',' << object.GetClassId() << ']'; }
	}
	of << "],\"word_return_register\":" << (dart::CallingConventions::kReturnReg == dart::R0 ? "\"x0\"" : "null");
	of << ",\"stack_limit_offset\":" << TargetThreadOffset(dart::Thread::stack_limit_offset());
	of << ",\"pool_code_entries\":[";
	comma = false;
	for (intptr_t i = 0; i < pool.Length(); ++i) if (pool.TypeAt(i) == dart::ObjectPool::EntryType::kTaggedObject) {
		const auto& object = dart::Object::Handle(zone, pool.ObjectAt(i));
		if (!object.IsCode()) continue;
		const auto& code = dart::Code::Cast(object);
		for (const auto kind : {dart::Code::EntryKind::kNormal, dart::Code::EntryKind::kUnchecked}) {
			const auto address = kind == dart::Code::EntryKind::kNormal ? code.EntryPoint() : code.UncheckedEntryPoint();
			if (!address) continue;
			if (comma) of << ','; comma = true;
			of << '[' << i << ',' << dart::Code::entry_point_offset(kind) - dart::kHeapObjectTag << ',' << address - app.base() << ']';
		}
	}
	of << "],\"leaf_math_contract\":[" << TargetThreadOffset(dart::Thread::LibcRound_entry_point_offset()) << ','
		<< TargetThreadOffset(dart::Thread::vm_tag_offset()) << ',' << TargetThreadOffset(dart::Thread::saved_stack_limit_offset()) << ',' << dart::VMTag::kDartTagId;
	of << "],\"thread_heap_classes\":[";
	// Audit actual cached objects independently of formatted names and pool facts.
	dart::ArrayPtr cachedEmptyArray;
	std::memcpy(&cachedEmptyArray, reinterpret_cast<const uint8_t*>(thread) + dart::Thread::empty_array_offset(), sizeof(cachedEmptyArray));
	const auto& emptyArray = dart::Object::Handle(zone, cachedEmptyArray);
	of << '[' << TargetThreadOffset(dart::Thread::empty_array_offset()) << ',' << emptyArray.GetClassId() << ']';
	of << "],\"frame_preserving_calls\":[";
#ifdef BLUTTER_NO_OBJECT_STORE_STUBS
	const auto& stackCheck = dart::StubCode::StackOverflowSharedWithoutFPURegs();
#else
	const auto& stackCheck = dart::Code::Handle(zone, thread->isolate_group()->object_store()->stack_overflow_stub_without_fpu_regs_stub());
#endif
	if (!stackCheck.IsNull()) of << '[' << stackCheck.EntryPoint() - app.base() << ",\"stack_overflow_without_fpu\"]";
#ifdef BLUTTER_NO_OBJECT_STORE_STUBS
	const auto& arrayBarrier = dart::StubCode::ArrayWriteBarrier();
#else
	const auto& arrayBarrier = dart::Code::Handle(zone, thread->isolate_group()->object_store()->array_write_barrier_stub());
#endif
	if (!arrayBarrier.IsNull()) {
		if (!stackCheck.IsNull()) of << ',';
		of << '[' << arrayBarrier.EntryPoint() - app.base() << ",\"array_write_barrier\"]";
	}
	const auto& doubleToInteger = dart::StubCode::DoubleToInteger();
	if (!doubleToInteger.IsNull()) {
		if (!stackCheck.IsNull() || !arrayBarrier.IsNull()) of << ',';
		of << '[' << doubleToInteger.EntryPoint() - app.base() << ",\"double_to_integer\"]";
	}
	of << "],\"nonreturning_calls\":[";
#ifdef BLUTTER_NO_OBJECT_STORE_STUBS
	const auto& rangeError = dart::StubCode::RangeErrorSharedWithoutFPURegs();
#else
	const auto& rangeError = dart::Code::Handle(zone, thread->isolate_group()->object_store()->range_error_stub_without_fpu_regs_stub());
#endif
	if (!rangeError.IsNull()) of << '[' << rangeError.EntryPoint() - app.base() << ",\"range_error_without_fpu\"]";
	of << "],\"predefined_allocations\":[";
#ifdef BLUTTER_NO_OBJECT_STORE_STUBS
	const auto& arrayAllocation = dart::StubCode::AllocateArray();
	const auto* closureAllocation = PlainClosureAllocationStub<dart::StubCode>();
	const auto& mintAllocation = dart::StubCode::AllocateMintSharedWithoutFPURegs();
#else
	const auto& arrayAllocation = dart::Code::Handle(zone, thread->isolate_group()->object_store()->allocate_array_stub());
	const auto* closureAllocation = &dart::Code::Handle(zone, thread->isolate_group()->object_store()->allocate_closure_stub());
	const auto& mintAllocation = dart::Code::Handle(zone, thread->isolate_group()->object_store()->allocate_mint_without_fpu_regs_stub());
#endif
	bool predefinedComma = false;
	auto auditPredefined = [&](const dart::Code& code, intptr_t cid) {
		if (code.IsNull()) return;
		const auto& cls = dart::Class::Handle(zone, thread->isolate_group()->class_table()->At(cid));
		if (predefinedComma) of << ','; predefinedComma = true;
		of << '[' << code.EntryPoint() - app.base() << ',' << cls.id() << ']';
	};
	auditPredefined(arrayAllocation, dart::kArrayCid);
	if (closureAllocation) auditPredefined(*closureAllocation, dart::kClosureCid);
	auditPredefined(mintAllocation, dart::kMintCid);
	of << "],\"field_decision_abi\":{\"supported\":"
        << ((dart::NULL_REG == dart::R22 && dart::compiler::target::kCompressedWordSize == 4) ? "true" : "false")
        << ",\"true_offset\":" << dart::compiler::target::ObjectAlignment::kTrueOffsetFromNull
        << ",\"false_offset\":" << dart::compiler::target::ObjectAlignment::kFalseOffsetFromNull << "}";
    of << ",\"heap_bits_register\":" << (dart::compiler::target::kCompressedWordSize == 4 && dart::HEAP_BITS == dart::R28 ? "\"x28\"" : "null");
	of << R"(,"decision_branch_abi":{"value_bit":)";
    if constexpr (dart::NULL_REG == dart::R22 && dart::compiler::target::kCompressedWordSize == 4)
        of << dart::compiler::target::ObjectAlignment::kBoolValueBitPosition;
    else of << "null";
    of << '}';
    of << ",\"array_body_contract\":[";
	if (!arrayAllocation.IsNull()) of << arrayAllocation.EntryPoint() - app.base() << ',' << dart::AllocateArrayABI::kLengthReg << ','
		<< dart::Array::data_offset() - dart::kHeapObjectTag << ',' << dart::compiler::target::kCompressedWordSize << ',' << dart::kSmiTagShift;
	of << "],\"array_length_layout\":[" << dart::kArrayCid << ',' << dart::Array::length_offset() - dart::kHeapObjectTag << ','
		<< dart::compiler::target::kCompressedWordSize << ',' << dart::kSmiTagShift;
	of << "],\"allocation_body_bounds\":[";
	bool bodyComma = false;
	auto auditBody = [&](const dart::Code& code, const dart::Class& cls) {
		const auto size = cls.target_instance_size();
		if (size < 8 || size > (1 << 20)) return;
		if (bodyComma) of << ','; bodyComma = true;
		of << '[' << code.EntryPoint() - app.base() << ',' << 8 - dart::kHeapObjectTag << ',' << size - dart::kHeapObjectTag << ']';
	};
	if (closureAllocation && !closureAllocation->IsNull()) auditBody(*closureAllocation, dart::Class::Handle(zone, thread->isolate_group()->class_table()->At(dart::kClosureCid)));
	if (!mintAllocation.IsNull()) auditBody(mintAllocation, dart::Class::Handle(zone, thread->isolate_group()->class_table()->At(dart::kMintCid)));
	for (const auto ptr : visitor.codes) {
		const auto& code = dart::Code::Handle(zone, ptr);
		const auto& owner = dart::Object::Handle(zone, code.owner());
		if (owner.IsClass() && dart::Class::Cast(owner).id() >= dart::kNumPredefinedCids) auditBody(code, dart::Class::Cast(owner));
	}
	of << "],\"preserved_call_registers\":[";
	uint32_t savedMask = 0;
	for (unsigned r = 0; r < 31; ++r) if (!(dart::kReservedCpuRegisters & (1U << r)) && r != dart::AllocateMintABI::kResultReg && r != dart::AllocateMintABI::kTempReg)
		savedMask |= 1U << r;
	if (!mintAllocation.IsNull()) of << '[' << mintAllocation.EntryPoint() - app.base() << ',' << savedMask << ']';
	uint32_t barrierMask = 0;
	for (unsigned r = 0; r < 31; ++r) if (!(dart::kReservedCpuRegisters & (1U << r)) && r != dart::kWriteBarrierSlotReg) barrierMask |= 1U << r;
	if (!arrayBarrier.IsNull()) {
		if (!mintAllocation.IsNull()) of << ',';
		of << '[' << arrayBarrier.EntryPoint() - app.base() << ',' << barrierMask << ']';
	}
	of << "],\"fresh_content_allocators\":[";
	if (!mintAllocation.IsNull()) of << mintAllocation.EntryPoint() - app.base();
	of << "],\"class_allocations\":[";
	comma = false;
	for (const auto ptr : visitor.codes) {
		const auto& code = dart::Code::Handle(zone, ptr);
		const auto& owner = dart::Object::Handle(zone, code.owner());
		if (owner.IsClass()) {
			if (comma) of << ','; comma = true;
			of << '[' << code.EntryPoint() - app.base() << ',' << dart::Class::Cast(owner).id() << ']';
		}
	}
	of << "],\"instance_field_metadata\":[";
	const auto* classTable = thread->isolate_group()->class_table();
	comma = false;
	for (intptr_t cid = dart::kNumPredefinedCids; cid < classTable->NumCids(); ++cid) {
		if (!classTable->HasValidClassAt(cid)) continue;
		const auto& cls = dart::Class::Handle(zone, classTable->At(cid));
		if (cls.IsTopLevel() || !cls.is_type_finalized()) continue;
		if (comma) of << ','; comma = true;
		const auto& parent = dart::Class::Handle(zone, cls.SuperClass());
#ifdef HAS_SHARED_CLASS_TABLE
		const auto bitmap = thread->isolate_group()->shared_class_table()->GetUnboxedFieldsMapAt(cid);
#else
		const auto bitmap = classTable->GetUnboxedFieldsMapAt(cid);
#endif
		of << '[' << cid << ',' << cls.host_next_field_offset() << ',' << cls.host_type_arguments_field_offset()
			<< ',' << bitmap.Value() << ',' << (parent.IsNull() ? 0 : parent.id()) << ",[";
		const auto& fields = dart::Array::Handle(zone, cls.fields());
		bool fieldComma = false;
		for (intptr_t n = 0; n < fields.Length(); ++n) {
			const auto& field = dart::Field::Handle(zone, dart::Field::RawCast(fields.At(n)));
			if (field.is_static() || field.is_unboxed()) continue;
			if (fieldComma) of << ','; fieldComma = true;
			const auto& type = dart::AbstractType::Handle(zone, field.type());
			dart::ZoneTextBuffer typeName(zone);
			type.PrintName(dart::Object::kScrubbedName, &typeName);
			of << '[' << field.TargetOffset() << ',' << JsonNativeText(field.UserVisibleNameCString())
				<< ',' << JsonNativeText(typeName.buffer()) << ']';
		}
		of << "]]";
	}
	of << "],\"instance_field_abi\":[" << dart::kHeapObjectTag << ',' << dart::kCompressedWordSize << ','
		<< dart::Instance::NextFieldOffset() << ',' << dart::kContextCid << ',' << dart::Context::parent_offset()
		<< ',' << dart::Context::variable_offset(0) << "]}\n";
}
#endif

static std::string getFunctionName4Ida(const DartFunction& dartFn, const std::string& cls_prefix)
{
	auto fnName = dartFn.Name();
	if (dartFn.IsClosure() && fnName == "<anonymous closure>") {
		return "_anon_closure";
	}

	auto periodPos = fnName.find('.');
	std::string prefix;
	if (dartFn.IsStatic() && dartFn.Kind() == DartFunction::NORMAL && periodPos != std::string::npos) {
		// this one is extension
		prefix = fnName.substr(0, periodPos + 1);
		if (prefix.starts_with("_extension#")) {
			// anonymous extension. '#' is invalid name in IDA.
			std::replace(prefix.begin(), prefix.end(), '#', '@');
		}
		fnName = fnName.substr(periodPos + 1);
	}

	if (OP_MAP.contains(fnName)) {
		return prefix + "op_" + OP_MAP[fnName];
	}
	const auto last = fnName.empty() ? '\0' : fnName.back();
	if (last == '=') {
		fnName.pop_back();
		return prefix + fnName + "_assign";
	}
	else if (last == '-') {
		fnName.pop_back();
		return prefix + fnName + "_neg";
	}
	else if (last == '!') {
		fnName.pop_back();
		return prefix + fnName + "_not";
	}

	switch (dartFn.Kind()) {
	case DartFunction::CONSTRUCTOR: {
		std::string name = dartFn.IsStatic() ? "factory_ctor" : "ctor";
		ASSERT(fnName.starts_with(cls_prefix));
		if (fnName.starts_with(cls_prefix) && fnName.size() > cls_prefix.size() && fnName[cls_prefix.size()] == '.') {
			name += '_';
			name += &fnName[cls_prefix.length() + 1];
		}
		return name;
	}
	case DartFunction::SETTER:
		return "set_" + fnName;
	case DartFunction::GETTER:
		return "get_" + fnName;
	default:
		break;
	}

	return prefix + fnName;
}

void DartDumper::Dump4Ida(std::filesystem::path outDir)
{
	std::filesystem::create_directory(outDir);
	std::ofstream of((outDir / "addNames.py").string());
	of << "import ida_funcs\n";
	of << "import idaapi\nimport idc\n\n";

	for (auto lib : app.libs) {
		std::string lib_prefix = lib->GetName();
		for (auto cls : lib->classes) {
			std::string cls_prefix = cls->Name();
			for (auto dartFn : cls->Functions()) {
				const auto ep = dartFn->Address();
				auto name = getFunctionName4Ida(*dartFn, cls_prefix);
#ifndef HAS_INSTRUCTIONS_TABLE_RODATA
				const auto fnSize = dartFn->Size();
				if (fnSize > 0) {
					of << std::format("ida_funcs.add_func({:#x}, {:#x})\n", ep, ep + fnSize);
				}
#endif
				of << std::format("idaapi.set_name({:#x}, {})\n", ep,
					pythonString(std::format("{}_{}::{}_{:x}", lib_prefix, cls_prefix, name, ep)));
				if (dartFn->HasMorphicCode()) {
					const auto payloadAddr = dartFn->PayloadAddress();
					const auto morphicAddr = dartFn->MonomorphicAddress();
					if (payloadAddr != 0 && payloadAddr != ep) {
						of << std::format("idaapi.set_name({:#x}, {})\n", payloadAddr,
							pythonString(std::format("{}_{}::{}_{:x}_miss", lib_prefix, cls_prefix, name, ep)));
					}
					if (morphicAddr != 0 && morphicAddr != ep && morphicAddr != payloadAddr) {
						of << std::format("idaapi.set_name({:#x}, {})\n", morphicAddr,
							pythonString(std::format("{}_{}::{}_{:x}_check", lib_prefix, cls_prefix, name, ep)));
					}
				}
			}
		}
	}

	for (auto& item : app.stubs) {
		auto stub = item.second;
		const auto ep = stub->Address();
		auto name = stub->FullName();
		std::replace(name.begin(), name.end(), '<', '@');
		std::replace(name.begin(), name.end(), '>', '@');
		std::replace(name.begin(), name.end(), ',', '&');
		std::replace(name.begin(), name.end(), ' ', '_');
		of << std::format("idaapi.set_name({:#x}, {})\n", ep,
			pythonString(std::format("{}_{:x}", name, ep)));
#ifndef HAS_INSTRUCTIONS_TABLE_RODATA
		// UnknownDartCode can have a negative size sentinel. Keep its name,
		// but do not emit a backwards IDA range for an unavailable size.
		if (stub->Size() <= 0)
			continue;
		of << std::format("ida_funcs.add_func({:#x}, {:#x})\n", ep, ep + stub->Size());
#else
		// Older snapshots store VM stubs in a separate image. They are outside
		// the application's canonical table and must keep their existing ranges.
		if (app.vm_snapshot_instructions && app.vm_snapshot_instructions != app.isolate_snapshot_instructions && stub->Size() > 0) {
			const auto vmStart = reinterpret_cast<uintptr_t>(app.vm_snapshot_instructions) - app.base();
			const auto vmSize = *reinterpret_cast<const uintptr_t*>(app.vm_snapshot_instructions);
			if (ep >= vmStart && ep - vmStart < vmSize) {
				if (static_cast<uint64_t>(stub->Size()) > vmSize - (ep - vmStart))
					throw std::runtime_error("VM stub range exceeds its instructions image");
				of << std::format("ida_funcs.add_func({:#x}, {:#x})\n", ep, ep + stub->Size());
			}
		}
#endif
	}


#ifdef HAS_INSTRUCTIONS_TABLE_RODATA
	// Export each VM payload exactly once, including checked-entry prefixes.
	// Avoid guessed sizes and overlapping duplicate ranges from metadata aliases.
	for (const auto& [start, end] : snapshotCodeRanges)
		of << std::format("ida_funcs.add_func({:#x}, {:#x})\n", start, end);
	for (const auto& [start, end] : recoveredCodeRanges) {
		of << std::format("idaapi.set_name({:#x}, \"unattributed_code_{:x}\")\n", start, start);
	}
#endif

	// Note: create struct with a lot of member by ida script is very slow
	//   use header file then adding comment is much faster
	auto comments = DumpStructHeaderFile((outDir / "ida_dart_struct.h").string());
	of << R"CBLOCK(
import ida_struct
import os
def create_Dart_structs():
	sid1 = idc.get_struc_id("DartThread")
	if sid1 != idc.BADADDR:
		return sid1, idc.get_struc_id("DartObjectPool")
	hdr_file = os.path.join(os.path.dirname(__file__), 'ida_dart_struct.h')
	idaapi.idc_parse_types(hdr_file, idc.PT_FILE)
	sid1 = idc.import_type(-1, "DartThread")
	sid2 = idc.import_type(-1, "DartObjectPool")
	struc = ida_struct.get_struc(sid2)
)CBLOCK";
	for (const auto& [offset, comment] : comments) {
		of << "\tida_struct.set_member_cmt(ida_struct.get_member(struc, " << offset << "), " << pythonString(comment) << ", True)\n";
	}
	of << "\treturn sid1, sid2\n";
	of << "thrs, pps = create_Dart_structs()\n";

	of << "print('Applying Thread and Object Pool struct')\n";
	applyStruct4Ida(of);

	of << "print('Script finished!')\n";
}

std::vector<std::pair<intptr_t, std::string>> DartDumper::DumpStructHeaderFile(std::string outFile)
{
	std::ofstream of(outFile);

	const auto max_offset = GetThreadMaxOffset();
	auto padNo = 0;
	of << "typedef struct DartThread {\n";
	for (intptr_t i = 0; i <= max_offset; i += 8) {
		auto& name = GetThreadOffsetName((int)i);
		if (name.empty()) {
			of << "\t__int64 pad" << std::hex << padNo << ";\n";
			padNo++;
		}
		else {
			of << "\t__int64 " << name << ";\n";
		}
	}
	of << "} DartThread;\n";

	of << "typedef struct DartObjectPool {\n";
	of << "\t__int64 pad0;\n";
	of << "\t__int64 pad1;\n";

	std::vector<std::pair<intptr_t, std::string>> comments;
	const auto& pool = app.GetObjectPool();
	intptr_t num = pool.Length();

	auto& obj = dart::Object::Handle();
	for (intptr_t i = num - 1; i >= 0; i--) {
		// the Dart Code access ObjectPool with offset that is not subtract by kHeapObjectTag (1)
		//   so we have to add 1 to make the offset same as offset in the code
		intptr_t offset = dart::ObjectPool::OffsetFromIndex(i) + 1;
		std::string name;

		auto objType = pool.TypeAt(i);
		if (objType == dart::ObjectPool::EntryType::kTaggedObject) {
			obj = pool.ObjectAt(i);
			if (obj.IsUnlinkedCall()) {
				// since Dart 3.10, target type might be kTaggedObject
				auto unlinkTargetType = pool.TypeAt(i + 1);
				if (unlinkTargetType == dart::ObjectPool::EntryType::kImmediate) {
					const auto imm = pool.RawValueAt(i + 1);
					auto dartFn = app.GetFunction(imm - app.base());
					if (dartFn != nullptr) {
						name = std::format("UnlinkedCall_{:#x}_{:#x}", offset, dartFn->Address(), offset);
					}
					else {
						name = std::format("UnlinkedCall_{:#x}_unknown", offset);
					}
				}
				else {
					ASSERT(unlinkTargetType == dart::ObjectPool::EntryType::kTaggedObject);
					const auto imm = pool.RawValueAt(i + 1);
					name = std::format("UnlinkedCall_{:#x}_tagged_{:#x}", offset, imm - app.base());
				}
			}
			else {
				// TODO: more meaningful variable name
				name = std::format("Obj_{:#x}", offset);
				auto comment = ObjectToString(obj);
				comments.push_back(std::make_pair(offset, comment));
			}
		}
		else if (objType == dart::ObjectPool::EntryType::kImmediate) {
			name = std::format("IMM_{:#x}_{:#x}", pool.RawValueAt(i), offset);
		}
		else if (objType == dart::ObjectPool::EntryType::kNativeFunction) {
			// the name of NativeFunction can be retrieved from dart::NativeSymbolResolver::LookupSymbolName
			//   but normally flutter code never access it
			// if we use the name, we should cache it because many Pool Objects reference same NativeFunction
			name = std::format("NativeFn_{:#x}_{:#x}", pool.RawValueAt(i), offset);
		}
		else {
			name = std::format("RAW_{:#x}_{:#x}", pool.RawValueAt(i), offset);
		}

		of << "\t__int64 " << name << ";\n";
	}

	of << "} DartObjectPool;\n";

	return comments;
}

void DartDumper::applyStruct4Ida(std::ostream& of)
{
	Disassembler disasmer;

	of << "import ida_ua\n";
	of << "insn = ida_ua.insn_t()\n";

	for (auto lib : app.libs) {
		if (lib->isInternal)
			continue;

		for (auto dartCls : lib->classes) {
			for (auto dartFn : dartCls->Functions()) {
				if (dartFn->PayloadSize() == 0)
					continue;

				auto insns = disasmer.Disasm((uint8_t*)dartFn->PayloadAddress() + app.base(), dartFn->PayloadSize(), dartFn->Address());

				for (uint32_t i = 0; i < insns.Count(); i++) {
					auto insn = insns.At(i);
					const auto op_count = insn.op_count();

					for (uint8_t j = 0; j < op_count; j++) {
						auto reg = ARM64_REG_INVALID;
						if (insn.ops[j].type == ARM64_OP_REG)
							reg = insn.ops[j].reg;
						else if (insn.ops[j].type == ARM64_OP_MEM)
							reg = insn.ops[j].mem.base;
						if (reg == CSREG_DART_THR) {
							of << "ida_ua.decode_insn(insn, " << insn.address() << ")\n";
							of << "idc.op_stroff(insn, " << (int)j << ", thrs, 0)\n";
							break;
						}
						else if (reg == CSREG_DART_PP) {
							// TODO: if it is not MEM operand, reg cannot be struct offset
							of << "ida_ua.decode_insn(insn, " << insn.address() << ")\n";
							of << "idc.op_stroff(insn, " << (int)j << ", pps, 0)\n";
							break;
						}
					}
				}
			}
		}
	}
}

const std::string& DartDumper::getQuoteString(dart::Object& obj)
{
	const auto ptr = (intptr_t)obj.ptr();
	auto& txt = quoteStringCache[ptr];
	// because string is always quotes, empty string means inserting a new one
	if (txt.empty()) {
		txt = Util::UnescapeWithQuote(obj.ToCString());
	}
	return txt;
}

void DartDumper::InvalidNativeRange(uint64_t address, const char* reason, const std::string& function)
{
	const AnalysisIssue issue("invalid-library-code-range", address, reason, AnalysisIssueKind::Invalid);
	if (diagnostics) diagnostics->Report(issue, function);
	throw issue;
}

void DartDumper::DumpNativeFunction(std::ostream& output, DartFunction& function, Disassembler& decoder)
{
	if (function.Size() == 0) return;
	const auto start = function.Address();
	const auto size = function.Size();
	const auto invalidRange = [&](const char* reason) {
		InvalidNativeRange(start, reason, function.FullName());
	};
	if (size < 0 || start % 4 || size % 4 || static_cast<uint64_t>(size) > UINT64_MAX - start)
		invalidRange("SDK function has an invalid instruction span.");
#ifdef HAS_INSTRUCTIONS_TABLE_RODATA
	const auto containing = std::upper_bound(snapshotCodeRanges.begin(), snapshotCodeRanges.end(), start,
		[](uint64_t address, const auto& range) { return address < range.first; });
	bool bounded = containing != snapshotCodeRanges.begin() && start + size <= std::prev(containing)->second;
	if (!bounded) {
		for (const auto& [address, stub] : app.stubs) {
			if (stub->Size() > 0 && start >= address && start - address <= static_cast<uint64_t>(stub->Size()) &&
				static_cast<uint64_t>(size) <= static_cast<uint64_t>(stub->Size()) - (start - address)) {
				bounded = true;
				break;
			}
		}
	}
	if (!bounded)
		invalidRange("SDK function exceeds its recorded native payload.");
#endif
	output << "    // Native assembly with snapshot annotations; declaration uses retained metadata.\n";
	WriteRawAssembly(output, decoder,
		std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(function.MemAddress()), size), start,
		[&](uint64_t address) -> std::string_view {
#ifdef HAS_INSTRUCTIONS_TABLE_RODATA
			if (const auto notes = callerResultNotes.find(address); notes != callerResultNotes.end())
				for (const auto& note : notes->second) output << "    // " << note << '\n';
#endif
			return {};
		}, [&](uint64_t address) {
			const AnalysisIssue issue("undecoded-sdk-instruction", address,
				"SDK function contains a word the ARM64 decoder cannot decode.");
			if (diagnostics) diagnostics->Report(issue, function.FullName());
			else throw issue;
		});
}

std::string DartDumper::DescribeAssembly(const AsmText& text)
{
	switch (text.dataType) {
	case AsmText::ThreadOffset: return "THR::" + GetThreadOffsetName(text.threadOffset);
	case AsmText::PoolOffset: return getPoolObjectDescription(text.poolOffset);
	case AsmText::Boolean: return text.boolVal ? "true" : "false";
	case AsmText::Call:
		if (auto* function = app.GetFunction(text.callAddress)) {
			auto name = function->FullName();
			const auto cid = function->ReturnType();
			if (cid != dart::kIllegalCid) {
				const auto* cls = app.classes.at(cid);
				name += std::format(" -> {} (size={:#x})", cls->FullName(), cls->Size());
			}
			return name;
		}
	}
	return {};
}

std::map<uint64_t, std::vector<std::string>> DartDumper::FunctionObservations(const std::vector<DartFunction*>& functions)
{
	std::map<uint64_t, std::vector<std::string>> notes;
#ifndef NO_CODE_ANALYSIS
	for (auto* function : functions) {
		const auto* analyzed = function->GetAnalyzedData();
		if (!analyzed) {
			if (!function->Class().Library().isInternal && function->Size() > 0) {
				const AnalysisIssue issue("missing-function-analysis", function->Address(),
					"Application function has no retained semantic analysis; exporting original native instructions.");
				if (diagnostics) diagnostics->Report(issue, function->FullName());
				else throw issue;
			}
			continue; // SDK bodies use native observations instead.
		}
		const auto origin = functions.size() > 1 ? " [" + function->FullName() + "]" : "";
		auto add = [&](uint64_t address, std::string text) {
			auto& at = notes[address];
			text += origin;
			if (std::find(at.begin(), at.end(), text) == at.end()) at.push_back(std::move(text));
		};
		for (const auto& instruction : analyzed->il_insns)
			if (instruction->Kind() != ILInstr::Unknown)
				add(instruction->Start(), "IL: " + instruction->ToString());
		for (const auto& text : function->GetAnalyzedData()->asmTexts.Data())
			if (auto description = DescribeAssembly(text); !description.empty())
				add(text.addr, "Application annotation: " + description);
	}
#endif
	return notes;
}

#ifdef HAS_INSTRUCTIONS_TABLE_RODATA
void DartDumper::DumpLibraryPayload(std::ostream& output, LibraryPayload& payload, Disassembler& decoder)
{
	output << std::format("    // Native payload {:#x}..{:#x}; function entry {:#x}.\n",
		payload.start, payload.end, payload.primary->Address());
	for (const auto* function : payload.functions)
		output << std::format("    // Entry {:#x}: {}\n", function->Address(), function->FullName());
	const auto semantic = FunctionObservations(payload.functions);
	for (const auto& [address, notes] : semantic)
		if (address < payload.start || address >= payload.end)
			InvalidNativeRange(address, "Retained function observation exceeds its native payload.", payload.primary->FullName());
	auto comment = payload.comments.begin();
	WriteRawAssembly(output, decoder,
		std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(app.base() + payload.start), payload.end - payload.start), payload.start,
		[&](uint64_t address) -> std::string_view {
			if (const auto found = semantic.find(address); found != semantic.end())
				for (const auto& note : found->second) output << std::format("    // @function {:#x}: {}\n", address, note);
			if (const auto found = callerResultNotes.find(address); found != callerResultNotes.end())
				for (const auto& note : found->second) output << "    // " << note << '\n';
			while (comment != payload.comments.end() && comment->first < address) ++comment;
			return comment != payload.comments.end() && comment->first == address ? std::string_view(comment->second) : std::string_view{};
		}, [](uint64_t) { /* The full-image pass has already reported decode gaps. */ });
	output << "    // End native payload\n";
	payload.comments.clear();
}
#endif

void DartDumper::DumpCode(const char* out_dir)
{
	std::filesystem::create_directory(out_dir);
#ifdef HAS_INSTRUCTIONS_TABLE_RODATA
	// Compute checked caller-result facts before either assembly writer uses them.
	DumpSnapshotCode(out_dir);
#endif

	Disassembler disasmer;

	for (auto dartLib : app.libs) {
		auto out_file = dartLib->CreatePath(out_dir);
		std::ofstream of(out_file);
		dartLib->PrintCommentInfo(of);

		for (auto dartCls : dartLib->classes) {
			dartCls->PrintHead(of);

			if (!dartCls->Fields().empty())
				of << "\n";
			for (auto dartField : dartCls->Fields()) {
				dartField->Print(of);
			}

			if (!dartCls->Functions().empty())
				of << "\n";
			for (auto dartFn : dartCls->Functions()) {
				dartFn->PrintHead(of);
#ifdef HAS_INSTRUCTIONS_TABLE_RODATA
				if (const auto route = functionPayloads.find(dartFn); route != functionPayloads.end()) {
					if (auto payload = libraryPayloads.find(route->second); payload != libraryPayloads.end()) {
						if (payload->second.primary == dartFn) DumpLibraryPayload(of, payload->second, disasmer);
						else of << std::format("    // Native body shared with payload {:#x}; see its primary declaration in this library.\n", route->second);
					}
					else {
						of << std::format("    // Native body: snapshot_code.asm, payload {:#x}; ownership is shared or uncertain.\n", route->second);
						for (const auto& [address, notes] : FunctionObservations({dartFn}))
							for (const auto& note : notes) of << std::format("    // @function {:#x}: {}\n", address, note);
					}
					dartFn->PrintFoot(of);
					continue;
				}
#endif
				if (dartLib->isInternal) {
					DumpNativeFunction(of, *dartFn, disasmer);
					dartFn->PrintFoot(of);
					continue;
				}

#ifndef NO_CODE_ANALYSIS
				// use as app is loaded at zero
				if (dartFn->Size() > 0) {
					auto& asmTexts = dartFn->GetAnalyzedData()->asmTexts.Data();
					auto& il_insns = dartFn->GetAnalyzedData()->il_insns;
					auto il_itr = il_insns.begin();
					AddrRange range;
					ASSERT(!asmTexts.empty());
					for (auto& asmText : asmTexts) {
						std::string extra;
						switch (asmText.dataType) {
						case AsmText::ThreadOffset:
							extra = "THR::" + GetThreadOffsetName(asmText.threadOffset);
							break;
						case AsmText::PoolOffset:
							extra = getPoolObjectDescription(asmText.poolOffset);
							break;
						case AsmText::Boolean:
							extra = asmText.boolVal ? "true" : "false";
							break;
						case AsmText::Call: {
							auto* fn = app.GetFunction(asmText.callAddress);
							if (fn) {
								extra = fn->FullName();
								auto retCid = fn->ReturnType();
								if (retCid != dart::kIllegalCid) {
									auto retCls = app.classes.at(retCid);
									extra += std::format(" -> {} (size={:#x})", retCls->FullName(), retCls->Size());
								}
							}
							break;
						}
						}

						std::string rawPrefix = "    // ";
						if (range.Has(asmText.addr)) {
							rawPrefix += "    ";
						}
						else {
							while ((*il_itr)->Start() < asmText.addr) {
								if ((*il_itr)->Kind() != ILInstr::Unknown) {
									of << "    // " << std::format("{:#x}: {}\n", (*il_itr)->Start(), (*il_itr)->ToString());
								}
								++il_itr;
							}
							if ((*il_itr)->Start() == asmText.addr) {
								if ((*il_itr)->Kind() != ILInstr::Unknown) {
									of << "    // " << std::format("{:#x}: {}\n", asmText.addr, (*il_itr)->ToString());
									rawPrefix += "    ";
									range = (*il_itr)->Range();
								}
								++il_itr;
							}
						}

#ifdef HAS_INSTRUCTIONS_TABLE_RODATA
						if (const auto notes = callerResultNotes.find(asmText.addr); notes != callerResultNotes.end())
							for (const auto& note : notes->second) of << "    // " << note << '\n';
#endif
						of << rawPrefix;
						if (extra.empty())
							of << std::format("{:#x}: {}\n", asmText.addr, &asmText.text[0]);
						else
							of << std::format("{:#x}: {}  ; {}\n", asmText.addr, &asmText.text[0], extra);
					}
				}
#endif // NO_CODE_ANALYSIS

				dartFn->PrintFoot(of);
			}

			dartCls->PrintFoot(of);
		}
		of.close();
		if (!of) throw std::runtime_error("Cannot write application assembly");
	}
}

#ifdef HAS_INSTRUCTIONS_TABLE_RODATA
void DartDumper::DumpSnapshotCode(const char* asm_dir)
{
	// A VM instructions-table entry is a native payload boundary. It does not
	// recover an absent Dart name, signature, or checked/unchecked entry offset.
	// Export raw code separately from the analyzer's typed/annotated output.
	const auto directory = std::filesystem::path(asm_dir);
	std::ofstream assembly(directory / "snapshot_code.asm");
	std::ofstream manifest(directory.parent_path() / "snapshot_code.json");
	if (!assembly || !manifest) throw std::runtime_error("Cannot create snapshot code output");
	recoveredCodeRanges.clear();
	snapshotCodeRanges.clear();
	libraryPayloads.clear();
	functionPayloads.clear();
	std::vector<uint64_t> metadataEntries;
	std::vector<NativePayloadClaim> ownership;
	std::vector<DartFunction*> functions;
	std::vector<SnapshotAnalysis::Name> metadataNames;
	std::vector<std::string> libraryFiles;
	size_t libraryIndex = 0;
	for (auto* library : app.libs) {
		const auto file = std::filesystem::relative(library->CreatePath(asm_dir), directory).generic_string();
		if (std::find(libraryFiles.begin(), libraryFiles.end(), file) != libraryFiles.end())
			throw std::runtime_error("Different Dart libraries have the same output path");
		libraryFiles.push_back(file);
		for (auto* cls : library->classes) {
			for (auto* fn : cls->Functions()) {
				metadataEntries.push_back(fn->Address());
				ownership.push_back({fn->Address(), libraryIndex});
				functions.push_back(fn);
				metadataNames.push_back({fn->Address(), fn->FullName(), "function"});
			}
		}
		++libraryIndex;
	}
	for (const auto& [address, stub] : app.stubs) {
		metadataEntries.push_back(address);
		ownership.push_back({address, std::nullopt});
		metadataNames.push_back({address, stub->FullName(), "stub"});
	}
	std::sort(metadataEntries.begin(), metadataEntries.end());
	std::sort(metadataNames.begin(), metadataNames.end(), [](const auto& a, const auto& b) {
		return std::tie(a.address, a.kind, a.text) < std::tie(b.address, b.kind, b.text);
	});
	const auto displayNames = metadataNames;
	const auto imageStart = reinterpret_cast<uintptr_t>(app.isolate_snapshot_instructions);
	const auto imageSize = *reinterpret_cast<const uintptr_t*>(imageStart);
	const auto imageEnd = imageStart + imageSize;
	// The section header is rounded by the matched SDK. Its alignment changed
	// across releases; a fixed byte count would exclude valid older images.
	const auto codeOffset = dart::kObjectStartAlignment + dart::InstructionsSection::HeaderSize();
	if (imageSize <= static_cast<uintptr_t>(codeOffset) || imageEnd < imageStart)
		throw std::runtime_error("Invalid instructions image size");
	const auto codeStart = imageStart + codeOffset;
	auto* thread = dart::Thread::Current();
	const auto& tables = dart::GrowableObjectArray::Handle(thread->zone(),
		thread->isolate_group()->object_store()->instructions_tables());
	Disassembler disassembler(true);
	if (tables.IsNull() || tables.Length() != 1)
		throw std::runtime_error("Expected one root instructions table");
	const auto& rootTable = dart::InstructionsTable::Handle(thread->zone(),
		dart::InstructionsTable::RawCast(tables.At(0)));
	if (!rootTable.rodata() || rootTable.rodata()->length == 0 || !rootTable.ContainsPc(imageEnd - 1))
		throw std::runtime_error("Unsupported or missing root instructions table");
	std::vector<SnapshotAnalysis::Payload> payloads;
	if (rootTable.rodata()->length > (imageEnd - codeStart) / 4)
		throw std::runtime_error("Instructions table exceeds the code image");
	std::vector<uint64_t> entries;
	entries.reserve(rootTable.rodata()->length);
	for (uint32_t i = 0; i < rootTable.rodata()->length; ++i)
		entries.push_back(rootTable.EntryPointAt(i));
	const auto inventory = SnapshotCodeRanges(imageStart, codeStart, imageEnd, entries);
	std::vector<std::pair<uint64_t, uint64_t>> outputRanges;
	for (const auto& [start, end] : inventory) {
		payloads.push_back({start - app.base(), end - app.base(), {}, ""});
		outputRanges.emplace_back(start - app.base(), end - app.base());
	}
	const auto destinations = NativePayloadDestinations(outputRanges, ownership);
	for (auto* function : functions) {
		const auto next = std::upper_bound(outputRanges.begin(), outputRanges.end(), function->Address(),
			[](uint64_t address, const auto& range) { return address < range.first; });
		if (next == outputRanges.begin() || function->Address() >= std::prev(next)->second) continue;
		const auto index = std::prev(next) - outputRanges.begin();
		const auto [start, end] = outputRanges[index];
		functionPayloads.emplace(function, start);
		if (!destinations[index]) continue;
		if (!NativeFunctionMatchesPayload(start, end, function->PayloadAddress(), function->PayloadSize(), function->Address()))
			InvalidNativeRange(function->Address(), "Retained function metadata disagrees with its native payload.", function->FullName());
		auto [found, inserted] = libraryPayloads.try_emplace(start, LibraryPayload{start, end, 0, 0, false, function, {}, {}});
		found->second.functions.push_back(function);
		if (std::tuple(function->Address(), function->FullName()) <
			std::tuple(found->second.primary->Address(), found->second.primary->FullName())) found->second.primary = function;
	}
	const auto& pool = app.GetObjectPool();
#if defined(BLUTTER_SHOREBIRD_DB65)
	const std::string profileName = "shorebird_db65";
#elif defined(BLUTTER_SHOREBIRD_26A7)
	const std::string profileName = "shorebird_26a7";
#elif defined(BLUTTER_SHOREBIRD_8768)
	const std::string profileName = "shorebird_8768";
#elif defined(BLUTTER_SHOREBIRD_7D8F)
	const std::string profileName = "shorebird_7d8f";
#elif defined(BLUTTER_SHOREBIRD_8399)
	const std::string profileName = "shorebird_8399";
#elif defined(BLUTTER_SHOREBIRD_3C9C)
	const std::string profileName = "shorebird_3c9c";
#else
	const std::string profileName = "dart_aot";
#endif
	SnapshotAnalysis::Profile profile{profileName, ARM64_REG_X27, ARM64_REG_X26,
		dart::ObjectPool::element_offset(0), 8, pool.Length(), {}, {}};
	profile.includeGraphStates = includeGraphStates;
	profile.dispatchRegister = ARM64_REG_X21;
	profile.stackLimitOffset = TargetThreadOffset(dart::Thread::stack_limit_offset());
	if constexpr (dart::CallingConventions::kReturnReg == dart::R0) profile.wordReturnRegister = ARM64_REG_X0;
	profile.futureBindingAbi=ReadFutureBindingAbi();
    profile.closureCaptureLayout = ReadClosureCaptureLayout();
    if constexpr (dart::NULL_REG == dart::R22 && dart::compiler::target::kCompressedWordSize == 4)
        profile.fieldDecisionAbi = {true,
            dart::compiler::target::ObjectAlignment::kTrueOffsetFromNull,
            dart::compiler::target::ObjectAlignment::kFalseOffsetFromNull};
	profile.describeInstanceLayout = [](uint32_t cid) {
		SnapshotAnalysis::InstanceLayout result;
		result.classId = cid;
		if constexpr (dart::kCompressedWordSize != 4 || dart::kHeapObjectTag != 1) return result;
		auto* thread = dart::Thread::Current();
		auto* zone = thread->zone();
		auto* table = thread->isolate_group()->class_table();
		if (!table->IsValidIndex(cid) || !table->HasValidClassAt(cid)) return result;
		const auto& cls = dart::Class::Handle(zone, table->At(cid));
		result.header = dart::Instance::NextFieldOffset();
		result.slotBytes = dart::kCompressedWordSize;
		result.tag = dart::kHeapObjectTag;
		if (cid == dart::kContextCid) {
			result.kind = "context";
			result.contextParent = dart::Context::parent_offset();
			result.contextData = dart::Context::variable_offset(0);
			result.end = result.contextData;
			return result;
		}
		// Variable-sized VM classes (including closure payloads) need their own
		// representation contracts. Do not interpret their body as Dart fields.
		if (cid < dart::kNumPredefinedCids || cls.IsTopLevel() || !cls.is_type_finalized()) return result;
		result.end = cls.host_next_field_offset();
		if (result.end < result.header || result.end > 1048576) return result;
		result.kind = "instance";
#ifdef HAS_SHARED_CLASS_TABLE
		const auto bitmap = thread->isolate_group()->shared_class_table()->GetUnboxedFieldsMapAt(cid);
#else
		const auto bitmap = table->GetUnboxedFieldsMapAt(cid);
#endif
		for (intptr_t off = result.header; off < result.end; off += result.slotBytes)
			if (bitmap.Get(off / result.slotBytes)) result.unboxed.push_back(off);
		auto& owner = dart::Class::Handle(zone, cls.ptr());
		std::set<intptr_t> visited;
		while (!owner.IsNull() && visited.insert(owner.id()).second) {
			const auto typeOffset = owner.host_type_arguments_field_offset();
			if (typeOffset >= result.header && typeOffset < result.end) result.excluded.push_back(typeOffset);
			const auto& fields = dart::Array::Handle(zone, owner.fields());
			for (intptr_t n = 0; n < fields.Length(); ++n) {
				const auto& field = dart::Field::Handle(zone, dart::Field::RawCast(fields.At(n)));
				if (field.is_static() || field.is_unboxed()) continue;
				const auto& type = dart::AbstractType::Handle(zone, field.type());
				dart::ZoneTextBuffer text(zone);
				type.PrintName(dart::Object::kScrubbedName, &text);
				result.fields.push_back({field.TargetOffset(), static_cast<uint32_t>(owner.id()),
					field.UserVisibleNameCString(), text.buffer()});
			}
			owner = owner.SuperClass();
		}
		std::sort(result.excluded.begin(), result.excluded.end());
		result.excluded.erase(std::unique(result.excluded.begin(), result.excluded.end()), result.excluded.end());
		std::sort(result.fields.begin(), result.fields.end(), [](const auto& a, const auto& b) { return a.offset < b.offset; });
		return result;
	};
	static_assert(dart::AllocateObjectABI::kResultReg == dart::R0);

	if constexpr (dart::CallingConventions::kReturnReg == dart::R0) {
		class NativeFunctionVisitor : public dart::ObjectVisitor {
		public:
			std::vector<dart::FunctionPtr> functions;
			std::vector<dart::CodePtr> codes;
			void VisitObject(dart::ObjectPtr object) override {
				if (object->IsFunction()) functions.push_back(dart::Function::RawCast(object));
				if (object->IsCode()) codes.push_back(dart::Code::RawCast(object));
			}
		} visitor;
		dart::HeapIterationScope iteration(thread);
		iteration.IterateOldObjects(&visitor);
		std::map<uint64_t, uint64_t> bounds;
		for (const auto& payload : payloads) bounds.emplace(payload.start, payload.end);
		profile.callInputAbi = ReadCallInputAbi();
		profile.descriptorPrologueAbi = ReadDescriptorPrologueAbi();
		profile.readInputCode = [&](uint64_t address, size_t bytes) {
			if (!address || bytes > 65536 || address > UINTPTR_MAX-app.base()) return std::vector<uint8_t>{};
			const auto absolute = app.base()+address;
			if (absolute < codeStart || absolute >= imageEnd || bytes > imageEnd-absolute) return std::vector<uint8_t>{};
			const auto* first = reinterpret_cast<const uint8_t*>(absolute);
			return std::vector<uint8_t>(first, first+bytes);
		};
		profile.callInputDescriptors = ReadCallInputDescriptors(pool);
		profile.callInputModels = ReadCallInputModels(visitor.functions, app.base(), bounds, profile.callInputModelRejections);
		profile.stubInputContracts = SnapshotAnalysis::SelectStubInputContracts(
			ReadInputRoleIdentities(visitor.codes, app.base(), codeStart, imageEnd),
			SnapshotAnalysis::ReadStubInputAbis<dart::AllocateArrayABI, dart::AllocateClosureABI>(), bounds, true);
		profile.completionExceptions=ReadCompletionExceptions(visitor.codes,app.base(),codeStart,imageEnd);
		profile.savedFrameAbi=ReadSavedFrameAbi();
    if constexpr (dart::NULL_REG == dart::R22 && dart::compiler::target::kCompressedWordSize == 4)
        profile.booleanValueBit = dart::compiler::target::ObjectAlignment::kBoolValueBitPosition;
		profile.describeSavedStackMap=[&](uint64_t payload,uint64_t site){return ReadSavedStackMap(rootTable,app.base(),payload,site);};
		for (uint32_t n=0;n<rootTable.rodata()->first_entry_with_code;++n)
            profile.discardedWithoutHandlers.insert(rootTable.EntryPointAt(n)-app.base());
        profile.describeCompletionBody=[&](uint64_t payload) {
			const auto found=std::lower_bound(outputRanges.begin(),outputRanges.end(),payload,[](const auto& range,uint64_t pc){return range.first<pc;});
			if (found==outputRanges.end() || found->first!=payload) return SnapshotAnalysis::CompletionBody{};
			return ReadCompletionBody(rootTable,app.base(),payload,found->second,found-outputRanges.begin());
		};
		profile.asyncContracts = SnapshotAnalysis::SelectAsyncContracts(
			ReadAsyncStubIdentities(visitor.codes, app.base(), codeStart, imageEnd), bounds, SupportedAsyncAbi());
		profile.sdkStubReturnClasses = SnapshotAnalysis::SdkStubReturnContracts(
			ReadSdkStubIdentities(visitor.codes, app.base(), codeStart, imageEnd),
			dart::kGrowableObjectArrayCid, bounds, true);
		std::vector<SnapshotAnalysis::NativeReturnIdentity> identities;
		for (auto& record : ReadNativeReturnIdentities(visitor.functions, app.base())) identities.push_back(std::move(record.identity));
		profile.nativeReturnClasses = SnapshotAnalysis::NativeReturnContracts(identities, dart::kOneByteStringCid, dart::kTwoByteStringCid);
		// Bind selected contracts to exact original payload bounds as well.
		for (const auto& id : identities) if (profile.nativeReturnClasses.contains(id.entry) &&
			!std::ranges::any_of(payloads, [&](const auto& p) { return p.start == id.payload && p.end == id.end; })) profile.nativeReturnClasses.erase(id.entry);
	}
	if constexpr (dart::compiler::target::kCompressedWordSize == 4 && dart::HEAP_BITS == dart::R28) profile.heapBitsRegister = ARM64_REG_X28;
	static_assert(dart::SP == dart::R15);
	profile.arrayLengthLayout = SnapshotAnalysis::ArrayLengthLayout{dart::kArrayCid,
		AOT_Array_length_offset - dart::kHeapObjectTag, dart::compiler::target::kCompressedWordSize, dart::kSmiTagShift};
	profile.dispatchOrigin = dart::DispatchTable::kOriginElement;
	profile.classIdShift = dart::UntaggedObject::ClassIdTag::shift();
	profile.classIdBits = dart::UntaggedObject::ClassIdTag::bitsize();
	profile.headerDisplacement = dart::Object::tags_offset() - dart::kHeapObjectTag;
	profile.leafMathContract = {TargetThreadOffset(dart::Thread::LibcRound_entry_point_offset()),
		TargetThreadOffset(dart::Thread::vm_tag_offset()), TargetThreadOffset(dart::Thread::saved_stack_limit_offset()), dart::VMTag::kDartTagId};
	profile.nullRegister = ARM64_REG_X22;
	profile.nullClassId = dart::kNullCid;
	profile.threadHeapClasses.emplace(TargetThreadOffset(dart::Thread::empty_array_offset()),
		static_cast<uint32_t>(dart::Object::empty_array().GetClassId()));
	profile.describeInputObject = [&](int64_t index) { return ReadInputObject(pool, index, app.base(), codeStart, imageEnd); };
	profile.poolHeapClass = [&](int64_t index) -> std::optional<uint32_t> {
		if (pool.TypeAt(index) != dart::ObjectPool::EntryType::kTaggedObject) return {};
		const auto& object = dart::Object::Handle(pool.ObjectAt(index));
		if (object.IsSmi()) return {};
		return static_cast<uint32_t>(object.GetClassId());
	};
	static_assert(dart::NULL_REG == dart::R22 && dart::AllocateObjectABI::kResultReg == dart::R0 && dart::AllocateArrayABI::kResultReg == dart::R0 &&
		dart::AllocateClosureABI::kResultReg == dart::R0 && dart::AllocateMintABI::kResultReg == dart::R0);
#ifdef BLUTTER_NO_OBJECT_STORE_STUBS
	const auto& arrayAllocation = dart::StubCode::AllocateArray();
	const auto* closureAllocation = PlainClosureAllocationStub<dart::StubCode>();
	const auto& mintAllocation = dart::StubCode::AllocateMintSharedWithoutFPURegs();
#else
	const auto& arrayAllocation = dart::Code::Handle(thread->zone(), thread->isolate_group()->object_store()->allocate_array_stub());
	const auto* closureAllocation = &dart::Code::Handle(thread->zone(), thread->isolate_group()->object_store()->allocate_closure_stub());
	const auto& mintAllocation = dart::Code::Handle(thread->zone(), thread->isolate_group()->object_store()->allocate_mint_without_fpu_regs_stub());
#endif
	auto addPredefined = [&](const dart::Code& code, uint32_t cid) {
		if (!code.IsNull() && code.EntryPoint() >= codeStart && code.EntryPoint() < imageEnd) {
			profile.allocationReturns.emplace(code.EntryPoint() - app.base(), cid);
			if (cid != dart::kArrayCid) {
				const auto& cls = dart::Class::Handle(thread->zone(), thread->isolate_group()->class_table()->At(cid));
				const auto size = cls.target_instance_size();
				if (size >= 8 && size <= (1 << 20)) profile.allocationBodyBounds.emplace(code.EntryPoint() - app.base(), std::pair{int64_t{7}, static_cast<int64_t>(size - dart::kHeapObjectTag)});
			}
		}
	};
	addPredefined(arrayAllocation, dart::kArrayCid);
	if (closureAllocation) addPredefined(*closureAllocation, dart::kClosureCid);
	addPredefined(mintAllocation, dart::kMintCid);
	static_assert(dart::AllocateArrayABI::kLengthReg == dart::R2 && dart::kSmiTagShift == 1 && dart::kHeapObjectTag == 1);
	if (!arrayAllocation.IsNull() && profile.allocationReturns.contains(arrayAllocation.EntryPoint() - app.base()))
		profile.arrayBodyContract = {static_cast<int64_t>(arrayAllocation.EntryPoint() - app.base()), 2,
			AOT_Array_data_offset - dart::kHeapObjectTag, dart::compiler::target::kCompressedWordSize, dart::kSmiTagShift};
	if (!mintAllocation.IsNull() && profile.allocationReturns.contains(mintAllocation.EntryPoint() - app.base())) {
		profile.preservedCallRegisters.emplace(mintAllocation.EntryPoint() - app.base(),
			static_cast<uint32_t>(dart::kDartAvailableCpuRegs) & ~(1U << dart::AllocateMintABI::kResultReg) & ~(1U << dart::AllocateMintABI::kTempReg));
		profile.freshContentAllocators.insert(mintAllocation.EntryPoint() - app.base());
	}
#ifdef BLUTTER_NO_OBJECT_STORE_STUBS
	const auto& stackCheck = dart::StubCode::StackOverflowSharedWithoutFPURegs();
#else
	const auto& stackCheck = dart::Code::Handle(thread->zone(), thread->isolate_group()->object_store()->stack_overflow_stub_without_fpu_regs_stub());
#endif
	if (!stackCheck.IsNull() && stackCheck.EntryPoint() >= codeStart && stackCheck.EntryPoint() < imageEnd)
		profile.framePreservingCalls.emplace(stackCheck.EntryPoint() - app.base(), "stack_overflow_without_fpu");
#ifdef BLUTTER_NO_OBJECT_STORE_STUBS
	const auto& rangeError = dart::StubCode::RangeErrorSharedWithoutFPURegs();
#else
	const auto& rangeError = dart::Code::Handle(thread->zone(), thread->isolate_group()->object_store()->range_error_stub_without_fpu_regs_stub());
#endif
	if (!rangeError.IsNull() && rangeError.EntryPoint() >= codeStart && rangeError.EntryPoint() < imageEnd)
		profile.nonReturningCalls.emplace(rangeError.EntryPoint() - app.base(), "range_error_without_fpu");
	const auto& doubleToInteger = dart::StubCode::DoubleToInteger();
	if (!doubleToInteger.IsNull())
		profile.framePreservingCalls.emplace(doubleToInteger.EntryPoint() - app.base(), "double_to_integer");
	static_assert(dart::kWriteBarrierObjectReg == dart::R1 && dart::kWriteBarrierValueReg == dart::R0 && dart::kWriteBarrierSlotReg == dart::R25);
	static_assert((dart::UntaggedObject::ClassIdTag::mask_in_place() &
		(dart::UntaggedObject::NotMarkedBit::mask_in_place() | dart::UntaggedObject::OldAndNotRememberedBit::mask_in_place())) == 0);
#ifdef BLUTTER_NO_OBJECT_STORE_STUBS
	const auto& arrayBarrier = dart::StubCode::ArrayWriteBarrier();
#else
	const auto& arrayBarrier = dart::Code::Handle(thread->zone(), thread->isolate_group()->object_store()->array_write_barrier_stub());
#endif
	if (!arrayBarrier.IsNull() && arrayBarrier.EntryPoint() >= codeStart && arrayBarrier.EntryPoint() < imageEnd) {
		const auto entry = arrayBarrier.EntryPoint() - app.base();
		profile.framePreservingCalls.emplace(entry, "array_write_barrier");
		profile.preservedCallRegisters.emplace(entry, static_cast<uint32_t>(dart::kDartAvailableCpuRegs) & ~(1U << dart::kWriteBarrierSlotReg));
	}
	for (const auto& [entry, stub] : app.stubs) if (stub->kind == DartStub::AllocateUserObjectStub) {
		const auto& code = dart::Code::Handle(stub->ptr);
		const auto& owner = dart::Object::Handle(code.owner());
		if (owner.IsClass() && code.EntryPoint() >= codeStart && code.EntryPoint() < imageEnd) {
			profile.allocationReturns.emplace(entry, static_cast<uint32_t>(dart::Class::Cast(owner).id()));
			const auto& cls = dart::Class::Handle(thread->zone(), thread->isolate_group()->class_table()->At(dart::Class::Cast(owner).id()));
			const auto size = cls.target_instance_size();
			if (cls.id() >= dart::kNumPredefinedCids && size >= 8 && size <= (1 << 20))
				profile.allocationBodyBounds.emplace(entry, std::pair{int64_t{7}, static_cast<int64_t>(size - dart::kHeapObjectTag)});
		}
	}
	if (const auto* dispatch = thread->isolate_group()->dispatch_table(); dispatch &&
		dispatch->length() >= profile.dispatchOrigin && dispatch->length() <= (1 << 24)) {
		const auto* array = dispatch->ArrayOrigin() - profile.dispatchOrigin;
		const auto vmStart = reinterpret_cast<uintptr_t>(app.vm_snapshot_instructions);
		const auto vmSize = vmStart ? *reinterpret_cast<const uintptr_t*>(vmStart) : 0;
		auto normalize = [&](uintptr_t value) -> std::optional<uint64_t> {
			if ((value & 3) != 0) return {};
			if ((value >= codeStart && value < imageEnd) ||
				(vmSize > codeOffset && vmSize <= UINTPTR_MAX - vmStart && value >= vmStart + codeOffset && value < vmStart + vmSize))
				return value - app.base();
			return {};
		};
		for (intptr_t i = 0; i < dispatch->length(); ++i)
			profile.dispatchEntries.push_back(normalize(array[i]));
#ifdef BLUTTER_NO_OBJECT_STORE_STUBS
		profile.dispatchNullTarget = normalize(dart::StubCode::DispatchTableNullError().EntryPoint());
#else
		profile.dispatchNullTarget = normalize(dart::Code::EntryPointOf(thread->isolate_group()->object_store()->dispatch_table_null_error_stub()));
#endif
		const auto snapshot = reinterpret_cast<uintptr_t>(thread->isolate_group()->dispatch_table_snapshot());
		const auto size = thread->isolate_group()->dispatch_table_snapshot_size();
		if (snapshot >= app.base() && size > 0 && size <= (1 << 27)) {
			profile.dispatchSnapshotAddress = snapshot - app.base();
			profile.dispatchSnapshotSize = size;
		}
	}
	for (const auto& [offset, name] : GetThreadOffsetsMap())
		if (!name.empty()) profile.threadFields.emplace(offset, name);
	profile.describePoolSlot = [&](int64_t index) -> SnapshotAnalysis::PoolSlot {
		switch (pool.TypeAt(index)) {
		case dart::ObjectPool::EntryType::kTaggedObject: {
			auto& obj = dart::Object::Handle(pool.ObjectAt(index));
			if (obj.IsUnlinkedCall()) return {"unlinked_call", "UnlinkedCall: target unresolved"};
			// Rendering nested objects reuses its input handle. Keep the typed
			// snapshot object separate from that mutable presentation scratch.
			auto& display = dart::Object::Handle(obj.ptr());
			SnapshotAnalysis::PoolSlot slot{"tagged_object", ObjectToString(display, false)};
			if (obj.IsCode()) {
				const auto& code = dart::Code::Cast(obj);
				auto addEntry = [&](dart::Code::EntryKind kind, uintptr_t address) {
					// Accept only instruction-image VAs; never export reader heap
					// pointers or the placeholder at the start of an image.
					bool inCode = address >= codeStart && address < imageEnd;
					if (app.vm_snapshot_instructions) {
						const auto vmStart = reinterpret_cast<uintptr_t>(app.vm_snapshot_instructions);
						const auto vmSize = *reinterpret_cast<const uintptr_t*>(vmStart);
						if (vmSize > codeOffset && vmSize <= UINTPTR_MAX - vmStart)
							inCode |= address >= vmStart + codeOffset && address < vmStart + vmSize;
					}
					if (inCode && (address & 3) == 0)
						slot.entryPoints.emplace(dart::Code::entry_point_offset(kind) - dart::kHeapObjectTag, address - app.base());
				};
				addEntry(dart::Code::EntryKind::kNormal, code.EntryPoint());
				addEntry(dart::Code::EntryKind::kUnchecked, code.UncheckedEntryPoint());
			}
			return slot;
		}
		case dart::ObjectPool::EntryType::kImmediate: {
			const auto value = pool.RawValueAt(index);
			// Deserialization relocates some immediate code values into this
			// reader's mapping. Export the original ELF VA, never a host pointer.
			if (value >= imageStart && value < imageEnd)
				return {"text_address_value", std::format("value in snapshot text: ELF {:#x}", value - app.base())};
			return {"immediate", std::format("bits: {:#x}", value)};
		}
		case dart::ObjectPool::EntryType::kNativeFunction:
			return {"native_function", "runtime native binding; target unresolved"};
		default: return {"unknown", "slot kind unknown"};
		}
	};
	SnapshotAnalysis::Analyzer annotations(std::move(profile), std::move(payloads), std::move(metadataNames), selectedCaller);
	// A separate first pass records cross-payload entry points before any alias
	// tracking. Do not carry an alias through a known incoming branch target.
	for (uint32_t i = 0; i < rootTable.rodata()->length; ++i) {
		const auto start = rootTable.EntryPointAt(i);
		const auto end = i + 1 < rootTable.rodata()->length ? rootTable.EntryPointAt(i + 1) : imageEnd;
		auto instructions = disassembler.Disasm(reinterpret_cast<const uint8_t*>(start), end - start, start - app.base());
		annotations.RegisterEntries(instructions.Insns(), instructions.Count());
	}
	assembly << "// Native fallback payloads from the VM instructions table.\n"
		"// Payloads with a verified library owner are written in that library's .dart listing.\n"
		"// Names/types may be unavailable; this file contains no inferred Dart IL.\n";
	manifest << "{\"format\":1,\"assembly_layout\":2,\"image_start\":" << imageStart - app.base()
		<< ",\"image_end\":" << imageEnd - app.base()
		<< ",\"table_data_address\":" << reinterpret_cast<uintptr_t>(rootTable.rodata()) - app.base()
		<< ",\"table_length\":" << rootTable.rodata()->length
		<< ",\"first_entry_with_code\":" << rootTable.rodata()->first_entry_with_code
		<< ",\"ranges\":[";
	bool comma = false;
	uint64_t total = 0;
	uint64_t undecoded = 0;
	struct AssemblyPayload {
		intptr_t table;
		uint32_t index;
		uint64_t start, end;
		bool discarded, hasMetadata;
		std::vector<std::pair<uint64_t, std::string>> comments;
	};
	std::vector<AssemblyPayload> assemblyPayloads;
	for (intptr_t t = 0; !tables.IsNull() && t < tables.Length(); ++t) {
		const auto& table = dart::InstructionsTable::Handle(thread->zone(),
			dart::InstructionsTable::RawCast(tables.At(t)));
		if (!table.rodata() || table.rodata()->length == 0)
			throw std::runtime_error("Missing instructions-table data");
		// This profile supports the root image, not a deferred loading-unit file.
		if (!table.ContainsPc(imageEnd - 1))
			throw std::runtime_error("Unsupported deferred instructions table");
		const auto length = table.rodata()->length;
		for (uint32_t i = 0; i < length; ++i) {
			const auto start = table.EntryPointAt(i);
			const auto end = i + 1 < length ? table.EntryPointAt(i + 1) : imageEnd;
			if (start < codeStart || end <= start || end > imageEnd ||
				(start % 4) != 0 || (end % 4) != 0)
				throw std::runtime_error("Invalid instructions-table boundary");
			const auto address = start - app.base();
			const auto limit = end - app.base();
			snapshotCodeRanges.emplace_back(address, limit);
			const auto name = std::lower_bound(metadataEntries.begin(), metadataEntries.end(), address);
			const bool hasMetadata = name != metadataEntries.end() && *name < limit;
			if (!hasMetadata) recoveredCodeRanges.emplace_back(address, limit);
			if (comma) manifest << ','; comma = true;
			manifest << std::format("{{\"table\":{},\"index\":{},\"start\":{},\"end\":{},\"discarded_code\":{},\"has_metadata_name\":{},\"assembly_file\":{}}}",
				t, i, address, limit, i < table.rodata()->first_entry_with_code ? "true" : "false", hasMetadata ? "true" : "false",
				JsonNativeText(destinations[i] ? libraryFiles[*destinations[i]] : "snapshot_code.asm"));
			AssemblyPayload printable{t, i, address, limit, i < table.rodata()->first_entry_with_code, hasMetadata, {}};
			uint64_t cursor = address;
			while (cursor < limit) {
				auto instructions = disassembler.Disasm(
					reinterpret_cast<const uint8_t*>(app.base() + cursor), limit - cursor, cursor);
				if (instructions.Count() == 0) {
					const AnalysisIssue issue("undecoded-snapshot-instruction", cursor,
						"Snapshot payload contains a word the ARM64 decoder cannot decode.");
					if (diagnostics)
						diagnostics->Report(issue);
					else
						throw issue;
					cursor += 4;
					++undecoded;
					continue;
				}
				auto comments = cursor == address && instructions.Count() * 4 == limit - address
					? annotations.Analyze(instructions.Insns(), instructions.Count(), address)
					: std::map<uint64_t, std::string>{};
				for (auto& [site, text] : comments) printable.comments.emplace_back(site, std::move(text));
				for (size_t n = 0; n < instructions.Count(); ++n) {
					const auto* instruction = instructions.Ptr(n);
					cursor = instruction->address + instruction->size;
				}
			}
			assemblyPayloads.push_back(std::move(printable));
			++total;
		}
	}
	manifest << std::format("],\"payload_count\":{},\"additional_exports\":{},\"undecoded_words\":{}}}\n",
		total, recoveredCodeRanges.size(), undecoded);
	callerResultNotes.clear();
	auto resultClassName = [&](uint32_t cid) {
		return cid < app.classes.size() && app.classes[cid] ? app.classes[cid]->Name() : std::string{};
	};
	auto appendResultNotes = [&](const auto& added) {
		for (const auto& [site, notes] : added) for (const auto& note : notes) {
			auto& retained = callerResultNotes[site];
			if (std::find(retained.begin(), retained.end(), note) == retained.end()) retained.push_back(note);
		}
	};
	appendResultNotes(SnapshotAnalysis::BuildCallInputNotes(annotations.Edges(), resultClassName, annotations.InputContracts(), annotations.InputShapes()));
	annotations.Write((directory.parent_path() / "snapshot_calls.json").string(), [&](const auto& result) {
		appendResultNotes(SnapshotAnalysis::BuildCallResultNotes(result, annotations.Edges(), resultClassName, annotations.InputContracts(), annotations.InputShapes()));
	}, [&](uint64_t entry) {
		AnalysisIssue issue("sdk-result-decode", entry, "SDK result analysis cannot decode this retained payload");
		if (diagnostics) diagnostics->Report(issue);
		else throw issue;
	}, [&](const auto& result) {
		appendResultNotes(SnapshotAnalysis::BuildRegisterResultNotes(result, annotations.Edges(), resultClassName));
	}, [&](const SnapshotAnalysis::FutureBindingsResult& result) {
		for (const auto& binding:result.bindings) if (binding.input.boundary.resumeSite) {
			const auto note=SnapshotAnalysis::AwaitFutureBindingNote(binding,resultClassName);
			if (!note.empty()) callerResultNotes[*binding.input.boundary.resumeSite].push_back(note);
		}
	}, [&](const SnapshotAnalysis::SavedReferencesResult& result) {
		for(const auto& context:result.contexts)for(const auto& reference:context.observations)
			callerResultNotes[reference.site].push_back(SnapshotAnalysis::RestoredReferenceNote(context,reference,resultClassName));
	}, [&](const SnapshotAnalysis::AsyncFieldsResult& result) {
		for (const auto& context : result.contexts) for (const auto& access : context.accesses)
			callerResultNotes[access.site].push_back(SnapshotAnalysis::AsyncFieldAccessNote(context,access,result.layouts.at(context.classId),resultClassName));
	}, [&](const SnapshotAnalysis::AsyncFieldsResult& fields, const std::vector<SnapshotAnalysis::CallInputOrigin>& origins,
		const SnapshotAnalysis::FieldInputLinksResult& links) {
		for (const auto& link : links.links) callerResultNotes[origins[link.origin].site].push_back(
			SnapshotAnalysis::FieldInputNote(fields,origins,link,resultClassName));
	}, [&](const SnapshotAnalysis::AsyncFieldsResult& fields, const SnapshotAnalysis::CapturedFieldsResult& result) {
		for(const auto& context:result.contexts) for(const auto& reload:context.reloads)
			callerResultNotes[reload.site].push_back(SnapshotAnalysis::CapturedFieldNote(fields,context,reload));
	}, [&](const SnapshotAnalysis::AsyncFieldsResult& fields, const SnapshotAnalysis::CapturedFieldsResult& captures, const SnapshotAnalysis::FreshFieldsResult& result) {
		for(const auto& c:result.contexts) if(c.write)
			callerResultNotes[c.write->site].push_back(SnapshotAnalysis::FreshFieldNote(fields,captures,c));
	}, [&](const SnapshotAnalysis::AsyncFieldsResult& fields, const SnapshotAnalysis::CapturedFieldsResult& captures,
		const SnapshotAnalysis::FreshFieldsResult& fresh, const std::vector<SnapshotAnalysis::CallInputOrigin>& origins,
		const SnapshotAnalysis::FreshContentResult& result) {
		for (const auto& c : result.contexts) for (const auto input : c.inputs)
			callerResultNotes[*c.transfer].push_back(SnapshotAnalysis::FreshContentNote(fields,captures,fresh,origins,c,input));
	}, [&](const SnapshotAnalysis::AsyncFieldsResult& fields, const SnapshotAnalysis::CapturedFieldsResult& captures,
		const SnapshotAnalysis::FreshFieldsResult& fresh, const SnapshotAnalysis::FreshContentResult& contents,
		const SnapshotAnalysis::CalleeEntryResult& result) {
		for (const auto& link : result.links)
			callerResultNotes[*contents.contexts[link.context].transfer].push_back(
				SnapshotAnalysis::ContainerEntryReadNote(fields,captures,fresh,contents,result,link));
	}, [&](const SnapshotAnalysis::JoinedReferencesResult& result) {
        for (const auto& context : result.contexts) for (const auto& reference : context.observations)
            callerResultNotes[reference.site].push_back(SnapshotAnalysis::JoinedReferenceNote(context,reference));
	}, [&](const SnapshotAnalysis::JoinedReferencesResult& joined,
		const SnapshotAnalysis::FieldBranchUsesResult& result) {
		for (const auto& use : result.uses)
			callerResultNotes[use.site].push_back(SnapshotAnalysis::FieldBranchNote(joined, use));
        for (const auto& decision : result.decisions)
            callerResultNotes[decision.site].push_back(SnapshotAnalysis::FieldDecisionNote(joined, result, decision));
    }, [&](const SnapshotAnalysis::FieldBranchUsesResult& fields,
        const SnapshotAnalysis::DecisionBranchesResult& result) {
        for (const auto& use : result.uses)
            callerResultNotes[use.site].push_back(SnapshotAnalysis::DecisionBranchNote(fields, result, use));
    }, [&](const SnapshotAnalysis::ClosureCapturesResult& result) {
        std::set<uint64_t> captureSites;
        for (const auto& transfer : result.transfers) {
            if (captureSites.insert(transfer.store).second)
                callerResultNotes[transfer.store].push_back(SnapshotAnalysis::ClosureCaptureNote(transfer));
            callerResultNotes[transfer.call].push_back(SnapshotAnalysis::ClosureCallbackNote(transfer));
        }
	});
	// Render original words after the checked result pass. Only disassembly is
	// repeated here; no receiver/context analysis is rerun for presentation.
	for (auto& payload : assemblyPayloads) {
		if (auto target = libraryPayloads.find(payload.start); target != libraryPayloads.end()) {
			target->second.table = payload.table;
			target->second.index = payload.index;
			target->second.discarded = payload.discarded;
			target->second.comments = std::move(payload.comments);
			continue;
		}
		assembly << std::format("\n// Table {}, entry {}, {} Code metadata; metadata name {}.\n// Payload {:#x}..{:#x}\n",
			payload.table, payload.index, payload.discarded ? "discarded" : "retained", payload.hasMetadata ? "available" : "unavailable", payload.start, payload.end);
		if (!payload.hasMetadata) assembly << std::format("// unattributed_code_{:x}\n", payload.start);
		for (auto name = std::lower_bound(displayNames.begin(), displayNames.end(), payload.start,
			[](const auto& name, uint64_t address) { return name.address < address; });
			name != displayNames.end() && name->address < payload.end; ++name)
			assembly << std::format("// Entry {:#x}: {} ({})\n", name->address, name->text, name->kind);
		auto comment = payload.comments.begin();
		uint64_t cursor = payload.start;
		while (cursor < payload.end) {
			auto instructions = disassembler.Disasm(reinterpret_cast<const uint8_t*>(app.base() + cursor), payload.end - cursor, cursor);
			if (!instructions.Count()) {
				const auto word = *reinterpret_cast<const uint32_t*>(app.base() + cursor);
				assembly << std::format("    // {:#x}: .word {:#010x} ; undecoded word\n", cursor, word);
				cursor += 4;
				continue;
			}
			for (size_t n = 0; n < instructions.Count(); ++n) {
				const auto* instruction = instructions.Ptr(n);
				if (const auto notes = callerResultNotes.find(instruction->address); notes != callerResultNotes.end())
					for (const auto& note : notes->second) assembly << "    // " << note << '\n';
				assembly << std::format("    // {:#x}: {} {}", instruction->address, instruction->mnemonic, instruction->op_str);
				while (comment != payload.comments.end() && comment->first < instruction->address) ++comment;
				if (comment != payload.comments.end() && comment->first == instruction->address) assembly << " ; " << comment->second;
				assembly << '\n';
				cursor = instruction->address + instruction->size;
			}
		}
		assembly << "// End native payload\n";
	}
	assembly.close(); manifest.close();
	if (!assembly || !manifest) throw std::runtime_error("Cannot write snapshot assembly or inventory");
	std::cout << std::format("Snapshot annotations: {} call/jump edges, {} pool/thread references\n",
		annotations.Edges().size(), annotations.References().size());
	std::cout << std::format("Snapshot code: {} payloads, {} additional anonymous exports, {} undecoded words\n",
		total, recoveredCodeRanges.size(), undecoded);
}
#endif

// collect instance ptr to dump the full contents in DumpObjects()
static std::set<intptr_t> knownObjectPtrs;

std::string DartDumper::ObjectToString(dart::Object& obj, bool simpleForm, bool nestedObj, int depth)
{
	const auto cid = obj.GetClassId();
	//auto dartCls = app_.classes[obj.GetClassId()];

	if (obj.IsString()) {
		auto& val = getQuoteString(obj);
		if (simpleForm || depth > 0)
			return val;
		return "String: " + val;
	}

	// use TypedData or TypedDataBase ?
	if (obj.IsTypedData()) {
		//dart::kTypedDataInt32ArrayCid;
		auto& arr = dart::TypedData::Cast(obj);
		const auto arr_len = arr.Length();
		auto ptr = arr.DataAddr(0);
		std::string txt;
		if (arr_len > 0) {
			switch (arr.ElementType()) {
#define ACCUMLATE(type) { \
	auto data = (type*)ptr; \
	txt = std::accumulate(data + 1, data + arr_len, std::format("[{:#x}", data[0]), [](std::string x, type y) { return x + ", " + std::format("{:#x}", y); } ); \
}
			case dart::kInt8ArrayElement:
				ACCUMLATE(int8_t);
				break;
			case dart::kUint8ArrayElement:
			case dart::kUint8ClampedArrayElement:
				ACCUMLATE(uint8_t);
				break;
			case dart::kInt16ArrayElement:
				ACCUMLATE(int16_t);
				break;
			case dart::kUint16ArrayElement:
				ACCUMLATE(uint16_t);
				break;
			case dart::kInt32ArrayElement:
				ACCUMLATE(int32_t);
				break;
			case dart::kUint32ArrayElement:
				ACCUMLATE(uint32_t);
				break;
			case dart::kInt64ArrayElement:
				ACCUMLATE(int64_t);
				break;
			case dart::kUint64ArrayElement:
				ACCUMLATE(uint64_t);
				break;
#undef ACCUMLATE
#define ACCUMLATE(type) { \
	auto data = (type*)ptr; \
	txt = std::accumulate(data + 1, data + arr_len, std::format("[{}", data[0]), [](std::string x, type y) { return x + ", " + std::format("{}", y); } ); \
}
			case dart::kFloat32ArrayElement:
				ACCUMLATE(float);
				break;
			case dart::kFloat64ArrayElement:
				ACCUMLATE(double);
				break;
#undef ACCUMLATE
			case dart::kFloat32x4ArrayElement:
			case dart::kInt32x4ArrayElement:
			case dart::kFloat64x2ArrayElement:
				FATAL("TODO: simd array");
			}

			txt += ']';
		}
		//arr.ElementSizeInBytes();
		return std::format("{}({}) {}", app.GetClass(cid)->Name(), arr_len, txt);
	}

	switch (cid) {
	case dart::kSmiCid:
		if (simpleForm || depth > 0)
			return std::format("{:#x}", dart::Smi::Cast(obj).Value());
		return std::format("Smi: {:#x}", dart::Smi::Cast(obj).Value());
	case dart::kMintCid:
		if (simpleForm || depth > 0)
			return std::format("{:#x}", MintValue(dart::Mint::Cast(obj)));
		return std::format("Mint: {:#x}", MintValue(dart::Mint::Cast(obj)));
	case dart::kDoubleCid:
		if (simpleForm || depth > 0)
			return std::format("{}", dart::Double::Cast(obj).value());
		return std::format("Double: {}", dart::Double::Cast(obj).value());
	case dart::kBoolCid:
		return dart::Bool::Cast(obj).value() ? "true" : "false";
	case dart::kNullCid:
		return "Null";
	case dart::kSentinelCid:
		return "Sentinel";
	case dart::kSubtypeTestCacheCid:
		return "SubtypeTestCache";
	case dart::kFunctionCid: {
		// stub never be in Object Pool
		const auto& metadata = dart::Function::Cast(obj);
		auto* dartFn = app.FindFunctionMetadata(metadata.ptr());
		if (!dartFn) {
			auto* fnBase = app.GetFunction(metadata.entry_point() - app.base());
			if (fnBase == nullptr || fnBase->IsStub())
				return std::format("Function: [unknown] ({:#x})", metadata.entry_point() - app.base());
			dartFn = fnBase->AsFunction();
		}
		if (dartFn->IsClosure()) {
			auto parentFn = dartFn->GetOutermostFunction();
			if (parentFn) {
				// AOT anonymous closure contains only static information
				return std::format("AnonymousClosure: {}({:#x}), in {} ({:#x})",
					dartFn->IsStatic() ? "static " : "", dartFn->Address(),
					parentFn->FullName(), parentFn->Address());
			}
			else {
				return std::format("AnonymousClosure: {}({:#x}), of {}",
					dartFn->IsStatic() ? "static " : "", dartFn->Address(),
					dartFn->Class().FullNameWithPackage());
			}
		}
		return std::format("Function: {} ({:#x})", dartFn->FullName(), dartFn->Address());
	}
	case dart::kClosureCid: {
		// TODO: show owner
		const auto& closure = dart::Closure::Cast(obj);
		if (!app.functions.contains(closure.entry_point() - app.base())) {
			std::cout << std::format("[!] missing closure at {:#x}\n", closure.entry_point() - app.base());
		}
		//RELEASE_ASSERT(app.functions.contains(closure.entry_point() - app.base()));
#if defined(BLUTTER_SHOREBIRD_3C9C)
		const auto imageStart = reinterpret_cast<uintptr_t>(app.isolate_snapshot_instructions);
		const auto imageEnd = imageStart + *reinterpret_cast<const uintptr_t*>(imageStart);
		const auto entry = closure.entry_point();
		if (entry >= imageStart && entry < imageEnd)
			return std::format("{} (ELF {:#x})", closure.ToCString(), entry - app.base());
		return std::format("{} (entry unresolved)", closure.ToCString());
#else
		return std::format("{} ({:#x})", closure.ToCString(), closure.entry_point());
#endif
	}
	case dart::kCodeCid: {
		const auto& code = dart::Code::Cast(obj);
		const auto ep = code.EntryPoint() - app.base();
		if (app.stubs.contains(ep)) {
			const auto stub = app.stubs[ep];
			return std::format("Stub: {} ({:#x})", stub->Name().c_str(), ep);
		}
		return std::format("Code: {} ({:#x})", code.ToCString(), ep);
	}
	case dart::kArrayCid:
	case dart::kImmutableArrayCid: {
		// Note: since Dart 3.7, Ojbect Pool is mutable. so, Array is used too
		// Objects in Object Pool immutable, so only immutable array is used for array
		// Most of no type arguments in Object Pool are Argument Descriptor
		const auto& arr = dart::Array::Cast(obj);
		const auto arr_len = arr.Length();
		const auto typeArg = app.typeDb->FindOrAdd(arr.GetTypeArguments());
		// without type arguments, assume it is argument descriptor. show it even simple form is true.
		if (simpleForm && typeArg->Length() > 0)
			return std::format("List{}({})", typeArg->ToString(), arr_len);

		std::ostringstream ss;
		if (arr_len > 0) {
			// in ImmutableList here, only Dart type (native type is not used)
			auto arrPtr = dart::Array::DataOf(arr.ptr());
			for (intptr_t i = 0; i < arr_len; i++) {
				if (i != 0)
					ss << ", ";

				if (arrPtr->IsHeapObject()) {
					obj = arrPtr->Decompress(app.heap_base());
					ss << ObjectToString(obj, simpleForm, nestedObj, depth + 1);
				}
				else {
					obj = arrPtr->DecompressSmi();
					ss << std::hex << std::showbase << dart::Smi::Cast(obj).Value();
				}
				arrPtr++;
			}
		}
		return std::format("List{}({}) [{}]", typeArg->ToString(), arr_len, ss.str());
	}
#ifdef HAS_RECORD_TYPE
	case dart::kRecordCid: {
		const auto& record = dart::Record::Cast(obj);
		std::ostringstream ss;
		const auto type = app.typeDb->FindOrAdd(DartGetRecordType(record));
		ss << "Record" << type->ToString() << " = (";
		auto& field = dart::Object::Handle();
		const auto num_fields = record.num_fields();
		for (intptr_t i = 0; i < num_fields; i++) {
			if (i != 0) ss << ", ";
			field = record.FieldAt(i);
			ss << ObjectToString(field, simpleForm, nestedObj, depth + 1);
		}
		ss << ")";
		return ss.str();
	}
#endif
	case dart::kTypeArgumentsCid:
		return "TypeArguments: " + app.typeDb->FindOrAdd(dart::TypeArguments::RawCast(obj.ptr()))->ToString();
	case dart::kTypeCid:
		return "Type: " + app.typeDb->FindOrAdd(dart::Type::RawCast(obj.ptr()))->ToString();
#ifdef HAS_RECORD_TYPE
	case dart::kRecordTypeCid:
		return "RecordType: " + app.typeDb->FindOrAdd(dart::RecordType::RawCast(obj.ptr()))->ToString();
#endif
	case dart::kTypeParameterCid:
		return "TypeParameter: " + app.typeDb->FindOrAdd(dart::TypeParameter::RawCast(obj.ptr()))->ToString();
	case dart::kFunctionTypeCid:
		return "FunctionType: " + app.typeDb->FindOrAdd(dart::FunctionType::RawCast(obj.ptr()))->ToString();
#ifdef HAS_TYPE_REF
	case dart::kTypeRefCid:
#endif
	case dart::kTypeParametersCid:
		// might be in a Type but not in Object Pool directly
		return std::format("{} (ptr: {:#x})", obj.ToCString(), (uint64_t)obj.ptr());
	case dart::kFieldCid: {
		const auto& field = dart::Field::Cast(obj);
		return std::format("{} (offset: {:#x})", field.ToCString(), field.TargetOffset());
	}
	case dart::kConstMapCid: {
		auto& map = dart::Map::Cast(obj);
		const auto typeArg = app.typeDb->FindOrAdd(map.GetTypeArguments());
		if (simpleForm)
			return std::format("Map{}({})", typeArg->ToString(), map.Length());

		std::ostringstream ss;
		std::string indent(depth * 2 + 2, ' ');
		ss << std::format("Map{}({}) {{\n", typeArg->ToString(), map.Length());
		dart::Map::Iterator iter(map);
		auto& key = dart::Object::Handle();
		auto& val = dart::Object::Handle();
		int cnt = 0;
		while (iter.MoveNext()) {
			if (cnt++) ss << ",\n";
			key = iter.CurrentKey();
			val = iter.CurrentValue();
			// key always be simple form
			ss << indent << ObjectToString(key, true, false, depth + 1) << ": " << ObjectToString(val, simpleForm, nestedObj, depth + 1);
		}
		if (cnt) ss << "\n";
		ss << std::string(depth * 2, ' ') << "}";
		return ss.str();
	}
	case dart::kConstSetCid: {
		auto& set = dart::Set::Cast(obj);
		const auto typeArg = app.typeDb->FindOrAdd(set.GetTypeArguments());
		if (simpleForm)
			return std::format("Set{}({})", typeArg->ToString(), set.Length());

		std::ostringstream ss;
		ss << std::format("Set{}({}) {{ ", typeArg->ToString(), set.Length());
		dart::Set::Iterator iter(set);
		auto& key = dart::Object::Handle();
		int cnt = 0;
		while (iter.MoveNext()) {
			if (cnt++)
				ss << ", ";
			key = iter.CurrentKey();
			ss << ObjectToString(key, simpleForm, nestedObj, depth + 1);
		}
		ss << " }";
		return ss.str();
	}
	case dart::kLibraryPrefixCid: {
		const auto& libPrefix = dart::LibraryPrefix::Cast(obj);
		const auto& name = dart::String::Handle(libPrefix.name());
		RELEASE_ASSERT(libPrefix.num_imports() == 1);
		// don't know what importer is
		//const auto& importer = dart::Library::Handle(libPrefix.importer());
		const auto& imports = dart::Array::Handle(libPrefix.imports());
		const auto& importObj = dart::Object::Handle(imports.At(0));
		RELEASE_ASSERT(importObj.GetClassId() == dart::kNamespaceCid);
		const auto& ns = dart::Namespace::Cast(importObj);
		const auto& lib = dart::Library::Handle(ns.target());
		const auto& libName = dart::String::Handle(lib.url());
		return std::format("LibraryPrefix: {}, target lib: {} ({})", name.ToCString(), libName.ToCString(), lib.toplevel_class().untag()->id());
	}
	case dart::kInt32x4Cid: {
		const auto& simd = dart::Int32x4::Cast(obj);
		return std::format("Int32x4: ({}, {}, {}, {})", simd.x(), simd.y(), simd.z(), simd.w());
	}
	case dart::kFloat32x4Cid: {
		const auto& simd = dart::Float32x4::Cast(obj);
		return std::format("Float32x4: ({}, {}, {}, {})", simd.x(), simd.y(), simd.z(), simd.w());
	}
	case dart::kFloat64x2Cid: {
		const auto& simd = dart::Float64x2::Cast(obj);
		return std::format("Float64x2: ({}, {})", simd.x(), simd.y());
	}
	case dart::kInstanceCid:
		return std::format("Obj!Object@{:x}", (uint32_t)(intptr_t)obj.ptr());
	// TODO: enum subclass
	}

	// many cids are instance. handling them after special classes.
	ASSERT(obj.IsInstance());

	if (cid < dart::kNumPredefinedCids) {
		FATAL("Unhandle internal class %s (%ld)", app.GetClass(cid)->Name().c_str(), cid);
	}

	// TODO: print library and package prefix
	knownObjectPtrs.insert((intptr_t)obj.ptr());
	return dumpInstance(obj, simpleForm, nestedObj, depth);
}

std::string DartDumper::dumpInstance(dart::Object& obj, bool simpleForm, bool nestedObj, int depth)
{
	auto dartCls = app.classes[obj.GetClassId()];
	ASSERT(dartCls->Id() >= dart::kNumPredefinedCids);

	std::string closeIndent(depth * 2, ' ');
	std::string indent(closeIndent.length() + 2, ' ');

	const auto ptr = dart::UntaggedObject::ToAddr(obj.ptr());
	DartType* dtype = app.typeDb->FindOrAdd(*dartCls, dart::Instance::Cast(obj));
	if (simpleForm || (!nestedObj && depth > 0)) {
		return std::format("Obj!{}@{:x}", dtype->ToString(), (uint32_t)(intptr_t)obj.ptr());
	}

	std::vector<DartClass*> parents;
	auto superCls = dartCls->Parent();
	while (superCls->Id() != dart::kInstanceCid) {
		parents.push_back(superCls);
		superCls = superCls->Parent();
	}

	std::ostringstream ss;
	int fieldCnt = 0;
	ss << std::format("Obj!{}@{:x} : {{\n", dtype->ToString(), (uint32_t)(intptr_t)obj.ptr());
	auto offset = dart::Instance::NextFieldOffset();
	for (auto parent : parents | std::views::reverse) {
		if (offset < parent->Size()) {
			// parent fields depth MUST increment by 2 because 1 is for "Super!..."
			auto txt = dumpInstanceFields(obj, *parent, ptr, offset, simpleForm, nestedObj, depth + 2);
			offset = parent->Size();
			if (!txt.empty()) {
				if (fieldCnt++)
					ss << ",\n";
				ss << indent << "Super!" << parent->FullName() << " : {\n";
				ss << txt << "\n";
				ss << indent << "}";
			}
		}
	}

	auto fieldTxt = dumpInstanceFields(obj, *dartCls, ptr, offset, simpleForm, nestedObj, depth + 1);
	if (!fieldTxt.empty()) {
		if (fieldCnt++)
			ss << ",\n";
		ss << fieldTxt;
	}
	if (fieldCnt)
		ss << "\n";
	ss << closeIndent << "}";

	return ss.str();
}

std::string DartDumper::dumpInstanceFields(dart::Object& obj, DartClass& dartCls, intptr_t ptr, intptr_t offset, bool simpleForm, bool nestedObj, int depth)
{
	std::stringstream ss;
	std::string indent(depth * 2, ' ');

	const auto bitmap = dartCls.UnboxedFieldsBitmap();
	while (offset < dartCls.Size()) {
		std::string txtField;
		// TODO: match the offset to field name if possible
		if (bitmap.Get(offset / dart::kCompressedWordSize)) {
			// AOT uses native integer if it is less than 31 bits (compressed pointer)
			// integer (4/8 bytes) or double (8 bytes)
			if (dart::kCompressedWordSize == 4)
				RELEASE_ASSERT(bitmap.Get((offset + dart::kCompressedWordSize) / dart::kCompressedWordSize));
			const auto bits = ReadUnaligned64(reinterpret_cast<const void*>(ptr + offset));
			// it is rare to find integer that larger than 0x1000_0000_0000_0000
			if (bits <= 0x1000000000000000 || bits >= 0xffffffffffff0000) {
				txtField = std::format("off_{:x}: int({:#x})", offset, bits);
			}
			else {
				txtField = std::format("off_{:x}: double({})", offset, std::bit_cast<double>(bits));
			}
			offset += dart::kCompressedWordSize;
		}
		else if (offset != dartCls.TypeArgumentsOffset()) {
			// compressed object ptr
			auto p = reinterpret_cast<dart::CompressedObjectPtr*>(ptr + offset);
			if (*p != dart::CompressedObjectPtr(nullptr)) {
				if (p->IsHeapObject()) {
					auto objPtr2 = p->Decompress(app.heap_base());
					if (objPtr2 != nullptr && objPtr2.GetClassId() != dart::kNullCid) {
						obj = objPtr2;
						if (simpleForm || objPtr2.GetClassId() < dart::kNumPredefinedCids)
							txtField = std::format("off_{:x}: {}", offset, ObjectToString(obj, simpleForm, nestedObj, depth));
						else
							txtField = std::format("off_{:x}_{}", offset, ObjectToString(obj, simpleForm, nestedObj, depth));
					}
				}
				else {
					obj = p->DecompressSmi();
					txtField = std::format("off_{:x}_Smi: {:#x}", offset, dart::Smi::Cast(obj).Value());
				}
			}
		}
		offset += dart::kCompressedWordSize;

		if (!txtField.empty()) {
			if (ss.tellp() != 0)
				ss << ",\n";
			ss << indent << txtField;
		}
	}

	return ss.str();
}

std::string DartDumper::getPoolObjectDescription(intptr_t offset, bool simpleForm)
{
	const auto& pool = app.GetObjectPool();
	intptr_t idx = dart::ObjectPool::IndexFromOffset(offset);
	auto objType = pool.TypeAt(idx);
	// see how the EntryType is handled from vm/object_service.cc - ObjectPool::PrintJSONImpl()
	if (objType == dart::ObjectPool::EntryType::kTaggedObject) {
		auto& obj = dart::Object::Handle(pool.ObjectAt(idx));
		if (obj.IsUnlinkedCall()) {
			// since Dart 3.10, target type might be kTaggedObject
			auto unlinkTargetType = pool.TypeAt(idx + 1);
			if (unlinkTargetType == dart::ObjectPool::EntryType::kImmediate) {
				const auto imm = pool.RawValueAt(idx + 1);
				auto dartFn = app.GetFunction(imm - app.base());
				if (dartFn != nullptr) {
					return std::format("[pp+{:#x}] UnlinkedCall: {:#x} - {}", offset, dartFn->Address(), dartFn->FullName().c_str());
				}
				else {
					return std::format("[pp+{:#x}] UnlinkedCall: {:#x} - [unknown function]", offset, imm - app.base());
				}
			}
			else {
				ASSERT(unlinkTargetType == dart::ObjectPool::EntryType::kTaggedObject);
				auto& obj2 = dart::Object::Handle(pool.ObjectAt(idx + 1));
				return std::format("[pp+{:#x}] UnlinkedCall: {}", offset, ObjectToString(obj2, simpleForm));
			}
		}
		return std::format("[pp+{:#x}] {}", offset, ObjectToString(obj, simpleForm));
	}
	else if (objType == dart::ObjectPool::EntryType::kImmediate) {
		dart::uword imm = pool.RawValueAt(idx);
		if (imm <= 0x1000000000000000 || imm >= 0xffffffffffff0000) {
			return std::format("[pp+{:#x}] IMM: {:#x}", offset, imm);
		}
		else {
			return std::format("[pp+{:#x}] IMM: double({}) from {:#x}", offset, std::bit_cast<double>(imm), imm);
		}
	}
	else if (objType == dart::ObjectPool::EntryType::kNativeFunction) {
		auto pc = pool.RawValueAt(idx);
		uintptr_t start = 0;
		auto name = dart::NativeSymbolResolver::LookupSymbolName(pc, &start);
		if (name != NULL) {
			auto txt = std::format("[pp+{:#x}] NativeFn: {} at {:#x}", offset, name, pc);
			dart::NativeSymbolResolver::FreeSymbolName(name);
			return txt;
		}
		else {
			return std::format("[pp+{:#x}] NativeFn: [no name] at {:#x}", offset, pc);
		}
	}
	else {
		throw std::runtime_error(std::format("unknown pool object type: {}", (int)objType).c_str());
	}
}

void DartDumper::DumpObjectPool(const char* filename)
{
	std::ofstream of(filename);
	const auto& pool = app.GetObjectPool();
	intptr_t num = pool.Length();

	const auto& rawObj = pool.ptr()->untag();
	const auto raw_addr = dart::UntaggedObject::ToAddr(rawObj);
	of << std::format("pool heap offset: {:#x}\n", raw_addr - app.heap_base());

	for (intptr_t i = 0; i < num; i++) {
		// offset here is from ObjectPool pointer subtracted by kHeapObjectTag
		// add 1 to make the offset value same as offset in compiled code
		intptr_t offset = dart::ObjectPool::OffsetFromIndex(i);
		auto txt = getPoolObjectDescription(offset + 1, false);
		of << txt << "\n";
		if (txt.compare(txt.find(']'), 15, "] UnlinkedCall:") == 0)
			i++;
	}
}

void DartDumper::DumpObjects(const char* filename)
{
	std::ofstream of(filename);

	auto& obj = dart::Object::Handle();
	for (auto objPtr : knownObjectPtrs) {
		obj = dart::ObjectPtr(objPtr);
		const bool simpleForm = false;
		const bool nestedObj = true;
		of << dumpInstance(obj, simpleForm, nestedObj, 0);
		of << "\n\n";
	}
}
