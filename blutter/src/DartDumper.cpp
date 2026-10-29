#include "pch.h"
#include "DartDumper.h"
#include "ReadUnaligned.h"
#include <bit>
#include <fstream>
#include <format>
#include <set>
#include <ranges>
#include <iostream>
#include <sstream>
#include <numeric>
#if defined(BLUTTER_SHOREBIRD_3C9C) || defined(HAS_INSTRUCTIONS_TABLE_RODATA)
#include <vm/heap/safepoint.h>
#include "SnapshotCodeAnalysis.h"
#include "SnapshotCodeRanges.h"
#endif
#include "Disassembler.h"
#include "DartThreadInfo.h"
#include "CodeAnalyzer.h"

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

#if defined(BLUTTER_SHOREBIRD_3C9C) || defined(HAS_INSTRUCTIONS_TABLE_RODATA)
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
	of << "],\"pool_heap_classes\":[";
	comma = false;
	const auto& pool = app.GetObjectPool();
	for (intptr_t i = 0; i < pool.Length(); ++i) if (pool.TypeAt(i) == dart::ObjectPool::EntryType::kTaggedObject) {
		const auto& object = dart::Object::Handle(zone, pool.ObjectAt(i));
		if (!object.IsSmi()) { if (comma) of << ','; comma = true; of << '[' << i << ',' << object.GetClassId() << ']'; }
	}
	of << "],\"word_return_register\":" << (dart::CallingConventions::kReturnReg == dart::R0 ? "\"x0\"" : "null");
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
	of << "],\"array_body_contract\":[";
	if (!arrayAllocation.IsNull()) of << arrayAllocation.EntryPoint() - app.base() << ',' << dart::AllocateArrayABI::kLengthReg << ','
		<< dart::Array::data_offset() - dart::kHeapObjectTag << ',' << dart::compiler::target::kCompressedWordSize << ',' << dart::kSmiTagShift;
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
	of << "]}\n";
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
#if !defined(BLUTTER_SHOREBIRD_3C9C) && !defined(HAS_INSTRUCTIONS_TABLE_RODATA)
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
#if !defined(BLUTTER_SHOREBIRD_3C9C) && !defined(HAS_INSTRUCTIONS_TABLE_RODATA)
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


#if defined(BLUTTER_SHOREBIRD_3C9C) || defined(HAS_INSTRUCTIONS_TABLE_RODATA)
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

void DartDumper::DumpCode(const char* out_dir)
{
	std::filesystem::create_directory(out_dir);

	Disassembler disasmer;

	for (auto dartLib : app.libs) {
		if (dartLib->isInternal)
			continue;

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

						of << "    // ";

						if (range.Has(asmText.addr)) {
							of << "    ";
						}
						else {
							while ((*il_itr)->Start() < asmText.addr) {
								if ((*il_itr)->Kind() != ILInstr::Unknown) {
									of << std::format("{:#x}: {}\n", (*il_itr)->Start(), (*il_itr)->ToString());
									of << "    // ";
								}
								++il_itr;
							}
							if ((*il_itr)->Start() == asmText.addr) {
								if ((*il_itr)->Kind() != ILInstr::Unknown) {
									of << std::format("{:#x}: {}\n", asmText.addr, (*il_itr)->ToString());
									of << "    //     ";
									range = (*il_itr)->Range();
								}
								++il_itr;
							}
						}

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
	}
#if defined(BLUTTER_SHOREBIRD_3C9C) || defined(HAS_INSTRUCTIONS_TABLE_RODATA)
	DumpSnapshotCode(out_dir);
#endif
}

#if defined(BLUTTER_SHOREBIRD_3C9C) || defined(HAS_INSTRUCTIONS_TABLE_RODATA)
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
	std::vector<uint64_t> metadataEntries;
	std::vector<SnapshotAnalysis::Name> metadataNames;
	for (const auto* library : app.libs) {
		for (auto* cls : library->classes) {
			for (const auto* fn : cls->Functions()) {
				metadataEntries.push_back(fn->Address());
				metadataNames.push_back({fn->Address(), fn->FullName(), "function"});
			}
		}
	}
	for (const auto& [address, stub] : app.stubs) {
		metadataEntries.push_back(address);
		metadataNames.push_back({address, stub->FullName(), "stub"});
	}
	std::sort(metadataEntries.begin(), metadataEntries.end());
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
	for (const auto& [start, end] : inventory) {
		payloads.push_back({start - app.base(), end - app.base(), {}, ""});
	}
	const auto& pool = app.GetObjectPool();
#if defined(BLUTTER_SHOREBIRD_3C9C)
	const std::string profileName = "shorebird_3c9c";
#else
	const std::string profileName = "dart_aot";
#endif
	SnapshotAnalysis::Profile profile{profileName, ARM64_REG_X27, ARM64_REG_X26,
		dart::ObjectPool::element_offset(0), 8, pool.Length(), {}, {}};
	profile.dispatchRegister = ARM64_REG_X21;
	if constexpr (dart::CallingConventions::kReturnReg == dart::R0) profile.wordReturnRegister = ARM64_REG_X0;
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
	if (!mintAllocation.IsNull() && profile.allocationReturns.contains(mintAllocation.EntryPoint() - app.base()))
		profile.preservedCallRegisters.emplace(mintAllocation.EntryPoint() - app.base(),
			static_cast<uint32_t>(dart::kDartAvailableCpuRegs) & ~(1U << dart::AllocateMintABI::kResultReg) & ~(1U << dart::AllocateMintABI::kTempReg));
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
	SnapshotAnalysis::Analyzer annotations(std::move(profile), std::move(payloads), std::move(metadataNames));
	// A separate first pass records cross-payload entry points before any alias
	// tracking. Do not carry an alias through a known incoming branch target.
	for (uint32_t i = 0; i < rootTable.rodata()->length; ++i) {
		const auto start = rootTable.EntryPointAt(i);
		const auto end = i + 1 < rootTable.rodata()->length ? rootTable.EntryPointAt(i + 1) : imageEnd;
		auto instructions = disassembler.Disasm(reinterpret_cast<const uint8_t*>(start), end - start, start - app.base());
		annotations.RegisterEntries(instructions.Insns(), instructions.Count());
	}
	assembly << "// Raw native payloads from the VM instructions table.\n"
		"// Names/types may be unavailable; this file contains no inferred Dart IL.\n";
	manifest << "{\"format\":1,\"image_start\":" << imageStart - app.base()
		<< ",\"image_end\":" << imageEnd - app.base()
		<< ",\"table_data_address\":" << reinterpret_cast<uintptr_t>(rootTable.rodata()) - app.base()
		<< ",\"table_length\":" << rootTable.rodata()->length
		<< ",\"first_entry_with_code\":" << rootTable.rodata()->first_entry_with_code
		<< ",\"ranges\":[";
	bool comma = false;
	uint64_t total = 0;
	uint64_t undecoded = 0;
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
			manifest << std::format("{{\"table\":{},\"index\":{},\"start\":{},\"end\":{},\"discarded_code\":{},\"has_metadata_name\":{}}}",
				t, i, address, limit, i < table.rodata()->first_entry_with_code ? "true" : "false", hasMetadata ? "true" : "false");
			assembly << std::format("\n// Table {}, entry {}, {} Code metadata; {}existing export.\n// Payload {:#x}..{:#x}\n",
				t, i, i < table.rodata()->first_entry_with_code ? "discarded" : "retained", hasMetadata ? "" : "no ", address, limit);
			if (!hasMetadata) assembly << std::format("// unattributed_code_{:x}\n", address);
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
					const auto word = *reinterpret_cast<const uint32_t*>(app.base() + cursor);
					assembly << std::format("    // {:#x}: .word {:#010x} ; undecoded word\n", cursor, word);
					cursor += 4;
					++undecoded;
					continue;
				}
				const auto comments = cursor == address && instructions.Count() * 4 == limit - address
					? annotations.Analyze(instructions.Insns(), instructions.Count(), address)
					: std::map<uint64_t, std::string>{};
				for (size_t n = 0; n < instructions.Count(); ++n) {
					const auto* instruction = instructions.Ptr(n);
					assembly << std::format("    // {:#x}: {} {}", instruction->address, instruction->mnemonic, instruction->op_str);
					if (const auto comment = comments.find(instruction->address); comment != comments.end())
						assembly << " ; " << comment->second;
					assembly << '\n';
					cursor = instruction->address + instruction->size;
				}
			}
			++total;
		}
	}
	manifest << std::format("],\"payload_count\":{},\"additional_exports\":{},\"undecoded_words\":{}}}\n",
		total, recoveredCodeRanges.size(), undecoded);
	annotations.Write((directory.parent_path() / "snapshot_calls.json").string());
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
		auto fnBase = app.GetFunction(dart::Function::Cast(obj).entry_point() - app.base());
		if (fnBase == nullptr || fnBase->IsStub()) {
			return std::format("Function: [unknown] ({:#x})", dart::Function::Cast(obj).entry_point() - app.base());
		}
		auto dartFn = fnBase->AsFunction();
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
