#include "pch.h"
#include "ReaderProbe.h"
#include "DartThreadInfo.h"
#include "ElfHelper.h"
#include "ReadUnaligned.h"
#include <fstream>
#include <limits>
#include <vm/stub_code.h>

void WriteReaderProbe(const std::filesystem::path& destination, uintptr_t libraryBase)
{
#ifdef HAS_INSTRUCTIONS_TABLE_RODATA
#if !defined(BLUTTER_SHOREBIRD_26A7)
	if (!TargetRuntime::hasNativeCallGuard)
		throw std::runtime_error("Reader probing requires a supported guarded runtime family");
#endif
	const auto images = ElfHelper::findSnapshots(reinterpret_cast<const uint8_t*>(libraryBase));
	if (!images.isolate_snapshot_instructions)
		throw std::runtime_error("Reader probe has no isolate instructions image");
	const auto imageStart = reinterpret_cast<uintptr_t>(images.isolate_snapshot_instructions);
	const auto imageSize = ReadUnaligned64(images.isolate_snapshot_instructions);
	if (imageSize < 128 || imageSize > std::numeric_limits<uintptr_t>::max() - imageStart)
		throw std::runtime_error("Reader probe found an invalid instructions image size");
	const auto imageEnd = imageStart + imageSize;
	auto* thread = dart::Thread::Current();
	const auto& tables = dart::GrowableObjectArray::Handle(
		thread->zone(), thread->isolate_group()->object_store()->instructions_tables());
	if (tables.IsNull() || tables.Length() != 1)
		throw std::runtime_error("Reader probe requires exactly one application instructions table");
	const auto& table = dart::InstructionsTable::Handle(
		thread->zone(), dart::InstructionsTable::RawCast(tables.At(0)));
	const auto* data = table.rodata();
	const auto& codes = dart::Array::Handle(thread->zone(), table.code_objects());
	if (!data || !data->length || data->length > imageSize / 4 ||
		data->first_entry_with_code > data->length ||
		codes.Length() != data->length - data->first_entry_with_code)
		throw std::runtime_error("Reader probe found inconsistent native table counts");
	uintptr_t previous = 0;
	for (uint32_t index = 0; index < data->length; ++index) {
		const auto entry = table.EntryPointAt(index);
		const auto offset = data->entries()[index].pc_offset;
		if (offset >= imageSize || entry != imageStart + offset ||
			entry < imageStart + 64 || entry >= imageEnd || entry % 4 ||
			(index && entry <= previous))
			throw std::runtime_error("Reader probe found an invalid native payload boundary");
		if (index >= data->first_entry_with_code) {
			const auto& code = dart::Code::Handle(thread->zone(), dart::Code::RawCast(
				codes.At(index - data->first_entry_with_code)));
			const auto end = index + 1 < data->length ? table.EntryPointAt(index + 1) : imageEnd;
			if (code.PayloadStart() != entry || code.Size() <= 0 ||
				static_cast<uintptr_t>(code.Size()) != end - entry)
				throw std::runtime_error("Reader probe found a Code/payload extent disagreement");
		}
		previous = entry;
	}

	std::ofstream file(destination);
	if (!file) throw std::runtime_error("Cannot create reader probe report");
	file << std::format(
		"{{\"schema\":1,\"status\":\"deserialized\",\"image_start\":{},\"image_end\":{},"
		"\"table_address\":{},\"payload_count\":{},\"first_with_code\":{},"
		"\"vm_tag_offset\":{},\"native_call_state_offset\":{},\"vm_stubs\":[",
		imageStart - libraryBase, imageEnd - libraryBase,
		reinterpret_cast<uintptr_t>(data) - libraryBase, data->length, data->first_entry_with_code,
		TargetThreadOffset(dart::Thread::vm_tag_offset()), TargetNativeCallStateOffset());
	bool comma = false;
#define WRITE_STUB_NAME(name) \
	if (comma) file << ','; \
	comma = true; \
	file << '"' << #name << '"';
	VM_STUB_CODE_LIST(WRITE_STUB_NAME);
#undef WRITE_STUB_NAME
#if defined(BLUTTER_SHOREBIRD_26A7)
	file << "],\"abi_kind\":\"arm64_stub_layout_v1\",\"thread_offsets\":{";
	bool firstOffset = true;
	for (const auto& [offset, name] : GetThreadOffsetsMap()) {
		if (!firstOffset) file << ',';
		firstOffset = false;
		file << '"' << name << "\":" << offset;
	}
	file << "},\"stub_ranges\":[";
	comma = false;
#define WRITE_STUB_RANGE(name) { \
	const auto& code = dart::StubCode::name(); \
	if (comma) file << ','; \
	comma = true; \
	file << std::format("{{\"name\":\"{}\",\"start\":{},\"size\":{}}}", \
		#name, code.PayloadStart() - libraryBase, code.Size()); \
}
	VM_STUB_CODE_LIST(WRITE_STUB_RANGE);
#undef WRITE_STUB_RANGE
	file << "]}\n";
#elif defined(BLUTTER_SHOREBIRD_DB65)
	file << "],\"abi_kind\":\"guarded_relocations_v1\"}\n";
#else
	file << "]}\n";
#endif
	file.close();
	if (!file) throw std::runtime_error("Cannot finish reader probe report");
#else
	throw std::runtime_error("Reader probing requires the supported instructions-table API");
#endif
}
