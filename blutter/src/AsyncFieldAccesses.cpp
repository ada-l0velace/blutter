#include "AsyncFieldAccesses.h"
#include "Arm64Decode.h"
#include "Arm64Ir.h"
#include "SnapshotCodeAnalysis.h"
#include <algorithm>
#include <format>
#include <memory>
#include <ostream>
#include <stdexcept>

namespace SnapshotAnalysis
{
namespace
{
constexpr size_t Limit = 200000, LocalLimit = 64;
int Number(arm64_reg reg)
{
	if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28)
		return reg - ARM64_REG_X0;
	if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30)
		return reg - ARM64_REG_W0;
	return -1;
}
unsigned Width(arm64_reg reg)
{
	return reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28   ? 8
	       : reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30 ? 4
	                                                     : 0;
}
bool Group(const cs_insn &i, unsigned group)
{
	return std::find(i.detail->groups, i.detail->groups + i.detail->groups_count, group) !=
	       i.detail->groups + i.detail->groups_count;
}
std::string Quote(const std::string &text)
{
	std::string result = "\"";
	for (unsigned char ch : text) {
		if (ch == '"' || ch == '\\') {
			result += '\\';
			result += ch;
		} else if (ch < 32 || ch == 127)
			result += std::format("\\u{:04x}", ch);
		else
			result += ch;
	}
	return result + '"';
}
void Validate(const InstanceLayout &layout)
{
	if (layout.kind == "unsupported")
		return;
	if (!layout.classId || layout.tag != 1 || (layout.slotBytes != 4 && layout.slotBytes != 8) ||
	    layout.header < 8 || layout.end < layout.header || layout.end > 1048576 ||
	    layout.header % layout.slotBytes || layout.end % layout.slotBytes ||
	    (layout.kind != "instance" && layout.kind != "context"))
		throw std::runtime_error("Invalid async field layout");
	for (const auto *offsets : {&layout.excluded, &layout.unboxed}) {
		if (!std::is_sorted(offsets->begin(), offsets->end()) ||
		    std::adjacent_find(offsets->begin(), offsets->end()) != offsets->end())
			throw std::runtime_error("Invalid async field exclusions");
		for (auto off : *offsets)
			if (off < layout.header || off >= layout.end || off % layout.slotBytes)
				throw std::runtime_error("Invalid async field exclusion offset");
	}
	int64_t previous = -1;
	for (const auto &field : layout.fields) {
		if (!field.owner || field.offset <= previous || field.offset < layout.header ||
		    field.offset >= layout.end || field.offset % layout.slotBytes ||
		    std::binary_search(layout.excluded.begin(), layout.excluded.end(), field.offset) ||
		    std::binary_search(layout.unboxed.begin(), layout.unboxed.end(), field.offset))
			throw std::runtime_error("Invalid retained async field");
		previous = field.offset;
	}
	if (layout.kind == "context" && (layout.contextParent < layout.header || layout.contextParent > 4096 ||
	                                 layout.contextParent + layout.slotBytes > layout.contextData ||
	                                 layout.contextData % layout.slotBytes || layout.contextData > 4096))
		throw std::runtime_error("Invalid async context layout");
}
} // namespace

void ValidateInstanceLayout(const InstanceLayout &layout)
{
	Validate(layout);
}

void AnalyzeFieldAccesses(const cs_insn *raw, size_t count, const InstanceLayout &layout,
                          const std::set<uint64_t> &entries, AsyncFieldContext &context, size_t &remaining)
{
	Validate(layout);
	if (context.reg >= 15 || context.classId != layout.classId)
		throw std::runtime_error("Invalid async field seed");
	if (layout.kind == "unsupported") {
		context.status = "unsupported_layout";
		return;
	}
	if (!raw || !count) {
		context.status = "missing_seed";
		return;
	}
	std::set<uint64_t> barriers = entries;
	for (size_t n = 0; n < count; ++n) {
		if (!raw[n].detail || raw[n].size != 4 || (n && raw[n].address != raw[n - 1].address + 4))
			throw std::runtime_error("Invalid async field instruction region");
		if (Group(raw[n], CS_GRP_JUMP)) {
			const auto &d = raw[n].detail->arm64;
			if (d.op_count && d.operands[d.op_count - 1].type == ARM64_OP_IMM)
				barriers.insert(d.operands[d.op_count - 1].imm);
		}
	}
	const auto first = std::lower_bound(raw, raw + count, context.seed,
	                                    [](const cs_insn &i, uint64_t site) { return i.address < site; });
	if (first == raw + count || first->address != context.seed) {
		context.status = "missing_seed";
		return;
	}
	uint32_t registers = 1U << context.reg;
	context.status = "payload_end";
	for (auto i = first; i != raw + count; ++i) {
		if (barriers.contains(i->address)) {
			context.status = "alternate_entry";
			break;
		}
		if (!remaining || context.steps == LocalLimit) {
			context.status = remaining ? "local_limit" : "work_limit";
			break;
		}
		--remaining;
		++context.steps;
		if (i->id == ARM64_INS_NOP)
			continue;
		if (Group(*i, CS_GRP_CALL)) {
			context.status = "call_boundary";
			break;
		}
		if (Group(*i, CS_GRP_JUMP) || Group(*i, CS_GRP_RET) || Group(*i, CS_GRP_INT) ||
		    i->id == ARM64_INS_BRK) {
			context.status = "control_boundary";
			break;
		}
		const auto &d = i->detail->arm64;
		const bool load = i->id == ARM64_INS_LDR || i->id == ARM64_INS_LDUR || i->id == ARM64_INS_LDTR;
		const bool store = i->id == ARM64_INS_STR || i->id == ARM64_INS_STUR;
		const bool memory = (load || store) && d.op_count == 2 && !d.writeback &&
		                    d.operands[0].type == ARM64_OP_REG && d.operands[1].type == ARM64_OP_MEM &&
		                    d.operands[1].mem.index == ARM64_REG_INVALID && Width(d.operands[0].reg);
		if (memory) {
			const auto &m = d.operands[1].mem;
			const int base = Number(m.base);
			const unsigned width = Width(d.operands[0].reg);
			if (Width(m.base) == 8 && base >= 0 && base < 15 && (registers & (1U << base)) &&
			    width == layout.slotBytes && m.disp >= 0 && m.disp < 1048576) {
				const int64_t offset = m.disp + layout.tag;
				std::string kind;
				std::optional<int64_t> index;
				if (layout.kind == "context") {
					if (offset == layout.contextParent)
						kind = "context_parent";
					else if (offset >= layout.contextData && (offset - layout.contextData) % width == 0) {
						kind = "context_slot";
						index = (offset - layout.contextData) / width;
					}
				} else if (offset >= layout.header && offset + width <= layout.end && offset % width == 0 &&
				           !std::binary_search(layout.excluded.begin(), layout.excluded.end(), offset) &&
				           !std::binary_search(layout.unboxed.begin(), layout.unboxed.end(), offset))
					kind = "instance_slot";
				if (!kind.empty())
					context.accesses.push_back({i->address, static_cast<unsigned>(base),
					                            static_cast<unsigned>(Number(d.operands[0].reg)), width,
					                            offset, load ? "read" : "write", kind, index});
			}
			if (load)
				registers &= ~(1U << Number(d.operands[0].reg));
		} else {
			const auto ir = LowerArm64(*i);
			if (!ir)
				registers = 0;
			else {
				const auto effects = NativeIr::GetEffects(*ir);
				const auto before = registers;
				if (effects.unlistedRegistersMayChange)
					registers = 0;
				else if (effects.destination && effects.destination->id < 32)
					registers &= ~(1U << effects.destination->id);
				if (const auto copy = std::get_if<NativeIr::Assign>(&ir->operation))
					if (const auto source = std::get_if<NativeIr::RegisterView>(&copy->value);
					    source && source->bits == 64 && source->id < 15 && copy->target.valueBits == 64 &&
					    copy->target.id < 15 && (before & (1U << source->id)))
						registers |= 1U << copy->target.id;
			}
		}
		if (!registers) {
			context.status = "registers_lost";
			break;
		}
	}
}

AsyncFieldsResult DescribeAsyncFields(const Profile &p, const FutureBindingsResult &bindings,
                                      const SavedReferencesResult &saved,
                                      const std::map<uint64_t, std::vector<uint8_t>> &bytes,
                                      const std::set<uint64_t> &entries)
{
	AsyncFieldsResult result;
	if (!p.describeInstanceLayout)
		return result;
	result.supported = true;
	for (const auto &binding : bindings.bindings)
		if (binding.status == "conditional_delivery" && binding.value == "heap_class" && binding.classId &&
		    binding.input.boundary.resumeSite)
			result.contexts.push_back({binding.input.boundary.payload, binding.input.boundary.site,
			                           *binding.input.boundary.resumeSite, 0, *binding.classId,
			                           "await_delivery"});
	for (const auto &context : saved.contexts)
		if (context.status == "checked" && context.classId != p.nullClassId)
			for (const auto &ref : context.observations)
				result.contexts.push_back({context.payload, context.sourceAwait, ref.site + 4, ref.reg,
				                           context.classId, "restored_reference"});
	struct Decoder {
		csh handle = 0;
		~Decoder()
		{
			if (handle)
				cs_close(&handle);
		}
	} decoder;
	if (!result.contexts.empty() &&
	    (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &decoder.handle) != CS_ERR_OK ||
	     cs_option(decoder.handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK))
		throw std::runtime_error("Cannot initialize async field decoder");
	uint64_t previous = UINT64_MAX;
	std::shared_ptr<cs_insn> decoded;
	size_t count = 0;
	for (auto &context : result.contexts) {
		if (!result.layouts.contains(context.classId)) {
			auto layout = p.describeInstanceLayout(context.classId);
			if (layout.classId != context.classId)
				throw std::runtime_error("Wrong async field class layout");
			Validate(layout);
			result.layouts.emplace(context.classId, std::move(layout));
		}
		context.status = "missing_caller_bytes";
		if (!bytes.contains(context.payload))
			continue;
		if (previous != context.payload) {
			const auto &code = bytes.at(context.payload);
			const auto [raw, size] =
			    DecodeArm64Instructions(decoder.handle, code.data(), code.size(), context.payload);
			if (size * 4 != code.size()) {
				cs_free(raw, size);
				throw std::runtime_error("Cannot decode async field caller");
			}
			decoded = std::shared_ptr<cs_insn>(raw, [size](cs_insn *p) { cs_free(p, size); });
			count = size;
			previous = context.payload;
		}
		auto barriers = std::set<uint64_t>(entries.lower_bound(context.payload),
		                                   entries.lower_bound(context.payload + count * 4));
		const auto body = p.completionBodies.find(context.payload);
		if (body != p.completionBodies.end())
			barriers.insert(body->second.handlers.begin(), body->second.handlers.end());
		AnalyzeFieldAccesses(decoded.get(), count, result.layouts.at(context.classId), barriers, context,
		                     result.remaining);
		result.steps += context.steps;
	}
	return result;
}

std::string AsyncFieldAccessNote(const AsyncFieldContext &c, const AsyncFieldAccess &a,
                                 const InstanceLayout &layout,
                                 const std::function<std::string(uint32_t)> &className)
{
	std::string owner = std::format("class {:#x}", c.classId);
	if (className)
		owner += " (" + Quote(className(c.classId)) + ')';
	std::string storage = a.kind == "context_parent" ? "context parent"
	                      : a.kind == "context_slot"
	                          ? std::format("context slot {} (bounds unknown)", *a.index)
	                          : "instance slot";
	std::string declaration = "name/type metadata unavailable";
	for (const auto &field : layout.fields)
		if (field.offset == a.offset) {
			storage = "field " + Quote(field.name);
			declaration = "declared type " + Quote(field.declaredType) +
			              std::format("; declaring class {:#x}", field.owner);
		}
	return std::format("async field-access: {} {} at byte {:#x} of X{} {}; {} [conditional: {} seed {:#x}; "
	                   "delivery at await {:#x}; successful SDK resumes; value/error-preserving callbacks; "
	                   "layout only; field value unknown]",
	                   a.access, storage, a.offset, a.base, owner, declaration, c.basis, c.seed,
	                   c.sourceAwait);
}

void WriteInstanceLayout(std::ostream &out, const InstanceLayout &l)
{
	out << "{\"class_id\":" << l.classId << ",\"kind\":" << Quote(l.kind) << ",\"header\":" << l.header
	    << ",\"end\":" << l.end << ",\"tag\":" << l.tag << ",\"slot_bytes\":" << l.slotBytes
	    << ",\"context_parent\":" << l.contextParent << ",\"context_data\":" << l.contextData;
	for (const auto &[key, offsets] : {std::pair{"excluded", &l.excluded}, {"unboxed", &l.unboxed}}) {
		out << ",\"" << key << "\":[";
		for (size_t n = 0; n < offsets->size(); ++n) {
			if (n)
				out << ',';
			out << (*offsets)[n];
		}
		out << ']';
	}
	out << ",\"fields\":[";
	for (size_t n = 0; n < l.fields.size(); ++n) {
		if (n)
			out << ',';
		const auto &f = l.fields[n];
		out << "{\"offset\":" << f.offset << ",\"owner\":" << f.owner << ",\"name\":" << Quote(f.name)
		    << ",\"declared_type\":" << Quote(f.declaredType) << '}';
	}
	out << "]}";
}

void WriteAsyncFields(std::ostream &out, const AsyncFieldsResult &result)
{
	out << ",\"async_field_layouts\":[";
	bool comma = false;
	for (const auto &[cid, l] : result.layouts) {
		if (comma)
			out << ',';
		comma = true;
		WriteInstanceLayout(out, l);
	}
	out << "],\"async_field_contexts\":[";
	comma = false;
	for (const auto &c : result.contexts) {
		if (comma)
			out << ',';
		comma = true;
		out << "{\"payload\":" << c.payload << ",\"source_await\":" << c.sourceAwait << ",\"seed\":" << c.seed
		    << ",\"register\":" << c.reg << ",\"class_id\":" << c.classId << ",\"basis\":" << Quote(c.basis)
		    << ",\"status\":" << Quote(c.status) << ",\"steps\":" << c.steps
		    << ",\"scope\":\"conditional_layout_only\",\"accesses\":[";
		for (size_t n = 0; n < c.accesses.size(); ++n) {
			if (n)
				out << ',';
			const auto &a = c.accesses[n];
			out << "{\"site\":" << a.site << ",\"base\":" << a.base << ",\"register\":" << a.reg
			    << ",\"bytes\":" << a.bytes << ",\"offset\":" << a.offset << ",\"access\":" << Quote(a.access)
			    << ",\"kind\":" << Quote(a.kind)
			    << ",\"index\":" << (a.index ? std::to_string(*a.index) : "null") << '}';
		}
		out << "]}";
	}
	out << "],\"async_field_work\":{\"supported\":" << (result.supported ? "true" : "false")
	    << ",\"limit\":" << Limit << ",\"local_limit\":" << LocalLimit << ",\"steps\":" << result.steps
	    << ",\"remaining\":" << result.remaining << '}';
}
} // namespace SnapshotAnalysis
