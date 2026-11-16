#include "CapturedFieldValues.h"
#include "Arm64Decode.h"
#include "Arm64Ir.h"
#include "SnapshotCodeAnalysis.h"
#include <algorithm>
#include <array>
#include <format>
#include <memory>
#include <ostream>
#include <stdexcept>

namespace SnapshotAnalysis
{
namespace
{
constexpr size_t Limit = 200000, RegionLimit = 64, ContextLimit = 4096, MapLimit = 4096;
bool Group(const cs_insn &i, unsigned group)
{
	return std::find(i.detail->groups, i.detail->groups + i.detail->groups_count, group) !=
	       i.detail->groups + i.detail->groups_count;
}
int Number(arm64_reg r)
{
	if (r >= ARM64_REG_X0 && r <= ARM64_REG_X28)
		return r - ARM64_REG_X0;
	if (r >= ARM64_REG_W0 && r <= ARM64_REG_W30)
		return r - ARM64_REG_W0;
	return r == ARM64_REG_X29 ? 29 : r == ARM64_REG_X30 ? 30 : -1;
}
unsigned Width(arm64_reg r)
{
	if ((r >= ARM64_REG_X0 && r <= ARM64_REG_X28) || r == ARM64_REG_X29 || r == ARM64_REG_X30 ||
	    r == ARM64_REG_XZR)
		return 8;
	if ((r >= ARM64_REG_W0 && r <= ARM64_REG_W30) || r == ARM64_REG_WZR)
		return 4;
	if (r >= ARM64_REG_Q0 && r <= ARM64_REG_Q31)
		return 16;
	if (r >= ARM64_REG_D0 && r <= ARM64_REG_D31)
		return 8;
	if (r >= ARM64_REG_S0 && r <= ARM64_REG_S31)
		return 4;
	return 0;
}
bool Slot(int64_t off, const Profile &p, const AsyncFramePoint &point)
{
	return off >= -4096 && off % 8 == 0 && off <= p.savedFrameAbi.firstLocalOffset &&
	       off + 8 <= p.futureBindingAbi.suspendStateOffset && off >= point.spUpper;
}
bool Reconstruct(const cs_insn &i, unsigned reg, const Profile &p)
{
	const auto &d = i.detail->arm64;
	return i.id == ARM64_INS_ADD && d.op_count == 3 && !d.writeback && !d.update_flags &&
	       d.operands[0].type == ARM64_OP_REG && Width(d.operands[0].reg) == 8 &&
	       Number(d.operands[0].reg) == static_cast<int>(reg) && d.operands[1].type == ARM64_OP_REG &&
	       d.operands[1].reg == d.operands[0].reg && d.operands[2].type == ARM64_OP_REG &&
	       d.operands[2].reg == p.heapBitsRegister && p.heapBitsRegister != ARM64_REG_INVALID &&
	       d.operands[2].ext == ARM64_EXT_INVALID && d.operands[2].shift.type == ARM64_SFT_LSL &&
	       d.operands[2].shift.value == 32;
}
bool Read(const cs_insn &i, const AsyncFieldAccess &a, const InstanceLayout &layout)
{
	const auto &d = i.detail->arm64;
	return (i.id == ARM64_INS_LDR || i.id == ARM64_INS_LDUR) && d.op_count == 2 && !d.writeback &&
	       d.operands[0].type == ARM64_OP_REG && Number(d.operands[0].reg) == static_cast<int>(a.reg) &&
	       Width(d.operands[0].reg) == a.bytes && d.operands[1].type == ARM64_OP_MEM &&
	       Width(d.operands[1].mem.base) == 8 && Number(d.operands[1].mem.base) == static_cast<int>(a.base) &&
	       d.operands[1].mem.index == ARM64_REG_INVALID && d.operands[1].mem.disp >= 0 &&
	       d.operands[1].mem.disp <= 1048576 && d.operands[1].mem.disp + layout.tag == a.offset &&
	       a.bytes == layout.slotBytes && (a.bytes == 4 || a.bytes == 8);
}
struct Decoder {
	csh handle = 0;
	~Decoder()
	{
		if (handle)
			cs_close(&handle);
	}
};
void CheckMap(const SavedStackMap &m, uint64_t payload, uint64_t site, const Profile &p)
{
	if (m.payload != payload || m.site != site || m.spillSlots > 8192 || m.objects.size() > m.spillSlots ||
	    !std::is_sorted(m.objects.begin(), m.objects.end()) ||
	    std::adjacent_find(m.objects.begin(), m.objects.end()) != m.objects.end() ||
	    (m.registerSlots && *m.registerSlots > 16384 - m.spillSlots) ||
	    (!m.available && (m.spillSlots || !m.objects.empty() || m.registerSlots)))
		throw std::runtime_error("Invalid captured-field stack map");
	for (auto off : m.objects)
		if (off < -69632 || off > p.savedFrameAbi.firstLocalOffset || off % 8 ||
		    (p.savedFrameAbi.firstLocalOffset - off) / 8 >= m.spillSlots)
			throw std::runtime_error("Invalid captured-field object slot");
}
} // namespace

CapturedFieldsResult PreserveCapturedFields(const Profile &p, const AsyncFieldsResult &fields,
                                            const SavedReferencesResult &saved,
                                            const std::map<uint64_t, std::vector<uint8_t>> &bytes,
                                            const std::set<uint64_t> &entries)
{
	CapturedFieldsResult result;
	if (!fields.supported || !p.savedFrameAbi.supported || !p.futureBindingAbi.supported)
		return result;
	if (p.savedFrameAbi.firstLocalOffset > -8 || p.savedFrameAbi.firstLocalOffset < -4096 ||
	    p.savedFrameAbi.firstLocalOffset % 8)
		throw std::runtime_error("Invalid captured-field frame ABI");
	std::map<uint64_t, const SavedReferenceFrame *> frames;
	for (const auto &f : saved.frames)
		frames.emplace(f.payload, &f);
	std::map<uint64_t, std::vector<std::pair<size_t, size_t>>> seeds;
	for (size_t n = 0; n < fields.contexts.size(); ++n)
		for (size_t m = 0; m < fields.contexts[n].accesses.size(); ++m)
			if (fields.contexts[n].accesses[m].access == "read")
				seeds[fields.contexts[n].payload].emplace_back(n, m);
	Decoder decoder;
	if (!seeds.empty() && (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &decoder.handle) != CS_ERR_OK ||
	                       cs_option(decoder.handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK))
		throw std::runtime_error("Cannot initialize captured-field decoder");
	std::map<uint64_t, SavedStackMap> maps;
	for (const auto &[payload, group] : seeds) {
		const auto frame = frames.find(payload);
		std::map<uint64_t, AsyncFramePoint> points;
		if (frame != frames.end())
			for (const auto &point : frame->second->points)
				points.emplace(point.site, point);
		cs_insn *raw = nullptr;
		size_t count = 0;
		if (frame != frames.end() && frame->second->status == "matched_async_frame" &&
		    bytes.contains(payload)) {
			const auto &code = bytes.at(payload);
			std::tie(raw, count) = DecodeArm64Instructions(decoder.handle, code.data(), code.size(), payload);
			if (count * 4 != code.size()) {
				cs_free(raw, count);
				throw std::runtime_error("Cannot decode captured-field caller payload");
			}
		}
		const std::shared_ptr<cs_insn> owner(raw, [count](cs_insn *v) { cs_free(v, count); });
		std::set<uint64_t> barriers(entries.lower_bound(payload), entries.lower_bound(payload + count * 4));
		for (size_t n = 0; n < count; ++n)
			if (Group(raw[n], CS_GRP_JUMP)) {
				const auto &d = raw[n].detail->arm64;
				if (d.op_count && d.operands[d.op_count - 1].type == ARM64_OP_IMM)
					barriers.insert(static_cast<uint64_t>(d.operands[d.op_count - 1].imm));
			}
		for (const auto &[ci, ai] : group) {
			if (result.contexts.size() == ContextLimit) {
				result.complete = false;
				break;
			}
			CapturedFieldContext c{ci, ai};
			const auto &field = fields.contexts[ci];
			const auto &a = field.accesses[ai];
			if (frame == frames.end() || frame->second->status != "matched_async_frame")
				c.status = "unproved_owned_frame";
			else if (!bytes.contains(payload))
				c.status = "missing_caller_bytes";
			else if (a.site < payload || a.site % 4 || (a.site - payload) / 4 >= count || a.reg >= 15 ||
			         !fields.layouts.contains(field.classId) ||
			         !Read(raw[(a.site - payload) / 4], a, fields.layouts.at(field.classId)))
				throw std::runtime_error("Captured-field seed contradicts decoded field read");
			else {
				size_t n = (a.site - payload) / 4 + 1;
				std::array<bool, 15> regs{};
				std::map<int64_t, uint64_t> slots;
				uint64_t call = 0, target = 0;
				c.status = "payload_end";
				if (a.bytes == 4) {
					if (n == count || barriers.contains(raw[n].address) || !Reconstruct(raw[n], a.reg, p))
						c.status = "unproved_reconstruction";
					else {
						regs[a.reg] = true;
						++n;
					}
				} else
					regs[a.reg] = true;
				if (c.status != "unproved_reconstruction")
					for (; n < count; ++n) {
						if (!result.remaining) {
							c.status = "step_limit";
							result.complete = false;
							break;
						}
						if (c.steps == RegionLimit) {
							c.status = "region_limit";
							break;
						}
						--result.remaining;
						++c.steps;
						const auto &i = raw[n];
						const auto &d = i.detail->arm64;
						if (barriers.contains(i.address)) {
							c.status = "alternate_entry";
							break;
						}
						const auto point = points.find(i.address);
						if (point == points.end()) {
							c.status = "unproved_active_frame";
							break;
						}
						std::erase_if(slots, [&](const auto &v) { return !Slot(v.first, p, point->second); });
						if ((!Group(i, CS_GRP_CALL) && Group(i, CS_GRP_JUMP)) || Group(i, CS_GRP_RET) ||
						    Group(i, CS_GRP_INT) || i.id == ARM64_INS_BRK) {
							c.status = "control_boundary";
							break;
						}
						if (Group(i, CS_GRP_CALL)) {
							if (call) {
								c.status = "second_call";
								break;
							}
							if (i.id != ARM64_INS_BL || d.op_count != 1 ||
							    d.operands[0].type != ARM64_OP_IMM ||
							    !p.allocationReturns.contains(static_cast<uint64_t>(d.operands[0].imm))) {
								c.status = "unmatched_call";
								break;
							}
							if (slots.empty()) {
								c.status = "no_saved_value";
								break;
							}
							if (!maps.contains(i.address)) {
								if (maps.size() == MapLimit) {
									c.status = "map_limit";
									result.complete = false;
									break;
								}
								auto m = p.describeSavedStackMap ? p.describeSavedStackMap(payload, i.address)
								                                 : SavedStackMap{payload, i.address};
								CheckMap(m, payload, i.address, p);
								maps.emplace(i.address, std::move(m));
							}
							const auto &m = maps.at(i.address);
							// The VM scans the gap below spills as tagged. Without saved-register
							// entries, Slot() supplies the required active-frame lower bound.
							std::erase_if(slots, [&](const auto &v) {
								return !m.available ||
								       (!std::binary_search(m.objects.begin(), m.objects.end(), v.first) &&
								        !(m.registerSlots && *m.registerSlots == 0 &&
								          v.first <= p.savedFrameAbi.firstLocalOffset -
								                         static_cast<int64_t>(m.spillSlots) * 8));
							});
							regs.fill(false);
							if (slots.empty()) {
								c.status = m.available ? "untagged_saved_value" : "missing_stack_map";
								break;
							}
							call = i.address;
							target = static_cast<uint64_t>(d.operands[0].imm);
							continue;
						}
						const bool pair = i.id == ARM64_INS_STP;
						const bool store = pair || i.id == ARM64_INS_STR || i.id == ARM64_INS_STUR ||
						                   i.id == ARM64_INS_STRB || i.id == ARM64_INS_STURB ||
						                   i.id == ARM64_INS_STRH || i.id == ARM64_INS_STURH;
						if (store) {
							if (d.op_count != (pair ? 3 : 2) ||
							    d.operands[d.op_count - 1].type != ARM64_OP_MEM)
								throw std::runtime_error("Invalid certified frame store");
							const auto &mem = d.operands[d.op_count - 1].mem;
							const auto base = Number(mem.base);
							const auto width = i.id == ARM64_INS_STRB || i.id == ARM64_INS_STURB ? 1U
							                   : i.id == ARM64_INS_STRH || i.id == ARM64_INS_STURH
							                       ? 2U
							                       : Width(d.operands[0].reg);
							if (base == 29 || base == 15) {
								if (!width || mem.index != ARM64_REG_INVALID || (d.writeback && base != 15) ||
								    (base == 15 && !point->second.spExact))
									slots.clear();
								else {
									const auto off = mem.disp + (base == 15 ? point->second.spUpper : 0);
									std::erase_if(slots, [&](const auto &v) {
										return off < v.first + 8 && off + width * (pair ? 2 : 1) > v.first;
									});
									// Do not build a second spill/reload chain after the allocation.
									if (!call)
										for (unsigned part = 0; part < (pair ? 2U : 1U); ++part) {
											const auto at = off + part * width;
											const auto r = Number(d.operands[part].reg);
											if (width == 8 && r >= 0 && r < 15 && regs[r] &&
											    Slot(at, p, point->second))
												slots[at] = i.address;
										}
								}
							}
							if (d.writeback && base >= 0 && base < 15)
								regs[base] = false;
							continue;
						}
						if ((i.id == ARM64_INS_LDR || i.id == ARM64_INS_LDUR || i.id == ARM64_INS_LDTR) &&
						    d.op_count == 2 && !d.writeback && d.operands[0].type == ARM64_OP_REG &&
						    Width(d.operands[0].reg) == 8 && Number(d.operands[0].reg) >= 0 &&
						    Number(d.operands[0].reg) < 15 && d.operands[1].type == ARM64_OP_MEM &&
						    d.operands[1].mem.base == ARM64_REG_X29 &&
						    d.operands[1].mem.index == ARM64_REG_INVALID) {
							const auto r = Number(d.operands[0].reg);
							const auto slot = slots.find(d.operands[1].mem.disp);
							regs[r] = slot != slots.end();
							if (call && slot != slots.end())
								c.reloads.push_back({i.address, slot->second, call, target, slot->first,
								                     static_cast<unsigned>(r)});
							continue;
						}
						if (i.id == ARM64_INS_CMP || i.id == ARM64_INS_CMN || i.id == ARM64_INS_TST ||
						    i.id == ARM64_INS_NOP)
							continue;
						const auto lower = LowerArm64(i);
						const auto before = regs;
						if (!lower)
							regs.fill(false);
						else {
							const auto effects = NativeIr::GetEffects(*lower);
							if (effects.unlistedRegistersMayChange)
								regs.fill(false);
							if (effects.destination && effects.destination->id < 15) {
								regs[effects.destination->id] = false;
								if (const auto *assign = std::get_if<NativeIr::Assign>(&lower->operation);
								    assign && assign->target.storageBits == 64 &&
								    assign->target.valueBits == 64)
									if (const auto *src = std::get_if<NativeIr::RegisterView>(&assign->value);
									    src && src->bits == 64 && src->id < 15)
										regs[effects.destination->id] = before[src->id];
							}
						}
					}
			}
			result.contexts.push_back(std::move(c));
		}
		if (!result.complete)
			break;
	}
	for (auto &[site, m] : maps)
		result.maps.push_back(std::move(m));
	result.steps = Limit - result.remaining;
	return result;
}
std::string CapturedFieldNote(const AsyncFieldsResult &fields, const CapturedFieldContext &context,
                              const CapturedFieldReload &r)
{
	const auto &c = fields.contexts.at(context.context);
	const auto &a = c.accesses.at(context.access);
	return std::format(
	    "captured field value: X{} <- read {:#x} from class {:#x} slot {:#x}; store {:#x} to FP{:+}; "
	    "reload after allocator {:#x} at {:#x} [conditional: {} seed {:#x}; delivery at await {:#x}; "
	    "normal producer/allocation returns; successful SDK resumes; value/error-preserving callbacks; "
	    "owned GC-tagged local; captured Dart value only; current field contents/type unknown]",
	    r.reg, a.site, c.classId, a.offset, r.store, r.slot, r.target, r.call, c.basis, c.seed,
	    c.sourceAwait);
}
void WriteCapturedFields(std::ostream &out, const CapturedFieldsResult &result)
{
	out << ",\"captured_field_contexts\":[";
	for (size_t n = 0; n < result.contexts.size(); ++n) {
		if (n)
			out << ',';
		const auto &c = result.contexts[n];
		out << "{\"context\":" << c.context << ",\"access\":" << c.access << ",\"status\":\"" << c.status
		    << "\",\"steps\":" << c.steps << ",\"reloads\":[";
		for (size_t j = 0; j < c.reloads.size(); ++j) {
			if (j)
				out << ',';
			const auto &r = c.reloads[j];
			out << "{\"site\":" << r.site << ",\"register\":" << r.reg << ",\"store\":" << r.store
			    << ",\"slot\":" << r.slot << ",\"call\":" << r.call << ",\"target\":" << r.target << '}';
		}
		out << "],\"scope\":\"conditional_captured_value_only\"}";
	}
	out << "],\"captured_field_stack_maps\":[";
	for (size_t n = 0; n < result.maps.size(); ++n) {
		if (n)
			out << ',';
		const auto &m = result.maps[n];
		out << "{\"payload\":" << m.payload << ",\"site\":" << m.site
		    << ",\"available\":" << (m.available ? "true" : "false") << ",\"spill_slots\":" << m.spillSlots
		    << ",\"register_slots\":" << (m.registerSlots ? std::to_string(*m.registerSlots) : "null")
		    << ",\"objects\":[";
		for (size_t j = 0; j < m.objects.size(); ++j) {
			if (j)
				out << ',';
			out << m.objects[j];
		}
		out << "]}";
	}
	out << "],\"captured_field_work\":{\"limit\":" << Limit << ",\"region_limit\":" << RegionLimit
	    << ",\"context_limit\":" << ContextLimit << ",\"map_limit\":" << MapLimit
	    << ",\"steps\":" << result.steps << ",\"remaining\":" << result.remaining
	    << ",\"complete\":" << (result.complete ? "true" : "false") << '}';
}
} // namespace SnapshotAnalysis
