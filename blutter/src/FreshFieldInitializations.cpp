#include "FreshFieldInitializations.h"
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
constexpr size_t Limit = 200000, RegionLimit = 64, ContextLimit = 4096;
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
	return 0;
}
bool Group(const cs_insn &i, unsigned g)
{
	return std::find(i.detail->groups, i.detail->groups + i.detail->groups_count, g) !=
	       i.detail->groups + i.detail->groups_count;
}
struct Decoder {
	csh handle = 0;
	~Decoder()
	{
		if (handle)
			cs_close(&handle);
	}
};
} // namespace
FreshFieldsResult DescribeFreshFieldWrites(const Profile &p, const AsyncFieldsResult &fields,
                                           const CapturedFieldsResult &captures,
                                           const std::map<uint64_t, std::vector<uint8_t>> &bytes,
                                           const std::set<uint64_t> &entries)
{
	FreshFieldsResult result;
	if (p.allocationResultRegister != ARM64_REG_X0)
		return result;
	Decoder decoder;
	std::map<uint64_t, std::vector<std::pair<size_t, size_t>>> seeds;
	for (size_t n = 0; n < captures.contexts.size(); ++n)
		for (size_t m = 0; m < captures.contexts[n].reloads.size(); ++m)
			seeds[fields.contexts.at(captures.contexts[n].context).payload].emplace_back(n, m);
	if (!seeds.empty() && (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &decoder.handle) != CS_ERR_OK ||
	                       cs_option(decoder.handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK))
		throw std::runtime_error("Cannot initialize fresh-field decoder");
	for (const auto &[payload, group] : seeds) {
		cs_insn *raw = nullptr;
		size_t count = 0;
		if (bytes.contains(payload)) {
			const auto &code = bytes.at(payload);
			std::tie(raw, count) = DecodeArm64Instructions(decoder.handle, code.data(), code.size(), payload);
			if (count * 4 != code.size()) {
				cs_free(raw, count);
				throw std::runtime_error("Cannot decode fresh-field caller");
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
		for (const auto &[ci, ri] : group) {
			if (result.contexts.size() == ContextLimit || !result.remaining) {
				result.complete = false;
				break;
			}
			FreshFieldContext c{ci, ri};
			const auto &r = captures.contexts[ci].reloads[ri];
			auto finish = [&](std::string why) {
				c.status = std::move(why);
				result.contexts.push_back(std::move(c));
			};
			if (!bytes.contains(payload)) {
				finish("missing_caller_bytes");
				continue;
			}
			if (r.call < payload || r.call % 4 || (r.call - payload) / 4 >= count || r.site <= r.call ||
			    r.site % 4 || r.site >= payload + count * 4 || r.reg >= 15 ||
			    !p.allocationReturns.contains(r.target))
				throw std::runtime_error("Invalid fresh-field captured allocation");
			const auto callIndex = (r.call - payload) / 4;
			const auto &call = raw[callIndex];
			const auto &cd = call.detail->arm64;
			if (call.id != ARM64_INS_BL || cd.op_count != 1 || cd.operands[0].type != ARM64_OP_IMM ||
			    static_cast<uint64_t>(cd.operands[0].imm) != r.target)
				throw std::runtime_error("Fresh-field allocator contradicts original call");
			c.classId = p.allocationReturns.at(r.target);
			unsigned width = 0;
			int64_t tag = 0, data = 0;
			const InstanceLayout *layout = nullptr;
			if (!p.arrayBodyContract.empty() && p.arrayBodyContract[0] == static_cast<int64_t>(r.target)) {
				const auto &a = p.arrayBodyContract;
				if (a.size() != 5 || a[1] < 0 || a[1] >= 15 || a[2] < 7 || a[2] > 4096 ||
				    (a[3] != 4 && a[3] != 8) || a[4] != 1 || !p.arrayLengthLayout ||
				    p.arrayLengthLayout->classId != c.classId ||
				    p.arrayLengthLayout->bytes != static_cast<unsigned>(a[3]) ||
				    p.arrayLengthLayout->smiShift != static_cast<unsigned>(a[4]))
					throw std::runtime_error("Invalid fresh array layout contract");
				c.kind = "array_element";
				width = static_cast<unsigned>(a[3]);
				tag = 1;
				data = a[2] + tag;
				const auto length = TraceWordInput(
				    raw, count, callIndex, {static_cast<uint16_t>(a[1]), {}}, p,
				    [&](uint64_t site) { return barriers.contains(site); },
				    std::min(result.remaining, RegionLimit), false);
				if (length.steps > result.remaining)
					throw std::runtime_error("Fresh array length exceeded work bound");
				c.lengthSteps = length.steps;
				result.remaining -= length.steps;
				if (!result.remaining && length.stop == "lookback_limit") {
					result.complete = false;
					finish("step_limit");
					break;
				}
				if (length.stop != "matched" || !length.source || length.source->kind != "literal" ||
				    !length.source->bits || (*length.source->bits & 1) || *length.source->bits > 2097152) {
					finish("unproved_array_length");
					continue;
				}
				c.length = *length.source->bits >> a[4];
				c.lengthSource = length.source;
			} else {
				const auto body = p.allocationBodyBounds.find(r.target);
				if (body == p.allocationBodyBounds.end() || !p.describeInstanceLayout) {
					finish("unproved_allocation_layout");
					continue;
				}
				if (body->second.first < 0 || body->second.second <= body->second.first ||
				    body->second.second > 1048576)
					throw std::runtime_error("Invalid fresh allocation body bounds");
				if (!result.layouts.contains(c.classId)) {
					auto l = p.describeInstanceLayout(c.classId);
					if (l.classId != c.classId)
						throw std::runtime_error("Wrong fresh-field class layout");
					ValidateInstanceLayout(l);
					result.layouts.emplace(c.classId, std::move(l));
				}
				layout = &result.layouts.at(c.classId);
				if (layout->kind != "instance" || body->second.first > layout->header - layout->tag ||
				    body->second.second < layout->end - layout->tag) {
					finish("unproved_allocation_layout");
					continue;
				}
				c.kind = "instance_field";
				width = layout->slotBytes;
				tag = layout->tag;
			}
			std::array<bool, 15> fresh{}, value{};
			fresh[0] = true;
			bool loaded = false;
			std::set<int64_t> written;
			c.status = "payload_end";
			for (size_t n = callIndex + 1; n < count; ++n) {
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
				if (Group(i, CS_GRP_CALL) || Group(i, CS_GRP_JUMP) || Group(i, CS_GRP_RET) ||
				    Group(i, CS_GRP_INT) || i.id == ARM64_INS_BRK) {
					c.status = "control_boundary";
					break;
				}
				if (i.address == r.site) {
					if ((i.id != ARM64_INS_LDR && i.id != ARM64_INS_LDUR && i.id != ARM64_INS_LDTR) ||
					    d.op_count != 2 || d.writeback || d.operands[0].type != ARM64_OP_REG ||
					    Width(d.operands[0].reg) != 8 ||
					    Number(d.operands[0].reg) != static_cast<int>(r.reg) ||
					    d.operands[1].type != ARM64_OP_MEM || d.operands[1].mem.base != ARM64_REG_X29 ||
					    d.operands[1].mem.index != ARM64_REG_INVALID || d.operands[1].mem.disp != r.slot)
						throw std::runtime_error("Fresh-field reload contradicts captured value");
					fresh[r.reg] = false;
					value[r.reg] = true;
					loaded = true;
					continue;
				}
				const bool copy = i.id == ARM64_INS_MOV && d.op_count == 2 && !d.writeback &&
				                  !d.update_flags && d.operands[0].type == ARM64_OP_REG &&
				                  d.operands[1].type == ARM64_OP_REG && Width(d.operands[0].reg) == 8 &&
				                  Width(d.operands[1].reg) == 8 && Number(d.operands[0].reg) >= 0 &&
				                  Number(d.operands[0].reg) < 15 && Number(d.operands[1].reg) >= 0 &&
				                  Number(d.operands[1].reg) < 15;
				if (copy) {
					const auto to = Number(d.operands[0].reg), from = Number(d.operands[1].reg);
					fresh[to] = fresh[from];
					value[to] = value[from];
					continue;
				}
				const bool store = i.id == ARM64_INS_STR || i.id == ARM64_INS_STUR;
				if (store && d.op_count == 2 && !d.writeback && d.operands[0].type == ARM64_OP_REG &&
				    d.operands[1].type == ARM64_OP_MEM && d.operands[1].mem.index == ARM64_REG_INVALID) {
					const auto source = Number(d.operands[0].reg), base = Number(d.operands[1].mem.base);
					if (source >= 0 && source < 15 && fresh[source]) {
						c.status = "fresh_result_escaped";
						break;
					}
					if (base >= 0 && base < 15 && fresh[base]) {
						const auto off = d.operands[1].mem.disp + tag;
						std::optional<uint64_t> index;
						bool valid = Width(d.operands[0].reg) == width && d.operands[1].mem.disp >= 0 &&
						             d.operands[1].mem.disp <= 1048576;
						if (layout)
							valid =
							    valid && off >= layout->header && off + width <= layout->end &&
							    off % width == 0 &&
							    !std::binary_search(layout->excluded.begin(), layout->excluded.end(), off) &&
							    !std::binary_search(layout->unboxed.begin(), layout->unboxed.end(), off);
						else {
							valid = valid && off >= data && (off - data) % width == 0 &&
							        static_cast<uint64_t>((off - data) / width) < *c.length;
							if (valid)
								index = static_cast<uint64_t>((off - data) / width);
						}
						if (!valid) {
							c.status = "unproved_destination";
							break;
						}
						if (loaded && source >= 0 && source < 15 && value[source]) {
							if (written.contains(off)) {
								c.status = "previously_written";
								break;
							}
							c.write = FreshFieldWrite{i.address,
							                          static_cast<unsigned>(base),
							                          static_cast<unsigned>(source),
							                          width,
							                          off,
							                          index};
							c.status = "matched_initialization";
							break;
						}
						written.insert(off);
					} else {
						// An untracked address is not a proved non-alias of this allocation.
						c.status = "unproved_alias_write";
						break;
					}
					continue;
				}
				bool freshRead = false;
				for (unsigned j = 0; j < d.op_count; ++j) {
					const auto &op = d.operands[j];
					if (op.type == ARM64_OP_REG && (op.access & CS_AC_READ)) {
						const auto x = Number(op.reg);
						freshRead |= x >= 0 && x < 15 && fresh[x];
					}
					if (op.type == ARM64_OP_MEM)
						for (auto r : {op.mem.base, op.mem.index}) {
							const auto x = Number(r);
							freshRead |= x >= 0 && x < 15 && fresh[x];
						}
				}
				if (freshRead) {
					c.status = "unproved_fresh_use";
					break;
				}
				if (i.id == ARM64_INS_NOP || i.id == ARM64_INS_CMP || i.id == ARM64_INS_CMN ||
				    i.id == ARM64_INS_TST)
					continue;
				const auto lower = LowerArm64(i);
				if (!lower) {
					c.status = "unknown_effects";
					break;
				}
				const auto effect = NativeIr::GetEffects(*lower);
				if (effect.unlistedRegistersMayChange || effect.memory == NativeIr::MemoryEffect::Unknown ||
				    effect.control != NativeIr::ControlEffect::Fallthrough) {
					c.status = "unknown_effects";
					break;
				}
				if (effect.destination && effect.destination->id < 15) {
					fresh[effect.destination->id] = false;
					value[effect.destination->id] = false;
				}
			}
			result.contexts.push_back(std::move(c));
		}
		if (!result.complete)
			break;
	}
	result.steps = Limit - result.remaining;
	return result;
}
std::string FreshFieldNote(const AsyncFieldsResult &fields, const CapturedFieldsResult &captures,
                           const FreshFieldContext &c)
{
	if (!c.write)
		throw std::runtime_error("Fresh-field comment lacks a write");
	const auto &parent = captures.contexts.at(c.capture);
	const auto &r = parent.reloads.at(c.reload);
	const auto &f = fields.contexts.at(parent.context);
	const auto &a = f.accesses.at(parent.access);
	const auto &w = *c.write;
	const auto destination =
	    w.index ? std::format("array element [{}]", *w.index) : std::format("instance slot {:#x}", w.offset);
	return std::format(
	    "fresh initialization: {} of class {:#x} allocated at {:#x} <- read {:#x} from class {:#x} slot "
	    "{:#x}; reload {:#x} "
	    "[conditional: {} seed {:#x}; delivery at await {:#x}; normal producer/allocation returns; "
	    "successful SDK resumes; value/error-preserving callbacks; "
	    "captured Dart value; unescaped allocation; first explicit write only; later contents/type unknown]",
	    destination, c.classId, r.call, a.site, f.classId, a.offset, r.site, f.basis, f.seed, f.sourceAwait);
}
void WriteFreshFields(std::ostream &out, const FreshFieldsResult &result)
{
	out << ",\"fresh_field_layouts\":[";
	bool comma = false;
	for (const auto &[cid, l] : result.layouts) {
		if (comma)
			out << ',';
		comma = true;
		WriteInstanceLayout(out, l);
	}
	out << "],\"fresh_field_contexts\":[";
	for (size_t n = 0; n < result.contexts.size(); ++n) {
		if (n)
			out << ',';
		const auto &c = result.contexts[n];
		out << "{\"capture\":" << c.capture << ",\"reload\":" << c.reload << ",\"class_id\":" << c.classId
		    << ",\"kind\":\"" << c.kind << "\",\"status\":\"" << c.status << "\",\"steps\":" << c.steps
		    << ",\"length_steps\":" << c.lengthSteps
		    << ",\"length\":" << (c.length ? std::to_string(*c.length) : "null") << ",\"length_source\":";
		if (!c.lengthSource)
			out << "null";
		else {
			const auto &v = *c.lengthSource;
			out << "{\"site\":" << v.site << ",\"bits\":" << *v.bits << ",\"proof\":[";
			for (size_t j = 0; j < v.proof.size(); ++j) {
				if (j)
					out << ',';
				out << v.proof[j];
			}
			out << "]}";
		}
		out << ",\"scope\":\"conditional_first_write_only\",\"write\":";
		if (!c.write)
			out << "null";
		else {
			const auto &v = *c.write;
			out << "{\"site\":" << v.site << ",\"base\":" << v.base << ",\"register\":" << v.reg
			    << ",\"bytes\":" << v.bytes << ",\"offset\":" << v.offset
			    << ",\"index\":" << (v.index ? std::to_string(*v.index) : "null") << '}';
		}
		out << '}';
	}
	out << "],\"fresh_field_work\":{\"limit\":" << Limit << ",\"region_limit\":" << RegionLimit
	    << ",\"context_limit\":" << ContextLimit << ",\"steps\":" << result.steps
	    << ",\"remaining\":" << result.remaining << ",\"complete\":" << (result.complete ? "true" : "false")
	    << '}';
}
} // namespace SnapshotAnalysis
