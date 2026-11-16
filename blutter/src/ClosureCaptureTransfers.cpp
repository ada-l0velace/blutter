#include "ClosureCaptureTransfers.h"
#include "Arm64Decode.h"
#include "CalleeEntryReads.h"
#include "SnapshotCodeAnalysis.h"
#include "WordOrigins.h"
#include <algorithm>
#include <format>
#include <memory>
#include <ostream>
#include <stdexcept>

namespace SnapshotAnalysis
{
namespace
{
int Wide(arm64_reg reg)
{
    return reg >= ARM64_REG_X0 && reg <= ARM64_REG_X14 ? reg - ARM64_REG_X0 : -1;
}
int Narrow(arm64_reg reg)
{
    return reg >= ARM64_REG_W0 && reg <= ARM64_REG_W14 ? reg - ARM64_REG_W0 : -1;
}
bool Local(const cs_insn &i, bool store, unsigned reg, int64_t slot)
{
    const auto &a = i.detail->arm64;
    return (store ? i.id == ARM64_INS_STUR : i.id == ARM64_INS_LDUR || i.id == ARM64_INS_LDR) &&
           a.op_count == 2 && !a.writeback && a.operands[0].type == ARM64_OP_REG &&
           Wide(a.operands[0].reg) == static_cast<int>(reg) && a.operands[1].type == ARM64_OP_MEM &&
           a.operands[1].mem.base == ARM64_REG_X29 &&
           a.operands[1].mem.index == ARM64_REG_INVALID && a.operands[1].mem.disp == slot;
}

std::optional<ClosureCaptureTransfer> Analyze(const Profile &p, const ClosureEntryModel &model,
                                              int64_t contextOffset,
                                              const std::vector<uint8_t> &code, uint64_t payload,
                                              const std::set<uint64_t> &entries, size_t &remaining)
{
    csh handle = 0;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK)
	throw std::runtime_error("Cannot initialize closure capture decoder");
    struct Close
    {
	csh &h;
	~Close() { cs_close(&h); }
    } close{handle};
    if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
	throw std::runtime_error("Cannot enable closure capture details");
    const auto [i, count] = DecodeArm64Instructions(handle, code.data(), code.size(), model.entry);
    auto release = [count](cs_insn *p) { cs_free(p, count); };
    const std::unique_ptr<cs_insn, decltype(release)> owner(i, release);
    if (!i || count * 4 != code.size())
	throw std::runtime_error("Cannot decode bounded closure capture prefix");
    if (count < 12)
	return {};
    for (size_t n = 1; n < 12; ++n)
	if (entries.contains(i[n].address))
	    return {};
    const auto body =
        p.describeCompletionBody ? p.describeCompletionBody(payload) : CompletionBody{};
    if (!body.available && !p.discardedWithoutHandlers.contains(payload))
	return {};
    for (auto handler : body.handlers)
	if (handler > model.entry && handler <= i[11].address)
	    return {};

    using Arm64DecodeDetail::ReadWord;
    if (ReadWord(i[0].bytes) != 0xa9bf79fdU || ReadWord(i[1].bytes) != 0xaa0f03fdU ||
        (ReadWord(i[2].bytes) & 0xffc003ffU) != 0xd10001efU)
	return {};
    const auto stack = static_cast<int64_t>((ReadWord(i[2].bytes) >> 10) & 0xfff);
    if (stack < 8 || stack % 8)
	return {};
    const CallInputAbi closureAbi{true, 0, 8, "matched_closure_entry"};
    auto entry = ProveCalleeEntryReads(model.entry, code, p, remaining, &closureAbi);
    const auto closure = std::find_if(entry.reads.begin(), entry.reads.end(),
                                      [&](const auto &r) {
	                                  return r.site == i[3].address &&
	                                         r.offset == model.entrySpOffset && !r.part;
                                      });
    if (closure == entry.reads.end() ||
        (i[3].id != ARM64_INS_LDR && i[3].id != ARM64_INS_LDUR && i[3].id != ARM64_INS_LDTR))
	return {};
    const auto &capture = i[4].detail->arm64;
    if (capture.op_count != 2 || capture.operands[0].type != ARM64_OP_REG ||
        Narrow(capture.operands[0].reg) < 0)
	return {};
    const auto contextReg = static_cast<uint16_t>(Narrow(capture.operands[0].reg));
    const auto context = TraceWordInput(i + 4, 3, 2, {contextReg, {}}, p);
    if (context.stop != "load_endpoint" || !context.source || !context.source->load ||
        context.source->kind != "load_compressed" || context.source->site != i[4].address ||
        context.source->load->base.id != closure->reg ||
        context.source->load->displacement != contextOffset)
	return {};
    const auto &save = i[8].detail->arm64;
    if (save.op_count != 2 || save.operands[0].type != ARM64_OP_REG ||
        Wide(save.operands[0].reg) < 0 || save.operands[1].type != ARM64_OP_MEM)
	return {};
    const auto valueReg = static_cast<uint16_t>(Wide(save.operands[0].reg));
    const auto slot = save.operands[1].mem.disp;
    if (slot > p.closureCaptureLayout.firstLocalOffset || slot < -stack || slot % 8 ||
        !Local(i[8], true, valueReg, slot))
	return {};
    const auto value = TraceWordInput(i + 6, 3, 2, {valueReg, {}}, p);
    if (value.stop != "load_endpoint" || !value.source || !value.source->load ||
        value.source->kind != "load_compressed" || value.source->site != i[6].address ||
        value.source->load->base.id != contextReg || value.source->load->displacement < 0 ||
        value.source->load->displacement > 4096)
	return {};
    const auto &call = i[9].detail->arm64;
    if (i[9].id != ARM64_INS_BL || call.op_count != 1 || call.operands[0].type != ARM64_OP_IMM ||
        p.allocationResultRegister != ARM64_REG_X0)
	return {};
    const uint64_t target = call.operands[0].imm;
    if (!p.allocationReturns.contains(target) || !p.describeInstanceLayout ||
        !p.describeSavedStackMap)
	return {};
    const auto &reload = i[10].detail->arm64;
    if (reload.op_count != 2 || reload.operands[0].type != ARM64_OP_REG ||
        Wide(reload.operands[0].reg) <= 0)
	return {};
    const auto reg = static_cast<unsigned>(Wide(reload.operands[0].reg));
    if (!Local(i[10], false, reg, slot))
	return {};
    const auto map = p.describeSavedStackMap(payload, i[9].address);
    if (map.payload != payload || map.site != i[9].address)
	throw std::runtime_error("Closure capture has a foreign GC map");
    const bool gap =
        map.registerSlots && *map.registerSlots == 0 &&
        slot <= p.closureCaptureLayout.firstLocalOffset - static_cast<int64_t>(map.spillSlots) * 8;
    if (!map.available ||
        (!std::binary_search(map.objects.begin(), map.objects.end(), slot) && !gap))
	return {};
    const auto cid = p.allocationReturns.at(target);
    auto layout = p.describeInstanceLayout(cid);
    if (layout.classId != cid)
	throw std::runtime_error("Closure capture has a foreign destination layout");
    ValidateInstanceLayout(layout);
    if (layout.kind != "instance")
	return {};
    AsyncFieldContext destination{payload, 0, i[11].address, 0, cid, "closure_capture"};
    size_t local = 1;
    AnalyzeFieldAccesses(i + 11, 1, layout, {}, destination, local);
    if (destination.accesses.size() != 1 || destination.accesses[0].access != "write" ||
        destination.accesses[0].reg != reg)
	return {};
    return ClosureCaptureTransfer{0,
                                  0,
                                  0,
                                  model,

                                  contextOffset,
                                  value.source->load->displacement,
                                  slot,
                                  i[6].address,
                                  i[9].address,
                                  target,
                                  i[10].address,
                                  i[11].address,
                                  cid,
                                  destination.accesses[0].offset,
                                  map,
                                  std::move(layout),
                                  !body.available};
}
} // namespace

ClosureCapturesResult
LinkClosureCaptures(const Profile &p, const std::vector<CallInputOrigin> &origins,
                    const std::map<int64_t, InputObject> &objects, const std::vector<Edge> &edges,
                    const std::vector<Payload> &payloads, const std::set<uint64_t> &entries)
{
    ClosureCapturesResult result;
    if (p.closureCaptureLayout.slotBytes != 4 || p.closureCaptureLayout.tag != 1 ||
        p.closureCaptureLayout.firstLocalOffset > -8 ||
        p.closureCaptureLayout.firstLocalOffset < -4096 || p.heapBitsRegister != ARM64_REG_X28 ||
        !p.readInputCode)
	return result;
    std::map<uint64_t, const Edge *> bySite;
    for (const auto &edge : edges)
	bySite.emplace(edge.site, &edge);
    for (size_t oi = 0; oi < origins.size(); ++oi)
    {
	const auto &origin = origins[oi];
	if (origin.role != "closure_function")
	    continue;
	const auto edge = bySite.find(origin.site);
	if (edge == bySite.end() || !edge->second->target)
	    continue;
	const auto contract = p.stubInputContracts.find(*edge->second->target);
	if (contract == p.stubInputContracts.end() ||
	    !p.closureCaptureLayout.contextOffsets.contains(contract->second.kind))
	    continue;
	for (const auto &step : origin.chain)
	{
	    if (!step.poolIndex || !step.origin.source || step.origin.stop != "load_endpoint" ||
	        !objects.contains(*step.poolIndex))
		continue;
	    const auto &object = objects.at(*step.poolIndex);
	    if (object.kind != "function" || !object.entry || !object.closureEntry ||
	        object.closureEntry->entry != *object.entry)
		continue;
	    if (result.candidates == 4096 || !result.remaining)
	    {
		result.complete = false;
		return result;
	    }
	    ++result.candidates;
	    const auto &model = *object.closureEntry;
	    if (model.fixed < 1 || model.fixed > 32 || model.entrySpOffset < 0 ||
	        model.entrySpOffset > 248 ||
	        model.entrySpOffset != static_cast<int64_t>((model.fixed - 1) * 8))
		throw std::runtime_error("Invalid closure entry model");
	    const auto range =
	        std::upper_bound(payloads.begin(), payloads.end(), model.entry,
	                         [](uint64_t pc, const auto &r) { return pc < r.start; });
	    if (range == payloads.begin() || model.entry >= std::prev(range)->end)
		continue;
	    const auto &payload = *std::prev(range);
	    const auto length = std::min<uint64_t>(64, payload.end - model.entry);
	    if (length > 524288 - result.bytes)
	    {
		result.complete = false;
		return result;
	    }
	    auto code = p.readInputCode(model.entry, length);
	    if (code.size() != length)
		throw std::runtime_error("Missing original closure capture bytes");
	    result.bytes += code.size();
	    auto transfer =
	        Analyze(p, model, p.closureCaptureLayout.contextOffsets.at(contract->second.kind),
	                code, payload.start, entries, result.remaining);
	    if (!result.remaining)
		result.complete = false;
	    if (transfer)
	    {
		transfer->origin = oi;
		transfer->call = origin.site;
		transfer->poolIndex = *step.poolIndex;
		result.transfers.push_back(std::move(*transfer));
	    }
	    break;
	}
    }
    return result;
}

std::string ClosureCaptureNote(const ClosureCaptureTransfer &t)
{
    return std::format(
        "closure capture: entry SP{:+} -> capture load {:#x} -> load {:#x} at {:+#x}; "
        "saved to FP{:+}; initializes class {:#x} instance slot {:#x} "
        "[at callback invocation; tagged local across allocator {:#x}; normal allocation return]",
        t.model.entrySpOffset, t.model.entry + 16, t.valueRead, t.valueDisplacement, t.savedSlot,
        t.classId, t.destinationOffset, t.target);
}
std::string ClosureCallbackNote(const ClosureCaptureTransfer &t)
{
    return std::format(
        "closure capture callback: entry {:#x}; capture read {:#x} reaches class {:#x} "
        "instance slot {:#x} at {:#x} [matched closure entry and capture layout; "
        "contents at invocation]",
        t.model.entry, t.valueRead, t.classId, t.destinationOffset, t.store);
}
void WriteClosureCaptureLayout(std::ostream &out, const ClosureCaptureLayout &layout)
{
    out << R"({"slot_bytes":)" << layout.slotBytes << R"(,"tag":)" << layout.tag
        << R"(,"first_local_offset":)" << layout.firstLocalOffset << R"(,"context_offsets":[)";
    bool comma = false;
    for (const auto &[kind, offset] : layout.contextOffsets)
    {
	if (comma)
	    out << ',';
	comma = true;
	out << "[\"" << StubInputKindName(kind) << "\"," << offset << ']';
    }
    out << "]}";
}
void WriteClosureCaptures(std::ostream &out, const Profile &p, const ClosureCapturesResult &result)
{
    out << R"(,"closure_capture_layout":)";
    WriteClosureCaptureLayout(out, p.closureCaptureLayout);
    out << R"(,"closure_capture_transfers":[)";
    bool comma = false;
    for (const auto &t : result.transfers)
    {
	if (comma)
	    out << ',';
	comma = true;
	out << R"({"origin":)" << t.origin << R"(,"call":)" << t.call << R"(,"pool_index":)"
	    << t.poolIndex << R"(,"entry":)" << t.model.entry << R"(,"fixed":)" << t.model.fixed
	    << R"(,"entry_sp_offset":)" << t.model.entrySpOffset << R"(,"context_displacement":)"
	    << t.contextDisplacement << R"(,"value_displacement":)" << t.valueDisplacement
	    << R"(,"saved_slot":)" << t.savedSlot << R"(,"value_read":)" << t.valueRead
	    << R"(,"allocation":)" << t.allocation << R"(,"target":)" << t.target << R"(,"reload":)"
	    << t.reload << R"(,"store":)" << t.store << R"(,"class_id":)" << t.classId
	    << R"(,"destination_offset":)" << t.destinationOffset << R"(,"stack_map":{"payload":)"
	    << t.map.payload << R"(,"site":)" << t.map.site << R"(,"available":)"
	    << (t.map.available ? "true" : "false") << R"(,"spill_slots":)" << t.map.spillSlots
	    << R"(,"register_slots":)"
	    << (t.map.registerSlots ? std::to_string(*t.map.registerSlots) : "null")
	    << R"(,"objects":[)";
	for (size_t n = 0; n < t.map.objects.size(); ++n)
	{
	    if (n)
		out << ',';
	    out << t.map.objects[n];
	}
	out << R"(]},"layout":)";
	WriteInstanceLayout(out, t.layout);
	out << R"(,"handler_basis":")"
	    << (t.discardedNoHandlers ? "discarded_code" : "retained_table") << '"';
	out << '}';
    }
    out << R"(],"closure_capture_work":{"candidates":)" << result.candidates << R"(,"bytes":)"
        << result.bytes << R"(,"steps":)" << (200000 - result.remaining) << R"(,"remaining":)"
        << result.remaining << R"(,"complete":)" << (result.complete ? "true" : "false") << '}';
}
} // namespace SnapshotAnalysis
