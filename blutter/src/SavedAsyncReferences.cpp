#include "SavedAsyncReferences.h"
#include "Arm64Decode.h"
#include "Arm64Ir.h"
#include "SnapshotCodeAnalysis.h"
#include <algorithm>
#include <deque>
#include <memory>
#include <ostream>

namespace SnapshotAnalysis
{
namespace
{
constexpr size_t Limit = 2000000, NodeLimit = 2048, MapLimit = 16384;
bool Group(const cs_insn &i, unsigned group)
{
    return std::find(i.detail->groups, i.detail->groups + i.detail->groups_count, group) !=
           i.detail->groups + i.detail->groups_count;
}
std::optional<uint64_t> Target(const cs_insn &i)
{
    const auto &d = i.detail->arm64;
    return d.op_count && d.operands[d.op_count - 1].type == ARM64_OP_IMM
               ? std::optional<uint64_t>{static_cast<uint64_t>(d.operands[d.op_count - 1].imm)}
               : std::nullopt;
}
bool PlainBranch(const cs_insn &i)
{
    return i.id == ARM64_INS_B &&
           (i.detail->arm64.cc == ARM64_CC_INVALID || i.detail->arm64.cc == ARM64_CC_AL);
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
struct Value
{
    uint64_t store = 0, suspension = 0;
    int64_t slot = 0;
    bool operator==(const Value &) const = default;
    static Value Saved(uint64_t store, int64_t slot) { return {store, 0, slot}; }
    void Suspend(uint64_t site) { suspension = site; }
    void Join(const Value &other, size_t &)
    {
	if (suspension != other.suspension)
	    suspension = 0;
    }
};
struct JoinedValue
{
    uint64_t store = 0;
    int64_t slot = 0;
    std::set<uint64_t> last{0};
    bool operator==(const JoinedValue &) const = default;
    static JoinedValue Saved(uint64_t store, int64_t slot) { return {store, slot, {0}}; }
    void Suspend(uint64_t site) { last = {site}; }
    void Join(const JoinedValue &other, size_t &overflows)
    {
	if (last.empty() || other.last.empty())
	{
	    last.clear();
	    return;
	}
	last.insert(other.last.begin(), other.last.end());
	if (last.size() > 8)
	{
	    last.clear();
	    ++overflows;
	}
    }
};
template <class V> struct State
{
    std::map<unsigned, V> regs;
    std::map<int64_t, V> slots;
    bool operator==(const State &) const = default;
};
template <class M> void Meet(M &into, const M &from, size_t &overflows)
{
    for (auto it = into.begin(); it != into.end();)
    {
	const auto p = from.find(it->first);
	if (p == from.end() || p->second.store != it->second.store ||
	    p->second.slot != it->second.slot)
	    it = into.erase(it);
	else
	{
	    it->second.Join(p->second, overflows);
	    ++it;
	}
    }
}
bool Slot(int64_t slot, const Profile &p)
{
    return slot >= -4096 && slot % 8 == 0 && slot <= p.savedFrameAbi.firstLocalOffset &&
           slot + 8 <= p.futureBindingAbi.suspendStateOffset;
}
template <class V>
void Trim(State<V> &state, const std::map<uint64_t, AsyncFramePoint> &points, uint64_t site)
{
    const auto f = points.find(site);
    if (f == points.end())
    {
	state = {};
	return;
    }
    std::erase_if(state.slots, [&](const auto &v) { return v.first < f->second.spUpper; });
}
struct Memory
{
    unsigned count, width;
    int base;
    int64_t offset;
};
std::optional<Memory> Store(const cs_insn &i)
{
    const auto &d = i.detail->arm64;
    const bool pair = i.id == ARM64_INS_STP;
    if (!(pair || i.id == ARM64_INS_STR || i.id == ARM64_INS_STUR || i.id == ARM64_INS_STRB ||
          i.id == ARM64_INS_STURB || i.id == ARM64_INS_STRH || i.id == ARM64_INS_STURH))
	return {};
    if (d.op_count != (pair ? 3 : 2) || d.operands[d.op_count - 1].type != ARM64_OP_MEM)
	return {};
    const auto &m = d.operands[d.op_count - 1].mem;
    unsigned w = i.id == ARM64_INS_STRB || i.id == ARM64_INS_STURB   ? 1
                 : i.id == ARM64_INS_STRH || i.id == ARM64_INS_STURH ? 2
                                                                     : Width(d.operands[0].reg);
    if (!w)
	return {};
    return Memory{pair ? 2U : 1U, w, Number(m.base), m.disp};
}
std::optional<std::pair<unsigned, int64_t>> Load(const cs_insn &i)
{
    const auto &d = i.detail->arm64;
    if ((i.id != ARM64_INS_LDR && i.id != ARM64_INS_LDUR && i.id != ARM64_INS_LDTR) ||
        d.op_count != 2 || d.writeback || d.operands[0].type != ARM64_OP_REG ||
        Width(d.operands[0].reg) != 8 || Number(d.operands[0].reg) < 0 ||
        Number(d.operands[0].reg) >= 15 || d.operands[1].type != ARM64_OP_MEM ||
        d.operands[1].mem.base != ARM64_REG_X29 || d.operands[1].mem.index != ARM64_REG_INVALID)
	return {};
    return std::pair{static_cast<unsigned>(Number(d.operands[0].reg)), d.operands[1].mem.disp};
}
std::string Quote(const std::string &s)
{
    std::string o = "\"";
    for (unsigned char c : s)
    {
	if (c == '"' || c == '\\')
	{
	    o += '\\';
	    o += c;
	}
	else if (c < 32 || c == 127)
	    o += std::format("\\x{:02x}", c);
	else
	    o += c;
    }
    return o + '"';
}
void Publish(const Value &v, uint64_t site, int64_t slot, unsigned reg, SavedReferenceContext &c)
{
    if (v.suspension)
	c.observations.push_back({site, v.store, v.suspension, slot, reg});
}
void Publish(const JoinedValue &v, uint64_t site, int64_t slot, unsigned reg,
             JoinedReferenceContext &c)
{
    if (v.last.size() > 1)
	c.observations.push_back({site, v.store, slot, reg, v.last});
}
struct LocalSeed
{
    uint64_t store;
    int64_t slot;
};
void Publish(const Value &v, uint64_t site, int64_t slot, unsigned reg,
             DecisionReferenceContext &context)
{
    context.reloads.push_back({site, v.store, slot, reg});
}
template <class V, class Context, class MapReader>
void ReplayReferenceContext(const cs_insn *raw, size_t count, const Profile &p,
                            const AwaitFutureBinding &seed,
                            const std::map<uint64_t, AsyncFramePoint> &points,
                            const std::set<uint64_t> &externalEntries, MapReader mapAt,
                            size_t &remaining, size_t &overflows, Context &context,
                            std::optional<LocalSeed> local = {})
{
    const auto payload = context.payload;
    const auto resume = local ? local->store + 4 : *seed.input.boundary.resumeSite;
    std::map<size_t, State<V>> incoming;
    std::deque<size_t> queue;
    State<V> initial;
    if (local)
	initial.slots.emplace(local->slot, V::Saved(local->store, local->slot));
    else
	initial.regs.emplace(0, V{});
    incoming.emplace((resume - payload) / 4, std::move(initial));
    queue.push_back((resume - payload) / 4);
    auto push = [&](uint64_t pc, const State<V> &state)
    {
	if (pc < payload || pc >= payload + count * 4 || pc % 4)
	    return false;
	const auto n = (pc - payload) / 4;
	auto [found, fresh] = incoming.emplace(n, state);
	if (fresh)
	    queue.push_back(n);
	else
	{
	    auto merged = found->second;
	    Meet(merged.regs, state.regs, overflows);
	    Meet(merged.slots, state.slots, overflows);
	    if (merged != found->second)
	    {
		found->second = std::move(merged);
		queue.push_back(n);
	    }
	}
	return true;
    };
    context.status = "checked";
    while (!queue.empty())
    {
	if (!remaining)
	{
	    context.status = "step_limit";
	    break;
	}
	if (incoming.size() > NodeLimit)
	{
	    context.status = "region_limit";
	    break;
	}
	--remaining;
	++context.steps;
	const auto n = queue.front();
	queue.pop_front();
	const auto &i = raw[n];
	auto state = incoming.at(n);
	Trim(state, points, i.address);
	if (externalEntries.contains(i.address) ||
	    std::binary_search(seed.input.body.handlers.begin(), seed.input.body.handlers.end(),
	                       i.address))
	    state = {};
	const auto target = Target(i);
	const bool call = Group(i, CS_GRP_CALL);
	if (i.id == ARM64_INS_BRK ||
	    (target && (call || PlainBranch(i)) && p.completionExceptions.contains(*target) &&
	     (!p.completionExceptions.at(*target).tailOnly || PlainBranch(i))) ||
	    (call && target && p.nonReturningCalls.contains(*target)))
	    continue;
	const auto op = target && p.asyncContracts.contains(*target)
	                    ? p.asyncContracts.at(*target).operation
	                    : AsyncOperation::Unknown;
	if (PlainBranch(i) &&
	    (op == AsyncOperation::CompleteValue || op == AsyncOperation::CompleteValueOrFuture))
	    continue;
	if (call)
	{
	    const auto *m = state.slots.empty() ? nullptr : mapAt(payload, i.address);
	    std::erase_if(state.slots,
	                  [&](const auto &v)
	                  {
		              return !m || !m->available ||
		                     !std::binary_search(m->objects.begin(), m->objects.end(),
		                                         v.first);
	                  });
	    if (op == AsyncOperation::Await || op == AsyncOperation::AwaitWithTypeCheck)
		for (auto &[offset, value] : state.slots)
		    value.Suspend(i.address);
	    state.regs.clear();
	}
	else if (Group(i, CS_GRP_JUMP))
	{
	    if (!target || !push(*target, state))
	    {
		context.status = "unsupported_control";
		break;
	    }
	    if (PlainBranch(i))
		continue;
	}
	else if (const auto store = Store(i))
	{
	    if (store->base == 29 || store->base == 15)
	    {
		const auto point = points.find(i.address);
		const auto &d = i.detail->arm64;
		const auto &mem = d.operands[d.op_count - 1].mem;
		if (mem.index != ARM64_REG_INVALID || (d.writeback && store->base != 15) ||
		    (store->base == 15 && (point == points.end() || !point->second.spExact)))
		    state.slots.clear();
		else
		{
		    const auto offset =
		        store->offset + (store->base == 15 ? point->second.spUpper : 0);
		    std::erase_if(state.slots,
		                  [&](const auto &v) {
			              return offset < v.first + 8 &&
			                     offset + store->width * store->count > v.first;
		                  });
		    for (unsigned part = 0; part < store->count; ++part)
		    {
			const auto off = offset + part * store->width;
			const auto reg = Number(d.operands[part].reg);
			if (store->width == 8 && Slot(off, p) && reg >= 0 &&
			    state.regs.contains(reg))
			    state.slots[off] = V::Saved(i.address, off);
		    }
		}
	    }
	    if (i.detail->arm64.writeback && store->base >= 0 && store->base < 15)
		state.regs.erase(store->base);
	}
	else if (const auto load = Load(i))
	{
	    state.regs.erase(load->first);
	    if (state.slots.contains(load->second))
		state.regs[load->first] = state.slots.at(load->second);
	}
	else if ((i.id == ARM64_INS_CMP || i.id == ARM64_INS_CMN || i.id == ARM64_INS_TST ||
	          i.id == ARM64_INS_NOP) &&
	         !i.detail->arm64.writeback)
	{
	}
	else
	{
	    const auto lower = LowerArm64(i);
	    if (!lower)
		state.regs.clear();
	    else
	    {
		const auto effects = NativeIr::GetEffects(*lower);
		const auto before = state.regs;
		if (effects.unlistedRegistersMayChange)
		    state.regs.clear();
		if (effects.destination)
		{
		    state.regs.erase(effects.destination->id);
		    if (const auto *assign = std::get_if<NativeIr::Assign>(&lower->operation);
		        assign && assign->target.storageBits == 64 &&
		        assign->target.valueBits == 64 && assign->target.id < 15)
		    {
			if (const auto *source =
			        std::get_if<NativeIr::RegisterView>(&assign->value);
			    source && source->bits == 64 && before.contains(source->id))
			    state.regs[assign->target.id] = before.at(source->id);
		    }
		}
	    }
	}
	if (n + 1 == count || !push(i.address + 4, state))
	{
	    context.status = "unsupported_control";
	    break;
	}
    }
    if (context.status == "checked")
	for (const auto &[n, s] : incoming)
	{
	    auto state = s;
	    Trim(state, points, raw[n].address);
	    if (externalEntries.contains(raw[n].address) ||
	        std::binary_search(seed.input.body.handlers.begin(), seed.input.body.handlers.end(),
	                           raw[n].address))
		continue;
	    if (const auto load = Load(raw[n]); load && state.slots.contains(load->second))
	    {
		const auto &value = state.slots.at(load->second);
		Publish(value, raw[n].address, load->second, load->first, context);
	    }
	}
}
} // namespace
SavedReferencesResult RestoreAsyncReferences(const Profile &p, const FutureBindingsResult &bindings,
                                             const std::vector<CompletionSummary> &summaries,
                                             const std::map<uint64_t, std::vector<uint8_t>> &bytes,
                                             const std::set<uint64_t> &externalEntries)
{
    SavedReferencesResult result;
    if (!p.savedFrameAbi.supported || !p.futureBindingAbi.supported)
	return result;
    if (p.savedFrameAbi.firstLocalOffset > -8 || p.savedFrameAbi.firstLocalOffset < -4096 ||
        p.savedFrameAbi.firstLocalOffset % 8)
	throw std::runtime_error("Invalid saved-reference frame ABI");
    std::map<uint64_t, const CompletionSummary *> byPayload;
    for (const auto &s : summaries)
	byPayload.emplace(s.payload, &s);
    std::map<uint64_t, std::vector<const AwaitFutureBinding *>> seeds;
    for (const auto &b : bindings.bindings)
	if (b.status == "conditional_delivery" && b.classId && b.input.boundary.resumeSite)
	    seeds[b.input.boundary.payload].push_back(&b);
    std::map<uint64_t, SavedStackMap> maps;
    auto mapAt = [&](uint64_t payload, uint64_t site) -> const SavedStackMap *
    {
	if (auto found = maps.find(site); found != maps.end())
	    return &found->second;
	if (maps.size() >= MapLimit)
	{
	    ++result.mapDrops;
	    return nullptr;
	}
	auto m = p.describeSavedStackMap ? p.describeSavedStackMap(payload, site)
	                                 : SavedStackMap{payload, site};
	if (m.payload != payload || m.site != site || m.spillSlots > 8192 ||
	    m.objects.size() > m.spillSlots ||
	    !std::is_sorted(m.objects.begin(), m.objects.end()) ||
	    std::adjacent_find(m.objects.begin(), m.objects.end()) != m.objects.end())
	    throw std::runtime_error("Invalid saved-reference stack map");
	for (auto off : m.objects)
	    if (off < -69632 || off > p.savedFrameAbi.firstLocalOffset || off % 8 ||
	        (p.savedFrameAbi.firstLocalOffset - off) / 8 >= m.spillSlots)
		throw std::runtime_error("Invalid saved-reference object slot");
	if (!m.available && (m.spillSlots || !m.objects.empty()))
	    throw std::runtime_error("Unavailable saved-reference stack map has objects");
	return &maps.emplace(site, std::move(m)).first->second;
    };
    struct Decoder
    {
	csh handle = 0;
	~Decoder()
	{
	    if (handle)
		cs_close(&handle);
	}
    } decoder;
    if (!seeds.empty() &&
        (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &decoder.handle) != CS_ERR_OK ||
         cs_option(decoder.handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK))
	throw std::runtime_error("Cannot initialize saved-reference decoder");
    for (const auto &[payload, group] : seeds)
    {
	SavedReferenceFrame frame{payload, "missing_caller_bytes", 0, {}};
	cs_insn *raw = nullptr;
	size_t count = 0;
	if (bytes.contains(payload) && byPayload.contains(payload))
	{
	    const auto &code = bytes.at(payload);
	    std::tie(raw, count) =
	        DecodeArm64Instructions(decoder.handle, code.data(), code.size(), payload);
	    const std::set<uint64_t> entries(
	        externalEntries.lower_bound(payload),
	        externalEntries.lower_bound(byPayload.at(payload)->end));
	    const auto check =
	        CheckAsyncReferenceFrame(raw, count, p, *byPayload.at(payload),
	                                 group.front()->input.body, entries, result.remaining);
	    frame.status = check.protocol.status;
	    frame.steps = check.protocol.steps;
	    frame.points = check.points;
	}
	else if (!byPayload.contains(payload))
	    frame.status = "no_completion_summary";
	const std::shared_ptr<cs_insn> owner(raw, [count](cs_insn *v) { cs_free(v, count); });
	result.frames.push_back(frame);
	std::map<uint64_t, AsyncFramePoint> points;
	for (const auto &f : frame.points)
	    points.emplace(f.site, f);
	for (const auto *seed : group)
	{
	    SavedReferenceContext context{payload, seed->input.boundary.site, *seed->classId,
	                                  frame.status};
	    if (frame.status != "matched_async_frame")
	    {
		result.contexts.push_back(std::move(context));
		continue;
	    }
	    const auto resume = *seed->input.boundary.resumeSite;
	    if (resume < payload || resume >= byPayload.at(payload)->end || resume % 4)
	    {
		context.status = "unsupported_resume";
		result.contexts.push_back(std::move(context));
		continue;
	    }
	    size_t unusedOverflows = 0;
	    ReplayReferenceContext<Value>(raw, count, p, *seed, points, externalEntries, mapAt,
	                                  result.remaining, unusedOverflows, context);
	    result.contexts.push_back(std::move(context));
	}
    }
    for (auto &[site, map] : maps)
	result.maps.push_back(std::move(map));
    result.steps = Limit - result.remaining;
    return result;
}
std::string RestoredReferenceNote(const SavedReferenceContext &context, const RestoredReference &r,
                                  const std::function<std::string(uint32_t)> &className)
{
    const auto name = className ? className(context.classId) : std::string{};
    return std::format("async restored-reference: load result X{} heap class {:#x}{} [conditional: "
                       "delivery at await {:#x}; "
                       "store {:#x} to FP{:+}; preserved through await {:#x}; normal call "
                       "fallthrough; successful SDK "
                       "resumes; value/error-preserving callbacks; reference only]",
                       r.reg, context.classId,
                       name.empty() ? "" : std::format(" ({})", Quote(name)), context.sourceAwait,
                       r.store, r.slot, r.suspension);
}

JoinedReferencesResult
RestoreJoinedReferences(const Profile &p, const FutureBindingsResult &bindings,
                        const SavedReferencesResult &saved,
                        const std::map<uint64_t, std::vector<uint8_t>> &bytes,
                        const std::set<uint64_t> &externalEntries)
{
    JoinedReferencesResult result;
    if (!p.savedFrameAbi.supported || !p.futureBindingAbi.supported)
	return result;
    std::map<std::pair<uint64_t, uint64_t>, const AwaitFutureBinding *> seeds;
    for (const auto &b : bindings.bindings)
	if (b.status == "conditional_delivery" && b.value == "heap_class" && b.classId &&
	    *b.classId != p.nullClassId && b.input.boundary.resumeSite)
	    if (!seeds.emplace(std::pair{b.input.boundary.payload, b.input.boundary.site}, &b)
	             .second)
		throw std::runtime_error("Duplicate joined-reference delivery");
    bool requested = false;
    for (const auto &c : saved.contexts)
	requested |= c.status == "checked" && c.classId != p.nullClassId;
    if (!requested)
	return result;
    std::map<uint64_t, const SavedReferenceFrame *> frames;
    for (const auto &f : saved.frames)
	if (!frames.emplace(f.payload, &f).second)
	    throw std::runtime_error("Duplicate joined-reference frame");
    std::map<uint64_t, const SavedStackMap *> maps;
    for (const auto &m : saved.maps)
	if (!maps.emplace(m.site, &m).second)
	    throw std::runtime_error("Duplicate joined-reference map");
    auto mapAt = [&](uint64_t payload, uint64_t site) -> const SavedStackMap *
    {
	const auto m = maps.find(site);
	if (m == maps.end())
	    return nullptr;
	if (m->second->payload != payload)
	    throw std::runtime_error("Wrong joined-reference GC-map owner");
	return m->second;
    };
    struct Decoder
    {
	csh handle = 0;
	~Decoder()
	{
	    if (handle)
		cs_close(&handle);
	}
    } decoder;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &decoder.handle) != CS_ERR_OK ||
        cs_option(decoder.handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
	throw std::runtime_error("Cannot initialize joined-reference decoder");
    uint64_t previous = UINT64_MAX;
    size_t count = 0;
    std::shared_ptr<cs_insn> owner;
    std::map<uint64_t, AsyncFramePoint> points;
    for (const auto &parent : saved.contexts)
    {
	if (parent.status != "checked" || parent.classId == p.nullClassId)
	    continue;
	if (result.contexts.size() == 4096)
	{
	    result.complete = false;
	    break;
	}
	const auto key = std::pair{parent.payload, parent.sourceAwait};
	if (!seeds.contains(key) || *seeds.at(key)->classId != parent.classId ||
	    !frames.contains(parent.payload) ||
	    frames.at(parent.payload)->status != "matched_async_frame")
	    throw std::runtime_error("Joined reference lacks its checked delivery/frame parent");
	JoinedReferenceContext context{parent.payload, parent.sourceAwait, parent.classId};
	if (!bytes.contains(parent.payload))
	{
	    context.status = "missing_caller_bytes";
	    result.contexts.push_back(std::move(context));
	    continue;
	}
	if (previous != parent.payload)
	{
	    const auto &code = bytes.at(parent.payload);
	    if (code.empty() || code.size() % 4 || code.size() > 65536 ||
	        code.size() > 8388608 - result.bytes)
		throw std::runtime_error("Invalid joined-reference source byte cache");
	    const auto [raw, size] =
	        DecodeArm64Instructions(decoder.handle, code.data(), code.size(), parent.payload);
	    if (size * 4 != code.size())
	    {
		cs_free(raw, size);
		throw std::runtime_error("Cannot decode joined-reference caller");
	    }
	    owner = std::shared_ptr<cs_insn>(raw, [size](cs_insn *v) { cs_free(v, size); });
	    count = size;
	    previous = parent.payload;
	    result.bytes += code.size();
	    points.clear();
	    for (const auto &point : frames.at(parent.payload)->points)
		points.emplace(point.site, point);
	}
	const auto &seed = *seeds.at(key);
	const auto resume = *seed.input.boundary.resumeSite;
	if (resume < parent.payload || resume >= parent.payload + count * 4 || resume % 4)
	    context.status = "unsupported_resume";
	else
	    ReplayReferenceContext<JoinedValue>(owner.get(), count, p, seed, points,
	                                        externalEntries, mapAt, result.remaining,
	                                        result.historyOverflows, context);
	if (context.status == "step_limit")
	    result.complete = false;
	// Never duplicate an observation already covered by the original certificate.
	std::erase_if(context.observations,
	              [&](const auto &o)
	              {
	                  return std::any_of(parent.observations.begin(), parent.observations.end(),
	                                     [&](const auto &old) { return old.site == o.site; });
	              });
	result.contexts.push_back(std::move(context));
    }
    result.steps = 200000 - result.remaining;
    return result;
}

DecisionBranchesResult
RestoreDecisionBranches(const Profile &p, const FutureBindingsResult &bindings,
                        const SavedReferencesResult &saved, const JoinedReferencesResult &joined,
                        const FieldBranchUsesResult &fields,
                        const std::map<uint64_t, std::vector<uint8_t>> &bytes,
                        const std::set<uint64_t> &externalEntries)
{
    DecisionBranchesResult result;
    if (!p.booleanValueBit || *p.booleanValueBit >= 32 || fields.decisions.empty())
	return result;
    std::map<uint64_t, const SavedReferenceFrame *> frames;
    for (const auto &frame : saved.frames)
	frames.emplace(frame.payload, &frame);
    std::map<std::pair<uint64_t, uint64_t>, const AwaitFutureBinding *> seeds;
    for (const auto &binding : bindings.bindings)
	seeds.emplace(std::pair{binding.input.boundary.payload, binding.input.boundary.site},
	              &binding);
    std::map<uint64_t, const SavedStackMap *> maps;
    for (const auto &map : saved.maps)
	maps.emplace(map.site, &map);
    auto mapAt = [&](uint64_t payload, uint64_t site) -> const SavedStackMap *
    {
	const auto it = maps.find(site);
	if (it == maps.end())
	    return nullptr;
	if (it->second->payload != payload)
	    throw std::runtime_error("Decision reload has a foreign stack map");
	return it->second;
    };
    std::map<uint64_t, std::vector<size_t>> groups;
    for (size_t n = 0; n < fields.decisions.size(); ++n)
    {
	const auto &use = fields.uses.at(fields.decisions[n].branchUse);
	groups[joined.contexts.at(use.context).payload].push_back(n);
    }
    struct Decoder
    {
	csh handle = 0;
	~Decoder()
	{
	    if (handle)
		cs_close(&handle);
	}
    } decoder;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &decoder.handle) != CS_ERR_OK ||
        cs_option(decoder.handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
	throw std::runtime_error("Cannot initialize decision-branch decoder");
    for (const auto &[payload, indices] : groups)
    {
	if (result.contexts.size() == 4096 || !result.remaining)
	{
	    result.complete = false;
	    break;
	}
	if (!frames.contains(payload) || frames.at(payload)->status != "matched_async_frame")
	    throw std::runtime_error("Decision branch lacks its checked frame");
	const auto &code = bytes.at(payload);
	const auto [raw, count] =
	    DecodeArm64Instructions(decoder.handle, code.data(), code.size(), payload);
	auto release = [count](cs_insn *p) { cs_free(p, count); };
	const std::unique_ptr<cs_insn, decltype(release)> owner(raw, release);
	if (!raw || count * 4 != code.size())
	    throw std::runtime_error("Cannot decode decision-branch payload");
	result.bytes += code.size();
	std::map<uint64_t, AsyncFramePoint> points;
	for (const auto &point : frames.at(payload)->points)
	    points.emplace(point.site, point);
	auto barriers = std::set<uint64_t>(externalEntries.lower_bound(payload),
	                                   externalEntries.lower_bound(payload + code.size()));
	for (size_t n = 0; n < count; ++n)
	    if ((Group(raw[n], CS_GRP_JUMP) || Group(raw[n], CS_GRP_CALL)) && Target(raw[n]))
		barriers.insert(*Target(raw[n]));

	for (const auto n : indices)
	{
	    if (result.contexts.size() == 4096 || !result.remaining)
	    {
		result.complete = false;
		break;
	    }
	    const auto &decision = fields.decisions[n];
	    const auto &parent = joined.contexts.at(fields.uses.at(decision.branchUse).context);
	    const auto &seed = *seeds.at({payload, parent.sourceAwait});
	    if (decision.site < payload || decision.site + 4 >= payload + code.size() ||
	        !Slot(decision.fpOffset, p))
		throw std::runtime_error("Invalid decision spill seed");
	    DecisionReferenceContext context{n, payload};
	    size_t ignoredOverflows = 0;
	    ReplayReferenceContext<Value>(raw, count, p, seed, points, externalEntries, mapAt,
	                                  result.remaining, ignoredOverflows, context,
	                                  LocalSeed{decision.site, decision.fpOffset});
	    if (context.status == "step_limit")
		result.complete = false;
	    const size_t contextIndex = result.contexts.size();
	    for (size_t r = 0; r < context.reloads.size(); ++r)
	    {
		const auto &reload = context.reloads[r];
		const size_t at = (reload.site - payload) / 4 + 1;
		if (at >= count || barriers.contains(raw[at].address) ||
		    std::binary_search(seed.input.body.handlers.begin(),
		                       seed.input.body.handlers.end(), raw[at].address))
		    continue;
		const auto &instruction = raw[at];
		const auto &a = instruction.detail->arm64;
		if ((instruction.id != ARM64_INS_TBZ && instruction.id != ARM64_INS_TBNZ) ||
		    a.op_count != 3 || a.operands[0].type != ARM64_OP_REG ||
		    a.operands[0].reg != ARM64_REG_W0 + reload.reg ||
		    a.operands[1].type != ARM64_OP_IMM || a.operands[1].imm != *p.booleanValueBit ||
		    a.operands[2].type != ARM64_OP_IMM)
		    continue;
		const uint64_t target = a.operands[2].imm, fallthrough = instruction.address + 4;
		if (target < payload || target >= payload + code.size() ||
		    fallthrough >= payload + code.size())
		    continue;
		const bool nonzero = instruction.id == ARM64_INS_TBNZ;
		result.uses.push_back({contextIndex, r, instruction.address,
		                       nonzero ? fallthrough : target,
		                       nonzero ? target : fallthrough});
	    }
	    result.contexts.push_back(std::move(context));
	}
    }
    result.steps = 200000 - result.remaining;
    return result;
}

std::string DecisionBranchNote(const FieldBranchUsesResult &fields,
                               const DecisionBranchesResult &result, const DecisionBranchUse &use)
{
    const auto &context = result.contexts.at(use.context);
    const auto &reload = context.reloads.at(use.reload);
    return std::format("decision branch: Boolean saved at {:#x}; true -> {:#x}, false -> {:#x} "
                       "[conditional on reload {:#x}; owned tagged frame slot FP{:+}; "
                       "normal call fallthrough; successful SDK resumes]",
                       fields.decisions.at(context.decision).site, use.trueTarget, use.falseTarget,
                       reload.site, reload.slot);
}

void WriteDecisionBranches(std::ostream &out, const Profile &p,
                           const DecisionBranchesResult &result)
{
    out << R"(,"decision_branch_abi":{"value_bit":)";
    if (p.booleanValueBit)
	out << *p.booleanValueBit;
    else
	out << "null";
    out << R"(},"decision_reference_contexts":[)";
    bool comma = false;
    for (const auto &c : result.contexts)
    {
	if (comma)
	    out << ',';
	comma = true;
	out << R"({"decision":)" << c.decision << R"(,"payload":)" << c.payload << R"(,"status":")"
	    << c.status << R"(","steps":)" << c.steps << R"(,"reloads":[)";
	bool reloadComma = false;
	for (const auto &r : c.reloads)
	{
	    if (reloadComma)
		out << ',';
	    reloadComma = true;
	    out << R"({"site":)" << r.site << R"(,"store":)" << r.store << R"(,"slot":)" << r.slot
	        << R"(,"register":)" << r.reg << '}';
	}
	out << "]}";
    }
    out << R"(],"decision_branch_uses":[)";
    comma = false;
    for (const auto &u : result.uses)
    {
	if (comma)
	    out << ',';
	comma = true;
	out << R"({"context":)" << u.context << R"(,"reload":)" << u.reload << R"(,"site":)"
	    << u.site << R"(,"true_target":)" << u.trueTarget << R"(,"false_target":)"
	    << u.falseTarget << '}';
    }
    out << R"(],"decision_branch_work":{"steps":)" << result.steps << R"(,"remaining":)"
        << result.remaining << R"(,"bytes":)" << result.bytes << R"(,"complete":)"
        << (result.complete ? "true" : "false") << '}';
}

std::string JoinedReferenceNote(const JoinedReferenceContext &c, const JoinedReference &r)
{
    if (r.lastSuspensions.size() < 2 || r.lastSuspensions.size() > 8)
	throw std::runtime_error("Joined-reference note lacks bounded alternatives");
    std::string alternatives;
    for (const auto site : r.lastSuspensions)
    {
	if (!alternatives.empty())
	    alternatives += ", ";
	alternatives += site ? std::format("{:#x}", site) : "no additional await";
    }
    return std::format("async joined-reference: load result X{} heap class {:#x} [conditional: "
                       "delivery at await {:#x}; "
                       "store {:#x} to FP{:+}; last suspension alternatives since store {{{}}}; "
                       "normal call fallthrough; "
                       "successful SDK resumes; value/error-preserving callbacks; reference only]",
                       r.reg, c.classId, c.sourceAwait, r.store, r.slot, alternatives);
}

void WriteJoinedReferences(std::ostream &out, const JoinedReferencesResult &result)
{
    out << ",\"joined_reference_contexts\":[";
    for (size_t n = 0; n < result.contexts.size(); ++n)
    {
	if (n)
	    out << ',';
	const auto &c = result.contexts[n];
	out << "{\"payload\":" << c.payload << ",\"source_await\":" << c.sourceAwait
	    << ",\"class_id\":" << c.classId
	    << ",\"scope\":\"conditional_joined_reference_only\",\"status\":" << Quote(c.status)
	    << ",\"steps\":" << c.steps << ",\"observations\":[";
	for (size_t j = 0; j < c.observations.size(); ++j)
	{
	    if (j)
		out << ',';
	    const auto &r = c.observations[j];
	    out << "{\"site\":" << r.site << ",\"store\":" << r.store << ",\"slot\":" << r.slot
	        << ",\"register\":" << r.reg << ",\"last_suspensions\":[";
	    bool comma = false;
	    for (const auto site : r.lastSuspensions)
	    {
		if (comma)
		    out << ',';
		comma = true;
		if (site)
		    out << site;
		else
		    out << "null";
	    }
	    out << "]}";
	}
	out << "]}";
    }
    out << "],\"joined_reference_work\":{\"limit\":200000,\"region_limit\":2048,\"history_limit\":"
           "8,\"context_limit\":4096,\"body_limit\":65536,\"byte_limit\":8388608,\"steps\":"
        << result.steps << ",\"remaining\":" << result.remaining
        << ",\"history_overflows\":" << result.historyOverflows << ",\"bytes\":" << result.bytes
        << ",\"complete\":" << (result.complete ? "true" : "false") << '}';
}
} // namespace SnapshotAnalysis
