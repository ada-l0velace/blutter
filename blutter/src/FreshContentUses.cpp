#include "FreshContentUses.h"
#include "Arm64Decode.h"
#include "Arm64Ir.h"
#include "FieldInputOrigins.h"
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
constexpr size_t Limit = 200000, RegionLimit = 128, ContextLimit = 4096;
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
bool Group(const cs_insn &i, unsigned group)
{
    return std::find(i.detail->groups, i.detail->groups + i.detail->groups_count, group) !=
           i.detail->groups + i.detail->groups_count;
}
struct State
{
    uint32_t objects = 0;
    std::array<uint64_t, 15> allocations{};
    std::set<int64_t> arguments;
};
void Meet(State &to, const State &from)
{
    to.objects &= from.objects;
    for (unsigned r = 0; r < 15; ++r)
	if (to.allocations[r] != from.allocations[r])
	    to.allocations[r] = 0;
    std::erase_if(to.arguments, [&](int64_t s) { return !from.arguments.contains(s); });
}
struct Decoder
{
    csh handle = 0;
    ~Decoder()
    {
	if (handle)
	    cs_close(&handle);
    }
};
} // namespace

FreshContentResult DescribeFreshContentUses(
    const Profile &p, const AsyncFieldsResult &fields, const CapturedFieldsResult &captures,
    const FreshFieldsResult &fresh, const std::map<uint64_t, std::vector<uint8_t>> &bytes,
    const std::set<uint64_t> &externalEntries, const std::vector<CallInputOrigin> &origins,
    const std::vector<Edge> &edges, const CallInputShapes &shapes)
{
    FreshContentResult result;
    std::map<uint64_t, std::vector<size_t>> seeds;
    for (size_t n = 0; n < fresh.contexts.size(); ++n)
    {
	const auto &c = fresh.contexts[n];
	if (c.write)
	    seeds[fields.contexts.at(captures.contexts.at(c.capture).context).payload].push_back(n);
    }
    if (seeds.empty())
	return result;
    std::map<std::pair<uint64_t, uint64_t>, const Edge *> calls;
    std::map<std::pair<uint64_t, uint64_t>, std::vector<size_t>> inputsAt;
    for (const auto &edge : edges)
	if (seeds.contains(edge.source))
	    calls.emplace(std::pair{edge.source, edge.site}, &edge);
    for (size_t n = 0; n < origins.size(); ++n)
	if (seeds.contains(origins[n].payload))
	    inputsAt[{origins[n].payload, origins[n].site}].push_back(n);
    Decoder decoder;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &decoder.handle) != CS_ERR_OK ||
        cs_option(decoder.handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
	throw std::runtime_error("Cannot initialize fresh-content decoder");
    for (const auto &[payload, group] : seeds)
    {
	cs_insn *raw = nullptr;
	size_t count = 0;
	if (bytes.contains(payload))
	{
	    const auto &code = bytes.at(payload);
	    std::tie(raw, count) =
	        DecodeArm64Instructions(decoder.handle, code.data(), code.size(), payload);
	    if (count * 4 != code.size())
	    {
		cs_free(raw, count);
		throw std::runtime_error("Cannot decode fresh-content caller");
	    }
	}
	const std::shared_ptr<cs_insn> owner(raw, [count](cs_insn *v) { cs_free(v, count); });
	std::map<uint64_t, std::set<uint64_t>> incoming;
	for (size_t n = 0; n < count; ++n)
	{
	    const auto &d = raw[n].detail->arm64;
	    if (Group(raw[n], CS_GRP_JUMP) && d.op_count &&
	        d.operands[d.op_count - 1].type == ARM64_OP_IMM)
		incoming[static_cast<uint64_t>(d.operands[d.op_count - 1].imm)].insert(
		    raw[n].address);
	}
	for (const auto seed : group)
	{
	    if (!result.remaining || result.contexts.size() == ContextLimit)
	    {
		result.complete = false;
		break;
	    }
	    FreshContentContext c{seed};
	    const auto &f = fresh.contexts[seed];
	    const auto &w = *f.write;
	    if (!bytes.contains(payload))
	    {
		c.status = "missing_caller_bytes";
		result.contexts.push_back(std::move(c));
		continue;
	    }
	    if (w.site < payload || w.site % 4 || (w.site - payload) / 4 >= count || w.base >= 15)
		throw std::runtime_error("Invalid fresh-content initialization");
	    const auto &store = raw[(w.site - payload) / 4];
	    const auto &sd = store.detail->arm64;
	    if ((store.id != ARM64_INS_STR && store.id != ARM64_INS_STUR) || sd.op_count != 2 ||
	        sd.writeback || sd.operands[0].type != ARM64_OP_REG ||
	        sd.operands[1].type != ARM64_OP_MEM ||
	        Number(sd.operands[0].reg) != static_cast<int>(w.reg) ||
	        Width(sd.operands[0].reg) != w.bytes ||
	        Number(sd.operands[1].mem.base) != static_cast<int>(w.base) ||
	        sd.operands[1].mem.index != ARM64_REG_INVALID ||
	        sd.operands[1].mem.disp + 1 != w.offset)
		throw std::runtime_error("Fresh-content seed contradicts original store");
	    std::map<size_t, State> pending{{(w.site - payload) / 4 + 1, State{1U << w.base}}};
	    std::set<uint64_t> visited{w.site};
	    std::optional<State> terminal;
	    bool failed = false;
	    auto stop = [&](const char *why)
	    {
		c.status = why;
		failed = true;
	    };
	    while (!pending.empty() && !failed)
	    {
		auto first = pending.begin();
		const auto n = first->first;
		auto state = first->second;
		pending.erase(first);
		if (n >= count)
		{
		    stop("payload_end");
		    break;
		}
		if (!result.remaining)
		{
		    result.complete = false;
		    stop("step_limit");
		    break;
		}
		if (c.steps == RegionLimit)
		{
		    stop("region_limit");
		    break;
		}
		--result.remaining;
		++c.steps;
		const auto &i = raw[n];
		const auto &d = i.detail->arm64;
		visited.insert(i.address);
		if (externalEntries.contains(i.address))
		{
		    stop("alternate_entry");
		    break;
		}
		if (!state.objects && state.arguments.empty())
		{
		    stop("container_lost");
		    break;
		}
		auto has = [&](int r) { return r >= 0 && r < 15 && (state.objects & (1U << r)); };
		auto next = [&](size_t target)
		{
		    if (auto old = pending.find(target); old != pending.end())
			Meet(old->second, state);
		    else
			pending.emplace(target, state);
		};
		if (i.id == ARM64_INS_BL ||
		    (i.id == ARM64_INS_B && d.cc == ARM64_CC_INVALID && d.op_count == 1 &&
		     d.operands[0].type == ARM64_OP_IMM &&
		     (d.operands[0].imm < static_cast<int64_t>(payload) ||
		      d.operands[0].imm >= static_cast<int64_t>(payload + count * 4))))
		{
		    if (d.op_count != 1 || d.operands[0].type != ARM64_OP_IMM)
		    {
			stop("unknown_transfer");
			break;
		    }
		    const auto target = static_cast<uint64_t>(d.operands[0].imm);
		    if (i.id == ARM64_INS_BL && p.freshContentAllocators.contains(target))
		    {
			if (!p.allocationReturns.contains(target) ||
			    !p.preservedCallRegisters.contains(target) ||
			    !p.allocationBodyBounds.contains(target) ||
			    p.allocationResultRegister != ARM64_REG_X0 ||
			    (p.preservedCallRegisters.at(target) & 1))
			    throw std::runtime_error("Invalid fresh-content allocator contract");
			if (!state.arguments.empty())
			{
			    stop("unproved_stack_lifetime");
			    break;
			}
			const auto mask = p.preservedCallRegisters.at(target);
			const auto bounds = p.allocationBodyBounds.at(target);
			if (bounds.first < 0 || bounds.second <= bounds.first ||
			    bounds.second > 1048576)
			    throw std::runtime_error("Invalid fresh-content allocator body bounds");
			state.objects &= mask;
			for (unsigned r = 0; r < 15; ++r)
			    if (!(mask & (1U << r)))
				state.allocations[r] = 0;
			state.allocations[0] = target;
			next(n + 1);
			continue;
		    }
		    if (c.transfer && *c.transfer != i.address)
		    {
			stop("divergent_transfers");
			break;
		    }
		    c.transfer = i.address;
		    terminal = state;
		    continue;
		}
		if (Group(i, CS_GRP_JUMP))
		{
		    if (!d.op_count || d.operands[d.op_count - 1].type != ARM64_OP_IMM)
		    {
			stop("unknown_transfer");
			break;
		    }
		    const auto target = static_cast<uint64_t>(d.operands[d.op_count - 1].imm);
		    if (target <= i.address || target < payload || target >= payload + count * 4 ||
		        target % 4)
		    {
			stop("unsupported_branch");
			break;
		    }
		    next((target - payload) / 4);
		    if (i.id != ARM64_INS_B || d.cc != ARM64_CC_INVALID)
			next(n + 1);
		    continue;
		}
		if (Group(i, CS_GRP_CALL) || Group(i, CS_GRP_RET) || Group(i, CS_GRP_INT) ||
		    i.id == ARM64_INS_BRK)
		{
		    stop("unknown_transfer");
		    break;
		}
		if (i.id == ARM64_INS_MOV && d.op_count == 2 && !d.writeback && !d.update_flags &&
		    d.operands[0].type == ARM64_OP_REG && d.operands[1].type == ARM64_OP_REG &&
		    Width(d.operands[0].reg) == 8 && Width(d.operands[1].reg) == 8 &&
		    Number(d.operands[0].reg) >= 0 && Number(d.operands[0].reg) < 15 &&
		    Number(d.operands[1].reg) >= 0 && Number(d.operands[1].reg) < 15)
		{
		    const auto to = Number(d.operands[0].reg), from = Number(d.operands[1].reg);
		    const bool object = has(from);
		    state.objects &= ~(1U << to);
		    if (object)
			state.objects |= 1U << to;
		    state.allocations[to] = state.allocations[from];
		    next(n + 1);
		    continue;
		}
		if ((i.id == ARM64_INS_STR || i.id == ARM64_INS_STUR) && d.op_count == 2 &&
		    !d.writeback && d.operands[0].type == ARM64_OP_REG &&
		    d.operands[1].type == ARM64_OP_MEM &&
		    d.operands[1].mem.index == ARM64_REG_INVALID)
		{
		    const auto source = Number(d.operands[0].reg),
		               base = Number(d.operands[1].mem.base);
		    const int64_t off = d.operands[1].mem.disp;
		    const unsigned width = Width(d.operands[0].reg);
		    if (base == 15 && p.callInputAbi.supported && p.callInputAbi.wordBytes == 8 &&
		        off >= 0 && off <= 4096 && width == 8 && off % 8 == 0)
		    {
			state.arguments.erase(off);
			if (has(source))
			    state.arguments.insert(off);
			next(n + 1);
			continue;
		    }
		    if (has(source))
		    {
			stop("container_escaped");
			break;
		    }
		    if (has(base))
		    {
			if (off < 0 || off > 1048576 || width != w.bytes)
			{
			    stop("unproved_store");
			    break;
			}
			const auto begin = off + 1;
			if (begin < w.offset + w.bytes && w.offset < begin + width)
			{
			    stop("selected_storage_overwritten");
			    break;
			}
			bool valid = false;
			if (f.kind == "array_element")
			{
			    const auto &a = p.arrayBodyContract;
			    valid = a.size() == 5 && f.length && begin >= a[2] + 1 &&
			            (begin - a[2] - 1) % width == 0 &&
			            static_cast<uint64_t>((begin - a[2] - 1) / width) < *f.length;
			}
			else
			{
			    const auto &l = fresh.layouts.at(f.classId);
			    valid =
			        begin >= l.header && begin + width <= l.end && begin % width == 0 &&
			        !std::binary_search(l.excluded.begin(), l.excluded.end(), begin) &&
			        !std::binary_search(l.unboxed.begin(), l.unboxed.end(), begin);
			}
			if (!valid)
			{
			    stop("unproved_store");
			    break;
			}
		    }
		    else if (base >= 0 && base < 15 && state.allocations[base])
		    {
			const auto bounds = p.allocationBodyBounds.at(state.allocations[base]);
			if (off < bounds.first || off > 1048576 || off + width > bounds.second)
			{
			    stop("unproved_store");
			    break;
			}
		    }
		    else
		    {
			stop("unproved_alias_write");
			break;
		    }
		    next(n + 1);
		    continue;
		}
		if (i.id == ARM64_INS_NOP || i.id == ARM64_INS_CMP || i.id == ARM64_INS_CMN ||
		    i.id == ARM64_INS_TST)
		{
		    next(n + 1);
		    continue;
		}
		const auto lower = LowerArm64(i);
		if (!lower)
		{
		    stop("unknown_effects");
		    break;
		}
		const auto effect = NativeIr::GetEffects(*lower);
		if (effect.unlistedRegistersMayChange ||
		    effect.memory == NativeIr::MemoryEffect::Unknown ||
		    effect.control != NativeIr::ControlEffect::Fallthrough)
		{
		    stop("unknown_effects");
		    break;
		}
		if (effect.memory != NativeIr::MemoryEffect::Read)
		    for (unsigned j = 0; j < d.op_count; ++j)
			if (d.operands[j].type == ARM64_OP_REG &&
			    (d.operands[j].access & CS_AC_READ) && has(Number(d.operands[j].reg)))
			{
			    stop("unproved_container_use");
			    break;
			}
		if (failed)
		    break;
		if (effect.destination)
		{
		    const auto r = effect.destination->id;
		    if (r == 15 || r == 29 || r == 31)
		    {
			stop("stack_changed");
			break;
		    }
		    if (r < 15)
		    {
			state.objects &= ~(1U << r);
			state.allocations[r] = 0;
		    }
		}
		next(n + 1);
	    }
	    if (!failed && terminal && c.transfer)
	    {
		// A branch into this region from an unvisited predecessor bypasses
		// the initialized state. Internal forward joins are checked above.
		for (const auto pc : visited)
		    if (pc != w.site && incoming.contains(pc))
			for (const auto pred : incoming.at(pc))
			    if (!visited.contains(pred))
				stop("alternate_entry");
		if (!failed)
		{
		    c.status = "consumer_role_unproved";
		    const auto edge = calls.find({payload, *c.transfer});
		    if (edge != calls.end() &&
		        (!edge->second->target ||
		         *edge->second->target !=
		             static_cast<uint64_t>(
		                 raw[(*c.transfer - payload) / 4].detail->arm64.operands[0].imm)))
			throw std::runtime_error(
			    "Fresh-content transfer contradicts original call");
		    if (edge != calls.end())
			for (const auto n : inputsAt[{payload, *c.transfer}])
			{
			    const auto &input = origins[n];
			    if (!IsRoleProvenCallInput(input, p, *edge->second, shapes))
				continue;
			    if ((input.reg && *input.reg < 15 &&
			         (terminal->objects & (1U << *input.reg))) ||
			        (input.spOffset && terminal->arguments.contains(*input.spOffset)))
				c.inputs.push_back(n);
			}
		    if (!c.inputs.empty())
			c.status = "matched_container_input";
		}
	    }
	    if (!failed && !terminal)
		c.status = "payload_end";
	    if (failed)
	    {
		c.inputs.clear();
		c.transfer.reset();
	    }
	    if (!failed && terminal && c.transfer)
		result.stackLocations.emplace(result.contexts.size(), terminal->arguments);
	    c.proof.assign(visited.begin(), visited.end());
	    result.contexts.push_back(std::move(c));
	}
	if (!result.complete)
	    break;
    }
    result.steps = Limit - result.remaining;
    return result;
}

std::string FreshContentNote(const AsyncFieldsResult &fields, const CapturedFieldsResult &captures,
                             const FreshFieldsResult &fresh,
                             const std::vector<CallInputOrigin> &origins,
                             const FreshContentContext &c, size_t input)
{
    if (c.status != "matched_container_input" || !c.transfer ||
        std::find(c.inputs.begin(), c.inputs.end(), input) == c.inputs.end())
	throw std::runtime_error("Fresh-content annotation lacks a proved input role");
    const auto &f = fresh.contexts.at(c.initialization);
    const auto &w = *f.write;
    const auto &capture = captures.contexts.at(f.capture);
    const auto &field = fields.contexts.at(capture.context);
    const auto &access = field.accesses.at(capture.access);
    const auto &o = origins.at(input);
    const auto role = o.index ? std::format("supplied input[{}]", *o.index) : o.role;
    const auto storage = w.index ? std::format("array element [{}]", *w.index)
                                 : std::format("instance slot {:#x}", w.offset);
    return std::format(
        "container input origin: {} contains {} <- captured read {:#x}; initialization {:#x} "
        "[conditional: {} seed {:#x}; delivery at await {:#x}; normal producer/allocation returns; "
        "successful SDK resumes; "
        "value/error-preserving callbacks; selected contents preserved to transfer; callee "
        "element/field use and value type unknown]",
        role, storage, access.site, w.site, field.basis, field.seed, field.sourceAwait);
}

void WriteFreshContentUses(std::ostream &out, const Profile &p, const FreshContentResult &result)
{
    out << ",\"fresh_content_allocators\":[";
    bool comma = false;
    for (const auto entry : p.freshContentAllocators)
    {
	if (comma)
	    out << ',';
	comma = true;
	out << entry;
    }
    out << "],\"fresh_content_contexts\":[";
    for (size_t n = 0; n < result.contexts.size(); ++n)
    {
	if (n)
	    out << ',';
	const auto &c = result.contexts[n];
	out << "{\"initialization\":" << c.initialization << ",\"status\":\"" << c.status
	    << "\",\"steps\":" << c.steps
	    << ",\"transfer\":" << (c.transfer ? std::to_string(*c.transfer) : "null")
	    << ",\"inputs\":[";
	for (size_t j = 0; j < c.inputs.size(); ++j)
	{
	    if (j)
		out << ',';
	    out << c.inputs[j];
	}
	out << "],\"proof\":[";
	for (size_t j = 0; j < c.proof.size(); ++j)
	{
	    if (j)
		out << ',';
	    out << c.proof[j];
	}
	out << "],\"scope\":\"conditional_container_contents_at_transfer\"}";
    }
    out << "],\"fresh_content_work\":{\"limit\":" << Limit << ",\"region_limit\":" << RegionLimit
        << ",\"context_limit\":" << ContextLimit << ",\"steps\":" << result.steps
        << ",\"remaining\":" << result.remaining
        << ",\"complete\":" << (result.complete ? "true" : "false") << '}';
}
} // namespace SnapshotAnalysis
