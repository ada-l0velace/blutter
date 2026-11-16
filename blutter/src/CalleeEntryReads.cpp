#include "CalleeEntryReads.h"
#include "Arm64Decode.h"
#include "Arm64Ir.h"
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
constexpr size_t Limit = 200000, PrefixLimit = 64, ByteLimit = 4 * 1024 * 1024;
constexpr size_t BodyLimit = 65536, ContractLimit = 4096, LinkLimit = 4096, ReadLimit = 16;
int Number(arm64_reg r)
{
    if (r >= ARM64_REG_X0 && r <= ARM64_REG_X28)
	return r - ARM64_REG_X0;
    if (r >= ARM64_REG_W0 && r <= ARM64_REG_W30)
	return r - ARM64_REG_W0;
    return r == ARM64_REG_X29 ? 29 : r == ARM64_REG_X30 ? 30 : r == ARM64_REG_SP ? 31 : -1;
}
unsigned Width(arm64_reg r)
{
    if ((r >= ARM64_REG_X0 && r <= ARM64_REG_X28) || r == ARM64_REG_X29 || r == ARM64_REG_X30 ||
        r == ARM64_REG_SP || r == ARM64_REG_XZR)
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

CalleeEntryContract ProveCalleeEntryReads(uint64_t entry, const std::vector<uint8_t> &code,
                                          const Profile &p, size_t &remaining, const CallInputAbi *entryAbi)
{
    CalleeEntryContract result{entry, entry};
    const auto &abi = entryAbi ? *entryAbi : p.callInputAbi;
    if (!abi.supported || abi.wordBytes != 8)
    {
	result.stop = "unsupported_abi";
	return result;
    }
    if (!entry || entry % 4 || code.empty() || code.size() % 4 || code.size() > BodyLimit ||
        entry > UINT64_MAX - code.size())
	throw std::runtime_error("Invalid callee-entry byte range");
    result.end = entry + code.size();
    if (code.size() / 4 > remaining)
    {
	result.stop = "step_limit";
	return result;
    }
    Decoder decoder;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &decoder.handle) != CS_ERR_OK ||
        cs_option(decoder.handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
	throw std::runtime_error("Cannot initialize callee-entry decoder");
    auto [raw, count] = DecodeArm64Instructions(decoder.handle, code.data(), code.size(), entry);
    if (count * 4 != code.size())
    {
	cs_free(raw, count);
	throw std::runtime_error("Cannot decode callee-entry body");
    }
    const std::shared_ptr<cs_insn> owner(raw, [count](cs_insn *i) { cs_free(i, count); });
    result.decoded = count;
    remaining -= count;
    const auto initialGuard = FindInitialStackCheck(raw, count, p);
    std::array<std::optional<int64_t>, 32> coordinate{};
    coordinate[15] = 0;
    result.stop = "body_end";
    for (size_t n = 0; n < count; ++n)
    {
	if (!remaining)
	{
	    result.stop = "step_limit";
	    result.reads.clear();
	    break;
	}
	if (result.steps == PrefixLimit)
	{
	    result.stop = "prefix_limit";
	    break;
	}
	if (result.reads.size() >= ReadLimit)
	{
	    result.stop = "read_limit";
	    break;
	}
	--remaining;
	++result.steps;
	const auto &i = raw[n];
	const auto &d = i.detail->arm64;
	if (Group(i, CS_GRP_CALL) || Group(i, CS_GRP_RET) || Group(i, CS_GRP_INT) ||
	    i.id == ARM64_INS_BRK)
	{
	    result.stop = "call_or_return";
	    break;
	}
	if (Group(i, CS_GRP_JUMP))
	{
	    if (!initialGuard || initialGuard->site != i.address)
	    {
		result.stop = "unproved_control";
		break;
	    }
	    result.guard = initialGuard;
	    result.prefix.push_back(i.address);
	    continue;
	}
	auto at = [&](arm64_reg r, int64_t displacement) -> std::optional<int64_t>
	{
	    const auto number = Number(r);
	    if (number < 0 || !coordinate[number] || displacement < -65536 || displacement > 65536)
		return {};
	    const auto value = *coordinate[number] + displacement;
	    return value >= -65536 && value <= 65536 ? std::optional<int64_t>{value} : std::nullopt;
	};
	const bool pairStore = i.id == ARM64_INS_STP;
	if (pairStore || i.id == ARM64_INS_STR || i.id == ARM64_INS_STUR)
	{
	    const unsigned mem = pairStore ? 2 : 1;
	    if (d.op_count != mem + 1 || d.operands[mem].type != ARM64_OP_MEM ||
	        d.operands[mem].mem.index != ARM64_REG_INVALID ||
	        d.operands[0].type != ARM64_OP_REG ||
	        (pairStore && d.operands[1].type != ARM64_OP_REG))
	    {
		result.stop = "unproved_store";
		break;
	    }
	    const auto &m = d.operands[mem].mem;
	    const auto offset = at(m.base, m.disp);
	    const auto width = Width(d.operands[0].reg);
	    const auto size = width * (pairStore ? 2 : 1);
	    if (!width || (pairStore && Width(d.operands[1].reg) != width) || !offset ||
	        !coordinate[15])
	    {
		result.stop = "unproved_store";
		break;
	    }
	    if (d.writeback)
	    {
		if (m.base != ARM64_REG_X15 || m.disp >= 0 || d.op_count != (pairStore ? 3 : 2))
		{
		    result.stop = "unproved_store";
		    break;
		}
		if (Number(d.operands[0].reg) == 15 ||
		    (pairStore && Number(d.operands[1].reg) == 15))
		{
		    result.stop = "unproved_store";
		    break;
		}
		coordinate[15] = offset;
	    }
	    if (*offset < *coordinate[15] || *offset + size > 0)
	    {
		result.stop = "incoming_or_unowned_write";
		break;
	    }
	    result.prefix.push_back(i.address);
	    continue;
	}
	const bool pairLoad = i.id == ARM64_INS_LDP;
	if (pairLoad || i.id == ARM64_INS_LDR || i.id == ARM64_INS_LDUR || i.id == ARM64_INS_LDTR)
	{
	    const unsigned mem = pairLoad ? 2 : 1;
	    if (d.op_count != mem + 1 || d.writeback || d.operands[mem].type != ARM64_OP_MEM ||
	        d.operands[mem].mem.index != ARM64_REG_INVALID ||
	        d.operands[0].type != ARM64_OP_REG ||
	        (pairLoad && d.operands[1].type != ARM64_OP_REG))
	    {
		result.stop = "unproved_load";
		break;
	    }
	    const auto &m = d.operands[mem].mem;
	    const auto width = Width(d.operands[0].reg);
	    if (!width || (pairLoad && Width(d.operands[1].reg) != width))
	    {
		result.stop = "unproved_load";
		break;
	    }
	    bool invalid = false;
	    for (unsigned part = 0; part < (pairLoad ? 2U : 1U); ++part)
	    {
		const auto r = Number(d.operands[part].reg);
		invalid |= r < 0 || r == 15 || r == 29 || r == 31;
	    }
	    if (invalid)
	    {
		result.stop = "frame_register_load";
		break;
	    }
	    if (pairLoad && d.operands[0].reg == d.operands[1].reg)
	    {
		result.stop = "unproved_load";
		break;
	    }
	    // Both addresses use the pre-instruction base, including an aliased LDP destination.
	    std::array<std::optional<int64_t>, 2> offsets;
	    for (unsigned part = 0; part < (pairLoad ? 2U : 1U); ++part)
		offsets[part] = at(m.base, m.disp + width * part);
	    for (unsigned part = 0; part < (pairLoad ? 2U : 1U); ++part)
	    {
		const auto r = Number(d.operands[part].reg);
		if (result.reads.size() < ReadLimit && width == 8 && r < 15 && offsets[part] &&
		    *offsets[part] >= 0 && *offsets[part] <= 248 && *offsets[part] % 8 == 0)
		    result.reads.push_back(
		        {i.address, *offsets[part], static_cast<unsigned>(r), part});
		coordinate[r].reset();
	    }
	    result.prefix.push_back(i.address);
	    continue;
	}
	if (i.id == ARM64_INS_MOV && d.op_count == 2 && !d.writeback && !d.update_flags &&
	    d.operands[0].type == ARM64_OP_REG && d.operands[1].type == ARM64_OP_REG &&
	    Width(d.operands[0].reg) == 8 && Width(d.operands[1].reg) == 8)
	{
	    const auto to = Number(d.operands[0].reg), from = Number(d.operands[1].reg);
	    if (to < 0 || from < 0 || to == 31 ||
	        (to == 15 && (!coordinate[from] || *coordinate[from] > 0)))
	    {
		result.stop = "coordinate_lost";
		break;
	    }
	    coordinate[to] = coordinate[from];
	    result.prefix.push_back(i.address);
	    continue;
	}
	if (i.id == ARM64_INS_NOP || i.id == ARM64_INS_CMP || i.id == ARM64_INS_CMN ||
	    i.id == ARM64_INS_TST)
	{
	    result.prefix.push_back(i.address);
	    continue;
	}
	const auto lowered = LowerArm64(i);
	if (!lowered)
	{
	    result.stop = "unknown_effects";
	    break;
	}
	const auto effect = NativeIr::GetEffects(*lowered);
	if (effect.unlistedRegistersMayChange || effect.memory != NativeIr::MemoryEffect::None ||
	    effect.control != NativeIr::ControlEffect::Fallthrough)
	{
	    result.stop = "unknown_effects";
	    break;
	}
	if (effect.destination)
	{
	    const auto r = effect.destination->id;
	    std::optional<int64_t> value;
	    if (const auto *b = std::get_if<NativeIr::Binary>(&lowered->operation);
	        b && b->target.valueBits == 64 &&
	        (b->kind == NativeIr::BinaryKind::Add ||
	         b->kind == NativeIr::BinaryKind::Subtract) &&
	        std::holds_alternative<NativeIr::RegisterView>(b->left) &&
	        std::holds_alternative<NativeIr::Literal>(b->right))
	    {
		const auto base = std::get<NativeIr::RegisterView>(b->left);
		const auto literal = std::get<NativeIr::Literal>(b->right).value;
		if (base.id < 32 && base.bits == 64 && coordinate[base.id] && literal <= 65536)
		{
		    const auto delta = static_cast<int64_t>(literal) *
		                       (b->kind == NativeIr::BinaryKind::Add ? 1 : -1);
		    const auto sum = *coordinate[base.id] + delta;
		    if (sum >= -65536 && sum <= 65536)
			value = sum;
		}
	    }
	    if (r >= 32 || r == 31 || (r == 15 && (!value || *value > 0)))
	    {
		result.stop = "coordinate_lost";
		break;
	    }
	    coordinate[r] = value;
	}
	result.prefix.push_back(i.address);
    }
    return result;
}

CalleeEntryResult LinkContainerEntryReads(const Profile &p, const FreshContentResult &contents,
                                          const std::vector<Payload> &payloads,
                                          const std::vector<Edge> &edges)
{
    CalleeEntryResult result;
    if (!p.callInputAbi.supported || p.callInputAbi.wordBytes != 8 || !p.readInputCode)
	return result;
    std::map<uint64_t, std::vector<size_t>> requests;
    for (size_t n = 0; n < contents.contexts.size(); ++n)
    {
	const auto &c = contents.contexts[n];
	if (c.transfer && c.inputs.empty() && contents.stackLocations.contains(n) &&
	    !contents.stackLocations.at(n).empty())
	    requests[*c.transfer].push_back(n);
    }
    if (requests.empty())
	return result;
    std::map<uint64_t, uint64_t> bounds;
    for (const auto &b : payloads)
	bounds.emplace(b.start, b.end);
    std::map<uint64_t, size_t> contracts;
    for (const auto &e : edges)
    {
	if (!requests.contains(e.site) || e.kind != "call" || !e.target ||
	    !bounds.contains(*e.target))
	    continue;
	const auto target = *e.target, end = bounds.at(target);
	if (!contracts.contains(target))
	{
	    if (result.contracts.size() >= ContractLimit || !result.remaining)
	    {
		result.complete = false;
		break;
	    }
	    CalleeEntryContract c{target, end};
	    if (end <= target || target % 4 || end % 4)
		throw std::runtime_error("Invalid entry-read payload bounds");
	    if (end - target > BodyLimit)
		c.stop = "body_limit";
	    else if (end - target > ByteLimit - result.bytes)
	    {
		c.stop = "byte_limit";
		result.complete = false;
	    }
	    else
	    {
		auto code = p.readInputCode(target, end - target);
		if (code.size() != end - target)
		    c.stop = "missing_bytes";
		else
		{
		    c = ProveCalleeEntryReads(target, code, p, result.remaining);
		    result.bytes += c.decoded * 4;
		}
		if (c.stop == "step_limit")
		    result.complete = false;
	    }
	    contracts.emplace(target, result.contracts.size());
	    result.contracts.push_back(std::move(c));
	}
	const auto ci = contracts.at(target);
	const auto &c = result.contracts[ci];
	for (const auto context : requests.at(e.site))
	    for (size_t ri = 0; ri < c.reads.size(); ++ri)
	    {
		if (!contents.stackLocations.at(context).contains(c.reads[ri].offset))
		    continue;
		if (result.links.size() >= LinkLimit)
		{
		    result.complete = false;
		    break;
		}
		result.links.push_back({context, ci, ri});
	    }
	if (!result.complete)
	    break;
    }
    result.steps = Limit - result.remaining;
    return result;
}

std::string ContainerEntryReadNote(const AsyncFieldsResult &fields,
                                   const CapturedFieldsResult &captures,
                                   const FreshFieldsResult &fresh,
                                   const FreshContentResult &contents,
                                   const CalleeEntryResult &result, const ContainerEntryLink &link)
{
    const auto &context = contents.contexts.at(link.context);
    const auto &f = fresh.contexts.at(context.initialization);
    const auto &w = *f.write;
    const auto &parent = captures.contexts.at(f.capture);
    const auto &field = fields.contexts.at(parent.context);
    const auto &access = field.accesses.at(parent.access);
    const auto &contract = result.contracts.at(link.contract);
    const auto &read = contract.reads.at(link.read);
    if (!context.transfer || !contents.stackLocations.at(link.context).contains(read.offset))
	throw std::runtime_error("Entry-read note lacks a container handoff");
    const auto storage = w.index ? std::format("array element [{}]", *w.index)
                                 : std::format("instance slot {:#x}", w.offset);
    return std::format(
        "container consumer: callee entry SP+{:#x}, read {:#x} contains {} <- captured read {:#x}; "
        "initialization {:#x} "
        "[conditional: {} seed {:#x}; delivery at await {:#x}; normal producer/allocation returns; "
        "successful SDK resumes; "
        "value/error-preserving callbacks; {}pure entry prefix; selected contents at this read "
        "only; source parameter position/type and later element/field use unknown]",
        read.offset, read.site, storage, access.site, w.site, field.basis, field.seed,
        field.sourceAwait, contract.guard ? "callee initial stack-check fast path; " : "");
}

void WriteCalleeEntryReads(std::ostream &out, const CalleeEntryResult &result)
{
    out << ",\"callee_entry_read_contracts\":[";
    for (size_t n = 0; n < result.contracts.size(); ++n)
    {
	if (n)
	    out << ',';
	const auto &c = result.contracts[n];
	out << "{\"entry\":" << c.entry << ",\"end\":" << c.end << ",\"stop\":\"" << c.stop
	    << "\",\"steps\":" << c.steps << ",\"decoded\":" << c.decoded << ",\"prefix\":[";
	for (size_t j = 0; j < c.prefix.size(); ++j)
	{
	    if (j)
		out << ',';
	    out << c.prefix[j];
	}
	out << "],\"reads\":[";
	for (size_t j = 0; j < c.reads.size(); ++j)
	{
	    if (j)
		out << ',';
	    const auto &r = c.reads[j];
	    out << "{\"site\":" << r.site << ",\"entry_sp_offset\":" << r.offset
	        << ",\"register\":" << r.reg << ",\"part\":" << r.part << ",\"bytes\":8}";
	}
	out << "],\"guard\":";
	if (!c.guard)
	    out << "null";
	else
	{
	    const auto &g = *c.guard;
	    out << "{\"site\":" << g.site << ",\"successor\":" << g.successor
	        << ",\"slow_path\":" << g.slowPath << ",\"stub\":" << g.stub << ",\"proof\":[";
	    for (size_t j = 0; j < g.proof.size(); ++j)
	    {
		if (j)
		    out << ',';
		out << g.proof[j];
	    }
	    out << "]}";
	}
	out << '}';
    }
    out << "],\"container_entry_read_links\":[";
    for (size_t n = 0; n < result.links.size(); ++n)
    {
	if (n)
	    out << ',';
	const auto &l = result.links[n];
	out << "{\"context\":" << l.context << ",\"contract\":" << l.contract
	    << ",\"read\":" << l.read << ",\"scope\":\"conditional_callee_entry_read\"}";
    }
    out << "],\"callee_entry_read_work\":{\"limit\":" << Limit
        << ",\"prefix_limit\":" << PrefixLimit << ",\"body_limit\":" << BodyLimit
        << ",\"byte_limit\":" << ByteLimit << ",\"contract_limit\":" << ContractLimit
        << ",\"link_limit\":" << LinkLimit << ",\"read_limit\":" << ReadLimit
        << ",\"steps\":" << result.steps << ",\"remaining\":" << result.remaining
        << ",\"bytes\":" << result.bytes << ",\"complete\":" << (result.complete ? "true" : "false")
        << '}';
}
} // namespace SnapshotAnalysis
