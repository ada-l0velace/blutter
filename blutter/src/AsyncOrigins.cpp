#include "AsyncOrigins.h"
#include "SnapshotCodeAnalysis.h"
#include "Arm64Ir.h"
#include <algorithm>
#include <limits>
#include <iterator>

namespace SnapshotAnalysis {
namespace {
bool Valid(const cs_insn& i) { return i.detail && i.size == 4 && i.detail->groups_count <= std::size(i.detail->groups) && i.detail->arm64.op_count <= std::size(i.detail->arm64.operands); }
}

AsyncInput TraceAsyncInput(const cs_insn* raw, size_t count, size_t consumer,
	const AsyncBoundary& boundary, const Profile& profile,
	const std::function<bool(uint64_t)>& isEntry, size_t limit)
{
	const bool await = boundary.operation == AsyncOperation::Await || boundary.operation == AsyncOperation::AwaitWithTypeCheck;
	AsyncInput result{boundary.site, boundary.payload, await ? "await_input" : "completion_operand", "unknown", {}};
	if (!raw || consumer >= count || !Valid(raw[consumer]) || raw[consumer].address != boundary.site || raw[0].address != boundary.payload ||
		profile.wordReturnRegister != ARM64_REG_X0 || (!await && boundary.operation != AsyncOperation::CompleteValue && boundary.operation != AsyncOperation::CompleteValueOrFuture)) {
		result.stop = "unsupported_input"; return result;
	}
	const auto& instruction = raw[consumer];
	const auto& detail = instruction.detail->arm64;
	const bool call = instruction.id == ARM64_INS_BL;
	const bool tail = instruction.id == ARM64_INS_B && (detail.cc == ARM64_CC_INVALID || detail.cc == ARM64_CC_AL);
	if ((!call && !tail) || detail.op_count != 1 || detail.operands[0].type != ARM64_OP_IMM ||
		static_cast<uint64_t>(detail.operands[0].imm) != boundary.callee || !profile.asyncContracts.contains(boundary.callee) ||
		profile.asyncContracts.at(boundary.callee).operation != boundary.operation || call != await) {
		result.stop = "unsupported_input"; return result;
	}
	const auto traced = TraceWordInput(raw, count, consumer, {0, {}}, profile, isEntry, limit, false);
	result.source = traced.source; result.stop = traced.stop; result.steps = traced.steps;
	return result;
}

std::string AsyncInputNote(const AsyncInput& input) {
	const auto prefix = input.role == "await_input" ? "async input" : "async completion operand";
	if (!input.source) return std::format("{}: origin unproved ({})", prefix, input.stop);
	const auto& value = *input.source;
	const auto kind = value.kind == "post_call_x0" ? "post-call X0" : value.kind == "await_delivery" ? "successful await delivery" : value.kind.c_str();
	const auto target = value.callee ? std::format("; callee {:#x}", *value.callee) : "";
	const auto detail = value.kind == "load" ? std::format("; content origin unproved ({})", input.stop) :
		value.bits ? std::format("; word {:#x}", *value.bits) : std::string{};
	return std::format("{}: X0 <- {} @{:#x}{}{} [normal fallthrough; no delivered-type claim]", prefix, kind, value.site, target, detail);
}
}
