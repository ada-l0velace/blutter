#pragma once
#include <cstdint>
#include <format>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace SnapshotAnalysis {
enum class AsyncOperation { Unknown, Init, Await, AwaitWithTypeCheck, CompleteValue, CompleteValueOrFuture, Resume };
struct AsyncStubIdentity {
	uint64_t entry, payload, end;
	AsyncOperation operation;
	bool matchesReference = false;
};
struct AsyncContract {
	AsyncOperation operation;
	uint64_t end;
	bool operator==(const AsyncContract&) const = default;
};
inline const char* AsyncOperationName(AsyncOperation operation)
{
	switch (operation) {
	case AsyncOperation::Init: return "init_async";
	case AsyncOperation::Await: return "await";
	case AsyncOperation::AwaitWithTypeCheck: return "await_with_type_check";
	case AsyncOperation::CompleteValue: return "complete_value";
	case AsyncOperation::CompleteValueOrFuture: return "complete_value_or_future";
	case AsyncOperation::Resume: return "resume";
	default: return "unknown";
	}
}
// Identity is supplied by the matched runtime adapter. Complete code equality
// admits legacy isolate copies. Neither names nor nearby addresses select it.
inline std::map<uint64_t, AsyncContract> SelectAsyncContracts(
	const std::vector<AsyncStubIdentity>& identities,
	const std::map<uint64_t, uint64_t>& payloads, bool supportedAbi)
{
	std::map<uint64_t, std::optional<AsyncContract>> groups;
	for (const auto& id : identities) {
		std::optional<AsyncContract> value;
		if (supportedAbi && std::string_view(AsyncOperationName(id.operation)) != "unknown" && id.matchesReference &&
			id.entry && id.entry % 4 == 0 && id.entry == id.payload && id.end > id.entry && id.end % 4 == 0 &&
			id.end - id.entry <= (1U << 20) && payloads.contains(id.entry) && payloads.at(id.entry) == id.end)
			value = AsyncContract{id.operation, id.end};
		const auto [it, inserted] = groups.emplace(id.entry, value);
		if (!inserted && it->second != value) it->second.reset();
	}
	std::map<uint64_t, AsyncContract> result;
	for (const auto& [entry, value] : groups) if (value) result.emplace(entry, *value);
	return result;
}
struct AsyncBoundary {
	AsyncOperation operation;
	uint64_t site, payload, callee;
	std::optional<uint64_t> resumeSite;
};
// Describes a physical boundary only. This grants no class, field, producer,
// heap-preservation or caller-frame-preservation facts to another analysis.
inline std::optional<AsyncBoundary> DescribeAsyncBoundary(std::string_view transfer,
	uint64_t site, uint64_t start, uint64_t end, uint64_t callee,
	const std::map<uint64_t, AsyncContract>& contracts)
{
	if (site % 4 || start % 4 || end % 4 || start > site || site >= end || end - site < 4) return {};
	const auto found = contracts.find(callee);
	if (found == contracts.end()) return {};
	const auto operation = found->second.operation;
	const bool complete = operation == AsyncOperation::CompleteValue || operation == AsyncOperation::CompleteValueOrFuture;
	const bool await = operation == AsyncOperation::Await || operation == AsyncOperation::AwaitWithTypeCheck;
	if (complete ? transfer != "jump" : transfer != "call" || (!await && operation != AsyncOperation::Init)) return {};
	return AsyncBoundary{operation, site, start, callee, await && end - site > 4 ? std::optional<uint64_t>{site + 4} : std::nullopt};
}
inline std::string AsyncBoundaryNote(const AsyncBoundary& boundary)
{
	switch (boundary.operation) {
	case AsyncOperation::Init:
		return "async init: X0 type arguments; initializes function data [matched SDK boundary]";
	case AsyncOperation::Await:
	case AsyncOperation::AwaitWithTypeCheck: {
		const auto resume = boundary.resumeSite ? std::format("{:#x}", *boundary.resumeSite) : "outside this payload";
		return std::format("async {}: input X0{}; successful resume {} delivers X0; delivered value origin unknown; exception path separate [matched SDK boundary]",
			boundary.operation == AsyncOperation::Await ? "await" : "await with type check",
			boundary.operation == AsyncOperation::Await ? "" : ", type arguments X1", resume);
	}
	case AsyncOperation::CompleteValue:
		return "async completion: X0 supplies a non-Future value; machine return is the Future [matched SDK boundary]";
	case AsyncOperation::CompleteValueOrFuture:
		return "async completion: X0 supplies a value or a Future to chain; machine return is the Future [matched SDK boundary]";
	default: return {};
	}
}
}
