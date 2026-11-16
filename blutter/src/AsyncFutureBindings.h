#pragma once
#include "CompletionAnalysis.h"
#include <functional>

namespace SnapshotAnalysis {
struct Profile;
struct FutureBindingAbi {
	bool supported = false;
	int64_t suspendStateOffset = 0;
};
struct AwaitFutureInput {
	AsyncBoundary boundary;
	CompletionBody body;
	WordOriginResult origin;
	std::string status;
};
struct FutureBoundary {
	uint64_t site;
	std::string operation;
};
struct FutureForward {
	uint64_t completion, call, producer;
};
struct FutureProducer {
	uint64_t entry = 0, payload = 0, end = 0;
	std::string status = "unknown", valueStatus = "unknown";
	std::optional<uint32_t> classId;
	bool nullValue = false;
	std::vector<uint64_t> beforeInit, afterInit, traps;
	std::vector<FutureBoundary> boundaries;
	std::vector<FutureForward> forwards;
	size_t steps = 0;
};
struct AwaitFutureBinding {
	AwaitFutureInput input;
	std::optional<uint64_t> call, producer, producerPayload;
	std::string status = "unknown", value = "unknown";
	std::optional<uint32_t> classId;
};
struct AsyncFramePoint {
	uint64_t site;
	int64_t spUpper;
	bool spExact;
};
struct AsyncReferenceFrame {
	FutureProducer protocol;
	std::vector<AsyncFramePoint> points;
};
struct FutureBindingsResult {
	std::vector<FutureProducer> producers;
	std::vector<AwaitFutureBinding> bindings;
	size_t remaining = 0, steps = 0;
};
// No heap-field contents or references saved across suspension are followed.
AwaitFutureInput ObserveAwaitFuture(const cs_insn* raw, size_t count, size_t consumer,
	const AsyncBoundary& boundary, const Profile& profile, const CompletionBody& body,
	const std::function<bool(uint64_t)>& entryBoundary, size_t& remaining);
FutureProducer CheckFutureProducer(const cs_insn* raw, size_t count, uint64_t entry,
	const Profile& profile, const CompletionSummary& summary, const CompletionBody& body,
	size_t& remaining);
FutureBindingsResult BindAwaitFutures(const Profile& profile,
	const std::vector<CompletionSummary>& summaries, const std::vector<AwaitFutureInput>& inputs,
	const std::map<uint64_t, std::vector<uint8_t>>& bytes, size_t remaining);
AsyncReferenceFrame CheckAsyncReferenceFrame(const cs_insn* raw, size_t count,
	const Profile& profile, const CompletionSummary& summary, const CompletionBody& body,
	const std::set<uint64_t>& externalEntries, size_t& remaining);
std::string AwaitFutureBindingNote(const AwaitFutureBinding& binding,
	const std::function<std::string(uint32_t)>& className = {});
}
