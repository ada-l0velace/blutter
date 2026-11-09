#pragma once
#include "AsyncContracts.h"
#include "NativeIr.h"
#include "WordOrigins.h"
#include <capstone.h>
#include <functional>

namespace SnapshotAnalysis {
struct Profile;
using AsyncValueSource = WordOrigin;
struct AsyncInput {
	uint64_t site, payload;
	std::string role, stop;
	std::optional<AsyncValueSource> source;
	size_t steps = 0;
};
// Conditional local word provenance. No delivered type, Future identity,
// heap contents, call effects or all-path source signature is inferred.
AsyncInput TraceAsyncInput(const cs_insn* instructions, size_t count, size_t consumer,
	const AsyncBoundary& boundary, const Profile& profile,
	const std::function<bool(uint64_t)>& isEntry = {}, size_t limit = 64);
std::string AsyncInputNote(const AsyncInput& input);
}
