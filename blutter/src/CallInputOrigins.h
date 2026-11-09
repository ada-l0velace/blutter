#pragma once
#include "WordOrigins.h"
#include <map>
namespace SnapshotAnalysis {
struct Profile;
struct InputObject {
	std::string kind, text;
	std::optional<uint64_t> entry;
};
struct InputOriginStep {
	std::string relation;
	WordOriginResult origin;
	std::optional<int64_t> poolIndex;
};
struct CallInputOrigin {
	uint64_t site, payload;
	std::string role;
	std::optional<unsigned> index, reg;
	std::optional<int64_t> spOffset;
	std::vector<InputOriginStep> chain;
};
using InputPoolLookup = std::function<std::optional<int64_t>(uint64_t)>;
// Read-only, fallthrough-qualified provenance. No field contents, result types,
// preserved-register effects or source parameter identity are inferred.
CallInputOrigin ObserveCallInput(const cs_insn* instructions, size_t count, size_t consumer,
	WordLocation location, CallInputOrigin result, const Profile& profile,
	const InputPoolLookup& poolAt, const std::function<bool(uint64_t)>& isEntry,
	size_t& remaining, size_t& steps);
std::string CallInputOriginNote(const CallInputOrigin& input, const std::map<int64_t, InputObject>& objects);
}
