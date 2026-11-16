#pragma once
#include "NativeIr.h"
#include <capstone.h>
#include <functional>
#include <string>
#include <vector>
namespace SnapshotAnalysis {
struct Profile;
struct WordOrigin {
	std::string kind;
	uint64_t site;
	std::optional<uint64_t> callee, bits;
	std::optional<NativeIr::Address> load;
	std::vector<uint64_t> proof;
};
struct WordLocation { uint16_t reg = 0; std::optional<NativeIr::Address> memory; };
struct WordOriginResult { std::string stop; std::optional<WordOrigin> source; size_t steps = 0; };
// One contiguous local fallthrough, bounded by entries, calls and ambiguous
// stores. Loads describe origins, not persistent heap contents or source types.
WordOriginResult TraceWordInput(const cs_insn* instructions, size_t count, size_t consumer,
	WordLocation location, const Profile& profile, const std::function<bool(uint64_t)>& isEntry = {},
	size_t limit = 64, bool extended = true, std::optional<uint16_t> invariantNull = {});
}
