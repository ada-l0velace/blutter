#pragma once
#include "AsyncFieldAccesses.h"

namespace SnapshotAnalysis
{
struct CapturedFieldReload {
	uint64_t site, store, call, target;
	int64_t slot;
	unsigned reg;
};
struct CapturedFieldContext {
	size_t context, access;
	std::string status = "unknown";
	size_t steps = 0;
	std::vector<CapturedFieldReload> reloads;
};
struct CapturedFieldsResult {
	std::vector<CapturedFieldContext> contexts;
	std::vector<SavedStackMap> maps;
	size_t steps = 0, remaining = 200000;
	bool complete = true;
};
// Preserve a captured Dart value, not unchanged pointer bits or current field contents.
// The existing whole-frame certificate and a tagged GC spill slot are mandatory.
CapturedFieldsResult PreserveCapturedFields(const Profile &profile, const AsyncFieldsResult &fields,
                                            const SavedReferencesResult &saved,
                                            const std::map<uint64_t, std::vector<uint8_t>> &bytes,
                                            const std::set<uint64_t> &entries);
std::string CapturedFieldNote(const AsyncFieldsResult &fields, const CapturedFieldContext &context,
                              const CapturedFieldReload &reload);
void WriteCapturedFields(std::ostream &out, const CapturedFieldsResult &result);
} // namespace SnapshotAnalysis
