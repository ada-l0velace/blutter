#pragma once
#include "CapturedFieldValues.h"
#include "WordOrigins.h"

namespace SnapshotAnalysis
{
struct FreshFieldWrite {
	uint64_t site;
	unsigned base, reg, bytes;
	int64_t offset;
	std::optional<uint64_t> index;
};
struct FreshFieldContext {
	size_t capture, reload;
	uint32_t classId = 0;
	std::string kind = "unknown", status = "unknown";
	size_t steps = 0, lengthSteps = 0;
	std::optional<uint64_t> length;
	std::optional<WordOrigin> lengthSource;
	std::optional<FreshFieldWrite> write;
};
struct FreshFieldsResult {
	std::map<uint32_t, InstanceLayout> layouts;
	std::vector<FreshFieldContext> contexts;
	size_t steps = 0, remaining = 200000;
	bool complete = true;
};
// A first write event before escape, never a persistent heap-content or type fact.
FreshFieldsResult DescribeFreshFieldWrites(const Profile &profile, const AsyncFieldsResult &fields,
                                           const CapturedFieldsResult &captures,
                                           const std::map<uint64_t, std::vector<uint8_t>> &bytes,
                                           const std::set<uint64_t> &entries);
std::string FreshFieldNote(const AsyncFieldsResult &fields, const CapturedFieldsResult &captures,
                           const FreshFieldContext &context);
void WriteFreshFields(std::ostream &out, const FreshFieldsResult &result);
} // namespace SnapshotAnalysis
