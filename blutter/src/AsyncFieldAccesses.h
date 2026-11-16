#pragma once
#include "SavedAsyncReferences.h"
#include <iosfwd>

namespace SnapshotAnalysis
{
// Retained declarations describe storage, not the value currently in a field.
struct InstanceField {
	int64_t offset;
	uint32_t owner;
	std::string name, declaredType;
};
struct InstanceLayout {
	uint32_t classId = 0;
	std::string kind = "unsupported";
	int64_t header = 0, end = 0, tag = 0, contextParent = 0, contextData = 0;
	unsigned slotBytes = 0;
	std::vector<int64_t> excluded, unboxed;
	std::vector<InstanceField> fields;
};
struct AsyncFieldAccess {
	uint64_t site;
	unsigned base, reg, bytes;
	int64_t offset;
	std::string access, kind;
	std::optional<int64_t> index;
};
struct AsyncFieldContext {
	uint64_t payload, sourceAwait, seed;
	unsigned reg;
	uint32_t classId;
	std::string basis, status = "unknown";
	size_t steps = 0;
	std::vector<AsyncFieldAccess> accesses;
};
struct AsyncFieldsResult {
	bool supported = false;
	std::map<uint32_t, InstanceLayout> layouts;
	std::vector<AsyncFieldContext> contexts;
	size_t steps = 0, remaining = 200000;
};
void ValidateInstanceLayout(const InstanceLayout &layout);
void WriteInstanceLayout(std::ostream &out, const InstanceLayout &layout);
void AnalyzeFieldAccesses(const cs_insn *instructions, size_t count, const InstanceLayout &layout,
                          const std::set<uint64_t> &entries, AsyncFieldContext &context, size_t &remaining);
AsyncFieldsResult DescribeAsyncFields(const Profile &profile, const FutureBindingsResult &bindings,
                                      const SavedReferencesResult &saved,
                                      const std::map<uint64_t, std::vector<uint8_t>> &bytes,
                                      const std::set<uint64_t> &entries);
std::string AsyncFieldAccessNote(const AsyncFieldContext &context, const AsyncFieldAccess &access,
                                 const InstanceLayout &layout,
                                 const std::function<std::string(uint32_t)> &className = {});
void WriteAsyncFields(std::ostream &out, const AsyncFieldsResult &result);
} // namespace SnapshotAnalysis
