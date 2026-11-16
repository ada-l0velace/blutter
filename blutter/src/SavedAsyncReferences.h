#pragma once
#include "AsyncFutureBindings.h"
#include <iosfwd>
#include <set>

namespace SnapshotAnalysis
{
struct SavedFrameAbi
{
    bool supported = false;
    int64_t firstLocalOffset = 0;
};
struct SavedStackMap
{
    uint64_t payload = 0, site = 0;
    bool available = false;
    uint32_t spillSlots = 0;
    std::vector<int64_t> objects;
    // Absent for spill-only contracts. The implicit tagged frame area needs the full map extent.
    std::optional<uint32_t> registerSlots;
};
struct RestoredReference
{
    uint64_t site, store, suspension;
    int64_t slot;
    unsigned reg;
};
struct SavedReferenceContext
{
    uint64_t payload, sourceAwait;
    uint32_t classId;
    std::string status = "unknown";
    size_t steps = 0;
    std::vector<RestoredReference> observations;
};
struct SavedReferenceFrame
{
    uint64_t payload;
    std::string status;
    size_t steps;
    std::vector<AsyncFramePoint> points;
};
struct SavedReferencesResult
{
    std::vector<SavedReferenceFrame> frames;
    std::vector<SavedStackMap> maps;
    std::vector<SavedReferenceContext> contexts;
    size_t steps = 0, remaining = 2000000, mapDrops = 0;
};
struct JoinedReference
{
    uint64_t site, store;
    int64_t slot;
    unsigned reg;
    // Zero means no additional suspension since the save, never unknown.
    std::set<uint64_t> lastSuspensions;
};
struct JoinedReferenceContext
{
    uint64_t payload, sourceAwait;
    uint32_t classId;
    std::string status = "unknown";
    size_t steps = 0;
    std::vector<JoinedReference> observations;
};
struct JoinedReferencesResult
{
    std::vector<JoinedReferenceContext> contexts;
    size_t steps = 0, remaining = 200000, historyOverflows = 0, bytes = 0;
    bool complete = true;
};
struct FieldBranchUsesResult;
struct DecisionReload
{
    uint64_t site, store;
    int64_t slot;
    unsigned reg;
};
struct DecisionReferenceContext
{
    size_t decision;
    uint64_t payload;
    std::string status = "unknown";
    size_t steps = 0;
    std::vector<DecisionReload> reloads;
};
struct DecisionBranchUse
{
    size_t context, reload;
    uint64_t site, trueTarget, falseTarget;
};
struct DecisionBranchesResult
{
    std::vector<DecisionReferenceContext> contexts;
    std::vector<DecisionBranchUse> uses;
    size_t steps = 0, remaining = 200000, bytes = 0;
    bool complete = true;
};
DecisionBranchesResult
RestoreDecisionBranches(const Profile &profile, const FutureBindingsResult &bindings,
                        const SavedReferencesResult &saved, const JoinedReferencesResult &joined,
                        const FieldBranchUsesResult &fields,
                        const std::map<uint64_t, std::vector<uint8_t>> &bytes,
                        const std::set<uint64_t> &externalEntries);
std::string DecisionBranchNote(const FieldBranchUsesResult &fields,
                               const DecisionBranchesResult &result, const DecisionBranchUse &use);
void WriteDecisionBranches(std::ostream &out, const Profile &profile,
                           const DecisionBranchesResult &result);
SavedReferencesResult RestoreAsyncReferences(const Profile &profile,
                                             const FutureBindingsResult &bindings,
                                             const std::vector<CompletionSummary> &summaries,
                                             const std::map<uint64_t, std::vector<uint8_t>> &bytes,
                                             const std::set<uint64_t> &externalEntries);
std::string RestoredReferenceNote(const SavedReferenceContext &context,
                                  const RestoredReference &reference,
                                  const std::function<std::string(uint32_t)> &className = {});
JoinedReferencesResult
RestoreJoinedReferences(const Profile &profile, const FutureBindingsResult &bindings,
                        const SavedReferencesResult &saved,
                        const std::map<uint64_t, std::vector<uint8_t>> &bytes,
                        const std::set<uint64_t> &externalEntries);
std::string JoinedReferenceNote(const JoinedReferenceContext &context,
                                const JoinedReference &reference);
void WriteJoinedReferences(std::ostream &out, const JoinedReferencesResult &result);
} // namespace SnapshotAnalysis
