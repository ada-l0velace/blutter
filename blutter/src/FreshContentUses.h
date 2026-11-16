#pragma once
#include "CallInputOrigins.h"
#include "CallInputShapes.h"
#include "FreshFieldInitializations.h"

namespace SnapshotAnalysis
{
struct Edge;
struct FreshContentContext
{
    size_t initialization;
    std::string status = "unknown";
    size_t steps = 0;
    std::optional<uint64_t> transfer;
    std::vector<size_t> inputs;
    // Unique original PCs in a forward, closed region; not a linear path.
    std::vector<uint64_t> proof;
};
struct FreshContentResult
{
    std::vector<FreshContentContext> contexts;
    size_t steps = 0, remaining = 200000;
    bool complete = true;
    // Transient handoff identities for separately checked consumer contracts.
    // These are not serialized as unproved call inputs.
    std::map<size_t, std::set<int64_t>> stackLocations;
};
// Selected contents at a first transfer, before the callee executes. An input
// role describes the container, never a claim that the callee reads this slot.
FreshContentResult DescribeFreshContentUses(
    const Profile &profile, const AsyncFieldsResult &fields, const CapturedFieldsResult &captures,
    const FreshFieldsResult &fresh, const std::map<uint64_t, std::vector<uint8_t>> &bytes,
    const std::set<uint64_t> &externalEntries, const std::vector<CallInputOrigin> &origins,
    const std::vector<Edge> &edges, const CallInputShapes &shapes);
std::string FreshContentNote(const AsyncFieldsResult &fields, const CapturedFieldsResult &captures,
                             const FreshFieldsResult &fresh,
                             const std::vector<CallInputOrigin> &origins,
                             const FreshContentContext &context, size_t input);
void WriteFreshContentUses(std::ostream &out, const Profile &profile,
                           const FreshContentResult &result);
} // namespace SnapshotAnalysis
