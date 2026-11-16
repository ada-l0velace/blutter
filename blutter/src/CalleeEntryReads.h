#pragma once
#include "FreshContentUses.h"
#include "StackCheckAnalysis.h"

namespace SnapshotAnalysis
{
struct Payload;
struct CalleeEntryRead
{
    uint64_t site;
    int64_t offset;
    unsigned reg, part;
};
struct CalleeEntryContract
{
    uint64_t entry, end;
    std::string stop = "unknown";
    size_t steps = 0, decoded = 0;
    std::vector<uint64_t> prefix;
    std::vector<CalleeEntryRead> reads;
    std::optional<InitialStackCheck> guard;
};
struct ContainerEntryLink
{
    size_t context, contract, read;
};
struct CalleeEntryResult
{
    std::vector<CalleeEntryContract> contracts;
    std::vector<ContainerEntryLink> links;
    size_t steps = 0, remaining = 200000, bytes = 0;
    bool complete = true;
};
// A checked use of a caller-entry stack word, not an argument ordinal or a
// recovered source signature. Runtime calls are excluded by the fast guard.
CalleeEntryContract ProveCalleeEntryReads(uint64_t entry, const std::vector<uint8_t> &code,
                                          const Profile &profile, size_t &remaining,
                                          const CallInputAbi *entryAbi = nullptr);
CalleeEntryResult LinkContainerEntryReads(const Profile &profile,
                                          const FreshContentResult &contents,
                                          const std::vector<Payload> &payloads,
                                          const std::vector<Edge> &edges);
std::string ContainerEntryReadNote(const AsyncFieldsResult &fields,
                                   const CapturedFieldsResult &captures,
                                   const FreshFieldsResult &fresh,
                                   const FreshContentResult &contents,
                                   const CalleeEntryResult &result, const ContainerEntryLink &link);
void WriteCalleeEntryReads(std::ostream &out, const CalleeEntryResult &result);
} // namespace SnapshotAnalysis
