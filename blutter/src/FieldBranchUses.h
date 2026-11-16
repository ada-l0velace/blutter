#pragma once
#include "AsyncFieldAccesses.h"

namespace SnapshotAnalysis
{
struct FieldBranchUse
{
    size_t context, reference;
    uint64_t site, setTarget, clearTarget;
    int64_t offset;
    unsigned bit;
};
struct FieldDecisionAbi
{
    bool supported = false;
    int64_t trueOffset = 0, falseOffset = 0;
};
struct FieldDecision
{
    size_t branchUse;
    uint64_t load, site;
    int64_t offset, fpOffset;
    unsigned reg;
    bool onSet, nonNullTrue;
};
struct FieldBranchUsesResult
{
    std::vector<FieldBranchUse> uses;
    std::vector<FieldDecision> decisions;
    size_t candidates = 0, bytes = 0;
};
FieldBranchUsesResult DescribeFieldBranches(const Profile &profile,
                                            const JoinedReferencesResult &joined,
                                            const AsyncFieldsResult &fields,
                                            const std::map<uint64_t, std::vector<uint8_t>> &bytes,
                                            const std::set<uint64_t> &entries);
std::string FieldBranchNote(const JoinedReferencesResult &joined, const FieldBranchUse &use);
std::optional<FieldDecision>
AnalyzeFieldDecision(const cs_insn *raw, size_t count, const Profile &profile,
                     const JoinedReference &reference, const InstanceLayout &layout,
                     size_t branchUse, const FieldBranchUse &use,
                     const std::set<uint64_t> &externalEntries,
                     const std::map<uint64_t, std::set<uint64_t>> &incoming);
std::string FieldDecisionNote(const JoinedReferencesResult &joined,
                              const FieldBranchUsesResult &result, const FieldDecision &decision);
void WriteFieldDecisions(std::ostream &out, const Profile &profile,
                         const FieldBranchUsesResult &result);
void WriteFieldBranches(std::ostream &out, const FieldBranchUsesResult &result);
} // namespace SnapshotAnalysis
