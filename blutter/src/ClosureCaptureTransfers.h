#pragma once
#include "AsyncFieldAccesses.h"
#include "CallInputOrigins.h"
#include "CallInputRoles.h"

namespace SnapshotAnalysis
{
struct Payload;
struct Edge;
struct ClosureCaptureLayout
{
    unsigned slotBytes = 0;
    int64_t tag = 0;
    std::map<StubInputKind, int64_t> contextOffsets;
    int64_t firstLocalOffset = 0;
};
struct ClosureCaptureTransfer
{
    size_t origin;
    uint64_t call;
    int64_t poolIndex;
    ClosureEntryModel model;
    int64_t contextDisplacement, valueDisplacement, savedSlot;
    uint64_t valueRead, allocation, target, reload, store;
    uint32_t classId;
    int64_t destinationOffset;
    SavedStackMap map;
    InstanceLayout layout;
    bool discardedNoHandlers = false;
};
struct ClosureCapturesResult
{
    std::vector<ClosureCaptureTransfer> transfers;
    size_t candidates = 0, bytes = 0, remaining = 200000;
    bool complete = true;
};
ClosureCapturesResult
LinkClosureCaptures(const Profile &profile, const std::vector<CallInputOrigin> &origins,
                    const std::map<int64_t, InputObject> &objects, const std::vector<Edge> &edges,
                    const std::vector<Payload> &payloads, const std::set<uint64_t> &entries);
std::string ClosureCaptureNote(const ClosureCaptureTransfer &transfer);
std::string ClosureCallbackNote(const ClosureCaptureTransfer &transfer);
void WriteClosureCaptureLayout(std::ostream &out, const ClosureCaptureLayout &layout);
void WriteClosureCaptures(std::ostream &out, const Profile &profile,
                          const ClosureCapturesResult &result);
} // namespace SnapshotAnalysis
