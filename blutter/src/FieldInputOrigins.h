#pragma once
#include "AsyncFieldAccesses.h"
#include "CallInputOrigins.h"
#include "CallInputShapes.h"

namespace SnapshotAnalysis
{
struct Edge;
bool IsRoleProvenCallInput(const CallInputOrigin &input, const Profile &profile, const Edge &edge,
                          const CallInputShapes &shapes);
struct FieldInputLink {
	size_t context, access, origin;
	bool operator==(const FieldInputLink &) const = default;
};
struct FieldInputLinksResult {
	std::vector<FieldInputLink> links;
	size_t originsExamined = 0, candidates = 0, remaining = 200000;
	bool complete = true;
};
// A value read from an object's storage, not the object or its declared type.
// Only the direct input source qualifies; a load-base source is a different value.
FieldInputLinksResult LinkFieldInputs(const AsyncFieldsResult &fields,
                                      const std::vector<CallInputOrigin> &origins, const Profile &profile,
                                      const std::vector<Edge> &edges, const CallInputShapes &shapes);
std::string FieldInputNote(const AsyncFieldsResult &fields, const std::vector<CallInputOrigin> &origins,
                           const FieldInputLink &link,
                           const std::function<std::string(uint32_t)> &className = {});
void WriteFieldInputs(std::ostream &out, const FieldInputLinksResult &result);
} // namespace SnapshotAnalysis
