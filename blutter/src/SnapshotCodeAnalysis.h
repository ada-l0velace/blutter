#pragma once
#include <capstone.h>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

// ARM64 instruction facts. This module has no Dart VM or vendor dependencies.
namespace SnapshotAnalysis {
struct Name {
	uint64_t address;
	std::string text;
	std::string kind;
};
struct Payload {
	uint64_t start;
	uint64_t end;
	std::vector<Name> names;
	std::string label;
	bool decoded = false;
};
struct PoolSlot {
	std::string kind;
	std::string description;
	// Tagged-pointer field displacement -> original ELF VA. Snapshot metadata,
	// not a promise that the runtime has not patched this entry.
	std::map<int64_t, uint64_t> entryPoints;
};
struct Profile {
	std::string name;
	arm64_reg poolRegister;
	arm64_reg threadRegister;
	int64_t poolDataOffset;
	int64_t poolSlotSize;
	int64_t poolLength;
	std::map<int64_t, std::string> threadFields;
	std::function<PoolSlot(int64_t)> describePoolSlot;
	arm64_reg dispatchRegister = ARM64_REG_INVALID;
	int64_t dispatchOrigin = 0;
	std::vector<std::optional<uint64_t>> dispatchEntries;
	std::optional<uint64_t> dispatchSnapshotAddress;
	uint64_t dispatchSnapshotSize = 0;
	std::optional<uint64_t> dispatchNullTarget;
	unsigned classIdShift = 0;
	unsigned classIdBits = 0; // Zero disables receiver inference for an unconfigured ABI.
	int64_t headerDisplacement = -1;
	arm64_reg nullRegister = ARM64_REG_INVALID;
	uint32_t nullClassId = 0;
	arm64_reg allocationResultRegister = ARM64_REG_X0;
	std::map<uint64_t, uint32_t> allocationReturns;
	std::function<std::optional<uint32_t>(int64_t)> poolHeapClass;
};
struct Reference {
	uint64_t site;
	uint64_t payload;
	std::string kind;
	std::string access;
	int64_t offset;
	unsigned width;
	std::string baseRegister;
	std::optional<int64_t> poolIndex;
	std::string fieldName;
	std::vector<uint64_t> proof;
};
struct RegisterConstant {
	std::string reg;
	uint64_t bits;
	std::vector<uint64_t> proof;
};
struct IndexExpression {
	uint64_t site;
	std::string sourceRegister;
	unsigned lsb;
	unsigned width;
	int64_t addend;
	std::vector<uint64_t> proof;
};
struct DispatchAccess {
	std::optional<int64_t> index;
	std::optional<int64_t> tableIndex;
	std::optional<IndexExpression> expression;
	std::vector<uint64_t> proof;
	std::string resolution = "unknown_index";
};
struct StaticDispatch {
	uint64_t load;
	int64_t index;
	uint64_t tableIndex;
	uint64_t snapshotTarget;
	std::vector<uint64_t> proof;
};
struct Edge {
	uint64_t site;
	uint64_t source;
	std::string kind;
	std::optional<uint64_t> target;
	std::optional<uint64_t> targetPayload;
	std::string targetLabel;
	std::string targetRegister;
	std::string viaKind;
	std::optional<int64_t> viaOffset;
	std::vector<uint64_t> proof;
	std::optional<int64_t> viaFieldOffset;
	std::string indexRegister;
	std::optional<uint64_t> snapshotTarget;
	std::vector<RegisterConstant> registerConstants;
	std::optional<DispatchAccess> dispatch;
	// A separate normal-flow CFG inference; original local facts stay unchanged.
	std::optional<StaticDispatch> staticDispatch;
};

class Analyzer {
public:
	Analyzer(Profile profile, std::vector<Payload> payloads, std::vector<Name> names);
	// Register all direct destinations before analysis, including destinations
	// reached from another payload. Their incoming aliases are not assumed.
	void RegisterEntries(const cs_insn* instructions, size_t count);
	std::map<uint64_t, std::string> Analyze(const cs_insn* instructions, size_t count, uint64_t payloadStart);
	void Write(const std::string& filename) const;
	const std::vector<Reference>& References() const { return references; }
	const std::vector<Edge>& Edges() const { return edges; }
private:
	std::optional<size_t> FindPayload(uint64_t address) const;
	Profile profile;
	std::vector<Payload> payloads;
	std::map<int64_t, PoolSlot> poolSlots;
	std::vector<Reference> references;
	std::vector<Edge> edges;
	std::set<uint64_t> entries;
	std::set<uint64_t> receiverEntries;
	std::vector<std::string> receiverCertificates;
	std::map<int64_t, uint32_t> receiverPoolClasses;
};
}
