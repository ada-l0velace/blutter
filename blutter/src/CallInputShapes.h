#pragma once
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace SnapshotAnalysis {
// ABI capability comes from reviewed compiler source, not a snapshot/version label.
struct CallInputAbi {
	bool supported = false;
	unsigned descriptorRegister = 0, wordBytes = 0;
	std::string reason = "unverified_sdk_policy";
};
struct CallInputDescriptor {
	int64_t poolIndex, typeArguments, count, size, positional;
	std::map<unsigned, std::string> named;
	bool operator==(const CallInputDescriptor&) const = default;
};
struct CallInputModel {
	uint64_t entry;
	int64_t fixed, implicit, typeParameters;
	std::string name;
	std::vector<std::string> declaredTypes;
	// Compatible retained metadata only; never original source identity proof.
};
struct CallInputShape {
	uint64_t site, payload, target, load;
	int64_t poolIndex;
	unsigned count, wordBytes;
	std::vector<uint64_t> proof;
	bool descriptorPrologue = false;
};
using CallInputShapes = std::map<uint64_t, CallInputShape>;
struct DescriptorLoad {
	uint64_t site;
	int64_t poolIndex, offset;
	unsigned width, baseRegister;
	std::vector<uint64_t> proof;
};
bool ValidCallInputDescriptor(const CallInputDescriptor& descriptor);
bool ValidCallInputModel(const CallInputModel& model);
bool ValidCallInputShape(const CallInputShape& shape);
// No value inference or effect/preservation contract is granted by this shape.
std::optional<CallInputShape> SelectCallInputShape(const CallInputAbi& abi,
	const CallInputModel& model, const CallInputDescriptor& descriptor,
	const DescriptorLoad& load, uint64_t site, uint64_t payload, uint64_t end,
	uint32_t loadWord, uint32_t callWord, bool callIsEntry, std::string& reason);
std::optional<CallInputShape> SelectDescriptorInputShape(const CallInputAbi& abi,
	const CallInputDescriptor& descriptor, uint64_t target, const DescriptorLoad& load,
	uint64_t site, uint64_t payload, uint64_t end, uint32_t loadWord, uint32_t callWord,
	bool callIsEntry, std::string& reason);
std::optional<unsigned> SuppliedInputIndex(const CallInputShape& shape, int64_t spOffset);
}
