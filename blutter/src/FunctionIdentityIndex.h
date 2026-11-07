#pragma once
#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <unordered_map>
#include <vector>

// Source metadata identity and machine entry address are different keys.
// Class models own these records; this index only borrows their pointers.
template <typename Function>
class FunctionIdentityIndex {
public:
	Function* Find(uintptr_t identity) const {
		const auto found = records.find(identity);
		return found == records.end() ? nullptr : found->second;
	}

	bool Remember(uintptr_t identity, Function* function) {
		if (!identity || !function) throw std::invalid_argument("Invalid Function metadata record");
		const auto [found, inserted] = records.try_emplace(identity, function);
		if (!inserted && found->second != function)
			throw std::logic_error("Function metadata identity has conflicting models");
		if (inserted) models.push_back(function);
		return inserted;
	}

	void Forget(uintptr_t identity, Function* function) {
		const auto found = records.find(identity);
		if (found == records.end()) return;
		if (found->second != function) throw std::logic_error("Removing a different Function metadata record");
		records.erase(found);
		std::erase(models, function);
	}

	const std::vector<Function*>& Models() const { return models; }

private:
	std::unordered_map<uintptr_t, Function*> records;
	std::vector<Function*> models;
};
