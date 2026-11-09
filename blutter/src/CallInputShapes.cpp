#include "CallInputShapes.h"
#include <algorithm>
#include <stdexcept>
#include <set>

namespace SnapshotAnalysis {
namespace {
bool Proof(const std::vector<uint64_t>& proof) {
	return !proof.empty() && proof.size() <= 128 && std::is_sorted(proof.begin(), proof.end()) &&
		std::adjacent_find(proof.begin(), proof.end()) == proof.end() &&
		std::none_of(proof.begin(), proof.end(), [](uint64_t p) { return !p || p % 4; });
}
}
bool ValidCallInputDescriptor(const CallInputDescriptor& d)
{
	std::set<std::string> names;
	for (const auto& [index, name] : d.named) if (!names.insert(name).second || name.find('\0') != std::string::npos) return false;
	return d.poolIndex >= 0 && d.typeArguments >= 0 && d.count >= 1 && d.count <= 32 &&
		d.size == d.count && d.positional >= 0 && d.positional <= d.count &&
		d.named.size() == static_cast<size_t>(d.count-d.positional) &&
		std::all_of(d.named.begin(), d.named.end(), [&](const auto& v) {
			return v.first >= static_cast<uint64_t>(d.positional) && v.first < static_cast<uint64_t>(d.count) &&
				!v.second.empty() && v.second.size() <= 4096;
		});
}
bool ValidCallInputModel(const CallInputModel& m)
{
	return m.entry && m.entry % 4 == 0 && m.fixed >= 1 && m.fixed <= 32 &&
		(m.implicit == 0 || m.implicit == 1) && m.implicit <= m.fixed && m.typeParameters > 0 &&
		m.declaredTypes.size() == static_cast<size_t>(m.fixed);
}
bool ValidCallInputShape(const CallInputShape& s)
{
	return s.site && s.site % 4 == 0 && s.payload && s.payload % 4 == 0 && s.site >= s.payload + 4 &&
		s.target && s.target % 4 == 0 && s.load == s.site - 4 && s.poolIndex >= 0 &&
		s.count >= 1 && s.count <= 32 && s.wordBytes == 8 && Proof(s.proof) &&
		s.proof.back() == s.site && std::binary_search(s.proof.begin(), s.proof.end(), s.load) &&
		s.proof.front() >= s.payload;
}
std::optional<CallInputShape> SelectCallInputShape(const CallInputAbi& abi,
	const CallInputModel& model, const CallInputDescriptor& descriptor, const DescriptorLoad& load,
	uint64_t site, uint64_t payload, uint64_t end, uint32_t loadWord, uint32_t callWord,
	bool callIsEntry, std::string& reason)
{
	if (!ValidCallInputModel(model)) throw std::runtime_error("Invalid retained call-input model");
	if (!descriptor.named.empty() || descriptor.positional != descriptor.count || descriptor.count != model.fixed || (descriptor.typeArguments && descriptor.typeArguments != model.typeParameters)) {
		reason = "incompatible_retained_model"; return {};
	}
	return SelectDescriptorInputShape(abi, descriptor, model.entry, load, site, payload, end, loadWord, callWord, callIsEntry, reason);
}
std::optional<CallInputShape> SelectDescriptorInputShape(const CallInputAbi& abi,
	const CallInputDescriptor& descriptor, uint64_t target, const DescriptorLoad& load,
	uint64_t site, uint64_t payload, uint64_t end, uint32_t loadWord, uint32_t callWord,
	bool callIsEntry, std::string& reason)
{
	auto reject = [&](const char* why) -> std::optional<CallInputShape> { reason = why; return {}; };
	if (!abi.supported || abi.wordBytes != 8 || abi.descriptorRegister >= 31) return reject("unsupported_sdk_abi");
	if (!ValidCallInputDescriptor(descriptor)) return reject("unsupported_descriptor_shape");
	if (!site || site % 4 || payload % 4 || payload >= end || site < payload + 4 || site >= end || load.site != site - 4)
		return reject("nonadjacent_descriptor_load");
	if (callIsEntry) return reject("descriptor_load_bypass");
	if ((callWord & 0xfc000000U) != 0x94000000U) return reject("not_direct_bl");
	const auto delta = static_cast<int64_t>(static_cast<int32_t>(callWord << 6)) >> 4;
	if ((delta < 0 && static_cast<uint64_t>(-delta) > site) ||
		(delta > 0 && site > UINT64_MAX - static_cast<uint64_t>(delta)) || site + delta != target)
		return reject("wrong_original_target");
	// Only full-width, non-writeback LDR/LDUR immediate forms. Existing pool
	// provenance supplies the base/add chain, independently checked on export.
	if ((loadWord & 0xffc00000U) != 0xf9400000U && (loadWord & 0xffe00c00U) != 0xf8400000U)
		return reject("unsupported_descriptor_load");
	if ((loadWord & 31) != abi.descriptorRegister || ((loadWord >> 5) & 31) != load.baseRegister ||
		load.width != 8 || load.baseRegister >= 31 || load.poolIndex != descriptor.poolIndex || !Proof(load.proof) ||
		load.proof.front() < payload || load.proof.back() != load.site)
		return reject("unproved_descriptor_pool_load");
	CallInputShape result{site, payload, target, load.site, descriptor.poolIndex,
		static_cast<unsigned>(descriptor.count), abi.wordBytes, load.proof};
	result.proof.push_back(site);
	if (!ValidCallInputShape(result)) throw std::runtime_error("Invalid admitted call-input shape");
	reason.clear(); return result;
}
std::optional<unsigned> SuppliedInputIndex(const CallInputShape& shape, int64_t offset)
{
	if (!ValidCallInputShape(shape)) throw std::runtime_error("Invalid supplied-input mapping");
	if (offset < 0 || offset % shape.wordBytes || offset / shape.wordBytes >= shape.count) return {};
	return shape.count - 1 - static_cast<unsigned>(offset / shape.wordBytes);
}
}
