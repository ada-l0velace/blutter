#include "CallInputOrigins.h"
#include "SnapshotCodeAnalysis.h"
#include <algorithm>
#include <format>
#include <stdexcept>
namespace SnapshotAnalysis {
CallInputOrigin ObserveCallInput(const cs_insn* raw, size_t count, size_t consumer,
	WordLocation location, CallInputOrigin result, const Profile& profile,
	const InputPoolLookup& poolAt, const std::function<bool(uint64_t)>& isEntry,
	size_t& remaining, size_t& steps)
{
	std::string relation = "input";
	for (unsigned depth = 0; depth < 3; ++depth) {
		if (!remaining) { result.chain.push_back({relation, {"work_limit", {}, 0}, {}}); break; }
		auto origin = TraceWordInput(raw, count, consumer, location, profile, isEntry, std::min(remaining, size_t{64}));
		if (origin.steps > remaining) throw std::runtime_error("Input provenance exceeded its work bound");
		remaining -= origin.steps; steps += origin.steps;
		std::optional<int64_t> pool;
		if (origin.source && origin.source->kind == "load" && poolAt) pool = poolAt(origin.source->site);
		result.chain.push_back({relation, std::move(origin), pool});
		const auto& value = result.chain.back().origin.source;
		if (!value || pool || value->site < raw[0].address || (value->site-raw[0].address)%4) break;
		consumer = (value->site-raw[0].address)/4;
		if (consumer >= count) throw std::runtime_error("Input provenance source exceeds its decoded payload");
		if (value->load && value->load->base.id < 15) {
			location = {value->load->base.id, {}}; relation = "load_base"; continue;
		}
		if (value->kind == "post_call_x0" && value->callee) {
			const auto contract = profile.stubInputContracts.find(*value->callee);
			if (contract == profile.stubInputContracts.end()) break;
			const auto& inputs = contract->second.inputs;
			const auto function = std::find_if(inputs.begin(), inputs.end(), [](const auto& i) { return i.role == StubInputRole::ClosureFunction; });
			if (function == inputs.end()) break;
			location = {static_cast<uint16_t>(function->reg), {}}; relation = "closure_function"; continue;
		}
		break;
	}
	return result;
}
std::string CallInputOriginNote(const CallInputOrigin& input, const std::map<int64_t, InputObject>& objects)
{
	std::string label = input.index ? std::format("supplied input[{}]", *input.index) : input.role;
	if (input.reg) label += std::format(" (X{})", *input.reg);
	std::string text = std::format("input origin: {}", label);
	for (const auto& step : input.chain) {
		if (step.relation == "closure_function") text += "; closure Function";
		else if (step.relation == "load_base") text += "; loaded from base";
		const auto& value = step.origin.source;
		if (!value) { text += " <- unproved (" + step.origin.stop + ")"; break; }
		if (step.poolIndex && objects.contains(*step.poolIndex)) {
			const auto& object = objects.at(*step.poolIndex);
			text += std::format(" <- pool[{}] {}", *step.poolIndex, object.kind);
			if (object.entry) text += std::format(" entry {:#x}", *object.entry);
			if (!object.text.empty()) {
				text += " \"";
				for (size_t n = 0; n < std::min(object.text.size(), size_t{96}); ++n) {
					const auto c = static_cast<unsigned char>(object.text[n]);
					if (c < 32 || c >= 127) text += std::format("\\x{:02x}", c);
					else { if (c == '\\' || c == '"') text += '\\'; text += static_cast<char>(c); }
				}
				if (object.text.size() > 96) text += "...";
				text += '"';
			}
		} else if (step.poolIndex) text += std::format(" <- pool[{}]", *step.poolIndex);
		else if (value->kind == "post_call_x0" || value->kind == "await_delivery") {
			text += value->kind == "await_delivery" ? " <- successful await delivery" : " <- post-call X0";
			if (value->callee) text += std::format(" from {:#x}", *value->callee);
		} else if (value->load) text += std::format(" <- {} [X{}{:+}] @{:#x}", value->kind, value->load->base.id, value->load->displacement, value->site);
		else if (value->kind == "entry_register") text += std::format(" <- entry X{}", value->bits.value_or(0));
		else if (value->bits) text += std::format(" <- raw word {:#x}", *value->bits);
		else text += " <- " + value->kind;
	}
	return text + " [normal fallthrough; partial provenance]";
}
}
