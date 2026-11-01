#include "CallResultAnnotations.h"
#include "CallResultContexts.h"
#include <algorithm>
#include <format>
#include <limits>
#include <stdexcept>

namespace SnapshotAnalysis {
namespace {
std::string QuotedName(const std::string& name)
{
	std::string text = "\"";
	for (const unsigned char c : name) {
		if (c == '"' || c == '\\') { text += '\\'; text += c; }
		else if (c < 32 || c == 127) text += std::format("\\x{:02x}", c);
		else text += c;
	}
	return text + '"';
}
}
AssemblyNotes BuildCallResultNotes(const CallResultContextResult& result, const std::vector<Edge>& edges,
	const std::function<std::string(uint32_t)>& className)
{
	AssemblyNotes notes;
	std::map<uint64_t, const Edge*> calls;
	for (const auto& edge : edges) calls.emplace(edge.site, &edge);
	std::map<uint32_t, std::string> names;
	auto type = [&](uint32_t cid) -> const std::string& {
		if (!cid) throw std::runtime_error("Invalid caller-result class annotation");
		if (!names.contains(cid)) {
			auto text = std::format("class {:#x}", cid);
			if (className) { const auto name = className(cid); if (!name.empty()) text += " (" + QuotedName(name) + ")"; }
			names.emplace(cid, std::move(text));
		}
		return names.at(cid);
	};
	for (const auto& context : result.contexts) {
		auto add = [&](uint64_t site, const std::string& text) {
			notes[site].push_back(std::format("caller-result @{:#x} [payload {:#x}]: {}", site, context.payload, text));
		};
		auto call = [&](uint64_t site) -> const Edge& {
			const auto found = calls.find(site);
			if (found == calls.end() || found->second->source != context.payload ||
				(found->second->kind != "call" && found->second->kind != "indirect_call"))
				throw std::runtime_error("Caller-result annotation has no matching original call");
			return *found->second;
		};
		for (const auto& binding : context.bindings) {
			const auto& edge = call(binding.site);
			if (edge.kind != "call" || edge.target != binding.callee)
				throw std::runtime_error("Caller-result annotation does not match its original callee");
			add(binding.site, std::format("normal-return X0 -> {} [{}]", type(binding.classId),
				binding.conditional ? "caller-bound helper" : "callee summary"));
		}
		for (const auto& [site, values] : context.analysis.stackInputs) {
			const auto& edge = call(site);
			for (const auto& value : values) {
				if (std::ranges::any_of(edge.stackInputs, [&](const auto& old) {
					return old.spOffset == value.spOffset && old.kind == value.kind && old.value == value.value;
				})) continue;
				if (value.kind != "heap_class" && value.kind != "word") throw std::runtime_error("Unknown caller-result stack annotation kind");
				if (value.kind == "heap_class" && value.value > std::numeric_limits<uint32_t>::max())
					throw std::runtime_error("Caller-result class annotation exceeds the class ID width");
				add(site, std::format("stack Dart SP{:+d} -> {} [partial]", value.spOffset,
					value.kind == "heap_class" ? type(static_cast<uint32_t>(value.value)) : std::format("word {:#x}", value.value)));
			}
		}
		for (const auto& [site, arrays] : context.analysis.arrayArguments) {
			const auto& edge = call(site);
			for (const auto& array : arrays) {
				const auto old = std::ranges::find_if(edge.arrayArguments, [&](const auto& item) {
					return item.spOffset == array.spOffset && item.allocation == array.allocation;
				});
				for (const auto& [index, cid] : array.elements) {
					if (old != edge.arrayArguments.end() && old->elements.contains(index) && old->elements.at(index) == cid) continue;
					add(site, std::format("array Dart SP{:+d}, allocation {:#x}, length {}, element[{}] -> {} [partial]",
						array.spOffset, array.allocation, array.length, index, type(cid)));
				}
			}
		}
		for (const auto& [site, resolution] : context.analysis.resolutions) {
			const auto edge = calls.find(site);
			if (edge == calls.end() || edge->second->source != context.payload ||
				(edge->second->kind != "indirect_call" && edge->second->kind != "indirect_jump"))
				throw std::runtime_error("Caller-result dispatch annotation has no matching indirect transfer");
			add(site, std::format("snapshot dispatch -> {:#x}", resolution.snapshotTarget));
		}
		for (const auto& [site, value] : context.analysis.returnClasses)
			add(site, "physical X0 at RET -> " + type(value.classId));
	}
	return notes;
}
}
