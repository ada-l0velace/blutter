#pragma once
#include "SnapshotCodeAnalysis.h"

namespace SnapshotAnalysis {
struct CallEffectResult {
	std::map<uint64_t, std::string> certificates;
	std::map<uint64_t, int64_t> forwardedInputs;
	size_t attempted = 0, steps = 0;
};
// Prove caller-frame/class preservation. A call-free body can additionally
// prove a full-word result alias of an entry-stack input, not a source type. Only
// writes inside its active frame or proved allocation body, and reviewed calls,
// qualify. Heap bounds never describe field contents or object identity.
CallEffectResult AnalyzeCallEffects(const std::map<uint64_t, std::vector<uint8_t>>& bytes,
	const Profile& profile);
}
