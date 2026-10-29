#pragma once
#include "SnapshotCodeAnalysis.h"

namespace SnapshotAnalysis {
struct CallEffectResult {
	std::map<uint64_t, std::string> certificates;
	size_t attempted = 0, steps = 0;
};
// Prove caller-frame/class preservation, not purity or return values. Only
// writes inside its active frame or proved allocation body, and reviewed calls,
// qualify. Heap bounds never describe field contents or object identity.
CallEffectResult AnalyzeCallEffects(const std::map<uint64_t, std::vector<uint8_t>>& bytes,
	const Profile& profile);
}
