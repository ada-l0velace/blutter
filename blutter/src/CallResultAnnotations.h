#pragma once
#include "SnapshotCodeAnalysis.h"

namespace SnapshotAnalysis {
struct CallResultContextResult;
struct RegisterContextResult;
using AssemblyNotes = std::map<uint64_t, std::vector<std::string>>;
// Read-only presentation of checked facts at original instruction addresses.
// Class names are optional metadata, never evidence for the class itself.
AssemblyNotes BuildCallInputNotes(const std::vector<Edge>& edges,
	const std::function<std::string(uint32_t)>& className = {}, const StubInputContracts& contracts = {},
	const CallInputShapes& shapes = {});
AssemblyNotes BuildCallResultNotes(const CallResultContextResult& result, const std::vector<Edge>& edges,
	const std::function<std::string(uint32_t)>& className = {}, const StubInputContracts& contracts = {},
	const CallInputShapes& shapes = {});
AssemblyNotes BuildRegisterResultNotes(const RegisterContextResult& result, const std::vector<Edge>& edges,
	const std::function<std::string(uint32_t)>& className = {});
}
