#pragma once
#include "CallInputRoles.h"
#include <utility>

namespace SnapshotAnalysis {
// Read the compiled SDK's members. Optional features, not version strings,
// distinguish the reviewed layouts. Missing/mixed layouts admit no closure ABI.
template <typename ArrayAbi, typename ClosureAbi>
StubInputAbis ReadStubInputAbis()
{
	using K = StubInputKind;
	using R = StubInputRole;
	StubInputAbis result;
	if constexpr (requires { ArrayAbi::kLengthReg; ArrayAbi::kTypeArgumentsReg; }) {
		std::vector<StubRegisterRole> roles{{static_cast<unsigned>(ArrayAbi::kLengthReg), R::ArrayLength},
			{static_cast<unsigned>(ArrayAbi::kTypeArgumentsReg), R::ArrayTypeArguments}};
		if (ValidStubInputRoles(K::Array, roles)) result.emplace(K::Array, std::move(roles));
	}
	if constexpr (requires { ClosureAbi::kFunctionReg; ClosureAbi::kContextReg; }) {
		constexpr bool variable = requires { ClosureAbi::kLengthAndFlagsReg; };
		constexpr bool legacy = requires { ClosureAbi::kInstantiatorTypeArgsReg; };
		if constexpr (variable != legacy) {
			std::vector<StubRegisterRole> roles{{static_cast<unsigned>(ClosureAbi::kFunctionReg), R::ClosureFunction},
				{static_cast<unsigned>(ClosureAbi::kContextReg), R::ClosureContext}};
			if constexpr (variable) {
				roles.push_back({static_cast<unsigned>(ClosureAbi::kLengthAndFlagsReg), R::ClosureLengthFlags});
				for (const auto kind : {K::Closure1, K::Closure2, K::Closure3, K::Closure4})
					if (ValidStubInputRoles(kind, roles)) result.emplace(kind, roles);
			} else if (ValidStubInputRoles(K::Closure, roles)) result.emplace(K::Closure, std::move(roles));
		}
	}
	return result;
}
}
