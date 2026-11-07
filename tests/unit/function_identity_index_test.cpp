#include "FunctionIdentityIndex.h"
#include <iostream>

namespace {
unsigned checks = 0;
void Check(bool value) { ++checks; if (!value) throw std::runtime_error("Function identity check failed"); }
struct Function { uint64_t entry; uintptr_t parent; };
}

int main()
{
	try {
		Function placeholder{0x1000, 0}, first{0x1000, 0}, second{0x1000, 0}, parent{0x2000, 0};
		FunctionIdentityIndex<Function> metadata;
		std::unordered_map<uint64_t, Function*> code{{0x1000, &placeholder}};
		Check(metadata.Find(11) == nullptr);
		Check(metadata.Remember(11, &first));
		Check(metadata.Remember(12, &second));
		code.try_emplace(first.entry, &first);
		code.try_emplace(second.entry, &second);
		Check(code.at(0x1000) == &placeholder);
		Check(metadata.Find(11) == &first && metadata.Find(12) == &second);
		Check(metadata.Models() == std::vector<Function*>{&first, &second});
		Check(!metadata.Remember(11, &first));
		Check(metadata.Models().size() == 2);
		bool refused = false;
		try { metadata.Remember(11, &second); }
		catch (const std::logic_error&) { refused = true; }
		Check(refused && metadata.Find(11) == &first);
		refused = false;
		try { metadata.Forget(11, &second); }
		catch (const std::logic_error&) { refused = true; }
		Check(refused && metadata.Models().size() == 2);
		for (const auto [identity, model] : std::vector<std::pair<uintptr_t, Function*>>{{0, &first}, {13, nullptr}}) {
			refused = false;
			try { metadata.Remember(identity, model); }
			catch (const std::invalid_argument&) { refused = true; }
			Check(refused);
		}
		unsigned visited = 0;
		for (size_t i = 0; i < metadata.Models().size(); ++i) {
			if (i == 0) metadata.Remember(13, &parent);
			++visited;
		}
		Check(visited == 3 && metadata.Find(13) == &parent);
		metadata.Forget(11, &first);
		Check(metadata.Find(11) == nullptr && metadata.Find(12) == &second);
		Check(metadata.Models() == std::vector<Function*>{&second, &parent});
		metadata.Forget(11, &first);
		Check(metadata.Models().size() == 2);

		Function parentA{0x3000, 0}, parentB{0x3000, 0}, childA{0x4000, 21}, childB{0x4000, 22};
		FunctionIdentityIndex<Function> closures;
		closures.Remember(21, &parentA); closures.Remember(22, &parentB);
		closures.Remember(31, &childA); closures.Remember(32, &childB);
		Check(closures.Find(closures.Find(31)->parent) == &parentA);
		Check(closures.Find(closures.Find(32)->parent) == &parentB);
		std::cout << checks << " Function metadata identity checks passed\n";
	}
	catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
