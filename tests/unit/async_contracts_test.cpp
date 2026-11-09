#include "AsyncContracts.h"
#include <iostream>
#include <limits>
#include <stdexcept>

using namespace SnapshotAnalysis;
namespace {
unsigned checks = 0;
void Check(bool value, const char* message) {
	++checks;
	if (!value) throw std::runtime_error(message);
}
}
int main() {
	try {
		const std::map<uint64_t, uint64_t> bounds{{0x8000, 0x8010}};
		for (const auto op : {AsyncOperation::Init, AsyncOperation::Await, AsyncOperation::AwaitWithTypeCheck,
			AsyncOperation::CompleteValue, AsyncOperation::CompleteValueOrFuture, AsyncOperation::Resume}) {
			const AsyncStubIdentity id{0x8000, 0x8000, 0x8010, op, true};
			const auto contracts = SelectAsyncContracts({id}, bounds, true);
			Check(contracts.size() == 1 && contracts.at(id.entry).operation == op, "Matched SDK operation retained");
			Check(SelectAsyncContracts({id, id}, bounds, true) == contracts, "Compatible aliases coalesce");
			auto other = id;
			other.operation = op == AsyncOperation::Init ? AsyncOperation::Await : AsyncOperation::Init;
			Check(SelectAsyncContracts({id, other, id}, bounds, true).empty(), "Two valid operation identities at one entry stay ambiguous");
			Check(SelectAsyncContracts({id}, bounds, false).empty(), "Unsupported ABI grants no contract");
			Check(SelectAsyncContracts({id}, {}, true).empty(), "Original range required");
			for (unsigned defect = 0; defect < 8; ++defect) {
				auto bad = id;
				if (defect == 0) bad.entry += 2;
				if (defect == 1) bad.payload -= 4;
				if (defect == 2) bad.end += 4;
				if (defect == 3) bad.end = bad.entry;
				if (defect == 4) bad.matchesReference = false;
				if (defect == 5) bad.operation = AsyncOperation::Unknown;
				if (defect == 6) bad.operation = static_cast<AsyncOperation>(255);
				if (defect == 7) bad.entry = 0;
				Check(SelectAsyncContracts({bad}, bounds, true).empty(), "Malformed identity rejected");
				Check(SelectAsyncContracts({id, bad, id}, bounds, true).contains(id.entry) == (bad.entry != id.entry), "Conflicting aliases never revive");
			}
			const bool complete = op == AsyncOperation::CompleteValue || op == AsyncOperation::CompleteValueOrFuture;
			for (const auto transfer : {"call", "jump", "conditional_jump", "indirect_call", "indirect_jump"}) {
				const auto b = DescribeAsyncBoundary(transfer, 0x1000, 0x1000, 0x1008, id.entry, contracts);
				const bool expected = op != AsyncOperation::Resume && std::string(transfer) == (complete ? "jump" : "call");
				Check(b.has_value() == expected, "Only supported transfer form receives a boundary");
				if (!b) continue;
				Check(b->site == 0x1000 && b->payload == 0x1000 && b->callee == 0x8000, "Original source and target retained");
				const bool await = op == AsyncOperation::Await || op == AsyncOperation::AwaitWithTypeCheck;
				Check(b->resumeSite == (await ? std::optional<uint64_t>{0x1004} : std::nullopt), "Only await records successful resume address");
				const auto note = AsyncBoundaryNote(*b);
				Check(!note.empty() && note.find("matched SDK boundary") != std::string::npos, "Annotation states its evidence basis");
				if (await) {
					Check(note.find("input X0") != std::string::npos && note.find("value origin unknown") != std::string::npos, "Await does not invent producer or confuse input with X1");
					Check(note.find("exception path separate") != std::string::npos, "Successful delivery excludes exceptions");
					const auto last = DescribeAsyncBoundary("call", 0x1000, 0x1000, 0x1004, id.entry, contracts);
					Check(last && !last->resumeSite && AsyncBoundaryNote(*last).find("outside this payload") != std::string::npos, "Final-word await has no in-payload resume");
				}
			}
			Check(!DescribeAsyncBoundary("call", 0x1000, 0x1000, 0x1008, id.entry + 4, contracts), "Interior target has no contract");
			Check(!DescribeAsyncBoundary("call", 0x1002, 0x1000, 0x1008, id.entry, contracts), "Unaligned source rejected");
			Check(!DescribeAsyncBoundary("call", 0x1000, 0x1004, 0x1008, id.entry, contracts), "Source outside payload rejected");
			Check(!DescribeAsyncBoundary("call", 0x1000, 0x1000, 0x1000, id.entry, contracts), "Empty range rejected");
		}
		const auto top = std::numeric_limits<uint64_t>::max() - 3;
		const std::map<uint64_t, AsyncContract> contracts{{0x8000, {AsyncOperation::Await, 0x8010}}};
		const auto last = DescribeAsyncBoundary("call", top - 4, top - 4, top, 0x8000, contracts);
		Check(last && !last->resumeSite, "Address limit does not overflow");
		Check(SelectAsyncContracts({{0x8000,0x8000,0x208004,AsyncOperation::Await,true}}, {{0x8000,0x208004}}, true).empty(), "Unbounded reference size rejected");
		std::cout << checks << " async contract checks passed\n";
	} catch (const std::exception& error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
}
