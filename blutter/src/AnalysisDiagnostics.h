#pragma once
#include <cstddef>
#include <cstdint>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

enum class AnalysisIssueKind { Unsupported, Invalid };

class AnalysisIssue : public std::runtime_error {
public:
	AnalysisIssue(std::string code, uint64_t address, std::string reason,
		AnalysisIssueKind kind = AnalysisIssueKind::Unsupported)
		: std::runtime_error(std::move(reason)), code(std::move(code)), address(address), kind(kind) {}

	std::string code;
	uint64_t address;
	AnalysisIssueKind kind;
};

class AnalysisStopped : public std::runtime_error {
public:
	AnalysisStopped() : std::runtime_error("Analysis FAILED. Stopping.") {}
};

class AnalysisDiagnostics {
public:
	explicit AnalysisDiagnostics(std::ostream& output) : output(output) {}
	std::size_t ErrorCount() const { return errorCount; }

	void Report(const AnalysisIssue& issue, const std::string& function = {}, const std::string& context = {})
	{
		++errorCount;
		std::ostringstream text;
		text << "\nAnalysis error [" << issue.code << "]\n";
		if (!function.empty())
			text << "  Function: " << function << '\n';
		text << "  Address:  0x" << std::hex << issue.address << std::dec << '\n'
			<< "  Reason:   " << issue.what() << '\n';
		if (!context.empty())
			text << '\n' << context;
		output << text.str();
		if (issue.kind == AnalysisIssueKind::Invalid)
			throw AnalysisStopped();
		if (!partialNoticePrinted) {
			output << "Continuing analysis; available output will be exported with errors.\n";
			partialNoticePrinted = true;
		}
	}

	int Finish(const std::string& directory)
	{
		if (!errorCount)
			return 0;
		output << "\nAnalysis INCOMPLETE.\n  Analysis errors: " << errorCount
			<< "\n  Partial output: " << directory << '\n';
		return 1;
	}

private:
	std::ostream& output;
	bool partialNoticePrinted = false;
	std::size_t errorCount = 0;
};
