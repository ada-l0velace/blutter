#include "AnalysisDiagnostics.h"
#include <iostream>
#include <sstream>
#include <string>

static size_t checks = 0;
static void Check(bool value, const char* reason)
{
	++checks;
	if (!value)
		throw std::runtime_error(reason);
}

static AnalysisIssue UnsupportedIssue()
{
	return AnalysisIssue("synthetic-unsupported", 0x1000, "Synthetic operation is not supported.");
}

static void ErrorsPermitExportButFail()
{
	std::ostringstream output;
	AnalysisDiagnostics diagnostics(output);
	diagnostics.Report(UnsupportedIssue(), "SyntheticSample.dispatch");
	diagnostics.Report(UnsupportedIssue());
	Check(diagnostics.ErrorCount() == 2, "recoverable errors must be counted");
	Check(output.str().find("Analysis error [synthetic-unsupported]") != std::string::npos, "reason code must be visible");
	Check(output.str().find("SyntheticSample.dispatch") != std::string::npos, "function must be visible");
	Check(output.str().find("0x1000") != std::string::npos, "instruction address must be visible");
	Check(diagnostics.Finish("synthetic-output") == 1, "exports with errors must not report success");
	Check(output.str().find("Analysis INCOMPLETE") != std::string::npos, "incomplete summary must be visible");
	const std::string notice = "Continuing analysis; available output will be exported with errors.";
	const auto first = output.str().find(notice);
	Check(first != std::string::npos && output.str().find(notice, first + 1) == std::string::npos,
		"continuation notice should be printed once");
}

static void InvalidAlwaysStops()
{
	std::ostringstream output;
	AnalysisDiagnostics diagnostics(output);
	bool stopped = false;
	try {
		diagnostics.Report(AnalysisIssue("synthetic-invalid", 0x1000, "Invalid synthetic range.", AnalysisIssueKind::Invalid));
	}
	catch (const AnalysisStopped&) { stopped = true; }
	Check(stopped, "invalid input must stop and prevent unsafe export");
	Check(diagnostics.ErrorCount() == 1, "invalid input must be counted");
	Check(output.str().find("Continuing") == std::string::npos, "invalid input must not advertise recovery");
}

static int FailureProbe(const std::string& mode)
{
	AnalysisDiagnostics diagnostics(std::cerr);
	if (mode == "--probe-invalid")
		diagnostics.Report(AnalysisIssue("synthetic-invalid", 0x1000, "Invalid synthetic range.", AnalysisIssueKind::Invalid));
	else
		diagnostics.Report(UnsupportedIssue(), "SyntheticSample.dispatch");
	return diagnostics.Finish("synthetic-output");
}

int main(int argc, char** argv)
{
	try {
		if (argc == 2) {
			const std::string mode = argv[1];
			if (mode != "--probe-unsupported" && mode != "--probe-invalid")
				throw std::runtime_error("Unknown diagnostic probe");
			return FailureProbe(mode);
		}
		ErrorsPermitExportButFail();
		InvalidAlwaysStops();
		std::ostringstream output;
		AnalysisDiagnostics successful(output);
		Check(successful.Finish("synthetic-output") == 0, "no errors should succeed");
		Check(output.str().empty(), "successful finish must not print a failure");
		std::cout << "Analysis diagnostic checks passed: " << checks << '\n';
		return 0;
	}
	catch (const AnalysisStopped& error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
	catch (const std::exception& error) {
		std::cerr << "Diagnostic test failed: " << error.what() << '\n';
		return 2;
	}
}
