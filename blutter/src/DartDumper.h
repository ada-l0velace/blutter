#pragma once
#include "DartApp.h"
#include "AnalysisDiagnostics.h"
#include <filesystem>
#include <optional>
#include <map>

class DartDumper
{
public:
	DartDumper(DartApp& app, AnalysisDiagnostics* diagnostics = nullptr, std::optional<uint64_t> selectedCaller = {})
		: app(app), diagnostics(diagnostics), selectedCaller(selectedCaller) {};

	void Dump4Ida(std::filesystem::path outDir);

	std::vector<std::pair<intptr_t, std::string>> DumpStructHeaderFile(std::string outFile);

	void DumpCode(const char* out_dir);
#ifdef HAS_INSTRUCTIONS_TABLE_RODATA
	void DumpCoverageAudit(const char* filename);
#endif

	void DumpObjectPool(const char* filename);
	void DumpObjects(const char* filename);

	std::string ObjectToString(dart::Object& obj, bool simpleForm = false, bool nestedObj = false, int depth = 0);

private:
#ifdef HAS_INSTRUCTIONS_TABLE_RODATA
	void DumpSnapshotCode(const char* asm_dir);
	std::vector<std::pair<uint64_t, uint64_t>> snapshotCodeRanges;
	std::vector<std::pair<uint64_t, uint64_t>> recoveredCodeRanges;
	std::map<uint64_t, std::vector<std::string>> callerResultNotes;
#endif
	std::string getPoolObjectDescription(intptr_t offset, bool simpleForm = true);

	std::string dumpInstance(dart::Object& obj, bool simpleForm = false, bool nestedObj = false, int depth = 0);
	std::string dumpInstanceFields(dart::Object& obj, DartClass& dartCls, intptr_t ptr, intptr_t offset, bool simpleForm = false, bool nestedObj = false, int depth = 0);

	void applyStruct4Ida(std::ostream& of);

	const std::string& getQuoteString(dart::Object& obj);

	DartApp& app;
	AnalysisDiagnostics* diagnostics;
	std::optional<uint64_t> selectedCaller;
	// map for object ptr to unescape string with quote
	std::unordered_map<intptr_t, std::string> quoteStringCache;
};
