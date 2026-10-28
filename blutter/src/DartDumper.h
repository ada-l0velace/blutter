#pragma once
#include "DartApp.h"
#include "AnalysisDiagnostics.h"
#include <filesystem>

class DartDumper
{
public:
	DartDumper(DartApp& app, AnalysisDiagnostics* diagnostics = nullptr) : app(app), diagnostics(diagnostics) {};

	void Dump4Ida(std::filesystem::path outDir);

	std::vector<std::pair<intptr_t, std::string>> DumpStructHeaderFile(std::string outFile);

	void DumpCode(const char* out_dir);
#if defined(BLUTTER_SHOREBIRD_3C9C)
	void DumpCoverageAudit(const char* filename);
#endif

	void DumpObjectPool(const char* filename);
	void DumpObjects(const char* filename);

	std::string ObjectToString(dart::Object& obj, bool simpleForm = false, bool nestedObj = false, int depth = 0);

private:
#if defined(BLUTTER_SHOREBIRD_3C9C)
	void DumpSnapshotCode(const char* asm_dir);
	std::vector<std::pair<uint64_t, uint64_t>> snapshotCodeRanges;
	std::vector<std::pair<uint64_t, uint64_t>> recoveredCodeRanges;
#endif
	std::string getPoolObjectDescription(intptr_t offset, bool simpleForm = true);

	std::string dumpInstance(dart::Object& obj, bool simpleForm = false, bool nestedObj = false, int depth = 0);
	std::string dumpInstanceFields(dart::Object& obj, DartClass& dartCls, intptr_t ptr, intptr_t offset, bool simpleForm = false, bool nestedObj = false, int depth = 0);

	void applyStruct4Ida(std::ostream& of);

	const std::string& getQuoteString(dart::Object& obj);

	DartApp& app;
	AnalysisDiagnostics* diagnostics;
	// map for object ptr to unescape string with quote
	std::unordered_map<intptr_t, std::string> quoteStringCache;
};
