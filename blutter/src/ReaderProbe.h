#pragma once
#include <cstdint>
#include <filesystem>

// Deserialization and target-contract evidence, before instruction analysis.
void WriteReaderProbe(const std::filesystem::path& destination, uintptr_t libraryBase);
