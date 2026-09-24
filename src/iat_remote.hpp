#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <Windows.h>

// Resolve obfuscated IAT stubs in a live process (reading its PEB remotely),
// rebuild a clean import directory into `image`, and leave IAT slots as
// IMAGE_THUNK_DATA pointing at the new ILT names.
// Returns number of resolved imports.
size_t rebuild_imports_remote(HANDLE hproc, std::uintptr_t actual_base,
    std::vector<std::uint8_t> &image, std::uint32_t iat_rva,
    std::uint32_t iat_size);
