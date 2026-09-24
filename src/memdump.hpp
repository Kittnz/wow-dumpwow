/*
    External dump for Eidolon-packed clients.

    Launch untouched, wait for window, force .text decrypt, RPM the image,
    resolve PEB-based IAT stubs remotely, rebuild a clean import directory,
    undo DIR64 relocs, write *_unpacked.exe.
*/
#pragma once

#include <filesystem>

namespace memdump
{

bool disk_has_eidolon_loader(std::filesystem::path const &exe_path);

// Full external dump including remote IAT rebuild. Returns EXIT_SUCCESS/FAILURE.
int run(std::filesystem::path const &exe_path);

} // namespace memdump
