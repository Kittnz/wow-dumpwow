/*
    Headless IAT deobfuscation for dumpwow (ported from OverwatchDumpFix / WOWDump).
*/
#pragma once

#include <hadesmem/process.hpp>
#include <hadesmem/pelib/pe_file.hpp>

#include <Windows.h>

// Resolve obfuscated import trampolines in the remapped image so each IAT
// slot holds a real absolute API address. Returns number of entries fixed.
size_t deobfuscate_import_address_table(const hadesmem::Process &process,
    PVOID remapped_base, const hadesmem::PeFile &pe_file);
