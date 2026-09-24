/*
    MIT License

    Copyright (c) 2020 namreeb (legal@namreeb.org) http://github.com/namreeb/dumpwow

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

// define to disable TLS callbacks in memory and display a message box.  this
// will result in an incorrect (read: probably broken?) exe dump, but will also
// allow for attaching a debugger.
//#define DEBUG_DISABLE_TLS

#include "misc.hpp"
#include "log.hpp"
#include "imports.hpp"
#include "relocations.hpp"
#include "iat_deobfuscate.hpp"

#include <hadesmem/region.hpp>
#include <hadesmem/region_list.hpp>
#include <hadesmem/module.hpp>
#include <hadesmem/pelib/pe_file.hpp>
#include <hadesmem/pelib/nt_headers.hpp>
#include <hadesmem/pelib/section.hpp>
#include <hadesmem/pelib/section_list.hpp>
#include <hadesmem/pelib/tls_dir.hpp>

#include <Windows.h>

#include <stdexcept>
#include <exception>
#include <filesystem>
#include <fstream>
#include <vector>
#include <cstring>
#include <cassert>
#include <algorithm>
#include <iomanip>

namespace fs = std::filesystem;

// Remapped image base from the last successful dump (for Scylla).
PVOID g_last_remapped_base = nullptr;

fs::path get_output_path(const fs::path& input_path);
PVOID find_remapped_base(const hadesmem::Process& process, PVOID base);
void repair_binary(const fs::path &path,const hadesmem::Process &process,
    PVOID base, std::vector<std::uint8_t> &pe,
    std::vector<std::uint8_t> &import_data);

void do_dump(PVOID base, DWORD pe_size)
{
    auto const exe_path = get_exe_path();
    auto const output_path = get_output_path(exe_path);

    const hadesmem::Process process(::GetCurrentProcessId());

    // Beta packers may finish remapping / IAT stub emission after EP.
    PVOID remapped = nullptr;
    std::exception_ptr last_err;
    for (int attempt = 0; attempt < 20; ++attempt)
    {
        if (attempt > 0)
            ::Sleep(500);
        try
        {
            remapped = find_remapped_base(process, base);
            // Prefer a real remapped RW image when it appears later.
            if (remapped != base || attempt >= 6)
                break;
            remapped = nullptr;
            last_err = nullptr;
        }
        catch (const std::exception &)
        {
            last_err = std::current_exception();
            remapped = nullptr;
        }
    }
    if (!remapped)
    {
        // Fall through to in-place protect path inside find_remapped_base.
        remapped = find_remapped_base(process, base);
    }

    base = remapped;
    g_last_remapped_base = base;

    // memory_pe will hold the PE header data before any changes were made
    std::vector<std::uint8_t> memory_pe(pe_size);
    std::vector<std::uint8_t> import_data;
    repair_binary(exe_path, process, base, memory_pe, import_data);
    fix_relocation(base);

    std::ofstream out(output_path, std::ios::binary);

    if (!out)
        throw std::runtime_error("Failed to open unpacked exe for writing");

    // first, write PE header
    const hadesmem::PeFile pe_file(process, base, hadesmem::PeFileType::kImage,
        pe_size);
    const hadesmem::NtHeaders nt_header(process, pe_file);

    out.write(reinterpret_cast<const char*>(base),
        static_cast<std::streamsize>(nt_header.GetSizeOfHeaders()));

    // second, write sections
    const hadesmem::SectionList section_list(process, pe_file);
    for (auto const& section : section_list)
    {
        // TODO: better logic to identify our section here
        if (section.GetName() == ".wowim")
            continue;

        auto const section_base = reinterpret_cast<const char *>(base) +
            section.GetVirtualAddress();
        out.write(section_base, section.GetSizeOfRawData());
    }

    // third, write the new section created for imports
    if (!import_data.empty())
        out.write(reinterpret_cast<const char *>(&import_data[0]),
            import_data.size());

    out.close();
}

fs::path get_output_path(const fs::path& input_path)
{
    auto const dir = input_path.parent_path();
    auto const extension = input_path.extension();
    auto const stem = input_path.stem();

    return dir / (stem.string() + "_unpacked" + extension.string());
}

PVOID find_remapped_base(const hadesmem::Process& process, PVOID base)
{
    const hadesmem::RegionList region_list(process);

    const hadesmem::PeFile pe_file(process, base, hadesmem::PeFileType::kImage,
        0);

    auto const image_size = pe_file.GetSize();
    gLog << "Image size: 0x" << std::hex << image_size << std::endl;
    gLog << "Searching for remapped copy of 0x" << std::hex
        << reinterpret_cast<std::uintptr_t>(base) << std::endl;

    auto pe_header_looks_like = [](PVOID candidate) -> bool {
        MEMORY_BASIC_INFORMATION mbi {};
        if (!::VirtualQuery(candidate, &mbi, sizeof(mbi)) ||
            mbi.State != MEM_COMMIT ||
            mbi.RegionSize < sizeof(IMAGE_DOS_HEADER))
            return false;

        auto const dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(candidate);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return false;
        if (dos->e_lfanew <= 0 ||
            static_cast<SIZE_T>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) >
                mbi.RegionSize)
            return false;

        auto const nt = reinterpret_cast<const IMAGE_NT_HEADERS64 *>(
            reinterpret_cast<const std::uint8_t *>(candidate) + dos->e_lfanew);
        return nt->Signature == IMAGE_NT_SIGNATURE;
    };

    auto is_writable = [](DWORD protect) {
        protect &= 0xFF;
        return protect == PAGE_READWRITE ||
            protect == PAGE_EXECUTE_READWRITE ||
            protect == PAGE_WRITECOPY ||
            protect == PAGE_EXECUTE_WRITECOPY;
    };

    // Prefer an exact-size duplicate of the image (classic remap behaviour).
    for (auto const& region : region_list)
    {
        if (region.GetState() == MEM_FREE)
            continue;

        if (region.GetAllocBase() != region.GetBase())
            continue;

        if (region.GetSize() != image_size)
            continue;

        if (region.GetBase() == base)
            continue;

        if (memcmp(base, region.GetBase(),
            (std::min)(static_cast<SIZE_T>(0x1000), region.GetSize())))
            continue;

        gLog << "Remapped base: 0x" << std::hex
            << reinterpret_cast<std::uintptr_t>(region.GetBase())
            << " protect: 0x" << region.GetProtect()
            << " size: 0x" << region.GetSize() << std::endl;

        return region.GetBase();
    }

    // Fallback: large writable allocation with a PE header (beta may remap
    // with a different region size than SizeOfImage).
    PVOID best = nullptr;
    SIZE_T best_size = 0;
    for (auto const& region : region_list)
    {
        if (region.GetState() != MEM_COMMIT)
            continue;
        if (region.GetAllocBase() != region.GetBase())
            continue;
        if (region.GetBase() == base)
            continue;
        if (region.GetSize() < 0x10000)
            continue;
        if (!is_writable(region.GetProtect()))
            continue;
        if (!pe_header_looks_like(region.GetBase()))
            continue;

        gLog << "Candidate remap: 0x" << std::hex
            << reinterpret_cast<std::uintptr_t>(region.GetBase())
            << " protect: 0x" << region.GetProtect()
            << " size: 0x" << region.GetSize() << std::endl;

        if (region.GetSize() >= image_size / 2 &&
            region.GetSize() > best_size)
        {
            best = region.GetBase();
            best_size = region.GetSize();
        }
    }

    if (best)
    {
        gLog << "Fallback remapped base: 0x" << std::hex
            << reinterpret_cast<std::uintptr_t>(best)
            << " size: 0x" << best_size << std::endl;
        return best;
    }

    // Last resort: unpack in-place — force the original image writable so
    // repair_binary / IAT rebuild can patch it (beta often has no RW remap).
    {
        gLog << "No remapped RW image found; making original writable 0x"
            << std::hex << reinterpret_cast<std::uintptr_t>(base)
            << " size 0x" << image_size << std::endl;

        auto cursor = reinterpret_cast<std::uint8_t *>(base);
        auto const end = cursor + image_size;
        while (cursor < end)
        {
            MEMORY_BASIC_INFORMATION mbi {};
            if (!::VirtualQuery(cursor, &mbi, sizeof(mbi)))
                break;

            auto const region_end =
                reinterpret_cast<std::uint8_t *>(mbi.BaseAddress) +
                mbi.RegionSize;
            auto const patch_end = (std::min)(region_end, end);
            auto const patch_size = static_cast<SIZE_T>(patch_end - cursor);

            if (mbi.State == MEM_COMMIT && patch_size)
            {
                DWORD old_protect = 0;
                if (!::VirtualProtect(cursor, patch_size,
                        PAGE_EXECUTE_READWRITE, &old_protect))
                {
                    gLog << "  VirtualProtect failed at 0x" << std::hex
                        << reinterpret_cast<std::uintptr_t>(cursor)
                        << " err=" << std::dec << ::GetLastError()
                        << std::endl;
                }
            }

            cursor = region_end;
        }

        return base;
    }
}

void repair_binary(const fs::path &path, const hadesmem::Process &process,
    PVOID base, std::vector<std::uint8_t> &pe,
    std::vector<std::uint8_t> &import_data)
{
    // copy the current PE header into the vector to save in case we need it
    memcpy(&pe[0], base, pe.size());

    const hadesmem::PeFile clobbered_pe(process, &pe[0],
        hadesmem::PeFileType::kData, static_cast<DWORD>(pe.size()));

    // read PE header from EXE file
    auto const pe_exe = read_pe_header_from_exe(path,
        static_cast<DWORD>(pe.size()));

    // install EXE PE header into memory
    memcpy(base, &pe_exe[0], pe_exe.size());

    // use the PE header read from the file
    const hadesmem::PeFile pe_file(process, base,
        hadesmem::PeFileType::kImage, static_cast<DWORD>(pe.size()));

    hadesmem::NtHeaders nt_header(process, pe_file);
    hadesmem::SectionList section_list(process, pe_file);
    auto raw_data_pointer = nt_header.GetSizeOfHeaders();

    // used later in import resolution
    PVOID rdata = nullptr;

    for (auto &section : section_list)
    {
        auto const virtual_size = round_up(section.GetVirtualSize(),
            nt_header.GetSectionAlignment());

        auto const section_base = reinterpret_cast<PVOID>(
            reinterpret_cast<std::uint8_t*>(base) +
            section.GetVirtualAddress());

        if (section.GetName() == ".rdata")
            rdata = section_base;

        // for some reason the wow binary has section with unusual sizes.  that's
        // fine, but lets clean it up by enforcing section alignment from the pe
        section.SetVirtualSize(virtual_size);

        // the unpacking may have enlarged the section.  increase the raw size
        // to match the virtual size, and then remove as much zero-fill from
        // the end as we can.
        for (auto remain = virtual_size; remain != 0; --remain)
        {
            auto const curr = reinterpret_cast<const std::uint8_t*>(
                section_base) + remain - 1;

            // we cannot shrink beyond this point
            if (*curr != 0x00)
            {
                auto const old_size = section.GetSizeOfRawData();
                section.SetSizeOfRawData(round_up(remain,
                    nt_header.GetFileAlignment()));
                break;
            }
        }

        // with sections changing size, we should also update the raw location
        section.SetPointerToRawData(raw_data_pointer);
        raw_data_pointer += section.GetSizeOfRawData();

        section.UpdateWrite();
    }

    auto const image_base = reinterpret_cast<void*>(
        nt_header.GetImageBase());

    // tls callbacks will point to the original (now unwritable) region of
    // memory.  the addresses should be rebased to be consistent with the base
    // address in the PE header.
    hadesmem::TlsDir tls_dir(process, pe_file);

    auto mem_tls_dir_in = reinterpret_cast<void**>(tls_dir.GetAddressOfCallBacks());
    auto mem_tls_dir_out = rebase(base, mem_tls_dir_in);

    while (*mem_tls_dir_in)
    {
#ifdef DEBUG_DISABLE_TLS
        *mem_tls_dir_out = nullptr;
#else
        *mem_tls_dir_out = rebase(image_base, *mem_tls_dir_in);
#endif
        ++mem_tls_dir_in;
        ++mem_tls_dir_out;
    }

    const hadesmem::Region old_tls_region(process, reinterpret_cast<PVOID>(
        tls_dir.GetAddressOfCallBacks()));

    auto const tls_callback_rva = static_cast<std::uint64_t>(
        reinterpret_cast<char*>(tls_dir.GetAddressOfCallBacks()) -
        reinterpret_cast<char*>(old_tls_region.GetAllocBase()));

    auto const output_tls_dir = nt_header.GetImageBase() + tls_callback_rva;

    auto const new_tls_address = reinterpret_cast<PVOID>(
        reinterpret_cast<char*>(base) + tls_callback_rva);

    auto const new_start_address = rebase(image_base,
        tls_dir.GetStartAddressOfRawData());
    auto const new_end_address = rebase(image_base,
        tls_dir.GetEndAddressOfRawData());
    auto const new_index_address = rebase(image_base,
        tls_dir.GetAddressOfIndex());
    auto const new_cb_address = rebase(image_base,
        tls_dir.GetAddressOfCallBacks());

    tls_dir.SetStartAddressOfRawData(new_start_address);
    tls_dir.SetEndAddressOfRawData(new_end_address);
    tls_dir.SetAddressOfIndex(new_index_address);
    tls_dir.SetAddressOfCallBacks(new_cb_address);

    tls_dir.UpdateWrite();

    std::uint8_t buff[5];

    auto const entry_point = reinterpret_cast<const char*>(base) +
        nt_header.GetAddressOfEntryPoint();

    memcpy(buff, entry_point, sizeof(buff));

    if (buff[0] == 0xE9)
    {
        auto const new_ep_offset = *reinterpret_cast<const std::int32_t*>(
            entry_point + 1);

        auto const new_ep = reinterpret_cast<const void*>(entry_point +
            new_ep_offset + 5);

        gLog << "True entry point:\t0x" << std::hex << new_ep << std::endl;
    }

    // Deobfuscate modern Blizzard IAT trampolines in the remapped image so
    // slots hold absolute API addresses before we rebuild the import dir.
    deobfuscate_import_address_table(process, base, pe_file);

    // the second TLS callback will generate simple pointer decryption
    // trampolines to mask calls to imported DLL functions.  to resolve
    // these calls we will perform a concolic execution of the trampolines
    // and see what function pointer results.
    if (rdata)
        rebuild_imports(process, pe_file, rdata, import_data);
    else
        gLog << "Did not find .rdata section.  Skipping import resolution."
        << std::endl;

#ifdef DEBUG_DISABLE_TLS
    auto const call_site = reinterpret_cast<void *>(
        reinterpret_cast<char *>(base) + 0x81F5E5);

    gMbLog << "Call site: 0x" << std::hex << call_site
        << "\nBase: 0x" << base << std::endl;
#endif
}
