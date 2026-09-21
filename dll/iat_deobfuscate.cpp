/*
    Headless IAT deobfuscation for dumpwow.
    Emulates modern Classic IAT stubs (rax ALU + PEB mixes) and writes
    resolved absolute API addresses back into the remapped IAT.
*/

#include "iat_deobfuscate.hpp"
#include "log.hpp"

#include <hadesmem/pelib/nt_headers.hpp>
#include <hadesmem/pelib/export_list.hpp>
#include <hadesmem/region.hpp>
#include <hadesmem/process.hpp>

#include <Windows.h>
#include <intrin.h>

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <vector>

namespace
{
constexpr size_t kIatEntryLimit = 1500;
constexpr size_t kMaxStubInsns = 128;

bool is_executable_protect(DWORD protect)
{
    protect &= 0xFF;
    return protect == PAGE_EXECUTE ||
        protect == PAGE_EXECUTE_READ ||
        protect == PAGE_EXECUTE_READWRITE ||
        protect == PAGE_EXECUTE_WRITECOPY;
}

std::uint64_t rol64(std::uint64_t v, unsigned n)
{
    n &= 63;
    return (v << n) | (v >> (64 - n));
}

std::uint64_t ror64(std::uint64_t v, unsigned n)
{
    n &= 63;
    return (v >> n) | (v << (64 - n));
}

bool readable(const void *p, size_t len = 1)
{
    MEMORY_BASIC_INFORMATION mbi {};
    auto const bytes = reinterpret_cast<const std::uint8_t *>(p);
    if (!::VirtualQuery(bytes, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT)
        return false;
    auto const end = bytes + len;
    auto const region_end =
        reinterpret_cast<const std::uint8_t *>(mbi.BaseAddress) + mbi.RegionSize;
    return end <= region_end;
}

// Emulate Classic IAT stubs: mov/inc/dec/rol/ror/add/sub/xor on rax, plus
// PEB mixes via gs:[0x60] and [rax+disp], push/pop, jmp rax.
bool deobfuscate_stub(const void *stub, std::uint64_t &out_addr)
{
    if (!readable(stub, 16))
        return false;

    auto ip = reinterpret_cast<const std::uint8_t *>(stub);
    std::uint64_t rax = 0;
    std::uint64_t stack_slot = 0;
    bool stack_live = false;

    for (size_t n = 0; n < kMaxStubInsns; ++n)
    {
        if (!readable(ip, 16))
            return false;

        // jmp rax
        if (ip[0] == 0xFF && ip[1] == 0xE0)
        {
            out_addr = rax;
            return rax != 0;
        }

        // E9 rel32
        if (ip[0] == 0xE9)
        {
            auto const rel = *reinterpret_cast<const std::int32_t *>(ip + 1);
            ip = ip + 5 + rel;
            continue;
        }

        // 48 B8 imm64  -> mov rax, imm64
        if (ip[0] == 0x48 && ip[1] == 0xB8)
        {
            rax = *reinterpret_cast<const std::uint64_t *>(ip + 2);
            ip += 10;
            continue;
        }

        // 48 FF C0 -> inc rax
        if (ip[0] == 0x48 && ip[1] == 0xFF && ip[2] == 0xC0)
        {
            ++rax;
            ip += 3;
            continue;
        }

        // 48 FF C8 -> dec rax
        if (ip[0] == 0x48 && ip[1] == 0xFF && ip[2] == 0xC8)
        {
            --rax;
            ip += 3;
            continue;
        }

        // 48 C1 C0 ib -> rol rax, ib
        if (ip[0] == 0x48 && ip[1] == 0xC1 && ip[2] == 0xC0)
        {
            rax = rol64(rax, ip[3]);
            ip += 4;
            continue;
        }

        // 48 C1 C8 ib -> ror rax, ib
        if (ip[0] == 0x48 && ip[1] == 0xC1 && ip[2] == 0xC8)
        {
            rax = ror64(rax, ip[3]);
            ip += 4;
            continue;
        }

        // 48 05 imm32 -> add rax, imm32
        if (ip[0] == 0x48 && ip[1] == 0x05)
        {
            rax += *reinterpret_cast<const std::int32_t *>(ip + 2);
            ip += 6;
            continue;
        }

        // 48 2D imm32 -> sub rax, imm32
        if (ip[0] == 0x48 && ip[1] == 0x2D)
        {
            rax -= *reinterpret_cast<const std::int32_t *>(ip + 2);
            ip += 6;
            continue;
        }

        // 48 35 imm32 -> xor rax, imm32
        if (ip[0] == 0x48 && ip[1] == 0x35)
        {
            rax ^= static_cast<std::uint64_t>(
                *reinterpret_cast<const std::int32_t *>(ip + 2));
            ip += 6;
            continue;
        }

        // 50 -> push rax
        if (ip[0] == 0x50)
        {
            stack_slot = rax;
            stack_live = true;
            ip += 1;
            continue;
        }

        // 58 -> pop rax
        if (ip[0] == 0x58)
        {
            if (!stack_live)
                return false;
            rax = stack_slot;
            stack_live = false;
            ip += 1;
            continue;
        }

        // 48 31 04 24 -> xor qword ptr [rsp], rax
        if (ip[0] == 0x48 && ip[1] == 0x31 && ip[2] == 0x04 && ip[3] == 0x24)
        {
            if (!stack_live)
                return false;
            stack_slot ^= rax;
            ip += 4;
            continue;
        }

        // 65 48 8B 04 25 60 00 00 00 -> mov rax, gs:[0x60] (PEB)
        if (ip[0] == 0x65 && ip[1] == 0x48 && ip[2] == 0x8B &&
            ip[3] == 0x04 && ip[4] == 0x25 &&
            *reinterpret_cast<const std::uint32_t *>(ip + 5) == 0x60)
        {
            rax = __readgsqword(0x60);
            ip += 9;
            continue;
        }

        // 48 8B 80 disp32 -> mov rax, qword ptr [rax+disp32]
        if (ip[0] == 0x48 && ip[1] == 0x8B && ip[2] == 0x80)
        {
            auto const disp = *reinterpret_cast<const std::int32_t *>(ip + 3);
            auto const addr = reinterpret_cast<const void *>(
                static_cast<std::uintptr_t>(rax + disp));
            if (!readable(addr, 8))
                return false;
            rax = *reinterpret_cast<const std::uint64_t *>(addr);
            ip += 7;
            continue;
        }

        // 48 8B 40 ib -> mov rax, qword ptr [rax+disp8]
        if (ip[0] == 0x48 && ip[1] == 0x8B && ip[2] == 0x40)
        {
            auto const disp = static_cast<std::int8_t>(ip[3]);
            auto const addr = reinterpret_cast<const void *>(
                static_cast<std::uintptr_t>(rax + disp));
            if (!readable(addr, 8))
                return false;
            rax = *reinterpret_cast<const std::uint64_t *>(addr);
            ip += 4;
            continue;
        }

        // 49 BA imm64 -> mov r10, imm64 (ignore r10; some stubs still emit it)
        if (ip[0] == 0x49 && ip[1] == 0xBA)
        {
            ip += 10;
            continue;
        }

        // Unrecognized — log first failing bytes for the first few callers via
        // out-of-band isn't available; return false.
        (void)n;
        return false;
    }

    return false;
}

bool is_export_of_module(std::uint64_t val)
{
    try
    {
        const hadesmem::Process proc(::GetCurrentProcessId());
        const hadesmem::Region region(proc, reinterpret_cast<PVOID>(val));
        if (region.GetType() != MEM_IMAGE)
            return false;
        if (!is_executable_protect(region.GetProtect()))
            return false;

        const hadesmem::PeFile mod_pe(proc, region.GetAllocBase(),
            hadesmem::PeFileType::kImage, 0);
        const hadesmem::ExportList exports(proc, mod_pe);
        for (auto const &e : exports)
        {
            if (e.GetVa() == reinterpret_cast<PVOID>(val))
                return true;
        }
    }
    catch (const std::exception &)
    {
    }
    return false;
}

PIMAGE_SECTION_HEADER find_rdata(PVOID base)
{
    auto const dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;

    auto const nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
        reinterpret_cast<std::uint8_t *>(base) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;

    auto section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
    {
        char name[9] {};
        std::memcpy(name, section->Name, 8);
        if (std::strcmp(name, ".rdata") == 0)
            return section;
    }
    return nullptr;
}
}

size_t deobfuscate_import_address_table(const hadesmem::Process & /*process*/,
    PVOID remapped_base, const hadesmem::PeFile &pe_file)
{
    auto const dos = reinterpret_cast<PIMAGE_DOS_HEADER>(remapped_base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        gLog << "IAT deobf: bad DOS header" << std::endl;
        return 0;
    }

    auto const nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
        reinterpret_cast<std::uint8_t *>(remapped_base) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        gLog << "IAT deobf: bad NT header" << std::endl;
        return 0;
    }

    auto const image_base = reinterpret_cast<std::uintptr_t>(remapped_base);
    auto const image_size = (std::max)(
        static_cast<std::uintptr_t>(nt->OptionalHeader.SizeOfImage),
        static_cast<std::uintptr_t>(pe_file.GetSize()));
    auto const preferred_base =
        static_cast<std::uintptr_t>(nt->OptionalHeader.ImageBase);

    std::uintptr_t iat_ea = 0;
    size_t count = 0;

    auto const &iat_dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    if (iat_dir.VirtualAddress &&
        iat_dir.Size >= sizeof(std::uint64_t) &&
        iat_dir.VirtualAddress < image_size &&
        iat_dir.VirtualAddress + iat_dir.Size <= image_size)
    {
        iat_ea = image_base + iat_dir.VirtualAddress;
        count = (std::min)(
            static_cast<size_t>(iat_dir.Size / sizeof(std::uint64_t)),
            kIatEntryLimit);
        gLog << "IAT deobf: using IAT directory VA=0x" << std::hex
            << iat_dir.VirtualAddress << " size=0x" << iat_dir.Size
            << std::endl;
    }
    else
    {
        auto const section = find_rdata(remapped_base);
        if (!section)
        {
            gLog << "IAT deobf: .rdata section not found" << std::endl;
            return 0;
        }

        auto section_bytes = static_cast<std::uintptr_t>(
            section->Misc.VirtualSize);
        if (section->VirtualAddress >= image_size)
        {
            gLog << "IAT deobf: .rdata VA past image end" << std::endl;
            return 0;
        }
        auto const max_bytes = image_size - section->VirtualAddress;
        if (section_bytes > max_bytes)
            section_bytes = max_bytes;

        auto const entries = reinterpret_cast<std::uint64_t *>(
            image_base + section->VirtualAddress);
        auto const max_entries = (std::min)(
            static_cast<size_t>(section_bytes / sizeof(std::uint64_t)),
            kIatEntryLimit);

        count = 0;
        for (; count < max_entries; ++count)
        {
            auto const val = entries[count];
            if (!val)
                break;
            auto const in_image =
                val >= image_base && val < image_base + image_size;
            auto const legacy_encoded = val < image_base;
            if (!in_image && !legacy_encoded)
                break;
        }

        iat_ea = image_base + section->VirtualAddress;
        gLog << "IAT deobf: scanning leading .rdata run (" << std::dec
            << count << " entries)" << std::endl;
    }

    if (!iat_ea || !count)
    {
        gLog << "IAT deobf: no IAT range found" << std::endl;
        return 0;
    }

    auto const entries = reinterpret_cast<std::uint64_t *>(iat_ea);
    gLog << "IAT deobf: scanning " << std::dec << count
        << " entries at 0x" << std::hex << iat_ea << std::endl;

    auto resolve_stub_ptr = [&](std::uint64_t val) -> const void * {
        try
        {
            const hadesmem::Process proc(::GetCurrentProcessId());
            const hadesmem::Region region(proc, reinterpret_cast<PVOID>(val));
            if (region.GetState() == MEM_COMMIT)
                return reinterpret_cast<const void *>(val);
        }
        catch (const std::exception &)
        {
        }

        if (val >= image_base && val < image_base + image_size)
            return reinterpret_cast<const void *>(val);

        if (preferred_base &&
            val >= preferred_base &&
            val < preferred_base + image_size)
        {
            return reinterpret_cast<const void *>(
                image_base + (val - preferred_base));
        }

        return nullptr;
    };

    size_t fixed = 0;
    size_t skipped = 0;
    size_t failed = 0;

    for (size_t i = 0; i < count; ++i)
    {
        auto &slot = entries[i];
        auto const val = slot;
        if (!val)
            continue;

        if (is_export_of_module(val))
        {
            ++skipped;
            continue;
        }

        auto const stub = resolve_stub_ptr(val);
        if (!stub)
        {
            ++skipped;
            continue;
        }

        std::uint64_t resolved = 0;
        if (!deobfuscate_stub(stub, resolved) || !resolved)
        {
            if (i < 4)
            {
                gLog << "  deobf fail IAT[" << std::dec << i << "] stub=0x"
                    << std::hex << reinterpret_cast<std::uintptr_t>(stub)
                    << std::endl;
            }
            ++failed;
            continue;
        }

        if (resolved >= image_base && resolved < image_base + image_size)
        {
            ++failed;
            continue;
        }

        try
        {
            const hadesmem::Region region(
                hadesmem::Process(::GetCurrentProcessId()),
                reinterpret_cast<PVOID>(resolved));
            if (region.GetType() != MEM_IMAGE ||
                !is_executable_protect(region.GetProtect()))
            {
                if (i < 4)
                    gLog << "  deobf bad target IAT[" << std::dec << i
                        << "] -> 0x" << std::hex << resolved << std::endl;
                ++failed;
                continue;
            }
        }
        catch (const std::exception &)
        {
            ++failed;
            continue;
        }

        if (i < 4)
            gLog << "  deobf ok IAT[" << std::dec << i << "] -> 0x"
                << std::hex << resolved << std::endl;

        slot = resolved;
        ++fixed;
    }

    auto &out_iat =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    out_iat.VirtualAddress = static_cast<DWORD>(iat_ea - image_base);
    out_iat.Size = static_cast<DWORD>(count * sizeof(std::uint64_t));

    gLog << "IAT deobf: fixed=" << std::dec << fixed
        << " skipped=" << skipped << " failed=" << failed
        << " iat_dir VA=0x" << std::hex << out_iat.VirtualAddress
        << " size=0x" << out_iat.Size << std::endl;

    return fixed;
}
