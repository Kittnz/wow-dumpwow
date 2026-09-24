#include "iat_remote.hpp"

#include <Windows.h>
#include <Psapi.h>
#include <winternl.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "Psapi.lib")

namespace
{

constexpr size_t kMaxStubInsns = 128;
constexpr size_t kIatEntryLimit = 1500;

using NtQueryInformationProcessT = NTSTATUS(NTAPI *)(HANDLE, PROCESSINFOCLASS,
    PVOID, ULONG, PULONG);

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

bool rpm(HANDLE h, std::uintptr_t addr, void *dst, size_t len)
{
    SIZE_T got = 0;
    return !!::ReadProcessMemory(h, reinterpret_cast<LPCVOID>(addr), dst, len,
        &got) && got == len;
}

std::uintptr_t remote_peb(HANDLE hproc)
{
    PROCESS_BASIC_INFORMATION pbi {};
    auto ntq = reinterpret_cast<NtQueryInformationProcessT>(::GetProcAddress(
        ::GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    if (!ntq)
        return 0;
    ULONG ret = 0;
    if (ntq(hproc, ProcessBasicInformation, &pbi, sizeof(pbi), &ret) < 0)
        return 0;
    return reinterpret_cast<std::uintptr_t>(pbi.PebBaseAddress);
}

bool emulate_stub(HANDLE hproc, std::uintptr_t stub_ea, std::uintptr_t peb,
    std::uint64_t &out_addr)
{
    std::uint8_t code[16] {};
    if (!rpm(hproc, stub_ea, code, sizeof(code)))
        return false;

    auto ip = stub_ea;
    std::uint64_t rax = 0;
    std::uint64_t stack_slot = 0;
    bool stack_live = false;

    for (size_t n = 0; n < kMaxStubInsns; ++n)
    {
        if (!rpm(hproc, ip, code, sizeof(code)))
            return false;

        if (code[0] == 0xFF && code[1] == 0xE0)
        {
            out_addr = rax;
            return rax != 0;
        }

        if (code[0] == 0xE9)
        {
            auto const rel = *reinterpret_cast<std::int32_t *>(code + 1);
            ip = ip + 5 + rel;
            continue;
        }

        if (code[0] == 0x48 && code[1] == 0xB8)
        {
            rax = *reinterpret_cast<std::uint64_t *>(code + 2);
            ip += 10;
            continue;
        }

        if (code[0] == 0x48 && code[1] == 0xFF && code[2] == 0xC0)
        {
            ++rax;
            ip += 3;
            continue;
        }

        if (code[0] == 0x48 && code[1] == 0xFF && code[2] == 0xC8)
        {
            --rax;
            ip += 3;
            continue;
        }

        if (code[0] == 0x48 && code[1] == 0xC1 && code[2] == 0xC0)
        {
            rax = rol64(rax, code[3]);
            ip += 4;
            continue;
        }

        if (code[0] == 0x48 && code[1] == 0xC1 && code[2] == 0xC8)
        {
            rax = ror64(rax, code[3]);
            ip += 4;
            continue;
        }

        if (code[0] == 0x48 && code[1] == 0x05)
        {
            rax += *reinterpret_cast<std::int32_t *>(code + 2);
            ip += 6;
            continue;
        }

        if (code[0] == 0x48 && code[1] == 0x2D)
        {
            rax -= *reinterpret_cast<std::int32_t *>(code + 2);
            ip += 6;
            continue;
        }

        if (code[0] == 0x48 && code[1] == 0x35)
        {
            rax ^= static_cast<std::uint64_t>(
                *reinterpret_cast<std::int32_t *>(code + 2));
            ip += 6;
            continue;
        }

        if (code[0] == 0x50)
        {
            stack_slot = rax;
            stack_live = true;
            ip += 1;
            continue;
        }

        if (code[0] == 0x58)
        {
            if (!stack_live)
                return false;
            rax = stack_slot;
            stack_live = false;
            ip += 1;
            continue;
        }

        if (code[0] == 0x48 && code[1] == 0x31 && code[2] == 0x04 &&
            code[3] == 0x24)
        {
            if (!stack_live)
                return false;
            stack_slot ^= rax;
            ip += 4;
            continue;
        }

        // mov rax, gs:[0x60]
        if (code[0] == 0x65 && code[1] == 0x48 && code[2] == 0x8B &&
            code[3] == 0x04 && code[4] == 0x25 &&
            *reinterpret_cast<std::uint32_t *>(code + 5) == 0x60)
        {
            rax = peb;
            ip += 9;
            continue;
        }

        if (code[0] == 0x48 && code[1] == 0x8B && code[2] == 0x80)
        {
            auto const disp = *reinterpret_cast<std::int32_t *>(code + 3);
            std::uint64_t val = 0;
            if (!rpm(hproc, static_cast<std::uintptr_t>(rax + disp), &val, 8))
                return false;
            rax = val;
            ip += 7;
            continue;
        }

        if (code[0] == 0x48 && code[1] == 0x8B && code[2] == 0x40)
        {
            auto const disp = static_cast<std::int8_t>(code[3]);
            std::uint64_t val = 0;
            if (!rpm(hproc, static_cast<std::uintptr_t>(rax + disp), &val, 8))
                return false;
            rax = val;
            ip += 4;
            continue;
        }

        if (code[0] == 0x49 && code[1] == 0xBA)
        {
            ip += 10;
            continue;
        }

        return false;
    }
    return false;
}

struct ExportInfo
{
    std::string dll;  // lowercase basename
    std::string name;
    WORD hint = 0;
};

struct ModuleExports
{
    std::uintptr_t base = 0;
    std::uint32_t size = 0;
    std::string name;
    std::unordered_map<std::uintptr_t, ExportInfo> by_va;
};

bool load_module_exports(HANDLE hproc, HMODULE mod, ModuleExports &out)
{
    MODULEINFO mi {};
    if (!::GetModuleInformation(hproc, mod, &mi, sizeof(mi)))
        return false;
    out.base = reinterpret_cast<std::uintptr_t>(mi.lpBaseOfDll);
    out.size = mi.SizeOfImage;

    wchar_t path[MAX_PATH] {};
    if (!::GetModuleFileNameExW(hproc, mod, path, MAX_PATH))
        return false;
    auto fname = std::filesystem::path(path).filename().string();
    for (auto &c : fname)
        c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
    out.name = fname;

    std::uint8_t hdr[0x1000] {};
    if (!rpm(hproc, out.base, hdr, sizeof(hdr)))
        return false;
    auto const dos = reinterpret_cast<IMAGE_DOS_HEADER *>(hdr);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    auto const nt = reinterpret_cast<IMAGE_NT_HEADERS64 *>(hdr + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return false;
    auto const exp_rva =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
            .VirtualAddress;
    auto const exp_size =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!exp_rva || !exp_size)
        return true;

    std::vector<std::uint8_t> exp_buf(exp_size);
    if (!rpm(hproc, out.base + exp_rva, exp_buf.data(), exp_size))
        return false;
    auto const exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY *>(exp_buf.data());

    auto rva_ptr = [&](DWORD rva) -> std::uint8_t * {
        if (rva < exp_rva || rva >= exp_rva + exp_size)
            return nullptr;
        return exp_buf.data() + (rva - exp_rva);
    };

    auto names = reinterpret_cast<DWORD *>(rva_ptr(exp->AddressOfNames));
    auto ords = reinterpret_cast<WORD *>(rva_ptr(exp->AddressOfNameOrdinals));
    auto funcs = reinterpret_cast<DWORD *>(rva_ptr(exp->AddressOfFunctions));
    if (!names || !ords || !funcs)
        return true;

    for (DWORD i = 0; i < exp->NumberOfNames; ++i)
    {
        auto name_p = reinterpret_cast<char *>(rva_ptr(names[i]));
        if (!name_p)
            continue;
        auto const ord = ords[i];
        if (ord >= exp->NumberOfFunctions)
            continue;
        auto const func_rva = funcs[ord];
        if (!func_rva)
            continue;
        // skip forwards inside export dir
        if (func_rva >= exp_rva && func_rva < exp_rva + exp_size)
            continue;
        ExportInfo info;
        info.dll = out.name;
        info.name = name_p;
        info.hint = static_cast<WORD>(i);
        out.by_va[out.base + func_rva] = std::move(info);
    }
    return true;
}

std::vector<ModuleExports> collect_exports(HANDLE hproc)
{
    std::vector<ModuleExports> mods;
    DWORD needed = 0;
    ::EnumProcessModulesEx(hproc, nullptr, 0, &needed, LIST_MODULES_ALL);
    auto count = (std::max)(
        needed / static_cast<DWORD>(sizeof(HMODULE)), static_cast<DWORD>(1));
    std::vector<HMODULE> handles(count);
    if (!::EnumProcessModulesEx(hproc, handles.data(),
            static_cast<DWORD>(handles.size() * sizeof(HMODULE)), &needed,
            LIST_MODULES_ALL))
        return mods;
    count = needed / static_cast<DWORD>(sizeof(HMODULE));
    for (DWORD i = 0; i < count; ++i)
    {
        ModuleExports m;
        if (load_module_exports(hproc, handles[i], m) && !m.by_va.empty())
            mods.push_back(std::move(m));
    }
    return mods;
}

ExportInfo const *lookup_export(std::vector<ModuleExports> const &mods,
    std::uintptr_t va)
{
    for (auto const &m : mods)
    {
        auto it = m.by_va.find(va);
        if (it != m.by_va.end())
            return &it->second;
    }
    return nullptr;
}

// IAT slots sometimes hold a jmp thunk in front of the real export.
bool follow_export_thunk(HANDLE hproc, std::uintptr_t &va)
{
    std::uint8_t code[16] {};
    if (!rpm(hproc, va, code, sizeof(code)))
        return false;
    if (code[0] == 0xE9)
    {
        auto const rel = *reinterpret_cast<std::int32_t *>(code + 1);
        va = va + 5 + static_cast<std::uintptr_t>(rel);
        return true;
    }
    if (code[0] == 0xFF && code[1] == 0x25)
    {
        auto const rel = *reinterpret_cast<std::int32_t *>(code + 2);
        std::uint64_t target = 0;
        if (!rpm(hproc, va + 6 + rel, &target, 8) || !target)
            return false;
        va = static_cast<std::uintptr_t>(target);
        return true;
    }
    return false;
}

ExportInfo named_rva_in_module(HANDLE hproc, std::uintptr_t va)
{
    ExportInfo info;
    DWORD needed = 0;
    ::EnumProcessModulesEx(hproc, nullptr, 0, &needed, LIST_MODULES_ALL);
    std::vector<HMODULE> handles(needed / sizeof(HMODULE) + 1);
    if (!::EnumProcessModulesEx(hproc, handles.data(),
            static_cast<DWORD>(handles.size() * sizeof(HMODULE)), &needed,
            LIST_MODULES_ALL))
        return info;
    auto const count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count; ++i)
    {
        MODULEINFO mi {};
        if (!::GetModuleInformation(hproc, handles[i], &mi, sizeof(mi)))
            continue;
        auto const base = reinterpret_cast<std::uintptr_t>(mi.lpBaseOfDll);
        if (va < base || va >= base + mi.SizeOfImage)
            continue;
        wchar_t path[MAX_PATH] {};
        ::GetModuleFileNameExW(hproc, handles[i], path, MAX_PATH);
        auto fname = std::filesystem::path(path).filename().string();
        if (fname.empty())
            fname = "unknown";
        for (auto &c : fname)
            c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
        char name[32];
        std::snprintf(name, sizeof(name), "rva_%llx",
            static_cast<unsigned long long>(va - base));
        info.dll = std::move(fname);
        info.name = name;
        return info;
    }
    return info;
}

ExportInfo const *lookup_export_follow(HANDLE hproc,
    std::vector<ModuleExports> const &mods, std::uintptr_t va)
{
    if (auto const *e = lookup_export(mods, va))
        return e;
    for (int n = 0; n < 4; ++n)
    {
        if (!follow_export_thunk(hproc, va))
            break;
        if (auto const *e = lookup_export(mods, va))
            return e;
    }
    return nullptr;
}

std::uint32_t align_up(std::uint32_t v, std::uint32_t a)
{
    return (v + a - 1) / a * a;
}

} // namespace

size_t rebuild_imports_remote(HANDLE hproc, std::uintptr_t actual_base,
    std::vector<std::uint8_t> &image, std::uint32_t iat_rva,
    std::uint32_t iat_size)
{
    if (!iat_rva || iat_size < 8 || iat_rva + iat_size > image.size())
        return 0;

    auto const peb = remote_peb(hproc);
    if (!peb)
    {
        std::cerr << "warning: could not read remote PEB" << std::endl;
        return 0;
    }

    auto const exports = collect_exports(hproc);
    std::cout << "loaded export maps for " << exports.size() << " modules"
              << std::endl;

    auto const count = (std::min)(
        static_cast<size_t>(iat_size / 8), kIatEntryLimit);
    struct Resolved
    {
        std::uint32_t slot_rva;
        ExportInfo info;
    };
    std::vector<Resolved> resolved;
    resolved.reserve(count);

    size_t failed = 0;
    for (size_t i = 0; i < count; ++i)
    {
        auto const slot_rva = iat_rva + static_cast<std::uint32_t>(i * 8);
        auto val = *reinterpret_cast<std::uint64_t *>(image.data() + slot_rva);
        if (!val)
            continue;

        // Already an export, or a jmp thunk in front of one?
        if (auto const *e = lookup_export_follow(hproc, exports,
                static_cast<std::uintptr_t>(val)))
        {
            resolved.push_back({ slot_rva, *e });
            continue;
        }

        // RVA into image?
        std::uintptr_t stub = 0;
        if (val < image.size())
            stub = actual_base + static_cast<std::uintptr_t>(val);
        else
            stub = static_cast<std::uintptr_t>(val);

        std::uint64_t api = 0;
        if (!emulate_stub(hproc, stub, peb, api) || !api)
        {
            ++failed;
            continue;
        }

        auto const *e = lookup_export_follow(hproc, exports,
            static_cast<std::uintptr_t>(api));
        ExportInfo fallback;
        if (!e)
        {
            fallback = named_rva_in_module(hproc, static_cast<std::uintptr_t>(api));
            if (!fallback.name.empty())
                e = &fallback;
        }
        if (!e)
        {
            std::uint8_t bytes[16] {};
            ::ReadProcessMemory(hproc, reinterpret_cast<LPCVOID>(api), bytes,
                sizeof(bytes), nullptr);
            MEMORY_BASIC_INFORMATION mbi {};
            wchar_t mapped[MAX_PATH] {};
            if (::VirtualQueryEx(hproc, reinterpret_cast<LPCVOID>(api), &mbi,
                    sizeof(mbi)))
            {
                ::GetMappedFileNameW(hproc, mbi.AllocationBase, mapped,
                    MAX_PATH);
            }
            std::cerr << "IAT unresolved slot rva 0x" << std::hex << slot_rva
                      << " val 0x" << val << " api 0x" << api;
            if (mapped[0])
                std::wcerr << L" map " << mapped;
            std::cerr << " bytes";
            for (auto b : bytes)
                std::cerr << " " << std::hex << static_cast<unsigned>(b);
            std::cerr << std::dec << std::endl;
            ++failed;
            continue;
        }
        resolved.push_back({ slot_rva, *e });
    }

    std::cout << "IAT resolved=" << resolved.size() << " failed=" << failed
              << std::endl;
    if (resolved.empty())
        return 0;

    // Group by DLL preserving first-seen order of slots (FirstThunk contiguous
    // runs per descriptor).
    struct Dir
    {
        std::string dll;
        std::vector<Resolved> entries;
    };
    std::vector<Dir> dirs;
    for (auto const &r : resolved)
    {
        if (dirs.empty() || dirs.back().dll != r.info.dll)
            dirs.push_back({ r.info.dll, {} });
        // Allow reopening earlier dir if interleaved
        Dir *target = &dirs.back();
        if (target->dll != r.info.dll)
        {
            auto it = std::find_if(dirs.begin(), dirs.end(),
                [&](Dir const &d) { return d.dll == r.info.dll; });
            if (it != dirs.end())
                target = &*it;
            else
            {
                dirs.push_back({ r.info.dll, {} });
                target = &dirs.back();
            }
        }
        target->entries.push_back(r);
    }

    // Build .wowim section buffer at end of image (memory layout).
    auto const e_lfanew = *reinterpret_cast<std::uint32_t *>(image.data() + 0x3C);
    auto const opt = e_lfanew + 24;
    auto const section_align =
        *reinterpret_cast<std::uint32_t *>(image.data() + opt + 32);
    auto num_sections =
        *reinterpret_cast<std::uint16_t *>(image.data() + e_lfanew + 6);
    auto const size_opt =
        *reinterpret_cast<std::uint16_t *>(image.data() + e_lfanew + 20);
    auto const sec_table = opt + size_opt;

    // Current SizeOfImage
    auto size_of_image =
        *reinterpret_cast<std::uint32_t *>(image.data() + opt + 56);
    auto const new_sec_va = align_up(size_of_image, section_align);

    std::vector<std::uint8_t> sec;
    auto write_bytes = [&](void const *p, size_t n) {
        auto const off = sec.size();
        sec.resize(off + n);
        std::memcpy(sec.data() + off, p, n);
        return static_cast<std::uint32_t>(new_sec_va + off);
    };
    auto write_str = [&](std::string const &s) {
        return write_bytes(s.c_str(), s.size() + 1);
    };
    auto write_u16 = [&](std::uint16_t v) { return write_bytes(&v, 2); };

    // Per-dir: ILT thunks
    std::vector<IMAGE_IMPORT_DESCRIPTOR> descriptors;
    descriptors.reserve(dirs.size());

    for (auto &dir : dirs)
    {
        IMAGE_IMPORT_DESCRIPTOR desc {};
        desc.Name = write_str(dir.dll);
        desc.OriginalFirstThunk = new_sec_va + static_cast<DWORD>(sec.size());

        // FirstThunk = first slot RVA in this group
        desc.FirstThunk = dir.entries.front().slot_rva;

        for (auto const &e : dir.entries)
        {
            IMAGE_THUNK_DATA64 thunk {};
            auto const hint_rva = write_u16(e.info.hint);
            write_str(e.info.name);
            if ((hint_rva + e.info.name.size() + 1) % 2 != 0)
            {
                std::uint8_t z = 0;
                write_bytes(&z, 1);
            }
            thunk.u1.AddressOfData = hint_rva;
            // Patch IAT slot to same thunk value (bound-style / loader-ready)
            *reinterpret_cast<std::uint64_t *>(image.data() + e.slot_rva) =
                thunk.u1.AddressOfData;
            write_bytes(&thunk, sizeof(thunk));
        }
        IMAGE_THUNK_DATA64 zero {};
        write_bytes(&zero, sizeof(zero));
        descriptors.push_back(desc);
    }

    auto const import_dir_rva = new_sec_va + static_cast<DWORD>(sec.size());
    for (auto const &d : descriptors)
        write_bytes(&d, sizeof(d));
    IMAGE_IMPORT_DESCRIPTOR null_desc {};
    write_bytes(&null_desc, sizeof(null_desc));

    auto const sec_raw = align_up(static_cast<std::uint32_t>(sec.size()),
        section_align);
    sec.resize(sec_raw, 0);

    // Append section to image
    image.resize(new_sec_va + sec_raw, 0);
    std::memcpy(image.data() + new_sec_va, sec.data(), sec.size());

    // Add section header
    auto const new_hdr_off = sec_table + num_sections * 40;
    if (new_hdr_off + 40 > image.size())
    {
        // headers area should already cover this for typical PEs; if not, abort
        std::cerr << "warning: no room for new section header" << std::endl;
        return resolved.size();
    }
    IMAGE_SECTION_HEADER sh {};
    std::memcpy(sh.Name, ".wowim", 6);
    sh.Misc.VirtualSize = sec_raw;
    sh.VirtualAddress = new_sec_va;
    sh.SizeOfRawData = sec_raw;
    sh.PointerToRawData = new_sec_va; // memory layout
    sh.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;
    std::memcpy(image.data() + new_hdr_off, &sh, sizeof(sh));

    *reinterpret_cast<std::uint16_t *>(image.data() + e_lfanew + 6) =
        static_cast<std::uint16_t>(num_sections + 1);
    *reinterpret_cast<std::uint32_t *>(image.data() + opt + 56) =
        new_sec_va + sec_raw; // SizeOfImage

    // Data directories: Import + IAT
    // PE32+ DataDirectory at opt+112
    auto const dd = opt + 112;
    *reinterpret_cast<std::uint32_t *>(image.data() + dd + 1 * 8) =
        import_dir_rva;
    *reinterpret_cast<std::uint32_t *>(image.data() + dd + 1 * 8 + 4) =
        static_cast<std::uint32_t>(
            (descriptors.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR));
    *reinterpret_cast<std::uint32_t *>(image.data() + dd + 12 * 8) = iat_rva;
    *reinterpret_cast<std::uint32_t *>(image.data() + dd + 12 * 8 + 4) = iat_size;

    return resolved.size();
}
