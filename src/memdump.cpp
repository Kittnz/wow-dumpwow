/*
    External memdump for Eidolon-packed Wow clients (see memdump.hpp).
*/

#define NOMINMAX
#include "memdump.hpp"
#include "iat_remote.hpp"
#include "raii_proc.hpp"

#include <Windows.h>
#include <Psapi.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "User32.lib")

namespace fs = std::filesystem;

namespace
{

constexpr std::uint64_t kPreferredImageBase = 0x140000000ull;
constexpr float kMinTextRatio = 0.85f;
constexpr double kWindowWaitSec = 120.0;
constexpr double kDecryptTimeoutSec = 60.0;

struct DiskPeInfo
{
    std::uint64_t image_base = 0;
    std::uint32_t size_of_image = 0;
    std::uint32_t text_va = 0;
    std::uint32_t text_vs = 0;
    std::uint32_t reloc_rva = 0;
    std::uint32_t reloc_size = 0;
    std::vector<std::uint8_t> reloc_bytes; // from disk file (trusted)
    bool has_loader_import = false;
};

std::string to_lower(std::string s)
{
    for (auto &c : s)
        c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool ends_with_ci(std::string const &s, std::string const &suffix)
{
    if (s.size() < suffix.size())
        return false;
    auto const lower = to_lower(s);
    return lower.compare(lower.size() - suffix.size(), suffix.size(),
        to_lower(suffix)) == 0;
}

std::uint32_t rva_to_file_off(std::vector<IMAGE_SECTION_HEADER> const &secs,
    std::uint32_t rva)
{
    for (auto const &s : secs)
    {
        auto const span = (std::max)(s.Misc.VirtualSize, s.SizeOfRawData);
        if (rva >= s.VirtualAddress && rva < s.VirtualAddress + span)
            return s.PointerToRawData + (rva - s.VirtualAddress);
    }
    return 0;
}

bool parse_disk_pe(fs::path const &exe_path, DiskPeInfo &out)
{
    std::ifstream in(exe_path, std::ios::binary);
    if (!in)
        return false;

    in.seekg(0, std::ios::end);
    auto const file_size = static_cast<std::size_t>(in.tellg());
    in.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> data(file_size);
    if (!in.read(reinterpret_cast<char *>(data.data()),
            static_cast<std::streamsize>(file_size)))
        return false;

    if (file_size < sizeof(IMAGE_DOS_HEADER))
        return false;
    auto const dos = reinterpret_cast<IMAGE_DOS_HEADER *>(data.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    if (static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) >
        file_size)
        return false;

    auto const nt = reinterpret_cast<IMAGE_NT_HEADERS64 *>(
        data.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return false;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return false;

    out.image_base = nt->OptionalHeader.ImageBase;
    out.size_of_image = nt->OptionalHeader.SizeOfImage;
    out.reloc_rva = nt->OptionalHeader
                        .DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                        .VirtualAddress;
    out.reloc_size = nt->OptionalHeader
                         .DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                         .Size;

    std::vector<IMAGE_SECTION_HEADER> secs(nt->FileHeader.NumberOfSections);
    auto const sec_off = dos->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) +
        nt->FileHeader.SizeOfOptionalHeader;
    if (sec_off + secs.size() * sizeof(IMAGE_SECTION_HEADER) > file_size)
        return false;
    std::memcpy(secs.data(), data.data() + sec_off,
        secs.size() * sizeof(IMAGE_SECTION_HEADER));

    for (auto const &s : secs)
    {
        char name[9] {};
        std::memcpy(name, s.Name, 8);
        if (std::strcmp(name, ".text") == 0)
        {
            out.text_va = s.VirtualAddress;
            out.text_vs = s.Misc.VirtualSize;
            break;
        }
    }

    if (out.reloc_rva && out.reloc_size)
    {
        auto const off = rva_to_file_off(secs, out.reloc_rva);
        if (off && off + out.reloc_size <= file_size)
        {
            out.reloc_bytes.assign(data.begin() + off,
                data.begin() + off + out.reloc_size);
        }
    }

    // Scan import DLL names for *_loader.dll
    auto const import_rva =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
            .VirtualAddress;
    if (import_rva)
    {
        auto off = rva_to_file_off(secs, import_rva);
        while (off && off + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= file_size)
        {
            auto const desc =
                reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(data.data() + off);
            if (!desc->Name)
                break;
            auto const name_off = rva_to_file_off(secs, desc->Name);
            if (name_off && name_off < file_size)
            {
                std::string name(reinterpret_cast<char *>(data.data() + name_off));
                if (ends_with_ci(name, "_loader.dll"))
                {
                    out.has_loader_import = true;
                    break;
                }
            }
            off += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        }
    }

    return true;
}

bool process_alive(HANDLE hproc)
{
    DWORD code = 0;
    if (!::GetExitCodeProcess(hproc, &code))
        return false;
    return code == STILL_ACTIVE;
}

struct EnumCtx
{
    DWORD pid = 0;
    bool found = false;
};

BOOL CALLBACK enum_windows_proc(HWND hwnd, LPARAM lparam)
{
    auto *ctx = reinterpret_cast<EnumCtx *>(lparam);
    if (!::IsWindowVisible(hwnd))
        return TRUE;
    DWORD wpid = 0;
    ::GetWindowThreadProcessId(hwnd, &wpid);
    if (wpid != ctx->pid)
        return TRUE;
    RECT rect {};
    if (::GetWindowRect(hwnd, &rect))
    {
        auto const w = rect.right - rect.left;
        auto const h = rect.bottom - rect.top;
        if (w >= 200 && h >= 150)
        {
            ctx->found = true;
            return FALSE;
        }
    }
    return TRUE;
}

bool wait_for_main_window(DWORD pid, double timeout_sec)
{
    EnumCtx ctx { pid, false };
    auto const deadline =
        std::chrono::steady_clock::now() +
        std::chrono::duration_cast<std::chrono::steady_clock::duration>(
            std::chrono::duration<double>(timeout_sec));
    while (std::chrono::steady_clock::now() < deadline)
    {
        ::EnumWindows(enum_windows_proc, reinterpret_cast<LPARAM>(&ctx));
        if (ctx.found)
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    return false;
}

bool launch_unsuspended(fs::path const &path, PROCESS_INFORMATION &proc_info)
{
    STARTUPINFOW si {};
    si.cb = sizeof(si);
    std::memset(&proc_info, 0, sizeof(proc_info));

    auto path_w = path.wstring();
    std::vector<wchar_t> path_raw(path_w.begin(), path_w.end());
    path_raw.push_back(L'\0');
    auto const dir_w = path.parent_path().wstring();

    return !!::CreateProcessW(path_raw.data(), nullptr, nullptr, nullptr,
        FALSE, CREATE_UNICODE_ENVIRONMENT, nullptr,
        dir_w.empty() ? nullptr : dir_w.c_str(), &si, &proc_info);
}

bool find_main_module(HANDLE hproc, fs::path const &exe_path,
    std::uintptr_t &base, std::uint32_t &size)
{
    DWORD needed = 0;
    if (!::EnumProcessModulesEx(hproc, nullptr, 0, &needed, LIST_MODULES_ALL))
        return false;
    auto const count = (std::max)(
        needed / static_cast<DWORD>(sizeof(HMODULE)), static_cast<DWORD>(1));
    std::vector<HMODULE> mods(count);
    if (!::EnumProcessModulesEx(hproc, mods.data(),
            static_cast<DWORD>(mods.size() * sizeof(HMODULE)), &needed,
            LIST_MODULES_ALL))
        return false;
    auto const n = needed / static_cast<DWORD>(sizeof(HMODULE));
    auto const want = fs::absolute(exe_path).lexically_normal().wstring();
    std::wstring want_lower = want;
    for (auto &c : want_lower)
        c = static_cast<wchar_t>(::towlower(c));

    for (DWORD i = 0; i < n; ++i)
    {
        wchar_t buf[1024] {};
        if (!::GetModuleFileNameExW(hproc, mods[i], buf, 1024))
            continue;
        std::wstring path = fs::absolute(buf).lexically_normal().wstring();
        for (auto &c : path)
            c = static_cast<wchar_t>(::towlower(c));
        if (path == want_lower)
        {
            MODULEINFO mi {};
            if (!::GetModuleInformation(hproc, mods[i], &mi, sizeof(mi)))
                return false;
            base = reinterpret_cast<std::uintptr_t>(mi.lpBaseOfDll);
            size = mi.SizeOfImage;
            return true;
        }
    }

    if (n)
    {
        MODULEINFO mi {};
        if (::GetModuleInformation(hproc, mods[0], &mi, sizeof(mi)))
        {
            base = reinterpret_cast<std::uintptr_t>(mi.lpBaseOfDll);
            size = mi.SizeOfImage;
            return true;
        }
    }
    return false;
}

bool page_looks_plaintext(std::uint8_t const *page, size_t len)
{
    if (len < 64)
        return false;

    // Entropy: ciphertext sits near 8.0; real code with padding is lower.
    unsigned hist[256] {};
    size_t nz = 0;
    for (size_t i = 0; i < len; ++i)
    {
        ++hist[page[i]];
        if (page[i])
            ++nz;
    }
    if (nz < 32)
        return false;

    double ent = 0.0;
    for (unsigned c : hist)
    {
        if (!c)
            continue;
        double p = static_cast<double>(c) / static_cast<double>(len);
        ent -= p * std::log2(p);
    }

    // Common x64 prologues / int3 padding.
    auto has = [&](std::initializer_list<std::uint8_t> seq) {
        auto const n = seq.size();
        for (size_t i = 0; i + n <= len; ++i)
        {
            bool ok = true;
            size_t j = 0;
            for (auto b : seq)
            {
                if (page[i + j] != b)
                {
                    ok = false;
                    break;
                }
                ++j;
            }
            if (ok)
                return true;
        }
        return false;
    };

    bool const prologue =
        has({0x48, 0x89, 0x5C, 0x24}) || // mov [rsp+…], rbx
        has({0x48, 0x83, 0xEC}) ||       // sub rsp, imm
        has({0x48, 0x8B, 0xC4}) ||       // mov rax, rsp
        has({0x40, 0x53}) ||             // push rbx
        has({0x55, 0x48, 0x8B, 0xEC}) || // push rbp; mov rbp, rsp
        has({0x4C, 0x8B, 0xDC}) ||       // mov r11, rsp
        has({0xCC, 0xCC, 0xCC, 0xCC});   // int3 padding

    if (prologue && ent < 7.85)
        return true;
    if (ent < 7.35)
        return true;
    return false;
}

std::uint32_t count_noaccess_pages(HANDLE hproc, std::uintptr_t region_base,
    std::uint32_t region_size)
{
    std::uint32_t n = 0;
    MEMORY_BASIC_INFORMATION mbi {};
    auto addr = region_base;
    auto const end = region_base + region_size;
    while (addr < end)
    {
        if (!::VirtualQueryEx(hproc, reinterpret_cast<LPCVOID>(addr), &mbi,
                sizeof(mbi)))
            break;
        auto const region_end =
            reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (mbi.State == MEM_COMMIT && (mbi.Protect & 0xFF) == PAGE_NOACCESS)
        {
            auto page = (std::max)(addr,
                reinterpret_cast<std::uintptr_t>(mbi.BaseAddress));
            auto const page_end = (std::min)(end, region_end);
            for (; page + 0x1000 <= page_end; page += 0x1000)
                ++n;
        }
        addr = (std::max)(region_end, addr + 0x1000);
    }
    return n;
}

// Eidolon leaves untouched .text as PAGE_NOACCESS and decrypts on *execute*
// faults, then resumes the faulting thread with NtContinue. Private shellcode
// never runs (CFG), and letting that thread execute the page crashes Wow.
// Hook ntdll!NtContinue / NtContinueEx in place: when Context.Rip is the page
// we just probed, rewrite it to kernel32!ExitThread before the real syscall.
// The hook body sits in a CFG-valid kernel32 export and is reached by a
// direct jmp, which CFG does not check.
bool force_decrypt_region(HANDLE hproc, std::uintptr_t region_base,
    std::uint32_t region_size,
    std::unordered_map<std::uint32_t, std::vector<std::uint8_t>> *snaps = nullptr)
{
    auto const k32mod = ::GetModuleHandleW(L"kernel32.dll");
    auto const ntdll = ::GetModuleHandleW(L"ntdll.dll");
    auto const p_exit = reinterpret_cast<std::uintptr_t>(
        ::GetProcAddress(k32mod, "ExitThread"));
    auto const p_nt = reinterpret_cast<std::uintptr_t>(
        ::GetProcAddress(ntdll, "NtContinue"));
    auto const p_nt_ex = reinterpret_cast<std::uintptr_t>(
        ::GetProcAddress(ntdll, "NtContinueEx"));
    auto cave_fn = reinterpret_cast<std::uintptr_t>(
        ::GetProcAddress(k32mod, "AddLocalAlternateComputerNameW"));
    if (!cave_fn)
        cave_fn = reinterpret_cast<std::uintptr_t>(
            ::GetProcAddress(k32mod, "GetDurationFormat"));
    if (!p_exit || !p_nt || !p_nt_ex || !cave_fn)
    {
        std::cerr << "warning: NtContinue hook targets not found" << std::endl;
        return false;
    }

    std::vector<std::uintptr_t> pages;
    MEMORY_BASIC_INFORMATION mbi {};
    auto addr = region_base;
    auto const end = region_base + region_size;
    std::uint32_t skipped = 0;
    while (addr < end)
    {
        if (!::VirtualQueryEx(hproc, reinterpret_cast<LPCVOID>(addr), &mbi,
                sizeof(mbi)))
            break;
        auto const region_end =
            reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        auto const prot = mbi.Protect & 0xFF;
        if (mbi.State == MEM_COMMIT && prot == PAGE_NOACCESS)
        {
            auto page = (std::max)(addr,
                reinterpret_cast<std::uintptr_t>(mbi.BaseAddress));
            auto const page_end = (std::min)(end, region_end);
            for (; page < page_end; page += 0x1000)
                pages.push_back(page);
        }
        else
        {
            skipped += static_cast<std::uint32_t>(
                (std::min)(end, region_end) - addr) / 0x1000;
        }
        if (region_end <= addr)
            break;
        addr = region_end;
    }

    if (pages.empty())
    {
        std::cout << "no NOACCESS .text pages (already decrypted? skipped ~"
                  << skipped << ")" << std::endl;
        return true;
    }
    std::cout << "execute-probing " << pages.size()
              << " NOACCESS pages (skipped non-NOACCESS ~" << skipped << ") ..."
              << std::endl;

    // Cave lives inside a CFG-valid export. armed qword at +0x300.
    constexpr size_t kArmed = 0x300;
    constexpr size_t kSteal = 8;
    auto const armed_ea = cave_fn + kArmed;

    std::uint8_t orig_nt[kSteal] {};
    std::uint8_t orig_ex[kSteal] {};
    SIZE_T nread = 0;
    if (!::ReadProcessMemory(hproc, reinterpret_cast<LPCVOID>(p_nt), orig_nt,
            kSteal, &nread) ||
        !::ReadProcessMemory(hproc, reinterpret_cast<LPCVOID>(p_nt_ex), orig_ex,
            kSteal, &nread) ||
        orig_nt[0] != 0x4C || orig_nt[1] != 0x8B || orig_nt[2] != 0xD1 ||
        orig_ex[0] != 0x4C || orig_ex[1] != 0x8B || orig_ex[2] != 0xD1)
    {
        std::cerr << "warning: unexpected NtContinue stub" << std::endl;
        return false;
    }

    // check (rcx = CONTEXT, r11 = stolen stub to resume):
    //   armed+0 = page, armed+8 = probe tid, armed+0x10 = call count,
    //   armed+0x14 = match count.
    //   Redirect only the probe thread, and only when its Rip is on that page.
    //   jmp r11
    std::vector<std::uint8_t> blob(0x320, 0xCC);
    size_t o = 0;
    auto emit = [&](std::initializer_list<std::uint8_t> bs) {
        for (auto b : bs)
            blob[o++] = b;
    };
    auto emit_u32 = [&](std::uint32_t v) {
        std::memcpy(blob.data() + o, &v, 4);
        o += 4;
    };
    auto emit_u64 = [&](std::uint64_t v) {
        std::memcpy(blob.data() + o, &v, 8);
        o += 8;
    };
    auto emit_i32_at = [&](size_t at, std::int32_t v) {
        std::memcpy(blob.data() + at, &v, 4);
    };

    auto const calls_ea = armed_ea + 0x10;
    auto const matches_ea = armed_ea + 0x14;
    // Filled by the hook while the page is still decrypted, before ExitThread.
    auto const slot = reinterpret_cast<std::uintptr_t>(::VirtualAllocEx(
        hproc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    auto const check = o;
    emit({0x50, 0x53, 0x51});                   // push rax, rbx, rcx
    emit({0x48, 0xB8});
    emit_u64(calls_ea);
    emit({0xFF, 0x00});                         // inc calls
    emit({0x48, 0xB8});
    emit_u64(armed_ea);
    emit({0x48, 0x8B, 0x18});                   // rbx = page
    emit({0x48, 0x8B, 0x40, 0x08});             // rax = tid
    emit({0x48, 0x85, 0xDB});
    emit({0x74, 0x00});
    auto const jz_page = o - 1;
    emit({0x48, 0x85, 0xC0});
    emit({0x74, 0x00});
    auto const jz_tid = o - 1;
    emit({0x65, 0x48, 0x8B, 0x0C, 0x25, 0x30, 0x00, 0x00, 0x00}); // rcx = TEB
    emit({0x48, 0x39, 0x41, 0x48});             // cmp [teb+UniqueThread], rax
    emit({0x75, 0x00});
    auto const jne_tid = o - 1;
    emit({0x48, 0x8B, 0x0C, 0x24});             // rcx = CONTEXT
    emit({0x48, 0x39, 0x99, 0xF8, 0x00, 0x00, 0x00}); // cmp [rcx+Rip], rbx
    emit({0x72, 0x00});
    auto const jb = o - 1;
    emit({0x48, 0x81, 0xC3, 0x00, 0x10, 0x00, 0x00}); // add rbx, 0x1000
    emit({0x48, 0x39, 0x99, 0xF8, 0x00, 0x00, 0x00});
    emit({0x73, 0x00});
    auto const jae = o - 1;
    emit({0x48, 0xB8});
    emit_u64(p_exit);
    emit({0x48, 0x89, 0x81, 0xF8, 0x00, 0x00, 0x00}); // Rip = ExitThread
    emit({0x48, 0xC7, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    emit({0x48, 0xC7, 0x81, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    emit({0x48, 0xB8});
    emit_u64(armed_ea);
    emit({0x48, 0x83, 0x20, 0x00});             // page = 0
    emit({0x48, 0x83, 0x60, 0x08, 0x00});       // tid = 0
    emit({0x48, 0xB8});
    emit_u64(matches_ea);
    emit({0xFF, 0x00});                         // inc matches
    emit({0xE9, 0x00, 0x00, 0x00, 0x00});       // jmp copy (patched below)
    auto const jmp_copy = o - 4;
    auto const skip = o;
    auto patch_jcc = [&](size_t at) {
        auto const rel = skip - (at + 1);
        if (rel > 127)
        {
            std::cerr << "warning: NtContinue hook branch too far" << std::endl;
            return false;
        }
        blob[at] = static_cast<std::uint8_t>(rel);
        return true;
    };
    if (!patch_jcc(jz_page) || !patch_jcc(jz_tid) || !patch_jcc(jne_tid) ||
        !patch_jcc(jb) || !patch_jcc(jae))
        return false;
    emit({0x59, 0x5B, 0x58});                   // pop rcx, rbx, rax
    emit({0x41, 0xFF, 0xE3});                   // jmp r11
    if (slot)
    {
        auto const copy_at = o;
        emit_i32_at(jmp_copy, static_cast<std::int32_t>(copy_at - (jmp_copy + 4)));
        emit({0x56, 0x57});                     // push rsi, rdi
        emit({0x48, 0x8D, 0xB3, 0x00, 0xF0, 0xFF, 0xFF}); // rsi = rbx-0x1000
        emit({0x48, 0xBF});
        emit_u64(slot);
        emit({0xB9, 0x00, 0x10, 0x00, 0x00});   // ecx = 0x1000
        emit({0xF3, 0xA4});                     // rep movsb
        emit({0x5F, 0x5E});                     // pop rdi, rsi
        emit({0xE9});
        auto const back_skip = o;
        emit_u32(0);
        emit_i32_at(back_skip, static_cast<std::int32_t>(skip - (back_skip + 4)));
    }
    else
        emit_i32_at(jmp_copy, static_cast<std::int32_t>(skip - (jmp_copy + 4)));

    auto add_entry = [&](std::uintptr_t target, std::uint8_t const *stolen) {
        auto const entry = o;
        auto const lea = o;
        emit({0x4C, 0x8D, 0x1D});               // lea r11, [rip+stolen]
        emit_u32(0);
        emit({0xE9});
        auto const jrel = o;
        emit_u32(0);
        auto const stolen_at = o;
        emit_i32_at(lea + 3, static_cast<std::int32_t>(stolen_at - (lea + 7)));
        emit_i32_at(jrel, static_cast<std::int32_t>(check - (jrel + 4)));
        for (size_t i = 0; i < kSteal; ++i)
            blob[o++] = stolen[i];
        emit({0xE9});
        auto const back = o;
        emit_u32(0);
        auto const resume = target + kSteal;
        emit_i32_at(back,
            static_cast<std::int32_t>(resume - (cave_fn + back + 4)));
        return entry;
    };

    auto const entry_nt = add_entry(p_nt, orig_nt);
    auto const entry_ex = add_entry(p_nt_ex, orig_ex);
    if (o > kArmed)
    {
        std::cerr << "warning: NtContinue hook cave too large" << std::endl;
        return false;
    }

    std::vector<std::uint8_t> orig_cave(o);
    if (!::ReadProcessMemory(hproc, reinterpret_cast<LPCVOID>(cave_fn),
            orig_cave.data(), orig_cave.size(), &nread))
    {
        std::cerr << "warning: failed to read hook cave" << std::endl;
        return false;
    }

    DWORD old_cave = 0, old_nt = 0, old_ex = 0;
    if (!::VirtualProtectEx(hproc, reinterpret_cast<LPVOID>(cave_fn), 0x400,
            PAGE_EXECUTE_READWRITE, &old_cave) ||
        !::VirtualProtectEx(hproc, reinterpret_cast<LPVOID>(p_nt), 16,
            PAGE_EXECUTE_READWRITE, &old_nt) ||
        !::VirtualProtectEx(hproc, reinterpret_cast<LPVOID>(p_nt_ex), 16,
            PAGE_EXECUTE_READWRITE, &old_ex))
    {
        std::cerr << "warning: VirtualProtectEx(NtContinue hook) failed" << std::endl;
        return false;
    }

    SIZE_T written = 0;
    std::uint8_t armed_zero[0x18] {};
    if (!::WriteProcessMemory(hproc, reinterpret_cast<LPVOID>(cave_fn),
            blob.data(), o, &written) ||
        !::WriteProcessMemory(hproc, reinterpret_cast<LPVOID>(armed_ea),
            armed_zero, sizeof(armed_zero), &written))
    {
        std::cerr << "warning: failed to write NtContinue hook" << std::endl;
        ::WriteProcessMemory(hproc, reinterpret_cast<LPVOID>(cave_fn),
            orig_cave.data(), orig_cave.size(), &written);
        return false;
    }

    auto plant = [&](std::uintptr_t target, size_t entry) {
        std::uint8_t jmp[8];
        std::memset(jmp, 0x90, sizeof(jmp));
        jmp[0] = 0xE9;
        auto const rel = static_cast<std::int32_t>(
            (cave_fn + entry) - (target + 5));
        std::memcpy(jmp + 1, &rel, 4);
        ::WriteProcessMemory(hproc, reinterpret_cast<LPVOID>(target), jmp,
            kSteal, &written);
    };
    plant(p_nt, entry_nt);
    plant(p_nt_ex, entry_ex);
    ::FlushInstructionCache(hproc, reinterpret_cast<LPCVOID>(p_nt), 16);
    ::FlushInstructionCache(hproc, reinterpret_cast<LPCVOID>(p_nt_ex), 16);
    ::FlushInstructionCache(hproc, reinterpret_cast<LPCVOID>(cave_fn), o);

    auto restore_hooks = [&]() {
        if (!process_alive(hproc))
            return;
        ::WriteProcessMemory(hproc, reinterpret_cast<LPVOID>(p_nt), orig_nt,
            kSteal, &written);
        ::WriteProcessMemory(hproc, reinterpret_cast<LPVOID>(p_nt_ex), orig_ex,
            kSteal, &written);
        ::FlushInstructionCache(hproc, reinterpret_cast<LPCVOID>(p_nt), 16);
        ::FlushInstructionCache(hproc, reinterpret_cast<LPCVOID>(p_nt_ex), 16);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        ::WriteProcessMemory(hproc, reinterpret_cast<LPVOID>(cave_fn),
            orig_cave.data(), orig_cave.size(), &written);
        DWORD ignored = 0;
        ::VirtualProtectEx(hproc, reinterpret_cast<LPVOID>(p_nt), 16, old_nt,
            &ignored);
        ::VirtualProtectEx(hproc, reinterpret_cast<LPVOID>(p_nt_ex), 16, old_ex,
            &ignored);
        ::VirtualProtectEx(hproc, reinterpret_cast<LPVOID>(cave_fn), 0x400,
            old_cave, &ignored);
    };

    std::uint32_t decrypted = 0;
    std::uint32_t failed = 0;
    auto limit = pages.size();
    char limit_env[32] {};
    if (::GetEnvironmentVariableA("DUMP_DECRYPT_LIMIT", limit_env,
            sizeof(limit_env)) > 0)
    {
        auto const n = std::strtoull(limit_env, nullptr, 10);
        if (n > 0 && n < limit)
            limit = static_cast<std::size_t>(n);
    }
    auto read_u32 = [&](std::uintptr_t ea) {
        std::uint32_t v = 0;
        SIZE_T nr = 0;
        ::ReadProcessMemory(hproc, reinterpret_cast<LPCVOID>(ea), &v,
            sizeof(v), &nr);
        return v;
    };
    // Eidolon re-encrypts a page once the probe thread leaves it. Copy the
    // plaintext before the next page, or the later image read sees NOACCESS.
    auto capture = [&](std::uintptr_t page, bool use_slot = true) {
        if (!snaps)
            return;
        auto const rva = static_cast<std::uint32_t>(page - region_base);
        std::vector<std::uint8_t> buf(0x1000);
        SIZE_T nread = 0;
        auto ok = ::ReadProcessMemory(hproc, reinterpret_cast<LPCVOID>(page),
            buf.data(), buf.size(), &nread) && nread >= buf.size();
        if (!ok && use_slot && slot)
        {
            nread = 0;
            ok = ::ReadProcessMemory(hproc, reinterpret_cast<LPCVOID>(slot),
                buf.data(), buf.size(), &nread) && nread >= buf.size();
        }
        if (!ok)
            return;
        (*snaps)[rva] = std::move(buf);
    };
    // Pages already decrypted can be re-locked while the probe runs.
    if (snaps)
    {
        for (auto page = region_base; page + 0x1000 <= region_base + region_size;
             page += 0x1000)
            capture(page, false);
        std::cout << "  snapshotted " << snaps->size()
                  << " readable .text pages before probe" << std::endl;
    }
    for (std::size_t i = 0; i < limit; ++i)
    {
        if (!process_alive(hproc))
        {
            std::cerr << "process died after " << decrypted << " decrypts ("
                      << i << "/" << pages.size() << ")" << std::endl;
            break;
        }

        auto const page = pages[i];
        // Game threads decrypt pages while the sweep runs. Starting a probe
        // on a page that is already RX executes it and crashes Wow.
        MEMORY_BASIC_INFORMATION now {};
        if (::VirtualQueryEx(hproc, reinterpret_cast<LPCVOID>(page), &now,
                sizeof(now)) &&
            (now.Protect & 0xFF) != PAGE_NOACCESS)
        {
            capture(page);
            ++decrypted;
            continue;
        }

        DWORD tid = 0;
        HANDLE ht = ::CreateRemoteThread(hproc, nullptr, 0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(page), nullptr,
            CREATE_SUSPENDED, &tid);
        std::uint64_t arm[2] = { page, tid };
        if (!ht || !tid ||
            !::WriteProcessMemory(hproc, reinterpret_cast<LPVOID>(armed_ea),
                arm, sizeof(arm), &written))
        {
            if (ht)
                ::CloseHandle(ht);
            ++failed;
            continue;
        }
        auto const matches_before = read_u32(matches_ea);
        ::ResumeThread(ht);
        // Hook rewrites NtContinue so this thread exits via ExitThread.
        auto const w = ::WaitForSingleObject(ht, 2000);
        if (w == WAIT_TIMEOUT && read_u32(matches_ea) == matches_before)
        {
            // Resume missed the hook and the thread is inside game code.
            ::SuspendThread(ht);
        }
        ::CloseHandle(ht);
        if (w != WAIT_OBJECT_0 && !process_alive(hproc))
        {
            std::cerr << "process died during page CRT @" << std::hex << page
                      << std::dec << std::endl;
            break;
        }

        MEMORY_BASIC_INFORMATION pmbi {};
        if (::VirtualQueryEx(hproc, reinterpret_cast<LPCVOID>(page), &pmbi,
                sizeof(pmbi)) &&
            (pmbi.Protect & 0xFF) != PAGE_NOACCESS)
        {
            capture(page);
            ++decrypted;
        }
        else
            ++failed;

        if (((i + 1) & 0x3FF) == 0 || (i + 1) == limit)
            std::cout << "  decrypted " << decrypted << "/" << (i + 1)
                      << " calls " << read_u32(calls_ea)
                      << " matches " << read_u32(matches_ea)
                      << std::endl;
    }

    restore_hooks();
    if (slot)
        ::VirtualFreeEx(hproc, reinterpret_cast<LPVOID>(slot), 0, MEM_RELEASE);

    std::cout << "execute-decrypted " << decrypted << "/" << pages.size()
              << " pages (failed " << failed << ")" << std::endl;
    return decrypted > 0;
}

float sample_plaintext_ratio(HANDLE hproc, std::uintptr_t base,
    std::uint32_t text_va, std::uint32_t text_vs)
{
    if (!text_vs)
        return 0.f;

    constexpr std::uint32_t page = 0x1000;
    // Dense sample across .text (every 16th page + ends).
    std::uint32_t step = page * 16;
    if (step > text_vs / 64)
        step = (std::max)(page, text_vs / 64);

    int plain = 0;
    int total = 0;
    int failed = 0;
    std::uint8_t buf[page];

    for (std::uint32_t off = 0; off < text_vs; off += step)
    {
        auto addr = reinterpret_cast<LPVOID>(base + text_va + off);
        SIZE_T nread = 0;
        auto ok = ::ReadProcessMemory(hproc, addr, buf, page, &nread);
        ++total;
        if (!ok || nread < 64)
        {
            ++failed;
            continue;
        }
        if (page_looks_plaintext(buf, static_cast<size_t>(nread)))
            ++plain;
    }

    if (failed)
        std::cout << "  (sample: " << failed << " pages still NOACCESS)"
                  << std::endl;
    // Count unreadable pages as not-yet-decrypted.
    return total ? static_cast<float>(plain) / static_cast<float>(total) : 0.f;
}

float wait_for_decrypt(HANDLE hproc, std::uintptr_t base, DiskPeInfo const &pe,
    double timeout_sec)
{
    if (pe.text_vs)
    {
        std::cout << "forcing .text decrypt via execute probe (Eidolon) ..."
                  << std::endl;
        force_decrypt_region(hproc, base + pe.text_va, pe.text_vs);
    }

    auto const deadline =
        std::chrono::steady_clock::now() +
        std::chrono::duration_cast<std::chrono::steady_clock::duration>(
            std::chrono::duration<double>(timeout_sec));
    float ratio = 0.f;
    while (true)
    {
        if (!process_alive(hproc))
        {
            std::cerr << "warning: process exited during decrypt poll"
                      << std::endl;
            return ratio;
        }
        ratio = sample_plaintext_ratio(hproc, base, pe.text_va, pe.text_vs);
        std::cout << "  .text sample plaintext pages: " << std::fixed
                  << (ratio * 100.f) << "%" << std::endl;
        if (ratio >= kMinTextRatio)
            return ratio;
        if (std::chrono::steady_clock::now() >= deadline)
            return ratio;
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

std::vector<std::uint8_t> read_memory(HANDLE hproc, std::uintptr_t base,
    std::uint32_t size)
{
    if (!process_alive(hproc))
        throw std::runtime_error("target process already exited before RPM");

    std::vector<std::uint8_t> out(size);
    constexpr std::uint32_t page = 0x1000;
    std::uint8_t staging[page];
    bool got_any = false;
    int failed = 0;

    for (std::uint32_t off = 0; off < size; off += page)
    {
        if (off && (off & 0xFFFFF) == 0 && !process_alive(hproc))
            throw std::runtime_error("target exited during ReadProcessMemory");

        auto const chunk = (std::min)(page, size - off);
        SIZE_T nread = 0;
        auto ok = ::ReadProcessMemory(hproc,
            reinterpret_cast<LPCVOID>(base + off), staging, chunk, &nread);
        if (ok && nread)
        {
            std::memcpy(out.data() + off, staging, nread);
            got_any = true;
            continue;
        }
        // Do NOT VirtualProtectEx — that exposes Eidolon ciphertext without
        // decrypting. Leave zeros for still-NOACCESS pages.
        ++failed;
    }

    if (!got_any)
        throw std::runtime_error("ReadProcessMemory (no pages readable)");
    if (failed)
        std::cerr << "warning: " << failed
                  << " pages unreadable (left as zero; still encrypted?)"
                  << std::endl;
    return out;
}

void undo_relocations(std::vector<std::uint8_t> &image,
    std::uint64_t preferred_base, std::uintptr_t actual_base,
    std::uint32_t reloc_rva, std::uint32_t reloc_size)
{
    if (!reloc_rva || !reloc_size || preferred_base == actual_base)
        return;
    auto const delta = static_cast<std::uint64_t>(actual_base) - preferred_base;
    auto const end = reloc_rva + reloc_size;
    auto off = reloc_rva;
    while (off + 8 <= end && off + 8 <= image.size())
    {
        auto const page_rva = *reinterpret_cast<std::uint32_t *>(image.data() + off);
        auto const block_size =
            *reinterpret_cast<std::uint32_t *>(image.data() + off + 4);
        if (block_size < 8)
            break;
        auto const entries = (block_size - 8) / 2;
        for (std::uint32_t i = 0; i < entries; ++i)
        {
            auto const entry =
                *reinterpret_cast<std::uint16_t *>(image.data() + off + 8 + i * 2);
            auto const etype = entry >> 12;
            auto const eoff = entry & 0xFFF;
            if (etype == 0)
                continue;
            // Slots already rewritten to import-name RVAs must not be relocated.
            if (etype == 10)
            {
                auto const target = page_rva + eoff;
                if (target + 8 <= image.size())
                {
                    auto const cur = *reinterpret_cast<std::uint64_t *>(
                        image.data() + target);
                    if (cur && cur < image.size())
                        continue;
                }
            }
            if (etype != IMAGE_REL_BASED_DIR64)
                continue;
            auto const abs_off = page_rva + eoff;
            if (abs_off + 8 > image.size())
                continue;
            auto &val =
                *reinterpret_cast<std::uint64_t *>(image.data() + abs_off);
            val = (val - delta);
        }
        off += block_size;
    }
}

void build_memory_pe(std::vector<std::uint8_t> &image,
    std::uint64_t preferred_base, std::uint32_t size_of_image)
{
    if (image.size() < size_of_image)
        image.resize(size_of_image, 0);
    else
        image.resize(size_of_image);

    auto const e_lfanew = *reinterpret_cast<std::uint32_t *>(image.data() + 0x3C);
    auto const num_sections =
        *reinterpret_cast<std::uint16_t *>(image.data() + e_lfanew + 6);
    auto const size_opt =
        *reinterpret_cast<std::uint16_t *>(image.data() + e_lfanew + 20);
    auto const opt = e_lfanew + 24;
    auto const magic = *reinterpret_cast<std::uint16_t *>(image.data() + opt);
    if (magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        throw std::runtime_error("expected PE32+ optional header");

    *reinterpret_cast<std::uint64_t *>(image.data() + opt + 24) = preferred_base;
    auto const section_align =
        *reinterpret_cast<std::uint32_t *>(image.data() + opt + 32);
    *reinterpret_cast<std::uint32_t *>(image.data() + opt + 36) = section_align;

    auto const sec_off = opt + size_opt;
    for (std::uint16_t i = 0; i < num_sections; ++i)
    {
        auto const s = sec_off + i * 40;
        auto const va = *reinterpret_cast<std::uint32_t *>(image.data() + s + 12);
        auto const vsize =
            *reinterpret_cast<std::uint32_t *>(image.data() + s + 8);
        std::uint32_t raw_size = 0;
        if (vsize)
        {
            raw_size = ((vsize + section_align - 1) / section_align) *
                section_align;
            if (!raw_size)
                raw_size = section_align;
        }
        *reinterpret_cast<std::uint32_t *>(image.data() + s + 16) = raw_size;
        *reinterpret_cast<std::uint32_t *>(image.data() + s + 20) = va;
    }
}

fs::path output_path_for(fs::path const &input)
{
    auto const dir = input.parent_path();
    auto const stem = input.stem().string();
    auto const ext = input.extension().string();
    return dir / (stem + "_unpacked" + ext);
}

} // namespace

namespace memdump
{

bool disk_has_eidolon_loader(fs::path const &exe_path)
{
    DiskPeInfo info;
    if (!parse_disk_pe(exe_path, info))
        return false;
    return info.has_loader_import;
}

int run(fs::path const &exe_path)
{
    DiskPeInfo pe;
    if (!parse_disk_pe(exe_path, pe))
    {
        std::cerr << "failed to parse PE: " << exe_path << std::endl;
        return EXIT_FAILURE;
    }

    auto preferred = pe.image_base ? pe.image_base : kPreferredImageBase;
    if (preferred != kPreferredImageBase)
    {
        std::cout << "note: disk ImageBase 0x" << std::hex << preferred
                  << ", rebasing dump to 0x" << kPreferredImageBase << std::dec
                  << std::endl;
        preferred = kPreferredImageBase;
    }

    PROCESS_INFORMATION proc_info {};
    std::cout << "external memdump: launching " << exe_path << std::endl;
    if (!launch_unsuspended(exe_path, proc_info))
    {
        std::cerr << "CreateProcess failed (" << ::GetLastError() << ")"
                  << std::endl;
        return EXIT_FAILURE;
    }

    RaiiProc killer(proc_info.dwProcessId);
    ::CloseHandle(proc_info.hThread);

    std::cout << "pid " << std::dec << proc_info.dwProcessId << std::endl;
    std::cout << "waiting up to " << kWindowWaitSec << "s for main window ..."
              << std::endl;
    if (!wait_for_main_window(proc_info.dwProcessId, kWindowWaitSec))
        std::cerr << "main window not seen; continuing anyway" << std::endl;
    else
        std::cout << "window up" << std::endl;

    DWORD access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD |
        PROCESS_TERMINATE;
    HANDLE hproc = ::OpenProcess(access, FALSE, proc_info.dwProcessId);
    if (!hproc)
    {
        std::cerr << "OpenProcess failed (" << ::GetLastError() << ")"
                  << std::endl;
        return EXIT_FAILURE;
    }

    try
    {
        std::uintptr_t base = 0;
        std::uint32_t mod_size = 0;
        if (!find_main_module(hproc, exe_path, base, mod_size))
        {
            std::cerr << "main module not found" << std::endl;
            ::CloseHandle(hproc);
            return EXIT_FAILURE;
        }
        std::cout << "module base=0x" << std::hex << base << " size=0x"
                  << mod_size << std::dec << std::endl;

        std::cout << "forcing .text decrypt via execute probe (Eidolon) ..."
                  << std::endl;
        std::unordered_map<std::uint32_t, std::vector<std::uint8_t>> snaps;
        auto const text_base = base + pe.text_va;
        auto const text_pages = pe.text_vs / 0x1000;
        std::uint32_t prev_na = 0xFFFFFFFFu;
        std::uint32_t prev_good = 0;
        int stuck = 0;
        for (int round = 1; round <= 8 && process_alive(hproc); ++round)
        {
            auto const na = count_noaccess_pages(hproc, text_base, pe.text_vs);
            if (round > 1 && na == 0)
                break;
            std::cout << "decrypt round " << round << ", NOACCESS pages "
                      << na << std::endl;
            force_decrypt_region(hproc, text_base, pe.text_vs, &snaps);
            if (!process_alive(hproc))
                break;
            auto const na_after = count_noaccess_pages(hproc, text_base, pe.text_vs);
            std::uint32_t good = 0;
            for (auto const &snap : snaps)
            {
                for (auto b : snap.second)
                {
                    if (b)
                    {
                        ++good;
                        break;
                    }
                }
            }
            std::cout << "  round " << round << " done: NOACCESS " << na_after
                      << ", snapshots " << good << "/" << text_pages
                      << std::endl;
            if (na_after == 0)
                break;
            if (na_after >= prev_na && good <= prev_good)
                ++stuck;
            else
                stuck = 0;
            prev_na = na_after;
            prev_good = good;
            if (stuck >= 2)
            {
                std::cerr << "warning: " << na_after
                          << " .text pages still NOACCESS after retries"
                          << std::endl;
                break;
            }
        }

        if (!process_alive(hproc))
        {
            std::cerr << "warning: process died during execute decrypt"
                      << std::endl;
            ::CloseHandle(hproc);
            return EXIT_FAILURE;
        }

        auto ratio =
            sample_plaintext_ratio(hproc, base, pe.text_va, pe.text_vs);
        std::cout << "  .text sample plaintext pages: " << std::fixed
                  << (ratio * 100.f) << "%" << std::endl;
        if (ratio < kMinTextRatio)
            std::cerr << "warning: plaintext ratio " << (ratio * 100.f)
                      << "% (wanted " << (kMinTextRatio * 100.f) << "%)"
                      << std::endl;

        auto size = (std::max)(mod_size, pe.size_of_image);
        std::cout << "reading 0x" << std::hex << size << " bytes from 0x" << base
                  << std::dec << " ..." << std::endl;
        auto image = read_memory(hproc, base, size);

        std::uint32_t filled = 0;
        for (auto const &snap : snaps)
        {
            auto const off = pe.text_va + snap.first;
            if (snap.second.size() != 0x1000 || off + 0x1000 > image.size())
                continue;
            auto dst = image.data() + off;
            auto const have = page_looks_plaintext(dst, 0x1000);
            auto const shot = page_looks_plaintext(snap.second.data(), 0x1000);
            bool blank = true;
            for (size_t n = 0; n < 0x1000; ++n)
            {
                if (dst[n])
                {
                    blank = false;
                    break;
                }
            }
            if (blank || (shot && !have))
            {
                std::memcpy(dst, snap.second.data(), 0x1000);
                ++filled;
            }
        }
        if (filled)
            std::cout << "restored " << filled
                      << " .text pages from probe snapshots" << std::endl;

        float plain_ratio = 0.f;
        if (pe.text_vs && pe.text_va + pe.text_vs <= image.size())
        {
            int plain = 0;
            int pages = 0;
            constexpr std::uint32_t page = 0x1000;
            for (std::uint32_t off = 0; off + page <= pe.text_vs; off += page)
            {
                ++pages;
                if (page_looks_plaintext(image.data() + pe.text_va + off, page))
                    ++plain;
            }
            plain_ratio = pages ? static_cast<float>(plain) /
                                      static_cast<float>(pages)
                                : 0.f;
        }
        std::cout << ".text plaintext pages: " << (plain_ratio * 100.f) << "%"
                  << std::endl;
        if (plain_ratio < 0.5f)
            std::cerr << "warning: .text still mostly ciphertext "
                         "(non-zero is not a decrypt signal)"
                      << std::endl;

        // IAT from PE header in the dump (still at runtime values).
        auto const e_lfanew =
            *reinterpret_cast<std::uint32_t *>(image.data() + 0x3C);
        auto const opt = e_lfanew + 24;
        auto const dd = opt + 112;
        auto iat_rva = *reinterpret_cast<std::uint32_t *>(image.data() + dd + 12 * 8);
        auto iat_size =
            *reinterpret_cast<std::uint32_t *>(image.data() + dd + 12 * 8 + 4);
        if (!iat_rva)
            iat_rva = 0x4882000; // WowB fallback; better than nothing
        std::cout << "rebuilding imports from live IAT 0x" << std::hex
                  << iat_rva << " size 0x" << iat_size << std::dec << " ..."
                  << std::endl;
        rebuild_imports_remote(hproc, base, image, iat_rva, iat_size);

        if (!pe.reloc_bytes.empty() &&
            pe.reloc_rva + pe.reloc_bytes.size() <= image.size())
        {
            std::memcpy(image.data() + pe.reloc_rva, pe.reloc_bytes.data(),
                pe.reloc_bytes.size());
        }

        std::cout << "undoing relocs: actual 0x" << std::hex << base
                  << " -> preferred 0x" << preferred << std::dec << std::endl;
        undo_relocations(image, preferred, base, pe.reloc_rva, pe.reloc_size);
        // Prefer SizeOfImage after import section append.
        auto const final_size =
            *reinterpret_cast<std::uint32_t *>(image.data() + opt + 56);
        build_memory_pe(image, preferred,
            (std::max)(final_size, pe.size_of_image));

        auto const out_path = output_path_for(exe_path);
        {
            std::ofstream out(out_path, std::ios::binary);
            if (!out)
            {
                std::cerr << "failed to write " << out_path << std::endl;
                ::CloseHandle(hproc);
                return EXIT_FAILURE;
            }
            out.write(reinterpret_cast<char *>(image.data()),
                static_cast<std::streamsize>(image.size()));
        }
        std::cout << "wrote " << out_path << " (" << std::dec << image.size()
                  << " bytes), ImageBase=0x" << std::hex << preferred << std::dec
                  << std::endl;
    }
    catch (std::exception const &e)
    {
        std::cerr << "memdump error: " << e.what() << std::endl;
        ::CloseHandle(hproc);
        return EXIT_FAILURE;
    }

    ::TerminateProcess(hproc, 0);
    ::CloseHandle(hproc);
    ::CloseHandle(proc_info.hProcess);
    return EXIT_SUCCESS;
}

} // namespace memdump
