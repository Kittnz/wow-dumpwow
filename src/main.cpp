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
#include "raii_proc.hpp"
#include "memdump.hpp"

#include <hadesmem/injector.hpp>
#include <hadesmem/region_list.hpp>
#include <hadesmem/module.hpp>
#include <hadesmem/read.hpp>
#include <hadesmem/write.hpp>
#include <hadesmem/pelib/pe_file.hpp>
#include <hadesmem/pelib/tls_dir.hpp>
#include <hadesmem/pelib/nt_headers.hpp>
#include <hadesmem/pelib/import_dir.hpp>
#include <hadesmem/pelib/import_dir_list.hpp>
#include <hadesmem/pelib/import_thunk.hpp>
#include <hadesmem/pelib/import_thunk_list.hpp>
#include <hadesmem/find_pattern.hpp>
#include <hadesmem/find_procedure.hpp>

#include <Windows.h>
#include <intrin.h>

#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <thread>
#include <chrono>
#include <fstream>
#include <cstdio>
#include <atomic>
#include <cstring>
#include <cctype>
#include <algorithm>

#pragma intrinsic(_ReturnAddress)

#define CALL_FIRST  1

namespace fs = std::filesystem;

fs::path get_temp_filename(const fs::path& path);
bool launch_wow_suspended(const fs::path &path,
    PROCESS_INFORMATION &proc_info);
hadesmem::PeFile find_wow_pe(const hadesmem::Process &process);
void *find_tls_callback_directory(const hadesmem::Process &process,
    const hadesmem::PeFile &pe);
BOOL ControlHandler(DWORD ctrl_type);
bool FindVEHCallerRVA();
size_t find_call_tls_initializers_rva();
void process_log_file(const fs::path &exe_path);
// Returns lowercase import name (e.g. "wowb_loader.dll") or empty if none.
std::string find_eidolon_loader_import(const hadesmem::Process &process,
    const hadesmem::PeFile &pe);
void disable_loader_import(const hadesmem::Process &process,
    const hadesmem::PeFile &pe, DWORD &import_rva, DWORD &import_size);
void load_loader_and_fix_iat(const hadesmem::Process &process,
    const hadesmem::PeFile &pe, const fs::path &exe_dir,
    const std::string &loader_import_name,
    DWORD import_rva, DWORD import_size);
DWORD get_export_rva_from_file(const fs::path &dll_path,
    const char *export_name);

size_t g_veh_caller_rva;
std::atomic_bool g_exit_wow;

int main(int argc, char *argv[])
{
    bool force_inject = false;
    char const *exe_arg = nullptr;
    for (int i = 1; i < argc; ++i)
    {
        if (std::strcmp(argv[i], "--inject") == 0)
            force_inject = true;
        else if (!exe_arg)
            exe_arg = argv[i];
        else
        {
            std::cerr << "Usage: " << argv[0]
                << " [--inject] <wow.exe>" << std::endl;
            return EXIT_FAILURE;
        }
    }

    if (!exe_arg)
    {
        std::cerr << "Usage: " << argv[0]
            << " [--inject] <wow.exe>" << std::endl;
        return EXIT_FAILURE;
    }

    const fs::path path = fs::absolute(exe_arg);

    // Eidolon (*_loader.dll) skips .text decrypt under injected unpacker.
    // Decrypt + remote IAT rebuild from outside (stubs need the target PEB).
    if (!force_inject && memdump::disk_has_eidolon_loader(path))
    {
        std::cout << "Detected Eidolon loader import; using external memdump"
            << std::endl;
        return memdump::run(path);
    }

    auto const call_tls_initializers_rva = find_call_tls_initializers_rva();

    if (!call_tls_initializers_rva)
    {
        std::cerr << "Failed to find LdrpCallTlsInitializers" << std::endl;
        return EXIT_FAILURE;
    }

    try
    {
        PROCESS_INFORMATION proc_info;
        if (!launch_wow_suspended(path, proc_info))
        {
            std::cerr << "launch_wow_suspended failed" << std::endl;
            return EXIT_FAILURE;
        }

        g_exit_wow = false;
      
        const hadesmem::Process process(proc_info.dwProcessId);

        // ensure process is killed upon exit
        const RaiiProc proc_killer(process.GetId());

        auto const pe_file = find_wow_pe(process);

        std::cout << "Wow base address:       0x" << std::hex
            << reinterpret_cast<std::uintptr_t>(pe_file.GetBase())
            << std::endl;

        // Modern Classic clients pull in *_loader.dll (Eidolon), e.g.
        // WowClassic_loader.dll / WowB_loader.dll. InjectDll forces loader
        // init first, which loads Eidolon and causes
        // LoadLibraryExW(unpacker.dll) to fail. Strip that import for now.
        DWORD loader_import_rva = 0;
        DWORD loader_import_size = 0;
        auto const loader_import = find_eidolon_loader_import(process, pe_file);
        if (!loader_import.empty())
        {
            std::cout << "Detected " << loader_import << " import; "
                << "deferring Eidolon load until after injection"
                << std::endl;
            disable_loader_import(process, pe_file, loader_import_rva,
                loader_import_size);
        }

        // temporarily disable TLS callbacks to prevent them from executing
        // when we inject
        auto const tls_callback_directory = 
            find_tls_callback_directory(process, pe_file);

        if (!tls_callback_directory)
        {
            std::cerr << "Unable to find TLS callback directory" << std::endl;
            return EXIT_FAILURE;
        }

        std::cout << "TLS callback directory: 0x" << std::hex
            << reinterpret_cast<std::uintptr_t>(tls_callback_directory)
            << std::endl;

        auto const first_callback = hadesmem::Read<void *>(process,
            tls_callback_directory);

        std::cout << "First TLS callback:     0x" << std::hex
            << reinterpret_cast<std::uintptr_t>(first_callback)
            << std::endl;

        hadesmem::Write<void *>(process, tls_callback_directory, nullptr);

        auto const verify = hadesmem::Read<void *>(process,
            tls_callback_directory);

        if (verify)
        {
            std::cerr << "Failed to zero first TLS callback" << std::endl;
            return EXIT_FAILURE;
        }

        // with the TLS callbacks disabled, our DLL may be safely injected
        std::cout << "Injecting unpacker.dll..." << std::endl;
        const hadesmem::Module unpacker(process, hadesmem::InjectDll(process,
            L"unpacker.dll",
            hadesmem::InjectFlags::kPathResolution |
            hadesmem::InjectFlags::kAddToSearchOrder));

        // call init function in DLL
        auto const func = reinterpret_cast<
            void(*)(size_t, DWORD, PVOID, DWORD)>(
            hadesmem::FindProcedure(process, unpacker, "Initialize"));

        hadesmem::Call(process, func, hadesmem::CallConv::kDefault,
            call_tls_initializers_rva, proc_info.dwThreadId,
            pe_file.GetBase(), pe_file.GetSize());

        if (!loader_import.empty())
        {
            std::cout << "Loading " << loader_import
                << " and fixing IAT..." << std::endl;
            load_loader_and_fix_iat(process, pe_file, path.parent_path(),
                loader_import, loader_import_rva, loader_import_size);
        }

        // restore first TLS callback
        hadesmem::Write<void *>(process, tls_callback_directory,
            first_callback);

        if (!::SetConsoleCtrlHandler(ControlHandler, TRUE))
        {
            std::cerr << "SetConsoleCtrlHandler failed" << std::endl;
            return EXIT_FAILURE;
        }

        CONTEXT context;
        memset(&context, 0, sizeof(context));
        context.ContextFlags = CONTEXT_ALL;
        ::GetThreadContext(proc_info.hThread, &context);

        if (!::ResumeThread(proc_info.hThread))
        {
            std::cerr << "Failed to resume main thread" << std::endl;
            return EXIT_FAILURE;
        }

        DWORD exit_code = 0;

        do
        {
            if (g_exit_wow)
            {
                std::cout << "Received CTRL-C.  Terminating wow..."
                    << std::endl;
                ::TerminateProcess(process.GetHandle(), 0);
                g_exit_wow = false;
            }

            if (!::GetExitCodeProcess(proc_info.hProcess, &exit_code))
            {
                std::cerr << "GetExitCodeProcess failed" << std::endl;
                return EXIT_FAILURE;
            }

            // if there is a different exit code, the process has exited
            if (exit_code != STILL_ACTIVE)
                break;

            // if STILL_ACTIVE is the exit code, the process may have chosen to
            // exit using that error code, so try one more check
            if (::WaitForSingleObject(proc_info.hProcess, 0) != WAIT_TIMEOUT)
                break;

            // if the waiting timed out, it means the process is still running.
            // so let us sleep for a little while and then check again
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
        } while (true);

        if (!::SetConsoleCtrlHandler(ControlHandler, FALSE))
        {
            std::cerr << "SetConsoleCtrlHandler failed" << std::endl;
            return EXIT_FAILURE;
        }

        std::cout << "Wow exited with code:   0x" << std::hex << exit_code
            << std::endl;

        process_log_file(path);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error:\n" << boost::diagnostic_information(e)
            << std::endl;
        process_log_file(path);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

LONG NTAPI VectoredExceptionHandler(struct _EXCEPTION_POINTERS *exceptionInfo)
{
    auto const return_address = reinterpret_cast<const std::uint8_t *>(
        ::_ReturnAddress());
    auto const base = reinterpret_cast<const std::uint8_t *>(
        ::GetModuleHandle(L"ntdll"));

    g_veh_caller_rva = return_address - base - 6;

    return EXCEPTION_CONTINUE_EXECUTION;
}

// find the RVA of RtlpCallVectoredHandlers within NTDLL so we know where to
// find it once we launch wow
bool FindVEHCallerRVA()
{
    // first, add our own VEH
    auto const veh_handle = ::AddVectoredExceptionHandler(CALL_FIRST,
        &VectoredExceptionHandler);

    // second, raise an exception
    ::RaiseException(1, 0, 0, nullptr);

    // third, remove the VEH
    if (!::RemoveVectoredExceptionHandler(veh_handle))
        return false;

    // at this point, g_veh_caller_rva will have a value.  now check if it is
    // valid
    auto const call_site = reinterpret_cast<std::uint8_t *>(
        GetModuleHandle(L"ntdll")) + g_veh_caller_rva;

    // first byte of indirect call instruction is right?
    return *call_site == 0xFF && *(call_site + 5) == 0;
}

std::string find_eidolon_loader_import(const hadesmem::Process &process,
    const hadesmem::PeFile &pe)
{
    try
    {
        hadesmem::ImportDirList dirs(process, pe);
        for (auto const &dir : dirs)
        {
            auto name = dir.GetName();
            for (auto &c : name)
                c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
            // WowClassic_loader.dll, WowB_loader.dll, etc.
            auto const suffix = std::string("_loader.dll");
            if (name.size() > suffix.size() &&
                name.compare(name.size() - suffix.size(), suffix.size(),
                    suffix) == 0)
                return name;
        }
    }
    catch (const std::exception &)
    {
    }

    return {};
}

void disable_loader_import(const hadesmem::Process &process,
    const hadesmem::PeFile &pe, DWORD &import_rva, DWORD &import_size)
{
    hadesmem::NtHeaders nt(process, pe);
    import_rva = nt.GetDataDirectoryVirtualAddress(hadesmem::PeDataDir::Import);
    import_size = nt.GetDataDirectorySize(hadesmem::PeDataDir::Import);
    nt.SetDataDirectoryVirtualAddress(hadesmem::PeDataDir::Import, 0);
    nt.SetDataDirectorySize(hadesmem::PeDataDir::Import, 0);
    nt.UpdateWrite();
}

DWORD get_export_rva_from_file(const fs::path &dll_path,
    const char *export_name)
{
    std::ifstream in(dll_path, std::ios::binary);
    if (!in)
        return 0;

    IMAGE_DOS_HEADER dos {};
    in.read(reinterpret_cast<char *>(&dos), sizeof(dos));
    if (!in || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    in.seekg(dos.e_lfanew, std::ios::beg);
    DWORD nt_sig = 0;
    in.read(reinterpret_cast<char *>(&nt_sig), sizeof(nt_sig));
    if (!in || nt_sig != IMAGE_NT_SIGNATURE)
        return 0;

    IMAGE_FILE_HEADER file_hdr {};
    in.read(reinterpret_cast<char *>(&file_hdr), sizeof(file_hdr));
    if (!in)
        return 0;

    IMAGE_OPTIONAL_HEADER64 opt64 {};
    if (file_hdr.SizeOfOptionalHeader < sizeof(opt64))
        return 0;
    in.read(reinterpret_cast<char *>(&opt64), sizeof(opt64));
    if (!in || opt64.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return 0;

    auto const export_rva =
        opt64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    auto const export_size =
        opt64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!export_rva || !export_size)
        return 0;

    std::vector<IMAGE_SECTION_HEADER> sections(file_hdr.NumberOfSections);
    in.read(reinterpret_cast<char *>(sections.data()),
        static_cast<std::streamsize>(
            sections.size() * sizeof(IMAGE_SECTION_HEADER)));
    if (!in)
        return 0;

    auto rva_to_offset = [&](DWORD rva) -> DWORD {
        for (auto const &sec : sections)
        {
            auto const size = (std::max)(sec.SizeOfRawData, sec.Misc.VirtualSize);
            if (rva >= sec.VirtualAddress &&
                rva < sec.VirtualAddress + size)
            {
                return sec.PointerToRawData + (rva - sec.VirtualAddress);
            }
        }
        return 0;
    };

    auto const export_off = rva_to_offset(export_rva);
    if (!export_off)
        return 0;

    IMAGE_EXPORT_DIRECTORY exp {};
    in.seekg(export_off, std::ios::beg);
    in.read(reinterpret_cast<char *>(&exp), sizeof(exp));
    if (!in || !exp.NumberOfNames)
        return 0;

    auto const names_off = rva_to_offset(exp.AddressOfNames);
    auto const ords_off = rva_to_offset(exp.AddressOfNameOrdinals);
    auto const funcs_off = rva_to_offset(exp.AddressOfFunctions);
    if (!names_off || !ords_off || !funcs_off)
        return 0;

    std::vector<DWORD> name_rvas(exp.NumberOfNames);
    in.seekg(names_off, std::ios::beg);
    in.read(reinterpret_cast<char *>(name_rvas.data()),
        static_cast<std::streamsize>(name_rvas.size() * sizeof(DWORD)));
    if (!in)
        return 0;

    std::vector<WORD> name_ords(exp.NumberOfNames);
    in.seekg(ords_off, std::ios::beg);
    in.read(reinterpret_cast<char *>(name_ords.data()),
        static_cast<std::streamsize>(name_ords.size() * sizeof(WORD)));
    if (!in)
        return 0;

    for (DWORD i = 0; i < exp.NumberOfNames; ++i)
    {
        auto const name_off = rva_to_offset(name_rvas[i]);
        if (!name_off)
            continue;

        char name_buf[256] {};
        in.seekg(name_off, std::ios::beg);
        in.read(name_buf, sizeof(name_buf) - 1);
        if (!in && !in.eof())
            continue;
        name_buf[sizeof(name_buf) - 1] = '\0';

        if (std::strcmp(name_buf, export_name) != 0)
            continue;

        auto const func_index = name_ords[i];
        if (func_index >= exp.NumberOfFunctions)
            return 0;

        DWORD func_rva = 0;
        in.seekg(funcs_off + func_index * sizeof(DWORD), std::ios::beg);
        in.read(reinterpret_cast<char *>(&func_rva), sizeof(func_rva));
        if (!in)
            return 0;

        // Skip forwarded exports (RVA lies inside the export directory).
        if (func_rva >= export_rva && func_rva < export_rva + export_size)
            return 0;

        return func_rva;
    }

    return 0;
}

DWORD get_export_rva_by_ordinal_from_file(const fs::path &dll_path,
    WORD ordinal)
{
    std::ifstream in(dll_path, std::ios::binary);
    if (!in)
        return 0;

    IMAGE_DOS_HEADER dos {};
    in.read(reinterpret_cast<char *>(&dos), sizeof(dos));
    if (!in || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    in.seekg(dos.e_lfanew, std::ios::beg);
    DWORD nt_sig = 0;
    in.read(reinterpret_cast<char *>(&nt_sig), sizeof(nt_sig));
    if (!in || nt_sig != IMAGE_NT_SIGNATURE)
        return 0;

    IMAGE_FILE_HEADER file_hdr {};
    in.read(reinterpret_cast<char *>(&file_hdr), sizeof(file_hdr));
    if (!in)
        return 0;

    IMAGE_OPTIONAL_HEADER64 opt64 {};
    if (file_hdr.SizeOfOptionalHeader < sizeof(opt64))
        return 0;
    in.read(reinterpret_cast<char *>(&opt64), sizeof(opt64));
    if (!in || opt64.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return 0;

    auto const export_rva =
        opt64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    auto const export_size =
        opt64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!export_rva || !export_size)
        return 0;

    std::vector<IMAGE_SECTION_HEADER> sections(file_hdr.NumberOfSections);
    in.read(reinterpret_cast<char *>(sections.data()),
        static_cast<std::streamsize>(
            sections.size() * sizeof(IMAGE_SECTION_HEADER)));
    if (!in)
        return 0;

    auto rva_to_offset = [&](DWORD rva) -> DWORD {
        for (auto const &sec : sections)
        {
            auto const size = (std::max)(sec.SizeOfRawData, sec.Misc.VirtualSize);
            if (rva >= sec.VirtualAddress &&
                rva < sec.VirtualAddress + size)
            {
                return sec.PointerToRawData + (rva - sec.VirtualAddress);
            }
        }
        return 0;
    };

    auto const export_off = rva_to_offset(export_rva);
    if (!export_off)
        return 0;

    IMAGE_EXPORT_DIRECTORY exp {};
    in.seekg(export_off, std::ios::beg);
    in.read(reinterpret_cast<char *>(&exp), sizeof(exp));
    if (!in || !exp.NumberOfFunctions)
        return 0;

    if (ordinal < exp.Base)
        return 0;
    auto const index = static_cast<DWORD>(ordinal - exp.Base);
    if (index >= exp.NumberOfFunctions)
        return 0;

    auto const funcs_off = rva_to_offset(exp.AddressOfFunctions);
    if (!funcs_off)
        return 0;

    DWORD func_rva = 0;
    in.seekg(funcs_off + index * sizeof(DWORD), std::ios::beg);
    in.read(reinterpret_cast<char *>(&func_rva), sizeof(func_rva));
    if (!in || !func_rva)
        return 0;

    if (func_rva >= export_rva && func_rva < export_rva + export_size)
        return 0;

    return func_rva;
}

void load_loader_and_fix_iat(const hadesmem::Process &process,
    const hadesmem::PeFile &pe, const fs::path &exe_dir,
    const std::string &loader_import_name,
    DWORD import_rva, DWORD import_size)
{
    // Restore the import directory so we can parse descriptors/IAT again.
    {
        hadesmem::NtHeaders nt(process, pe);
        nt.SetDataDirectoryVirtualAddress(hadesmem::PeDataDir::Import,
            import_rva);
        nt.SetDataDirectorySize(hadesmem::PeDataDir::Import, import_size);
        nt.UpdateWrite();
    }

    // Prefer an on-disk file whose name matches the import (case-insensitive).
    fs::path loader_path;
    for (auto const &entry : fs::directory_iterator(exe_dir))
    {
        if (!entry.is_regular_file())
            continue;
        auto fname = entry.path().filename().string();
        for (auto &c : fname)
            c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
        if (fname == loader_import_name)
        {
            loader_path = entry.path();
            break;
        }
    }

    if (loader_path.empty())
        throw std::runtime_error(
            loader_import_name + " not found next to exe");

    auto const loader_handle = hadesmem::InjectDll(process,
        loader_path.wstring(), hadesmem::InjectFlags::kNone);

    // Resolve entry: named eidolon_run (Classic) or ordinal 1 (Beta / unnamed).
    FARPROC eidolon = nullptr;
    try
    {
        const hadesmem::Module loader(process, loader_handle);
        eidolon = hadesmem::FindProcedure(process, loader, "eidolon_run");
    }
    catch (const std::exception &)
    {
        eidolon = nullptr;
    }

    if (!eidolon)
    {
        auto rva = get_export_rva_from_file(loader_path, "eidolon_run");
        if (!rva)
            rva = get_export_rva_by_ordinal_from_file(loader_path, 1);
        if (!rva)
            throw std::runtime_error(
                "Failed to resolve eidolon entry in " + loader_import_name);

        eidolon = reinterpret_cast<FARPROC>(
            reinterpret_cast<std::uint8_t *>(loader_handle) + rva);
        std::cout << "Resolved loader entry via on-disk export RVA 0x"
            << std::hex << rva << std::endl;
    }

    std::cout << "eidolon_run:            0x" << std::hex
        << reinterpret_cast<std::uintptr_t>(eidolon) << std::endl;

    hadesmem::ImportDirList dirs(process, pe);
    for (auto const &dir : dirs)
    {
        auto name = dir.GetName();
        for (auto &c : name)
            c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
        if (name != loader_import_name)
            continue;

        // Count INT entries so we do not walk past this DLL's IAT slice into
        // the shared obfuscated import table (null-terminated walk would
        // overwrite hundreds of stub pointers with eidolon_run).
        size_t loader_import_count = 0;
        if (dir.GetOriginalFirstThunk())
        {
            hadesmem::ImportThunkList ilt(process, pe,
                dir.GetOriginalFirstThunk());
            for (auto const &t : ilt)
            {
                (void)t;
                ++loader_import_count;
            }
        }

        if (!loader_import_count)
            loader_import_count = 1;

        size_t patched = 0;
        hadesmem::ImportThunkList thunks(process, pe, dir.GetFirstThunk());
        for (auto thunk : thunks)
        {
            if (patched >= loader_import_count)
                break;
            thunk.SetFunction(reinterpret_cast<ULONGLONG>(eidolon));
            thunk.UpdateWrite();
            ++patched;
        }

        std::cout << "Patched " << std::dec << patched
            << " " << loader_import_name << " IAT entr"
            << (patched == 1 ? "y" : "ies") << std::endl;
        break;
    }
}

bool launch_wow_suspended(const fs::path &path,
    PROCESS_INFORMATION &proc_info)
{
    // disable ASLR for subprocesses so the base address matches static tools
    SIZE_T cb = 0;
    if (!::InitializeProcThreadAttributeList(nullptr, 1, 0, &cb) &&
        ::GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        return false;

    auto attribs = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(malloc(cb));

    if (!attribs)
        return false;

    if (!::InitializeProcThreadAttributeList(attribs, 1, 0, &cb))
    {
        free(attribs);
        return false;
    }

    DWORD64 attribute =
        PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_OFF;
    if (!::UpdateProcThreadAttribute(attribs, 0,
        PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &attribute, sizeof(DWORD64),
        nullptr, nullptr))
    {
        ::DeleteProcThreadAttributeList(attribs);
        free(attribs);
        return false;
    }

    STARTUPINFOEXW start_info {};
    start_info.StartupInfo.cb = static_cast<DWORD>(sizeof(start_info));
    start_info.lpAttributeList = attribs;
    memset(&proc_info, 0, sizeof(proc_info));

    auto path_w = path.wstring();
    std::vector<wchar_t> path_raw(path_w.begin(), path_w.end());
    path_raw.push_back(L'\0');

    auto const dir_w = path.parent_path().wstring();

    auto const result = !!::CreateProcessW(path_raw.data(), nullptr, nullptr,
        nullptr, FALSE,
        CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT |
            EXTENDED_STARTUPINFO_PRESENT,
        nullptr, dir_w.empty() ? nullptr : dir_w.c_str(),
        &start_info.StartupInfo, &proc_info);

    ::DeleteProcThreadAttributeList(attribs);
    free(attribs);

    return result;
}

hadesmem::PeFile find_wow_pe(const hadesmem::Process &process)
{
    const hadesmem::RegionList region_list(process);

    // find the PE header for wow
    for (auto const &region : region_list)
    {
        if (region.GetState() == MEM_FREE)
            continue;

        if (region.GetType() != MEM_IMAGE)
            continue;

        if (region.GetProtect() != PAGE_READONLY)
            continue;

        if (region.GetAllocBase() != region.GetBase())
            continue;

        hadesmem::PeFile pe_file(process, region.GetBase(),
            hadesmem::PeFileType::kImage,
            static_cast<DWORD>(region.GetSize()));

        std::vector<ULONGLONG> callbacks;

        try
        {
            const hadesmem::TlsDir tls_dir(process, pe_file);
            tls_dir.GetCallbacks(std::back_inserter(callbacks));
        }
        catch (const hadesmem::Error &)
        {
            continue;
        }

        // wow has tls callbacks
        if (callbacks.empty())
            continue;

        return std::move(pe_file);
    }

    throw std::runtime_error("Could not find wow PE");
}

void *find_tls_callback_directory(const hadesmem::Process &process,
    const hadesmem::PeFile &pe)
{
    try
    {
        const hadesmem::TlsDir tls_dir(process, pe);
        return reinterpret_cast<void *>(tls_dir.GetAddressOfCallBacks());
    }
    catch (const hadesmem::Error &)
    {
        return nullptr;
    }
}

size_t find_call_tls_initializers_rva()
{
    auto const ntdll = ::GetModuleHandle(L"ntdll");

    if (!ntdll)
        return 0;

    const hadesmem::Process process(::GetCurrentProcessId());

    // find "LdrpCallTlsInitializers"
    auto const magic_value = hadesmem::Find(process, L"ntdll.dll",
        L"4C 64 72 70 43 61 6C 6C 54 6C 73 49 "
         "6E 69 74 69 61 6C 69 7A 65 72 73 00",
        hadesmem::PatternFlags::kScanData,
        0);

    if (!magic_value)
        return 0;

    const std::uint8_t *magic_value_ref = nullptr;

    // find recurrences of the byte pattern which dereferences the magic value
    // and check for one that actually is dereferencing it
    for (auto p = hadesmem::Find(process, L"ntdll.dll",
        L"4c 8d 05 ?? ?? ?? 00", 0, 0); p;)
    {
        auto const p_offset = reinterpret_cast<std::uint8_t *>(p) -
            reinterpret_cast<std::uint8_t *>(ntdll);

        auto const expected_offset = static_cast<std::uint32_t>(
            reinterpret_cast<std::uintptr_t>(magic_value) -
            reinterpret_cast<std::uintptr_t>(p)) - 7;

        auto const offset = hadesmem::Read<std::uint32_t>(process,
            reinterpret_cast<unsigned char *>(p) + 3);

        if (offset == expected_offset)
        {
            magic_value_ref = reinterpret_cast<const std::uint8_t *>(p);
            break;
        }

        p = hadesmem::Find(process, L"ntdll.dll", L"4c 8d 05 ?? ?? ?? 00", 0,
            p_offset);
    }

    // not found?  give up
    if (!magic_value_ref)
        return 0;

    const std::uint8_t *func = nullptr;

    // begin searching backwards for a few INT3 (0xCC) instructions to guess at
    // the start of the function
    for (int offset = 0; offset < 0x200; ++offset)
    {
        auto const p = reinterpret_cast<const std::uint8_t *>(magic_value_ref)
            - offset;

        if (*p != 0xCC &&
            *(p - 1) == 0xCC &&
            *(p - 2) == 0xCC &&
            *(p - 3) == 0xCC &&
            *(p - 4) == 0xCC)
        {
            func = p;
            break;
        }
    }

    // function start not found?  give up
    if (!func)
        return 0;

    return static_cast<std::uint64_t>(func -
        reinterpret_cast<const std::uint8_t *>(ntdll));
}

void process_log_file(const fs::path &exe_path)
{
    auto const parent = exe_path.parent_path();
    auto const log_path = parent / "log.txt";

    std::ifstream in(log_path, std::ios::ate);

    if (!in)
    {
        std::cerr << "Failed to read " << log_path << std::endl;
        return;
    }

    auto const file_size = static_cast<size_t>(in.tellg());
    in.seekg(std::ios::beg);

    std::vector<char> file_data(file_size + 1);
    in.read(&file_data[0], file_data.size());
    file_data[file_data.size() - 1] = '\0';
    in.close();


    std::cout << "\nLog:\n\n" << &file_data[0];

    std::remove(log_path.string().c_str());
}

BOOL ControlHandler(DWORD ctrl_type)
{
    if (ctrl_type == CTRL_C_EVENT)
    {
        g_exit_wow = true;
        return TRUE;
    }

    std::cout << "Received unrecognized event: " << std::dec << ctrl_type
        << std::endl;

    return FALSE;
}
