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

#include "concolic.hpp"

#include <Windows.h>

#include <cstdint>

namespace
{
template <typename T>
T read(PVOID &address)
{
    auto const ret_ptr = reinterpret_cast<T *>(address);

    address = reinterpret_cast<PVOID>(
        reinterpret_cast<std::uintptr_t>(address) + sizeof(T));

    return *ret_ptr;
}
}

bool conclic_begin(PVOID start, ConclicThreadContext &context)
{
    memset(&context, 0, sizeof(context));

    MEMORY_BASIC_INFORMATION mbi {};
    if (!::VirtualQuery(start, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT)
        return false;

    auto const bytes = reinterpret_cast<const std::uint8_t *>(start);
    // Classic: mov rax, imm64 (48 B8)
    // Modern:  mov r10, imm64 (49 BA) — may precede mov rax
    if (!((bytes[0] == 0x48 && bytes[1] == 0xB8) ||
          (bytes[0] == 0x49 && bytes[1] == 0xBA)))
        return false;

    auto current = start;
    constexpr int kMaxSteps = 64;

    for (int step = 0; step < kMaxSteps; ++step)
    {
        auto const op1 = read<std::uint8_t>(current);

        switch (op1)
        {
            // FF E0 -> jmp rax
            case 0xFF:
                return read<std::uint8_t>(current) == 0xE0 && context.rax != 0;

            // E9 rel32 -> jmp
            case 0xE9:
            {
                auto const offset = read<std::int32_t>(current);
                current = reinterpret_cast<PVOID>(
                    reinterpret_cast<std::uintptr_t>(current) + offset);
                break;
            }
            case 0x48:
            {
                auto const op2 = read<std::uint8_t>(current);
                switch (op2)
                {
                    // 48 B8 imm64 -> mov rax, imm64
                    case 0xB8:
                        context.rax = read<std::uint64_t>(current);
                        break;
                    // 48 05 imm32 -> add rax, imm32
                    case 0x05:
                        context.rax += read<std::int32_t>(current);
                        break;
                    // 48 2D imm32 -> sub rax, imm32
                    case 0x2D:
                        context.rax -= read<std::int32_t>(current);
                        break;
                    // 48 35 imm32 -> xor rax, imm32
                    case 0x35:
                        context.rax ^= static_cast<std::uint64_t>(
                            read<std::int32_t>(current));
                        break;
                    default:
                        return false;
                }
                break;
            }
            case 0x49:
            {
                auto const op2 = read<std::uint8_t>(current);
                switch (op2)
                {
                    // 49 0F AF C2 -> imul rax, r10
                    case 0x0F:
                    {
                        if (read<std::uint8_t>(current) != 0xAF)
                            return false;
                        if (read<std::uint8_t>(current) != 0xC2)
                            return false;
                        auto const signed_rax =
                            static_cast<std::int64_t>(context.rax);
                        auto const signed_r10 =
                            static_cast<std::int64_t>(context.r10);
                        context.rax = static_cast<std::uint64_t>(
                            signed_rax * signed_r10);
                        break;
                    }
                    // 49 BA imm64 -> mov r10, imm64
                    case 0xBA:
                        context.r10 = read<std::uint64_t>(current);
                        break;
                    default:
                        return false;
                }
                break;
            }
            default:
                return false;
        }
    }

    return false;
}
