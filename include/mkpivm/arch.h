#pragma once

#include <cstdint>
#include <string_view>

namespace mkpivm {
    enum class Arch : std::uint8_t {
        X86 = 0,
        X64 = 1,
    };

    constexpr std::string_view arch_name(Arch a) noexcept {
        return a == Arch::X64 ? "x64" : "x86";
    }

    constexpr std::uint8_t arch_ptr_bytes(Arch a) noexcept {
        return a == Arch::X64 ? 8u : 4u;
    }

    constexpr std::uint8_t arch_ptr_bits(Arch a) noexcept {
        return arch_ptr_bytes(a) * 8u;
    }

    // 16 on x64, 8 on x86 go figure
    constexpr std::uint8_t arch_native_gpr_count(Arch a) noexcept {
        return a == Arch::X64 ? 16u : 8u;
    }
}