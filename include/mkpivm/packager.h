#pragma once

#include "mkpivm/arch.h"
#include "mkpivm/util.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace mkpivm {
    // half-open byte windows. start, end-exclusive
    using ByteRange = std::pair<std::uint32_t, std::uint32_t>;

    struct PackageOptions {
        Arch                   arch{Arch::X64};
        std::uint64_t          seed{0xDEADBEEFCAFEBABEULL};
        std::uint64_t          base_va{0};
        bool                   verbose{false};
        std::vector<ByteRange> ranges{};

        // accept ranges that exit via tail-jmp instead of ret
        bool coroutines_allowed{false};

        // --pack mode. skip the lifter entirely, stuff the input bytes into the
        // data island encrypted, emit a one-insn IR program of JMP_NATIVE imm=0,
        // and let the wrapper VM decrypt and jump
        bool pack_mode{false};
    };

    struct PackageResult {
        std::vector<std::uint8_t> blob;
        std::string               stats;
    };

    // lift, virtualize, encrypt, pack. throws on lift errors like a good boy
    PackageResult package_shellcode(Span<std::uint8_t> shellcode, const PackageOptions& opt);
}