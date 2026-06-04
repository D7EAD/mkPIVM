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

        // --range-leak-nvs. JMP_NATIVE imm-cleanup overwrites the prologue
        // NV saves with the current VMState slots so lifted ebx/ebp/esi/edi
        // and r12..r15 writes make it back to the surrounding native bytes.
        bool range_leak_nvs{false};

        // --coro-prelo N. for coroutine-style range entries where native code
        // has pushed values onto the real stack BEFORE we enter the VM at a
        // mid-helper offset.
        std::uint32_t coro_prelo{0};

        // --heap-stack. switch the VM dispatcher to a blob-embedded static
        // stack region instead of running on top of the host's real
        // stack.
        bool heap_stack{false};

        // --rx 
        bool rx_mode{false};

        // --rx-loader-vp 
        bool rx_loader_vp{false};
    };

    struct PackageResult {
        std::vector<std::uint8_t> blob;
        std::string               stats;
    };

    // lift, virtualize, encrypt, pack. throws on lift errors like a good boy
    PackageResult package_shellcode(Span<std::uint8_t> shellcode, const PackageOptions& opt);
}