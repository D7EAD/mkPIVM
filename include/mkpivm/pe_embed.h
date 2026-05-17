#pragma once

#include "mkpivm/arch.h"
#include "mkpivm/util.h"

#include <cstdint>
#include <string>
#include <vector>

namespace mkpivm {
    struct EmbedOptions {
        // PE we're going to mangle
        std::string target_pe_path;

        // RVA where we drop the jmp rel32 
        std::uint32_t at_rva{0};

        // optional 8-byte section name 
        std::string section_name;

        // true: wrapper spawns CreateThread so host main keeps running. 
        // false: wrapper calls vm_blob directly, blocking
        bool spawn_thread{true};
        bool verbose{false};
    };

    struct EmbedResult {
        std::vector<std::uint8_t> patched_pe;
        std::string               stats;
    };

    // patch the PE: add a new RWX section holding a wrapper + vm_blob, write a
    // jmp rel32 at at_rva that lands in the wrapper. wrapper saves flags and
    // volatile regs, transfers to vm_blob, restores, runs the displaced bytes,
    // jmps back.
    //
    // there are better ways to do this, but will explore later
    EmbedResult embed_vm_blob(Span<std::uint8_t> vm_blob, Arch arch, const EmbedOptions& opt);
}