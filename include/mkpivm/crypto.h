#pragma once

#include "mkpivm/vm_isa.h"

#include <cstdint>
#include <vector>

namespace mkpivm {
    // shortcut so callers can encrypt a buffer without dragging in the whole codec
    // stack. real cipher work happens in vm_isa.cpp and codec.cpp.
    inline void encrypt_bytecode(const VMConfig& vm, std::vector<std::uint8_t>& bc) {
        vm.encrypt_inplace(bc);
    }
}