#pragma once

#include "mkpivm/codec.h"
#include "mkpivm/seed.h"
#include "mkpivm/util.h"
#include "mkpivm/vm_isa.h"
#include "mkpivm/x64_emit.h"
#include "mkpivm/x86_emit.h"

#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

namespace mkpivm {
    // grab the prologue NV-push order for an emitter. codecs that wanna leak
    // VM NV regs back over the stack saves need to know what's in what slot.
    const std::vector<std::uint8_t>* prologue_order_for(const X64Emitter& e);
    const std::vector<std::uint8_t>* prologue_order_for(const X86Emitter& e);

    // emits the PIC scaffolding around the codec handlers
    class VMCodeGen {
        public:
            VMCodeGen(const VMConfig& vm, const CodecRegistry& codecs, SeedRng& rng);

            void emit_full(
                X64Emitter& e,
                std::size_t bytecode_size,
                std::size_t data_island_size,
                std::uint32_t block_table_count
            );

            void emit_full(
                X86Emitter& e,
                std::size_t bytecode_size,
                std::size_t data_island_size,
                std::uint32_t block_table_count
            );

            // offsets we hand back so the packager can wire fixups
            struct Offsets {
                std::size_t              entry{0};
                std::size_t              dispatch_entry{0};
                std::size_t              handler_table{0};      // 256-entry int32 table
                std::vector<std::size_t> handler_offsets;       // 256 entries, -1 if unused
                std::size_t              exit_handler{0};
                std::size_t              bytecode_placement{0}; // where bytecode is appended
                std::size_t              data_island_placement{0};

                // range mode only 
                std::vector<std::size_t> range_entries;

                // one-byte marker. state_init checks it before decrypting in
                // place, sets it after pls no doubling
                std::size_t init_flag{0};

                // separate one-byte marker for the lazy data-island decrypt
                std::size_t data_island_init_flag{0};

                // 8-byte blob mirror of the runtime nonce. computed once via
                // rdtsc^cipher_init on first state_init, copied into the
                // per-entry VMState slot every entry after. VMState dies with
                // the stack between range entries so the old VMState-only
                // scheme handed dispatch random stack garbage for entry 2.
                std::size_t runtime_nonce_slot{0};
            };

            const Offsets& offsets() const noexcept { return off_; }

            // only emit full handler bodies for codecs whose family is in `used` 
            // why should we give everyone the full table if they dont use it.
            void set_used_families(std::unordered_set<std::string> used) {
                used_families_ = std::move(used);
                prune_handlers_ = true;
            }

            // hybrid mode. emit_full produces N per-range entry stubs at the start
            // of the VM region instead of one prologue 
            void set_range_mode(std::vector<std::uint32_t> entry_bc_offsets) {
                range_entry_bc_offsets_ = std::move(entry_bc_offsets);
                range_mode_ = true;
            }

            const std::vector<std::size_t>& range_entry_stub_offsets() const noexcept {
                return off_.range_entries;
            }

        private:
            const VMConfig&                 vm_;
            const CodecRegistry&            codecs_;
            SeedRng&                        rng_;
            Offsets                         off_{};
            std::unordered_set<std::string> used_families_{};
            bool                            prune_handlers_{false};
            bool                            range_mode_{false};
            std::vector<std::uint32_t>      range_entry_bc_offsets_{};

            // cached NV-push order
            std::array<std::uint8_t, 8>     cached_nv_order_x64_{};
            bool                            cached_nv_order_x64_set_{false};
            std::array<std::uint8_t, 4>     cached_nv_order_x86_{};
            bool                            cached_nv_order_x86_set_{false};

            void emit_prologue(X64Emitter& e, std::size_t data_island_size);
            void emit_state_init(
                X64Emitter& e,
                std::size_t bytecode_size,
                std::size_t data_island_size,
                std::uint32_t block_table_count,
                bool skip_regs_zero = false
            );

            void emit_range_entry(
                X64Emitter& e,
                std::uint32_t bytecode_offset,
                std::size_t data_island_size,
                std::uint32_t block_table_count
            );

            void emit_handler_table(X64Emitter& e);
            void emit_all_handlers(X64Emitter& e);
            void emit_exit_handler(X64Emitter& e);

            void emit_prologue(X86Emitter& e, std::size_t data_island_size);
            void emit_state_init(
                X86Emitter& e,
                std::size_t bytecode_size,
                std::size_t data_island_size,
                std::uint32_t block_table_count,
                bool skip_regs_zero = false
            );

            void emit_range_entry(
                X86Emitter& e,
                std::uint32_t bytecode_offset,
                std::size_t data_island_size,
                std::uint32_t block_table_count
            );

            void emit_handler_table(X86Emitter& e);
            void emit_all_handlers(X86Emitter& e);
            void emit_exit_handler(X86Emitter& e);

        public:
            // one trampoline body per call site. control lands here when the
            // callee's ret pops the trampoline addr off the shadow stack
            void emit_trampoline(X64Emitter& e, std::uint32_t bytecode_offset);
            void emit_trampoline(X86Emitter& e, std::uint32_t bytecode_offset);
    };
}