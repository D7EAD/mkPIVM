#pragma once

#include "mkpivm/arch.h"
#include "mkpivm/util.h"

#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <utility>
#include <vector>

namespace mkpivm {
    class CFGBuilder {
        public:
            struct Block {
                std::uint64_t start_va{0};
                std::uint64_t end_va{0}; // one past last byte
                std::vector<std::uint64_t> insn_vas;
                std::vector<std::uint64_t> successors;
                bool is_call_target{false};
                bool is_jmp_target{false};
                bool ends_with_ret{false}; // scan looks at this
            };

            struct DataRange {
                std::uint64_t start_va{0};
                std::uint64_t end_va{0};
            };

            CFGBuilder(Arch arch, Span<std::uint8_t> code, std::uint64_t base_va);
            ~CFGBuilder();

            CFGBuilder(const CFGBuilder&) = delete;
            CFGBuilder& operator=(const CFGBuilder&) = delete;

            void build();

            // hybrid mode 
            void set_lifted_ranges(std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges);

            const std::vector<Block>& blocks() const noexcept { return blocks_; }
            const std::vector<DataRange>& data_ranges() const noexcept { return data_ranges_; }
            const std::map<std::uint64_t, std::uint32_t>& va_to_block_id() const noexcept { return va_to_block_id_; }
            const std::set<std::uint64_t>& code_vas() const noexcept { return code_vas_; }
            const std::set<std::uint64_t>& lea_data_refs() const noexcept { return lea_data_refs_; }

            bool in_code(std::uint64_t va) const noexcept {
                return va >= base_va_ && va < base_va_ + code_.size;
            }

            // is this VA something we lift? idk. in default mode same as in_code.
            // in hybrid mode only true inside a configured range. lifter
            // uses this to pick BR vs JMP_NATIVE.
            bool in_lifted(std::uint64_t va) const noexcept {
                if (lifted_ranges_.empty()) return in_code(va);
                for (const auto& [s, e] : lifted_ranges_) {
                    if (va >= s && va < e) return true;
                }
                return false;
            }

            Span<std::uint8_t> code() const noexcept { return code_; }
            std::uint64_t base_va() const noexcept { return base_va_; }
            Arch arch() const noexcept { return arch_; }

        private:
            struct Impl;
            std::unique_ptr<Impl> impl_;

            Arch arch_;
            Span<std::uint8_t> code_;
            std::uint64_t base_va_;

            std::set<std::uint64_t> code_vas_;
            std::set<std::uint64_t> leaders_;
            std::set<std::uint64_t> call_targets_;
            std::set<std::uint64_t> jmp_targets_;
            std::set<std::uint64_t> lea_data_refs_;

            // ASCII string-shaped data the prepass found. disasm stops at
            // these so we don't try to lift "kernel32.dll" as instructions
            // as that would be retarded
            std::vector<DataRange> ascii_strings_;

            std::vector<Block> blocks_;
            std::vector<DataRange> data_ranges_;
            std::map<std::uint64_t, std::uint32_t> va_to_block_id_;

            std::vector<std::pair<std::uint64_t, std::uint64_t>> lifted_ranges_;

            void scan_ascii_strings();
            bool in_ascii_data(std::uint64_t va) const noexcept;
            void recursive_disassemble(std::uint64_t va);
            void finalize_blocks();
    };
}