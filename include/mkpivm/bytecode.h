#pragma once

#include "mkpivm/util.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace mkpivm {
    // accumulates plaintext bytecode. tracks branch fixups 
    class BytecodeBuilder {
        public:
            std::size_t pos() const noexcept { return buf_.size(); }
            void u8 (std::uint8_t  v) { buf_.push_back(v); }

            void u16(std::uint16_t v) {
                buf_.push_back(static_cast<std::uint8_t>(v));
                buf_.push_back(static_cast<std::uint8_t>(v >> 8));
            }

            void u32(std::uint32_t v) {
                for (int i = 0; i < 4; ++i) buf_.push_back(static_cast<std::uint8_t>(v >> (8*i)));
            }

            void u64(std::uint64_t v) {
                for (int i = 0; i < 8; ++i) buf_.push_back(static_cast<std::uint8_t>(v >> (8*i)));
            }

            void bytes(const std::uint8_t* p, std::size_t n) { buf_.insert(buf_.end(), p, p+n); }

            // record this cursor as the start of IR block_id
            void mark_block(std::uint32_t block_id) {
                block_offsets_[block_id] = buf_.size();
            }

            std::uint32_t block_offset(std::uint32_t block_id) const {
                auto it = block_offsets_.find(block_id);
                if (it == block_offsets_.end()) throw Error("block_offset: unbound id");
                return static_cast<std::uint32_t>(it->second);
            }

            // placeholder rel32 to a target block. resolved later to target_off
            // minus end_of_field
            void emit_branch_rel32(std::uint32_t target_block_id) {
                branch_fixups_.push_back({buf_.size(), target_block_id});
                u32(0);
            }

            // walk the fixup list once every block has an offset
            void resolve_branches() {
                for (const auto& f : branch_fixups_) {
                    auto it = block_offsets_.find(f.target_block_id);

                    if (it == block_offsets_.end()) throw Error("resolve_branches: missing block");
                    const std::int64_t rel = static_cast<std::int64_t>(it->second) - (static_cast<std::int64_t>(f.patch_pos) + 4);

                    if (rel < INT32_MIN || rel > INT32_MAX) throw Error("resolve_branches: oob");
                    const std::uint32_t v = static_cast<std::uint32_t>(static_cast<std::int32_t>(rel));

                    for (int i = 0; i < 4; ++i) {
                        buf_[f.patch_pos + i] = static_cast<std::uint8_t>(v >> (8*i));
                    }
                }
                branch_fixups_.clear();
            }

            // placeholder offset into the data island for an original VA. encoder
            // fills it in using the IRProgram data map
            void emit_data_island_offset_for_va(std::uint64_t va) {
                data_fixups_.push_back({buf_.size(), va});
                u32(0);
            }

            struct DataFixup { std::size_t patch_pos; std::uint64_t va; };
            const std::vector<DataFixup>& data_fixups() const noexcept { return data_fixups_; }

            // placeholder u32 the packager fills with the offset of the trampoline
            // for the post-call block 
            void emit_trampoline_offset_for_return_va(std::uint64_t va) {
                trampoline_fixups_.push_back({buf_.size(), va});
                u32(0);
            }
            
            struct TrampolineFixup { std::size_t patch_pos; std::uint64_t return_va; };
            const std::vector<TrampolineFixup>& trampoline_fixups() const noexcept { return trampoline_fixups_; }

            // poke a u32 in place, encoder uses this when patching data refs
            void poke_u32(std::size_t at, std::uint32_t v) {
                for (int i = 0; i < 4; ++i) buf_[at + i] = static_cast<std::uint8_t>(v >> (8*i));
            }

            std::vector<std::uint8_t> take() { return std::move(buf_); }
            const std::vector<std::uint8_t>& view() const noexcept { return buf_; }

            // sorted block start offsets. block 0 is at 0, the rest follow emit order.
            std::vector<std::size_t> block_start_offsets() const {
                std::vector<std::size_t> out;
                out.reserve(block_offsets_.size());
                for (const auto& kv : block_offsets_) out.push_back(kv.second);
                std::sort(out.begin(), out.end());
                return out;
            }

        private:
            std::vector<std::uint8_t> buf_;
            struct BranchFixup { std::size_t patch_pos; std::uint32_t target_block_id; };

            std::vector<BranchFixup>                       branch_fixups_;
            std::vector<DataFixup>                         data_fixups_;
            std::vector<TrampolineFixup>                   trampoline_fixups_;
            std::unordered_map<std::uint32_t, std::size_t> block_offsets_;
    };
}