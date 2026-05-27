#include "mkpivm/cfg.h"

#include <Zydis/Zydis.h>
#include <algorithm>
#include <deque>

namespace mkpivm {
    struct CFGBuilder::Impl {
        ZydisDecoder decoder{};
    };

    CFGBuilder::CFGBuilder(Arch arch, Span<std::uint8_t> code, std::uint64_t base_va)
    : impl_{std::make_unique<Impl>()}, arch_{arch}, code_{code}, base_va_{base_va} {
        const ZydisMachineMode mm = (arch == Arch::X64) ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32;
        const ZydisStackWidth  sw = (arch == Arch::X64) ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32;
        if (ZYAN_FAILED(ZydisDecoderInit(&impl_->decoder, mm, sw))) {
            throw Error("ZydisDecoderInit failed");
        }
    }

    CFGBuilder::~CFGBuilder() = default;

    void CFGBuilder::set_lifted_ranges(
        std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges) {
        lifted_ranges_ = std::move(ranges);
    }

    void CFGBuilder::build() {
        scan_ascii_strings();
        if (lifted_ranges_.empty()) {
            // default mode, one entry at the start of the blob.
            leaders_.insert(base_va_);
            recursive_disassemble(base_va_);
        }
        else {
            // hybrid mode 
            for (const auto& [s, e] : lifted_ranges_) {
                (void)e;
                leaders_.insert(s);
                recursive_disassemble(s);
            }
        }
        finalize_blocks();
    }

    // find ascii string regions 
    void CFGBuilder::scan_ascii_strings() {
        constexpr std::size_t kMinAscii = 8;
        const std::size_t     n = code_.size;
        std::size_t           i = 0;

        while (i < n) {
            std::size_t j = i;
            while (j < n) {
                const std::uint8_t b = code_.data[j];
                if (b < 0x20 || b > 0x7E) break;
                ++j;
            }
            const bool nul_term = (j < n && code_.data[j] == 0x00);
            const bool long_run = (j - i) >= kMinAscii;

            // call-then-string check: byte at i-5 is 0xE8, the start of a
            // 5-byte call rel32 sitting right before the string.
            const bool call_anchor = (j - i) >= 3 && i >= 5 && code_.data[i - 5] == 0xE8;

            if (nul_term && (long_run || call_anchor)) {
                ascii_strings_.push_back({base_va_ + i, base_va_ + j + 1});
                i = j + 1;
            }
            else {
                i = j + 1;
            }
        }
    }

    bool CFGBuilder::in_ascii_data(std::uint64_t va) const noexcept {
        for (const auto& r : ascii_strings_) {
            if (va >= r.start_va && va < r.end_va) return true;
        }
        return false;
    }

    void CFGBuilder::recursive_disassemble(std::uint64_t entry) {
        std::deque<std::uint64_t> worklist;
        worklist.push_back(entry);

        while (!worklist.empty()) {
            std::uint64_t va = worklist.front();
            worklist.pop_front();

            while (in_lifted(va)) {
                if (code_vas_.count(va)) break;

                // bail on any pre-identified ascii string 
                if (in_ascii_data(va)) break;

                const std::size_t offset = static_cast<std::size_t>(va - base_va_);
                const std::size_t avail  = code_.size - offset;

                ZydisDecodedInstruction   insn{};
                ZydisDecodedOperand       ops[ZYDIS_MAX_OPERAND_COUNT]{};
                const ZyanStatus status = ZydisDecoderDecodeFull(
                    &impl_->decoder,
                    code_.data + offset,
                    avail,
                    &insn,
                    ops
                );

                if (ZYAN_FAILED(status)) {
                    // not reachable as code, treat the rest as data.
                    break;
                }

                code_vas_.insert(va);
                const std::uint64_t next_va = va + insn.length;

                // any rip-relative LEA target that lands inside the blob but
                // outside reachable code is a data ref.
                if (insn.mnemonic == ZYDIS_MNEMONIC_LEA) {
                    for (std::uint8_t i = 0; i < insn.operand_count; ++i) {
                        if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                            ops[i].mem.base == ZYDIS_REGISTER_RIP &&
                            ops[i].mem.disp.has_displacement) {
                            const std::int64_t disp = ops[i].mem.disp.value;
                            const std::uint64_t ref_va = next_va + static_cast<std::uint64_t>(disp);
                            if (ref_va >= base_va_ && ref_va < base_va_ + code_.size) {
                                lea_data_refs_.insert(ref_va);
                            }
                        }
                    }
                }

                const auto meta    = insn.meta;
                const bool is_call = (meta.category == ZYDIS_CATEGORY_CALL);
                const bool is_ret  = (meta.category == ZYDIS_CATEGORY_RET);
                const bool is_cjmp = (meta.category == ZYDIS_CATEGORY_COND_BR);
                const bool is_ujmp = (meta.category == ZYDIS_CATEGORY_UNCOND_BR);

                // for direct rel jmp/call, resolve the target.
                std::uint64_t branch_target = 0;
                bool has_static_target = false;
                if (is_call || is_cjmp || is_ujmp) {
                    for (std::uint8_t i = 0; i < insn.operand_count; ++i) {
                        if (ops[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                            ops[i].imm.is_relative) {
                            ZyanU64 abs = 0;
                            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                                                 &insn,
                                                 &ops[i],
                                                 va,
                                                 &abs
                                             ))) {
                                branch_target = abs;
                                has_static_target = true;
                            }
                        }
                    }
                }

                // targets that fall outside lifted regions don't get enqueued 
                if (has_static_target && in_lifted(branch_target)) {
                    leaders_.insert(branch_target);
                    if (is_call) {
                        call_targets_.insert(branch_target);
                    }
                    else {
                        jmp_targets_.insert(branch_target); 
                    }
                    
                    if (!code_vas_.count(branch_target)) worklist.push_back(branch_target);
                }

                if (is_ret) {
                    leaders_.insert(next_va);
                    break;
                }
                
                if (is_ujmp) {
                    leaders_.insert(next_va);
                    break;
                }

                // cond branches and calls fall through.
                if (is_cjmp || is_call) {
                    leaders_.insert(next_va);
                }
                
                va = next_va;
            }
        }
    }

    void CFGBuilder::finalize_blocks() {
        if (code_vas_.empty()) return;

        std::vector<std::uint64_t> sorted_leaders(leaders_.begin(), leaders_.end());
        sorted_leaders.erase(
            std::remove_if(
                sorted_leaders.begin(), 
                sorted_leaders.end(),
                [&](std::uint64_t v) { 
                    return !code_vas_.count(v) || !in_code(v); 
                }
            ),
            sorted_leaders.end()
        );
        std::sort(sorted_leaders.begin(), sorted_leaders.end());

        // from each leader, walk forward until we hit a terminator like ret or
        // unconditional jmp, or until we reach the next leader.
        auto next_leader = [&](std::uint64_t after) -> std::uint64_t {
            auto it = std::upper_bound(sorted_leaders.begin(), sorted_leaders.end(), after);
            return it == sorted_leaders.end() ? UINT64_MAX : *it;
        };

        for (std::uint64_t leader : sorted_leaders) {
            Block b;
            b.start_va = leader;
            b.is_call_target = (call_targets_.count(leader) != 0);
            b.is_jmp_target  = (jmp_targets_.count(leader) != 0);

            const std::uint64_t boundary = next_leader(leader);
            std::uint64_t va = leader;
            while (in_code(va) && code_vas_.count(va) && va < boundary) {
                b.insn_vas.push_back(va);
                const std::size_t offset = static_cast<std::size_t>(va - base_va_);
                const std::size_t avail  = code_.size - offset;
                ZydisDecodedInstruction insn{};
                ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
                if (ZYAN_FAILED(ZydisDecoderDecodeFull(
                        &impl_->decoder,
                        code_.data + offset,
                        avail,
                        &insn,
                        ops
                    ))) break;
                const std::uint64_t next_va = va + insn.length;
                const auto cat = insn.meta.category;

                if (cat == ZYDIS_CATEGORY_RET || cat == ZYDIS_CATEGORY_UNCOND_BR) {
                    if (cat == ZYDIS_CATEGORY_UNCOND_BR) {
                        for (std::uint8_t i = 0; i < insn.operand_count; ++i) {
                            if (ops[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && ops[i].imm.is_relative) {
                                ZyanU64 abs = 0;
                                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                                                     &insn,
                                                     &ops[i],
                                                     va,
                                                     &abs
                                                 ))) {
                                    if (in_code(abs)) b.successors.push_back(abs);
                                }
                            }
                        }
                    }
                    else {
                        b.ends_with_ret = true;
                    }

                    b.end_va = next_va;
                    va = next_va;
                    break;
                }

                if (cat == ZYDIS_CATEGORY_COND_BR) {
                    for (std::uint8_t i = 0; i < insn.operand_count; ++i) {
                        if (ops[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && ops[i].imm.is_relative) {
                            ZyanU64 abs = 0;
                            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                                                 &insn,
                                                 &ops[i],
                                                 va,
                                                 &abs
                                             ))) {
                                if (in_code(abs)) b.successors.push_back(abs);
                            }
                        }
                    }

                    if (in_code(next_va) && code_vas_.count(next_va)) b.successors.push_back(next_va);

                    b.end_va = next_va;
                    va = next_va;
                    break;
                }

                // call or normal insn: keep going in this block. call falls through.
                va = next_va;
            }

            if (b.end_va == 0) b.end_va = va;

            // if the block ran into the next leader by fall-through, that
            // leader is the implicit successor 
            if (!b.ends_with_ret && b.successors.empty() &&
                in_code(b.end_va) && code_vas_.count(b.end_va)) {
                b.successors.push_back(b.end_va);
            }

            if (!b.insn_vas.empty()) {
                va_to_block_id_[b.start_va] = static_cast<std::uint32_t>(blocks_.size());
                blocks_.push_back(std::move(b));
            }
        }

        // data ranges are just the gaps in the blob not covered by code_vas_,
        // along with anything LEA refs point at.
        std::vector<std::pair<std::uint64_t, std::uint64_t>> code_spans;
        code_spans.reserve(blocks_.size());

        for (const auto& b : blocks_) code_spans.emplace_back(b.start_va, b.end_va);
        std::sort(code_spans.begin(), code_spans.end());

        std::uint64_t cursor = base_va_;
        const std::uint64_t code_end = base_va_ + code_.size;

        for (const auto& [s, e] : code_spans) {
            if (cursor < s) data_ranges_.push_back({cursor, s});
            cursor = std::max(cursor, e);
        }

        if (cursor < code_end) data_ranges_.push_back({cursor, code_end});
    }
}