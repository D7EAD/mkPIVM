#include "mkpivm/vm_isa.h"
#include "mkpivm/x64_emit.h"

#include <algorithm>
#include <array>

namespace mkpivm {
    VMConfig::VMConfig(Arch arch, SeedRng& rng) : arch_{arch}, master_seed_{rng.next()} {
        // register file shape
        // need 16 arch gprs + 4 tmps + at least 4 scratch = 24 minimum
        reg_count_ = static_cast<std::uint8_t>(rng.uniform(24, 32));

        // XReg to slot mapping. random permutation over 0..reg_count_-1 with
        // the first 16 reserved for x86 gprs
        std::vector<std::uint8_t> perm(reg_count_);
        for (std::uint8_t i = 0; i < reg_count_; ++i) perm[i] = i;
        shuffle_in_place(perm, rng);

        const std::uint8_t gpr_count = arch_native_gpr_count(arch);
        xreg_to_slot_.fill(0xFF);
        for (std::uint8_t i = 0; i < gpr_count; ++i) {
            xreg_to_slot_[i] = perm[i];
        }

        // four slots for Tmp0..Tmp3. these sit past the arch gprs 
        const std::uint8_t tmp_count = 4;
        for (std::uint8_t i = 0; i < tmp_count; ++i) {
            xreg_to_slot_[16 + i] = perm[gpr_count + i];
        }
        scratch_slots_.assign(perm.begin() + gpr_count + tmp_count, perm.begin() + reg_count_);

        // VMState layout. fields go in random order 
        auto pad = [&](std::uint16_t cur, std::uint16_t align) {
            const std::uint16_t over = cur % align;
            return over ? static_cast<std::uint16_t>(cur + (align - over)) : cur;
        };
        
        auto sprinkle_gap = [&](std::uint16_t cur)->std::uint16_t {
            return cur + static_cast<std::uint16_t>(rng.uniform(0, 7));
        };

        std::uint16_t cur = static_cast<std::uint16_t>(rng.uniform(0, 31)); // random initial offset
        cur = pad(cur, 8);

        // reg-slot array.
        state_.regs_base         = cur;
        state_.regs_total_bytes  = static_cast<std::uint16_t>(reg_count_ * 8);
        cur = static_cast<std::uint16_t>(cur + state_.regs_total_bytes);

        // scalar fields, placed in random order.
        enum Field { F_OP, F_A, F_B, F_RES, F_W, F_DF, F_CSP, F_RSP, F_BCB, F_DIB, F_BTB, F_BTC, F_TRB, F_EXT, F_CSB, F_VP, F_VPO, F_END };
        std::array<std::uint8_t, F_END> order{};
        for (std::uint8_t i = 0; i < F_END; ++i) order[i] = i;
        shuffle_in_place(order, rng);

        for (auto f : order) {
            cur = sprinkle_gap(cur);
            cur = pad(cur, 8);
            switch (f) {
                case F_OP:  state_.flags_op          = cur; cur += 8;   break;
                case F_A:   state_.flags_a           = cur; cur += 8;   break;
                case F_B:   state_.flags_b           = cur; cur += 8;   break;
                case F_RES: state_.flags_result      = cur; cur += 8;   break;
                case F_W:   state_.flags_width       = cur; cur += 8;   break;
                case F_DF:  state_.df                = cur; cur += 8;   break;
                case F_CSP: state_.call_sp           = cur; cur += 8;   break;
                case F_RSP: state_.saved_native_rsp  = cur; cur += 8;   break;
                case F_BCB: state_.bytecode_base     = cur; cur += 8;   break;
                case F_DIB: state_.data_island_base  = cur; cur += 8;   break;
                case F_BTB: state_.block_table_base  = cur; cur += 8;   break;
                case F_BTC: state_.block_table_count = cur; cur += 8;   break;
                case F_TRB: state_.trampoline_base   = cur; cur += 8;   break;
                case F_EXT: state_.cipher_extra      = cur; cur += 768; break; // cipher constants, s-box, scratch
                case F_CSB: state_.call_stack_base   = cur; cur += 0;   break; // real size set below
                case F_VP:  state_.vp_addr           = cur; cur += 8;   break;
                case F_VPO: state_.vp_old            = cur; cur += 8;   break; // 8B alloc for DWORD &old_protect
                default:                                                break;
            }
        }

        // call stack: number of return slots times 8 bytes per slot.
        call_stack_depth_ = static_cast<std::uint32_t>(rng.uniform(32, 96));
        cur = pad(cur, 16);
        state_.call_stack_base = cur;
        cur += static_cast<std::uint16_t>(call_stack_depth_ * 8);

        // --rx mode 
        state_.data_island_buf_off = cur;

        state_.total_size = pad(cur, 16);

        // dispatcher native register assignment.
        if (arch_ == Arch::X64) {
            // win64 nv pool is 8 candidates: rbx, rbp, rdi, rsi, r12..r15 
            std::array<std::uint8_t, 8> nv{rx::rbx, rx::rbp, rx::rdi, rx::rsi, rx::r12, rx::r13, rx::r14, rx::r15};

            shuffle_in_place(nv, rng);
            regs_.state_ptr     = nv[0];
            regs_.ip            = nv[1];
            regs_.handler_base  = nv[2];
            regs_.cipher_state  = nv[3];
            regs_.scratch_a     = nv[4];
            regs_.scratch_b     = nv[5];
        }
        else {
            // win32 only has 4 nv gprs. ebx, esi, edi, ebp. dispatcher takes
            // 3 of them for state_ptr/ip/handler_base out of rsi,rdi,rbp,
            // and we pin cipher_state to rbx
            std::array<std::uint8_t, 3> nv32{rx::rsi, rx::rdi, rx::rbp};
            shuffle_in_place(nv32, rng);
            regs_.state_ptr    = nv32[0];
            regs_.ip           = nv32[1];
            regs_.handler_base = nv32[2];
            regs_.cipher_state = rx::rbx;

            // scratch_a/b are volatile eax/ecx/edx. they're recomputed at the
            // top of every handler so volatility across native calls is fine.
            std::array<std::uint8_t, 3> vol{rx::rax, rx::rcx, rx::rdx};
            shuffle_in_place(vol, rng);
            regs_.scratch_a = vol[0];
            regs_.scratch_b = vol[1];
        }

        // cipher choice and key material.
        cipher_ = static_cast<CipherKind>(rng.pick(4));
        cipher_init_ = rng.next();
        cipher_k1_   = rng.next() | 1ULL;
        cipher_k2_   = rng.next();

        // on 32-bit guests the runtime cipher state lives in a 32-bit gpr so
        // all the math is mod 2^32 
        if (arch_ == Arch::X86) {
            cipher_init_ &= 0xFFFFFFFFu;
            cipher_k1_   &= 0xFFFFFFFFu;
            if ((cipher_k1_ & 1) == 0) cipher_k1_ |= 1;
            cipher_k2_   &= 0xFFFFFFFFu;
        }

        // s-box is just a random permutation of 0..255.
        for (std::size_t i = 0; i < 256; ++i) sbox_[i] = static_cast<std::uint8_t>(i);
        shuffle_in_place(sbox_, rng);
        for (std::size_t i = 0; i < 256; ++i) sbox_inv_[sbox_[i]] = static_cast<std::uint8_t>(i);

        prologue_           = static_cast<PrologueStyle>(rng.pick(3));
        dispatch_           = static_cast<DispatchStyle>(rng.pick(2));
        shadow_stack_bytes_ = static_cast<std::uint32_t>(rng.uniform(2048, 8192) & ~0xFu);
        junk_density_       = static_cast<std::uint8_t>(rng.pick(4));

        // codec opcode assignment happens later in CodecRegistry. 
        static const char* kFamilies[] = {
            "MOV","IMM","LOAD","STORE","LEA","READ_SEG","ADD","ADC","SUB","SBB","INC","DEC",
            "NEG","NOT","AND","OR","XOR","SHL","SHR","SAR","ROL","ROR","RCL","RCR",
            "CMP","TEST","BR","BRCC","BRIND","CALLVM","RETVM","CALLNATIVE","JMPNATIVE",
            "RETNATIVE","PUSH","POP","XCHG","ZEXT","SEXT","BSWAP","SETCC","NOP","EXIT",
            "LOOP","CDQE","STOSB","LODSB","MOVSB","REP","DF","IMUL","MUL","IDIV","DIV"
        };

        for (auto* f : kFamilies) {
            const std::uint32_t v = rng.pick(3); // default 3 variants per family
            family_to_variant_[f] = v;
            OperandShape sh{};
            sh.reg_index_bits   = (reg_count_ <= 16 && rng.chance(1, 3)) ? 4u : 8u;
            sh.pack_two_regs    = (sh.reg_index_bits == 4) && rng.chance(1, 2);
            sh.scramble_regs    = rng.chance(1, 3);
            sh.disp32_first     = rng.chance(1, 2);
            sh.imm_then_reg     = rng.chance(1, 3);
            sh.extra_decoy_byte = rng.chance(1, 4);
            family_to_shape_[f] = sh;
        }
    }

    OperandShape VMConfig::operand_shape_for(std::string_view family) const {
        auto it = family_to_shape_.find(std::string(family));
        return it == family_to_shape_.end() ? OperandShape{} : it->second;
    }

    std::uint32_t VMConfig::variant_for(std::string_view family) const {
        auto it = family_to_variant_.find(std::string(family));
        return it == family_to_variant_.end() ? 0u : it->second;
    }

    std::uint8_t VMConfig::opcode_for(std::string_view k) const {
        auto it = family_to_opcode_.find(std::string(k));
        if (it == family_to_opcode_.end()) throw Error(std::string("no opcode for ") + std::string(k));
        return it->second;
    }

    void VMConfig::assign_opcode(std::string_view k, std::uint8_t b) {
        family_to_opcode_[std::string(k)] = b;
        op_to_key_[b] = std::string(k);
    }

    SeedRng VMConfig::codec_rng(std::string_view k) const {
        SeedRng base{master_seed_};
        return base.derive(k);
    }

    void VMConfig::encrypt_inplace(std::vector<std::uint8_t>& bc, const std::vector<std::size_t>& block_starts) const {
        std::uint64_t st = cipher_init_;
        const std::uint64_t k1 = cipher_k1_;
        const std::uint64_t k2 = cipher_k2_;

        // 32-bit guests: cipher state lives in a 32-bit gpr at runtime, so the
        // math is mod 2^32, truncate per step
        const bool is32 = (arch_ == Arch::X86);
        const std::uint64_t mask = is32 ? 0xFFFFFFFFULL : ~0ULL;
        auto rotl = [&](std::uint64_t x, int n) -> std::uint64_t {
            if (is32) {
                const std::uint32_t y = static_cast<std::uint32_t>(x);
                return static_cast<std::uint64_t>((y << n) | (y >> (32 - n)));
            }
            return (x << n) | (x >> (64 - n));
        };

        // mult and add constants per cipher kind 
        const auto kind = cipher_;
        const std::uint64_t mult = (kind == CipherKind::LcgSub)      ? 0x5851F42D4C957F2DULL :
                                   (kind == CipherKind::SBoxAdd)     ? 0x100000001B3ULL :
                                   (kind == CipherKind::FeistelByte) ? k1 : 0ULL;

        const std::uint64_t add = (kind == CipherKind::FeistelByte) ? k2 : k1;

        // walk a sorted copy of block_starts in lockstep with the bytecode index 
        std::vector<std::size_t> resets(block_starts);
        std::sort(resets.begin(), resets.end());
        std::size_t ri = 0;

        for (std::size_t i = 0; i < bc.size(); ++i) {
            while (ri < resets.size() && resets[ri] == i) {
                st = cipher_init_;
                ++ri;
            }
            std::uint8_t pt = bc[i];
            std::uint8_t ct = 0;
            switch (kind) {
                case CipherKind::ARX: {
                    st = (st + add) & mask;
                    st = rotl(st, 13) & mask;
                    ct = static_cast<std::uint8_t>(pt ^ (st & 0xFF));
                    break;
                }
                case CipherKind::LcgSub: {
                    st = (st * mult + add) & mask;
                    ct = static_cast<std::uint8_t>(pt + (st & 0xFF));
                    break;
                }
                case CipherKind::SBoxAdd: {
                    const std::uint8_t key = static_cast<std::uint8_t>(st);
                    ct = static_cast<std::uint8_t>(sbox_[pt] + key);
                    st = (st * mult + add) & mask;
                    break;
                }
                case CipherKind::FeistelByte: {
                    ct = static_cast<std::uint8_t>(pt ^ (st & 0xFF));
                    st = (st * mult + add) & mask;
                    break;
                }
            }
            bc[i] = ct;
        }
    }
}