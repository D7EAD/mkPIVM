#include "mkpivm/codec.h"
#include "mkpivm/vm_codegen.h"

#include <algorithm>

namespace mkpivm {
    static std::uint8_t slot_for(const VMConfig& vm, XReg r) {
        return vm.slot_of_xreg(r);
    }

    static void enc_slot(BytecodeBuilder& out, const VMConfig& vm, const VirReg& v) {
        out.u8(slot_for(vm, v.reg));
        out.u8(static_cast<std::uint8_t>(width_bytes(v.width)) | (v.is_high_byte ? 0x80 : 0));
    }

    // mem operand: base 1B, index 1B, scale_log2 1B, seg 1B, disp32 4B, width 1B
    static void enc_mem(BytecodeBuilder& out, const VMConfig& vm, const Mem& m) {
        out.u8(m.base  == XReg::Invalid ? 0xFF : slot_for(vm, m.base));
        out.u8(m.index == XReg::Invalid ? 0xFF : slot_for(vm, m.index));
        std::uint8_t scale_log2 = 0;

        switch (m.scale) {
            case 2: scale_log2  = 1; break;
            case 4: scale_log2  = 2; break;
            case 8: scale_log2  = 3; break;
            default: scale_log2 = 0; break; 
        }

        out.u8(scale_log2);
        out.u8(m.seg_override);
        out.u32(static_cast<std::uint32_t>(m.disp));
        out.u8(static_cast<std::uint8_t>(width_bytes(m.width)));
    }

    static void enc_imm_n(BytecodeBuilder& out, std::int64_t v, std::uint8_t bytes_count) {
        for (std::uint8_t i = 0; i < bytes_count; ++i) {
            out.u8(static_cast<std::uint8_t>(v >> (8 * i)));
        }
    }

    // hide sensitive immediates so the plaintext value doesn't show up as a
    // contiguous run after the stream cipher decrypts
    static void enc_imm_n_obfuscated(BytecodeBuilder& out, std::int64_t v,
                                     std::uint8_t bytes_count,
                                     const VMConfig& vm) {
        auto mix64 = [](std::uint64_t x) {
            x ^= x >> 33;
            x *= 0xFF51AFD7ED558CCDULL;
            x ^= x >> 33;
            x *= 0xC4CEB9FE1A85EC53ULL;
            x ^= x >> 33;
            return x;
        };

        const std::uint64_t mask = (bytes_count >= 8) ? ~0ULL : ((1ULL << (bytes_count * 8)) - 1);
        const std::uint64_t salt = vm.cipher_init_state() ^ static_cast<std::uint64_t>(out.pos());

        std::uint64_t h = mix64(static_cast<std::uint64_t>(v) ^ salt);
        const std::uint64_t a = h & mask; h = mix64(h);
        const std::uint64_t b = h & mask; h = mix64(h);
        const std::uint64_t c = h & mask;

        // d = a + b xor c - v
        const std::uint64_t d = (a + (b ^ c) - static_cast<std::uint64_t>(v)) & mask;
        auto emit_one = [&](std::uint64_t x) {
            for (std::uint8_t i = 0; i < bytes_count; ++i) out.u8(static_cast<std::uint8_t>(x >> (8 * i)));
        };

        emit_one(a);
        emit_one(b);
        emit_one(c);
        emit_one(d);
    }

    // cipher_extra offsets 
    constexpr std::int32_t kCipherAddOff   = 0;  // 0..7   cipher add k
    constexpr std::int32_t kCipherMultOff  = 8;  // 8..15  cipher mult k
    constexpr std::int32_t kSavedIpOff     = 16; // 16..23 saved ip during native bridge
    constexpr std::int32_t kSavedHbOff     = 24; // 24..31 saved handler_base
    constexpr std::int32_t kSavedCsOff     = 32; // 32..39 saved cipher_state
    constexpr std::int32_t kSavedTargetOff = 40; // 40..47 saved target value
    constexpr std::int32_t kCipherInitOff  = 48; // 48..55 cipher_init for block-boundary resync
    // 256..511 sbox_inv table for SBoxAdd

    // saved tag byte 0=imm, 1=vreg, 2=mem during JMP_NATIVE / CALL_NATIVE 
    constexpr std::int32_t kSavedTagOff = 72;

    // 32-bit nonce computed from rdtsc xor cipher_init at prologue 
    constexpr std::int32_t kRuntimeNonceOff = 80;

    // save slots for ip and cipher_state across the deferred data-island
    // decrypt 
    constexpr std::int32_t kPreDecryptIpOff = 88;
    constexpr std::int32_t kPreDecryptCsOff = 96;
    constexpr std::int32_t kSboxInvOff      = 256;

    // reload cipher_state from cipher_init 
    inline void emit_cipher_reset(X64Emitter& e, const VMConfig& vm) {
        const auto& r = vm.dispatcher_regs();
        const std::int32_t init_off = static_cast<std::int32_t>(vm.state_layout().cipher_extra) + kCipherInitOff;
        e.mov_reg_mem(
            r.cipher_state,
            r.state_ptr,
            init_off,
            true
        );
    }

    // fetch one byte from [ip], decrypt with current cipher state, update state,
    // advance ip, leave result in low 8 of dst 
    void emit_fetch_byte_dec(X64Emitter& e, const VMConfig& vm, std::uint8_t dst) {
        const auto& r = vm.dispatcher_regs();
        const std::int32_t add_off  = static_cast<std::int32_t>(vm.state_layout().cipher_extra) + kCipherAddOff;
        const std::int32_t mult_off = static_cast<std::int32_t>(vm.state_layout().cipher_extra) + kCipherMultOff;
        const std::int32_t sbox_off = static_cast<std::int32_t>(vm.state_layout().cipher_extra) + kSboxInvOff;

        // movzx dst, byte [ip]
        e.emit_rex(
            false,
            dst >= 8,
            false,
            r.ip >= 8
        );
        e.u8(0x0F); e.u8(0xB6);
        e.emit_modrm_mem(
            dst & 7,
            r.ip,
            rx::none,
            0,
            0
        );

        // inc ip
        e.inc_reg(r.ip, true);

        // mix byte with cipher_state low, then advance state
        auto add_cs_mem = [&](std::int32_t disp) {
            e.emit_rex(
                true,
                r.cipher_state >= 8,
                false,
                r.state_ptr >= 8
            );
            e.u8(0x03); // ADD r64, r/m64

            e.emit_modrm_mem(
                r.cipher_state & 7,
                r.state_ptr,
                rx::none,
                0,
                disp
            );
        };

        auto imul_cs_mem = [&](std::int32_t disp) {
            e.emit_rex(
                true,
                r.cipher_state >= 8,
                false,
                r.state_ptr >= 8
            );
            e.u8(0x0F); e.u8(0xAF); // IMUL r64, r/m64

            e.emit_modrm_mem(
                r.cipher_state & 7,
                r.state_ptr,
                rx::none,
                0,
                disp
            );
        };

        // 8-bit ops on cipher_state low and dst low 
        auto rex_byte = [](std::uint8_t reg_r, std::uint8_t reg_b) {
            return static_cast<std::uint8_t>(0x40 | (reg_r >= 8 ? 0x04 : 0) | (reg_b >= 8 ? 0x01 : 0));
        };

        auto xor8_dst_csLow = [&]() {
            e.u8(rex_byte(r.cipher_state, dst));
            e.u8(0x30); // XOR r/m8, r8
            e.emit_modrm(3, r.cipher_state & 7, dst & 7);
        };

        auto sub8_dst_csLow = [&]() {
            e.u8(rex_byte(r.cipher_state, dst));
            e.u8(0x28); // SUB r/m8, r8
            e.emit_modrm(3, r.cipher_state & 7, dst & 7);
        };

        switch (vm.cipher_kind()) {
            case CipherKind::ARX: {
                add_cs_mem(add_off);
                e.rol_reg_imm8(r.cipher_state, 13);
                xor8_dst_csLow();
                e.movzx_r64_r8(dst, dst);
                break;
            }
            case CipherKind::LcgSub: {
                imul_cs_mem(mult_off);
                add_cs_mem(add_off);

                // build did ct = pt + state_low, so invert with pt = ct - state_low
                sub8_dst_csLow();
                e.movzx_r64_r8(dst, dst);
                break;
            }
            case CipherKind::SBoxAdd: {
                // ct = sbox[pt] + state_low; state = state*mult + add
                // pt = sbox_inv[ct - state_low]; state = state*mult + add
                sub8_dst_csLow();
                e.movzx_r64_r8(dst, dst);

                // movzx dst, byte [state_ptr + dst + sbox_off]
                // modr/m: mod=10 disp32, reg=dst_low3, rm=4 with SIB follow.
                // sib: scale=0, index=dst, base=state_ptr
                e.emit_rex(
                    false,
                    dst >= 8,
                    dst >= 8,
                    r.state_ptr >= 8
                );
                e.u8(0x0F); e.u8(0xB6);
                e.emit_modrm(2, dst & 7, 4);
                e.emit_sib(0, dst & 7, r.state_ptr & 7);
                e.u32(static_cast<std::uint32_t>(sbox_off));
                imul_cs_mem(mult_off);
                add_cs_mem(add_off);
                break;
            }
            case CipherKind::FeistelByte: {
                xor8_dst_csLow();
                e.movzx_r64_r8(dst, dst);
                imul_cs_mem(mult_off);
                add_cs_mem(add_off);
                break;
            }
        }
    }

    void emit_fetch_uN_dec(X64Emitter& e, const VMConfig& vm, std::uint8_t dst, std::uint8_t n) {
        // assemble N little-endian bytes into dst 
        (void)vm;
        e.xor_reg_reg(dst, dst);
        if (n == 0) return;
        emit_fetch_byte_dec(e, vm, dst);

        for (std::uint8_t i = 1; i < n; ++i) {
            emit_fetch_byte_dec(e, vm, rx::r11);
            e.shl_reg_imm8(rx::r11, static_cast<std::uint8_t>(8 * i));
            e.or_reg_reg(dst, rx::r11);
        }
    }

    void emit_fetch_u32_dec(X64Emitter& e, const VMConfig& vm, std::uint8_t dst) {
        emit_fetch_uN_dec(
            e,
            vm,
            dst,
            4
        );
    }

    // pick a per-seed shuffled scratch from the volatile pool that doesn't
    // collide with any caller-supplied register 
    static std::uint8_t pick_temp_reg(const VMConfig& vm,
                                      std::uint64_t salt,
                                      std::initializer_list<std::uint8_t> avoid) {
        std::array<std::uint8_t, 7> pool{rx::rax, rx::rcx, rx::rdx, rx::r8, rx::r9, rx::r10, rx::r11};
        SeedRng local(vm.cipher_k1() ^ salt);
        shuffle_in_place(pool, local);

        for (std::uint8_t r : pool) {
            bool collide = false;
            for (std::uint8_t a : avoid) if (a == r) { collide = true; break; }
            if (!collide) return r;
        }

        return rx::rdx; // unreachable: pool > avoid
    }

    // mask reg to width_reg's width, stripping the high-byte flag 
    static void emit_mask_to_width(X64Emitter& e, const VMConfig& vm,
                                   std::uint8_t reg, std::uint8_t width_reg,
                                   std::uint64_t call_salt = 0) {
        // stack-save the shuffled temp 
        const std::uint8_t T = pick_temp_reg(vm, 0xA5751717ULL ^ call_salt, {reg, width_reg});
        e.push_reg(T);
        e.mov_reg_reg(T, width_reg);
        e.and_reg_imm32(T, 0x7F);

        // permute cascade order and body layout per seed + call_salt
        SeedRng rng(vm.cipher_k1() ^ 0xA5751717ULL ^ call_salt ^ 0x511177BCULL);
        std::array<int, 4> widths{1, 2, 4, 8};
        shuffle_in_place(widths, rng);

        // widths[0..2] are the three cascade tests, widths[3] is the inline default.
        std::array<int, 3> body_order{widths[0], widths[1], widths[2]};
        shuffle_in_place(body_order, rng);

        auto lbl_w1 = e.new_label(), lbl_w2 = e.new_label();
        auto lbl_w4 = e.new_label(), lbl_w8 = e.new_label();
        auto lbl_done = e.new_label();

        auto label_of = [&](int w) {
            switch (w) { 
                case 1:  return lbl_w1;
                case 2:  return lbl_w2;
                case 4:  return lbl_w4;
                default: return lbl_w8;
            }
        };

        auto emit_body = [&](int w) {
            switch (w) {
                case 1: e.and_reg_imm32(reg, 0xFF);       break;
                case 2: e.and_reg_imm32(reg, 0xFFFF);     break;
                case 4: e.mov_reg_reg(reg, reg, false);   break;
                case 8: /* full 64-bit, no mask needed */ break;
            }
        };

        for (int w : {widths[0], widths[1], widths[2]}) {
            e.cmp_reg_imm32(T, w);
            e.jcc_label(cc::z, label_of(w));
        }

        // inline default body, then jump out
        emit_body(widths[3]);
        e.jmp_label(lbl_done);

        // labeled bodies in permuted order.
        for (std::size_t i = 0; i < body_order.size(); ++i) {
            const int w = body_order[i];
            e.bind(label_of(w));
            emit_body(w);
            if (i + 1 != body_order.size()) e.jmp_label(lbl_done);
        }

        e.bind(lbl_done);
        e.pop_reg(T);
    }

    // extract architectural register-operand value from a 64-bit slot,
    // honoring the width byte 
    static void emit_extract_operand(X64Emitter& e, const VMConfig& vm, std::uint8_t reg, std::uint8_t width_reg) {
        const std::uint8_t T = pick_temp_reg(vm, 0xE107AC7117ULL, {reg, width_reg});
        e.push_reg(T);

        // shift right by 8 if the high-byte flag is set
        {
            auto lbl_no_hi = e.new_label();
            e.mov_reg_reg(T, width_reg);
            e.and_reg_imm32(T, 0x80);
            e.test_reg_reg(T, T);
            e.jcc_label(cc::z, lbl_no_hi);
            e.shr_reg_imm8(reg, 8);
            e.bind(lbl_no_hi);
        }

        // dispatch on width.
        e.mov_reg_reg(T, width_reg);
        e.and_reg_imm32(T, 0x7F);

        auto lbl_w8   = e.new_label(),
             lbl_w4   = e.new_label(),
             lbl_w2   = e.new_label(), 
             lbl_done = e.new_label();

        e.cmp_reg_imm32(T, 8);
        e.jcc_label(cc::z, lbl_w8);
        e.cmp_reg_imm32(T, 4);
        e.jcc_label(cc::z, lbl_w4);
        e.cmp_reg_imm32(T, 2);
        e.jcc_label(cc::z, lbl_w2);
        
        // width 1
        e.and_reg_imm32(reg, 0xFF);
        e.jmp_label(lbl_done);
        e.bind(lbl_w2);
        e.and_reg_imm32(reg, 0xFFFF);
        e.jmp_label(lbl_done);
        e.bind(lbl_w4);
        
        // 32-bit reg-reg mov zero-extends the top 32.
        e.mov_reg_reg(reg, reg, false);
        e.jmp_label(lbl_done);
        e.bind(lbl_w8);
        e.bind(lbl_done);
        e.pop_reg(T);
    }

    // write value into VMState slot at slot_idx_reg 
    static void emit_store_slot_value(X64Emitter& e, const VMConfig& vm,
                                      std::uint8_t slot_idx_reg, std::uint8_t value_reg,
                                      std::uint8_t width_reg) {
        const std::uint8_t T_ADDR = pick_temp_reg(vm, 0xA110C5577ULL, {slot_idx_reg, value_reg, width_reg});
        const std::uint8_t T_W    = pick_temp_reg(vm, 0xA110C5578ULL, {slot_idx_reg, value_reg, width_reg, T_ADDR});

        // save the two scratches we clobber 
        e.push_reg(T_ADDR);
        e.push_reg(T_W);

        // compute slot address into T_ADDR.
        e.lea_reg_mem(
            T_ADDR,
            vm.dispatcher_regs().state_ptr,
            slot_idx_reg,
            3,         
            static_cast<std::int32_t>(vm.state_layout().regs_base)
        );

        // high-byte flag set, so bump addr by 1 so byte-store hits the high byte.
        {
            auto lbl_no_hi = e.new_label();
            e.test_reg_reg(width_reg, width_reg);
            e.mov_reg_reg(T_W, width_reg);
            e.and_reg_imm32(T_W, 0x80);
            e.cmp_reg_imm32(T_W, 0);
            e.jcc_label(cc::z, lbl_no_hi);
            e.inc_reg(T_ADDR, true);
            e.bind(lbl_no_hi);
        }

        // strip the high bit for the real width.
        e.mov_reg_reg(T_W, width_reg);
        e.and_reg_imm32(T_W, 0x7F);

        auto lbl_w8  = e.new_label(),
             lbl_w4  = e.new_label(),
             lbl_w2  = e.new_label(),
             lbl_w1  = e.new_label(),
             lbl_end = e.new_label();

        e.cmp_reg_imm32(T_W, 8);
        e.jcc_label(cc::z, lbl_w8);
        e.cmp_reg_imm32(T_W, 4);
        e.jcc_label(cc::z, lbl_w4);
        e.cmp_reg_imm32(T_W, 2);
        e.jcc_label(cc::z, lbl_w2);

        // fall to width=1
        e.bind(lbl_w1);
        e.mov_mem_reg_size(
            T_ADDR,
            0,
            value_reg,
            1
        );
        e.jmp_label(lbl_end);
        e.bind(lbl_w2);
        e.mov_mem_reg_size(
            T_ADDR,
            0,
            value_reg,
            2
        );
        e.jmp_label(lbl_end);
        e.bind(lbl_w4);
        e.mov_mem_reg_size(
            T_ADDR,
            0,
            value_reg,
            4
        );

        // zero the top 32 bits to match x86 32-bit dst semantics.
        e.xor_reg_reg(T_W, T_W);
        e.mov_mem_reg(
            T_ADDR,
            4,
            T_W,
            false
        );
        e.jmp_label(lbl_end);
        e.bind(lbl_w8);
        e.mov_mem_reg(
            T_ADDR,
            0,
            value_reg,
            true
        );
        e.bind(lbl_end);
        e.pop_reg(T_W);
        e.pop_reg(T_ADDR);
    }

    // dispatch tail: fetch next opcode, look up handler offset, jump 
    void emit_dispatch_tail(X64Emitter& e, const VMConfig& vm) {
        const auto& r = vm.dispatcher_regs();
        const auto& st = vm.state_layout();
        emit_fetch_byte_dec(e, vm, r.scratch_a);

        // mov scratch_b_32, dword [handler_base + scratch_a*4] zexted.
        e.emit_rex(
            false,
            r.scratch_b >= 8,
            r.scratch_a >= 8,
            r.handler_base >= 8
        );
        e.u8(0x8B);
        e.emit_modrm_mem(
            r.scratch_b & 7,
            r.handler_base,
            r.scratch_a,
            2,
            0
        );

        // xor with the runtime nonce to undo the per-process xor layer
        // emit_state_init applied to the in-memory handler table
        e.emit_rex(
            false,
            r.scratch_b >= 8,
            false,
            r.state_ptr >= 8
        );
        e.u8(0x33);
        e.emit_modrm_mem(
            r.scratch_b & 7,
            r.state_ptr,
            rx::none,
            0,
            static_cast<std::int32_t>(st.cipher_extra) + kRuntimeNonceOff
        );

        // movsxd scratch_b, scratch_b_32
        e.movsxd_r64_r32(r.scratch_b, r.scratch_b);

        // lea scratch_a, [handler_base + scratch_b]
        e.lea_reg_mem(
            r.scratch_a,
            r.handler_base,
            r.scratch_b,
            0,
            0
        );
        e.jmp_reg(r.scratch_a);
    }

    // emit a short null-effect junk gadget.
    void emit_junk(X64Emitter& e, const VMConfig& vm, SeedRng& rng) {
        const std::uint8_t density = vm.junk_density();
        const std::uint32_t n = 1u + (density ? rng.pick(2u + density) : 0u);
        for (std::uint32_t i = 0; i < n; ++i) {
            switch (rng.pick(5)) {
                case 0: e.poly_nop(rng); break;
                case 1: {
                    const std::uint8_t s = vm.dispatcher_regs().scratch_a;
                    e.xor_reg_reg(s, s);
                    break;
                }
                case 2: {
                    const std::uint8_t s = vm.dispatcher_regs().scratch_b;
                    e.mov_reg_reg(s, s);
                    break;
                }
                case 3: {
                    const std::uint8_t s = vm.dispatcher_regs().scratch_a;
                    e.test_reg_reg(s, s);
                    break;
                }
                case 4: {
                    e.poly_nop(rng);
                    break;
                }
            }
        }
    }

    // codec implementations

    template <typename T>
    static const T& get_op(const IRInsn& i, std::size_t k) {
        return std::get<T>(i.ops[k]);
    }

    // IMM: dst_slot = imm
    void ImmCodec::encode(BytecodeBuilder& out, const IRInsn& i, const VMConfig& vm) const {
        out.u8(vm.opcode_for(family()));
        const auto& v = get_op<VirReg>(i, 0);
        enc_slot(out, vm, v);
        const auto& im = get_op<Imm>(i, 1);

        // 4-component obfuscated encoding so the original imm value never sits
        // as contiguous bytes in the bytecode encrypted or decrypted 
        enc_imm_n_obfuscated(
            out,
            im.value,
            8,
            vm
        );
    }

    void ImmCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();

        // slot index → scratch_a; width byte → scratch_b
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, r.scratch_b);

        // fetch the 4 obfuscation components, 8 bytes each, then compute
        // a + b xor c - d 
        e.sub_reg_imm32(rx::rsp, 48); // 32 for components, 16 for align

        // a -> [rsp+16]
        emit_fetch_uN_dec(
            e,
            vm,
            rx::rax,
            8
        );
        e.mov_mem_reg(
            rx::rsp,
            16,
            rx::rax,
            true
        );

        // b -> [rsp+24]
        emit_fetch_uN_dec(
            e,
            vm,
            rx::rax,
            8
        );
        e.mov_mem_reg(
            rx::rsp,
            24,
            rx::rax,
            true
        );

        // c -> [rsp+32]
        emit_fetch_uN_dec(
            e,
            vm,
            rx::rax,
            8
        );
        e.mov_mem_reg(
            rx::rsp,
            32,
            rx::rax,
            true
        );

        // d -> [rsp+40]
        emit_fetch_uN_dec(
            e,
            vm,
            rx::rax,
            8
        );
        e.mov_mem_reg(
            rx::rsp,
            40,
            rx::rax,
            true
        );

        // rax = b xor c
        e.mov_reg_mem(
            rx::rax,
            rx::rsp,
            24,
            true
        );
        e.mov_reg_mem(
            rx::r10,
            rx::rsp,
            32,
            true
        );
        e.xor_reg_reg(rx::rax, rx::r10, true);

        // rax += a
        e.mov_reg_mem(
            rx::r10,
            rx::rsp,
            16,
            true
        );
        e.add_reg_reg(rx::rax, rx::r10, true);

        // rax -= d
        e.mov_reg_mem(
            rx::r10,
            rx::rsp,
            40,
            true
        );
        e.sub_reg_reg(rx::rax, rx::r10, true);

        // store rax into the slot. IMM always overwrites the full 64
        e.mov_mem_sib_reg(
            r.state_ptr,
            r.scratch_a,
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base),
            rx::rax,
            true
        );

        e.add_reg_imm32(rx::rsp, 48);
        emit_dispatch_tail(e, vm);
    }

    // MOV reg, reg
    void MovCodec::encode(BytecodeBuilder& out, const IRInsn& i, const VMConfig& vm) const {
        out.u8(vm.opcode_for(family()));
        enc_slot(out, vm, get_op<VirReg>(i, 0));
        enc_slot(out, vm, get_op<VirReg>(i, 1));
    }

    void MovCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();

        // dst slot, dst width
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, r.scratch_b); // width with high-byte bit
        e.push_reg(r.scratch_a);
        e.push_reg(r.scratch_b);

        // src slot, src width
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, r.scratch_b);

        // load src full 64 into rax
        e.mov_reg_mem_sib(
            rx::rax,
            r.state_ptr,
            r.scratch_a,
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base),
            true
        );

        // pop dst width / slot
        e.pop_reg(r.scratch_b);
        e.pop_reg(r.scratch_a);

        // no width-mask: MOV writes raw, store helper zero-extends for w=4.
        emit_store_slot_value(
            e,
            vm,
            r.scratch_a,
            rx::rax,
            r.scratch_b
        );
        emit_dispatch_tail(e, vm);
    }

    // LOAD reg, [mem]
    void LoadCodec::encode(BytecodeBuilder& out, const IRInsn& i, const VMConfig& vm) const {
        out.u8(vm.opcode_for(family()));
        enc_slot(out, vm, get_op<VirReg>(i, 0));
        enc_mem (out, vm, get_op<Mem>(i, 1));
    }

    void LoadCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();

        // seed-permute the 6 role regs 
        std::array<std::uint8_t, 6> pool{rx::rax, rx::rcx, rx::rdx, rx::r8, rx::r9, rx::r10};
        SeedRng local_rng(vm.cipher_k1() ^ 0x10ADC0DEC0DEULL);
        shuffle_in_place(pool, local_rng);

        const std::uint8_t B = pool[0]; // base slot idx, base val, final loaded value
        const std::uint8_t I = pool[1]; // index slot idx, index val with scale shift
        const std::uint8_t S = pool[2]; // scale_log2, dead after scale dispatch
        const std::uint8_t G = pool[3]; // seg byte
        const std::uint8_t W = pool[4]; // mem_width, unused after fetch
        const std::uint8_t A = pool[5]; // address accumulator
        (void)W;

        // dst slot index + width
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        e.push_reg(r.scratch_a);
        e.push_reg(r.scratch_b);

        // base slot idx, index slot idx, scale_log2, seg, disp32, width
        emit_fetch_byte_dec(e, vm, B);          // base idx
        emit_fetch_byte_dec(e, vm, I);          // index idx
        emit_fetch_byte_dec(e, vm, S);          // scale
        emit_fetch_byte_dec(e, vm, G);          // seg
        emit_fetch_u32_dec(e, vm, r.scratch_a); // disp32. clobbers scratch_b
        emit_fetch_byte_dec(e, vm, W);          // mem width

        // ea = base + index<<scale + disp32, plus optional seg.
        auto lbl_no_base = e.new_label(), lbl_has_base = e.new_label();
        e.cmp_reg_imm32(B, 0xFF);
        e.jcc_label(cc::nz, lbl_has_base);
        e.xor_reg_reg(A, A);
        e.jmp_label(lbl_no_base);
        e.bind(lbl_has_base);
        e.mov_reg_mem_sib(
            A,
            r.state_ptr,
            B,
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base),
            true
        );
        e.bind(lbl_no_base);

        // index*scale:
        auto lbl_no_idx = e.new_label(), lbl_has_idx = e.new_label();
        e.cmp_reg_imm32(I, 0xFF);
        e.jcc_label(cc::nz, lbl_has_idx);
        e.xor_reg_reg(I, I);
        e.jmp_label(lbl_no_idx);
        e.bind(lbl_has_idx);
        e.mov_reg_mem_sib(
            I,
            r.state_ptr, 
            I, 
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base), 
            true
        );

        // permute the scale dispatch per seed: cascade order and body layout 
        {
            SeedRng prng(vm.cipher_k1() ^ 0x10ADC5CA1EULL);
            std::array<int, 4> sc{0, 1, 2, 3};   // scale_log2 values
            shuffle_in_place(sc, prng);
            std::array<int, 3> body_order{sc[0], sc[1], sc[2]};
            shuffle_in_place(body_order, prng);

            auto lbl_s0 = e.new_label(), lbl_s1 = e.new_label();
            auto lbl_s2 = e.new_label(), lbl_s3 = e.new_label();
            auto lbl_send = e.new_label();

            auto label_of = [&](int v) {
                switch (v) { 
                    case 0:  return lbl_s0; 
                    case 1:  return lbl_s1;        
                    case 2:  return lbl_s2;
                    default: return lbl_s3; 
                }
            };

            auto emit_body = [&](int v) {
                if (v != 0) e.shl_reg_imm8(I, static_cast<std::uint8_t>(v));
                // v==0: scale 1, no shift
            };

            // 3 cmp/jz tests, then inline default for sc[3].
            for (int v : {sc[0], sc[1], sc[2]}) {
                e.cmp_reg_imm32(S, v);
                e.jcc_label(cc::z, label_of(v));
            }

            emit_body(sc[3]);
            e.jmp_label(lbl_send);

            for (std::size_t i = 0; i < body_order.size(); ++i) {
                const int v = body_order[i];
                e.bind(label_of(v));
                emit_body(v);
                if (i + 1 != body_order.size()) e.jmp_label(lbl_send);
            }

            e.bind(lbl_send);
        }
        e.bind(lbl_no_idx);
        e.add_reg_reg(A, I);

        // sign-extend disp32 then add
        e.movsxd_r64_r32(B, r.scratch_a);
        e.add_reg_reg(A, B);

        // seg override. G has the seg byte: 0 default, 1 fs, 2 gs.
        auto lbl_seg_default = e.new_label(), lbl_seg_done = e.new_label();
        e.cmp_reg_imm32(G, 0);
        e.jcc_label(cc::z, lbl_seg_default);
        auto lbl_gs = e.new_label();
        e.cmp_reg_imm32(G, 2);
        e.jcc_label(cc::z, lbl_gs);
        e.u8(0x64); // fs prefix
        e.mov_reg_mem(
            B,
            A,
            0,
            true
        );
        e.jmp_label(lbl_seg_done);
        e.bind(lbl_gs);
        e.u8(0x65); // gs prefix
        e.mov_reg_mem(
            B,
            A,
            0,
            true
        );
        e.jmp_label(lbl_seg_done);
        e.bind(lbl_seg_default);
        e.mov_reg_mem(
            B,
            A,
            0,
            true
        );
        e.bind(lbl_seg_done);

        // restore dst width/slot, store loaded value
        e.pop_reg(r.scratch_b);
        e.pop_reg(r.scratch_a);
        emit_store_slot_value(
            e,
            vm,
            r.scratch_a,
            B,
            r.scratch_b
        );
        emit_dispatch_tail(e, vm);
    }

    // STORE [mem], reg
    void StoreCodec::encode(BytecodeBuilder& out, const IRInsn& i, const VMConfig& vm) const {
        out.u8(vm.opcode_for(family()));
        enc_mem(out, vm, get_op<Mem>(i, 0));
        if (std::holds_alternative<VirReg>(i.ops[1])) {
            out.u8(0); // tag: reg
            enc_slot(out, vm, get_op<VirReg>(i, 1));
        }
        else {
            out.u8(1); // tag: imm
            const auto& im = get_op<Imm>(i, 1);
            out.u8(static_cast<std::uint8_t>(width_bytes(im.width)));
            enc_imm_n(out, im.value, 8);
        }
    }

    void StoreCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();

        // seed-permute the 5 temporary roles 
        std::array<std::uint8_t, 6> pool{rx::rax, rx::rcx, rx::rdx, rx::r8, rx::r9, rx::r10};
        SeedRng local_rng(vm.cipher_k1() ^ 0x5707E5577ULL);
        shuffle_in_place(pool, local_rng);

        const std::uint8_t B = pool[0]; // base slot idx, base val, fetched value
        const std::uint8_t I = pool[1]; // index slot idx, index val with scale shift
        const std::uint8_t S = pool[2]; // scale_log2, dead after scale dispatch
        const std::uint8_t W = pool[3]; // mem_width
        const std::uint8_t A = pool[4]; // address accumulator

        // base, index, scale, seg, disp32, mem_width
        emit_fetch_byte_dec(e, vm, B);
        emit_fetch_byte_dec(e, vm, I);
        emit_fetch_byte_dec(e, vm, S);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        emit_fetch_u32_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, W);

        // Compute addr in A.
        auto lbl_nb = e.new_label(), lbl_hb = e.new_label();
        e.cmp_reg_imm32(B, 0xFF);
        e.jcc_label(cc::nz, lbl_hb);
        e.xor_reg_reg(A, A);
        e.jmp_label(lbl_nb);
        e.bind(lbl_hb);
        e.mov_reg_mem_sib(
            A, 
            r.state_ptr, 
            B, 
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base), 
            true
        );
        e.bind(lbl_nb);
        auto lbl_ni = e.new_label(), lbl_hi = e.new_label();
        e.cmp_reg_imm32(I, 0xFF);
        e.jcc_label(cc::nz, lbl_hi);
        e.xor_reg_reg(I, I);
        e.jmp_label(lbl_ni);
        e.bind(lbl_hi);
        e.mov_reg_mem_sib(
            I, 
            r.state_ptr, 
            I, 
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base), 
            true
        );

        // scale dispatch, was missing this impl like a fucking retard
        {
            SeedRng prng(vm.cipher_k1() ^ 0x570BE5CA1EULL);
            std::array<int, 4> sc{0, 1, 2, 3};
            shuffle_in_place(sc, prng);
            std::array<int, 3> body_order{sc[0], sc[1], sc[2]};
            shuffle_in_place(body_order, prng);

            auto lbl_s0 = e.new_label(), lbl_s1 = e.new_label();
            auto lbl_s2 = e.new_label(), lbl_s3 = e.new_label();
            auto lbl_send = e.new_label();

            auto label_of = [&](int v) {
                switch (v) {
                    case 0:  return lbl_s0;
                    case 1:  return lbl_s1;
                    case 2:  return lbl_s2;
                    default: return lbl_s3;
                }
            };

            auto emit_body = [&](int v) {
                if (v != 0) e.shl_reg_imm8(I, static_cast<std::uint8_t>(v));
            };

            for (int v : {sc[0], sc[1], sc[2]}) {
                e.cmp_reg_imm32(S, v);
                e.jcc_label(cc::z, label_of(v));
            }

            emit_body(sc[3]);
            e.jmp_label(lbl_send);

            for (std::size_t i = 0; i < body_order.size(); ++i) {
                const int v = body_order[i];
                e.bind(label_of(v));
                emit_body(v);
                if (i + 1 != body_order.size()) e.jmp_label(lbl_send);
            }

            e.bind(lbl_send);
        }

        e.bind(lbl_ni);
        e.add_reg_reg(A, I);
        e.movsxd_r64_r32(B, r.scratch_a);
        e.add_reg_reg(A, B);

        // stash addr and width on stack so value-fetch can't stomp them
        e.sub_reg_imm32(rx::rsp, 16);
        e.mov_mem_reg(
            rx::rsp,
            0,
            A,
            true
        );
        e.mov_mem_reg(
            rx::rsp,
            8,
            W,
            true
        );

        // tag byte
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        auto lbl_imm = e.new_label(), lbl_done = e.new_label();
        e.cmp_reg_imm32(r.scratch_a, 1);
        e.jcc_label(cc::z, lbl_imm);

        // reg form: slot idx + width
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        e.mov_reg_mem_sib(
            B, 
            r.state_ptr, 
            r.scratch_a, 
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base),
            true
        );
        e.jmp_label(lbl_done);
        e.bind(lbl_imm);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        emit_fetch_uN_dec(
            e,
            vm,
            B,
            8
        );
        e.bind(lbl_done);

        // recover addr A and width W.
        e.mov_reg_mem(
            A,
            rx::rsp,
            0,
            true
        );
        e.mov_reg_mem(
            W,
            rx::rsp,
            8,
            true
        );
        e.add_reg_imm32(rx::rsp, 16);

        // store B at [A], sized by W.
        auto lbl_w8 = e.new_label(),
             lbl_w4 = e.new_label(),
             lbl_w2 = e.new_label(), 
             lbl_end = e.new_label();

        e.cmp_reg_imm32(W, 8);
        e.jcc_label(cc::z, lbl_w8);
        e.cmp_reg_imm32(W, 4);
        e.jcc_label(cc::z, lbl_w4);
        e.cmp_reg_imm32(W, 2);
        e.jcc_label(cc::z, lbl_w2);
        e.mov_mem_reg_size(
            A,
            0,
            B,
            1
        );
        e.jmp_label(lbl_end);
        e.bind(lbl_w2);
        e.mov_mem_reg_size(
            A,
            0,
            B,
            2
        );
        e.jmp_label(lbl_end);
        e.bind(lbl_w4);
        e.mov_mem_reg_size(
            A,
            0,
            B,
            4
        );
        e.jmp_label(lbl_end);
        e.bind(lbl_w8);
        e.mov_mem_reg_size(
            A,
            0,
            B,
            8
        );
        e.bind(lbl_end);
        emit_dispatch_tail(e, vm);
    }

    // LEA reg, mem
    // tag=0: full mem operand base/idx/scale/seg/disp/width, addr calc
    // tag=1: data-island offset u32, runtime addr = data_island_base + off
    void LeaCodec::encode(BytecodeBuilder& out, const IRInsn& i, const VMConfig& vm) const {
        out.u8(vm.opcode_for(family()));
        enc_slot(out, vm, get_op<VirReg>(i, 0));
        const auto& marker = get_op<Imm>(i, 2);
        if (marker.value == 1) {
            // rip-relative: 2nd operand is an Imm with absolute VA.
            out.u8(1);
            const auto& va_op = get_op<Imm>(i, 1);
            out.emit_data_island_offset_for_va(static_cast<std::uint64_t>(va_op.value));
        }
        else {
            out.u8(0);
            enc_mem(out, vm, get_op<Mem>(i, 1));
        }
    }

    void LeaCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        emit_fetch_byte_dec(e, vm, r.scratch_a); // dst slot
        emit_fetch_byte_dec(e, vm, r.scratch_b); // dst width
        e.push_reg(r.scratch_a);
        e.push_reg(r.scratch_b);

        // tag byte
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        auto lbl_rip = e.new_label(), lbl_done = e.new_label();
        e.cmp_reg_imm32(r.scratch_a, 1);
        e.jcc_label(cc::z, lbl_rip);

        // normal mem
        emit_fetch_byte_dec(e, vm, rx::rax);     // base
        emit_fetch_byte_dec(e, vm, rx::rcx);     // idx
        emit_fetch_byte_dec(e, vm, rx::rdx);     // scale
        emit_fetch_byte_dec(e, vm, r.scratch_b); // seg ignored
        emit_fetch_u32_dec(e, vm, r.scratch_a);  // disp
        emit_fetch_byte_dec(e, vm, rx::r10);     // mem width ignored for LEA

        // base value
        auto lbl_nb = e.new_label(), lbl_hb = e.new_label();
        e.cmp_reg_imm32(rx::rax, 0xFF);
        e.jcc_label(cc::nz, lbl_hb);
        e.xor_reg_reg(rx::r11, rx::r11);
        e.jmp_label(lbl_nb);
        e.bind(lbl_hb);
        e.mov_reg_mem_sib(
            rx::r11,
            r.state_ptr, 
            rx::rax, 
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base), 
            true
        );
        e.bind(lbl_nb);
        auto lbl_ni = e.new_label(), lbl_hi = e.new_label();
        e.cmp_reg_imm32(rx::rcx, 0xFF);
        e.jcc_label(cc::nz, lbl_hi);
        e.xor_reg_reg(rx::rcx, rx::rcx);
        e.jmp_label(lbl_ni);
        e.bind(lbl_hi);
        e.mov_reg_mem_sib(
            rx::rcx, 
            r.state_ptr, 
            rx::rcx, 
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base), 
            true
        );
        e.bind(lbl_ni);

        // permute the scale cascade per seed
        {
            SeedRng prng(vm.cipher_k1() ^ 0x1EA5CA1EFFULL);
            std::array<int, 4> sc{0, 1, 2, 3};
            shuffle_in_place(sc, prng);
            std::array<int, 3> body_order{sc[0], sc[1], sc[2]};
            shuffle_in_place(body_order, prng);

            auto lbl_s0 = e.new_label(), lbl_s1 = e.new_label();
            auto lbl_s2 = e.new_label(), lbl_s3 = e.new_label();
            auto lbl_send = e.new_label();
            auto label_of = [&](int v) {
                switch (v) {
                    case 0: return lbl_s0;
                    case 1: return lbl_s1;
                    case 2: return lbl_s2;
                    default: return lbl_s3;
                }
            };

            auto emit_body = [&](int v) {
                if (v != 0) e.shl_reg_imm8(rx::rcx, static_cast<std::uint8_t>(v));
            };

            for (int v : {sc[0], sc[1], sc[2]}) {
                e.cmp_reg_imm32(rx::rdx, v);
                e.jcc_label(cc::z, label_of(v));
            }

            emit_body(sc[3]);
            e.jmp_label(lbl_send);

            for (std::size_t i = 0; i < body_order.size(); ++i) {
                const int v = body_order[i];
                e.bind(label_of(v));
                emit_body(v);
                if (i + 1 != body_order.size()) e.jmp_label(lbl_send);
            }

            e.bind(lbl_send);
        }
        e.add_reg_reg(rx::r11, rx::rcx);
        e.movsxd_r64_r32(rx::rax, r.scratch_a);
        e.add_reg_reg(rx::r11, rx::rax);
        e.jmp_label(lbl_done);
        e.bind(lbl_rip);
        emit_fetch_u32_dec(e, vm, r.scratch_a); // data island offset
        e.mov_reg_mem(
            rx::r11, 
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().data_island_base),
            true
        );
        e.add_reg_reg(rx::r11, r.scratch_a);
        e.bind(lbl_done);

        // store r11 into dst slot. LEA is always pointer width here.
        e.pop_reg(r.scratch_b);
        e.pop_reg(r.scratch_a);
        emit_store_slot_value(
            e,
            vm,
            r.scratch_a,
            rx::r11,
            r.scratch_b
        );
        emit_dispatch_tail(e, vm);
    }

    // READ_SEG fs:[disp] / gs:[disp]
    // not actually produced by the lifter 
    void ReadSegCodec::encode(BytecodeBuilder& out, const IRInsn& i, const VMConfig& vm) const {
        (void)i;
        out.u8(vm.opcode_for(family()));
    }

    void ReadSegCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        // unused: fall through.
        emit_dispatch_tail(e, vm);
    }

    // ALU bin helper: ADD/SUB/AND/OR/XOR
    // shared encoding: opcode | dst slot | width | tag | slot or imm data
    enum class BinOp { ADD, SUB, ANDV, ORV, XORV };

    static void enc_bin(BytecodeBuilder& out, const IRInsn& i, const VMConfig& vm, const Codec* self) {
        out.u8(vm.opcode_for(self->family()));
        const auto& dst = get_op<VirReg>(i, 0);
        enc_slot(out, vm, dst);
        if (std::holds_alternative<VirReg>(i.ops[1])) {
            out.u8(0);
            enc_slot(out, vm, get_op<VirReg>(i, 1));
        }
        else if (std::holds_alternative<Imm>(i.ops[1])) {
            out.u8(1);
            const auto& im = get_op<Imm>(i, 1);
            enc_imm_n(out, im.value, 8);
        }
        else {
            // mem on RHS: load+op pattern.
            out.u8(2);
            enc_mem(out, vm, get_op<Mem>(i, 1));
        }
    }

    static void emit_bin_handler(X64Emitter& e, const VMConfig& vm, BinOp op, FlagsOp fkind) {
        const auto& r = vm.dispatcher_regs();
        emit_fetch_byte_dec(e, vm, r.scratch_a); // dst slot
        emit_fetch_byte_dec(e, vm, r.scratch_b); // dst width
        e.push_reg(r.scratch_a);
        e.push_reg(r.scratch_b);

        // load full dst slot, then extract the subregister value, handling
        // ah/ch/dh/bh and the B/W/D/Q widths. result in rax low.
        e.mov_reg_mem_sib(
            rx::rax,
            r.state_ptr,
            r.scratch_a,
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base),
            true
        );
        emit_extract_operand(
            e,
            vm,
            rx::rax,
            r.scratch_b
        );

        // tag
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        auto lbl_imm = e.new_label(), lbl_mem = e.new_label(), lbl_done = e.new_label();
        e.cmp_reg_imm32(r.scratch_a, 1);
        e.jcc_label(cc::z, lbl_imm);
        e.cmp_reg_imm32(r.scratch_a, 2);
        e.jcc_label(cc::z, lbl_mem);

        // reg: fetch slot+width, load, extract
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        e.mov_reg_mem_sib(
            rx::rcx,
            r.state_ptr,
            r.scratch_a,
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base),
            true
        );
        emit_extract_operand(
            e,
            vm,
            rx::rcx,
            r.scratch_b
        );
        e.jmp_label(lbl_done);
        e.bind(lbl_imm);
        e.sub_reg_imm32(rx::rsp, 16);
        emit_fetch_uN_dec(
            e,
            vm,
            rx::rcx,
            8
        );
        e.add_reg_imm32(rx::rsp, 16);

        // mask imm to dst width 
        e.mov_reg_mem(
            r.scratch_b,
            rx::rsp,
            0,
            true
        );
        emit_mask_to_width(
            e,
            vm,
            rx::rcx,
            r.scratch_b,
            0x11
        );
        e.jmp_label(lbl_done);
        e.bind(lbl_mem);

        // mem: fetch base/idx/scale/seg/disp/width, compute addr, load 8 bytes
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, rx::rdx);
        emit_fetch_byte_dec(e, vm, rx::r10);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        emit_fetch_u32_dec(e, vm, rx::rcx);
        emit_fetch_byte_dec(e, vm, rx::r11);

        // addr = base + idx<<scale + disp ; load
        e.mov_reg_mem_sib(
            r.scratch_b,
            r.state_ptr,
            r.scratch_a,
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base),
            true
        );
        e.movsxd_r64_r32(rx::rcx, rx::rcx);
        e.add_reg_reg(r.scratch_b, rx::rcx);
        e.mov_reg_mem(
            rx::rcx,
            r.scratch_b,
            0,
            true
        );
        e.bind(lbl_done);

        // save flag context: A = rax extracted dst, B = rcx extracted operand
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_a),
            rx::rax,
            true
        );
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_b),
            rx::rcx,
            true
        );

        switch (op) {
            case BinOp::ADD:  e.add_reg_reg(rx::rax, rx::rcx); break;
            case BinOp::SUB:  e.sub_reg_reg(rx::rax, rx::rcx); break;
            case BinOp::ANDV: e.and_reg_reg(rx::rax, rx::rcx); break;
            case BinOp::ORV:  e.or_reg_reg (rx::rax, rx::rcx); break;
            case BinOp::XORV: e.xor_reg_reg(rx::rax, rx::rcx); break;
        }

        // pop width, slot
        e.pop_reg(r.scratch_b);
        e.pop_reg(r.scratch_a);

        // mask result to dst width so flag_result reflects the right view. 
        emit_mask_to_width(
            e,
            vm,
            rx::rax,
            r.scratch_b,
            0x22
        );

        // record result, flag kind, width
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_result),
            rx::rax,
            true
        );
        e.push_reg(r.scratch_a);
        e.push_reg(r.scratch_b);
        e.mov_reg_imm32(rx::rdx, static_cast<std::int32_t>(fkind));
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_op),
            rx::rdx,
            true
        );
        e.pop_reg(r.scratch_b);
        e.pop_reg(r.scratch_a);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_width),
            r.scratch_b,
            true
        );
        emit_store_slot_value(
            e,
            vm,
            r.scratch_a,
            rx::rax,
            r.scratch_b
        );
        emit_dispatch_tail(e, vm);
    }

    void AddCodec::encode(BytecodeBuilder& o, const IRInsn& i, const VMConfig& v) const { 
        enc_bin(
            o,
            i,
            v,
            this
        );
    }

    void AddCodec::emit_handler(X64Emitter& e, const VMConfig& v) const {
        emit_bin_handler(
            e,
            v,
            BinOp::ADD,
            FlagsOp::ADD
        );
    }

    void SubCodec::encode(BytecodeBuilder& o, const IRInsn& i, const VMConfig& v) const { 
        enc_bin(
            o,
            i,
            v,
            this
        ); 
    }

    void SubCodec::emit_handler(X64Emitter& e, const VMConfig& v) const { 
        emit_bin_handler(
            e,
            v,
            BinOp::SUB,
            FlagsOp::SUB
        ); 
    }

    void AndCodec::encode(BytecodeBuilder& o, const IRInsn& i, const VMConfig& v) const {
        enc_bin(
            o,
            i,
            v,
            this
        ); 
    }

    void AndCodec::emit_handler(X64Emitter& e, const VMConfig& v) const { 
        emit_bin_handler(
            e,
            v,
            BinOp::ANDV,
            FlagsOp::LOGIC
        ); 
    }

    void OrCodec::encode (BytecodeBuilder& o, const IRInsn& i, const VMConfig& v) const { 
        enc_bin(
            o,
            i,
            v,
            this
        ); 
    }

    void OrCodec::emit_handler(X64Emitter& e, const VMConfig& v) const { 
        emit_bin_handler(
            e,
            v,
            BinOp::ORV,
            FlagsOp::LOGIC
        ); 
    }

    void XorCodec::encode(BytecodeBuilder& o, const IRInsn& i, const VMConfig& v) const { 
        enc_bin(
            o,
            i,
            v,
            this
        ); 
    }

    void XorCodec::emit_handler(X64Emitter& e, const VMConfig& v) const { 
        emit_bin_handler(
            e,
            v,
            BinOp::XORV,
            FlagsOp::LOGIC
        ); 
    }

    // INC / DEC
    void IncCodec::encode(BytecodeBuilder& out, const IRInsn& i, const VMConfig& vm) const {
        out.u8(vm.opcode_for(family()));
        enc_slot(out, vm, get_op<VirReg>(i, 0));
    }

    void DecCodec::encode(BytecodeBuilder& out, const IRInsn& i, const VMConfig& vm) const {
        out.u8(vm.opcode_for(family()));
        enc_slot(out, vm, get_op<VirReg>(i, 0));
    }

    static void emit_unary_arith(X64Emitter& e, const VMConfig& vm, FlagsOp fk,
                                 void (X64Emitter::*op_reg)(std::uint8_t, bool)) {
        const auto& r = vm.dispatcher_regs();
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        e.push_reg(r.scratch_a);
        e.push_reg(r.scratch_b);
        e.mov_reg_mem_sib(
            rx::rax, 
            r.state_ptr, 
            r.scratch_a, 
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base), 
            true
        );
        emit_extract_operand(
            e,
            vm,
            rx::rax,
            r.scratch_b
        );
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_a),
            rx::rax,
            true
        );
        (e.*op_reg)(rx::rax, true);
        e.pop_reg(r.scratch_b);
        e.pop_reg(r.scratch_a);
        emit_mask_to_width(
            e,
            vm,
            rx::rax,
            r.scratch_b,
            0x33
        );
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_result),
            rx::rax,
            true
        );
        e.push_reg(r.scratch_a);
        e.push_reg(r.scratch_b);
        e.mov_reg_imm32(rx::rdx, static_cast<std::int32_t>(fk));
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_op),
            rx::rdx,
            true
        );
        e.pop_reg(r.scratch_b);
        e.pop_reg(r.scratch_a);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_width),
            r.scratch_b,
            true
        );
        emit_store_slot_value(
            e,
            vm,
            r.scratch_a,
            rx::rax,
            r.scratch_b
        );
        emit_dispatch_tail(e, vm);
    }

    void IncCodec::emit_handler(X64Emitter& e, const VMConfig& v) const { 
        emit_unary_arith(
            e,
            v,
            FlagsOp::INC,
            &X64Emitter::inc_reg
        ); 
    }

    void DecCodec::emit_handler(X64Emitter& e, const VMConfig& v) const { 
        emit_unary_arith(
            e,
            v,
            FlagsOp::DEC,
            &X64Emitter::dec_reg
        ); 
    }

    void NegCodec::encode(BytecodeBuilder& out, const IRInsn& i, const VMConfig& vm) const {
        out.u8(vm.opcode_for(family())); enc_slot(out, vm, get_op<VirReg>(i, 0));
    }

    void NegCodec::emit_handler(X64Emitter& e, const VMConfig& v) const { 
        emit_unary_arith(
            e,
            v,
            FlagsOp::NEG,
            &X64Emitter::neg_reg
        ); 
    }

    void NotCodec::encode(BytecodeBuilder& out, const IRInsn& i, const VMConfig& vm) const {
        out.u8(vm.opcode_for(family())); enc_slot(out, vm, get_op<VirReg>(i, 0));
    }

    void NotCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        e.mov_reg_mem_sib(
            rx::rax,
            r.state_ptr,
            r.scratch_a,
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base), 
            true
        );
        e.not_reg(rx::rax, true);
        emit_store_slot_value(
            e,
            vm,
            r.scratch_a,
            rx::rax,
            r.scratch_b
        );
        emit_dispatch_tail(e, vm);
    }

    // shifts
    static void enc_shift(BytecodeBuilder& out, const IRInsn& i, const VMConfig& vm, const Codec* self) {
        out.u8(vm.opcode_for(self->family()));
        enc_slot(out, vm, get_op<VirReg>(i, 0));
        if (std::holds_alternative<Imm>(i.ops[1])) {
            out.u8(1);
            const auto& im = get_op<Imm>(i, 1);
            out.u8(static_cast<std::uint8_t>(im.value & 0xFF));
        }
        else {
            out.u8(0);
            enc_slot(out, vm, get_op<VirReg>(i, 1));
        }
    }

    static void emit_shift_handler(X64Emitter& e, const VMConfig& vm, void (X64Emitter::*op_cl)(std::uint8_t, bool)) {
        const auto& r = vm.dispatcher_regs();
        emit_fetch_byte_dec(e, vm, r.scratch_a); // dst slot
        emit_fetch_byte_dec(e, vm, r.scratch_b); // dst width
        e.push_reg(r.scratch_a); e.push_reg(r.scratch_b);
        e.mov_reg_mem_sib(
            rx::rax,
            r.state_ptr,
            r.scratch_a,
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base), 
            true
        );
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        auto lbl_reg = e.new_label(), lbl_done = e.new_label();
        e.cmp_reg_imm32(r.scratch_a, 0);
        e.jcc_label(cc::z, lbl_reg);
        emit_fetch_byte_dec(e, vm, rx::rcx);
        e.jmp_label(lbl_done);
        e.bind(lbl_reg);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        e.mov_reg_mem_sib(
            rx::rcx, 
            r.state_ptr, 
            r.scratch_b, 
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base), 
            true
        );
        e.bind(lbl_done);
        e.and_reg_imm32(rx::rcx, 0x3F);

        // width-aware shift
        auto lbl_w8_shift = e.new_label(), lbl_shift_done = e.new_label();
        e.mov_reg_mem(
            rx::rdx,
            rx::rsp,
            0,
            true
        ); // rdx = saved width byte

        e.and_reg_imm32(rx::rdx, 0x7F);
        e.cmp_reg_imm32(rx::rdx, 8);
        e.jcc_label(cc::z, lbl_w8_shift);
        (e.*op_cl)(rx::rax, false); // 32-bit shift zero-extends
        e.jmp_label(lbl_shift_done);
        e.bind(lbl_w8_shift);
        (e.*op_cl)(rx::rax, true); // 64-bit shift
        e.bind(lbl_shift_done);
        e.pop_reg(r.scratch_b);
        e.pop_reg(r.scratch_a);
        emit_store_slot_value(
            e,
            vm,
            r.scratch_a,
            rx::rax,
            r.scratch_b
        );
        emit_dispatch_tail(e, vm);
    }

    void ShlCodec::encode(BytecodeBuilder& o, const IRInsn& i, const VMConfig& v) const { 
            enc_shift(
            o,
            i,
            v,
            this
        ); 
    }

    void ShlCodec::emit_handler(X64Emitter& e, const VMConfig& v) const { emit_shift_handler(e, v, &X64Emitter::shl_reg_cl); }

    void ShrCodec::encode(BytecodeBuilder& o, const IRInsn& i, const VMConfig& v) const { 
        enc_shift(
            o,
            i,
            v,
            this
        ); 
    }

    void ShrCodec::emit_handler(X64Emitter& e, const VMConfig& v) const { emit_shift_handler(e, v, &X64Emitter::shr_reg_cl); }

    void SarCodec::encode(BytecodeBuilder& o, const IRInsn& i, const VMConfig& v) const { 
        enc_shift(
            o,
            i,
            v,
            this
        ); 
    }

    void SarCodec::emit_handler(X64Emitter& e, const VMConfig& v) const { emit_shift_handler(e, v, &X64Emitter::sar_reg_cl); }

    void RolCodec::encode(BytecodeBuilder& o, const IRInsn& i, const VMConfig& v) const { 
        enc_shift(
            o,
            i,
            v,
            this
        ); 
    }

    void RolCodec::emit_handler(X64Emitter& e, const VMConfig& v) const { emit_shift_handler(e, v, &X64Emitter::rol_reg_cl); }

    void RorCodec::encode(BytecodeBuilder& o, const IRInsn& i, const VMConfig& v) const { 
        enc_shift(
            o,
            i,
            v,
            this
        ); 
    }

    void RorCodec::emit_handler(X64Emitter& e, const VMConfig& v) const { emit_shift_handler(e, v, &X64Emitter::ror_reg_cl); }

    // CMP / TEST: share the bin-op encoding but only write flag context.
    static void enc_cmp_test(BytecodeBuilder& o, const IRInsn& i, const VMConfig& v, const Codec* self) {
        o.u8(v.opcode_for(self->family()));
        if (std::holds_alternative<VirReg>(i.ops[0])) {
            o.u8(0);
            enc_slot(o, v, get_op<VirReg>(i, 0));
        }
        else {
            o.u8(1);
            const auto& im = get_op<Imm>(i, 0);
            enc_imm_n(o, im.value, 8);
        }

        if (std::holds_alternative<VirReg>(i.ops[1])) {
            o.u8(0);
            enc_slot(o, v, get_op<VirReg>(i, 1));
        }
        else if (std::holds_alternative<Imm>(i.ops[1])) {
            o.u8(1);
            const auto& im = get_op<Imm>(i, 1);
            enc_imm_n(o, im.value, 8);
        }
        else {
            o.u8(2);
            enc_mem(o, v, get_op<Mem>(i, 1));
        }

        o.u8(static_cast<std::uint8_t>(width_bytes(i.width)));
    }

    static void emit_cmp_test_handler(X64Emitter& e, const VMConfig& vm, bool is_test) {
        const auto& r = vm.dispatcher_regs();

        // op0: tag + payload
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        auto lbl_op0_imm = e.new_label(), lbl_op0_done = e.new_label();
        e.cmp_reg_imm32(r.scratch_a, 0);
        e.jcc_label(cc::nz, lbl_op0_imm);
        emit_fetch_byte_dec(e, vm, r.scratch_a); // slot
        emit_fetch_byte_dec(e, vm, r.scratch_b); // op0 width
        e.mov_reg_mem_sib(
            rx::rax,
            r.state_ptr,
            r.scratch_a,
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base),
            true
        );
        emit_extract_operand(
            e,
            vm,
            rx::rax,
            r.scratch_b
        );
        e.jmp_label(lbl_op0_done);
        e.bind(lbl_op0_imm);
        e.sub_reg_imm32(rx::rsp, 16);
        emit_fetch_uN_dec(
            e,
            vm,
            rx::rax,
            8
        );
        e.add_reg_imm32(rx::rsp, 16);

        // imm carries no per-operand width, gets masked by global width below.
        e.bind(lbl_op0_done);

        // op1
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        auto lbl_imm = e.new_label(), lbl_mem = e.new_label(), lbl_done = e.new_label();
        e.cmp_reg_imm32(r.scratch_a, 1);
        e.jcc_label(cc::z, lbl_imm);
        e.cmp_reg_imm32(r.scratch_a, 2);
        e.jcc_label(cc::z, lbl_mem);
        emit_fetch_byte_dec(e, vm, r.scratch_a); // slot
        emit_fetch_byte_dec(e, vm, r.scratch_b); // op1 width
        e.mov_reg_mem_sib(
            rx::rcx,
            r.state_ptr,
            r.scratch_a,
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base),
            true
        );
        emit_extract_operand(
            e,
            vm,
            rx::rcx,
            r.scratch_b
        );
        e.jmp_label(lbl_done);
        e.bind(lbl_imm);
        e.sub_reg_imm32(rx::rsp, 16);
        emit_fetch_uN_dec(
            e,
            vm,
            rx::rcx,
            8
        );
        e.add_reg_imm32(rx::rsp, 16);
        e.jmp_label(lbl_done);
        e.bind(lbl_mem);
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, rx::rdx);
        emit_fetch_byte_dec(e, vm, rx::r10);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        emit_fetch_u32_dec(e, vm, rx::rcx);
        emit_fetch_byte_dec(e, vm, rx::r11);
        e.mov_reg_mem_sib(
            r.scratch_b,
            r.state_ptr,
            r.scratch_a,
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base),
            true
        );
        e.movsxd_r64_r32(rx::rcx, rx::rcx);
        e.add_reg_reg(r.scratch_b, rx::rcx);
        e.mov_reg_mem(
            rx::rcx,
            r.scratch_b,
            0,
            true
        );
        e.bind(lbl_done);
        emit_fetch_byte_dec(e, vm, r.scratch_b); // global cmp width

        // final mask on both operands. idempotent on already-extracted regs.
        e.push_reg(rx::rax);
        e.push_reg(rx::rcx);

        // no high-byte shift on the final mask
        emit_mask_to_width(
            e,
            vm,
            rx::rax,
            r.scratch_b,
            0x44
        );
        emit_mask_to_width(
            e,
            vm,
            rx::rcx,
            r.scratch_b,
            0x55
        );
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_a),
            rx::rax,
            true
        );
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_b),
            rx::rcx,
            true
        );
        if (is_test) {
            e.and_reg_reg(rx::rax, rx::rcx);
        }
        else {
            e.sub_reg_reg(rx::rax, rx::rcx);
        }

        // mask result by width so ZF/SF reflect the byte/word view.
        emit_mask_to_width(
            e,
            vm,
            rx::rax,
            r.scratch_b,
            0x66
        );
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_result),
            rx::rax,
            true
        );
        e.pop_reg(rx::rcx);
        e.pop_reg(rx::rax);
        e.mov_reg_imm32(
            rx::rdx,
            static_cast<std::int32_t>(is_test ? FlagsOp::LOGIC : FlagsOp::SUB)
        );
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_op),
            rx::rdx,
            true
        );
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_width),
            r.scratch_b,
            true
        );
        emit_dispatch_tail(e, vm);
    }

    void CmpCodec::encode(BytecodeBuilder& o, const IRInsn& i, const VMConfig& v) const { 
        enc_cmp_test(
            o,
            i,
            v,
            this
        ); 
    }

    void CmpCodec::emit_handler(X64Emitter& e, const VMConfig& v) const { emit_cmp_test_handler(e, v, false); }

    void TestCodec::encode(BytecodeBuilder& o, const IRInsn& i, const VMConfig& v) const { 
        enc_cmp_test(
            o,
            i,
            v,
            this
        ); 
    }

    void TestCodec::emit_handler(X64Emitter& e, const VMConfig& v) const { emit_cmp_test_handler(e, v, true); }

    // BR: unconditional bytecode-relative branch
    void BrCodec::encode(BytecodeBuilder& out, const IRInsn& i, const VMConfig& vm) const {
        out.u8(vm.opcode_for(family()));
        out.emit_branch_rel32(i.target_block_id);
    }

    void BrCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();

        // fetch 4 decrypted bytes, sign-extend, add to ip.
        emit_fetch_u32_dec(e, vm, r.scratch_a);
        e.movsxd_r64_r32(r.scratch_a, r.scratch_a);
        e.add_reg_reg(r.ip, r.scratch_a);
        emit_cipher_reset(e, vm);
        emit_dispatch_tail(e, vm);
    }

    // BR_CC: opcode | cond_byte | rel32
    void BrCcCodec::encode(BytecodeBuilder& out, const IRInsn& i, const VMConfig& vm) const {
        out.u8(vm.opcode_for(family()));
        out.u8(static_cast<std::uint8_t>(i.cond));
        out.emit_branch_rel32(i.target_block_id);
    }

    void BrCcCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();

        // seed-permute the 6 temp-register roles across the Win64 volatile pool
        // rax/rcx/rdx/r8/r9/r10/r11
        std::array<std::uint8_t, 6> pool{rx::rax, rx::rcx, rx::rdx, rx::r8, rx::r9, rx::r10};

        SeedRng local_rng(vm.cipher_k1());
        shuffle_in_place(pool, local_rng);

        const std::uint8_t R_RESULT = pool[0];  // flags_result, later cf_byte
        const std::uint8_t R_A      = pool[1];  // flags_a, later zf_byte
        const std::uint8_t R_B      = pool[2];  // flags_b, later lt_byte
        const std::uint8_t R_W      = pool[3];  // width, dies after Phase A
        const std::uint8_t R_SF     = pool[4];  // sf_byte
        const std::uint8_t R_PRED   = pool[5];  // predicate accumulator

        emit_fetch_byte_dec(e, vm, r.scratch_a); // cond
        emit_fetch_u32_dec(e, vm, r.scratch_b);  // rel32
        e.movsxd_r64_r32(r.scratch_b, r.scratch_b);
        e.mov_reg_mem(
            R_RESULT,
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_result),
            true
        );
        e.mov_reg_mem(
            R_A,
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_a),
            true
        );
        e.mov_reg_mem(
            R_B,
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_b),
            true
        );

        // sign-extend the three flag operands by flag_width so 64-bit SF/CF/
        // signed-cmp insns reflect sub-width semantics 
        {
            e.mov_reg_mem(
                R_W,
                r.state_ptr,
                static_cast<std::int32_t>(vm.state_layout().flags_width),
                true
            );
            e.and_reg_imm32(R_W, 0x7F);

            auto lbl_done = e.new_label(),
                 lbl_w8 = e.new_label(),
                 lbl_w4 = e.new_label(), 
                 lbl_w2 = e.new_label();

            e.cmp_reg_imm32(R_W, 8);
            e.jcc_label(cc::z, lbl_w8);
            e.cmp_reg_imm32(R_W, 4);
            e.jcc_label(cc::z, lbl_w4);
            e.cmp_reg_imm32(R_W, 2);
            e.jcc_label(cc::z, lbl_w2);

            // w1
            e.movsx_r64_r8(R_RESULT, R_RESULT);
            e.movsx_r64_r8(R_A,      R_A);
            e.movsx_r64_r8(R_B,      R_B);
            e.jmp_label(lbl_done);
            e.bind(lbl_w2);
            e.movsx_r64_r16(R_RESULT, R_RESULT);
            e.movsx_r64_r16(R_A,      R_A);
            e.movsx_r64_r16(R_B,      R_B);
            e.jmp_label(lbl_done);
            e.bind(lbl_w4);
            e.movsxd_r64_r32(R_RESULT, R_RESULT);
            e.movsxd_r64_r32(R_A,      R_A);
            e.movsxd_r64_r32(R_B,      R_B);
            e.jmp_label(lbl_done);
            e.bind(lbl_w8);
            e.bind(lbl_done);
        }
        e.test_reg_reg(R_RESULT, R_RESULT); // ZF, SF from result

        // setcc emitter that handles REX.B for r8b..r15b.
        auto setcc = [&](std::uint8_t cc_code, std::uint8_t dst_reg){
            e.emit_rex(
                false,
                false,
                false,
                dst_reg >= 8
            );
            e.u8(0x0F); e.u8(static_cast<std::uint8_t>(0x90 + cc_code));
            e.emit_modrm(3, 0, dst_reg & 7);
        };

        setcc(cc::z, R_W);  // R_W gets ZF, dead. recomputed in R_A below.
        setcc(cc::s, R_SF); // R_SF = sf_byte

        // CF = a < b unsigned, SUB semantic, via setb after cmp.
        e.cmp_reg_reg(R_A, R_B);
        setcc(cc::b, R_RESULT); // R_RESULT = cf_byte

        e.movzx_r64_r8(R_RESULT, R_RESULT);
        const std::uint8_t cf_byte = R_RESULT;

        // signed less-than via setl after the same cmp.
        e.cmp_reg_reg(R_A, R_B);
        setcc(cc::l, R_B); // R_B = lt_byte

        e.movzx_r64_r8(R_B, R_B);
        const std::uint8_t lt_byte = R_B;

        // ZF: re-read flags_result, test, setz.
        e.mov_reg_mem(
            R_A,
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_result),
            true
        );
        e.test_reg_reg(R_A, R_A);
        setcc(cc::z, R_A); // R_A = zf_byte
        e.movzx_r64_r8(R_A, R_A);
        const std::uint8_t zf_byte = R_A;

        auto lbl_take      = e.new_label();
        auto lbl_skip      = e.new_label();
        auto lbl_eval_pred = e.new_label();

        // R_PRED starts at zero 
        e.xor_reg_reg(R_PRED, R_PRED);

        auto handle = [&](std::uint8_t cond_val, auto&& fn) {
            auto lbl_n = e.new_label();
            e.cmp_reg_imm32(r.scratch_a, static_cast<std::int32_t>(cond_val));
            e.jcc_label(cc::nz, lbl_n);
            fn();
            e.jmp_label(lbl_eval_pred);
            e.bind(lbl_n);
        };

        handle(static_cast<std::uint8_t>(Cond::Z),   [&](){ e.mov_reg_reg(R_PRED, zf_byte); });
        handle(static_cast<std::uint8_t>(Cond::NZ),  [&](){ e.mov_reg_reg(R_PRED, zf_byte); e.xor_reg_imm32(R_PRED, 1); });
        handle(static_cast<std::uint8_t>(Cond::B),   [&](){ e.mov_reg_reg(R_PRED, cf_byte); });
        handle(static_cast<std::uint8_t>(Cond::NB),  [&](){ e.mov_reg_reg(R_PRED, cf_byte); e.xor_reg_imm32(R_PRED, 1); });
        handle(static_cast<std::uint8_t>(Cond::BE),  [&](){ e.mov_reg_reg(R_PRED, cf_byte); e.or_reg_reg(R_PRED, zf_byte); });
        handle(static_cast<std::uint8_t>(Cond::NBE), [&](){ e.mov_reg_reg(R_PRED, cf_byte); e.or_reg_reg(R_PRED, zf_byte); e.xor_reg_imm32(R_PRED, 1); });
        handle(static_cast<std::uint8_t>(Cond::S),   [&](){ e.mov_reg_reg(R_PRED, R_SF); });
        handle(static_cast<std::uint8_t>(Cond::NS),  [&](){ e.mov_reg_reg(R_PRED, R_SF); e.xor_reg_imm32(R_PRED, 1); });
        handle(static_cast<std::uint8_t>(Cond::L),   [&](){ e.mov_reg_reg(R_PRED, lt_byte); });
        handle(static_cast<std::uint8_t>(Cond::NL),  [&](){ e.mov_reg_reg(R_PRED, lt_byte); e.xor_reg_imm32(R_PRED, 1); });
        handle(static_cast<std::uint8_t>(Cond::LE),  [&](){ e.mov_reg_reg(R_PRED, lt_byte); e.or_reg_reg(R_PRED, zf_byte); });
        handle(static_cast<std::uint8_t>(Cond::NLE), [&](){ e.mov_reg_reg(R_PRED, lt_byte); e.or_reg_reg(R_PRED, zf_byte); e.xor_reg_imm32(R_PRED, 1); });

        e.bind(lbl_eval_pred);
        e.and_reg_imm32(R_PRED, 1);
        e.test_reg_reg(R_PRED, R_PRED);
        e.jcc_label(cc::nz, lbl_take);
        e.jmp_label(lbl_skip);
        e.bind(lbl_take);
        e.add_reg_reg(r.ip, r.scratch_b);
        e.bind(lbl_skip);

        // both paths land at a fresh block boundary, so resync cipher state
        // regardless of taken/not-taken
        emit_cipher_reset(e, vm);
        emit_dispatch_tail(e, vm);
    }

    // BR_IND
    void BrIndCodec::encode(BytecodeBuilder& out, const IRInsn& i, const VMConfig& vm) const {
        out.u8(vm.opcode_for(family()));
        (void)i;
    }

    void BrIndCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        emit_dispatch_tail(e, vm); // unused
    }

    // CALL_VM: push return offset
    void CallVmCodec::encode(BytecodeBuilder& out, const IRInsn& i, const VMConfig& vm) const {
        out.u8(vm.opcode_for(family()));

        // operand layout: [trampoline_offset u32][rel32 i32]
        out.emit_trampoline_offset_for_return_va(i.return_va);
        out.emit_branch_rel32(i.target_block_id);
        (void)vm;
    }

    void CallVmCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        const auto& st = vm.state_layout();

        // operand layout: [trampoline_offset u32][rel32 i32]

        // fetch trampoline_offset into scratch_b, compute trampoline
        // addr = trampoline_base + offset in rax
        emit_fetch_u32_dec(e, vm, r.scratch_b);
        e.mov_reg_mem(
            rx::rax,
            r.state_ptr,
            static_cast<std::int32_t>(st.trampoline_base), 
            true
        );
        e.add_reg_reg(rx::rax, r.scratch_b); // rax = trampoline addr

        // fetch rel32 into scratch_a, sign-extended. ip is now past
        // the operand block
        emit_fetch_u32_dec(e, vm, r.scratch_a);
        e.movsxd_r64_r32(r.scratch_a, r.scratch_a);

        // push trampoline addr onto SHADOW stack. VM_RSP -= 8,
        // *VM_RSP = rax
        const std::uint8_t rsp_slot = vm.slot_of_xreg(XReg::SP);
        const std::int32_t rsp_off  = static_cast<std::int32_t>(st.regs_base + rsp_slot * 8);
        e.mov_reg_mem(
            rx::rcx,
            r.state_ptr,
            rsp_off,
            true
        );
        e.sub_reg_imm32(rx::rcx, 8);
        e.mov_mem_reg(
            r.state_ptr,
            rsp_off,
            rx::rcx,
            true
        );
        e.mov_mem_reg(
            rx::rcx,
            0,
            rx::rax,
            true
        );

        // push bytecode return-offset, ip - bytecode_base, onto the
        // VM call stack so a matching RET_VM resumes at the call site
        e.mov_reg_mem(
            rx::rax,
            r.state_ptr,
            static_cast<std::int32_t>(st.bytecode_base),
            true
        );
        e.mov_reg_reg(rx::rcx, r.ip);
        e.sub_reg_reg(rx::rcx, rx::rax);
        e.mov_reg_mem(
            rx::rdx,
            r.state_ptr,
            static_cast<std::int32_t>(st.call_sp),
            true
        );
        e.lea_reg_mem(
            r.scratch_b,
            r.state_ptr,
            rx::rdx,
            3,
            static_cast<std::int32_t>(st.call_stack_base)
        );
        e.mov_mem_reg(
            r.scratch_b,
            0,
            rx::rcx,
            true
        );
        e.inc_reg(rx::rdx, true);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.call_sp),
            rx::rdx,
            true
        );

        // ip += rel32, jump to callee
        e.add_reg_reg(r.ip, r.scratch_a);
        emit_cipher_reset(e, vm);
        emit_dispatch_tail(e, vm);
    }

    // RET_VM
    void RetVmCodec::encode(BytecodeBuilder& out, const IRInsn& i, const VMConfig& vm) const {
        out.u8(vm.opcode_for(family()));
        (void)i;
    }

    void RetVmCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        // pop the top of the shadow stack and jump there natively
        const auto& r = vm.dispatcher_regs();
        const auto& st = vm.state_layout();
        const std::uint8_t rsp_slot = vm.slot_of_xreg(XReg::SP);
        const std::int32_t rsp_off  = static_cast<std::int32_t>(st.regs_base + rsp_slot * 8);

        // pop shadow stack: rax = popped value, VM_RSP += 8.
        e.mov_reg_mem(
            rx::rcx,
            r.state_ptr,
            rsp_off,
            true
        );
        e.mov_reg_mem(
            rx::rax,
            rx::rcx,
            0,
            true
        ); // rax = popped target

        e.add_reg_imm32(rx::rcx, 8);
        e.mov_mem_reg(
            r.state_ptr,
            rsp_off,
            rx::rcx,
            true
        ); // commit VM_RSP

        // stash target. materialization loop clobbers rax.
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.cipher_extra) + kSavedTargetOff,
            rx::rax,
            true
        );

        // save dispatcher state for the trampoline to restore
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.cipher_extra) + kSavedIpOff,
            r.ip,
            true
        );
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.cipher_extra) + kSavedHbOff,
            r.handler_base,
            true
        );
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.cipher_extra) + kSavedCsOff,
            r.cipher_state,
            true
        );
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.saved_native_rsp),
            rx::rsp,
            true
        );

        // materialize x86 gprs from VMState slots 
        auto sp = r.state_ptr;
        auto load_xreg_to = [&](XReg xr, std::uint8_t real_reg) {
            const std::uint8_t slot = vm.slot_of_xreg(xr);
            e.mov_reg_mem(
                real_reg, 
                sp,
                static_cast<std::int32_t>(vm.state_layout().regs_base + slot * 8),
                true
            );
        };

        static constexpr XReg materialize_order[] = {
            XReg::AX, XReg::CX, XReg::DX, XReg::BX, XReg::BP, XReg::SI, XReg::DI,
            XReg::R8, XReg::R9, XReg::R10, XReg::R11, XReg::R12, XReg::R13, XReg::R14, XReg::R15
        };
        
        static constexpr std::uint8_t real_regs[] = {
            rx::rax, rx::rcx, rx::rdx, rx::rbx, rx::rbp, rx::rsi, rx::rdi,
            rx::r8,  rx::r9,  rx::r10, rx::r11, rx::r12, rx::r13, rx::r14, rx::r15
        };

        for (std::size_t k = 0; k < 15; ++k) {
            if (real_regs[k] == sp) continue;
            load_xreg_to(materialize_order[k], real_regs[k]);
        }

        // load rsp last, then jmp through memory so rax isn't clobbered
        e.mov_reg_mem(
            rx::rsp,
            sp,
            static_cast<std::int32_t>(vm.state_layout().regs_base + vm.slot_of_xreg(XReg::SP) * 8),
            true
        );
        e.jmp_mem_disp32(sp, static_cast<std::int32_t>(st.cipher_extra) + kSavedTargetOff);
    }

    // CALL_NATIVE / JMP_NATIVE / RET_NATIVE
    static void enc_native(BytecodeBuilder& o, const IRInsn& i, const VMConfig& v, const Codec* self) {
        o.u8(v.opcode_for(self->family()));
        o.emit_trampoline_offset_for_return_va(i.return_va);

        if (std::holds_alternative<Imm>(i.ops[0])) {
            o.u8(0);
            enc_imm_n(o, get_op<Imm>(i, 0).value, 8);
        }
        else if (std::holds_alternative<VirReg>(i.ops[0])) {
            o.u8(1);
            enc_slot(o, v, get_op<VirReg>(i, 0));
        }
        else {
            o.u8(2);
            enc_mem(o, v, get_op<Mem>(i, 0));
        }
    }

    static void emit_native_handler(X64Emitter& e, const VMConfig& vm, bool is_jmp) {
        const auto& r = vm.dispatcher_regs();
        {
            // deferred data-island decrypt
            const auto& st_local = vm.state_layout();
            auto lbl_dec_done = e.new_label();

            // lea rax, [rip + data_island_init_flag]; cmp byte [rax], 0; jnz done
            auto flag_lea = e.lea_reg_rip(rx::rax, 0);
            e.add_fixup(
                flag_lea,
                static_cast<std::uint32_t>(FixupKind::DataIslandInitFlag),
                0,
                0
            );
            e.u8(0x80);
            e.emit_modrm_mem(
                7,
                rx::rax,
                rx::none,
                0,
                0
            );
            e.u8(0);
            e.jcc_label(cc::nz, lbl_dec_done);

            // save cipher_state + ip so the rest of the handler's fetch
            // invariant survives the loop.
            e.mov_mem_reg(
                r.state_ptr,
                static_cast<std::int32_t>(st_local.cipher_extra) + kPreDecryptCsOff,
                r.cipher_state,
                true
            );

            e.mov_mem_reg(
                r.state_ptr,
                static_cast<std::int32_t>(st_local.cipher_extra) + kPreDecryptIpOff,
                r.ip,
                true
            );

            // reset cipher_state to cipher_init and walk the island tom hanks
            e.mov_reg_imm64(rx::rax, vm.cipher_init_state());
            e.mov_reg_reg(r.cipher_state, rx::rax);
            auto src_slot = e.lea_reg_rip(r.ip, 0);
            e.add_fixup(
                src_slot,
                static_cast<std::uint32_t>(FixupKind::DataIsland),
                0,
                0
            );
            auto dst_slot = e.lea_reg_rip(r.scratch_b, 0);
            e.add_fixup(
                dst_slot,
                static_cast<std::uint32_t>(FixupKind::DataIsland),
                0,
                0
            );
            e.mov_reg_imm32(rx::rcx, static_cast<std::int32_t>(vm.data_island_size()));

            auto lbl_loop = e.new_label();
            e.bind(lbl_loop);
            emit_fetch_byte_dec(e, vm, rx::rax);
            e.emit_rex(
                false,
                false,
                false,
                r.scratch_b >= 8
            );
            e.u8(0x88);
            e.emit_modrm_mem(
                0 /*al*/,
                r.scratch_b,
                rx::none,
                0,
                0
            );
            e.inc_reg(r.scratch_b, true);
            e.dec_reg(rx::rcx, true);
            e.test_reg_reg(rx::rcx, rx::rcx);
            e.jcc_label(cc::nz, lbl_loop);

            // restore ip + cipher_state.
            e.mov_reg_mem(
                r.cipher_state,
                r.state_ptr,
                static_cast<std::int32_t>(st_local.cipher_extra) + kPreDecryptCsOff,
                true
            );

            e.mov_reg_mem(
                r.ip,
                r.state_ptr,
                static_cast<std::int32_t>(st_local.cipher_extra) + kPreDecryptIpOff,
                true
            );

            // mark flag.
            auto flag_set = e.lea_reg_rip(rx::rax, 0);
            e.add_fixup(
                flag_set,
                static_cast<std::uint32_t>(FixupKind::DataIslandInitFlag),
                0,
                0
            );
            e.u8(0xC6);
            e.emit_modrm_mem(
                0,
                rx::rax,
                rx::none,
                0,
                0
            );
            e.u8(1);

            e.bind(lbl_dec_done);
        }
        const auto& st = vm.state_layout();

        // operand stream: [u32 return_va_offset_in_data_island][u8 tgt_tag][payload]
        constexpr std::int32_t kRangeRetSignOff = 64;
        const std::int32_t saved_ret_off  = static_cast<std::int32_t>(st.cipher_extra) + kSavedTargetOff + 16;
        const std::int32_t range_sign_off = static_cast<std::int32_t>(st.cipher_extra) + kRangeRetSignOff;
        emit_fetch_u32_dec(e, vm, r.scratch_b);
        e.movsxd_r64_r32(r.scratch_b, r.scratch_b);
        e.mov_mem_reg(r.state_ptr, range_sign_off, r.scratch_b, true);
        e.mov_reg_mem(
            rx::rax,
            r.state_ptr,
            static_cast<std::int32_t>(st.trampoline_base),
            true
        );
        e.add_reg_reg(rx::rax, r.scratch_b);
        e.mov_mem_reg(
            r.state_ptr,
            saved_ret_off,
            rx::rax,
            true
        );

        // VM_RSP push
        const bool range_mode_call = vm.range_mode() && !vm.pack_mode() && !is_jmp;
        if (!is_jmp) {
            const std::uint8_t rsp_slot = vm.slot_of_xreg(XReg::SP);
            const std::int32_t rsp_off = static_cast<std::int32_t>(st.regs_base + rsp_slot * 8);
            e.mov_reg_mem(
                rx::rcx,
                r.state_ptr,
                rsp_off,
                true
            );
            e.sub_reg_imm32(rx::rcx, 8);
            e.mov_mem_reg(
                r.state_ptr,
                rsp_off,
                rx::rcx,
                true
            );
            e.mov_mem_reg(
                rx::rcx,
                0,
                rx::rax,
                true
            );
        }

        // fetch target into rax.
        emit_fetch_byte_dec(e, vm, r.scratch_a);

        // save tag byte 
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.cipher_extra) + kSavedTagOff,
            r.scratch_a,
            true
        );

        auto lbl_vreg = e.new_label(), lbl_mem = e.new_label(), lbl_tgt_done = e.new_label();
        e.cmp_reg_imm32(r.scratch_a, 1);
        e.jcc_label(cc::z, lbl_vreg);
        e.cmp_reg_imm32(r.scratch_a, 2);
        e.jcc_label(cc::z, lbl_mem);
        e.sub_reg_imm32(rx::rsp, 16);
        emit_fetch_uN_dec(
            e,
            vm,
            rx::rax,
            8
        );
        e.add_reg_imm32(rx::rsp, 16);

        // in --ranges hybrid mode, imm targets from the lifter are blob-va
        // offsets not runtime absolutes
        if (vm.range_mode() || vm.pack_mode()) {
            e.mov_reg_mem(
                r.scratch_b,
                r.state_ptr,
                static_cast<std::int32_t>(st.data_island_base),
                true
            );
            e.add_reg_reg(rx::rax, r.scratch_b);
        }

        e.jmp_label(lbl_tgt_done);
        e.bind(lbl_vreg);
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        e.mov_reg_mem_sib(
            rx::rax,
            r.state_ptr,
            r.scratch_a,
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base), 
            true
        );
        e.jmp_label(lbl_tgt_done);
        e.bind(lbl_mem);
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, rx::rdx);
        emit_fetch_byte_dec(e, vm, rx::r10);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        emit_fetch_u32_dec(e, vm, rx::rcx);
        emit_fetch_byte_dec(e, vm, rx::r11);
        e.mov_reg_mem_sib(
            r.scratch_b, 
            r.state_ptr, 
            r.scratch_a, 
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base),
            true
        );
        e.movsxd_r64_r32(rx::rcx, rx::rcx);
        e.add_reg_reg(r.scratch_b, rx::rcx);
        e.mov_reg_mem(
            rx::rax,
            r.scratch_b,
            0,
            true
        );
        e.bind(lbl_tgt_done);

        // save target into temp slot
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.cipher_extra) + kSavedTargetOff,
            rx::rax,
            true
        );

        // bullshit didnt work try again later
        (void)saved_ret_off;

        // save dispatcher state into VMState slots before clobber.
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.cipher_extra) + kSavedIpOff,
            r.ip,
            true
        );
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.cipher_extra) + kSavedHbOff,
            r.handler_base,
            true
        );
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.cipher_extra) + kSavedCsOff,
            r.cipher_state,
            true
        );
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.saved_native_rsp),
            rx::rsp,
            true
        );

        // materialize x86 gprs from VMState slots 
        auto load_reg = [&](XReg xr, std::uint8_t real_reg) {
            const std::uint8_t slot = vm.slot_of_xreg(xr);

            // [state_ptr + slot*8 + regs_base]
            e.mov_reg_mem_sib(
                real_reg,
                r.state_ptr,
                0xFE,
                3,
                0
            );
        };

        auto load_xreg_to = [&](XReg xr, std::uint8_t real_reg) {
            const std::uint8_t slot = vm.slot_of_xreg(xr);
            e.mov_reg_mem(
                real_reg,
                r.state_ptr,
                static_cast<std::int32_t>(vm.state_layout().regs_base + slot * 8),
                true
            );
        };

        // r10/r11 are still scratch above, so load them last in this pass
        // nv-mapped first like rbx/rbp/rdi/rsi/r12..r15 except state_ptr
        auto sp = r.state_ptr;
        static constexpr XReg materialize_order[] = {
            XReg::AX, XReg::CX, XReg::DX, XReg::BX, XReg::BP, XReg::SI, XReg::DI,
            XReg::R8, XReg::R9, XReg::R10, XReg::R11, XReg::R12, XReg::R13, XReg::R14, XReg::R15
        };

        static constexpr std::uint8_t real_regs[] = {
            rx::rax, rx::rcx, rx::rdx, rx::rbx, rx::rbp, rx::rsi, rx::rdi,
            rx::r8,  rx::r9,  rx::r10, rx::r11, rx::r12, rx::r13, rx::r14, rx::r15
        };

        for (std::size_t k = 0; k < 15; ++k) {
            if (real_regs[k] == sp) continue;
            load_xreg_to(materialize_order[k], real_regs[k]);
        }

        // range-mode mid-exec JMP_NATIVE teardown
        if (vm.range_mode() && !vm.pack_mode() && is_jmp) {
            // cleanup style from saved tag
            auto lbl_api_path = e.new_label();
            e.mov_reg_mem(
                rx::rax, 
                sp,
                static_cast<std::int32_t>(st.cipher_extra) + kSavedTagOff,
                true
            );

            e.test_reg_reg(rx::rax, rx::rax);
            e.jcc_label(cc::nz, lbl_api_path);

            // tag == 0: imm passthrough cleanup.
            e.mov_reg_mem(
                rx::rax, 
                sp,
                static_cast<std::int32_t>(st.cipher_extra) + kSavedTargetOff,
                true
            );

            const std::uint32_t frame_size = static_cast<std::uint32_t>(vm.state_layout().total_size) + vm.shadow_stack_bytes() + vm.frame_padding();
            const std::uint32_t aligned_frame = (frame_size + 15) & ~15u;

            e.mov_reg_mem(
                rx::rcx, 
                sp,
                static_cast<std::int32_t>(st.saved_native_rsp),
                true
            );

            e.add_reg_imm32(
                rx::rcx,
                static_cast<std::int32_t>(aligned_frame + 72)
            );

            e.mov_mem_reg(
                rx::rcx,
                0,
                rx::rax,
                true
            ); // [caller_retaddr] = target

            // --range-leak-nvs. blast current VMState NV slots over the
            // prologue stack saves so exit_handler's pop sequence picks up
            // what the lifted range actually wrote instead of the stale,
            // shitty caller-side values
            if (vm.range_leak_nvs()) {
                if (const auto* order = prologue_order_for(e)) {
                    auto host_to_xreg = [](std::uint8_t reg) -> XReg {
                        if (reg == rx::rbx) return XReg::BX;
                        if (reg == rx::rbp) return XReg::BP;
                        if (reg == rx::rdi) return XReg::DI;
                        if (reg == rx::rsi) return XReg::SI;
                        if (reg == rx::r12) return XReg::R12;
                        if (reg == rx::r13) return XReg::R13;
                        if (reg == rx::r14) return XReg::R14;
                        if (reg == rx::r15) return XReg::R15;
                        return XReg::Invalid;
                    };

                    for (std::size_t i = 0; i < order->size(); ++i) {
                        const std::uint8_t nv_reg = (*order)[i];
                        const XReg xr = host_to_xreg(nv_reg);
                        if (xr == XReg::Invalid) continue;
                        e.mov_reg_mem(
                            rx::rax,
                            sp,
                            static_cast<std::int32_t>(vm.state_layout().regs_base + vm.slot_of_xreg(xr) * 8),
                            true
                        );
                        e.mov_mem_reg(
                            rx::rcx,
                            -static_cast<std::int32_t>(8 * (i + 1)),
                            rx::rax,
                            true
                        );
                    }
                }
            }

            e.mov_reg_mem(
                rx::rcx,
                sp,
                static_cast<std::int32_t>(vm.state_layout().regs_base + vm.slot_of_xreg(XReg::CX) * 8),
                true
            );

            e.u8(0xE9);
            const std::size_t patch = e.size();
            e.u32(0);
            e.add_fixup(
                patch,
                static_cast<std::uint32_t>(FixupKind::VMExit),
                0,
                0
            );
            // flow ends, control transferred to exit_handler

            e.bind(lbl_api_path);

            // re-materialize rax
            e.mov_reg_mem(
                rx::rax,
                sp,
                static_cast<std::int32_t>(vm.state_layout().regs_base + vm.slot_of_xreg(XReg::AX) * 8),
                true
            );

            // range-mode JMP_NATIVE api_path. support for --heap-stack
            // and shadow-stack default
            {
                const auto host_to_xreg_j = [](std::uint8_t reg) -> XReg {
                    if (reg == rx::rbx) return XReg::BX;
                    if (reg == rx::rbp) return XReg::BP;
                    if (reg == rx::rdi) return XReg::DI;
                    if (reg == rx::rsi) return XReg::SI;
                    if (reg == rx::r12) return XReg::R12;
                    if (reg == rx::r13) return XReg::R13;
                    if (reg == rx::r14) return XReg::R14;
                    if (reg == rx::r15) return XReg::R15;
                    return XReg::Invalid;
                };
                const XReg sp_xreg_j = host_to_xreg_j(sp);
                if (sp_xreg_j != XReg::Invalid) {
                    if (vm.heap_stack()) {
                        // heap stack
                        e.mov_reg_mem(
                            rx::r10,
                            sp,
                            static_cast<std::int32_t>(vm.state_layout().regs_base + vm.slot_of_xreg(XReg::SP) * 8),
                            true
                        );
                        e.mov_reg_mem(rx::r10, rx::r10, 0, true);

                        // target -> r11, jmp r11 at end
                        e.mov_reg_mem(
                            rx::r11,
                            sp,
                            static_cast<std::int32_t>(st.cipher_extra) + kSavedTargetOff,
                            true
                        );

                        // compute new rsp
                        const std::uint32_t frame_size_h = static_cast<std::uint32_t>(vm.state_layout().total_size) + vm.shadow_stack_bytes() + vm.frame_padding();
                        const std::uint32_t aligned_h = (frame_size_h + 15) & ~15u;
                        const std::int32_t  native_rsp_delta_h = static_cast<std::int32_t>(aligned_h) + 72 - static_cast<std::int32_t>(vm.shadow_stack_bytes());
                        e.lea_reg_mem(rx::rsp, sp, rx::none, 0, native_rsp_delta_h + 0x08);

                        // write retaddr at [rsp]
                        e.mov_mem_reg(rx::rsp, 0, rx::r10, true);

                        // put state_ptr-host-reg's lifted slot back into it
                        e.mov_reg_mem(
                            sp,
                            sp,
                            static_cast<std::int32_t>(vm.state_layout().regs_base + vm.slot_of_xreg(sp_xreg_j) * 8),
                            true
                        );

                        // jmp target r11, rax stays = AX_slot, rcx = CX_slot, etc
                        e.jmp_reg(rx::r11);
                        return;
                    }

                    // shadow-stack default
                    e.mov_reg_mem(
                        rx::rcx,
                        sp,
                        static_cast<std::int32_t>(st.cipher_extra) + kSavedTargetOff,
                        true
                    );
                    e.mov_reg_mem(
                        rx::rsp,
                        sp,
                        static_cast<std::int32_t>(vm.state_layout().regs_base + vm.slot_of_xreg(XReg::SP) * 8),
                        true
                    );
                    e.mov_reg_mem(
                        sp,
                        sp,
                        static_cast<std::int32_t>(vm.state_layout().regs_base + vm.slot_of_xreg(sp_xreg_j) * 8),
                        true
                    );
                    e.jmp_reg(rx::rcx);
                    return;
                }
            }
            // fall through to the normal path: rsp = VM_RSP, jmp via mem.
        }

        // range-mode CALL_NATIVE
        if (range_mode_call) {
            auto lbl_in_range = e.new_label();

            // load the saved signed offset; if non-negative branch to the
            // default tail
            e.mov_reg_mem(rx::rax, sp, range_sign_off, true);
            e.test_reg_reg(rx::rax, rx::rax, true);
            e.jcc_label(cc::ns, lbl_in_range);

            // if out of range, real stack disp
            const std::uint32_t frame_size_b = static_cast<std::uint32_t>(vm.state_layout().total_size) + vm.shadow_stack_bytes() + vm.frame_padding();
            const std::uint32_t aligned_frame_b = (frame_size_b + 15) & ~15u;
            const std::int32_t native_rsp_delta = static_cast<std::int32_t>(aligned_frame_b) + 72 - static_cast<std::int32_t>(vm.shadow_stack_bytes());

            const auto host_to_xreg = [](std::uint8_t reg) -> XReg {
                if (reg == rx::rbx) return XReg::BX;
                if (reg == rx::rbp) return XReg::BP;
                if (reg == rx::rdi) return XReg::DI;
                if (reg == rx::rsi) return XReg::SI;
                if (reg == rx::r12) return XReg::R12;
                if (reg == rx::r13) return XReg::R13;
                if (reg == rx::r14) return XReg::R14;
                if (reg == rx::r15) return XReg::R15;
                return XReg::Invalid;
            };
            const XReg sp_xreg = host_to_xreg(sp);
            const std::int32_t sp_slot_off = (sp_xreg == XReg::Invalid) ? 0 : static_cast<std::int32_t>(vm.state_layout().regs_base + vm.slot_of_xreg(sp_xreg) * 8);

            // rsp = native_entry_rsp - 8
            e.lea_reg_mem(rx::rsp, sp, rx::none, 0, native_rsp_delta - 8);

            // push ret_va_ptr onto real stack.
            e.mov_reg_mem(rx::rcx, sp, saved_ret_off, true);
            e.mov_mem_reg(rx::rsp, 0, rx::rcx, true);

            // target -> rcx
            e.mov_reg_mem(
                rx::rcx,
                sp,
                static_cast<std::int32_t>(st.cipher_extra) + kSavedTargetOff,
                true
            );

            // restore rax from the AX slot
            e.mov_reg_mem(
                rx::rax,
                sp,
                static_cast<std::int32_t>(vm.state_layout().regs_base + vm.slot_of_xreg(XReg::AX) * 8),
                true
            );

            // splat state_ptr-host-reg's lifted slot back into it.
            if (sp_xreg != XReg::Invalid) {
                e.mov_reg_mem(sp, sp, sp_slot_off, true);
            }

            e.jmp_reg(rx::rcx);

            // in-range path falls through to the default tail.
            e.bind(lbl_in_range);
        }

        // set rsp = VM_RSP. must be the last gpr materialization.
        e.mov_reg_mem(
            rx::rsp,
            sp,
            static_cast<std::int32_t>(vm.state_layout().regs_base + vm.slot_of_xreg(XReg::SP) * 8),
            true
        );

        // tail-call to target. both CALL_NATIVE and JMP_NATIVE use CPU JMP
        // through memory so rax stays untouched
        e.jmp_mem_disp32(sp, static_cast<std::int32_t>(st.cipher_extra) + kSavedTargetOff);
    }

    void CallNativeCodec::encode(BytecodeBuilder& o, const IRInsn& i, const VMConfig& v) const { 
        enc_native(
            o,
            i,
            v,
            this
        ); 
    }

    void CallNativeCodec::emit_handler(X64Emitter& e, const VMConfig& v) const { emit_native_handler(e, v, false); }

    void JmpNativeCodec::encode(BytecodeBuilder& o, const IRInsn& i, const VMConfig& v) const { 
        enc_native(
            o,
            i,
            v,
            this
        );
    }

    void JmpNativeCodec::emit_handler(X64Emitter& e, const VMConfig& v) const { emit_native_handler(e, v, true); }

    void RetNativeCodec::encode(BytecodeBuilder& out, const IRInsn&, const VMConfig& vm) const {
        out.u8(vm.opcode_for(family()));
    }

    void RetNativeCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        // same as EXIT.
        e.u8(0xE9);
        e.emit_rel32_fixup(static_cast<std::uint32_t>(FixupKind::VMExit), 0, 0);
        (void)vm;
    }

    // PUSH / POP on shadow stack
    void PushCodec::encode(BytecodeBuilder& out, const IRInsn& i, const VMConfig& vm) const {
        out.u8(vm.opcode_for(family()));
        if (std::holds_alternative<VirReg>(i.ops[0])) {
            out.u8(0);
            enc_slot(out, vm, get_op<VirReg>(i, 0));
        }
        else if (std::holds_alternative<Imm>(i.ops[0])) {
            out.u8(1);
            enc_imm_n(out, get_op<Imm>(i, 0).value, 8);
        }
        else {
            out.u8(2);
            enc_mem(out, vm, get_op<Mem>(i, 0));
        }
    }

    void PushCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();

        // load value into rax
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        auto lbl_imm = e.new_label(), lbl_mem = e.new_label(), lbl_done = e.new_label();
        e.cmp_reg_imm32(r.scratch_a, 1);
        e.jcc_label(cc::z, lbl_imm);
        e.cmp_reg_imm32(r.scratch_a, 2);
        e.jcc_label(cc::z, lbl_mem);
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        e.mov_reg_mem_sib(
            rx::rax, 
            r.state_ptr, 
            r.scratch_a, 
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base),
            true
        );
        e.jmp_label(lbl_done);
        e.bind(lbl_imm);
        e.sub_reg_imm32(rx::rsp, 16);
        emit_fetch_uN_dec(
            e,
            vm,
            rx::rax,
            8
        );
        e.add_reg_imm32(rx::rsp, 16);
        e.jmp_label(lbl_done);
        e.bind(lbl_mem);
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, rx::rdx);
        emit_fetch_byte_dec(e, vm, rx::r10);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        emit_fetch_u32_dec(e, vm, rx::rcx);
        emit_fetch_byte_dec(e, vm, rx::r11);
        e.mov_reg_mem_sib(
            r.scratch_b, 
            r.state_ptr, 
            r.scratch_a, 
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base), 
            true
        );
        e.movsxd_r64_r32(rx::rcx, rx::rcx);
        e.add_reg_reg(r.scratch_b, rx::rcx);
        e.mov_reg_mem(
            rx::rax,
            r.scratch_b,
            0,
            true
        );
        e.bind(lbl_done);

        // VM_RSP -= 8 ; mem[VM_RSP] = rax
        const std::uint8_t rsp_slot = vm.slot_of_xreg(XReg::SP);
        e.mov_reg_mem(
            rx::rcx,
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().regs_base + rsp_slot * 8),
            true
        );
        e.sub_reg_imm32(rx::rcx, 8);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().regs_base + rsp_slot * 8),
            rx::rcx,
            true
        );
        e.mov_mem_reg(
            rx::rcx,
            0,
            rx::rax,
            true
        );
        emit_dispatch_tail(e, vm);
    }

    void PopCodec::encode(BytecodeBuilder& out, const IRInsn& i, const VMConfig& vm) const {
        out.u8(vm.opcode_for(family()));
        if (std::holds_alternative<VirReg>(i.ops[0])) {
            out.u8(0);
            enc_slot(out, vm, get_op<VirReg>(i, 0));
        }
        else {
            out.u8(1);
            enc_mem(out, vm, get_op<Mem>(i, 0));
        }
    }

    void PopCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        const std::uint8_t rsp_slot = vm.slot_of_xreg(XReg::SP);

        // val = mem[VM_RSP] ; VM_RSP += 8
        e.mov_reg_mem(
            rx::rcx, 
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().regs_base + rsp_slot * 8),
            true
        );
        e.mov_reg_mem(
            rx::rax,
            rx::rcx,
            0,
            true
        );
        e.add_reg_imm32(rx::rcx, 8);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().regs_base + rsp_slot * 8),
            rx::rcx,
            true
        );
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        auto lbl_mem = e.new_label(), lbl_done = e.new_label();
        e.cmp_reg_imm32(r.scratch_a, 1);
        e.jcc_label(cc::z, lbl_mem);
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        emit_store_slot_value(
            e,
            vm,
            r.scratch_a,
            rx::rax,
            r.scratch_b
        );
        e.jmp_label(lbl_done);
        e.bind(lbl_mem);

        // mem destination should be rare for shellcode, will worry if a issue shows up.
        e.bind(lbl_done);
        emit_dispatch_tail(e, vm);
    }

    // ZEXT / SEXT
    void ZextCodec::encode(BytecodeBuilder& out, const IRInsn& i, const VMConfig& vm) const {
        out.u8(vm.opcode_for(family()));
        enc_slot(out, vm, get_op<VirReg>(i, 0));
        if (std::holds_alternative<VirReg>(i.ops[1])) {
            out.u8(0);
            enc_slot(out, vm, get_op<VirReg>(i, 1));
        }
        else {
            out.u8(1);
            enc_mem(out, vm, get_op<Mem>(i, 1));
        }
        out.u8(static_cast<std::uint8_t>(get_op<Imm>(i, 2).value)); // src width
    }

    void ZextCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, r.scratch_b); // dst width
        e.push_reg(r.scratch_a); e.push_reg(r.scratch_b);
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        auto lbl_mem = e.new_label(), lbl_load_done = e.new_label();
        e.cmp_reg_imm32(r.scratch_a, 1);
        e.jcc_label(cc::z, lbl_mem);
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        e.mov_reg_mem_sib(
            rx::rax,
            r.state_ptr,
            r.scratch_a,
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base), 
            true
        );
        e.jmp_label(lbl_load_done);
        e.bind(lbl_mem);
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, rx::rdx);
        emit_fetch_byte_dec(e, vm, rx::r10);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        emit_fetch_u32_dec(e, vm, rx::rcx);
        emit_fetch_byte_dec(e, vm, rx::r11);
        e.mov_reg_mem_sib(
            r.scratch_b,
            r.state_ptr,
            r.scratch_a,
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base),
            true
        );
        e.movsxd_r64_r32(rx::rcx, rx::rcx);
        e.add_reg_reg(r.scratch_b, rx::rcx);
        e.mov_reg_mem(
            rx::rax,
            r.scratch_b,
            0,
            true
        );
        e.bind(lbl_load_done);

        // src width byte
        emit_fetch_byte_dec(e, vm, rx::rcx);

        // zero-extend via AND.
        e.cmp_reg_imm32(rx::rcx, 1);
        auto lbl_w2 = e.new_label(), lbl_w4 = e.new_label(), lbl_zext_done = e.new_label();
        auto lbl_zw1 = e.new_label();
        e.jcc_label(cc::z, lbl_zw1);
        e.cmp_reg_imm32(rx::rcx, 2);
        e.jcc_label(cc::z, lbl_w2);
        e.jmp_label(lbl_zext_done); // w4: already 32 in low, treat as zext to 64 by clearing upper
        e.bind(lbl_zw1);
        e.and_reg_imm32(rx::rax, 0xFF);
        e.jmp_label(lbl_zext_done);
        e.bind(lbl_w2);
        e.and_reg_imm32(rx::rax, 0xFFFF);
        e.bind(lbl_zext_done);
        e.pop_reg(r.scratch_b); e.pop_reg(r.scratch_a);
        emit_store_slot_value(
            e,
            vm,
            r.scratch_a,
            rx::rax,
            r.scratch_b
        );
        emit_dispatch_tail(e, vm);
    }

    void SextCodec::encode(BytecodeBuilder& out, const IRInsn& i, const VMConfig& vm) const {
        out.u8(vm.opcode_for(family()));
        enc_slot(out, vm, get_op<VirReg>(i, 0));
        if (std::holds_alternative<VirReg>(i.ops[1])) {
            out.u8(0);
            enc_slot(out, vm, get_op<VirReg>(i, 1));
        }
        else {
            out.u8(1);
            enc_mem(out, vm, get_op<Mem>(i, 1));
        }
        out.u8(static_cast<std::uint8_t>(get_op<Imm>(i, 2).value));
    }

    void SextCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        e.push_reg(r.scratch_a); e.push_reg(r.scratch_b);
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        auto lbl_mem = e.new_label(), lbl_load_done = e.new_label();
        e.cmp_reg_imm32(r.scratch_a, 1);
        e.jcc_label(cc::z, lbl_mem);
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        e.mov_reg_mem_sib(
            rx::rax, 
            r.state_ptr,
            r.scratch_a, 
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base), 
            true
        );
        e.jmp_label(lbl_load_done);
        e.bind(lbl_mem);
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, rx::rdx);
        emit_fetch_byte_dec(e, vm, rx::r10);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        emit_fetch_u32_dec(e, vm, rx::rcx);
        emit_fetch_byte_dec(e, vm, rx::r11);
        e.mov_reg_mem_sib(
            r.scratch_b, 
            r.state_ptr, 
            r.scratch_a, 
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base), 
            true
        );
        e.movsxd_r64_r32(rx::rcx, rx::rcx);
        e.add_reg_reg(r.scratch_b, rx::rcx);
        e.mov_reg_mem(
            rx::rax,
            r.scratch_b,
            0,
            true
        );
        e.bind(lbl_load_done);
        emit_fetch_byte_dec(e, vm, rx::rcx);
        auto lbl_sw2 = e.new_label(), lbl_sw4 = e.new_label(), lbl_sext_done = e.new_label();
        e.cmp_reg_imm32(rx::rcx, 1);
        auto lbl_sw1 = e.new_label();
        e.jcc_label(cc::z, lbl_sw1);
        e.cmp_reg_imm32(rx::rcx, 2);
        e.jcc_label(cc::z, lbl_sw2);

        // w4
        e.movsxd_r64_r32(rx::rax, rx::rax);
        e.jmp_label(lbl_sext_done);
        e.bind(lbl_sw1);
        e.movsx_r64_r8(rx::rax, rx::rax);
        e.jmp_label(lbl_sext_done);
        e.bind(lbl_sw2);
        e.movsx_r64_r16(rx::rax, rx::rax);
        e.bind(lbl_sext_done);
        e.pop_reg(r.scratch_b); e.pop_reg(r.scratch_a);
        emit_store_slot_value(
            e,
            vm,
            r.scratch_a,
            rx::rax,
            r.scratch_b
        );
        emit_dispatch_tail(e, vm);
    }

    // XCHG
    void XchgCodec::encode(BytecodeBuilder& out, const IRInsn& i, const VMConfig& vm) const {
        out.u8(vm.opcode_for(family()));
        enc_slot(out, vm, get_op<VirReg>(i, 0));
        enc_slot(out, vm, get_op<VirReg>(i, 1));
    }

    void XchgCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        e.mov_reg_mem_sib(
            rx::rax, 
            r.state_ptr, 
            r.scratch_a, 
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base),
            true
        );
        e.push_reg(rx::rax); e.push_reg(r.scratch_a);
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        e.mov_reg_mem_sib(
            rx::rcx,
            r.state_ptr,
            r.scratch_a,
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base),
            true
        );
        e.mov_mem_sib_reg(
            r.state_ptr, 
            r.scratch_a, 
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base), rx::rax /*pre-pop*/, 
            true
        );
        e.pop_reg(r.scratch_a); e.pop_reg(rx::rax);

        // write rcx, second op's original value, into the first op's slot.
        e.mov_mem_sib_reg(
            r.state_ptr, 
            r.scratch_a, 
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base), rx::rcx, 
            true
        );

        emit_dispatch_tail(e, vm);
    }

    // SETCC
    void SetccCodec::encode(BytecodeBuilder& out, const IRInsn& i, const VMConfig& vm) const {
        out.u8(vm.opcode_for(family()));

        // encoding: dst_slot, cond. width is always 1 since SETCC writes one
        // byte, so we don't encode it 
        if (!std::holds_alternative<VirReg>(i.ops[0])) {
            throw Error("SETCC: memory destination not supported by codec");
        }

        enc_slot(out, vm, get_op<VirReg>(i, 0));
        out.u8(static_cast<std::uint8_t>(i.cond));
    }

    void SetccCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        // mirror of the x86 SetccCodec. cond -> predicate byte 0 or 1 written
        // to dst slot 
        const auto& r = vm.dispatcher_regs();
        const auto& st = vm.state_layout();

        emit_fetch_byte_dec(e, vm, r.scratch_a); // dst slot
        emit_fetch_byte_dec(e, vm, r.scratch_b); // dst width = 1
        e.push_reg(r.scratch_a);
        e.push_reg(r.scratch_b);
        emit_fetch_byte_dec(e, vm, r.scratch_a); // cond

        // valreg = predicate accumulator 
        constexpr std::uint8_t valreg = rx::rax;
        constexpr std::uint8_t flag_b_reg = rx::rcx;

        e.mov_reg_mem(
            valreg,
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_result),
            true
        );
        e.mov_reg_mem(
            r.scratch_b,
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_a),
            true
        );

        auto lbl_done = e.new_label();

        // setcc r/m8: 0F 9X /0 + reg
        auto setcc_to_valreg = [&](std::uint8_t cc_code) {
            e.emit_rex(
                false,
                false,
                false,
                valreg >= 8
            );
            e.u8(0x0F); e.u8(static_cast<std::uint8_t>(0x90 + cc_code));
            e.emit_modrm(3, 0, valreg & 7);
            e.movzx_r64_r8(valreg, valreg);
        };

        auto handle = [&](std::uint8_t want, auto&& fn) {
            auto lbl_n = e.new_label();
            e.cmp_reg_imm32(r.scratch_a, static_cast<std::int32_t>(want));
            e.jcc_label(cc::nz, lbl_n);
            fn();
            e.jmp_label(lbl_done);
            e.bind(lbl_n);
        };

        // Z / NZ / S / NS from flag_result.
        handle(static_cast<std::uint8_t>(Cond::Z),  [&](){
            e.test_reg_reg(valreg, valreg);  setcc_to_valreg(cc::z);
        });
        
        handle(static_cast<std::uint8_t>(Cond::NZ), [&](){
            e.test_reg_reg(valreg, valreg);  setcc_to_valreg(cc::nz);
        });

        handle(static_cast<std::uint8_t>(Cond::S),  [&](){
            e.test_reg_reg(valreg, valreg);  setcc_to_valreg(cc::s);
        });

        handle(static_cast<std::uint8_t>(Cond::NS), [&](){
            e.test_reg_reg(valreg, valreg);  setcc_to_valreg(cc::ns);
        });

        // B / NB / L / NL from cmp flag_a, flag_b.
        auto cmp_ab_and_set = [&](std::uint8_t cc_code) {
            e.mov_reg_mem(
                flag_b_reg,
                r.state_ptr,
                static_cast<std::int32_t>(st.flags_b),
                true
            );
            e.cmp_reg_reg(r.scratch_b, flag_b_reg);
            setcc_to_valreg(cc_code);
        };

        handle(static_cast<std::uint8_t>(Cond::B),  [&](){ cmp_ab_and_set(cc::b);  });
        handle(static_cast<std::uint8_t>(Cond::NB), [&](){ cmp_ab_and_set(cc::nb); });
        handle(static_cast<std::uint8_t>(Cond::L),  [&](){ cmp_ab_and_set(cc::l);  });
        handle(static_cast<std::uint8_t>(Cond::NL), [&](){ cmp_ab_and_set(cc::nl); });

        // unmatched cond: predicate = 0.
        e.xor_reg_reg(valreg, valreg);
        e.bind(lbl_done);

        e.pop_reg(r.scratch_b);
        e.pop_reg(r.scratch_a);
        emit_store_slot_value(
            e,
            vm,
            r.scratch_a,
            valreg,
            r.scratch_b
        );
        emit_dispatch_tail(e, vm);
    }

    // BSWAP
    void BswapCodec::encode(BytecodeBuilder& out, const IRInsn& i, const VMConfig& vm) const {
        out.u8(vm.opcode_for(family())); enc_slot(out, vm, get_op<VirReg>(i, 0));
    }

    void BswapCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        e.mov_reg_mem_sib(
            rx::rax, 
            r.state_ptr, 
            r.scratch_a, 3,
            static_cast<std::int32_t>(vm.state_layout().regs_base), 
            true
        );
        e.bswap_reg(rx::rax, true);
        emit_store_slot_value(
            e,
            vm,
            r.scratch_a,
            rx::rax,
            r.scratch_b
        );
        emit_dispatch_tail(e, vm);
    }

    // NOP / DF / CDQE / LOOP / Lodsb / Stosb / Movsb
    void NopCodec::encode(BytecodeBuilder& out, const IRInsn&, const VMConfig& vm) const { out.u8(vm.opcode_for(family())); }
    void NopCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const { emit_dispatch_tail(e, vm); }

    void ExitCodec::encode(BytecodeBuilder& out, const IRInsn&, const VMConfig& vm) const { out.u8(vm.opcode_for(family())); }
    void ExitCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        e.u8(0xE9);
        e.emit_rel32_fixup(static_cast<std::uint32_t>(FixupKind::VMExit), 0, 0);
        (void)vm;
    }

    void LoopDecCodec::encode(BytecodeBuilder& out, const IRInsn& i, const VMConfig& vm) const {
        out.u8(vm.opcode_for(family())); out.emit_branch_rel32(i.target_block_id);
    }

    void LoopDecCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();

        // dec VM_CX, if non-zero ip += rel32.
        const std::uint8_t cx_slot = vm.slot_of_xreg(XReg::CX);
        e.mov_reg_mem(
            rx::rax, 
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().regs_base + cx_slot * 8),
            true
        );
        e.dec_reg(rx::rax, true);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().regs_base + cx_slot * 8),
            rx::rax,
            true
        );
        emit_fetch_u32_dec(e, vm, r.scratch_a);
        e.test_reg_reg(rx::rax, rx::rax);
        auto lbl_skip = e.new_label();
        e.jcc_label(cc::z, lbl_skip);
        e.movsxd_r64_r32(r.scratch_a, r.scratch_a);
        e.add_reg_reg(r.ip, r.scratch_a);
        e.bind(lbl_skip);
        emit_cipher_reset(e, vm);
        emit_dispatch_tail(e, vm);
    }

    void CdqeCodec::encode(BytecodeBuilder& out, const IRInsn&, const VMConfig& vm) const { out.u8(vm.opcode_for(family())); }
    void CdqeCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        const std::uint8_t s = vm.slot_of_xreg(XReg::AX);
        e.mov_reg_mem(
            rx::rax, 
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().regs_base + s * 8), 
            true
        );
        e.movsxd_r64_r32(rx::rax, rx::rax);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().regs_base + s * 8), 
            rx::rax, 
            true
        );
        emit_dispatch_tail(e, vm);
    }

    void LodsbCodec::encode(BytecodeBuilder& out, const IRInsn&, const VMConfig& vm) const { out.u8(vm.opcode_for(family())); }
    void LodsbCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        const std::uint8_t si = vm.slot_of_xreg(XReg::SI);
        const std::uint8_t ax = vm.slot_of_xreg(XReg::AX);

        // tmp = byte at [VM_SI]
        e.mov_reg_mem(
            rx::rcx, 
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().regs_base + si * 8),
            true
        );
        e.mov_reg_mem_size(
            rx::rax,
            rx::rcx,
            0,
            1,
            false
        );

        // VM_AX low 8 = al, preserve upper.
        e.mov_reg_mem(
            rx::rdx, 
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().regs_base + ax * 8), 
            true
        );
        e.and_reg_imm32(rx::rdx, -256 /*0xFFFFFFFFFFFFFF00*/);
        e.or_reg_reg(rx::rdx, rx::rax);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().regs_base + ax * 8),
            rx::rdx, 
            true
        );

        // VM_SI += 1. assumes DF=0.
        e.inc_reg(rx::rcx, true);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().regs_base + si * 8),
            rx::rcx,
            true
        );
        emit_dispatch_tail(e, vm);
    }

    void StosbCodec::encode(BytecodeBuilder& out, const IRInsn&, const VMConfig& vm) const { out.u8(vm.opcode_for(family())); }
    void StosbCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        const std::uint8_t di = vm.slot_of_xreg(XReg::DI);
        const std::uint8_t ax = vm.slot_of_xreg(XReg::AX);
        e.mov_reg_mem(
            rx::rcx, 
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().regs_base + di * 8), 
            true
        );
        e.mov_reg_mem(
            rx::rax,
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().regs_base + ax * 8), 
            true
        );
        e.mov_mem_reg_size(
            rx::rcx,
            0,
            rx::rax,
            1
        );
        e.inc_reg(rx::rcx, true);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().regs_base + di * 8),
            rx::rcx,
            true
        );
        emit_dispatch_tail(e, vm);
    }

    void CmpsbCodec::encode(BytecodeBuilder& out, const IRInsn&, const VMConfig& vm) const { out.u8(vm.opcode_for(family())); }
    void CmpsbCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        const std::uint8_t si = vm.slot_of_xreg(XReg::SI);
        const std::uint8_t di = vm.slot_of_xreg(XReg::DI);

        // load byte [rsi] / byte [rdi]
        e.mov_reg_mem(
            rx::rcx, 
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().regs_base + si * 8),
            true
        );
        e.mov_reg_mem(
            rx::rdx,
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().regs_base + di * 8),
            true
        );
        e.mov_reg_mem_size(
            rx::rax,
            rx::rcx,
            0,
            1,
            false
        );
        e.mov_reg_mem_size(
            r.scratch_a,
            rx::rdx,
            0,
            1,
            false
        );

        // sub flags.
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_a),
            rx::rax,
            true
        );
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_b),
            r.scratch_a,
            true
        );
        e.sub_reg_reg(rx::rax, r.scratch_a);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_result),
            rx::rax,
            true
        );
        e.mov_reg_imm32(r.scratch_b, static_cast<std::int32_t>(FlagsOp::SUB));
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_op),
            r.scratch_b,
            true
        );
        e.mov_reg_imm32(r.scratch_b, 1);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_width),
            r.scratch_b,
            true
        );

        // rsi++, rdi++. assumes DF=0.
        e.inc_reg(rx::rcx, true);
        e.inc_reg(rx::rdx, true);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().regs_base + si * 8),
            rx::rcx,
            true
        );
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().regs_base + di * 8),
            rx::rdx,
            true
        );
        emit_dispatch_tail(e, vm);
    }

    void ScasbCodec::encode(BytecodeBuilder& out, const IRInsn&, const VMConfig& vm) const { out.u8(vm.opcode_for(family())); }
    void ScasbCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        const std::uint8_t di = vm.slot_of_xreg(XReg::DI);
        const std::uint8_t ax = vm.slot_of_xreg(XReg::AX);
        e.mov_reg_mem(
            rx::rdx,
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().regs_base + di * 8),
            true
        );
        e.mov_reg_mem_size(
            r.scratch_a,
            rx::rdx,
            0,
            1,
            false
        );
        e.mov_reg_mem(
            rx::rax,
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().regs_base + ax * 8),
            true
        );
        e.and_reg_imm32(rx::rax, 0xFF);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_a),
            rx::rax,
            true
        );
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_b),
            r.scratch_a,
            true
        );
        e.sub_reg_reg(rx::rax, r.scratch_a);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_result),
            rx::rax,
            true
        );
        e.mov_reg_imm32(r.scratch_b, static_cast<std::int32_t>(FlagsOp::SUB));
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_op),
            r.scratch_b,
            true
        );
        e.mov_reg_imm32(r.scratch_b, 1);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().flags_width),
            r.scratch_b,
            true
        );
        e.inc_reg(rx::rdx, true);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().regs_base + di * 8),
            rx::rdx,
            true
        );
        emit_dispatch_tail(e, vm);
    }

    void MovsbCodec::encode(BytecodeBuilder& out, const IRInsn&, const VMConfig& vm) const { out.u8(vm.opcode_for(family())); }
    void MovsbCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        const std::uint8_t si = vm.slot_of_xreg(XReg::SI);
        const std::uint8_t di = vm.slot_of_xreg(XReg::DI);
        e.mov_reg_mem(
            rx::rcx,
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().regs_base + si * 8),
            true
        );
        e.mov_reg_mem(
            rx::rdx,
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().regs_base + di * 8),
            true
        );
        e.mov_reg_mem_size(
            rx::rax,
            rx::rcx,
            0,
            1,
            false
        );
        e.mov_mem_reg_size(
            rx::rdx,
            0,
            rx::rax,
            1
        );
        e.inc_reg(rx::rcx, true);
        e.inc_reg(rx::rdx, true);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().regs_base + si * 8),
            rx::rcx,
            true
        );
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().regs_base + di * 8),
            rx::rdx,
            true
        );
        emit_dispatch_tail(e, vm);
    }

    void DfCodec::encode(BytecodeBuilder& out, const IRInsn&, const VMConfig& vm) const { out.u8(vm.opcode_for(family())); }
    void DfCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const { emit_dispatch_tail(e, vm); }

    void ImulCodec::encode(BytecodeBuilder& out, const IRInsn& i, const VMConfig& vm) const {
        out.u8(vm.opcode_for(family()));
        (void)i; // not doing it
    }

    void ImulCodec::emit_handler(X64Emitter& e, const VMConfig& vm) const { emit_dispatch_tail(e, vm); }

    // CodecRegistry stuff
    CodecRegistry::CodecRegistry(VMConfig& vm, SeedRng& rng) {
        auto add = [&](std::unique_ptr<Codec> c) {
            const std::string fam{c->family()};
            by_family_[fam] = c.get();
            owners_.push_back(std::move(c));
        };

        add(std::make_unique<ImmCodec>());
        add(std::make_unique<MovCodec>());
        add(std::make_unique<LoadCodec>());
        add(std::make_unique<StoreCodec>());
        add(std::make_unique<LeaCodec>());
        add(std::make_unique<ReadSegCodec>());
        add(std::make_unique<AddCodec>());
        add(std::make_unique<SubCodec>());
        add(std::make_unique<AndCodec>());
        add(std::make_unique<OrCodec>());
        add(std::make_unique<XorCodec>());
        add(std::make_unique<NotCodec>());
        add(std::make_unique<NegCodec>());
        add(std::make_unique<IncCodec>());
        add(std::make_unique<DecCodec>());
        add(std::make_unique<ShlCodec>());
        add(std::make_unique<ShrCodec>());
        add(std::make_unique<SarCodec>());
        add(std::make_unique<RolCodec>());
        add(std::make_unique<RorCodec>());
        add(std::make_unique<CmpCodec>());
        add(std::make_unique<TestCodec>());
        add(std::make_unique<BrCodec>());
        add(std::make_unique<BrCcCodec>());
        add(std::make_unique<CallVmCodec>());
        add(std::make_unique<RetVmCodec>());
        add(std::make_unique<CallNativeCodec>());
        add(std::make_unique<JmpNativeCodec>());
        add(std::make_unique<PushCodec>());
        add(std::make_unique<PopCodec>());
        add(std::make_unique<XchgCodec>());
        add(std::make_unique<ZextCodec>());
        add(std::make_unique<SextCodec>());
        add(std::make_unique<SetccCodec>());
        add(std::make_unique<BswapCodec>());
        add(std::make_unique<NopCodec>());
        add(std::make_unique<ExitCodec>());
        add(std::make_unique<LoopDecCodec>());
        add(std::make_unique<CdqeCodec>());
        add(std::make_unique<LodsbCodec>());
        add(std::make_unique<StosbCodec>());
        add(std::make_unique<MovsbCodec>());
        add(std::make_unique<CmpsbCodec>());
        add(std::make_unique<ScasbCodec>());
        add(std::make_unique<DfCodec>());
        add(std::make_unique<ImulCodec>());
        add(std::make_unique<BrIndCodec>());
        add(std::make_unique<RetNativeCodec>());

        // pick opcode bytes via random permutation over 0..255.
        std::vector<std::uint8_t> opcodes;
        opcodes.reserve(owners_.size());
        for (std::size_t i = 0; i < owners_.size(); ++i) opcodes.push_back(static_cast<std::uint8_t>(i));

        std::vector<std::uint8_t> pool(256);
        for (std::size_t i = 0; i < 256; ++i) pool[i] = static_cast<std::uint8_t>(i);
        shuffle_in_place(pool, rng);

        order_.resize(256, nullptr);
        for (std::size_t i = 0; i < owners_.size(); ++i) {
            const std::uint8_t b = pool[i];
            vm.assign_opcode(owners_[i]->family(), b);
            order_[b] = owners_[i].get();
        }
    }

    const Codec* CodecRegistry::by_family(std::string_view fam) const {
        auto it = by_family_.find(std::string(fam));
        return it == by_family_.end() ? nullptr : it->second;
    }

    const Codec* CodecRegistry::by_opcode(std::uint8_t b) const {
        return (b < order_.size()) ? order_[b] : nullptr;
    }

    // pick codec family for an IR op.
    std::string codec_family_for(IROp op) {
        switch (op) {
            case IROp::IMM:                                                   return "IMM";
            case IROp::MOV:                                                   return "MOV";
            case IROp::LOAD:                                                  return "LOAD";
            case IROp::STORE:                                                 return "STORE";
            case IROp::LEA:                                                   return "LEA";
            case IROp::ADD: case IROp::ADC:                                   return "ADD";
            case IROp::SUB: case IROp::SBB:                                   return "SUB";
            case IROp::AND:                                                   return "AND";
            case IROp::OR:                                                    return "OR";
            case IROp::XOR:                                                   return "XOR";
            case IROp::NOT:                                                   return "NOT";
            case IROp::NEG:                                                   return "NEG";
            case IROp::INC:                                                   return "INC";
            case IROp::DEC:                                                   return "DEC";
            case IROp::SHL:                                                   return "SHL";
            case IROp::SHR:                                                   return "SHR";
            case IROp::SAR:                                                   return "SAR";
            case IROp::ROL:                                                   return "ROL";
            case IROp::ROR: case IROp::RCL: case IROp::RCR:                   return "ROR";
            case IROp::CMP:                                                   return "CMP";
            case IROp::TEST:                                                  return "TEST";
            case IROp::BR:                                                    return "BR";
            case IROp::BR_CC:                                                 return "BRCC";
            case IROp::BR_IND:                                                return "BRIND";
            case IROp::CALL_VM:                                               return "CALLVM";
            case IROp::RET_VM:                                                return "RETVM";
            case IROp::CALL_NATIVE:                                           return "CALLNATIVE";
            case IROp::JMP_NATIVE:                                            return "JMPNATIVE";
            case IROp::RET_NATIVE:                                            return "RETNATIVE";
            case IROp::PUSH:                                                  return "PUSH";
            case IROp::POP:                                                   return "POP";
            case IROp::XCHG:                                                  return "XCHG";
            case IROp::ZEXT:                                                  return "ZEXT";
            case IROp::SEXT:                                                  return "SEXT";
            case IROp::SETCC:                                                 return "SETCC";
            case IROp::BSWAP:                                                 return "BSWAP";
            case IROp::NOP:                                                   return "NOP";
            case IROp::EXIT:                                                  return "EXIT";
            case IROp::LOOP_DEC:                                              return "LOOP";
            case IROp::CDQE:                                                  return "CDQE";
            case IROp::LODSB:                                                 return "LODSB";
            case IROp::STOSB:                                                 return "STOSB";
            case IROp::MOVSB:                                                 return "MOVSB";
            case IROp::CMPSB:                                                 return "CMPSB";
            case IROp::SCASB:                                                 return "SCASB";
            case IROp::REP_PREFIX:                                            return "NOP";
            case IROp::CLD: case IROp::STD:                                   return "DF";
            case IROp::IMUL: case IROp::MUL: case IROp::IDIV: case IROp::DIV: return "IMUL";
            case IROp::READ_SEG:                                              return "READ_SEG";
        }
        return "NOP";
    }
}