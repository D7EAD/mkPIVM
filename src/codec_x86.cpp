#include "mkpivm/codec.h"
#include "mkpivm/x86_emit.h"

namespace mkpivm {
    namespace {
        constexpr std::int32_t kCipherAddOff    = 0;
        constexpr std::int32_t kCipherMultOff   = 8;
        constexpr std::int32_t kSavedIpOff      = 16;
        constexpr std::int32_t kSavedHbOff      = 24;
        constexpr std::int32_t kSavedCsOff      = 32;
        constexpr std::int32_t kSavedTargetOff  = 40;
        constexpr std::int32_t kCipherInitOff   = 48;
        constexpr std::int32_t kPreDecryptIpOff = 88;
        constexpr std::int32_t kPreDecryptCsOff = 96;
        constexpr std::int32_t kSboxInvOff      = 256;

        // local copy of vm_codegen_x86.cpp's x86_self_locate 
        static void x86_self_locate(X86Emitter& e, std::uint8_t dst,
                                    FixupKind kind, std::uint64_t data = 0) {
            e.call_rel32(0);
            e.pop_reg(dst);
            e.u8(0x81);
            e.emit_modrm(3, 0, dst & 7);
            const std::size_t patch = e.size();
            e.u32(0);
            e.add_fixup(
                patch,
                static_cast<std::uint32_t>(kind),
                data,
                /*addend=*/7
            );
        }
    }

    // pick the volatile of eax/ecx/edx that is neither scratch_a nor
    // scratch_b 
    static std::uint8_t third_volatile(const DispatcherRegs& r) {
        for (auto v : {rx::rax, rx::rcx, rx::rdx}) {
            if (v != r.scratch_a && v != r.scratch_b) return v;
        }
        throw Error("third_volatile: dispatcher exhausted volatile pool");
    }

    // inline byte fetch + cipher decrypt for 32-bit 
    void emit_fetch_byte_dec(X86Emitter& e, const VMConfig& vm, std::uint8_t dst) {
        const auto& r = vm.dispatcher_regs();
        const std::int32_t add_off  = static_cast<std::int32_t>(vm.state_layout().cipher_extra) + kCipherAddOff;
        const std::int32_t mult_off = static_cast<std::int32_t>(vm.state_layout().cipher_extra) + kCipherMultOff;
        const std::int32_t sbox_off = static_cast<std::int32_t>(vm.state_layout().cipher_extra) + kSboxInvOff;

        // movzx dst, byte [ip]
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

        // 32-bit helpers: add r32, [state_ptr+disp32] and imul r32, [state_ptr+disp32].
        auto add_cs_mem = [&](std::int32_t disp) {
            e.u8(0x03); // ADD r32, r/m32
            e.emit_modrm_mem(
                r.cipher_state & 7,
                r.state_ptr,
                rx::none,
                0,
                disp
            );
        };

        auto imul_cs_mem = [&](std::int32_t disp) {
            e.u8(0x0F); e.u8(0xAF); // IMUL r32, r/m32
            e.emit_modrm_mem(
                r.cipher_state & 7,
                r.state_ptr,
                rx::none,
                0,
                disp
            );
        };

        // 8-bit op between dst low and cipher_state low which is bl 
        auto xor8_dst_csLow = [&]() {
            e.u8(0x30); // XOR r/m8, r8
            e.emit_modrm(3, r.cipher_state & 7, dst & 7);
        };

        auto sub8_dst_csLow = [&]() {
            e.u8(0x28); // SUB r/m8, r8
            e.emit_modrm(3, r.cipher_state & 7, dst & 7);
        };

        switch (vm.cipher_kind()) {
            case CipherKind::ARX: {
                add_cs_mem(add_off);
                e.rol_reg_imm8(r.cipher_state, 13, true);
                xor8_dst_csLow();
                e.movzx_r32_r8(dst, dst);
                break;
            }
            case CipherKind::LcgSub: {
                imul_cs_mem(mult_off);
                add_cs_mem(add_off);
                sub8_dst_csLow();
                e.movzx_r32_r8(dst, dst);
                break;
            }
            case CipherKind::SBoxAdd: {
                sub8_dst_csLow();
                e.movzx_r32_r8(dst, dst);

                // movzx dst, byte [state_ptr + dst + sbox_off]
                e.u8(0x0F); e.u8(0xB6);
                e.emit_modrm(2, dst & 7, 4); // SIB follows, disp32 modrm
                e.emit_sib(0, dst & 7, r.state_ptr & 7);
                e.u32(static_cast<std::uint32_t>(sbox_off));
                imul_cs_mem(mult_off);
                add_cs_mem(add_off);
                break;
            }
            case CipherKind::FeistelByte: {
                xor8_dst_csLow();
                e.movzx_r32_r8(dst, dst);
                imul_cs_mem(mult_off);
                add_cs_mem(add_off);
                break;
            }
        }
    }

    void emit_fetch_uN_dec(X86Emitter& e, const VMConfig& vm, std::uint8_t dst, std::uint8_t n) {
        // accumulate N little-endian bytes into dst 
        const auto& r = vm.dispatcher_regs();
        const std::uint8_t inner = (dst == r.scratch_b) ? r.scratch_a : r.scratch_b;
        e.push_reg(inner);
        e.xor_reg_reg(dst, dst, true);
        if (n > 0) {
            emit_fetch_byte_dec(e, vm, dst);
            for (std::uint8_t i = 1; i < n; ++i) {
                emit_fetch_byte_dec(e, vm, inner);
                e.shl_reg_imm8(inner, static_cast<std::uint8_t>(8 * i), true);
                e.or_reg_reg(dst, inner, true);
            }
        }
        e.pop_reg(inner);
    }

    void emit_fetch_u32_dec(X86Emitter& e, const VMConfig& vm, std::uint8_t dst) {
        emit_fetch_uN_dec(
            e,
            vm,
            dst,
            4
        );
    }

    // dispatcher tail for 32-bit 
    void emit_dispatch_tail(X86Emitter& e, const VMConfig& vm) {
        const auto& r = vm.dispatcher_regs();
        const auto& st = vm.state_layout();
        constexpr std::int32_t kRuntimeNonceOff = 80;
        emit_fetch_byte_dec(e, vm, r.scratch_a);

        // mov scratch_b, dword [handler_base + scratch_a*4]
        e.u8(0x8B);
        e.emit_modrm(2, r.scratch_b & 7, 4); // SIB follows, disp32
        e.emit_sib(2, r.scratch_a & 7, r.handler_base & 7);
        e.u32(0); // disp32 = 0

        // xor with runtime nonce to undo the per-process xor layer
        // emit_state_init applied to the in-memory handler table.
        e.u8(0x33);
        e.emit_modrm_mem(
            r.scratch_b & 7,
            r.state_ptr,
            rx::none,
            0,
            static_cast<std::int32_t>(st.cipher_extra) + kRuntimeNonceOff
        );

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

    // reload cipher_state from VMState at cipher_extra+48 
    static inline void x86_cipher_reset(X86Emitter& e, const VMConfig& vm) {
        const auto& r = vm.dispatcher_regs();
        const std::int32_t init_off = static_cast<std::int32_t>(vm.state_layout().cipher_extra) + kCipherInitOff;
        e.mov_reg_mem(
            r.cipher_state,
            r.state_ptr,
            init_off,
            true
        );
    }

    // forward decls 
    static void emit_x86_mem_addr(X86Emitter& e, const VMConfig& vm, std::uint8_t out_reg);
    static void emit_unary_arith_x86(X86Emitter& e, const VMConfig& vm, FlagsOp fkind, void (X86Emitter::*op_reg)(std::uint8_t, bool));

    // mask reg to width_reg's width using low 7 bits, for imm and non-reg
    // operands 
    static void emit_mask_to_width_x86(X86Emitter& e, const VMConfig&, std::uint8_t reg, std::uint8_t width_reg) {
        auto lbl_w4 = e.new_label(), lbl_w2 = e.new_label(), lbl_done = e.new_label();

        e.push_reg(width_reg);
        e.and_reg_imm32(width_reg, 0x7F, true);
        e.cmp_reg_imm32(width_reg, 4, true);
        e.pop_reg(width_reg);
        e.jcc_label(cc::z, lbl_w4);
        e.push_reg(width_reg);
        e.and_reg_imm32(width_reg, 0x7F, true);
        e.cmp_reg_imm32(width_reg, 2, true);
        e.pop_reg(width_reg);
        e.jcc_label(cc::z, lbl_w2);

        e.and_reg_imm32(reg, 0xFF, true);
        e.jmp_label(lbl_done);
        e.bind(lbl_w2);
        e.and_reg_imm32(reg, 0xFFFF, true);
        e.jmp_label(lbl_done);
        e.bind(lbl_w4);

        // width 4, or 8 which we treat as 4 on x86. already 32-bit, no-op.
        e.bind(lbl_done);
    }

    // extract a register-operand value, honoring the high-byte flag in bit 7
    // of width_reg. high-byte case ah/ch/dh/bh shifts right 8 first.
    static void emit_extract_operand_x86(X86Emitter& e, const VMConfig& vm, std::uint8_t reg, std::uint8_t width_reg) {
        auto lbl_no_hi = e.new_label();

        e.push_reg(width_reg);
        e.and_reg_imm32(width_reg, 0x80, true);
        e.cmp_reg_imm32(width_reg, 0, true);
        e.pop_reg(width_reg);
        e.jcc_label(cc::z, lbl_no_hi);
        e.shr_reg_imm8(reg, 8, true);
        e.bind(lbl_no_hi);
        emit_mask_to_width_x86(
            e,
            vm,
            reg,
            width_reg
        );
    }

    // store value_reg into VMState slot at slot_idx_reg, honoring width 
    static void emit_store_slot_value_x86(X86Emitter& e, const VMConfig& vm,
                                          std::uint8_t slot_idx_reg,
                                          std::uint8_t value_reg,
                                          std::uint8_t width_reg) {
        const auto& r = vm.dispatcher_regs();
        const auto regs_base = static_cast<std::int32_t>(vm.state_layout().regs_base);

        auto lbl_hi   = e.new_label();
        auto lbl_done = e.new_label();
        auto lbl_w4   = e.new_label();
        auto lbl_w2   = e.new_label();

        // test bit 7 of width_reg, the high-byte flag 
        e.push_reg(width_reg);
        e.and_reg_imm32(width_reg, 0x80, true);
        e.cmp_reg_imm32(width_reg, 0, true);
        e.pop_reg(width_reg);
        e.jcc_label(cc::nz, lbl_hi);

        // non-high-byte path: dispatch on low 7 width bits.
        e.push_reg(width_reg);
        e.and_reg_imm32(width_reg, 0x7F, true);
        e.cmp_reg_imm32(width_reg, 4, true);
        e.pop_reg(width_reg);
        e.jcc_label(cc::z, lbl_w4);
        e.push_reg(width_reg);
        e.and_reg_imm32(width_reg, 0x7F, true);
        e.cmp_reg_imm32(width_reg, 2, true);
        e.pop_reg(width_reg);
        e.jcc_label(cc::z, lbl_w2);

        // width 1, no high-byte: mov byte [state_ptr + slot*8 + 0], value.low8
        e.u8(0x88);
        e.emit_modrm(2, value_reg & 7, 4);     // mod=10, reg=value, rm=4 SIB
        e.emit_sib(3, slot_idx_reg & 7, r.state_ptr & 7);
        e.u32(static_cast<std::uint32_t>(regs_base + 0));
        e.jmp_label(lbl_done);

        e.bind(lbl_w2);
        
        // width 2: 0x66 prefix, mov word, value.low16
        e.u8(0x66);
        e.u8(0x89);
        e.emit_modrm(2, value_reg & 7, 4);
        e.emit_sib(3, slot_idx_reg & 7, r.state_ptr & 7);
        e.u32(static_cast<std::uint32_t>(regs_base + 0));
        e.jmp_label(lbl_done);

        e.bind(lbl_w4);

        // width 4: dword store + zero upper 4.
        e.u8(0x89);
        e.emit_modrm(2, value_reg & 7, 4);
        e.emit_sib(3, slot_idx_reg & 7, r.state_ptr & 7);
        e.u32(static_cast<std::uint32_t>(regs_base + 0));

        // mov dword [state_ptr + slot*8 + 4], 0 -> C7 /0 mod10 sib disp32 imm32
        e.u8(0xC7);
        e.emit_modrm(2, 0, 4);
        e.emit_sib(3, slot_idx_reg & 7, r.state_ptr & 7);
        e.u32(static_cast<std::uint32_t>(regs_base + 4));
        e.u32(0);
        e.jmp_label(lbl_done);

        e.bind(lbl_hi);

        // high-byte: byte store at slot offset +1.
        e.u8(0x88);
        e.emit_modrm(2, value_reg & 7, 4);
        e.emit_sib(3, slot_idx_reg & 7, r.state_ptr & 7);
        e.u32(static_cast<std::uint32_t>(regs_base + 1));

        e.bind(lbl_done);
    }

    // polymorphic NOP filler.
    void emit_junk(X86Emitter& e, const VMConfig& vm, SeedRng& rng) {
        const std::uint8_t density = vm.junk_density();
        const std::uint32_t n = 1u + (density ? rng.pick(2u + density) : 0u);
        for (std::uint32_t i = 0; i < n; ++i) {
            e.poly_nop(rng);
        }
    }

    // stub used to fall back any unimplemented x86 codec to jmp VMExit so
    // the dispatcher exits cleanly 
    #define X86_STUB(Name)                                                              \
        void Name##Codec::emit_handler(X86Emitter& e, const VMConfig& /*v*/) const {    \
            e.u8(0xE9);                                                                 \
            e.emit_rel32_fixup(static_cast<std::uint32_t>(FixupKind::VMExit), 0, 0);    \
        }

    #undef X86_STUB

    // NOP
    void NopCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        emit_dispatch_tail(e, vm);
    }

    // EXIT: jmp to VMExit. packager resolves the rel32.
    void ExitCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        (void)vm;
        e.u8(0xE9);
        e.emit_rel32_fixup(static_cast<std::uint32_t>(FixupKind::VMExit), 0, 0);
    }

    // ALU bin handler 
    enum class X86BinOp { ADD, SUB, ANDV, ORV, XORV };

    static void emit_bin_handler_x86(X86Emitter& e, const VMConfig& vm, X86BinOp op, FlagsOp fkind) {
        const auto& r = vm.dispatcher_regs();
        const auto regs_base = static_cast<std::int32_t>(vm.state_layout().regs_base);
        const auto& st = vm.state_layout();
        const std::uint8_t valreg = third_volatile(r);

        emit_fetch_byte_dec(e, vm, r.scratch_a); // dst slot
        emit_fetch_byte_dec(e, vm, r.scratch_b); // dst width
        e.push_reg(r.scratch_a);                 // save dst slot for storeback
        e.push_reg(r.scratch_b);                 // save dst width

        // load dst slot into valreg, extract per width + high-byte flag.
        e.mov_reg_mem_sib(
            valreg,
            r.state_ptr,
            r.scratch_a,
            3,
            regs_base,
            true
        );
        
        emit_extract_operand_x86(
            e,
            vm,
            valreg,
            r.scratch_b
        );

        emit_fetch_byte_dec(e, vm, r.scratch_a); // tag
        auto lbl_imm = e.new_label();
        auto lbl_mem = e.new_label();
        auto lbl_have_op1 = e.new_label();
        e.cmp_reg_imm32(r.scratch_a, 1, true);
        e.jcc_label(cc::z, lbl_imm);
        e.cmp_reg_imm32(r.scratch_a, 2, true);
        e.jcc_label(cc::z, lbl_mem);

        // tag=0 reg: fetch op1 slot+width, SIB-load, extract.
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        e.mov_reg_mem_sib(
            r.scratch_a,
            r.state_ptr,
            r.scratch_a,
            3,
            regs_base,
            true
        );

        emit_extract_operand_x86(
            e,
            vm,
            r.scratch_a,
            r.scratch_b
        );
        e.jmp_label(lbl_have_op1);

        e.bind(lbl_imm);

        // tag=1 imm: fetch 8 bytes, x86 uses only low 32.
        emit_fetch_uN_dec(
            e,
            vm,
            r.scratch_a,
            4
        );
        emit_fetch_uN_dec(
            e,
            vm,
            r.scratch_b,
            4
        ); // discard high 32

        // mask imm to dst width. reload dst width from stack-saved copy.
        e.mov_reg_mem(
            r.scratch_b,
            rx::rsp,
            0,
            true
        );
        emit_mask_to_width_x86(
            e,
            vm,
            r.scratch_a,
            r.scratch_b
        );
        e.jmp_label(lbl_have_op1);

        e.bind(lbl_mem);

        // mem source. emit_x86_mem_addr clobbers valreg which currently holds
        // op0, so save it across the call.
        e.push_reg(valreg);
        emit_x86_mem_addr(e, vm, valreg);
        e.add_reg_imm32(rx::rsp, 8, true); // drop seg + width
        e.mov_reg_mem(
            r.scratch_a,
            valreg,
            0,
            true
        ); // op1 to scratch_a

        e.pop_reg(valreg); // restore dst
        e.mov_reg_mem(
            r.scratch_b,
            rx::rsp,
            0,
            true
        ); // peek dst width

        emit_mask_to_width_x86(
            e,
            vm,
            r.scratch_a,
            r.scratch_b
        );

        e.bind(lbl_have_op1);

        // valreg = extracted dst, scratch_a = extracted op1.
        // save flag context: A = dst, B = op1.
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_a),
            valreg,
            true
        );
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_b),
            r.scratch_a,
            true
        );

        // ALU op into valreg.
        switch (op) {
            case X86BinOp::ADD:  e.add_reg_reg(valreg, r.scratch_a, true); break;
            case X86BinOp::SUB:  e.sub_reg_reg(valreg, r.scratch_a, true); break;
            case X86BinOp::ANDV: e.and_reg_reg(valreg, r.scratch_a, true); break;
            case X86BinOp::ORV:  e.or_reg_reg (valreg, r.scratch_a, true); break;
            case X86BinOp::XORV: e.xor_reg_reg(valreg, r.scratch_a, true); break;
        }

        // restore dst width/slot.
        e.pop_reg(r.scratch_b);
        e.pop_reg(r.scratch_a);
        
        // mask result so flag_result reflects the right view.
        emit_mask_to_width_x86(
            e,
            vm,
            valreg,
            r.scratch_b
        );

        // save flag_result. valreg still holds the result for storeback.
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_result),
            valreg,
            true
        );

        // write flag_op. all 3 volatiles in use, so spill valreg via
        // flags_result and reload after.
        e.mov_reg_imm32(valreg, static_cast<std::int32_t>(fkind), true);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_op),
            valreg,
            true
        );
        e.mov_reg_mem(
            valreg,
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_result),
            true
        );
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_width),
            r.scratch_b,
            true
        );
        emit_store_slot_value_x86(
            e,
            vm,
            r.scratch_a,
            valreg,
            r.scratch_b
        );
        emit_dispatch_tail(e, vm);
    }

    void AddCodec::emit_handler(X86Emitter& e, const VMConfig& v) const {
        emit_bin_handler_x86(
            e,
            v,
            X86BinOp::ADD,
            FlagsOp::ADD
        );
    }

    void SubCodec::emit_handler(X86Emitter& e, const VMConfig& v) const {
        emit_bin_handler_x86(
            e,
            v,
            X86BinOp::SUB,
            FlagsOp::SUB
        );
    }

    void AndCodec::emit_handler(X86Emitter& e, const VMConfig& v) const {
        emit_bin_handler_x86(
            e,
            v,
            X86BinOp::ANDV,
            FlagsOp::LOGIC
        );
    }

    void OrCodec::emit_handler (X86Emitter& e, const VMConfig& v) const {
        emit_bin_handler_x86(
            e,
            v,
            X86BinOp::ORV,
            FlagsOp::LOGIC
        );
    }
    
    void XorCodec::emit_handler(X86Emitter& e, const VMConfig& v) const { 
        emit_bin_handler_x86(
            e,
            v,
            X86BinOp::XORV,
            FlagsOp::LOGIC
        );
    }

    // MOV reg, reg: copy slot[src] into slot[dst], honoring dst width.
    void MovCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        const auto regs_base = static_cast<std::int32_t>(vm.state_layout().regs_base);
        const std::uint8_t valreg = third_volatile(r);

        emit_fetch_byte_dec(e, vm, r.scratch_a); // dst slot
        emit_fetch_byte_dec(e, vm, r.scratch_b); // dst width
        e.push_reg(r.scratch_a);
        e.push_reg(r.scratch_b);
        emit_fetch_byte_dec(e, vm, r.scratch_a); // src slot
        emit_fetch_byte_dec(e, vm, r.scratch_b); // src width ignored. MOV writes raw, store helper handles width.
        e.mov_reg_mem_sib(
            valreg,
            r.state_ptr,
            r.scratch_a,
            3,
            regs_base,
            true
        );
        e.pop_reg(r.scratch_b); // restore dst width
        e.pop_reg(r.scratch_a); // restore dst slot
        emit_store_slot_value_x86(
            e,
            vm,
            r.scratch_a,
            valreg,
            r.scratch_b
        );
        emit_dispatch_tail(e, vm);
    }

    // effective-address helper 
    static void emit_x86_mem_addr(X86Emitter& e, const VMConfig& vm,
                                  std::uint8_t out_reg) {
        const auto& r = vm.dispatcher_regs();
        const auto regs_base = static_cast<std::int32_t>(vm.state_layout().regs_base);

        // fetch operand fields 
        emit_fetch_byte_dec(e, vm, r.scratch_a);  e.push_reg(r.scratch_a); // [esp]    = base
        emit_fetch_byte_dec(e, vm, r.scratch_a);  e.push_reg(r.scratch_a); // [esp+4]  = idx
        emit_fetch_byte_dec(e, vm, r.scratch_a);  e.push_reg(r.scratch_a); // [esp+8]  = scale
        emit_fetch_byte_dec(e, vm, r.scratch_a);  e.push_reg(r.scratch_a); // [esp+12] = seg
        emit_fetch_u32_dec(e, vm, r.scratch_a);   e.push_reg(r.scratch_a); // [esp+16] = disp32
        emit_fetch_byte_dec(e, vm, r.scratch_a);  e.push_reg(r.scratch_a); // [esp+20] = width

        // out_reg = disp32 first.
        e.mov_reg_mem(
            out_reg,
            rx::rsp,
            4,
            true
        ); // disp32, just above width

        // apply idx*scale if idx != 0xFF.
        e.mov_reg_mem(
            r.scratch_a,
            rx::rsp,
            16,
            true
        ); // idx slot id

        auto lbl_no_idx = e.new_label();
        e.cmp_reg_imm32(r.scratch_a, 0xFF, true);
        e.jcc_label(cc::z, lbl_no_idx);
        e.mov_reg_mem_sib(
            r.scratch_a,
            r.state_ptr,
            r.scratch_a,
            3,
            regs_base,
            true
        ); // load slot[idx]

        e.mov_reg_mem(
            r.scratch_b,
            rx::rsp,
            12,
            true
        ); // scale

        {
            auto lbl_s0 = e.new_label(), 
                 lbl_s1 = e.new_label(),
                 lbl_s2 = e.new_label(), 
                 lbl_send = e.new_label();

            e.cmp_reg_imm32(r.scratch_b, 0, true); e.jcc_label(cc::z, lbl_s0);
            e.cmp_reg_imm32(r.scratch_b, 1, true); e.jcc_label(cc::z, lbl_s1);
            e.cmp_reg_imm32(r.scratch_b, 2, true); e.jcc_label(cc::z, lbl_s2);
            e.shl_reg_imm8(r.scratch_a, 3, true); e.jmp_label(lbl_send);
            e.bind(lbl_s2); e.shl_reg_imm8(r.scratch_a, 2, true); e.jmp_label(lbl_send);
            e.bind(lbl_s1); e.shl_reg_imm8(r.scratch_a, 1, true); e.jmp_label(lbl_send);
            e.bind(lbl_s0);
            e.bind(lbl_send);
        }
        e.add_reg_reg(out_reg, r.scratch_a, true);
        e.bind(lbl_no_idx);

        // apply base if != 0xFF.
        e.mov_reg_mem(
            r.scratch_a,
            rx::rsp,
            20,
            true
        ); // base slot id

        auto lbl_no_base = e.new_label();
        e.cmp_reg_imm32(r.scratch_a, 0xFF, true);
        e.jcc_label(cc::z, lbl_no_base);
        e.mov_reg_mem_sib(
            r.scratch_a,
            r.state_ptr,
            r.scratch_a,
            3,
            regs_base,
            true
        );
        e.add_reg_reg(out_reg, r.scratch_a, true);
        e.bind(lbl_no_base);

        // drop width/disp/scale/idx/base, keep only seg + width on stack 
        e.pop_reg(r.scratch_a); // width into scratch_a
        e.pop_reg(r.scratch_b); // disp, discard
        
        // top is seg, scale, idx, base. pull seg out, drop the rest.
        e.pop_reg(r.scratch_b); // seg
        e.add_reg_imm32(rx::rsp, 12, true);

        // push so the caller sees [esp+0]=seg, [esp+4]=width.
        e.push_reg(r.scratch_a); // width
        e.push_reg(r.scratch_b); // seg
    }

    // NOT: bitwise not a slot value, no flag effects.
    // NEG: negate, via shared unary handler with FlagsOp::NEG.
    void NotCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        const auto regs_base = static_cast<std::int32_t>(vm.state_layout().regs_base);
        const std::uint8_t valreg = third_volatile(r);
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        e.push_reg(r.scratch_a);
        e.push_reg(r.scratch_b);
        e.mov_reg_mem_sib(
            valreg,
            r.state_ptr,
            r.scratch_a,
            3,
            regs_base,
            true
        );
        e.not_reg(valreg, true);
        e.pop_reg(r.scratch_b);
        e.pop_reg(r.scratch_a);
        emit_store_slot_value_x86(
            e,
            vm,
            r.scratch_a,
            valreg,
            r.scratch_b
        );
        emit_dispatch_tail(e, vm);
    }

    void NegCodec::emit_handler(X86Emitter& e, const VMConfig& v) const {
        emit_unary_arith_x86(
            e,
            v,
            FlagsOp::NEG,
            &X86Emitter::neg_reg
        );
    }

    // BSWAP a 32-bit reg.
    void BswapCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        const auto regs_base = static_cast<std::int32_t>(vm.state_layout().regs_base);
        const std::uint8_t valreg = third_volatile(r);
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        e.push_reg(r.scratch_a);
        e.push_reg(r.scratch_b);
        e.mov_reg_mem_sib(
            valreg,
            r.state_ptr,
            r.scratch_a,
            3,
            regs_base,
            true
        );
        e.bswap_reg(valreg, true);
        e.pop_reg(r.scratch_b);
        e.pop_reg(r.scratch_a);
        emit_store_slot_value_x86(
            e,
            vm,
            r.scratch_a,
            valreg,
            r.scratch_b
        );
        emit_dispatch_tail(e, vm);
    }

    // SETcc: write 0 or 1 to a slot based on a cond 
    void SetccCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        const auto& st = vm.state_layout();
        const std::uint8_t valreg = third_volatile(r);

        emit_fetch_byte_dec(e, vm, r.scratch_a); // dst slot
        emit_fetch_byte_dec(e, vm, r.scratch_b); // dst width = 1
        e.push_reg(r.scratch_a);
        e.push_reg(r.scratch_b);
        emit_fetch_byte_dec(e, vm, r.scratch_a); // cond

        // load flag_result/flag_a/flag_b into stack-spilled slots for the
        // setcc-derived byte computation 
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

        // need flag_b in another reg. use scratch_a after we dispatch on cond.
        auto lbl_done = e.new_label();

        // setcc into low byte of valreg, then movzx.
        auto setcc_to_valreg = [&](std::uint8_t cc_code) {
            e.u8(0x0F); e.u8(static_cast<std::uint8_t>(0x90 + cc_code));
            e.emit_modrm(3, 0, valreg & 7);
            e.movzx_r32_r8(valreg, valreg);
        };

        auto handle = [&](std::uint8_t want, auto&& fn) {
            auto lbl_n = e.new_label();
            e.cmp_reg_imm32(r.scratch_a, static_cast<std::int32_t>(want), true);
            e.jcc_label(cc::nz, lbl_n);
            fn();
            e.jmp_label(lbl_done);
            e.bind(lbl_n);
        };

        // Z / NZ test flag_result.
        handle(static_cast<std::uint8_t>(Cond::Z),  [&](){
            e.test_reg_reg(valreg, valreg, true);
            setcc_to_valreg(cc::z);
        });

        handle(static_cast<std::uint8_t>(Cond::NZ), [&](){
            e.test_reg_reg(valreg, valreg, true);
            setcc_to_valreg(cc::nz);
        });
        
        // S / NS test flag_result sign.
        handle(static_cast<std::uint8_t>(Cond::S),  [&](){
            e.test_reg_reg(valreg, valreg, true);
            setcc_to_valreg(cc::s);
        });
        
        handle(static_cast<std::uint8_t>(Cond::NS), [&](){
            e.test_reg_reg(valreg, valreg, true);
            setcc_to_valreg(cc::ns);
        });
        
        // B / NB / L / NL: cmp flag_a, flag_b.
        auto cmp_ab_and_set = [&](std::uint8_t cc_code) {
            e.mov_reg_mem(
                valreg,
                r.state_ptr,
                static_cast<std::int32_t>(st.flags_b),
                true
            );

            e.cmp_reg_reg(r.scratch_b, valreg, true);
            setcc_to_valreg(cc_code);
        };

        handle(static_cast<std::uint8_t>(Cond::B),  [&](){ cmp_ab_and_set(cc::b); });
        handle(static_cast<std::uint8_t>(Cond::NB), [&](){ cmp_ab_and_set(cc::nb); });
        handle(static_cast<std::uint8_t>(Cond::L),  [&](){ cmp_ab_and_set(cc::l); });
        handle(static_cast<std::uint8_t>(Cond::NL), [&](){ cmp_ab_and_set(cc::nl); });

        // unmatched cond: predicate = 0.
        e.xor_reg_reg(valreg, valreg, true);
        e.bind(lbl_done);

        e.pop_reg(r.scratch_b);
        e.pop_reg(r.scratch_a);
        emit_store_slot_value_x86(
            e,
            vm,
            r.scratch_a,
            valreg,
            r.scratch_b
        );
        emit_dispatch_tail(e, vm);
    }

    // CDQE: sign-extend EAX to RAX  
    void CdqeCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        emit_dispatch_tail(e, vm);
    }

    // READ_SEG: read N bytes from fs:[disp] or gs:[disp] into a slot
    void ReadSegCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        emit_dispatch_tail(e, vm);
    }

    // STOSB / SCASB / MOVSB: byte string ops on esi/edi. 
    void StosbCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        const auto regs_base = static_cast<std::int32_t>(vm.state_layout().regs_base);
        const std::uint8_t di_slot = vm.slot_of_xreg(XReg::DI);
        const std::uint8_t ax_slot = vm.slot_of_xreg(XReg::AX);

        // [VM_DI] = low byte of VM_AX, VM_DI += 1.
        e.mov_reg_mem(
            r.scratch_a,
            r.state_ptr,
            regs_base + di_slot * 8,
            true
        );
        e.mov_reg_mem(
            r.scratch_b,
            r.state_ptr,
            regs_base + ax_slot * 8,
            true
        );
        e.u8(0x88); // mov r/m8, r8: scratch_b low to [scratch_a]
        e.emit_modrm_mem(
            r.scratch_b & 7,
            r.scratch_a,
            rx::none,
            0,
            0
        );
        e.inc_reg(r.scratch_a, true);
        e.mov_mem_reg(
            r.state_ptr,
            regs_base + di_slot * 8,
            r.scratch_a,
            true
        );
        emit_dispatch_tail(e, vm);
    }

    void ScasbCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        const auto& st = vm.state_layout();
        const auto regs_base = static_cast<std::int32_t>(st.regs_base);
        const std::uint8_t di_slot = vm.slot_of_xreg(XReg::DI);
        const std::uint8_t ax_slot = vm.slot_of_xreg(XReg::AX);
        const std::uint8_t valreg = third_volatile(r);

        // result = AL - [DI]
        e.mov_reg_mem(
            r.scratch_a,
            r.state_ptr,
            regs_base + di_slot * 8,
            true
        );
        e.u8(0x0F); e.u8(0xB6);
        e.emit_modrm_mem(
            r.scratch_b & 7,
            r.scratch_a,
            rx::none,
            0,
            0
        ); // scratch_b = byte [DI]

        e.mov_reg_mem(
            valreg,
            r.state_ptr,
            regs_base + ax_slot * 8,
            true
        );
        e.and_reg_imm32(valreg, 0xFF, true);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_a),
            valreg,
            true
        );
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_b),
            r.scratch_b,
            true
        );
        e.sub_reg_reg(valreg, r.scratch_b, true);
        e.and_reg_imm32(valreg, 0xFF, true);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_result),
            valreg,
            true
        );
        e.mov_reg_imm32(valreg, static_cast<std::int32_t>(FlagsOp::SUB), true);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_op),
            valreg,
            true
        );
        e.mov_reg_imm32(valreg, 1, true);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_width),
            valreg,
            true
        );
        e.inc_reg(r.scratch_a, true);
        e.mov_mem_reg(
            r.state_ptr,
            regs_base + di_slot * 8,
            r.scratch_a,
            true
        );
        emit_dispatch_tail(e, vm);
    }

    void MovsbCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        const auto regs_base = static_cast<std::int32_t>(vm.state_layout().regs_base);
        const std::uint8_t si_slot = vm.slot_of_xreg(XReg::SI);
        const std::uint8_t di_slot = vm.slot_of_xreg(XReg::DI);

        // byte [VM_DI] ← byte [VM_SI]; both ++.
        e.mov_reg_mem(
            r.scratch_a,
            r.state_ptr,
            regs_base + si_slot * 8,
            true
        );
        e.u8(0x0F); e.u8(0xB6);
        e.emit_modrm_mem(
            r.scratch_b & 7,
            r.scratch_a,
            rx::none,
            0,
            0
        ); // scratch_b = byte [SI]

        e.inc_reg(r.scratch_a, true);
        e.mov_mem_reg(
            r.state_ptr,
            regs_base + si_slot * 8,
            r.scratch_a,
            true
        );
        e.mov_reg_mem(
            r.scratch_a,
            r.state_ptr,
            regs_base + di_slot * 8,
            true
        );
        e.u8(0x88);
        e.emit_modrm_mem(
            r.scratch_b & 7,
            r.scratch_a,
            rx::none,
            0,
            0
        );
        e.inc_reg(r.scratch_a, true);
        e.mov_mem_reg(
            r.state_ptr,
            regs_base + di_slot * 8,
            r.scratch_a,
            true
        );
        emit_dispatch_tail(e, vm);
    }

    // IMUL / MUL / DIV / IDIV. real impl is width-aware and dual-register
    // result, edx:eax for full-width. 
    void ImulCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        emit_dispatch_tail(e, vm);
    }

    // BR_IND: jmp via register. 
    void BrIndCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        emit_dispatch_tail(e, vm);
    }

    // LOAD reg, [mem]: load value from mem operand into a slot 
    void LoadCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        const std::uint8_t valreg = third_volatile(r);

        emit_fetch_byte_dec(e, vm, r.scratch_a); // dst slot
        emit_fetch_byte_dec(e, vm, r.scratch_b); // dst width
        e.push_reg(r.scratch_a);                 // dst slot
        e.push_reg(r.scratch_b);                 // dst width

        // compute addr into valreg. after this, stack from top
        // [esp+0]=seg, [esp+4]=mem_width, then dst_width, dst_slot.
        emit_x86_mem_addr(e, vm, valreg);

        // branch on seg 0 default, 1 fs, 2 gs. non-default needs a seg prefix
        // before the load.
        e.mov_reg_mem(
            r.scratch_a,
            rx::rsp,
            0,
            true
        ); // seg

        auto lbl_seg_fs = e.new_label();
        auto lbl_seg_gs = e.new_label();
        auto lbl_load_done = e.new_label();
        e.cmp_reg_imm32(r.scratch_a, 1, true);
        e.jcc_label(cc::z, lbl_seg_fs);
        e.cmp_reg_imm32(r.scratch_a, 2, true);
        e.jcc_label(cc::z, lbl_seg_gs);

        // default: mov valreg, [valreg]
        e.mov_reg_mem(
            valreg,
            valreg,
            0,
            true
        );
        e.jmp_label(lbl_load_done);
        e.bind(lbl_seg_fs);
        e.u8(0x64); // fs prefix

        e.mov_reg_mem(
            valreg,
            valreg,
            0,
            true
        );
        e.jmp_label(lbl_load_done);
        e.bind(lbl_seg_gs);
        e.u8(0x65); // gs prefix

        e.mov_reg_mem(
            valreg,
            valreg,
            0,
            true
        );
        e.bind(lbl_load_done);

        // drop seg + mem_width. emit_store_slot_value_x86 uses dst width.
        e.add_reg_imm32(rx::rsp, 8, true);
        e.pop_reg(r.scratch_b); // dst width
        e.pop_reg(r.scratch_a); // dst slot
        emit_store_slot_value_x86(
            e,
            vm,
            r.scratch_a,
            valreg,
            r.scratch_b
        );
        emit_dispatch_tail(e, vm);
    }

    // STORE [mem], reg or imm: write a slot's value or imm to memory.
    void StoreCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        const std::uint8_t valreg = third_volatile(r);

        // compute addr into valreg 
        emit_x86_mem_addr(e, vm, valreg);

        // tag: 0 reg, 1 imm
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        auto lbl_imm = e.new_label();
        auto lbl_store_done = e.new_label();
        e.cmp_reg_imm32(r.scratch_a, 1, true);
        e.jcc_label(cc::z, lbl_imm);

        // tag=0 reg: fetch src slot+width, load into scratch_a.
        emit_fetch_byte_dec(e, vm, r.scratch_a); // src slot
        emit_fetch_byte_dec(e, vm, r.scratch_b); // src width ignored, use mem width below
        e.mov_reg_mem_sib(
            r.scratch_a,
            r.state_ptr,
            r.scratch_a,
            3,
            static_cast<std::int32_t>(vm.state_layout().regs_base),
            true
        );
        e.jmp_label(lbl_store_done);
        e.bind(lbl_imm);

        // tag=1 imm: 1-byte width then 8-byte imm. truncate to 32-bit.
        emit_fetch_byte_dec(e, vm, r.scratch_b); // imm width, ignored
        emit_fetch_uN_dec(
            e,
            vm,
            r.scratch_a,
            4
        ); // low 32 to scratch_a

        emit_fetch_uN_dec(
            e,
            vm,
            r.scratch_b,
            4
        ); // discard high 32

        e.bind(lbl_store_done);

        // stack still has [seg, mem_width]. load mem_width, write b/w/d.
        e.mov_reg_mem(
            r.scratch_b,
            rx::rsp,
            4,
            true
        ); // mem_width

        auto lbl_w4 = e.new_label(), lbl_w2 = e.new_label(), lbl_end = e.new_label();
        e.cmp_reg_imm32(r.scratch_b, 4, true);
        e.jcc_label(cc::z, lbl_w4);
        e.cmp_reg_imm32(r.scratch_b, 2, true);
        e.jcc_label(cc::z, lbl_w2);

        // width 1: byte store. scratch_a must be 0..3 which volatiles are.
        e.u8(0x88);
        e.emit_modrm(0, r.scratch_a & 7, valreg & 7); // mov [valreg], scratch_a.low8
        e.jmp_label(lbl_end);
        e.bind(lbl_w2);
        e.u8(0x66); e.u8(0x89);
        e.emit_modrm(0, r.scratch_a & 7, valreg & 7);
        e.jmp_label(lbl_end);
        e.bind(lbl_w4);
        e.u8(0x89);
        e.emit_modrm(0, r.scratch_a & 7, valreg & 7);
        e.bind(lbl_end);

        // drop seg + mem_width.
        e.add_reg_imm32(rx::rsp, 8, true);
        emit_dispatch_tail(e, vm);
    }

    // INC / DEC reg: single-operand arith, sets flags but not CF.
    static void emit_unary_arith_x86(X86Emitter& e, const VMConfig& vm,
                                     FlagsOp fkind,
                                     void (X86Emitter::*op_reg)(std::uint8_t, bool)) {
        const auto& r = vm.dispatcher_regs();
        const auto regs_base = static_cast<std::int32_t>(vm.state_layout().regs_base);
        const auto& st = vm.state_layout();
        const std::uint8_t valreg = third_volatile(r);

        emit_fetch_byte_dec(e, vm, r.scratch_a); // slot
        emit_fetch_byte_dec(e, vm, r.scratch_b); // width
        e.push_reg(r.scratch_a);
        e.push_reg(r.scratch_b);
        e.mov_reg_mem_sib(
            valreg,
            r.state_ptr,
            r.scratch_a,
            3,
            regs_base,
            true
        );
        emit_extract_operand_x86(
            e,
            vm,
            valreg,
            r.scratch_b
        );

        // save flag_a = pre-op value.
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_a),
            valreg,
            true
        );

        // apply inc/dec.
        (e.*op_reg)(valreg, true);
        e.pop_reg(r.scratch_b);
        e.pop_reg(r.scratch_a);
        emit_mask_to_width_x86(
            e,
            vm,
            valreg,
            r.scratch_b
        );
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_result),
            valreg,
            true
        );

        // flag_op. spill valreg through flags_result.
        e.mov_reg_imm32(valreg, static_cast<std::int32_t>(fkind), true);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_op),
            valreg,
            true
        );
        e.mov_reg_mem(
            valreg,
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_result),
            true
        );
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_width),
            r.scratch_b,
            true
        );
        emit_store_slot_value_x86(
            e,
            vm,
            r.scratch_a,
            valreg,
            r.scratch_b
        );
        emit_dispatch_tail(e, vm);
    }

    void IncCodec::emit_handler(X86Emitter& e, const VMConfig& v) const {
        emit_unary_arith_x86(
            e,
            v,
            FlagsOp::INC,
            &X86Emitter::inc_reg
        );
    }

    void DecCodec::emit_handler(X86Emitter& e, const VMConfig& v) const {
        emit_unary_arith_x86(
            e,
            v,
            FlagsOp::DEC,
            &X86Emitter::dec_reg
        ); 
    }

    // BR: unconditional bytecode-relative branch 
    void BrCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        emit_fetch_u32_dec(e, vm, r.scratch_a);

        // already 32-bit, plain add.
        e.add_reg_reg(r.ip, r.scratch_a, true);
        x86_cipher_reset(e, vm);
        emit_dispatch_tail(e, vm);
    }

    // CMP / TEST: bin-shaped operand fetch, writes only flag state, no
    // slot writeback.
    static void emit_cmp_test_x86(X86Emitter& e, const VMConfig& vm, bool is_test) {
        const auto& r = vm.dispatcher_regs();
        const auto regs_base = static_cast<std::int32_t>(vm.state_layout().regs_base);
        const auto& st = vm.state_layout();
        const std::uint8_t valreg = third_volatile(r);

        // op0: tag 1B, reg path slot+width, imm path 8 bytes.
        emit_fetch_byte_dec(e, vm, r.scratch_a); // op0 tag
        auto lbl_op0_imm = e.new_label();
        auto lbl_op0_done = e.new_label();
        e.cmp_reg_imm32(r.scratch_a, 0, true);
        e.jcc_label(cc::nz, lbl_op0_imm);

        // op0 reg
        emit_fetch_byte_dec(e, vm, r.scratch_a); // slot
        emit_fetch_byte_dec(e, vm, r.scratch_b); // width
        e.mov_reg_mem_sib(
            valreg,
            r.state_ptr,
            r.scratch_a,
            3,
            regs_base,
            true
        );
        emit_extract_operand_x86(
            e,
            vm,
            valreg,
            r.scratch_b
        );
        e.jmp_label(lbl_op0_done);
        e.bind(lbl_op0_imm);
        emit_fetch_uN_dec(
            e,
            vm,
            valreg,
            4
        );
        emit_fetch_uN_dec(
            e,
            vm,
            r.scratch_a,
            4
        ); // discard high 32

        e.bind(lbl_op0_done);

        // save op0 on stack.
        e.push_reg(valreg);

        // op1: tag, reg/imm/mem.
        emit_fetch_byte_dec(e, vm, r.scratch_a); // op1 tag

        auto lbl_op1_imm = e.new_label();
        auto lbl_op1_mem = e.new_label();
        auto lbl_op1_done = e.new_label();
        e.cmp_reg_imm32(r.scratch_a, 1, true);
        e.jcc_label(cc::z, lbl_op1_imm);
        e.cmp_reg_imm32(r.scratch_a, 2, true);
        e.jcc_label(cc::z, lbl_op1_mem);

        // op1 reg
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        e.mov_reg_mem_sib(
            valreg,
            r.state_ptr,
            r.scratch_a,
            3,
            regs_base,
            true
        );
        emit_extract_operand_x86(
            e,
            vm,
            valreg,
            r.scratch_b
        );
        e.jmp_label(lbl_op1_done);
        e.bind(lbl_op1_imm);
        emit_fetch_uN_dec(
            e,
            vm,
            valreg,
            4
        );
        emit_fetch_uN_dec(
            e,
            vm,
            r.scratch_a,
            4
        );
        e.jmp_label(lbl_op1_done);
        e.bind(lbl_op1_mem);

        // compute ea, load 32 bits.
        emit_x86_mem_addr(e, vm, valreg);
        e.add_reg_imm32(rx::rsp, 8, true); // drop seg + width side-channel
        e.mov_reg_mem(
            valreg,
            valreg,
            0,
            true
        );
        e.bind(lbl_op1_done);

        // stack: [esp]=op0. pop into scratch_a.
        e.pop_reg(r.scratch_a); // op0 back into scratch_a

        // global width.
        emit_fetch_byte_dec(e, vm, r.scratch_b);

        // mask both operands.
        emit_mask_to_width_x86(
            e,
            vm,
            r.scratch_a,
            r.scratch_b
        );
        emit_mask_to_width_x86(
            e,
            vm,
            valreg,
            r.scratch_b
        );

        // save flags_a = op0, flags_b = op1.
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_a),
            r.scratch_a,
            true
        );
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_b),
            valreg,
            true
        );
        if (is_test) {
            e.and_reg_reg(r.scratch_a, valreg, true);
        }
        else {
            e.sub_reg_reg(r.scratch_a, valreg, true);
        }
        emit_mask_to_width_x86(
            e,
            vm,
            r.scratch_a,
            r.scratch_b
        );
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_result),
            r.scratch_a,
            true
        );

        // flag op + width.
        e.mov_reg_imm32(valreg, static_cast<std::int32_t>(is_test ? FlagsOp::LOGIC : FlagsOp::SUB), true);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_op),
            valreg,
            true
        );
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_width),
            r.scratch_b,
            true
        );
        emit_dispatch_tail(e, vm);
    }

    void CmpCodec::emit_handler(X86Emitter& e, const VMConfig& v) const { emit_cmp_test_x86(e, v, false); }
    void TestCodec::emit_handler(X86Emitter& e, const VMConfig& v) const { emit_cmp_test_x86(e, v, true);  }

    // LEA: compute ea, store in slot 
    void LeaCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        const auto regs_base = static_cast<std::int32_t>(vm.state_layout().regs_base);
        const std::uint8_t valreg = third_volatile(r);

        emit_fetch_byte_dec(e, vm, r.scratch_a); // dst slot
        emit_fetch_byte_dec(e, vm, r.scratch_b); // dst width
        e.push_reg(r.scratch_a);
        e.push_reg(r.scratch_b);
        emit_fetch_byte_dec(e, vm, r.scratch_a); // tag
        auto lbl_rip  = e.new_label();
        auto lbl_done = e.new_label();
        e.cmp_reg_imm32(r.scratch_a, 1, true);
        e.jcc_label(cc::z, lbl_rip);

        // normal mem operand.
        emit_x86_mem_addr(e, vm, valreg);
        e.add_reg_imm32(rx::rsp, 8, true); // drop seg + mem_width side-channel
        e.jmp_label(lbl_done);
        e.bind(lbl_rip);

        // data-island offset: fetch 4 bytes, valreg = data_island_base + off.
        emit_fetch_uN_dec(
            e,
            vm,
            r.scratch_a,
            4
        );
        e.mov_reg_mem(
            valreg,
            r.state_ptr,
            static_cast<std::int32_t>(vm.state_layout().data_island_base),
            true
        );
        e.add_reg_reg(valreg, r.scratch_a, true);
        e.bind(lbl_done);
        e.pop_reg(r.scratch_b);
        e.pop_reg(r.scratch_a);
        emit_store_slot_value_x86(
            e,
            vm,
            r.scratch_a,
            valreg,
            r.scratch_b
        );
        (void)regs_base;
        emit_dispatch_tail(e, vm);
    }

    // PUSH / POP on the VM shadow stack via the VM_SP slot.
    // PUSH: VM_RSP -= 4, [VM_RSP] = value. POP: value = [VM_RSP], VM_RSP += 4.
    void PushCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        const auto regs_base = static_cast<std::int32_t>(vm.state_layout().regs_base);
        const std::uint8_t valreg = third_volatile(r);
        const std::int32_t sp_off = regs_base + vm.slot_of_xreg(XReg::SP) * 8;

        emit_fetch_byte_dec(e, vm, r.scratch_a); // tag
        auto lbl_imm  = e.new_label();
        auto lbl_mem  = e.new_label();
        auto lbl_done = e.new_label();
        e.cmp_reg_imm32(r.scratch_a, 1, true);
        e.jcc_label(cc::z, lbl_imm);
        e.cmp_reg_imm32(r.scratch_a, 2, true);
        e.jcc_label(cc::z, lbl_mem);

        // reg
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        emit_fetch_byte_dec(e, vm, r.scratch_b);
        e.mov_reg_mem_sib(
            valreg,
            r.state_ptr,
            r.scratch_a,
            3,
            regs_base,
            true
        );
        e.jmp_label(lbl_done);
        e.bind(lbl_imm);
        emit_fetch_uN_dec(
            e,
            vm,
            valreg,
            4
        );
        emit_fetch_uN_dec(
            e,
            vm,
            r.scratch_a,
            4
        );
        e.jmp_label(lbl_done);
        e.bind(lbl_mem);
        emit_x86_mem_addr(e, vm, valreg);
        e.add_reg_imm32(rx::rsp, 8, true);
        e.mov_reg_mem(
            valreg,
            valreg,
            0,
            true
        );
        e.bind(lbl_done);

        // VM_RSP -= 4, [VM_RSP] = valreg, commit VM_RSP.
        e.mov_reg_mem(
            r.scratch_a,
            r.state_ptr,
            sp_off,
            true
        );
        e.sub_reg_imm32(r.scratch_a, 4, true);
        e.mov_mem_reg(
            r.scratch_a,
            0,
            valreg,
            true
        );
        e.mov_mem_reg(
            r.state_ptr,
            sp_off,
            r.scratch_a,
            true
        );
        emit_dispatch_tail(e, vm);
    }

    void PopCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        const auto regs_base = static_cast<std::int32_t>(vm.state_layout().regs_base);
        const std::uint8_t valreg = third_volatile(r);
        const std::int32_t sp_off = regs_base + vm.slot_of_xreg(XReg::SP) * 8;

        // pop the value from the VM shadow stack first.
        e.mov_reg_mem(
            r.scratch_b,
            r.state_ptr,
            sp_off,
            true
        );
        e.mov_reg_mem(
            valreg,
            r.scratch_b,
            0,
            true
        );
        e.add_reg_imm32(r.scratch_b, 4, true);
        e.mov_mem_reg(
            r.state_ptr,
            sp_off,
            r.scratch_b,
            true
        );

        // tag: 0 reg, 1 mem 
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        auto lbl_mem  = e.new_label();
        auto lbl_done = e.new_label();
        e.cmp_reg_imm32(r.scratch_a, 1, true);
        e.jcc_label(cc::z, lbl_mem);

        // reg dest: fetch slot+width, store popped value.
        emit_fetch_byte_dec(e, vm, r.scratch_a); // dst slot
        emit_fetch_byte_dec(e, vm, r.scratch_b); // dst width
        emit_store_slot_value_x86(
            e,
            vm,
            r.scratch_a,
            valreg,
            r.scratch_b
        );
        e.jmp_label(lbl_done);
        e.bind(lbl_mem);

        // mem dest is rare for shellcode, skip.
        e.bind(lbl_done);
        emit_dispatch_tail(e, vm);
    }

    // LODSB: al = byte [esi], esi += 1. DF=0 assumed.
    // CMPSB: cmp byte [esi] vs byte [edi], set flags, esi+=1, edi+=1.
    void LodsbCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        const auto regs_base = static_cast<std::int32_t>(vm.state_layout().regs_base);
        const std::uint8_t si_off = static_cast<std::uint8_t>(vm.slot_of_xreg(XReg::SI));
        const std::uint8_t ax_off = static_cast<std::uint8_t>(vm.slot_of_xreg(XReg::AX));

        // VM_SI into scratch_a, byte [VM_SI] into scratch_b low, write to
        // VM_AX low byte, then VM_SI += 1.
        e.mov_reg_mem(
            r.scratch_a,
            r.state_ptr,
            regs_base + si_off * 8,
            true
        );
        e.u8(0x0F); e.u8(0xB6); // movzx r32, byte ptr [r/m]
        e.emit_modrm_mem(
            r.scratch_b & 7,
            r.scratch_a,
            rx::none,
            0,
            0
        );

        // store low byte of scratch_b into VM_AX low byte. 
        e.u8(0x88); // mov r/m8, r8
        e.emit_modrm_mem(
            r.scratch_b & 7,
            r.state_ptr,
            rx::none,
            0,
            regs_base + ax_off * 8
        );

        // VM_SI += 1.
        e.inc_reg(r.scratch_a, true);
        e.mov_mem_reg(
            r.state_ptr,
            regs_base + si_off * 8,
            r.scratch_a,
            true
        );
        emit_dispatch_tail(e, vm);
    }

    void CmpsbCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        const auto regs_base = static_cast<std::int32_t>(vm.state_layout().regs_base);
        const auto& st = vm.state_layout();
        const std::uint8_t si_off = static_cast<std::uint8_t>(vm.slot_of_xreg(XReg::SI));
        const std::uint8_t di_off = static_cast<std::uint8_t>(vm.slot_of_xreg(XReg::DI));
        const std::uint8_t valreg = third_volatile(r);

        // valreg = byte [VM_SI], scratch_a = VM_SI for increment.
        e.mov_reg_mem(
            r.scratch_a,
            r.state_ptr,
            regs_base + si_off * 8,
            true
        );
        e.u8(0x0F); e.u8(0xB6);
        e.emit_modrm_mem(
            valreg & 7,
            r.scratch_a,
            rx::none,
            0,
            0
        );
        e.inc_reg(r.scratch_a, true);
        e.mov_mem_reg(
            r.state_ptr,
            regs_base + si_off * 8,
            r.scratch_a,
            true
        );

        // scratch_b = byte [VM_DI], scratch_a = VM_DI gets overwritten.
        e.mov_reg_mem(
            r.scratch_a,
            r.state_ptr,
            regs_base + di_off * 8,
            true
        );
        e.u8(0x0F); e.u8(0xB6);
        e.emit_modrm_mem(
            r.scratch_b & 7,
            r.scratch_a,
            rx::none,
            0,
            0
        );
        e.inc_reg(r.scratch_a, true);
        e.mov_mem_reg(
            r.state_ptr,
            regs_base + di_off * 8,
            r.scratch_a,
            true
        );

        // flags context: a = src byte valreg, b = dst byte scratch_b.
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_a),
            valreg,
            true
        );
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_b),
            r.scratch_b,
            true
        );

        // result = src - dst.
        e.sub_reg_reg(valreg, r.scratch_b, true);
        e.and_reg_imm32(valreg, 0xFF, true);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_result),
            valreg,
            true
        );

        // flag_op SUB, flag_width 1.
        e.mov_reg_imm32(valreg, static_cast<std::int32_t>(FlagsOp::SUB), true);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_op),
            valreg,
            true
        );
        e.mov_reg_imm32(valreg, 1, true);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_width),
            valreg,
            true
        );
        emit_dispatch_tail(e, vm);
    }

    // CALL_NATIVE: invoke a Win32 API 
    static void emit_native_handler_x86(X86Emitter& e, const VMConfig& vm, bool is_jmp) {
        const auto& r = vm.dispatcher_regs();
        const auto& st = vm.state_layout();
        {
            // deferred data-island decrypt 
            auto lbl_done = e.new_label();
            x86_self_locate(e, r.scratch_a, FixupKind::DataIslandInitFlag);
            e.u8(0x80);
            e.emit_modrm_mem(
                7,
                r.scratch_a,
                rx::none,
                0,
                0
            );
            e.u8(0);
            e.jcc_label(cc::nz, lbl_done);

            // save cipher_state and ip.
            e.mov_mem_reg(
                r.state_ptr,
                static_cast<std::int32_t>(st.cipher_extra) + kPreDecryptCsOff,
                r.cipher_state,
                true
            );
            e.mov_mem_reg(
                r.state_ptr,
                static_cast<std::int32_t>(st.cipher_extra) + kPreDecryptIpOff,
                r.ip,
                true
            );

            // reset cipher_state to cipher_init.
            e.mov_reg_imm32(r.scratch_a, static_cast<std::int32_t>(vm.cipher_init_state()), true);
            e.mov_reg_reg(r.cipher_state, r.scratch_a, true);

            // cursors.
            x86_self_locate(e, r.ip, FixupKind::DataIsland);
            x86_self_locate(e, r.scratch_b, FixupKind::DataIsland);

            // counter. pick a volatile the decrypt loop's body doesn't use
            std::uint8_t counter_reg = rx::rax;
            for (std::uint8_t rr : {rx::rax, rx::rcx, rx::rdx}) {
                if (rr != r.scratch_a && rr != r.scratch_b) { counter_reg = rr; break; }
            }
            e.mov_reg_imm32(counter_reg, static_cast<std::int32_t>(vm.data_island_size()), true);

            auto lbl_loop = e.new_label();
            e.bind(lbl_loop);
            emit_fetch_byte_dec(e, vm, r.scratch_a);
            e.u8(0x88);
            e.emit_modrm_mem(
                r.scratch_a & 7,
                r.scratch_b,
                rx::none,
                0,
                0
            );
            e.inc_reg(r.scratch_b, true);
            e.dec_reg(counter_reg, true);
            e.test_reg_reg(counter_reg, counter_reg, true);
            e.jcc_label(cc::nz, lbl_loop);

            // restore ip + cipher_state.
            e.mov_reg_mem(
                r.cipher_state,
                r.state_ptr,
                static_cast<std::int32_t>(st.cipher_extra) + kPreDecryptCsOff,
                true
            );
            e.mov_reg_mem(
                r.ip,
                r.state_ptr,
                static_cast<std::int32_t>(st.cipher_extra) + kPreDecryptIpOff,
                true
            );

            // mark flag.
            x86_self_locate(e, r.scratch_a, FixupKind::DataIslandInitFlag);
            e.u8(0xC6);
            e.emit_modrm_mem(
                0,
                r.scratch_a,
                rx::none,
                0,
                0
            );
            e.u8(1);

            e.bind(lbl_done);
        }
        const auto regs_base = static_cast<std::int32_t>(st.regs_base);
        const std::uint8_t valreg = third_volatile(r);
        const std::int32_t sp_off = regs_base + vm.slot_of_xreg(XReg::SP) * 8;
        const std::int32_t ax_off = regs_base + vm.slot_of_xreg(XReg::AX) * 8;
        const std::int32_t saved_eax_off = static_cast<std::int32_t>(st.cipher_extra) + kSavedTargetOff;

        // skip cipher_extra+48 since the prologue stores cipher_init_state there.
        const std::int32_t saved_ret_off = saved_eax_off + 16;

        // fetch trampoline_offset, compute trampoline addr in valreg, save it.
        emit_fetch_u32_dec(e, vm, valreg);
        e.mov_reg_mem(
            r.scratch_a,
            r.state_ptr,
            static_cast<std::int32_t>(st.trampoline_base),
            true
        );
        e.add_reg_reg(valreg, r.scratch_a, true);
        e.mov_mem_reg(
            r.state_ptr,
            saved_ret_off,
            valreg,
            true
        );

        // fetch tag + compute target into valreg.
        emit_fetch_byte_dec(e, vm, r.scratch_a);
        auto lbl_vreg = e.new_label();
        auto lbl_mem  = e.new_label();
        auto lbl_have = e.new_label();
        e.cmp_reg_imm32(r.scratch_a, 1, true);
        e.jcc_label(cc::z, lbl_vreg);
        e.cmp_reg_imm32(r.scratch_a, 2, true);
        e.jcc_label(cc::z, lbl_mem);

        // imm: 8 bytes, we use low 32.
        emit_fetch_uN_dec(
            e,
            vm,
            valreg,
            4
        );
        emit_fetch_uN_dec(
            e,
            vm,
            r.scratch_a,
            4
        );

        // in --ranges hybrid mode, imm targets from the lifter are blob-va
        // offsets
        if (vm.range_mode() || vm.pack_mode()) {
            e.mov_reg_mem(
                r.scratch_b,
                r.state_ptr,
                static_cast<std::int32_t>(st.data_island_base),
                true
            );
            e.add_reg_reg(valreg, r.scratch_b, true);
        }
        e.jmp_label(lbl_have);
        e.bind(lbl_vreg);
        emit_fetch_byte_dec(e, vm, r.scratch_a); // slot
        emit_fetch_byte_dec(e, vm, r.scratch_b); // width ignored
        e.mov_reg_mem_sib(
            valreg,
            r.state_ptr,
            r.scratch_a,
            3,
            regs_base,
            true
        );
        e.jmp_label(lbl_have);
        e.bind(lbl_mem);
        emit_x86_mem_addr(e, vm, valreg);
        e.add_reg_imm32(rx::rsp, 8, true);
        e.mov_reg_mem(
            valreg,
            valreg,
            0,
            true
        );
        e.bind(lbl_have);

        // va-lookup disabled, see x64 comment, too lazy
        e.mov_mem_reg(
            r.state_ptr,
            saved_eax_off,
            valreg,
            true
        );

        // CALL_NATIVE: push trampoline_addr onto VM_ESP so the api's ret
        // pops it, landing in our trampoline rather than a data island
        // address 
        if (!is_jmp) {
            e.mov_reg_mem(
                r.scratch_a,
                r.state_ptr,
                saved_ret_off,
                true
            );
            e.mov_reg_mem(
                r.scratch_b,
                r.state_ptr,
                sp_off,
                true
            );
            e.sub_reg_imm32(r.scratch_b, 4, true);
            e.mov_mem_reg(
                r.state_ptr,
                sp_off,
                r.scratch_b,
                true
            );
            e.mov_mem_reg(
                r.scratch_b,
                0,
                r.scratch_a,
                true
            );
        }

        // save dispatcher state to slots so the trampoline, reached via api
        // ret or direct CPU-jmp on the CALL_NATIVE-to-trampoline path, can
        // restore them 
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

        // save dispatcher esp.
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.saved_native_rsp),
            rx::rsp,
            true
        );

        // range-mode mid-exec JMP_NATIVE teardown for x86 
        if (vm.range_mode() && !vm.pack_mode() && is_jmp) {
            const std::uint32_t frame_size = static_cast<std::uint32_t>(vm.state_layout().total_size) + vm.shadow_stack_bytes() + 256;
            const std::uint32_t aligned_frame = (frame_size + 15) & ~15u;

            // scratch_a = saved_native_rsp value + aligned_frame + 20.
            e.mov_reg_mem(
                r.scratch_a,
                r.state_ptr,
                static_cast<std::int32_t>(st.saved_native_rsp),
                true
            );
            e.add_reg_imm32(r.scratch_a, static_cast<std::int32_t>(aligned_frame + 20), true);

            // scratch_b = target.
            e.mov_reg_mem(
                r.scratch_b,
                r.state_ptr,
                saved_eax_off,
                true
            );

            // [scratch_a] = target.
            e.mov_mem_reg(
                r.scratch_a,
                0,
                r.scratch_b,
                true
            );

            // eax = VM_AX for the native return-value convention.
            e.mov_reg_mem(
                rx::rax,
                r.state_ptr,
                ax_off,
                true
            );

            // jmp rel32 to exit_handler.
            e.u8(0xE9);
            const std::size_t patch = e.size();
            e.u32(0);
            e.add_fixup(
                patch,
                static_cast<std::uint32_t>(FixupKind::VMExit),
                0,
                0
            );
            return;
        }

        // switch esp to VM_RSP. args were already pushed by shellcode PUSHes.
        e.mov_reg_mem(
            rx::rsp,
            r.state_ptr,
            sp_off,
            true
        );

        // load host eax = VM_AX so the trampoline's VM_AX = eax writeback is
        // a no-op when control reaches a trampoline directly 
        e.mov_reg_mem(
            rx::rax,
            r.state_ptr,
            ax_off,
            true
        );

        // tail-call to target via CPU JMP for both CALL_NATIVE and JMP_NATIVE 
        e.jmp_mem_disp32(r.state_ptr, saved_eax_off);
    }

    void CallNativeCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        emit_native_handler_x86(e, vm, /*is_jmp=*/false);
    }

    // JMP_NATIVE: for in-blob targets we stay in the VM, same as CALL_NATIVE
    // minus the return-state push 
    void JmpNativeCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        emit_native_handler_x86(e, vm, /*is_jmp=*/true);
    }

    // RET_NATIVE: same as EXIT 
    void RetNativeCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        (void)vm;
        e.u8(0xE9);
        e.emit_rel32_fixup(static_cast<std::uint32_t>(FixupKind::VMExit), 0, 0);
    }

    // shifts: Shl/Shr/Sar/Rol/Ror by imm8 or by CL via vreg.
    static void emit_shift_handler_x86(X86Emitter& e, const VMConfig& vm,
                                       std::uint8_t op_ext) {
        const auto& r = vm.dispatcher_regs();
        const auto regs_base = static_cast<std::int32_t>(vm.state_layout().regs_base);
        const std::uint8_t valreg = third_volatile(r);

        emit_fetch_byte_dec(e, vm, r.scratch_a); // dst slot
        emit_fetch_byte_dec(e, vm, r.scratch_b); // dst width
        e.push_reg(r.scratch_a);                 // [esp+8] dst slot
        e.push_reg(r.scratch_b);                 // [esp+4] dst width
        e.mov_reg_mem_sib(
            valreg,
            r.state_ptr,
            r.scratch_a,
            3,
            regs_base,
            true
        );
        e.push_reg(valreg); // [esp+0] value

        emit_fetch_byte_dec(e, vm, r.scratch_a); // count tag, 0 reg 1 imm
        auto lbl_reg  = e.new_label();
        auto lbl_done = e.new_label();
        e.cmp_reg_imm32(r.scratch_a, 0, true);
        e.jcc_label(cc::z, lbl_reg);
        emit_fetch_byte_dec(e, vm, rx::rcx);
        e.jmp_label(lbl_done);
        e.bind(lbl_reg);
        emit_fetch_byte_dec(e, vm, r.scratch_b); // src slot
        emit_fetch_byte_dec(e, vm, r.scratch_a); // src width ignored
        e.mov_reg_mem_sib(
            rx::rcx,
            r.state_ptr,
            r.scratch_b,
            3,
            regs_base,
            true
        );
        e.bind(lbl_done);
        e.and_reg_imm32(rx::rcx, 0x1F, true); // 32-bit shifts mask count to 5 bits

        // shift dword [esp] by CL. encodes as D3 /<op_ext> SIB esp.
        e.u8(0xD3);
        e.emit_modrm(0 /*mod=00*/, op_ext, 4 /*r/m=100 SIB*/);
        e.emit_sib(0, 4 /*no index*/, 4 /*base=esp*/);

        e.pop_reg(valreg);      // shifted value
        e.pop_reg(r.scratch_b); // dst width
        e.pop_reg(r.scratch_a); // dst slot

        emit_store_slot_value_x86(
            e,
            vm,
            r.scratch_a,
            valreg,
            r.scratch_b
        );
        emit_dispatch_tail(e, vm);
    }

    void ShlCodec::emit_handler(X86Emitter& e, const VMConfig& v) const { emit_shift_handler_x86(e, v, 4); }
    void ShrCodec::emit_handler(X86Emitter& e, const VMConfig& v) const { emit_shift_handler_x86(e, v, 5); }
    void SarCodec::emit_handler(X86Emitter& e, const VMConfig& v) const { emit_shift_handler_x86(e, v, 7); }
    void RolCodec::emit_handler(X86Emitter& e, const VMConfig& v) const { emit_shift_handler_x86(e, v, 0); }
    void RorCodec::emit_handler(X86Emitter& e, const VMConfig& v) const { emit_shift_handler_x86(e, v, 1); }

    // DF CLD/STD: no-op dispatch on x86, mirroring x64 
    void DfCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        emit_dispatch_tail(e, vm);
    }

    // ZEXT / SEXT: zero- or sign-extend a sub-width source into a wider dst.
    static void emit_extend_x86(X86Emitter& e, const VMConfig& vm, bool is_signed) {
        const auto& r = vm.dispatcher_regs();
        const auto regs_base = static_cast<std::int32_t>(vm.state_layout().regs_base);
        const std::uint8_t valreg = third_volatile(r);

        emit_fetch_byte_dec(e, vm, r.scratch_a); // dst slot
        emit_fetch_byte_dec(e, vm, r.scratch_b); // dst width
        e.push_reg(r.scratch_a);
        e.push_reg(r.scratch_b);

        // source tag: 0 reg, 1 mem 
        emit_fetch_byte_dec(e, vm, r.scratch_a); // tag
        auto lbl_mem      = e.new_label();
        auto lbl_load_done = e.new_label();
        e.cmp_reg_imm32(r.scratch_a, 1, true);
        e.jcc_label(cc::z, lbl_mem);

        // tag=0 reg: fetch src slot + src width, SIB-load.
        emit_fetch_byte_dec(e, vm, r.scratch_a); // src slot
        emit_fetch_byte_dec(e, vm, r.scratch_b); // src width
        e.mov_reg_mem_sib(
            valreg,
            r.state_ptr,
            r.scratch_a,
            3,
            regs_base,
            true
        );
        e.jmp_label(lbl_load_done);

        // tag=1 mem: consume the 9-byte mem operand, load 4 bytes.
        e.bind(lbl_mem);
        emit_x86_mem_addr(e, vm, valreg);

        // emit_x86_mem_addr leaves seg + mem-width on stack, 8 bytes 
        e.add_reg_imm32(rx::rsp, 8, true);
        e.mov_reg_mem(
            valreg,
            valreg,
            0,
            true
        );

        e.bind(lbl_load_done);

        // trailing src-width byte. drives the zero/sign-extend below.
        emit_fetch_byte_dec(e, vm, r.scratch_b);

        // extend by src width.
        auto lbl_w1 = e.new_label(), lbl_w2 = e.new_label(), lbl_done = e.new_label();
        e.cmp_reg_imm32(r.scratch_b, 1, true);
        e.jcc_label(cc::z, lbl_w1);
        e.cmp_reg_imm32(r.scratch_b, 2, true);
        e.jcc_label(cc::z, lbl_w2);
        e.jmp_label(lbl_done);
        e.bind(lbl_w1);

        if (is_signed) e.movsx_r32_r8(valreg, valreg);
        else           e.movzx_r32_r8(valreg, valreg);
        e.jmp_label(lbl_done);
        e.bind(lbl_w2);

        if (is_signed) e.movsx_r32_r16(valreg, valreg);
        else           e.movzx_r32_r16(valreg, valreg);
        e.bind(lbl_done);

        e.pop_reg(r.scratch_b);
        e.pop_reg(r.scratch_a);
        emit_store_slot_value_x86(
            e,
            vm,
            r.scratch_a,
            valreg,
            r.scratch_b
        );
        emit_dispatch_tail(e, vm);
    }

    void ZextCodec::emit_handler(X86Emitter& e, const VMConfig& v) const { emit_extend_x86(e, v, false); }
    void SextCodec::emit_handler(X86Emitter& e, const VMConfig& v) const { emit_extend_x86(e, v, true);  }

    // XCHG slot_A, slot_B: swap two slot values 
    void XchgCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        const auto regs_base = static_cast<std::int32_t>(vm.state_layout().regs_base);
        const std::uint8_t valreg = third_volatile(r);

        // fetch A's slot/width, push.
        emit_fetch_byte_dec(e, vm, r.scratch_a); // slot A
        emit_fetch_byte_dec(e, vm, r.scratch_b); // width A
        e.push_reg(r.scratch_a);                 // slotA
        e.push_reg(r.scratch_b);                 // widthA

        // fetch B's slot/width, push.
        emit_fetch_byte_dec(e, vm, r.scratch_a); // slot B
        emit_fetch_byte_dec(e, vm, r.scratch_b); // width B
        e.push_reg(r.scratch_a);                 // slotB
        e.push_reg(r.scratch_b);                 // widthB

        // stack low to high iirc:
        //   [esp+0]  widthB
        //   [esp+4]  slotB
        //   [esp+8]  widthA
        //   [esp+12] slotA

        // load A's value, push it. peek slotA at [esp+12].
        e.mov_reg_mem(
            r.scratch_a,
            rx::rsp,
            12,
            true
        );
        e.mov_reg_mem_sib(
            valreg,
            r.state_ptr,
            r.scratch_a,
            3,
            regs_base,
            true
        );
        e.push_reg(valreg); // [esp+0] valA, everything else +4

        // stack now?
        //   [esp+0]  valA
        //   [esp+4]  widthB
        //   [esp+8]  slotB
        //   [esp+12] widthA
        //   [esp+16] slotA

        // load B's value into valreg. peek slotB at [esp+8].
        e.mov_reg_mem(
            r.scratch_a,
            rx::rsp,
            8,
            true
        );
        e.mov_reg_mem_sib(
            valreg,
            r.state_ptr,
            r.scratch_a,
            3,
            regs_base,
            true
        );

        // store slot[A] = valreg, which is B's old value.
        e.mov_reg_mem(
            r.scratch_a,
            rx::rsp,
            16,
            true
        ); // slotA

        e.mov_reg_mem(
            r.scratch_b,
            rx::rsp,
            12,
            true
        ); // widthA

        emit_store_slot_value_x86(
            e,
            vm,
            r.scratch_a,
            valreg,
            r.scratch_b
        );

        // store slot[B] = valA from [esp+0].
        e.mov_reg_mem(
            valreg,
            rx::rsp,
            0,
            true
        ); // valA

        e.mov_reg_mem(
            r.scratch_a,
            rx::rsp,
            8,
            true
        ); // slotB

        e.mov_reg_mem(
            r.scratch_b,
            rx::rsp,
            4,
            true
        ); // widthB

        emit_store_slot_value_x86(
            e,
            vm,
            r.scratch_a,
            valreg,
            r.scratch_b
        );

        // drop 5 dwords: valA, widthB, slotB, widthA, slotA.
        e.add_reg_imm32(rx::rsp, 20, true);
        emit_dispatch_tail(e, vm);
    }

    // LOOP: dec ecx, jump if non-zero.
    void LoopDecCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        const auto regs_base = static_cast<std::int32_t>(vm.state_layout().regs_base);
        const std::uint8_t cx_slot = vm.slot_of_xreg(XReg::CX);

        e.mov_reg_mem(
            r.scratch_a,
            r.state_ptr,
            regs_base + cx_slot * 8,
            true
        );
        e.dec_reg(r.scratch_a, true);
        e.mov_mem_reg(
            r.state_ptr,
            regs_base + cx_slot * 8,
            r.scratch_a,
            true
        );
        emit_fetch_u32_dec(e, vm, r.scratch_b); // rel32, uses inner-temp stack spill
        e.test_reg_reg(r.scratch_a, r.scratch_a, true);
        auto lbl_skip = e.new_label();
        e.jcc_label(cc::z, lbl_skip);
        e.add_reg_reg(r.ip, r.scratch_b, true);
        e.bind(lbl_skip);
        x86_cipher_reset(e, vm);
        emit_dispatch_tail(e, vm);
    }

    // CALL_VM: internal call to a shellcode-local function
    void CallVmCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        const auto& st = vm.state_layout();
        const std::uint8_t valreg = third_volatile(r);
        const auto regs_base = static_cast<std::int32_t>(st.regs_base);
        const std::int32_t sp_off = regs_base + vm.slot_of_xreg(XReg::SP) * 8;

        // operand layout: [trampoline_offset u32][rel32 i32]
        // fetch trampoline_offset into valreg, compute trampoline addr.
        emit_fetch_u32_dec(e, vm, valreg);
        e.mov_reg_mem(
            r.scratch_b,
            r.state_ptr,
            static_cast<std::int32_t>(st.trampoline_base),
            true
        );
        e.add_reg_reg(valreg, r.scratch_b, true); // valreg = trampoline addr

        // push native return addr onto SHADOW stack. VM_RSP -= 4, [VM_RSP] = valreg.
        e.mov_reg_mem(
            r.scratch_b,
            r.state_ptr,
            sp_off,
            true
        );
        e.sub_reg_imm32(r.scratch_b, 4, true);
        e.mov_mem_reg(
            r.scratch_b,
            0,
            valreg,
            true
        );
        e.mov_mem_reg(
            r.state_ptr,
            sp_off,
            r.scratch_b,
            true
        );

        // fetch rel32 into scratch_a. ip now past operands.
        emit_fetch_u32_dec(e, vm, r.scratch_a);

        // push bytecode return-offset = ip - bytecode_base onto the VM call stack.
        e.mov_reg_reg(valreg, r.ip, true);
        e.mov_reg_mem(
            r.scratch_b,
            r.state_ptr,
            static_cast<std::int32_t>(st.bytecode_base),
            true
        );
        e.sub_reg_reg(valreg, r.scratch_b, true);
        e.mov_reg_mem(
            r.scratch_b,
            r.state_ptr,
            static_cast<std::int32_t>(st.call_sp),
            true
        );
        e.mov_mem_sib_reg(
            r.state_ptr,
            r.scratch_b,
            3,
            static_cast<std::int32_t>(st.call_stack_base),
            valreg,
            true
        );
        e.inc_reg(r.scratch_b, true);
        e.mov_mem_reg(
            r.state_ptr,
            static_cast<std::int32_t>(st.call_sp),
            r.scratch_b,
            true
        );

        // ip += rel32.
        e.add_reg_reg(r.ip, r.scratch_a, true);
        x86_cipher_reset(e, vm);
        emit_dispatch_tail(e, vm);
    }

    // RET_VM: pop the saved return-offset from the VM call stack and jump
    // to it 
    void RetVmCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        // RET_VM x86: pop 4 bytes off the shadow stack and jmp natively 
        const auto& r = vm.dispatcher_regs();
        const auto& st = vm.state_layout();
        const auto regs_base = static_cast<std::int32_t>(st.regs_base);
        const std::int32_t sp_off = regs_base + vm.slot_of_xreg(XReg::SP) * 8;
        const std::uint8_t valreg = third_volatile(r);
        const std::int32_t saved_tgt_off = static_cast<std::int32_t>(st.cipher_extra) + kSavedTargetOff;

        // pop shadow stack: valreg = popped value, VM_RSP += 4.
        e.mov_reg_mem(
            r.scratch_a,
            r.state_ptr,
            sp_off,
            true
        );
        e.mov_reg_mem(
            valreg,
            r.scratch_a,
            0,
            true
        ); // valreg = *VM_RSP

        e.add_reg_imm32(r.scratch_a, 4, true);
        e.mov_mem_reg(
            r.state_ptr,
            sp_off,
            r.scratch_a,
            true
        ); // commit VM_RSP

        // stash the popped target. materialization clobbers eax and other
        // volatiles.
        e.mov_mem_reg(
            r.state_ptr,
            saved_tgt_off,
            valreg,
            true
        );

        // save dispatcher state for the trampoline to restore.
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

        // materialize x86 gprs from VMState slots. skip state_ptr's real reg.
        auto sp_reg = r.state_ptr;
        auto load_to = [&](XReg xr, std::uint8_t real_reg) {
            const std::uint8_t slot = vm.slot_of_xreg(xr);
            e.mov_reg_mem(
                real_reg,
                sp_reg,
                static_cast<std::int32_t>(regs_base + slot * 8),
                true
            );
        };

        static constexpr XReg materialize_order[] = {
            XReg::AX, XReg::CX, XReg::DX, XReg::BX, XReg::BP, XReg::SI, XReg::DI
        };

        static constexpr std::uint8_t real_regs[] = {
            rx::rax, rx::rcx, rx::rdx, rx::rbx, rx::rbp, rx::rsi, rx::rdi
        };

        for (std::size_t k = 0; k < 7; ++k) {
            if (real_regs[k] == sp_reg) continue;
            load_to(materialize_order[k], real_regs[k]);
        }

        // load esp = VM_RSP last, then jmp through memory so eax isn't
        // clobbered 
        e.mov_reg_mem(
            rx::rsp,
            sp_reg,
            static_cast<std::int32_t>(regs_base + vm.slot_of_xreg(XReg::SP) * 8),
            true
        );
        e.jmp_mem_disp32(sp_reg, saved_tgt_off);
    }

    // BR_CC: bytecode-level conditional branch 
    void BrCcCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        const auto& st = vm.state_layout();
        const std::uint8_t valreg = third_volatile(r);

        emit_fetch_byte_dec(e, vm, r.scratch_a); // cond
        e.push_reg(r.scratch_a);                 // [esp+24] cond
        emit_fetch_u32_dec(e, vm, r.scratch_b);  // rel32
        e.push_reg(r.scratch_b);                 // [esp+20] rel32

        // load flag_a, flag_b, flag_result into volatiles for sign-ext, then
        // spill to stackk
        e.mov_reg_mem(
            r.scratch_a,
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_a),
            true
        );
        e.mov_reg_mem(
            r.scratch_b,
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_b),
            true
        );
        e.mov_reg_mem(
            valreg,
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_result),
            true
        );

        // width-aware sign-extension 
        e.push_reg(valreg);      // [esp+16] flags_result raw
        e.push_reg(r.scratch_b); // [esp+12] flags_b raw
        e.push_reg(r.scratch_a); // [esp+8]  flags_a raw

        // load width into scratch_a, mask low 7 bits.
        e.mov_reg_mem(
            r.scratch_a,
            r.state_ptr,
            static_cast<std::int32_t>(st.flags_width),
            true
        );
        e.and_reg_imm32(r.scratch_a, 0x7F, true);

        auto lbl_w4 = e.new_label(),
             lbl_w2 = e.new_label(),
             lbl_w1 = e.new_label(),
             lbl_w_done = e.new_label();

        e.cmp_reg_imm32(r.scratch_a, 4, true);
        e.jcc_label(cc::z, lbl_w4);
        e.cmp_reg_imm32(r.scratch_a, 2, true);
        e.jcc_label(cc::z, lbl_w2);

        // width 1: sign-extend low byte. reload each value, movsx, store back.
        e.bind(lbl_w1);
        e.mov_reg_mem(
            r.scratch_a,
            rx::rsp,
            0,
            true
        );
        e.movsx_r32_r8(r.scratch_a, r.scratch_a);
        e.mov_mem_reg(
            rx::rsp,
            0,
            r.scratch_a,
            true
        );
        e.mov_reg_mem(
            r.scratch_a,
            rx::rsp,
            4,
            true
        );
        e.movsx_r32_r8(r.scratch_a, r.scratch_a);
        e.mov_mem_reg(
            rx::rsp,
            4,
            r.scratch_a,
            true
        );
        e.mov_reg_mem(
            r.scratch_a,
            rx::rsp,
            8,
            true
        );
        e.movsx_r32_r8(r.scratch_a, r.scratch_a);
        e.mov_mem_reg(
            rx::rsp,
            8,
            r.scratch_a,
            true
        );
        e.jmp_label(lbl_w_done);
        e.bind(lbl_w2);
        e.mov_reg_mem(
            r.scratch_a,
            rx::rsp,
            0,
            true
        );
        e.movsx_r32_r16(r.scratch_a, r.scratch_a);
        e.mov_mem_reg(
            rx::rsp,
            0,
            r.scratch_a,
            true
        );
        e.mov_reg_mem(
            r.scratch_a,
            rx::rsp,
            4,
            true
        );
        e.movsx_r32_r16(r.scratch_a, r.scratch_a);
        e.mov_mem_reg(
            rx::rsp,
            4,
            r.scratch_a,
            true
        );
        e.mov_reg_mem(
            r.scratch_a,
            rx::rsp,
            8,
            true
        );
        e.movsx_r32_r16(r.scratch_a, r.scratch_a);
        e.mov_mem_reg(
            rx::rsp,
            8,
            r.scratch_a,
            true
        );
        e.jmp_label(lbl_w_done);
        e.bind(lbl_w4);

        // width 4: already 32-bit, no-op.
        e.bind(lbl_w_done);

        e.mov_reg_mem(
            r.scratch_a,
            rx::rsp,
            8,
            true
        );
        e.test_reg_reg(r.scratch_a, r.scratch_a, true);
        
        // setz al. al is scratch_a's low byte only when scratch_a is 0..3
        e.u8(0x0F); e.u8(static_cast<std::uint8_t>(0x90 + cc::z));
        e.emit_modrm(3, 0, r.scratch_a & 7);
        e.movzx_r32_r8(r.scratch_a, r.scratch_a);
        e.push_reg(r.scratch_a); // ZF byte

        // SF from flags_result_sx.
        e.mov_reg_mem(
            r.scratch_a,
            rx::rsp,
            12,
            true
        );
        e.test_reg_reg(r.scratch_a, r.scratch_a, true);
        e.u8(0x0F); e.u8(static_cast<std::uint8_t>(0x90 + cc::s));
        e.emit_modrm(3, 0, r.scratch_a & 7);
        e.movzx_r32_r8(r.scratch_a, r.scratch_a);
        e.push_reg(r.scratch_a); // SF byte

        // CF unsigned-less: cmp flags_a, flags_b; setb.
        e.mov_reg_mem(
            r.scratch_a,
            rx::rsp,
            8,
            true
        ); // flags_a, post-push offset

        e.mov_reg_mem(
            r.scratch_b,
            rx::rsp,
            12,
            true
        ); // flags_b

        e.cmp_reg_reg(r.scratch_a, r.scratch_b, true);
        e.u8(0x0F); e.u8(static_cast<std::uint8_t>(0x90 + cc::b));
        e.emit_modrm(3, 0, r.scratch_a & 7);
        e.movzx_r32_r8(r.scratch_a, r.scratch_a);
        e.push_reg(r.scratch_a); // CF byte

        // LT signed-less: cmp; setl.
        e.mov_reg_mem(
            r.scratch_a,
            rx::rsp,
            12,
            true
        ); // flags_a, offset shifted by prior push

        e.mov_reg_mem(
            r.scratch_b,
            rx::rsp,
            16,
            true
        ); // flags_b
        
        e.cmp_reg_reg(r.scratch_a, r.scratch_b, true);
        e.u8(0x0F); e.u8(static_cast<std::uint8_t>(0x90 + cc::l));
        e.emit_modrm(3, 0, r.scratch_a & 7);
        e.movzx_r32_r8(r.scratch_a, r.scratch_a);
        e.push_reg(r.scratch_a); // LT byte

        // stack should now be top to bottom in form and if isnt fml
        //   [esp+0]  LT
        //   [esp+4]  CF
        //   [esp+8]  SF
        //   [esp+12] ZF
        //   [esp+16] flags_a_sx
        //   [esp+20] flags_b_sx
        //   [esp+24] flags_result_sx
        //   [esp+28] rel32
        //   [esp+32] cond
        //
        // load cond and dispatch predicate computation into valreg.
        e.mov_reg_mem(
            r.scratch_a,
            rx::rsp,
            32,
            true
        ); // cond

        auto lbl_take = e.new_label();
        auto lbl_skip = e.new_label();
        auto lbl_eval = e.new_label();
        e.xor_reg_reg(valreg, valreg, true); // valreg = 0

        auto handle = [&](std::uint8_t cond_val, auto&& fn) {
            auto lbl_n = e.new_label();
            e.cmp_reg_imm32(r.scratch_a, static_cast<std::int32_t>(cond_val), true);
            e.jcc_label(cc::nz, lbl_n);
            fn();
            e.jmp_label(lbl_eval);
            e.bind(lbl_n);
        };

        // load flag byte from stack into valreg.
        auto zf = [&]() {
            e.mov_reg_mem(
                valreg,
                rx::rsp,
                12,
                true
            );
        };

        auto sf = [&]() {
            e.mov_reg_mem(
                valreg,
                rx::rsp,
                8,
                true
            ); 
        };

        auto cf = [&]() { 
            e.mov_reg_mem(
                valreg,
                rx::rsp,
                4,
                true
            );
        };

        auto lt = [&]() { 
            e.mov_reg_mem(
                valreg,
                rx::rsp,
                0,
                true
            ); 
        };

        handle(static_cast<std::uint8_t>(Cond::Z),   [&]() { zf(); });
        handle(static_cast<std::uint8_t>(Cond::NZ),  [&]() { zf(); e.xor_reg_imm32(valreg, 1, true); });
        handle(static_cast<std::uint8_t>(Cond::B),   [&]() { cf(); });
        handle(static_cast<std::uint8_t>(Cond::NB),  [&]() { cf(); e.xor_reg_imm32(valreg, 1, true); });
        handle(static_cast<std::uint8_t>(Cond::BE),  [&]() {
            cf(); e.mov_reg_mem(
                r.scratch_b,
                rx::rsp,
                12,
                true
            ); 
            e.or_reg_reg(valreg, r.scratch_b, true); 
        });

        handle(static_cast<std::uint8_t>(Cond::NBE), [&]() {
            cf(); e.mov_reg_mem(
                r.scratch_b,
                rx::rsp,
                12,
                true
            );
            e.or_reg_reg(valreg, r.scratch_b, true); e.xor_reg_imm32(valreg, 1, true); 
        });

        handle(static_cast<std::uint8_t>(Cond::S),   [&]() { sf(); });
        handle(static_cast<std::uint8_t>(Cond::NS),  [&]() { sf(); e.xor_reg_imm32(valreg, 1, true); });
        handle(static_cast<std::uint8_t>(Cond::L),   [&]() { lt(); });
        handle(static_cast<std::uint8_t>(Cond::NL),  [&]() { lt(); e.xor_reg_imm32(valreg, 1, true); });
        handle(static_cast<std::uint8_t>(Cond::LE),  [&]() { 
            lt(); e.mov_reg_mem(
                r.scratch_b,
                rx::rsp,
                12,
                true
            );
            e.or_reg_reg(valreg, r.scratch_b, true); 
        });

        handle(static_cast<std::uint8_t>(Cond::NLE), [&]() { 
            lt(); e.mov_reg_mem(
                r.scratch_b,
                rx::rsp,
                12,
                true
            );
            e.or_reg_reg(valreg, r.scratch_b, true);
            e.xor_reg_imm32(valreg, 1, true);
        });

        e.bind(lbl_eval);
        e.and_reg_imm32(valreg, 1, true);
        e.test_reg_reg(valreg, valreg, true);
        e.jcc_label(cc::nz, lbl_take);
        e.jmp_label(lbl_skip);

        e.bind(lbl_take);
        e.mov_reg_mem(
            r.scratch_a,
            rx::rsp,
            28,
            true
        );
        e.add_reg_reg(r.ip, r.scratch_a, true);

        e.bind(lbl_skip);

        // drop 9 pushed slots: 4 predicate bytes, 3 sign-ext flags, rel32, cond.
        e.add_reg_imm32(rx::rsp, 9 * 4, true);
        x86_cipher_reset(e, vm);
        emit_dispatch_tail(e, vm);
    }

    // IMM: load an 8-byte imm into a slot 
    void ImmCodec::emit_handler(X86Emitter& e, const VMConfig& vm) const {
        const auto& r = vm.dispatcher_regs();
        const auto regs_base = static_cast<std::int32_t>(vm.state_layout().regs_base);
        const std::uint8_t valreg = third_volatile(r);

        emit_fetch_byte_dec(e, vm, r.scratch_a); // slot idx, preserved across fetches
        emit_fetch_byte_dec(e, vm, r.scratch_b); // width ignored, IMM = full slot

        // obfuscated IMM 
        auto fetch_lo_hi = [&](std::int32_t lo_off) {
            emit_fetch_uN_dec(
                e,
                vm,
                valreg,
                4
            );

            e.mov_mem_reg(
                r.state_ptr,
                static_cast<std::int32_t>(vm.state_layout().cipher_extra) + 128 + lo_off,
                valreg,
                true
            );

            emit_fetch_uN_dec(
                e,
                vm,
                r.scratch_b,
                4
            ); // discard high
        };

        fetch_lo_hi(0);  // a_lo at cipher_extra+128
        fetch_lo_hi(4);  // b_lo at cipher_extra+132
        fetch_lo_hi(8);  // c_lo at cipher_extra+136
        fetch_lo_hi(12); // d_lo at cipher_extra+140

        const std::int32_t comp_base = static_cast<std::int32_t>(vm.state_layout().cipher_extra) + 128;

        // valreg = b_lo
        e.mov_reg_mem(
            valreg,
            r.state_ptr,
            comp_base + 4,
            true
        );

        // xor valreg, [state_ptr + comp_base+8], c_lo
        e.u8(0x33);
        e.emit_modrm_mem(
            valreg & 7,
            r.state_ptr,
            rx::none,
            0,
            comp_base + 8
        );

        // add valreg, [state_ptr + comp_base+0], a_lo
        e.u8(0x03);
        e.emit_modrm_mem(
            valreg & 7,
            r.state_ptr,
            rx::none,
            0,
            comp_base + 0
        );

        // sub valreg, [state_ptr + comp_base+12], d_lo
        e.u8(0x2B);
        e.emit_modrm_mem(
            valreg & 7,
            r.state_ptr,
            rx::none,
            0,
            comp_base + 12
        );

        // store low 32 into slot+0
        e.mov_mem_sib_reg(
            r.state_ptr,
            r.scratch_a,
            3,
            regs_base + 0,
            valreg,
            true
        );

        // zero high 32 into slot+4
        e.xor_reg_reg(valreg, valreg, true);
        e.mov_mem_sib_reg(
            r.state_ptr,
            r.scratch_a,
            3,
            regs_base + 4,
            valreg,
            true
        );
        emit_dispatch_tail(e, vm);
    }
}