#include "mkpivm/vm_codegen.h"

#include <array>
#include <unordered_map>

namespace mkpivm {
    namespace {
        // remember the push order so the exit handler pops in reverse. keyed off
        // the emitter pointer since emitters are single-use.
        struct X86PrologueOrder {
            std::vector<std::uint8_t> order;
        };
        static std::unordered_map<const X86Emitter*, X86PrologueOrder> g_x86_prologue_orders;
    }

    const std::vector<std::uint8_t>* prologue_order_for(const X86Emitter& e) {
        auto it = g_x86_prologue_orders.find(&e);
        return it == g_x86_prologue_orders.end() ? nullptr : &it->second.order;
    }

    void VMCodeGen::emit_prologue(X86Emitter& e, std::size_t /*data_island_size*/) {
        X86PrologueOrder po;
        if (!cached_nv_order_x86_set_) {
            std::array<std::uint8_t, 4> nv{rx::rbx, rx::rsi, rx::rdi, rx::rbp};
            shuffle_in_place(nv, rng_);
            cached_nv_order_x86_     = nv;
            cached_nv_order_x86_set_ = true;
        }

        for (auto r : cached_nv_order_x86_) {
            e.push_reg(r);
            po.order.push_back(r);
        }

        e.pushfq(); // same 0x9C opcode in 32-bit, just called pushfd
        g_x86_prologue_orders[&e] = std::move(po);

        const auto& cfg = vm_.dispatcher_regs();
        const std::uint32_t frame_size = static_cast<std::uint32_t>(vm_.state_layout().total_size) + vm_.shadow_stack_bytes() + 256;
        const std::uint32_t aligned = (frame_size + 15) & ~15u;
        e.sub_reg_imm32(rx::rsp, static_cast<std::int32_t>(aligned));
        e.lea_reg_mem(
            cfg.state_ptr,
            rx::rsp,
            rx::none,
            0,
            static_cast<std::int32_t>(vm_.shadow_stack_bytes())
        );
    }

    // 32-bit self-locate wizard shit
    static void x86_self_locate(X86Emitter& e, std::uint8_t dst, FixupKind kind, std::uint64_t data = 0) {
        e.call_rel32(0); // call $+5
        e.pop_reg(dst);  // runtime addr of the pop site
        e.u8(0x81);      // add r32, imm32 is 81 /0
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

    void VMCodeGen::emit_state_init(X86Emitter& e, std::size_t, std::size_t data_island_size,
                                    std::uint32_t block_table_count, bool skip_regs_zero) {
        const auto& cfg = vm_.dispatcher_regs();
        const auto& st  = vm_.state_layout();

        // zero VM regs[]
        if (!skip_regs_zero) {
            e.xor_reg_reg(rx::rax, rx::rax, true);
            for (std::uint8_t i = 0; i < vm_.reg_count(); ++i) {
                e.mov_mem_reg(
                    cfg.state_ptr,
                    static_cast<std::int32_t>(st.regs_base + i * 8),
                    rx::rax,
                    true
                );
                e.mov_mem_reg(
                    cfg.state_ptr,
                    static_cast<std::int32_t>(st.regs_base + i * 8 + 4),
                    rx::rax,
                    true
                );
            }
        }

        // cipher state init, 32-bit constants 
        const std::uint32_t cipher_init32 = static_cast<std::uint32_t>(vm_.cipher_init_state());
        e.mov_reg_imm32(rx::rax, static_cast<std::int32_t>(cipher_init32), true);
        e.mov_reg_reg(cfg.cipher_state, rx::rax, true);
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.cipher_extra) + 48,
            rx::rax,
            true
        );

        // zero the upper 4 bytes of that 8-byte slot for layout consistency.
        e.xor_reg_reg(rx::rax, rx::rax, true);
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.cipher_extra) + 48 + 4,
            rx::rax,
            true
        );

        // mult/add constants into VMState 
        std::uint64_t mult = 0, add = 0;
        switch (vm_.cipher_kind()) {
            case CipherKind::ARX:         mult = 0;                     add = vm_.cipher_k1(); break;
            case CipherKind::LcgSub:      mult = 0x5851F42D4C957F2DULL; add = vm_.cipher_k1(); break;
            case CipherKind::SBoxAdd:     mult = 0x100000001B3ULL;      add = vm_.cipher_k1(); break;
            case CipherKind::FeistelByte: mult = vm_.cipher_k1();       add = vm_.cipher_k2(); break;
        }

        constexpr std::int32_t kCipherAddOff  = 0;
        constexpr std::int32_t kCipherMultOff = 8;
        e.mov_reg_imm32(rx::rax, static_cast<std::int32_t>(add & 0xFFFFFFFFu), true);
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.cipher_extra) + kCipherAddOff,
            rx::rax,
            true
        );

        e.xor_reg_reg(rx::rax, rx::rax, true);
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.cipher_extra) + kCipherAddOff + 4,
            rx::rax,
            true
        );

        e.mov_reg_imm32(rx::rax, static_cast<std::int32_t>(mult & 0xFFFFFFFFu), true);
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.cipher_extra) + kCipherMultOff,
            rx::rax,
            true
        );

        e.xor_reg_reg(rx::rax, rx::rax, true);
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.cipher_extra) + kCipherMultOff + 4,
            rx::rax,
            true
        );

        // handler_base via call/pop self-locate.
        x86_self_locate(e, cfg.handler_base, FixupKind::HandlerTable);
        x86_self_locate(e, cfg.ip, FixupKind::Bytecode);

        // VM_RSP = state_ptr - 4 - headroom. headroom reserves room above
        // VM_SP for lifted code with positive [esp+disp]/[ebp+disp] reads.
        // fixed that weird ass bug where 1/N for large shellcode would
        // remain constant.
        {
            const std::uint32_t hr_raw = vm_.vm_sp_headroom();
            const std::uint32_t hr = (hr_raw + 15u) & ~15u;
            e.mov_reg_reg(rx::rax, cfg.state_ptr, true);
            e.sub_reg_imm32(rx::rax, static_cast<std::int32_t>(4u + hr), true);
        }
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.regs_base + vm_.slot_of_xreg(XReg::SP) * 8),
            rx::rax,
            true
        );

        e.xor_reg_reg(rx::rcx, rx::rcx, true);
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.regs_base + vm_.slot_of_xreg(XReg::SP) * 8 + 4),
            rx::rcx,
            true
        );

        // seed the bottom of the shadow stack with exit_handler
        x86_self_locate(e, rx::rcx, FixupKind::VMExit);
        e.mov_mem_reg(
            rx::rax,
            0,
            rx::rcx,
            true
        );

        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.saved_native_rsp),
            rx::rsp,
            true
        );

        e.xor_reg_reg(rx::rax, rx::rax, true);
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.saved_native_rsp) + 4,
            rx::rax,
            true
        );

        e.xor_reg_reg(rx::rax, rx::rax, true);
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.call_sp),
            rx::rax,
            true
        );

        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.call_sp) + 4,
            rx::rax,
            true
        );

        // copy sbox_inv table from the embedded blob to cipher_extra+256, 256
        // bytes total
        x86_self_locate(
            e,
            cfg.scratch_a,
            FixupKind::DataIsland,
            /*data=*/0xFFFFFFFFFFFFFFFFULL
        );

        e.lea_reg_mem(
            cfg.scratch_b,
            cfg.state_ptr,
            rx::none,
            0,
            static_cast<std::int32_t>(st.cipher_extra) + 256
        );

        e.push_reg(rx::rsi);
        e.push_reg(rx::rdi);
        e.mov_reg_reg(rx::rsi, cfg.scratch_a, true);
        e.mov_reg_reg(rx::rdi, cfg.scratch_b, true);
        e.mov_reg_imm32(rx::rcx, 64, true); // 64 dwords, 256 bytes
        e.u8(0xFC);                         // cld
        e.u8(0xF3); e.u8(0xA5);             // rep movsd
        e.pop_reg(rx::rdi);
        e.pop_reg(rx::rsi);

        // data-region decrypt
        const std::uint32_t cinit32 = static_cast<std::uint32_t>(vm_.cipher_init_state());

        // counter_reg = third_volatile, cipher_state in rbx
        std::uint8_t counter_reg = rx::rax;
        for (auto v : {rx::rax, rx::rcx, rx::rdx}) {
            if (v != cfg.scratch_a && v != cfg.scratch_b) { counter_reg = v; break; }
        }

        auto emit_decrypt_loop_x86 = [&](FixupKind kind, std::uint32_t byte_count) {
            x86_self_locate(e, cfg.ip, kind);
            x86_self_locate(e, cfg.scratch_b, kind);
            e.mov_reg_imm32(counter_reg, static_cast<std::int32_t>(byte_count), true);
            e.mov_reg_imm32(cfg.scratch_a, static_cast<std::int32_t>(cinit32), true);
            e.mov_reg_reg(cfg.cipher_state, cfg.scratch_a, true);

            auto lbl_loop = e.new_label();
            e.bind(lbl_loop);
            emit_fetch_byte_dec(e, vm_, cfg.scratch_a);
            e.u8(0x88);
            e.emit_modrm_mem(
                cfg.scratch_a & 7,
                cfg.scratch_b,
                rx::none,
                0,
                0
            );

            e.inc_reg(cfg.scratch_b, true);
            e.dec_reg(counter_reg, true);
            e.test_reg_reg(counter_reg, counter_reg, true);
            e.jcc_label(cc::nz, lbl_loop);
        };

        auto lbl_skip_decrypts_x86 = e.new_label();
        {
            x86_self_locate(e, cfg.scratch_a, FixupKind::InitFlag);
            e.u8(0x80);

            e.emit_modrm_mem(
                7,
                cfg.scratch_a,
                rx::none,
                0,
                0
            );

            e.u8(0);
            e.jcc_label(cc::nz, lbl_skip_decrypts_x86);
        }

        // data-region decrypt stays in the prologue for default/range mode
        // because lifted VM LOAD/STORE need plaintext
        if (data_island_size > 0 && !vm_.pack_mode()) {
            emit_decrypt_loop_x86(FixupKind::DataIsland, static_cast<std::uint32_t>(data_island_size));
        }

        if (block_table_count > 0) {
            emit_decrypt_loop_x86(FixupKind::BlockTable, block_table_count * 8);
        }

        // runtime nonce
        constexpr std::int32_t kRuntimeNonceOff_x86 = 80;
        constexpr std::int32_t kCipherInitOffLocal  = 48;
        {
            // rdtsc into edx:eax
            e.u8(0x0F); e.u8(0x31);
            e.xor_reg_reg(rx::rax, rx::rdx, true);

            // xor eax with the stored cipher_init
            e.u8(0x33);
            e.emit_modrm_mem(
                0 /*eax*/,
                cfg.state_ptr,
                rx::none,
                0,
                static_cast<std::int32_t>(st.cipher_extra) + kCipherInitOffLocal
            );

            e.mov_mem_reg(
                cfg.state_ptr,
                static_cast<std::int32_t>(st.cipher_extra) + kRuntimeNonceOff_x86,
                rx::rax,
                true
            );

            // zero upper 4 bytes of the slot
            e.xor_reg_reg(rx::rax, rx::rax, true);
            e.mov_mem_reg(
                cfg.state_ptr,
                static_cast<std::int32_t>(st.cipher_extra) + kRuntimeNonceOff_x86 + 4,
                rx::rax,
                true
            );

            // dump lo+hi dword into the blob slot so entry 2+ can recover
            // the nonce. per-entry VMState lives on stack and dies between
            // entries, same retarded story as x64.
            e.mov_reg_mem(
                rx::rax,
                cfg.state_ptr,
                static_cast<std::int32_t>(st.cipher_extra) + kRuntimeNonceOff_x86,
                true
            );
            x86_self_locate(e, cfg.scratch_b, FixupKind::RuntimeNonce);
            e.mov_mem_reg(cfg.scratch_b, 0, rx::rax, true);
            e.mov_reg_mem(
                rx::rax,
                cfg.state_ptr,
                static_cast<std::int32_t>(st.cipher_extra) + kRuntimeNonceOff_x86 + 4,
                true
            );
            e.mov_mem_reg(cfg.scratch_b, 4, rx::rax, true);
        }

        emit_decrypt_loop_x86(FixupKind::HandlerTable, 256 * 4);

        // post-decrypt
        {
            x86_self_locate(e, cfg.scratch_b, FixupKind::HandlerTable);
            e.mov_reg_mem(
                cfg.scratch_a,
                cfg.state_ptr,
                static_cast<std::int32_t>(st.cipher_extra) + kRuntimeNonceOff_x86,
                true
            );

            e.mov_reg_imm32(counter_reg, 256, true);
            auto lbl_xor_loop = e.new_label();
            e.bind(lbl_xor_loop);

            // xor dword [scratch_b], scratch_a
            e.u8(0x31);
            e.emit_modrm_mem(
                cfg.scratch_a & 7,
                cfg.scratch_b,
                rx::none,
                0,
                0
            );

            e.add_reg_imm32(cfg.scratch_b, 4, true);
            e.dec_reg(counter_reg, true);
            e.test_reg_reg(counter_reg, counter_reg, true);
            e.jcc_label(cc::nz, lbl_xor_loop);
        }

        {
            x86_self_locate(e, cfg.scratch_a, FixupKind::InitFlag);
            e.u8(0xC6);
            e.emit_modrm_mem(
                0,
                cfg.scratch_a,
                rx::none,
                0,
                0
            );
            e.u8(1);
        }
        e.bind(lbl_skip_decrypts_x86);

        // copy blob nonce into VMState slot, every entry, no exceptions.
        // same shit as x64. without this entry 2 reads stack garbage and
        // dispatch lookups go straight into the weeds.
        {
            x86_self_locate(e, cfg.scratch_b, FixupKind::RuntimeNonce);
            e.mov_reg_mem(rx::rax, cfg.scratch_b, 0, true);
            e.mov_mem_reg(
                cfg.state_ptr,
                static_cast<std::int32_t>(st.cipher_extra) + kRuntimeNonceOff_x86,
                rx::rax,
                true
            );
            e.mov_reg_mem(rx::rax, cfg.scratch_b, 4, true);
            e.mov_mem_reg(
                cfg.state_ptr,
                static_cast<std::int32_t>(st.cipher_extra) + kRuntimeNonceOff_x86 + 4,
                rx::rax,
                true
            );
        }

        // set ip to bytecode start. cipher_state reset deferred to the very
        // end of emit_state_init
        x86_self_locate(e, cfg.ip, FixupKind::Bytecode);

        // data_island_base via self-locate, points at the now-plaintext bytes.
        x86_self_locate(e, rx::rax, FixupKind::DataIsland);
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.data_island_base),
            rx::rax,
            true
        );

        e.xor_reg_reg(rx::rax, rx::rax, true);
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.data_island_base) + 4,
            rx::rax,
            true
        );

        x86_self_locate(e, rx::rax, FixupKind::BlockTable);
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.block_table_base),
            rx::rax,
            true
        );

        e.xor_reg_reg(rx::rax, rx::rax, true);
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.block_table_base) + 4,
            rx::rax,
            true
        );

        e.mov_reg_imm32(rx::rax, static_cast<std::int32_t>(block_table_count), true);
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.block_table_count),
            rx::rax,
            true
        );

        e.xor_reg_reg(rx::rax, rx::rax, true);
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.block_table_count) + 4,
            rx::rax,
            true
        );

        x86_self_locate(e, rx::rax, FixupKind::TrampolineBase);
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.trampoline_base),
            rx::rax,
            true
        );

        e.xor_reg_reg(rx::rax, rx::rax, true);
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.trampoline_base) + 4,
            rx::rax,
            true
        );

        // bytecode_base = ip
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.bytecode_base),
            cfg.ip,
            true
        );

        e.xor_reg_reg(rx::rax, rx::rax, true);
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.bytecode_base) + 4,
            rx::rax,
            true
        );

        // cipher_state reset
        e.mov_reg_imm32(cfg.scratch_a, static_cast<std::int32_t>(cinit32), true);
        e.mov_reg_reg(cfg.cipher_state, cfg.scratch_a, true);
    }

    // x86 version of --ranges hybrid mode
    void VMCodeGen::emit_range_entry(X86Emitter& e, std::uint32_t bytecode_offset,
                                     std::size_t data_island_size,
                                     std::uint32_t block_table_count) {
        const auto& cfg = vm_.dispatcher_regs();
        const auto& st  = vm_.state_layout();

        emit_prologue(e, data_island_size);

        const std::uint32_t frame_size = static_cast<std::uint32_t>(vm_.state_layout().total_size) + vm_.shadow_stack_bytes() + 256;
        const std::uint32_t aligned_frame = (frame_size + 15) & ~15u;

        // volatile GPRs eax/ecx/edx into VM slot low halves.
        auto write_slot_lo = [&](XReg xr, std::uint8_t host_reg) {
            e.mov_mem_reg(
                cfg.state_ptr,
                static_cast<std::int32_t>(st.regs_base + vm_.slot_of_xreg(xr) * 8),
                host_reg,
                true
            );
        };

        write_slot_lo(XReg::AX, rx::rax);
        write_slot_lo(XReg::CX, rx::rcx);
        write_slot_lo(XReg::DX, rx::rdx);

        // zero the upper halves of the GPR slots we just wrote and of the NV
        // slots we'll fill below
        e.xor_reg_reg(rx::rax, rx::rax, true);
        auto zero_slot_hi = [&](XReg xr) {
            e.mov_mem_reg(
                cfg.state_ptr,
                static_cast<std::int32_t>(st.regs_base + vm_.slot_of_xreg(xr) * 8 + 4),
                rx::rax,
                true
            );
        };

        zero_slot_hi(XReg::AX);
        zero_slot_hi(XReg::CX);
        zero_slot_hi(XReg::DX);

        // saved NV regs from the host stack into VM slots
        auto it = g_x86_prologue_orders.find(&e);
        if (it == g_x86_prologue_orders.end()) throw Error("emit_range_entry x86: missing prologue order");

        auto host_to_xreg = [](std::uint8_t r) -> XReg {
            if (r == rx::rbx) return XReg::BX;
            if (r == rx::rbp) return XReg::BP;
            if (r == rx::rdi) return XReg::DI;
            if (r == rx::rsi) return XReg::SI;
            return XReg::Invalid;
        };

        for (std::size_t i = 0; i < it->second.order.size(); ++i) {
            const std::uint8_t nv_reg = it->second.order[i];
            const XReg xr = host_to_xreg(nv_reg);
            if (xr == XReg::Invalid) throw Error("emit_range_entry x86: unmapped NV reg");
            const std::int32_t stack_off = static_cast<std::int32_t>(aligned_frame) + 4 + (3 - static_cast<std::int32_t>(i)) * 4;

            // eax = host stack slot
            e.mov_reg_mem(
                rx::rax,
                rx::rsp,
                stack_off,
                true
            );

            // VM slot lo
            e.mov_mem_reg(
                cfg.state_ptr,
                static_cast<std::int32_t>(st.regs_base + vm_.slot_of_xreg(xr) * 8),
                rx::rax,
                true
            );

            // VM slot hi zero
            e.xor_reg_reg(rx::rax, rx::rax, true);
            e.mov_mem_reg(
                cfg.state_ptr,
                static_cast<std::int32_t>(st.regs_base + vm_.slot_of_xreg(xr) * 8 + 4),
                rx::rax,
                true
            );
        }

        // state init proper, skip the regs[] zero because we just marshalled
        // values in.
        emit_state_init(
            e,
            /*bytecode_size=*/0,
            data_island_size,
            block_table_count,
            /*skip_regs_zero=*/true
        );

        // push exit_handler_addr onto VM shadow stack so the lifted ret becomes
        // RET_VM, pops this, and lands in exit_handler
        x86_self_locate(e, rx::rax, FixupKind::VMExit);
        const std::uint8_t sp_slot = vm_.slot_of_xreg(XReg::SP);
        const std::int32_t sp_off  = static_cast<std::int32_t>(st.regs_base + sp_slot * 8);

        // ecx = current VM_RSP low 32 bits
        e.mov_reg_mem(
            rx::rcx,
            cfg.state_ptr,
            sp_off,
            true
        );

        e.sub_reg_imm32(rx::rcx, 4, true); // 4-byte push on x86
        e.mov_mem_reg(
            cfg.state_ptr,
            sp_off,
            rx::rcx,
            true
        );

        e.mov_mem_reg(
            rx::rcx,
            0,
            rx::rax,
            true
        ); // [VM_RSP] = exit_handler

        if (bytecode_offset != 0) {
            e.add_reg_imm32(cfg.ip, static_cast<std::int32_t>(bytecode_offset), true);
        }

        emit_dispatch_tail(e, vm_);
    }

    void VMCodeGen::emit_trampoline(X86Emitter& e, std::uint32_t bytecode_offset) {
        const auto& cfg = vm_.dispatcher_regs();
        const auto& st  = vm_.state_layout();
        constexpr std::int32_t kCipherInitOff = 48;
        constexpr std::int32_t kSavedHbOff    = 24;
        constexpr std::int32_t kSavedCsOff    = 32;

        // save host eax to VM_AX, x86 ABI return reg.
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.regs_base + vm_.slot_of_xreg(XReg::AX) * 8),
            rx::rax,
            true
        );

        // writeback host esp to VM_ESP
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.regs_base + vm_.slot_of_xreg(XReg::SP) * 8),
            rx::rsp,
            true
        );

        e.mov_reg_mem(
            rx::rsp,
            cfg.state_ptr,
            static_cast<std::int32_t>(st.saved_native_rsp),
            true
        );

        e.mov_reg_mem(
            cfg.handler_base,
            cfg.state_ptr,
            static_cast<std::int32_t>(st.cipher_extra) + kSavedHbOff,
            true
        );

        e.mov_reg_mem(
            cfg.cipher_state,
            cfg.state_ptr,
            static_cast<std::int32_t>(st.cipher_extra) + kSavedCsOff,
            true
        );

        e.mov_reg_mem(
            cfg.ip,
            cfg.state_ptr,
            static_cast<std::int32_t>(st.bytecode_base),
            true
        );

        if (bytecode_offset != 0) {
            e.add_reg_imm32(cfg.ip, static_cast<std::int32_t>(bytecode_offset), true);
        }

        // fresh block boundary, reset cipher.
        e.mov_reg_mem(
            cfg.cipher_state,
            cfg.state_ptr,
            static_cast<std::int32_t>(st.cipher_extra) + kCipherInitOff,
            true
        );

        emit_dispatch_tail(e, vm_);
    }

    void VMCodeGen::emit_handler_table(X86Emitter&) {}

    void VMCodeGen::emit_all_handlers(X86Emitter& e) {
        const auto& order = codecs_.by_order();

        // one shared `jmp VMExit` for every unused codec slot
        const std::size_t shared_unused = e.size();
        e.u8(0xE9);
        e.emit_rel32_fixup(static_cast<std::uint32_t>(FixupKind::VMExit), 0, 0);

        for (std::size_t op = 0; op < 256; ++op) {
            const Codec* c = order[op];
            const bool used = !prune_handlers_ || (c && used_families_.count(std::string(c->family())));

            if (!c || !used) {
                off_.handler_offsets[op] = shared_unused;
                continue;
            }

            off_.handler_offsets[op] = e.size();
            c->emit_handler(e, vm_);
        }
    }

    void VMCodeGen::emit_exit_handler(X86Emitter& e) {
        off_.exit_handler = e.size();
        const auto& cfg = vm_.dispatcher_regs();
        const auto& st  = vm_.state_layout();

        e.mov_reg_mem(
            rx::rsp,
            cfg.state_ptr,
            static_cast<std::int32_t>(st.saved_native_rsp),
            true
        );

        // return value: VM_AX into eax.
        e.mov_reg_mem(
            rx::rax,
            cfg.state_ptr,
            static_cast<std::int32_t>(st.regs_base + vm_.slot_of_xreg(XReg::AX) * 8),
            true
        );

        const std::uint32_t frame_size = static_cast<std::uint32_t>(vm_.state_layout().total_size) + vm_.shadow_stack_bytes() + 256;
        const std::uint32_t aligned = (frame_size + 15) & ~15u;
        e.add_reg_imm32(rx::rsp, static_cast<std::int32_t>(aligned));

        e.popfq(); // popfd opcode, same as x64 popfq
        auto it = g_x86_prologue_orders.find(&e);
        if (it == g_x86_prologue_orders.end()) throw Error("emit_exit_handler x86: missing prologue order");
        for (auto rit = it->second.order.rbegin(); rit != it->second.order.rend(); ++rit) {
            e.pop_reg(*rit);
        }
        e.ret();
    }

    void VMCodeGen::emit_full(X86Emitter& e,
                              std::size_t /*bytecode_size*/,
                              std::size_t data_island_size,
                              std::uint32_t block_table_count) {
        if (range_mode_) {
            off_.range_entries.assign(range_entry_bc_offsets_.size(), 0);
            for (std::size_t k = 0; k < range_entry_bc_offsets_.size(); ++k) {
                off_.range_entries[k] = e.size();
                emit_range_entry(e, range_entry_bc_offsets_[k], data_island_size, block_table_count);
            }
            off_.entry = off_.range_entries[0];
            off_.dispatch_entry = e.size(); // unused here
        }
        else {
            off_.entry = e.size();
            emit_prologue(e, data_island_size);
            emit_state_init(
                e,
                0,
                data_island_size,
                block_table_count
            );

            off_.dispatch_entry = e.size();
            emit_dispatch_tail(e, vm_);
        }

        off_.handler_table = e.size();
        off_.handler_offsets.assign(256, static_cast<std::size_t>(-1));

        for (int i = 0; i < 256; ++i) e.u32(0);

        // 1-byte init-done flag
        off_.init_flag = e.size();
        e.u8(0);

        // deferred data-island-decrypt flag
        off_.data_island_init_flag = e.size();
        e.u8(vm_.pack_mode() ? 0 : 1);

        // blob mirror of the runtime nonce, same dumbass story as x64
        off_.runtime_nonce_slot = e.size();
        for (int i = 0; i < 8; ++i) e.u8(0);

        emit_all_handlers(e);
        emit_exit_handler(e);
    }
}