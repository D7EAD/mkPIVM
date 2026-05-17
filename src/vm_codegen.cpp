#include "mkpivm/vm_codegen.h"

#include <cstdio>

namespace mkpivm {
    namespace {
        // remember the exact push order so the exit handler can pop in reverse.
        // keyed off the emitter pointer to avoid TLS bullshit.
        struct PrologueOrder {
            std::vector<std::uint8_t> order;
        };
    }

    VMCodeGen::VMCodeGen(const VMConfig& vm, const CodecRegistry& codecs, SeedRng& rng)
    : vm_{vm}, codecs_{codecs}, rng_{rng} {}

    void VMCodeGen::emit_full(X64Emitter& e, std::size_t /*bytecode_size*/, std::size_t data_island_size, std::uint32_t block_table_count) {
        if (range_mode_) {
            // hybrid mode. one full prologue+state_init+marshalling stub per range
            // up front, then the shared handler table and handlers go in once at
            // the end 
            off_.range_entries.assign(range_entry_bc_offsets_.size(), 0);

            for (std::size_t k = 0; k < range_entry_bc_offsets_.size(); ++k) {
                off_.range_entries[k] = e.size();
                emit_range_entry(e, range_entry_bc_offsets_[k], data_island_size, block_table_count);
            }

            // off_.entry is unused in range mode but the packager still reads it 
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

        // companion flag for the deferred data-island decrypt
        off_.data_island_init_flag = e.size();
        e.u8(vm_.pack_mode() ? 0 : 1);

        emit_all_handlers(e);
        emit_exit_handler(e);
    }

    // keyed by emitter pointer
    static std::unordered_map<const X64Emitter*, PrologueOrder> g_prologue_orders;

    void VMCodeGen::emit_prologue(X64Emitter& e, std::size_t /*data_island_size*/) {
        PrologueOrder po;
        if (!cached_nv_order_x64_set_) {
            std::array<std::uint8_t, 8> nv{rx::rbx, rx::rbp, rx::rdi, rx::rsi, rx::r12, rx::r13, rx::r14, rx::r15};
            shuffle_in_place(nv, rng_);
            cached_nv_order_x64_     = nv;
            cached_nv_order_x64_set_ = true;
        }

        for (auto r : cached_nv_order_x64_) {
            e.push_reg(r);
            po.order.push_back(r);
        }

        e.pushfq();
        g_prologue_orders[&e] = std::move(po);
        emit_junk(e, vm_, rng_);

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
        emit_junk(e, vm_, rng_);
    }

    void VMCodeGen::emit_state_init(X64Emitter& e, std::size_t, std::size_t data_island_size,
                                    std::uint32_t block_table_count, bool skip_regs_zero) {
        const auto& cfg = vm_.dispatcher_regs();
        const auto& st  = vm_.state_layout();

        // zero VM regs[]
        if (!skip_regs_zero) {
            const std::uint8_t zpool[7] = {rx::rax, rx::rcx, rx::rdx, rx::r8, rx::r9, rx::r10, rx::r11};
            SeedRng zero_rng(vm_.cipher_init_state() ^ 0x2E07117EU);
            
            for (std::uint8_t i = 0; i < vm_.reg_count(); ++i) {
                const std::uint8_t Z = zpool[zero_rng.pick(7)];
                e.xor_reg_reg(Z, Z);
                e.mov_mem_reg(
                    cfg.state_ptr,
                    static_cast<std::int32_t>(st.regs_base + i * 8),
                    Z,
                    true
                );
            }
        }

        // cipher state init, random per seed
        e.mov_reg_imm64(rx::rax, vm_.cipher_init_state());
        e.mov_reg_reg(cfg.cipher_state, rx::rax);
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.cipher_extra) + 48,
            rx::rax,
            true
        );

        // mult/add constants into VMState slots
        std::uint64_t mult = 0, add = 0;
        switch (vm_.cipher_kind()) {
            case CipherKind::ARX:         mult = 0;                     add = vm_.cipher_k1(); break;
            case CipherKind::LcgSub:      mult = 0x5851F42D4C957F2DULL; add = vm_.cipher_k1(); break;
            case CipherKind::SBoxAdd:     mult = 0x100000001B3ULL;      add = vm_.cipher_k1(); break;
            case CipherKind::FeistelByte: mult = vm_.cipher_k1();       add = vm_.cipher_k2(); break;
        }
        constexpr std::int32_t kCipherAddOff  = 0;
        constexpr std::int32_t kCipherMultOff = 8;

        e.mov_reg_imm64(rx::rax, add);
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.cipher_extra) + kCipherAddOff,
            rx::rax,
            true
        );

        e.mov_reg_imm64(rx::rax, mult);
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.cipher_extra) + kCipherMultOff,
            rx::rax,
            true
        );

        auto h_slot = e.lea_reg_rip(cfg.handler_base, 0);
        e.add_fixup(
            h_slot,
            static_cast<std::uint32_t>(FixupKind::HandlerTable),
            0,
            0
        );

        auto ip_slot = e.lea_reg_rip(cfg.ip, 0);
        e.add_fixup(
            ip_slot,
            static_cast<std::uint32_t>(FixupKind::Bytecode),
            0,
            0
        );

        // VM_RSP = state_ptr - 8, top of the shadow stack right below VMState.
        e.mov_reg_reg(rx::rax, cfg.state_ptr);
        e.sub_reg_imm32(rx::rax, 8);
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.regs_base + vm_.slot_of_xreg(XReg::SP) * 8),
            rx::rax,
            true
        );

        // seed the bottom of the shadow stack with exit_handler's address
        auto exit_slot = e.lea_reg_rip(rx::rcx, 0);
        e.add_fixup(
            exit_slot,
            static_cast<std::uint32_t>(FixupKind::VMExit),
            0,
            0
        );

        e.mov_mem_reg(
            rx::rax,
            0,
            rx::rcx,
            true
        );

        // saved_native_rsp for the exit handler.
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.saved_native_rsp),
            rx::rsp,
            true
        );

        e.xor_reg_reg(rx::rax, rx::rax);
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.call_sp),
            rx::rax,
            true
        );

        // copy sbox_inv table from the rip-relative blob into cipher_extra+256
        auto sbox_slot = e.lea_reg_rip(cfg.scratch_a, 0);
        e.add_fixup(
            sbox_slot,
            static_cast<std::uint32_t>(FixupKind::DataIsland),
            /*data=*/0xFFFFFFFFFFFFFFFFULL,
            /*addend=*/0
        );

        e.lea_reg_mem(
            cfg.scratch_b,
            cfg.state_ptr,
            rx::none,
            0,
            static_cast<std::int32_t>(st.cipher_extra) + 256
        );

        e.mov_reg_imm32(rx::rcx, 32);
        auto lbl_loop = e.new_label();
        e.bind(lbl_loop);
        e.mov_reg_mem(
            rx::rax,
            cfg.scratch_a,
            0,
            true
        );

        e.mov_mem_reg(
            cfg.scratch_b,
            0,
            rx::rax,
            true
        );

        e.add_reg_imm32(cfg.scratch_a, 8);
        e.add_reg_imm32(cfg.scratch_b, 8);
        e.dec_reg(rx::rcx, true);
        e.test_reg_reg(rx::rcx, rx::rcx);
        e.jcc_label(cc::nz, lbl_loop);

        // the three in-place decrypts for data island, block table and handler
        // table must run exactly once per blob load
        auto lbl_skip_decrypts = e.new_label();
        {
            auto flag_lea = e.lea_reg_rip(rx::rax, 0);
            e.add_fixup(
                flag_lea,
                static_cast<std::uint32_t>(FixupKind::InitFlag),
                0,
                0
            );

            // cmp byte [rax], 0
            e.u8(0x80);
            e.emit_modrm_mem(
                7,
                rx::rax,
                rx::none,
                0,
                0
            );

            e.u8(0);
            e.jcc_label(cc::nz, lbl_skip_decrypts);
        }

        // data island decrypt in place
        if (data_island_size > 0 && !vm_.pack_mode()) {
            auto src_slot = e.lea_reg_rip(cfg.ip, 0);
            e.add_fixup(
                src_slot,
                static_cast<std::uint32_t>(FixupKind::DataIsland),
                0,
                0
            );

            auto dst_slot = e.lea_reg_rip(cfg.scratch_b, 0);
            e.add_fixup(
                dst_slot,
                static_cast<std::uint32_t>(FixupKind::DataIsland),
                0,
                0
            );

            e.mov_reg_imm32(rx::rcx, static_cast<std::int32_t>(data_island_size));
            e.mov_reg_imm64(rx::rax, vm_.cipher_init_state());
            e.mov_reg_reg(cfg.cipher_state, rx::rax);

            auto lbl_dec_loop = e.new_label();
            e.bind(lbl_dec_loop);
            emit_fetch_byte_dec(e, vm_, rx::rax);
            e.emit_rex(
                false,
                false,
                false,
                cfg.scratch_b >= 8
            );

            e.u8(0x88);
            e.emit_modrm_mem(
                0 /*al*/,
                cfg.scratch_b,
                rx::none,
                0,
                0
            );

            e.inc_reg(cfg.scratch_b, true);
            e.dec_reg(rx::rcx, true);
            e.test_reg_reg(rx::rcx, rx::rcx);
            e.jcc_label(cc::nz, lbl_dec_loop);
        }

        // block-table decrypt, same scheme as data island
        if (block_table_count > 0) {
            auto src_slot = e.lea_reg_rip(cfg.ip, 0);
            e.add_fixup(
                src_slot,
                static_cast<std::uint32_t>(FixupKind::BlockTable),
                0,
                0
            );

            auto dst_slot = e.lea_reg_rip(cfg.scratch_b, 0);
            e.add_fixup(
                dst_slot,
                static_cast<std::uint32_t>(FixupKind::BlockTable),
                0,
                0
            );

            e.mov_reg_imm32(rx::rcx, static_cast<std::int32_t>(block_table_count) * 8);

            // fresh cipher restart, independent of the island stream.
            e.mov_reg_imm64(rx::rax, vm_.cipher_init_state());
            e.mov_reg_reg(cfg.cipher_state, rx::rax);

            auto lbl_bt_loop = e.new_label();
            e.bind(lbl_bt_loop);
            emit_fetch_byte_dec(e, vm_, rx::rax);
            e.emit_rex(
                false,
                false,
                false,
                cfg.scratch_b >= 8
            );

            e.u8(0x88);
            e.emit_modrm_mem(
                0 /*al*/,
                cfg.scratch_b,
                rx::none,
                0,
                0
            );

            e.inc_reg(cfg.scratch_b, true);
            e.dec_reg(rx::rcx, true);
            e.test_reg_reg(rx::rcx, rx::rcx);
            e.jcc_label(cc::nz, lbl_bt_loop);
        }

        // runtime nonce
        constexpr std::int32_t kRuntimeNonceOff = 80;
        {
            // rdtsc gives edx:eax
            e.u8(0x0F); e.u8(0x31);
            e.shl_reg_imm8(rx::rdx, 32, true);
            e.or_reg_reg(rx::rax, rx::rdx, true);

            // xor rax with the stored cipher_init
            e.emit_rex(
                true,
                false,
                false,
                cfg.state_ptr >= 8
            );

            e.u8(0x33);
            e.emit_modrm_mem(
                0 /*rax*/,
                cfg.state_ptr,
                rx::none,
                0,
                static_cast<std::int32_t>(st.cipher_extra) + 48
            );

            e.mov_mem_reg(
                cfg.state_ptr,
                static_cast<std::int32_t>(st.cipher_extra) + kRuntimeNonceOff,
                rx::rax,
                true
            );
        }

        // handler-table decrypt, always runs since the table is fixed 1024 bytes
        {
            auto src_slot = e.lea_reg_rip(cfg.ip, 0);
            e.add_fixup(
                src_slot,
                static_cast<std::uint32_t>(FixupKind::HandlerTable),
                0,
                0
            );

            auto dst_slot = e.lea_reg_rip(cfg.scratch_b, 0);
            e.add_fixup(
                dst_slot,
                static_cast<std::uint32_t>(FixupKind::HandlerTable),
                0,
                0
            );

            e.mov_reg_imm32(rx::rcx, 256 * 4);

            // independent stream restart, has to match the build-time
            // encrypt_inplace call on handler_table_bytes.
            e.mov_reg_imm64(rx::rax, vm_.cipher_init_state());
            e.mov_reg_reg(cfg.cipher_state, rx::rax);

            auto lbl_ht_loop = e.new_label();
            e.bind(lbl_ht_loop);
            emit_fetch_byte_dec(e, vm_, rx::rax);
            e.emit_rex(
                false,
                false,
                false,
                cfg.scratch_b >= 8
            );
            e.u8(0x88);

            e.emit_modrm_mem(
                0 /*al*/,
                cfg.scratch_b,
                rx::none,
                0,
                0
            );

            e.inc_reg(cfg.scratch_b, true);
            e.dec_reg(rx::rcx, true);
            e.test_reg_reg(rx::rcx, rx::rcx);
            e.jcc_label(cc::nz, lbl_ht_loop);
        }

        // post-decrypt pass
        {
            auto dst_slot = e.lea_reg_rip(cfg.scratch_b, 0);
            e.add_fixup(
                dst_slot,
                static_cast<std::uint32_t>(FixupKind::HandlerTable),
                0,
                0
            );

            e.mov_reg_mem(
                rx::rax,
                cfg.state_ptr,
                static_cast<std::int32_t>(st.cipher_extra) + kRuntimeNonceOff,
                true
            );

            e.mov_reg_imm32(rx::rcx, 256);
            auto lbl_xor_loop = e.new_label();
            e.bind(lbl_xor_loop);

            // xor dword [scratch_b], eax. 32-bit, uses low half of rax.
            e.emit_rex(
                false,
                false,
                false,
                cfg.scratch_b >= 8
            );

            e.u8(0x31);
            e.emit_modrm_mem(
                0 /*eax*/,
                cfg.scratch_b,
                rx::none,
                0,
                0
            );

            e.add_reg_imm32(cfg.scratch_b, 4);
            e.dec_reg(rx::rcx, true);
            e.test_reg_reg(rx::rcx, rx::rcx);
            e.jcc_label(cc::nz, lbl_xor_loop);
        }

        // flip init_flag so later vm_entry stubs skip the decrypts.
        {
            auto flag_lea = e.lea_reg_rip(rx::rax, 0);
            e.add_fixup(
                flag_lea,
                static_cast<std::uint32_t>(FixupKind::InitFlag),
                0,
                0
            );

            // mov byte [rax], 1
            e.u8(0xC6);
            e.emit_modrm_mem(
                0,
                rx::rax,
                rx::none,
                0,
                0
            );

            e.u8(1);
        }
        e.bind(lbl_skip_decrypts);

        // reset cipher_state and ip for bytecode dispatch
        {
            e.mov_reg_imm64(rx::rax, vm_.cipher_init_state());
            e.mov_reg_reg(cfg.cipher_state, rx::rax);
            auto ip_reset = e.lea_reg_rip(cfg.ip, 0);

            e.add_fixup(
                ip_reset,
                static_cast<std::uint32_t>(FixupKind::Bytecode),
                0,
                0
            );
        }

        auto di_slot = e.lea_reg_rip(rx::rax, 0);
        e.add_fixup(
            di_slot,
            static_cast<std::uint32_t>(FixupKind::DataIsland),
            0,
            0
        );

        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.data_island_base),
            rx::rax,
            true
        );

        auto bt_slot = e.lea_reg_rip(rx::rax, 0);
        e.add_fixup(
            bt_slot,
            static_cast<std::uint32_t>(FixupKind::BlockTable),
            0,
            0
        );

        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.block_table_base),
            rx::rax,
            true
        );

        // block_table_count baked into the prologue as a per-blob constant.
        e.mov_reg_imm32(rx::rax, static_cast<std::int32_t>(block_table_count));
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.block_table_count),
            rx::rax,
            true
        );

        auto tr_slot = e.lea_reg_rip(rx::rax, 0);
        e.add_fixup(
            tr_slot,
            static_cast<std::uint32_t>(FixupKind::TrampolineBase),
            0,
            0
        );

        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.trampoline_base),
            rx::rax,
            true
        );

        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.bytecode_base),
            cfg.ip,
            true
        );

        emit_junk(e, vm_, rng_);
    }

    // --ranges hybrid mode entry stub
    void VMCodeGen::emit_range_entry(X64Emitter& e, std::uint32_t bytecode_offset,
                                     std::size_t data_island_size,
                                     std::uint32_t block_table_count) {
        const auto& cfg = vm_.dispatcher_regs();
        const auto& st  = vm_.state_layout();

        emit_prologue(e, data_island_size);

        // frame size has to match what emit_prologue computed.
        const std::uint32_t frame_size = static_cast<std::uint32_t>(vm_.state_layout().total_size) + vm_.shadow_stack_bytes() + 256;
        const std::uint32_t aligned_frame = (frame_size + 15) & ~15u;

        // host volatile GPRs into VM slots
        auto write_slot = [&](XReg xr, std::uint8_t host_reg) {
            e.mov_mem_reg(
                cfg.state_ptr,
                static_cast<std::int32_t>(st.regs_base + vm_.slot_of_xreg(xr) * 8),
                host_reg,
                true
            );
        };

        write_slot(XReg::AX,  rx::rax);
        write_slot(XReg::CX,  rx::rcx);
        write_slot(XReg::DX,  rx::rdx);
        write_slot(XReg::R8,  rx::r8);
        write_slot(XReg::R9,  rx::r9);
        write_slot(XReg::R10, rx::r10);
        write_slot(XReg::R11, rx::r11);

        // saved NV regs from the host stack into VM slots
        auto it = g_prologue_orders.find(&e);
        if (it == g_prologue_orders.end()) throw Error("emit_range_entry: missing prologue order");

        auto host_to_xreg = [](std::uint8_t r) -> XReg {
            if (r == rx::rbx) return XReg::BX;
            if (r == rx::rbp) return XReg::BP;
            if (r == rx::rdi) return XReg::DI;
            if (r == rx::rsi) return XReg::SI;
            if (r == rx::r12) return XReg::R12;
            if (r == rx::r13) return XReg::R13;
            if (r == rx::r14) return XReg::R14;
            if (r == rx::r15) return XReg::R15;
            return XReg::Invalid;
        };

        for (std::size_t i = 0; i < it->second.order.size(); ++i) {
            const std::uint8_t nv_reg = it->second.order[i];
            const XReg xr = host_to_xreg(nv_reg);
            if (xr == XReg::Invalid) throw Error("emit_range_entry: unmapped NV reg in prologue order");
            const std::int32_t stack_off = static_cast<std::int32_t>(aligned_frame) + 64 - 8 * static_cast<std::int32_t>(i);

            e.mov_reg_mem(
                rx::rax,
                rx::rsp,
                stack_off,
                true
            );

            e.mov_mem_reg(
                cfg.state_ptr,
                static_cast<std::int32_t>(st.regs_base + vm_.slot_of_xreg(xr) * 8),
                rx::rax,
                true
            );
        }

        // state init proper, skip the regs[] zero loop because we already
        // marshalled values into those slots
        emit_state_init(
            e,
            /*bytecode_size=*/0,
            data_island_size,
            block_table_count,
            /*skip_regs_zero=*/true
        );

        // push exit_handler_addr onto the VM shadow stack
        auto exit_slot = e.lea_reg_rip(rx::rax, 0);
        e.add_fixup(
            exit_slot,
            static_cast<std::uint32_t>(FixupKind::VMExit),
            0,
            0
        );

        const std::uint8_t sp_slot = vm_.slot_of_xreg(XReg::SP);
        const std::int32_t sp_off  = static_cast<std::int32_t>(st.regs_base + sp_slot * 8);
        e.mov_reg_mem(
            rx::rcx,
            cfg.state_ptr,
            sp_off,
            true
        );

        e.sub_reg_imm32(rx::rcx, 8);
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
        );

        if (bytecode_offset != 0) {
            e.add_reg_imm32(cfg.ip, static_cast<std::int32_t>(bytecode_offset));
        }

        emit_dispatch_tail(e, vm_);
    }

    // one trampoline per call site
    void VMCodeGen::emit_trampoline(X64Emitter& e, std::uint32_t bytecode_offset) {
        const auto& cfg = vm_.dispatcher_regs();
        const auto& st  = vm_.state_layout();
        constexpr std::int32_t kCipherInitOff = 48;
        constexpr std::int32_t kSavedHbOff    = 24;
        constexpr std::int32_t kSavedCsOff    = 32;

        // save host rax to VM_AX
        e.mov_mem_reg(
            cfg.state_ptr,
            static_cast<std::int32_t>(st.regs_base + vm_.slot_of_xreg(XReg::AX) * 8),
            rx::rax,
            true
        );

        // writeback host rsp to VM_RSP
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
            e.add_reg_imm32(cfg.ip, static_cast<std::int32_t>(bytecode_offset));
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

    void VMCodeGen::emit_handler_table(X64Emitter&) {}

    void VMCodeGen::emit_all_handlers(X64Emitter& e) {
        const auto& order = codecs_.by_order();

        // one shared `jmp VMExit` for every unused-codec slot
        // dont be retarded and give unused codecs
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
            emit_junk(e, vm_, rng_);
            c->emit_handler(e, vm_);
        }
    }

    void VMCodeGen::emit_exit_handler(X64Emitter& e) {
        off_.exit_handler = e.size();
        const auto& cfg = vm_.dispatcher_regs();
        const auto& st  = vm_.state_layout();

        e.mov_reg_mem(
            rx::rsp,
            cfg.state_ptr,
            static_cast<std::int32_t>(st.saved_native_rsp),
            true
        );

        // return value: VM_AX into rax
        e.mov_reg_mem(
            rx::rax,
            cfg.state_ptr,
            static_cast<std::int32_t>(st.regs_base + vm_.slot_of_xreg(XReg::AX) * 8),
            true
        );

        const std::uint32_t frame_size = static_cast<std::uint32_t>(vm_.state_layout().total_size) + vm_.shadow_stack_bytes() + 256;
        const std::uint32_t aligned = (frame_size + 15) & ~15u;
        e.add_reg_imm32(rx::rsp, static_cast<std::int32_t>(aligned));
        e.popfq();
        auto it = g_prologue_orders.find(&e);
        if (it == g_prologue_orders.end()) throw Error("emit_exit_handler: missing prologue order");

        for (auto rit = it->second.order.rbegin(); rit != it->second.order.rend(); ++rit) {
            e.pop_reg(*rit);
        }

        e.ret();
    }
}