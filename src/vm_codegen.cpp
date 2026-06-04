#include "mkpivm/vm_codegen.h"

#include <array>
#include <cstdio>
#include <functional>
#include <vector>

namespace mkpivm {
    namespace {
        // remember the exact push order so the exit handler can pop in reverse.
        // keyed off the emitter pointer to avoid TLS bullshit.
        struct PrologueOrder {
            std::vector<std::uint8_t> order;
        };

        // Emit a Win64 call
        void emit_vprotect_call_x64(X64Emitter& e, const VMConfig& vm, std::uint32_t new_protect) {
            const auto& cfg = vm.dispatcher_regs();
            const auto& st  = vm.state_layout();

            // sub rsp, 0x30: 32B shadow space + 16B alignment maintenance
            e.sub_reg_imm32(rx::rsp, 0x30);

            // rcx = &data_island via RIP-relative LEA with DataIsland fixup
            auto rcx_lea = e.lea_reg_rip(rx::rcx, 0);
            e.add_fixup(
                rcx_lea,
                static_cast<std::uint32_t>(FixupKind::DataIsland),
                0,
                0
            );

            // edx = size (zero-extended to rdx by 32-bit imm)
            e.mov_reg_imm32(rx::rdx, static_cast<std::int32_t>(vm.data_island_size()));

            // r8d = new_protect
            e.mov_reg_imm32(rx::r8, static_cast<std::int32_t>(new_protect));

            // r9 = state_ptr + vp_old slot (PDWORD &old)
            e.lea_reg_mem(
                rx::r9,
                cfg.state_ptr,
                rx::none,
                0,
                static_cast<std::int32_t>(st.vp_old)
            );

            // rax = [state_ptr + vp_addr]
            e.mov_reg_mem(
                rx::rax,
                cfg.state_ptr,
                static_cast<std::int32_t>(st.vp_addr),
                true
            );

            // call rax (FF /2 = D0)
            e.u8(0xFF);
            e.u8(0xD0);

            // add rsp, 0x30
            e.add_reg_imm32(rx::rsp, 0x30);
        }

        // Win32 PAGE_* constants
        constexpr std::uint32_t kPageReadWrite = 0x04;
        constexpr std::uint32_t kPageExecuteRead = 0x20;

        // salted ror13+add hash
        std::uint32_t ror_hash_module(const wchar_t* name, std::uint32_t salt) {
            std::uint32_t h = 0;
            for (; *name; ++name) {
                std::uint32_t c = static_cast<std::uint32_t>(*name);
                if (c >= L'A' && c <= L'Z') c += 32;
                h = ((h >> 13) | (h << 19)) + c;
            }
            return h ^ salt;
        }
        std::uint32_t ror_hash_api(const char* name, std::uint32_t salt) {
            std::uint32_t h = 0;
            for (; *name; ++name) {
                std::uint32_t c = static_cast<std::uint8_t>(*name);
                h = ((h >> 13) | (h << 19)) + c;
            }
            return h ^ salt;
        }

        // in-blob PEB walker
        void emit_resolve_vp_x64(X64Emitter& e, const VMConfig& vm) {
            const auto& cfg = vm.dispatcher_regs();
            const auto& st  = vm.state_layout();
            const std::uint32_t salt = static_cast<std::uint32_t>(vm.cipher_init_state() ^ 0xC0DEC0DEULL);
            const std::uint32_t hash_k32 = ror_hash_module(L"kernel32.dll", salt);
            const std::uint32_t hash_vp  = ror_hash_api("VirtualProtect", salt);

            auto lbl_mod_loop  = e.new_label();
            auto lbl_mod_hash  = e.new_label();
            auto lbl_mod_hdone = e.new_label();
            auto lbl_mod_skip_lc = e.new_label();
            auto lbl_mod_found = e.new_label();
            auto lbl_api_loop  = e.new_label();
            auto lbl_api_hash  = e.new_label();
            auto lbl_api_hdone = e.new_label();
            auto lbl_fail      = e.new_label();
            auto lbl_done      = e.new_label();

            // rax = PEB
            e.mov_reg_seg_disp32(rx::rax, /*gs*/2, 0x60, true);

            // rax = PEB.Ldr 
            e.mov_reg_mem(rx::rax, rx::rax, 0x18, true);

            // rcx = &InLoadOrderModuleList head
            e.lea_reg_mem(rx::rcx, rx::rax, rx::none, 0, 0x10);

            // rdx = first Flink
            e.mov_reg_mem(rx::rdx, rx::rcx, 0, true);

            e.bind(lbl_mod_loop);
            e.cmp_reg_reg(rx::rdx, rx::rcx, true);
            e.jcc_label(cc::z, lbl_fail);

            // r11 = BaseDllName.Buffer
            e.mov_reg_mem(rx::r11, rx::rdx, 0x60, true);

            // r9d = BaseDllName.Length
            e.mov_reg_mem_size(rx::r9, rx::rdx, 0x58, 2, false);
            e.shr_reg_imm8(rx::r9, 1, false);

            // r8d = 0
            e.xor_reg_reg(rx::r8, rx::r8, false);

            e.bind(lbl_mod_hash);
            e.test_reg_reg(rx::r9, rx::r9, false);
            e.jcc_label(cc::z, lbl_mod_hdone);

            // eax = movzx word [r11]
            e.mov_reg_mem_size(rx::rax, rx::r11, 0, 2, false);
            e.add_reg_imm32(rx::r11, 2, true);

            // lowercase if [A-Z]
            e.cmp_reg_imm32(rx::rax, 'A', false);
            e.jcc_label(cc::b, lbl_mod_skip_lc);
            e.cmp_reg_imm32(rx::rax, 'Z', false);
            e.jcc_label(cc::nbe, lbl_mod_skip_lc);
            e.add_reg_imm32(rx::rax, 32, false);
            e.bind(lbl_mod_skip_lc);
            e.ror_reg_imm8(rx::r8, 13, false);
            e.add_reg_reg(rx::r8, rx::rax, false);
            e.dec_reg(rx::r9, false);
            e.jmp_label(lbl_mod_hash);

            e.bind(lbl_mod_hdone);
            e.xor_reg_imm32(rx::r8, static_cast<std::int32_t>(salt), false);
            e.cmp_reg_imm32(rx::r8, static_cast<std::int32_t>(hash_k32), false);
            e.jcc_label(cc::z, lbl_mod_found);

            // next entry
            e.mov_reg_mem(rx::rdx, rx::rdx, 0, true);
            e.jmp_label(lbl_mod_loop);

            e.bind(lbl_mod_found);
            // r11 = kernel32 DllBase
            e.mov_reg_mem(rx::r11, rx::rdx, 0x30, true);

            // eax = e_lfanew
            // edx = ExportTable RVA
            // rdx = ExportTable addr
            e.mov_reg_mem(rx::rax, rx::r11, 0x3c, false);
            e.mov_reg_mem_sib(rx::rdx, rx::r11, rx::rax, 0, 0x88, false);
            e.add_reg_reg(rx::rdx, rx::r11, true);

            // r10d = NumberOfNames
            e.mov_reg_mem(rx::r10, rx::rdx, 0x18, false);

            // rcx = AddressOfNames addr = [rdx+0x20] + r11
            e.mov_reg_mem(rx::rcx, rx::rdx, 0x20, false);
            e.add_reg_reg(rx::rcx, rx::r11, true);

            e.bind(lbl_api_loop);
            e.dec_reg(rx::r10, false);
            e.jcc_label(cc::s, lbl_fail);

            // eax = name RVA = [rcx + r10*4]; rax = name addr
            e.mov_reg_mem_sib(rx::rax, rx::rcx, rx::r10, 2, 0, false);
            e.add_reg_reg(rx::rax, rx::r11, true);
            e.xor_reg_reg(rx::r8, rx::r8, false);

            e.bind(lbl_api_hash);
            e.mov_reg_mem_size(rx::r9, rx::rax, 0, 1, false);
            e.test_reg_reg(rx::r9, rx::r9, false);
            e.jcc_label(cc::z, lbl_api_hdone);
            e.inc_reg(rx::rax, true);
            e.ror_reg_imm8(rx::r8, 13, false);
            e.add_reg_reg(rx::r8, rx::r9, false);
            e.jmp_label(lbl_api_hash);

            e.bind(lbl_api_hdone);
            e.xor_reg_imm32(rx::r8, static_cast<std::int32_t>(salt), false);
            e.cmp_reg_imm32(rx::r8, static_cast<std::int32_t>(hash_vp), false);
            e.jcc_label(cc::nz, lbl_api_loop);

            e.mov_reg_mem(rx::rax, rx::rdx, 0x24, false);
            e.add_reg_reg(rx::rax, rx::r11, true);

            // rax = &ordinal entry = rax + r10*2
            e.lea_reg_mem(rx::rax, rx::rax, rx::r10, 1, 0);

            // r9d = movzx word [rax]
            e.mov_reg_mem_size(rx::r9, rx::rax, 0, 2, false);

            // rax = AddressOfFunctions addr = [rdx+0x1c] + r11
            e.mov_reg_mem(rx::rax, rx::rdx, 0x1c, false);
            e.add_reg_reg(rx::rax, rx::r11, true);

            // eax = function RVA = [rax + r9*4]
            e.mov_reg_mem_sib(rx::rax, rx::rax, rx::r9, 2, 0, false);

            // rax = function addr = rax + r11
            e.add_reg_reg(rx::rax, rx::r11, true);

            // store to vp_addr slot.
            e.mov_mem_reg(
                cfg.state_ptr,
                static_cast<std::int32_t>(st.vp_addr),
                rx::rax,
                true
            );
            e.jmp_label(lbl_done);

            e.bind(lbl_fail);
            e.int3();
            e.bind(lbl_done);
        }
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

        // handler dispatch table 
        off_.handler_table = e.size();
        off_.handler_offsets.assign(256, static_cast<std::size_t>(-1));
        for (int i = 0; i < 256 * 5; ++i) e.u8(0);

        // 1-byte init-done flag 
        off_.init_flag = e.size();
        e.u8(0);

        // companion flag for the deferred data-island decrypt
        off_.data_island_init_flag = e.size();
        e.u8(vm_.pack_mode() ? 0 : 1);

        // blob mirror of the runtime nonce 
        off_.runtime_nonce_slot = e.size();
        for (int i = 0; i < 8; ++i) e.u8(0);

        emit_all_handlers(e);
        emit_exit_handler(e);
    }

    // keyed by emitter pointer
    static std::unordered_map<const X64Emitter*, PrologueOrder> g_prologue_orders;

    const std::vector<std::uint8_t>* prologue_order_for(const X64Emitter& e) {
        auto it = g_prologue_orders.find(&e);
        return it == g_prologue_orders.end() ? nullptr : &it->second.order;
    }

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
        const std::uint32_t frame_size = static_cast<std::uint32_t>(vm_.state_layout().total_size) + vm_.shadow_stack_bytes() + vm_.frame_padding();
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

        // --rx 
        if (vm_.rx_mode()) {
            if (vm_.rx_loader_vp()) {
                e.mov_mem_reg(
                    cfg.state_ptr,
                    static_cast<std::int32_t>(st.vp_addr),
                    rx::rcx,
                    true
                );
            } 
            else {
                emit_resolve_vp_x64(e, vm_);
            }
        }

        // zero VM regs[] 
        if (!skip_regs_zero) {
            const std::uint8_t zpool[7] = {rx::rax, rx::rcx, rx::rdx, rx::r8, rx::r9, rx::r10, rx::r11};
            SeedRng zero_rng(vm_.cipher_init_state() ^ 0x2E07117EU);

            // shuffle slot order 
            std::vector<std::uint8_t> slot_order(vm_.reg_count());
            for (std::uint8_t i = 0; i < vm_.reg_count(); ++i) slot_order[i] = i;
            for (std::size_t i = slot_order.size(); i > 1; --i) {
                const std::size_t j = zero_rng.pick(static_cast<std::uint32_t>(i));
                std::swap(slot_order[i - 1], slot_order[j]);
            }

            // track which volatile host regs we know are zero so a later slot
            // can reuse one without re-issuing the xor/sub/mov-imm.
            std::array<bool, 16> reg_is_zero{};

            auto zero_a_reg = [&](std::uint8_t Z) {
                // three opcodes that all leave Z == 0 
                switch (zero_rng.pick(3)) {
                    case 0:  e.xor_reg_reg(Z, Z, false); break;
                    case 1:  e.sub_reg_reg(Z, Z, false); break;
                    default: e.mov_reg_imm32(Z, 0, false); break;
                }
                reg_is_zero[Z] = true;
            };

            // mov qword [state+disp], 0 via REX.W C7 /0 disp imm32 
            auto mem_zero_imm = [&](std::int32_t disp) {
                e.emit_rex(true, false, false, cfg.state_ptr >= 8);
                e.u8(0xC7);
                e.emit_modrm_mem(0, cfg.state_ptr, rx::none, 0, disp);
                e.u32(0);
            };

            for (std::uint8_t slot : slot_order) {
                if (zero_rng.pick(2)) e.poly_nop(zero_rng);
                const std::int32_t disp = static_cast<std::int32_t>(st.regs_base + slot * 8);

                switch (zero_rng.pick(6)) {
                    case 0:
                    case 1: {
                        // single-instruction mem-direct zero
                        mem_zero_imm(disp);
                        break;
                    }
                    case 2: {
                        // reuse an already-zeroed reg if one exists, else seed one
                        std::uint8_t Z = 0xFF;
                        for (auto r : zpool) if (reg_is_zero[r]) { Z = r; break; }
                        if (Z == 0xFF) {
                            Z = zpool[zero_rng.pick(7)];
                            zero_a_reg(Z);
                        }
                        e.mov_mem_reg(cfg.state_ptr, disp, Z, true);
                        break;
                    }
                    default: {
                        // pick a pool reg, zero it via one of three opcodes,
                        // then store
                        const std::uint8_t Z = zpool[zero_rng.pick(7)];
                        zero_a_reg(Z);
                        e.mov_mem_reg(cfg.state_ptr, disp, Z, true);
                        break;
                    }
                }
            }
        }

        // build the per-cipher constants we'll write to state slots.
        std::uint64_t mult = 0, add = 0;
        switch (vm_.cipher_kind()) {
            case CipherKind::ARX:         mult = 0;                     add = vm_.cipher_k1(); break;
            case CipherKind::LcgSub:      mult = 0x5851F42D4C957F2DULL; add = vm_.cipher_k1(); break;
            case CipherKind::SBoxAdd:     mult = 0x100000001B3ULL;      add = vm_.cipher_k1(); break;
            case CipherKind::FeistelByte: mult = vm_.cipher_k1();       add = vm_.cipher_k2(); break;
        }
        constexpr std::int32_t kCipherAddOff  = 0;
        constexpr std::int32_t kCipherMultOff = 8;
        constexpr std::int32_t kCipherInitSlotOff = 48;

        // non-regs-zero state writes are independent of each other within this
        // block 
        SeedRng init_rng(vm_.cipher_init_state() ^ 0x517A7E1117ULL);
        std::vector<std::function<void()>> init_steps;

        // cipher_state register + cipher_init slot, both from one imm64 load
        init_steps.push_back([&]() {
            e.mov_reg_imm64(rx::rax, vm_.cipher_init_state());
            e.mov_reg_reg(cfg.cipher_state, rx::rax);
            e.mov_mem_reg(
                cfg.state_ptr,
                static_cast<std::int32_t>(st.cipher_extra) + kCipherInitSlotOff,
                rx::rax,
                true
            );
        });

        // cipher add constant
        init_steps.push_back([&]() {
            e.mov_reg_imm64(rx::rax, add);
            e.mov_mem_reg(
                cfg.state_ptr,
                static_cast<std::int32_t>(st.cipher_extra) + kCipherAddOff,
                rx::rax,
                true
            );
        });

        // cipher mult constant
        init_steps.push_back([&]() {
            e.mov_reg_imm64(rx::rax, mult);
            e.mov_mem_reg(
                cfg.state_ptr,
                static_cast<std::int32_t>(st.cipher_extra) + kCipherMultOff,
                rx::rax,
                true
            );
        });

        // handler_base = lea_rip
        init_steps.push_back([&]() {
            auto h_slot = e.lea_reg_rip(cfg.handler_base, 0);
            e.add_fixup(
                h_slot,
                static_cast<std::uint32_t>(FixupKind::HandlerTable),
                0,
                0
            );
        });

        // ip = lea_rip
        init_steps.push_back([&]() {
            auto ip_slot = e.lea_reg_rip(cfg.ip, 0);
            e.add_fixup(
                ip_slot,
                static_cast<std::uint32_t>(FixupKind::Bytecode),
                0,
                0
            );
        });

        // VM_RSP + exit_handler seed at shadow stack bottom 
        init_steps.push_back([&]() {
            const std::uint32_t hr_raw = vm_.vm_sp_headroom();
            const std::uint32_t hr = (hr_raw + 15u) & ~15u;
            e.mov_reg_reg(rx::rax, cfg.state_ptr);
            e.sub_reg_imm32(rx::rax, static_cast<std::int32_t>(8u + hr));
            e.mov_mem_reg(
                cfg.state_ptr,
                static_cast<std::int32_t>(st.regs_base + vm_.slot_of_xreg(XReg::SP) * 8),
                rx::rax,
                true
            );
            auto exit_slot = e.lea_reg_rip(rx::rcx, 0);
            e.add_fixup(
                exit_slot,
                static_cast<std::uint32_t>(FixupKind::VMExit),
                0,
                0
            );
            e.mov_mem_reg(rx::rax, 0, rx::rcx, true);
        });

        // saved_native_rsp = current host rsp
        init_steps.push_back([&]() {
            e.mov_mem_reg(
                cfg.state_ptr,
                static_cast<std::int32_t>(st.saved_native_rsp),
                rx::rsp,
                true
            );
        });

        // call_sp = 0 
        init_steps.push_back([&]() {
            switch (init_rng.pick(3)) {
                case 0: e.xor_reg_reg(rx::rax, rx::rax, false); break;
                case 1: e.sub_reg_reg(rx::rax, rx::rax, false); break;
                default: e.mov_reg_imm32(rx::rax, 0, false); break;
            }
            e.mov_mem_reg(
                cfg.state_ptr,
                static_cast<std::int32_t>(st.call_sp),
                rx::rax,
                true
            );
        });

        for (std::size_t i = init_steps.size(); i > 1; --i) {
            const std::size_t j = init_rng.pick(static_cast<std::uint32_t>(i));
            std::swap(init_steps[i - 1], init_steps[j]);
        }

        for (auto& step : init_steps) {
            if (init_rng.pick(2)) e.poly_nop(init_rng);
            step();
        }

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

        SeedRng sbox_rng(vm_.cipher_init_state() ^ 0x550B0CDC0DULL);
        e.add_reg_imm32(cfg.scratch_a, 8);
        if (sbox_rng.pick(2)) e.poly_nop(sbox_rng);
        e.add_reg_imm32(cfg.scratch_b, 8);
        if (sbox_rng.pick(2)) e.poly_nop(sbox_rng);

        // dec sets ZF; no need for test rcx, rcx
        e.dec_reg(rx::rcx, true);
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

        // data island decrypt 
        if (data_island_size > 0 && !vm_.pack_mode()) {
            if (vm_.rx_mode()) {
                emit_vprotect_call_x64(e, vm_, kPageReadWrite);
            }
            auto src_slot = e.lea_reg_rip(cfg.ip, 0);
            e.add_fixup(
                src_slot,
                static_cast<std::uint32_t>(FixupKind::DataIsland),
                0,
                0
            );

            {
                auto dst_slot = e.lea_reg_rip(cfg.scratch_b, 0);
                e.add_fixup(
                    dst_slot,
                    static_cast<std::uint32_t>(FixupKind::DataIsland),
                    0,
                    0
                );
            }

            e.mov_reg_imm32(rx::rcx, static_cast<std::int32_t>(data_island_size));
            e.mov_reg_imm64(rx::rax, vm_.cipher_init_state());
            e.mov_reg_reg(cfg.cipher_state, rx::rax);

            // poly local rng so 3 decrypt loops don't share the same nop layout.
            SeedRng dl_rng(vm_.cipher_init_state() ^ 0xDA7A151EULL);
            if (dl_rng.pick(2)) e.poly_nop(dl_rng);
            auto lbl_dec_loop = e.new_label();
            e.bind(lbl_dec_loop);
            emit_fetch_byte_dec(e, vm_, rx::rax);
            if (dl_rng.pick(2)) e.poly_nop(dl_rng);
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
            if (dl_rng.pick(2)) e.poly_nop(dl_rng);

            // dec rcx already sets ZF, no need for explicit test rcx, rcx
            e.dec_reg(rx::rcx, true);
            e.jcc_label(cc::nz, lbl_dec_loop);

            // RX-restore the data island region now that the decrypt is done.
            if (vm_.rx_mode()) {
                emit_vprotect_call_x64(e, vm_, kPageExecuteRead);
            }
        }

        // block-table decrypt, skipped in --rx 
        if (block_table_count > 0 && !vm_.rx_mode()) {
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

            SeedRng bt_rng(vm_.cipher_init_state() ^ 0xB10C7AB1ULL);
            if (bt_rng.pick(2)) e.poly_nop(bt_rng);
            auto lbl_bt_loop = e.new_label();
            e.bind(lbl_bt_loop);
            emit_fetch_byte_dec(e, vm_, rx::rax);
            if (bt_rng.pick(2)) e.poly_nop(bt_rng);
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
            if (bt_rng.pick(2)) e.poly_nop(bt_rng);
            e.dec_reg(rx::rcx, true);
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

            // also dump it into the blob slot so entries 2..N can pick it up
            if (!vm_.rx_mode()) {
            auto nonce_slot_lea = e.lea_reg_rip(cfg.scratch_b, 0);
            e.add_fixup(
                nonce_slot_lea,
                static_cast<std::uint32_t>(FixupKind::RuntimeNonce),
                0,
                0
            );
            e.mov_mem_reg(
                cfg.scratch_b,
                0,
                rx::rax,
                true
            );
            }
        }

        // handler-table decrypt 
        if (!vm_.rx_mode()) {
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

            e.mov_reg_imm32(rx::rcx, 256 * 5);

            // independent stream restart, has to match the build-time
            // encrypt_inplace call on handler_table_bytes.
            e.mov_reg_imm64(rx::rax, vm_.cipher_init_state());
            e.mov_reg_reg(cfg.cipher_state, rx::rax);

            SeedRng ht_rng(vm_.cipher_init_state() ^ 0x4AB1ECEFULL);
            if (ht_rng.pick(2)) e.poly_nop(ht_rng);
            auto lbl_ht_loop = e.new_label();
            e.bind(lbl_ht_loop);
            emit_fetch_byte_dec(e, vm_, rx::rax);
            if (ht_rng.pick(2)) e.poly_nop(ht_rng);
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
            if (ht_rng.pick(2)) e.poly_nop(ht_rng);
            e.dec_reg(rx::rcx, true);
            e.jcc_label(cc::nz, lbl_ht_loop);
        }

        if (!vm_.rx_mode()) {
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

        // copy blob nonce -> VMState slot every single entry 
        {
            constexpr std::int32_t kRuntimeNonceOff2 = 80;
            auto nonce_lea = e.lea_reg_rip(cfg.scratch_b, 0);
            e.add_fixup(
                nonce_lea,
                static_cast<std::uint32_t>(FixupKind::RuntimeNonce),
                0,
                0
            );
            e.mov_reg_mem(
                rx::rax,
                cfg.scratch_b,
                0,
                true
            );
            e.mov_mem_reg(
                cfg.state_ptr,
                static_cast<std::int32_t>(st.cipher_extra) + kRuntimeNonceOff2,
                rx::rax,
                true
            );
        }

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

        // data_island_base setup 
        {
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
        }

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
        const std::uint32_t frame_size = static_cast<std::uint32_t>(vm_.state_layout().total_size) + vm_.shadow_stack_bytes() + vm_.frame_padding();
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
        // marshalled values into the GPR slots
        emit_state_init(
            e,
            /*bytecode_size=*/0,
            data_island_size,
            block_table_count,
            /*skip_regs_zero=*/true
        );

        // --coro-prelo N: copy N qwords from real_stack[0..N*8] onto VM_RSP
        if (vm_.coro_prelo() > 0) {
            const std::uint32_t prelo_n = vm_.coro_prelo();
            const std::int32_t native_rsp_delta = static_cast<std::int32_t>(aligned_frame) + 72 -
                static_cast<std::int32_t>(vm_.shadow_stack_bytes());
            const std::uint8_t rsp_slot = vm_.slot_of_xreg(XReg::SP);
            const std::int32_t rsp_off  = static_cast<std::int32_t>(st.regs_base + rsp_slot * 8);

            e.lea_reg_mem(rx::rcx, cfg.state_ptr, rx::none, 0, native_rsp_delta);
            e.mov_reg_mem(rx::r8, cfg.state_ptr, rsp_off, true);

            // push in reverse so real[0] lands at BOTTOM of VM_RSP
            for (std::int32_t i = static_cast<std::int32_t>(prelo_n) - 1; i >= 0; --i) {
                e.mov_reg_mem(rx::rax, rx::rcx, i * 8, true);
                e.sub_reg_imm32(rx::r8, 8, /*w64=*/true);
                e.mov_mem_reg(rx::r8, 0, rx::rax, true);
            }
            e.mov_mem_reg(cfg.state_ptr, rsp_off, rx::r8, true);
        }

        if (bytecode_offset != 0) {
            e.add_reg_imm32(cfg.ip, static_cast<std::int32_t>(bytecode_offset));
        }

        emit_dispatch_tail(e, vm_);
    }

    // one trampoline per call site
    void VMCodeGen::emit_trampoline(X64Emitter& e, std::uint32_t bytecode_offset) {
        const auto& cfg                       = vm_.dispatcher_regs();
        const auto& st                        = vm_.state_layout();
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

        const std::uint32_t frame_size = static_cast<std::uint32_t>(vm_.state_layout().total_size) + vm_.shadow_stack_bytes() + vm_.frame_padding();
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