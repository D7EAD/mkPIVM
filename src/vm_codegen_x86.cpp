#include "mkpivm/vm_codegen.h"

#include <array>
#include <functional>
#include <unordered_map>
#include <vector>

namespace mkpivm {
    namespace {
        // remember the push order so the exit handler pops in reverse. keyed off
        // the emitter pointer since emitters are single-use.
        struct X86PrologueOrder {
            std::vector<std::uint8_t> order;
        };
        static std::unordered_map<const X86Emitter*, X86PrologueOrder> g_x86_prologue_orders;

        constexpr std::uint32_t kPageReadWrite_x86 = 0x04;
        constexpr std::uint32_t kPageExecuteRead_x86 = 0x20;

        // Salted ror13+add hashes, shared shape with the x64 PEB walker.
        std::uint32_t ror_hash_module_x86(const wchar_t* name, std::uint32_t salt) {
            std::uint32_t h = 0;
            for (; *name; ++name) {
                std::uint32_t c = static_cast<std::uint32_t>(*name);
                if (c >= L'A' && c <= L'Z') c += 32;
                h = ((h >> 13) | (h << 19)) + c;
            }
            return h ^ salt;
        }
        std::uint32_t ror_hash_api_x86(const char* name, std::uint32_t salt) {
            std::uint32_t h = 0;
            for (; *name; ++name) {
                std::uint32_t c = static_cast<std::uint8_t>(*name);
                h = ((h >> 13) | (h << 19)) + c;
            }
            return h ^ salt;
        }

        // x86 in-blob PEB walker
        void emit_resolve_vp_x86(X86Emitter& e, const VMConfig& vm) {
            const auto& cfg = vm.dispatcher_regs();
            const auto& st  = vm.state_layout();
            const std::uint32_t salt = static_cast<std::uint32_t>(vm.cipher_init_state() ^ 0xC0DEC0DEULL);
            const std::uint32_t hash_k32 = ror_hash_module_x86(L"kernel32.dll", salt);
            const std::uint32_t hash_vp  = ror_hash_api_x86("VirtualProtect", salt);

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
            auto lbl_restore_fail = e.new_label();

            // save all 4 NV regs 
            e.push_reg(rx::rbx);
            e.push_reg(rx::rsi);
            e.push_reg(rx::rdi);
            e.push_reg(rx::rbp);
            e.u8(0xFC); // cld lodsb relies on DF=0

            // PEB at fs:[0x30]; Ldr at PEB+0xc
            e.mov_reg_seg_disp32(rx::rax, /*fs*/1, 0x30, false);
            e.mov_reg_mem(rx::rax, rx::rax, 0xc, false);

            // ecx = head = &InLoadOrderModuleList
            e.lea_reg_mem(rx::rcx, rx::rax, rx::none, 0, 0xc);

            // edx = first Flink
            e.mov_reg_mem(rx::rdx, rx::rcx, 0, false);

            e.bind(lbl_mod_loop);
            e.cmp_reg_reg(rx::rdx, rx::rcx, false);
            e.jcc_label(cc::z, lbl_restore_fail);

            // ebx = BaseDllName.Buffer 
            e.mov_reg_mem(rx::rbx, rx::rdx, 0x30, false);
            
            // edi = length (u16 at [edx+0x2c]) >> 1
            e.mov_reg_mem_size(rx::rdi, rx::rdx, 0x2c, 2, false);
            e.shr_reg_imm8(rx::rdi, 1, false);
            
            // ebp = hash acc
            e.xor_reg_reg(rx::rbp, rx::rbp, false);

            e.bind(lbl_mod_hash);
            e.test_reg_reg(rx::rdi, rx::rdi, false);
            e.jcc_label(cc::z, lbl_mod_hdone);
            e.mov_reg_mem_size(rx::rax, rx::rbx, 0, 2, false);
            e.add_reg_imm32(rx::rbx, 2, false);
            e.cmp_reg_imm32(rx::rax, 'A', false);
            e.jcc_label(cc::b, lbl_mod_skip_lc);
            e.cmp_reg_imm32(rx::rax, 'Z', false);
            e.jcc_label(cc::nbe, lbl_mod_skip_lc);
            e.add_reg_imm32(rx::rax, 32, false);
            e.bind(lbl_mod_skip_lc);
            e.ror_reg_imm8(rx::rbp, 13, false);
            e.add_reg_reg(rx::rbp, rx::rax, false);
            e.dec_reg(rx::rdi, false);
            e.jmp_label(lbl_mod_hash);

            e.bind(lbl_mod_hdone);
            e.xor_reg_imm32(rx::rbp, static_cast<std::int32_t>(salt), false);
            e.cmp_reg_imm32(rx::rbp, static_cast<std::int32_t>(hash_k32), false);
            e.jcc_label(cc::z, lbl_mod_found);
            e.mov_reg_mem(rx::rdx, rx::rdx, 0, false);
            e.jmp_label(lbl_mod_loop);

            e.bind(lbl_mod_found);

            // ebx = kernel32 DllBase
            e.mov_reg_mem(rx::rbx, rx::rdx, 0x18, false);

            // EAT walk. PE32 ExportTable RVA at PE+0x78
            e.mov_reg_mem(rx::rax, rx::rbx, 0x3c, false);
            e.mov_reg_mem_sib(rx::rdx, rx::rbx, rx::rax, 0, 0x78, false);
            e.add_reg_reg(rx::rdx, rx::rbx, false);
            e.mov_reg_mem(rx::rdi, rx::rdx, 0x18, false); // NumberOfNames
            e.mov_reg_mem(rx::rcx, rx::rdx, 0x20, false); // AddressOfNames RVA
            e.add_reg_reg(rx::rcx, rx::rbx, false);

            e.bind(lbl_api_loop);
            e.dec_reg(rx::rdi, false);
            e.jcc_label(cc::s, lbl_restore_fail);
            e.mov_reg_mem_sib(rx::rsi, rx::rcx, rx::rdi, 2, 0, false);
            e.add_reg_reg(rx::rsi, rx::rbx, false); // esi = name addr
            e.xor_reg_reg(rx::rbp, rx::rbp, false);

            e.bind(lbl_api_hash);
            e.u8(0xAC); // lodsb: AL = [ESI++]; relies on DF=0
            e.test_reg_reg(rx::rax, rx::rax, false); // tests AL via low byte presence
            e.jcc_label(cc::z, lbl_api_hdone);
            e.movzx_r32_r8(rx::rax, rx::rax); // ensure high bits clean
            e.ror_reg_imm8(rx::rbp, 13, false);
            e.add_reg_reg(rx::rbp, rx::rax, false);
            e.jmp_label(lbl_api_hash);

            e.bind(lbl_api_hdone);
            e.xor_reg_imm32(rx::rbp, static_cast<std::int32_t>(salt), false);
            e.cmp_reg_imm32(rx::rbp, static_cast<std::int32_t>(hash_vp), false);
            e.jcc_label(cc::nz, lbl_api_loop);

            // resolve ordinal -> function addr in eax.
            // eax = AddressOfNameOrdinals addr ([edx+0x24] + ebx)
            e.mov_reg_mem(rx::rax, rx::rdx, 0x24, false);
            e.add_reg_reg(rx::rax, rx::rbx, false);

            // eax = &ordinal_entry = eax + edi*2
            e.lea_reg_mem(rx::rax, rx::rax, rx::rdi, 1, 0);

            // esi = ordinal (movzx word)
            e.mov_reg_mem_size(rx::rsi, rx::rax, 0, 2, false);

            // eax = AddressOfFunctions addr ([edx+0x1c] + ebx)
            e.mov_reg_mem(rx::rax, rx::rdx, 0x1c, false);
            e.add_reg_reg(rx::rax, rx::rbx, false);

            // eax = function RVA ([eax + esi*4])
            e.mov_reg_mem_sib(rx::rax, rx::rax, rx::rsi, 2, 0, false);
            e.add_reg_reg(rx::rax, rx::rbx, false); // = VirtualProtect addr

            // restore NV regs before storing the result
            e.pop_reg(rx::rbp);
            e.pop_reg(rx::rdi);
            e.pop_reg(rx::rsi);
            e.pop_reg(rx::rbx);

            e.mov_mem_reg(
                cfg.state_ptr,
                static_cast<std::int32_t>(st.vp_addr),
                rx::rax,
                false
            );
            e.jmp_label(lbl_done);

            e.bind(lbl_restore_fail);
            e.pop_reg(rx::rbp);
            e.pop_reg(rx::rdi);
            e.pop_reg(rx::rsi);
            e.pop_reg(rx::rbx);
            e.bind(lbl_fail);
            e.u8(0xCC); // int3
            e.bind(lbl_done);
        }

        // inlined version of x86_self_locate
        void x86_self_locate_inline(X86Emitter& e, std::uint8_t dst, FixupKind kind) {
            e.call_rel32(0); // call $+5
            e.pop_reg(dst);
            e.u8(0x81);
            e.emit_modrm(3, 0, dst & 7);
            const std::size_t patch = e.size();
            e.u32(0);
            e.add_fixup(
                patch,
                static_cast<std::uint32_t>(kind),
                0,
                7
            );
        }

        // emit stdcall VirtualProtect(data_island, size, new_protect, &old_protect)
        void emit_vprotect_call_x86(X86Emitter& e, const VMConfig& vm, std::uint32_t new_protect) {
            const auto& cfg = vm.dispatcher_regs();
            const auto& st  = vm.state_layout();

            // push &old_protect (state_ptr + vp_old)
            e.lea_reg_mem(
                rx::rax,
                cfg.state_ptr,
                rx::none,
                0,
                static_cast<std::int32_t>(st.vp_old)
            );
            e.push_reg(rx::rax);

            // push new_protect
            e.push_imm32(static_cast<std::int32_t>(new_protect));

            // push size
            e.push_imm32(static_cast<std::int32_t>(vm.data_island_size()));

            // push data_island_addr
            x86_self_locate_inline(e, rx::rax, FixupKind::DataIsland);
            e.push_reg(rx::rax);

            // eax = [state_ptr + vp_addr]; call eax. stdcall pops the 4 args.
            e.mov_reg_mem(
                rx::rax,
                cfg.state_ptr,
                static_cast<std::int32_t>(st.vp_addr),
                true
            );
            e.u8(0xFF); e.u8(0xD0); // call eax
        }
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

        // --rx
        if (vm_.rx_mode()) {
            if (vm_.rx_loader_vp()) {
                const std::uint32_t frame_size = static_cast<std::uint32_t>(vm_.state_layout().total_size) + vm_.shadow_stack_bytes() + vm_.frame_padding();
                const std::uint32_t aligned = (frame_size + 15) & ~15u;

                // entry esp = current esp + aligned + 4 + 16 + 0; arg at entry esp+4.
                const std::int32_t arg_off = static_cast<std::int32_t>(aligned + 4 + 16 + 4);
                e.mov_reg_mem(rx::rax, rx::rsp, arg_off, true);
                e.mov_mem_reg(
                    cfg.state_ptr,
                    static_cast<std::int32_t>(st.vp_addr),
                    rx::rax,
                    true
                );
            }
            else {
                emit_resolve_vp_x86(e, vm_);
            }
        }

        // zero VM regs[] 
        if (!skip_regs_zero) {
            SeedRng zero_rng(vm_.cipher_init_state() ^ 0x2E07117EU);
            const std::uint8_t zpool[3] = {rx::rax, rx::rcx, rx::rdx};

            // shuffle slot order so consecutive writes aren't sweeping +0, +4, +8...
            std::vector<std::uint8_t> slot_order(vm_.reg_count());
            for (std::uint8_t i = 0; i < vm_.reg_count(); ++i) slot_order[i] = i;
            for (std::size_t i = slot_order.size(); i > 1; --i) {
                const std::size_t j = zero_rng.pick(static_cast<std::uint32_t>(i));
                std::swap(slot_order[i - 1], slot_order[j]);
            }

            std::array<bool, 16> reg_is_zero{};

            auto zero_a_reg = [&](std::uint8_t Z) {
                switch (zero_rng.pick(3)) {
                    case 0:  e.xor_reg_reg(Z, Z, true); break;
                    case 1:  e.sub_reg_reg(Z, Z, true); break;
                    default: e.mov_reg_imm32(Z, 0, true); break;
                }
                reg_is_zero[Z] = true;
            };

            // mov dword [state+disp], 0 via C7 /0 disp imm32 
            auto mem_zero_imm = [&](std::int32_t disp) {
                e.u8(0xC7);
                e.emit_modrm_mem(0, cfg.state_ptr, rx::none, 0, disp);
                e.u32(0);
            };

            auto write_dword_zero = [&](std::int32_t disp) {
                if (zero_rng.pick(2)) e.poly_nop(zero_rng);
                switch (zero_rng.pick(5)) {
                    case 0:
                    case 1: {
                        mem_zero_imm(disp);
                        break;
                    }
                    case 2: {
                        std::uint8_t Z = 0xFF;
                        for (auto r : zpool) if (reg_is_zero[r]) { Z = r; break; }
                        if (Z == 0xFF) {
                            Z = zpool[zero_rng.pick(3)];
                            zero_a_reg(Z);
                        }
                        e.mov_mem_reg(cfg.state_ptr, disp, Z, true);
                        break;
                    }
                    default: {
                        const std::uint8_t Z = zpool[zero_rng.pick(3)];
                        zero_a_reg(Z);
                        e.mov_mem_reg(cfg.state_ptr, disp, Z, true);
                        break;
                    }
                }
            };

            for (std::uint8_t slot : slot_order) {
                const std::int32_t lo_disp = static_cast<std::int32_t>(st.regs_base + slot * 8);
                const std::int32_t hi_disp = lo_disp + 4;
                if (zero_rng.pick(2)) {
                    write_dword_zero(lo_disp);
                    write_dword_zero(hi_disp);
                }
                else {
                    write_dword_zero(hi_disp);
                    write_dword_zero(lo_disp);
                }
            }
        }

        // cipher init constants
        const std::uint32_t cipher_init32 = static_cast<std::uint32_t>(vm_.cipher_init_state());
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

        SeedRng init_rng(vm_.cipher_init_state() ^ 0x517A7E1117ULL);

        // pick a zero-write form per call so xor / sub / mov-imm rotate.
        auto write_zero_dword = [&](std::int32_t disp) {
            switch (init_rng.pick(3)) {
                case 0:
                case 1: {
                    // mov dword [state+disp], 0
                    e.u8(0xC7);
                    e.emit_modrm_mem(0, cfg.state_ptr, rx::none, 0, disp);
                    e.u32(0);
                    break;
                }
                default: {
                    e.xor_reg_reg(rx::rax, rx::rax, true);
                    e.mov_mem_reg(cfg.state_ptr, disp, rx::rax, true);
                    break;
                }
            }
        };

        // independent init steps 
        std::vector<std::function<void()>> init_steps;

        // cipher init: load into cipher_state register AND slot lo. zero hi.
        init_steps.push_back([&]() {
            e.mov_reg_imm32(rx::rax, static_cast<std::int32_t>(cipher_init32), true);
            e.mov_reg_reg(cfg.cipher_state, rx::rax, true);
            e.mov_mem_reg(
                cfg.state_ptr,
                static_cast<std::int32_t>(st.cipher_extra) + kCipherInitSlotOff,
                rx::rax,
                true
            );
            write_zero_dword(static_cast<std::int32_t>(st.cipher_extra) + kCipherInitSlotOff + 4);
        });

        // add constant lo + hi zero
        init_steps.push_back([&]() {
            e.mov_reg_imm32(rx::rax, static_cast<std::int32_t>(add & 0xFFFFFFFFu), true);
            e.mov_mem_reg(
                cfg.state_ptr,
                static_cast<std::int32_t>(st.cipher_extra) + kCipherAddOff,
                rx::rax,
                true
            );
            write_zero_dword(static_cast<std::int32_t>(st.cipher_extra) + kCipherAddOff + 4);
        });

        // mult constant lo + hi zero
        init_steps.push_back([&]() {
            e.mov_reg_imm32(rx::rax, static_cast<std::int32_t>(mult & 0xFFFFFFFFu), true);
            e.mov_mem_reg(
                cfg.state_ptr,
                static_cast<std::int32_t>(st.cipher_extra) + kCipherMultOff,
                rx::rax,
                true
            );
            write_zero_dword(static_cast<std::int32_t>(st.cipher_extra) + kCipherMultOff + 4);
        });

        init_steps.push_back([&]() {
            x86_self_locate(e, cfg.handler_base, FixupKind::HandlerTable);
        });

        init_steps.push_back([&]() {
            x86_self_locate(e, cfg.ip, FixupKind::Bytecode);
        });

        // VM_RSP + exit_handler seed 
        init_steps.push_back([&]() {
            const std::uint32_t hr_raw = vm_.vm_sp_headroom();
            const std::uint32_t hr = (hr_raw + 15u) & ~15u;
            e.mov_reg_reg(rx::rax, cfg.state_ptr, true);
            e.sub_reg_imm32(rx::rax, static_cast<std::int32_t>(4u + hr), true);
            e.mov_mem_reg(
                cfg.state_ptr,
                static_cast<std::int32_t>(st.regs_base + vm_.slot_of_xreg(XReg::SP) * 8),
                rx::rax,
                true
            );
            write_zero_dword(static_cast<std::int32_t>(st.regs_base + vm_.slot_of_xreg(XReg::SP) * 8 + 4));
            x86_self_locate(e, rx::rcx, FixupKind::VMExit);
            e.mov_mem_reg(rx::rax, 0, rx::rcx, true);
        });

        // saved_native_rsp lo + hi
        init_steps.push_back([&]() {
            e.mov_mem_reg(
                cfg.state_ptr,
                static_cast<std::int32_t>(st.saved_native_rsp),
                rx::rsp,
                true
            );
            write_zero_dword(static_cast<std::int32_t>(st.saved_native_rsp) + 4);
        });

        // call_sp lo + hi
        init_steps.push_back([&]() {
            write_zero_dword(static_cast<std::int32_t>(st.call_sp));
            write_zero_dword(static_cast<std::int32_t>(st.call_sp) + 4);
        });

        for (std::size_t i = init_steps.size(); i > 1; --i) {
            const std::size_t j = init_rng.pick(static_cast<std::uint32_t>(i));
            std::swap(init_steps[i - 1], init_steps[j]);
        }

        for (auto& step : init_steps) {
            if (init_rng.pick(2)) e.poly_nop(init_rng);
            step();
        }

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

            // poly per-loop seeded by kind so the 3 decrypt loops differ.
            SeedRng dl_rng(vm_.cipher_init_state() ^ 0xDEC0DECULL ^ static_cast<std::uint64_t>(kind));
            if (dl_rng.pick(2)) e.poly_nop(dl_rng);
            auto lbl_loop = e.new_label();
            e.bind(lbl_loop);
            emit_fetch_byte_dec(e, vm_, cfg.scratch_a);
            if (dl_rng.pick(2)) e.poly_nop(dl_rng);
            e.u8(0x88);
            e.emit_modrm_mem(
                cfg.scratch_a & 7,
                cfg.scratch_b,
                rx::none,
                0,
                0
            );

            e.inc_reg(cfg.scratch_b, true);
            if (dl_rng.pick(2)) e.poly_nop(dl_rng);

            // dec sets ZF, no need for explicit test
            e.dec_reg(counter_reg, true);
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

        // data-region decrypt 
        if (data_island_size > 0 && !vm_.pack_mode()) {
            if (vm_.rx_mode()) {
                emit_vprotect_call_x86(e, vm_, kPageReadWrite_x86);
            }
            emit_decrypt_loop_x86(FixupKind::DataIsland, static_cast<std::uint32_t>(data_island_size));
            if (vm_.rx_mode()) {
                emit_vprotect_call_x86(e, vm_, kPageExecuteRead_x86);
            }
        }

        // block-table decrypt 
        if (block_table_count > 0 && !vm_.rx_mode()) {
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
            // the nonce
            if (!vm_.rx_mode()) {
                x86_self_locate(e, cfg.scratch_b, FixupKind::RuntimeNonce);
                e.mov_reg_mem(
                    cfg.scratch_a,
                    cfg.state_ptr,
                    static_cast<std::int32_t>(st.cipher_extra) + kRuntimeNonceOff_x86,
                    true
                );
                e.mov_mem_reg(cfg.scratch_b, 0, cfg.scratch_a, true);
                e.mov_reg_mem(
                    cfg.scratch_a,
                    cfg.state_ptr,
                    static_cast<std::int32_t>(st.cipher_extra) + kRuntimeNonceOff_x86 + 4,
                    true
                );
                e.mov_mem_reg(cfg.scratch_b, 4, cfg.scratch_a, true);
            }
        }

        // handler-table decrypt skipped in --rx mode
        if (!vm_.rx_mode()) {
            emit_decrypt_loop_x86(FixupKind::HandlerTable, 256 * 5);
        }

        // flip init_flag
        if (!vm_.rx_mode()) {
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

        // copy blob nonce into VMState slot, every entry
        {
            x86_self_locate(e, cfg.scratch_b, FixupKind::RuntimeNonce);
            e.mov_reg_mem(cfg.scratch_a, cfg.scratch_b, 0, true);
            e.mov_mem_reg(
                cfg.state_ptr,
                static_cast<std::int32_t>(st.cipher_extra) + kRuntimeNonceOff_x86,
                cfg.scratch_a,
                true
            );
            e.mov_reg_mem(cfg.scratch_a, cfg.scratch_b, 4, true);
            e.mov_mem_reg(
                cfg.state_ptr,
                static_cast<std::int32_t>(st.cipher_extra) + kRuntimeNonceOff_x86 + 4,
                cfg.scratch_a,
                true
            );
        }

        // set ip to bytecode start. cipher_state reset deferred to the very
        // end of emit_state_init
        x86_self_locate(e, cfg.ip, FixupKind::Bytecode);

        {
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
        }

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

        const std::uint32_t frame_size = static_cast<std::uint32_t>(vm_.state_layout().total_size) + vm_.shadow_stack_bytes() + vm_.frame_padding();
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

        // --coro-prelo N: copy N dwords from real_stack[0..N*4] onto VM_RSP
        // at range entry
        if (vm_.coro_prelo() > 0) {
            const std::uint32_t prelo_n = vm_.coro_prelo();
            const std::uint32_t frame_size_p = static_cast<std::uint32_t>(vm_.state_layout().total_size) + vm_.shadow_stack_bytes() + vm_.frame_padding();
            const std::uint32_t aligned_p = (frame_size_p + 15) & ~15u;

            // x86 prologue: 4 NV pushes + pushfd = 20B before
            // sub esp + lea state_ptr.
            const std::int32_t native_esp_delta = static_cast<std::int32_t>(aligned_p) + 20 - static_cast<std::int32_t>(vm_.shadow_stack_bytes());
            const std::uint8_t sp_slot_p = vm_.slot_of_xreg(XReg::SP);
            const std::int32_t sp_off_p  = static_cast<std::int32_t>(st.regs_base + sp_slot_p * 8);

            // ecx = native_entry_esp.
            e.lea_reg_mem(rx::rcx, cfg.state_ptr, rx::none, 0, native_esp_delta);

            // edx = current VM_RSP slot value.
            e.mov_reg_mem(rx::rdx, cfg.state_ptr, sp_off_p, true);

            // push real[N-1] first, down to real[0]
            for (std::int32_t i = static_cast<std::int32_t>(prelo_n) - 1; i >= 0; --i) {
                e.mov_reg_mem(rx::rax, rx::rcx, i * 4, true);
                e.sub_reg_imm32(rx::rdx, 4, true);
                e.mov_mem_reg(rx::rdx, 0, rx::rax, true);
            }
            e.mov_mem_reg(cfg.state_ptr, sp_off_p, rx::rdx, true);

            // BP_slot override: when --coro-prelo > 0, shadow stack mirrors
            // the top N dwords of real stack at range entry
            const std::uint8_t bp_slot_p = vm_.slot_of_xreg(XReg::BP);
            const std::int32_t bp_off_p  = static_cast<std::int32_t>(st.regs_base + bp_slot_p * 8);
            e.mov_mem_reg(cfg.state_ptr, bp_off_p, rx::rdx, true);
            e.xor_reg_reg(rx::rax, rx::rax, true);
            e.mov_mem_reg(cfg.state_ptr, bp_off_p + 4, rx::rax, true);
        }

        if (bytecode_offset != 0) {
            e.add_reg_imm32(cfg.ip, static_cast<std::int32_t>(bytecode_offset), true);
        }

        emit_dispatch_tail(e, vm_);
    }

    void VMCodeGen::emit_trampoline(X86Emitter& e, std::uint32_t bytecode_offset) {
        const auto& cfg                       = vm_.dispatcher_regs();
        const auto& st                        = vm_.state_layout();
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

        const std::uint32_t frame_size = static_cast<std::uint32_t>(vm_.state_layout().total_size) + vm_.shadow_stack_bytes() + vm_.frame_padding();
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

    void VMCodeGen::emit_full(X86Emitter& e, std::size_t /*bytecode_size*/,
                              std::size_t data_island_size, std::uint32_t block_table_count) {
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

        // handler dispatch table 
        off_.handler_table = e.size();
        off_.handler_offsets.assign(256, static_cast<std::size_t>(-1));

        for (int i = 0; i < 256 * 5; ++i) e.u8(0);

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