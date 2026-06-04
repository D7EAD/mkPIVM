#pragma once

#include "mkpivm/arch.h"
#include "mkpivm/ir.h"
#include "mkpivm/seed.h"
#include "mkpivm/util.h"

#include <array>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace mkpivm {
    // one VM register slot. slot count and which XReg maps where is randomized
    // per seed.
    struct VRegSlot {
        std::uint8_t  index{0};       // 0 to reg_count - 1
        std::uint16_t byte_offset{0}; // offset inside VMState.regs
    };

    // cipher families. per-seed choice. 
    enum class CipherKind : std::uint8_t {
        ARX         = 0, // state += k1, rotl 13, xor into byte
        LcgSub      = 1, // LCG keystream, byte = ciphertext - state>>24
        SBoxAdd     = 2, // byte = sbox[ciphertext] + state++
        FeistelByte = 3, // 2-round feistel byte mix
        // ... more?
    };

    // dispatcher shape
    enum class DispatchStyle : std::uint8_t {
        Threaded = 0, // every handler fetches next opcode and jmps
        Central = 1,  // handlers jmp back to a shared dispatcher tail
    };

    // self-locate strategy for the PIC prologue
    enum class PrologueStyle : std::uint8_t {
        CallPop = 0,        // call $+5; pop reg
        LeaRip = 1,         // lea reg, [rip+0]
        JmpCallShuffle = 2, // jmp forward, call back, pop
    };

    // per-codec encoding shape. codec asks VMConfig for one of these so the
    // same codec source emits wildly different bytecode under different seeds.
    struct OperandShape {
        std::uint8_t reg_index_bits{8}; // 4 or 8
        bool         pack_two_regs{false};
        bool         scramble_regs{false};
        bool         disp32_first{false};
        bool         imm_then_reg{false};
        bool         extra_decoy_byte{false};
    };

    // which physical host regs hold the dispatcher's hot state. picked per
    // seed 
    struct DispatcherRegs {
        std::uint8_t state_ptr;    // points at VMState
        std::uint8_t ip;           // bytecode cursor
        std::uint8_t handler_base; // handler table base for indirect dispatch
        std::uint8_t cipher_state; // running stream cipher state
        std::uint8_t scratch_a;
        std::uint8_t scratch_b;
    };

    // field offsets in the on-stack VMState. order is shuffled per seed so
    // reverse engineers don't get a free structural skeleton. i mean i kinda
    // am holding back on the anti-RE shit with this thing, bc shellcode explosion
    // matters believe it or not
    struct VMStateLayout {
        std::uint16_t regs_base{0};        // reg slot array start
        std::uint16_t regs_total_bytes{0}; // reg_count * 8
        std::uint16_t flags_op{0};
        std::uint16_t flags_a{0};
        std::uint16_t flags_b{0};
        std::uint16_t flags_result{0};
        std::uint16_t flags_width{0};
        std::uint16_t df{0};
        std::uint16_t call_stack_base{0};
        std::uint16_t call_sp{0};
        std::uint16_t saved_native_rsp{0};
        std::uint16_t bytecode_base{0};     // saved at startup
        std::uint16_t data_island_base{0};
        std::uint16_t block_table_base{0};  // va_offset to bytecode_offset pairs
        std::uint16_t block_table_count{0};
        std::uint16_t trampoline_base{0};   // per-call-site trampoline region
        std::uint16_t cipher_extra{0};      // sbox and other key material
        // --rx mode only 
        std::uint16_t data_island_buf_off{0};
        // --rx mode only 
        std::uint16_t vp_addr{0};
        // --rx mode only 
        std::uint16_t vp_old{0};
        std::uint16_t total_size{0};
    };

    // master config for one VM build. fully derived from the seed 
    class VMConfig {
        public:
            explicit VMConfig(Arch arch, SeedRng& rng);

            Arch arch() const noexcept { return arch_; }

            // register file
            std::uint8_t reg_count() const noexcept { return reg_count_; }
            std::uint8_t slot_of_xreg(XReg r) const noexcept { return xreg_to_slot_[static_cast<std::uint8_t>(r)]; }
            std::uint16_t slot_offset(std::uint8_t slot) const noexcept { return state_.regs_base + slot * 8; }

            // slot reserved for IR scratch, not aliased to any XReg
            std::uint8_t scratch_slot(std::uint8_t which) const noexcept { return scratch_slots_[which % scratch_slots_.size()]; }
            std::size_t  scratch_slot_count() const noexcept { return scratch_slots_.size(); }

            const VMStateLayout&  state_layout()    const noexcept { return state_; }
            const DispatcherRegs& dispatcher_regs() const noexcept { return regs_; }
            DispatchStyle         dispatch_style()  const noexcept { return dispatch_; }
            PrologueStyle         prologue_style()  const noexcept { return prologue_; }
            CipherKind            cipher_kind()     const noexcept { return cipher_; }

            // true when we're building in --ranges hybrid mode 
            bool range_mode() const noexcept { return range_mode_; }
            void set_range_mode(bool on) noexcept { range_mode_ = on; }

            // true when this blob is a --pack wrapper
            bool pack_mode() const noexcept { return pack_mode_; }
            void set_pack_mode(bool on) noexcept { pack_mode_ = on; }

            // --range-leak-nvs opt-in 
            bool range_leak_nvs() const noexcept { return range_leak_nvs_; }
            void set_range_leak_nvs(bool on) noexcept { range_leak_nvs_ = on; }

            // --coro-prelo 
            std::uint32_t coro_prelo() const noexcept { return coro_prelo_; }
            void set_coro_prelo(std::uint32_t n) noexcept { coro_prelo_ = n; }

            // setter for shadow_stack_bytes so packager can override the
            // seed-randomized default
            void set_shadow_stack_bytes(std::uint32_t n) noexcept {
                shadow_stack_bytes_ = (n + 0xFu) & ~0xFu;
            }

            // padding above state in the prologue allocation. baseline 256
            // bytes 
            std::uint32_t frame_padding() const noexcept {
                // 4 KB in coro-prelo mode 
                return coro_prelo_ > 0 ? 0x1000u : 256u;
            }

            // --heap-stack toggle
            bool heap_stack() const noexcept { return heap_stack_; }
            void set_heap_stack(bool on) noexcept { heap_stack_ = on; }

            // --rx toggle 
            bool rx_mode() const noexcept { return rx_mode_; }
            void set_rx_mode(bool on) noexcept { rx_mode_ = on; }

            // --rx-loader-vp 
            bool rx_loader_vp() const noexcept { return rx_loader_vp_; }
            void set_rx_loader_vp(bool on) noexcept { rx_loader_vp_ = on; }

            // grow VMState by `bytes` to accommodate the data-island runtime
            // buffer
            void set_rx_data_island_size(std::uint32_t bytes) noexcept {
                state_.total_size = static_cast<std::uint16_t>(
                    ((state_.data_island_buf_off + bytes) + 15u) & ~15u);
            }
            std::uint16_t data_island_buf_off() const noexcept { return state_.data_island_buf_off; }

            // size of the data island in bytes
            std::uint32_t data_island_size() const noexcept { return data_island_size_; }
            void set_data_island_size(std::uint32_t n) noexcept { data_island_size_ = n; }

            // this shit was so fucking retarded i dont even wanna talk abt it
            std::uint32_t vm_sp_headroom() const noexcept { return vm_sp_headroom_; }
            void set_vm_sp_headroom(std::uint32_t n) noexcept { vm_sp_headroom_ = n; }

            // cipher state and keys
            std::uint64_t cipher_init_state() const noexcept { return cipher_init_; }
            std::uint64_t cipher_k1()         const noexcept { return cipher_k1_; }
            std::uint64_t cipher_k2()         const noexcept { return cipher_k2_; }
            const std::array<std::uint8_t, 256>& cipher_sbox() const noexcept { return sbox_; }

            // operand encoding shape per codec family
            OperandShape operand_shape_for(std::string_view family) const;

            // opcode byte assigned to a codec by family + variant
            std::uint8_t opcode_for(std::string_view codec_key) const;
            void assign_opcode(std::string_view codec_key, std::uint8_t byte);

            // reverse lookup, only used for diagnostic dumps
            const std::unordered_map<std::uint8_t, std::string>& opcode_to_codec() const noexcept { return op_to_key_; }

            // pick the variant for a family 
            std::uint32_t variant_for(std::string_view family) const;

            // bytecode encryption.
            void encrypt_inplace(std::vector<std::uint8_t>& bytecode, const std::vector<std::size_t>& block_starts) const;

            // per-codec deterministic sub-RNG 
            SeedRng codec_rng(std::string_view codec_key) const;

            // VM stack and data island sizes
            std::uint32_t shadow_stack_bytes() const noexcept { return shadow_stack_bytes_; }
            std::uint32_t call_stack_depth()   const noexcept { return call_stack_depth_; }

            // 0 to 3. higher means more junk between handlers.
            std::uint8_t junk_density() const noexcept { return junk_density_; }

        private:
            Arch                          arch_;
            std::uint64_t                 master_seed_;
            std::uint8_t                  reg_count_{0};
            std::array<std::uint8_t, 20>  xreg_to_slot_{};
            std::vector<std::uint8_t>     scratch_slots_;
            VMStateLayout                 state_{};
            DispatcherRegs                regs_{};
            DispatchStyle                 dispatch_{DispatchStyle::Threaded};
            PrologueStyle                 prologue_{PrologueStyle::CallPop};
            CipherKind                    cipher_{CipherKind::ARX};
            std::uint64_t                 cipher_init_{0};
            std::uint64_t                 cipher_k1_{0};
            std::uint64_t                 cipher_k2_{0};
            std::array<std::uint8_t, 256> sbox_{};
            std::array<std::uint8_t, 256> sbox_inv_{};
            std::uint32_t                 shadow_stack_bytes_{0};
            std::uint32_t                 call_stack_depth_{0};
            std::uint8_t                  junk_density_{0};
            bool                          range_mode_{false};
            bool                          pack_mode_{false};
            bool                          range_leak_nvs_{false};
            std::uint32_t                 coro_prelo_{0};
            bool                          heap_stack_{false};
            bool                          rx_mode_{false};
            bool                          rx_loader_vp_{false};
            std::uint32_t                 data_island_size_{0};
            std::uint32_t                 vm_sp_headroom_{0};

            std::unordered_map<std::string, std::uint8_t>  family_to_opcode_;
            std::unordered_map<std::uint8_t, std::string>  op_to_key_;
            std::unordered_map<std::string, std::uint32_t> family_to_variant_;
            std::unordered_map<std::string, OperandShape>  family_to_shape_;
    };
}