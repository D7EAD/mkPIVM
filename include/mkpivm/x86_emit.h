#pragma once

#include "mkpivm/util.h"
#include "mkpivm/x64_emit.h"

#include <cstdint>
#include <vector>

namespace mkpivm {
    class X86Emitter {
        public:
            using LabelId = std::uint32_t;
            static constexpr LabelId kInvalidLabel = static_cast<LabelId>(-1);

            X86Emitter() = default;
            X86Emitter(const X86Emitter&) = delete;
            X86Emitter& operator=(const X86Emitter&) = delete;

            std::size_t size() const noexcept { return buf_.size(); }
            const std::vector<std::uint8_t>& bytes() const noexcept { return buf_; }
            std::vector<std::uint8_t> take() noexcept { return std::move(buf_); }

            // raw byte emission
            void u8(std::uint8_t b) { buf_.push_back(b); }
            void u16(std::uint16_t v);
            void u32(std::uint32_t v);
            void u64(std::uint64_t v);
            void bytes(std::initializer_list<std::uint8_t> bs);
            void bytes(const std::uint8_t* p, std::size_t n);
            void zero(std::size_t n);
            void patch_u32(std::size_t at, std::uint32_t v);
            void patch_u8(std::size_t at, std::uint8_t v);

            // labels
            LabelId new_label();
            void bind(LabelId l);
            bool bound(LabelId l) const noexcept;
            std::int64_t pos_of(LabelId l) const noexcept;

            // external rel32 placeholders resolved later by the packager.
            struct Fixup {
                std::size_t  patch_offset;
                std::int64_t addend;
                std::uint32_t target_kind;
                std::uint64_t target_data;
            };
            std::size_t emit_rel32_fixup(std::uint32_t kind, std::uint64_t data, std::int64_t addend = 0);

            void add_fixup(std::size_t at, std::uint32_t kind, std::uint64_t data, std::int64_t addend = 0) {
                fixups_.push_back({at, addend, kind, data});
            }
            const std::vector<Fixup>& fixups() const noexcept { return fixups_; }

            // low-level encoding primitives. no REX in 32-bit. 
            void emit_rex(bool /*w*/, bool /*r*/, bool /*x*/, bool /*b*/) {}
            
            void emit_modrm(std::uint8_t mod, std::uint8_t reg, std::uint8_t rm);
            void emit_sib(std::uint8_t scale_log2, std::uint8_t index, std::uint8_t base);
            
            std::size_t emit_modrm_mem(
                std::uint8_t reg_field,
                std::uint8_t base,
                std::uint8_t index,
                std::uint8_t scale_log2,
                std::int32_t disp
            );

            // the full bool just exists for API parity with X64Emitter 
            void mov_reg_reg(std::uint8_t dst, std::uint8_t src, bool full = true);
            void mov_reg_imm32(std::uint8_t dst, std::int32_t imm, bool full = true);
            
            // mov_reg_imm64 isn't a thing on x86 
            void mov_reg_imm64(std::uint8_t dst, std::uint64_t imm);
            void mov_reg_mem(std::uint8_t dst, std::uint8_t base, std::int32_t disp, bool full = true);
            void mov_mem_reg(std::uint8_t base, std::int32_t disp, std::uint8_t src, bool full = true);
            void mov_reg_mem_sib(
                std::uint8_t dst,
                std::uint8_t base,
                std::uint8_t index,
                std::uint8_t scale_log2,
                std::int32_t disp,
                bool full = true
            );

            void mov_mem_sib_reg(
                std::uint8_t base,
                std::uint8_t index,
                std::uint8_t scale_log2,
                std::int32_t disp,
                std::uint8_t src,
                bool full = true
            );

            void mov_reg_mem_size(
                std::uint8_t dst,
                std::uint8_t base,
                std::int32_t disp,
                std::uint8_t size_bytes,
                bool sign_extend
            );
            
            void mov_mem_reg_size(
                std::uint8_t base,
                std::int32_t disp,
                std::uint8_t src,
                std::uint8_t size_bytes
            );

            // rip-relative LEA is x64-only 
            std::size_t lea_reg_rip(std::uint8_t dst, std::int32_t disp = 0);
            void lea_reg_mem(
                std::uint8_t dst,
                std::uint8_t base,
                std::uint8_t index,
                std::uint8_t scale_log2,
                std::int32_t disp
            );

            void add_reg_reg(std::uint8_t dst, std::uint8_t src, bool full = true);
            void sub_reg_reg(std::uint8_t dst, std::uint8_t src, bool full = true);
            void xor_reg_reg(std::uint8_t dst, std::uint8_t src, bool full = true);
            void and_reg_reg(std::uint8_t dst, std::uint8_t src, bool full = true);
            void or_reg_reg(std::uint8_t dst, std::uint8_t src, bool full = true);
            void cmp_reg_reg(std::uint8_t dst, std::uint8_t src, bool full = true);
            void test_reg_reg(std::uint8_t dst, std::uint8_t src, bool full = true);

            void add_reg_imm32(std::uint8_t dst, std::int32_t imm, bool full = true);
            void sub_reg_imm32(std::uint8_t dst, std::int32_t imm, bool full = true);
            void and_reg_imm32(std::uint8_t dst, std::int32_t imm, bool full = true);
            void or_reg_imm32(std::uint8_t dst, std::int32_t imm, bool full = true);
            void xor_reg_imm32(std::uint8_t dst, std::int32_t imm, bool full = true);
            void cmp_reg_imm32(std::uint8_t dst, std::int32_t imm, bool full = true);

            void shl_reg_imm8(std::uint8_t dst, std::uint8_t s, bool full = true);
            void shr_reg_imm8(std::uint8_t dst, std::uint8_t s, bool full = true);
            void sar_reg_imm8(std::uint8_t dst, std::uint8_t s, bool full = true);
            void rol_reg_imm8(std::uint8_t dst, std::uint8_t s, bool full = true);
            void ror_reg_imm8(std::uint8_t dst, std::uint8_t s, bool full = true);
            void shl_reg_cl(std::uint8_t dst, bool full = true);
            void shr_reg_cl(std::uint8_t dst, bool full = true);
            void sar_reg_cl(std::uint8_t dst, bool full = true);
            void rol_reg_cl(std::uint8_t dst, bool full = true);
            void ror_reg_cl(std::uint8_t dst, bool full = true);

            void inc_reg(std::uint8_t r, bool full = true);
            void dec_reg(std::uint8_t r, bool full = true);
            void neg_reg(std::uint8_t r, bool full = true);
            void not_reg(std::uint8_t r, bool full = true);
            void bswap_reg(std::uint8_t r, bool full = true);

            void push_reg(std::uint8_t r);
            void pop_reg(std::uint8_t r);
            void push_imm32(std::int32_t imm);

            // pushfq becomes pushfd in 32-bit, same single-byte 0x9C opcode either way.
            void pushfq();
            void popfq();

            void ret();
            void call_reg(std::uint8_t r);
            void jmp_reg(std::uint8_t r);
            void call_rel32(std::int32_t rel32);
            void jmp_rel32(std::int32_t rel32);
            void jmp_mem_disp32(std::uint8_t base, std::int32_t disp32);
            void jcc_rel32(std::uint8_t cc, std::int32_t rel32);
            void jmp_rel8(std::int8_t rel8);
            void jcc_rel8(std::uint8_t cc, std::int8_t rel8);

            void jmp_label(LabelId l);
            void jcc_label(std::uint8_t cc, LabelId l);
            void call_label(LabelId l);

            // movzx/movsx variants 
            void movzx_r32_r8(std::uint8_t dst, std::uint8_t src);
            void movzx_r32_r16(std::uint8_t dst, std::uint8_t src);
            void movzx_r64_r8(std::uint8_t dst, std::uint8_t src);
            void movzx_r64_r16(std::uint8_t dst, std::uint8_t src);
            void movsx_r32_r8(std::uint8_t dst, std::uint8_t src);
            void movsx_r32_r16(std::uint8_t dst, std::uint8_t src);
            void movsx_r64_r8(std::uint8_t dst, std::uint8_t src);
            void movsx_r64_r16(std::uint8_t dst, std::uint8_t src);

            // movsxd r64, r32 has no 32-bit counterpart 
            void movsxd_r64_r32(std::uint8_t dst, std::uint8_t src);

            // mov reg, fs:[disp32] or gs:[disp32]. in 32-bit code the PEB lives at
            // fs:[0x30] vs x64's gs:[0x60]. seg is 1 for fs and 2 for gs.
            void mov_reg_seg_disp32(
                std::uint8_t dst,
                std::uint8_t seg,
                std::int32_t disp,
                bool full = true
            );

            void nop();
            void int3();

            // semantic-nop pool. mix of short 0F 1F nops, mov reg,reg in 89
            // and 8B encodings, and lea reg,[reg]. dropped the longer 0F 1F
            // forms which fingerprinted across samples. all preserve flags.
            template <typename Rng>
            void poly_nop(Rng& rng) {
                switch (rng.pick(15)) {
                    case 0:  bytes({0x90});                   break; // nop
                    case 1:  bytes({0x66, 0x90});             break; // 66 nop
                    case 2:  bytes({0x8B, 0xC0});             break; // mov eax, eax (8B)
                    case 3:  bytes({0x8B, 0xC9});             break; // mov ecx, ecx (8B)
                    case 4:  bytes({0x8B, 0xD2});             break; // mov edx, edx (8B)
                    case 5:  bytes({0x89, 0xC0});             break; // mov eax, eax (89)
                    case 6:  bytes({0x89, 0xC9});             break; // mov ecx, ecx (89)
                    case 7:  bytes({0x89, 0xD2});             break; // mov edx, edx (89)
                    case 8:  bytes({0x0F, 0x1F, 0x00});       break; // 3-byte nopl
                    case 9:  bytes({0x0F, 0x1F, 0x40, 0x00}); break; // 4-byte nopl
                    case 10: bytes({0x8D, 0x00});             break; // lea eax, [eax]
                    case 11: bytes({0x8D, 0x09});             break; // lea ecx, [ecx]
                    case 12: bytes({0x8D, 0x12});             break; // lea edx, [edx]
                    case 13: bytes({0x8D, 0x40, 0x00});       break; // lea eax, [eax+0]
                    default: bytes({0x8D, 0x49, 0x00});       break; // lea ecx, [ecx+0]
                }
            }

        private:
            std::vector<std::uint8_t>             buf_;
            std::vector<std::int64_t>             label_pos_;
            std::vector<std::vector<std::size_t>> pending_;
            std::vector<Fixup>                    fixups_;
    };
}