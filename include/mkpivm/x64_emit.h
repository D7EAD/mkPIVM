#pragma once

#include "mkpivm/util.h"

#include <cstdint>
#include <vector>

namespace mkpivm {
    // x64 register codes 0 to 15 
    namespace rx {
        constexpr std::uint8_t rax  = 0;
        constexpr std::uint8_t rcx  = 1;
        constexpr std::uint8_t rdx  = 2;
        constexpr std::uint8_t rbx  = 3;
        constexpr std::uint8_t rsp  = 4;
        constexpr std::uint8_t rbp  = 5;
        constexpr std::uint8_t rsi  = 6;
        constexpr std::uint8_t rdi  = 7;
        constexpr std::uint8_t r8   = 8;
        constexpr std::uint8_t r9   = 9;
        constexpr std::uint8_t r10  = 10;
        constexpr std::uint8_t r11  = 11;
        constexpr std::uint8_t r12  = 12;
        constexpr std::uint8_t r13  = 13;
        constexpr std::uint8_t r14  = 14;
        constexpr std::uint8_t r15  = 15;
        constexpr std::uint8_t none = 0xFF;
    }

    // JCC cc codes, low nibble of the opcode per the Intel manual.
    namespace cc {
        constexpr std::uint8_t o  = 0x0,  no = 0x1;
        constexpr std::uint8_t b  = 0x2,  nb = 0x3;
        constexpr std::uint8_t z  = 0x4,  nz = 0x5;
        constexpr std::uint8_t be = 0x6, nbe = 0x7;
        constexpr std::uint8_t s  = 0x8,  ns = 0x9;
        constexpr std::uint8_t p  = 0xA,  np = 0xB;
        constexpr std::uint8_t l  = 0xC,  nl = 0xD;
        constexpr std::uint8_t le = 0xE, nle = 0xF;
    }

    // small x64 emitter 
    class X64Emitter {
        public:
            using LabelId = std::uint32_t;
            static constexpr LabelId kInvalidLabel = static_cast<LabelId>(-1);

            X64Emitter() = default;
            X64Emitter(const X64Emitter&) = delete;
            X64Emitter& operator=(const X64Emitter&) = delete;

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

            // emit a placeholder rel32 and let the packager fill it in later
            struct Fixup {
                std::size_t   patch_offset; // where the 32-bit slot is
                std::int64_t  addend;       // signed addend applied on resolve
                std::uint32_t target_kind;  // user tag
                std::uint64_t target_data;  // user payload
            };
            std::size_t emit_rel32_fixup(std::uint32_t kind, std::uint64_t data, std::int64_t addend = 0);
            
            void add_fixup(
                std::size_t at,
                std::uint32_t kind,
                std::uint64_t data,
                std::int64_t addend = 0
            ) {
                fixups_.push_back({at, addend, kind, data});
            }
            const std::vector<Fixup>& fixups() const noexcept { return fixups_; }

            // x64 encodings
            void emit_rex(bool w, bool r, bool x, bool b);
            void emit_modrm(std::uint8_t mod, std::uint8_t reg, std::uint8_t rm);
            void emit_sib(std::uint8_t scale_log2, std::uint8_t index, std::uint8_t base);

            // encodes [base + index*scale + disp], [base + disp], or [rip+disp]
            // into ModR/M, optional SIB, and displacement bytes 
            std::size_t emit_modrm_mem(
                std::uint8_t reg_field,
                std::uint8_t base,
                std::uint8_t index,
                std::uint8_t scale_log2,
                std::int32_t disp
            );

            // common helpers. w64 true = 64-bit operand, false = 32-bit.
            void mov_reg_reg(std::uint8_t dst, std::uint8_t src, bool w64 = true);
            void mov_reg_imm32(std::uint8_t dst, std::int32_t imm, bool w64 = true);
            void mov_reg_imm64(std::uint8_t dst, std::uint64_t imm);
            void mov_reg_mem(std::uint8_t dst, std::uint8_t base, std::int32_t disp, bool w64 = true);
            void mov_mem_reg(std::uint8_t base, std::int32_t disp, std::uint8_t src, bool w64 = true);
            void mov_reg_mem_sib(
                std::uint8_t dst,
                std::uint8_t base,
                std::uint8_t index,
                std::uint8_t scale_log2,
                std::int32_t disp,
                bool w64 = true
            );

            void mov_mem_sib_reg(
                std::uint8_t base,
                std::uint8_t index,
                std::uint8_t scale_log2,
                std::int32_t disp,
                std::uint8_t src,
                bool w64 = true
            );

            // size-typed memory access. size is 1, 2, 4, or 8 bytes.
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

            // LEA reg, [rip + disp32]. emits a placeholder, returns the disp32
            // offset for fixup.
            std::size_t lea_reg_rip(std::uint8_t dst, std::int32_t disp = 0);
            void lea_reg_mem(
                std::uint8_t dst,
                std::uint8_t base,
                std::uint8_t index,
                std::uint8_t scale_log2,
                std::int32_t disp
            );

            // ALU reg, reg
            void add_reg_reg(std::uint8_t dst, std::uint8_t src, bool w64 = true);
            void sub_reg_reg(std::uint8_t dst, std::uint8_t src, bool w64 = true);
            void xor_reg_reg(std::uint8_t dst, std::uint8_t src, bool w64 = true);
            void and_reg_reg(std::uint8_t dst, std::uint8_t src, bool w64 = true);
            void or_reg_reg(std::uint8_t dst, std::uint8_t src, bool w64 = true);
            void cmp_reg_reg(std::uint8_t dst, std::uint8_t src, bool w64 = true);
            void test_reg_reg(std::uint8_t dst, std::uint8_t src, bool w64 = true);

            // ALU reg, imm32. sign-extended when w64.
            void add_reg_imm32(std::uint8_t dst, std::int32_t imm, bool w64 = true);
            void sub_reg_imm32(std::uint8_t dst, std::int32_t imm, bool w64 = true);
            void and_reg_imm32(std::uint8_t dst, std::int32_t imm, bool w64 = true);
            void or_reg_imm32(std::uint8_t dst, std::int32_t imm, bool w64 = true);
            void xor_reg_imm32(std::uint8_t dst, std::int32_t imm, bool w64 = true);
            void cmp_reg_imm32(std::uint8_t dst, std::int32_t imm, bool w64 = true);

            // shifts
            void shl_reg_imm8(std::uint8_t dst, std::uint8_t s, bool w64 = true);
            void shr_reg_imm8(std::uint8_t dst, std::uint8_t s, bool w64 = true);
            void sar_reg_imm8(std::uint8_t dst, std::uint8_t s, bool w64 = true);
            void rol_reg_imm8(std::uint8_t dst, std::uint8_t s, bool w64 = true);
            void ror_reg_imm8(std::uint8_t dst, std::uint8_t s, bool w64 = true);
            void shl_reg_cl(std::uint8_t dst, bool w64 = true);
            void shr_reg_cl(std::uint8_t dst, bool w64 = true);
            void sar_reg_cl(std::uint8_t dst, bool w64 = true);
            void rol_reg_cl(std::uint8_t dst, bool w64 = true);
            void ror_reg_cl(std::uint8_t dst, bool w64 = true);

            // misc unary shit
            void inc_reg(std::uint8_t r, bool w64 = true);
            void dec_reg(std::uint8_t r, bool w64 = true);
            void neg_reg(std::uint8_t r, bool w64 = true);
            void not_reg(std::uint8_t r, bool w64 = true);
            void bswap_reg(std::uint8_t r, bool w64 = true);

            // stack
            void push_reg(std::uint8_t r);
            void pop_reg (std::uint8_t r);
            void push_imm32(std::int32_t imm);
            void pushfq();
            void popfq();

            // control flow
            void ret();
            void call_reg(std::uint8_t r);
            void jmp_reg(std::uint8_t r);
            void call_rel32(std::int32_t rel32);
            void jmp_rel32(std::int32_t rel32);
            void jmp_mem_disp32(std::uint8_t base, std::int32_t disp32);
            void jcc_rel32(std::uint8_t cc, std::int32_t rel32);
            void jmp_rel8(std::int8_t rel8);
            void jcc_rel8(std::uint8_t cc, std::int8_t rel8);

            // forward-label branches
            void jmp_label(LabelId l);
            void jcc_label(std::uint8_t cc, LabelId l);
            void call_label(LabelId l);

            // extensions
            void movzx_r32_r8(std::uint8_t dst, std::uint8_t src);
            void movzx_r32_r16(std::uint8_t dst, std::uint8_t src);
            void movzx_r64_r8(std::uint8_t dst, std::uint8_t src);
            void movzx_r64_r16(std::uint8_t dst, std::uint8_t src);
            void movsx_r32_r8(std::uint8_t dst, std::uint8_t src);
            void movsx_r32_r16(std::uint8_t dst, std::uint8_t src);
            void movsx_r64_r8(std::uint8_t dst, std::uint8_t src);
            void movsx_r64_r16(std::uint8_t dst, std::uint8_t src);
            void movsxd_r64_r32(std::uint8_t dst, std::uint8_t src);

            // segment access. mov reg, gs:[disp32] or fs:[disp32]. seg
            // takes 1 for fs and 2 for gs.
            void mov_reg_seg_disp32(
                std::uint8_t dst,
                std::uint8_t seg,
                std::int32_t disp,
                bool w64 = true
            );

            void nop();
            void int3();

            // semantically null NOP 
            template <typename Rng>
            void poly_nop(Rng& rng) {
                switch (rng.pick(20)) {
                    case 0:  bytes({0x90});                         break; // nop
                    case 1:  bytes({0x66, 0x90});                   break; // 66 90
                    case 2:  bytes({0x0F, 0x1F, 0x00});             break; // 3-byte nopl
                    case 3:  bytes({0x0F, 0x1F, 0x40, 0x00});       break; // 4-byte nopl
                    case 4:  bytes({0x0F, 0x1F, 0x44, 0x00, 0x00}); break; // 5-byte nopl
                    case 5:  bytes({0x48, 0x89, 0xC0});             break; // mov rax, rax (89)
                    case 6:  bytes({0x48, 0x89, 0xC9});             break; // mov rcx, rcx (89)
                    case 7:  bytes({0x48, 0x89, 0xD2});             break; // mov rdx, rdx (89)
                    case 8:  bytes({0x48, 0x8B, 0xC0});             break; // mov rax, rax (8B)
                    case 9:  bytes({0x48, 0x8B, 0xC9});             break; // mov rcx, rcx (8B)
                    case 10: bytes({0x48, 0x8B, 0xD2});             break; // mov rdx, rdx (8B)
                    case 11: bytes({0x4D, 0x89, 0xC0});             break; // mov r8, r8
                    case 12: bytes({0x4D, 0x89, 0xC9});             break; // mov r9, r9
                    case 13: bytes({0x4D, 0x8B, 0xC0});             break; // mov r8, r8 (8B)
                    case 14: bytes({0x4D, 0x8B, 0xD2});             break; // mov r10, r10
                    case 15: bytes({0x48, 0x8D, 0x00});             break; // lea rax, [rax]
                    case 16: bytes({0x48, 0x8D, 0x09});             break; // lea rcx, [rcx]
                    case 17: bytes({0x48, 0x8D, 0x12});             break; // lea rdx, [rdx]
                    case 18: bytes({0x48, 0x8D, 0x40, 0x00});       break; // lea rax, [rax+0]
                    default: bytes({0x48, 0x8D, 0x49, 0x00});       break; // lea rcx, [rcx+0]
                }
            }

        private:
            std::vector<std::uint8_t> buf_;
            std::vector<std::int64_t> label_pos_;           // -1 if unbound
            std::vector<std::vector<std::size_t>> pending_; // patch sites per label
            std::vector<Fixup> fixups_;
    };
}