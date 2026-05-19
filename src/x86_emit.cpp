#include "mkpivm/x86_emit.h"

#include <cstring>

namespace mkpivm {
    void X86Emitter::u16(std::uint16_t v) {
        buf_.push_back(static_cast<std::uint8_t>(v));
        buf_.push_back(static_cast<std::uint8_t>(v >> 8));
    }

    void X86Emitter::u32(std::uint32_t v) {
        for (int i = 0; i < 4; ++i) buf_.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
    }

    void X86Emitter::u64(std::uint64_t v) {
        for (int i = 0; i < 8; ++i) buf_.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
    }

    void X86Emitter::bytes(std::initializer_list<std::uint8_t> bs) {
        for (auto b : bs) buf_.push_back(b);
    }

    void X86Emitter::bytes(const std::uint8_t* p, std::size_t n) {
        buf_.insert(buf_.end(), p, p + n);
    }

    void X86Emitter::zero(std::size_t n) {
        buf_.insert(buf_.end(), n, std::uint8_t{0});
    }

    void X86Emitter::patch_u32(std::size_t at, std::uint32_t v) {
        if (at + 4 > buf_.size()) throw Error("patch_u32: oob");
        std::memcpy(buf_.data() + at, &v, 4);
    }

    void X86Emitter::patch_u8(std::size_t at, std::uint8_t v) {
        if (at + 1 > buf_.size()) throw Error("patch_u8: oob");
        buf_[at] = v;
    }

    X86Emitter::LabelId X86Emitter::new_label() {
        label_pos_.push_back(-1);
        pending_.emplace_back();
        return static_cast<LabelId>(label_pos_.size() - 1);
    }

    bool X86Emitter::bound(LabelId l) const noexcept {
        return l < label_pos_.size() && label_pos_[l] >= 0;
    }

    std::int64_t X86Emitter::pos_of(LabelId l) const noexcept {
        return (l < label_pos_.size()) ? label_pos_[l] : -1;
    }

    void X86Emitter::bind(LabelId l) {
        if (l >= label_pos_.size()) throw Error("bind: bad label");
        label_pos_[l] = static_cast<std::int64_t>(buf_.size());

        for (auto site : pending_[l]) {
            const std::int64_t rel = static_cast<std::int64_t>(buf_.size()) - (static_cast<std::int64_t>(site) + 4);
            if (rel < INT32_MIN || rel > INT32_MAX) throw Error("bind: rel32 overflow");
            const std::uint32_t v = static_cast<std::uint32_t>(static_cast<std::int32_t>(rel));
            patch_u32(site, v);
        }

        pending_[l].clear();
    }

    std::size_t X86Emitter::emit_rel32_fixup(std::uint32_t kind, std::uint64_t data, std::int64_t addend) {
        const std::size_t at = buf_.size();
        u32(0);
        fixups_.push_back({at, addend, kind, data});
        return at;
    }

    // no REX in 32-bit mode.
    void X86Emitter::emit_modrm(std::uint8_t mod, std::uint8_t reg, std::uint8_t rm) {
        buf_.push_back(static_cast<std::uint8_t>(((mod & 0x3) << 6) | ((reg & 0x7) << 3) | (rm  & 0x7)));
    }

    void X86Emitter::emit_sib(std::uint8_t scale_log2, std::uint8_t index, std::uint8_t base) {
        buf_.push_back(static_cast<std::uint8_t>(((scale_log2 & 0x3) << 6) | ((index & 0x7) << 3) | (base  & 0x7)));
    }

    // 32-bit has no rip-relative addressing. base == rx::none here means an
    // absolute disp32, encoded as mod=00 rm=101.
    std::size_t X86Emitter::emit_modrm_mem(std::uint8_t reg_field,
                                           std::uint8_t base,
                                           std::uint8_t index,
                                           std::uint8_t scale_log2,
                                           std::int32_t disp) {
        std::size_t disp_offset = 0;

        // absolute disp32 form
        if (base == rx::none && index == rx::none) {
            emit_modrm(0, reg_field, 5); // 32-bit mod=00 rm=101 -> absolute disp32
            disp_offset = buf_.size();
            u32(static_cast<std::uint32_t>(disp));
            return disp_offset;
        }

        const bool need_sib = (index != rx::none) || ((base & 7) == 4);
        const bool zero_disp = (disp == 0) && ((base & 7) != 5);
        const bool disp8 = disp >= -128 && disp <= 127;

        std::uint8_t mod;
        if (zero_disp)  mod = 0;
        else if (disp8) mod = 1;
        else            mod = 2;

        if (need_sib) {
            emit_modrm(mod, reg_field, 4);
            const std::uint8_t idx = (index == rx::none) ? 4 : (index & 7);
            const std::uint8_t bs  = (base  == rx::none) ? 5 : (base  & 7);
            emit_sib(scale_log2, idx, bs);
        }
        else {
            emit_modrm(mod, reg_field, base & 7);
        }

        disp_offset = buf_.size();
        if (mod == 1) {
            buf_.push_back(static_cast<std::uint8_t>(disp));
        }
        else if (mod == 2) {
            u32(static_cast<std::uint32_t>(disp));
        }

        return disp_offset;
    }

    void X86Emitter::mov_reg_reg(std::uint8_t dst, std::uint8_t src, bool /*full*/) {
        if (dst >= 8 || src >= 8) throw Error("x86 emitter: register code >= 8");
        buf_.push_back(0x89); // MOV r/m32, r32
        emit_modrm(3, src & 7, dst & 7);
    }

    void X86Emitter::mov_reg_imm32(std::uint8_t dst, std::int32_t imm, bool /*full*/) {
        if (dst >= 8) throw Error("x86 emitter: register code >= 8");
        buf_.push_back(static_cast<std::uint8_t>(0xB8 + (dst & 7)));
        u32(static_cast<std::uint32_t>(imm));
    }

    void X86Emitter::mov_reg_imm64(std::uint8_t dst, std::uint64_t imm) {
        // no 64-bit immediates in 32-bit mode, so just truncate. split
        // it yourself
        mov_reg_imm32(dst, static_cast<std::int32_t>(imm & 0xFFFFFFFFu), true);
    }

    void X86Emitter::mov_reg_mem(std::uint8_t dst, std::uint8_t base, std::int32_t disp, bool /*full*/) {
        if (dst >= 8 || (base != rx::none && base >= 8)) throw Error("x86 emitter: no r8+");
        buf_.push_back(0x8B);
        emit_modrm_mem(
            dst & 7,
            base,
            rx::none,
            0,
            disp
        );
    }

    void X86Emitter::mov_mem_reg(std::uint8_t base, std::int32_t disp, std::uint8_t src, bool /*full*/) {
        if (src >= 8 || (base != rx::none && base >= 8)) throw Error("x86 emitter: no r8+");
        buf_.push_back(0x89);
        emit_modrm_mem(
            src & 7,
            base,
            rx::none,
            0,
            disp
        );
    }

    void X86Emitter::mov_reg_mem_sib(std::uint8_t dst, std::uint8_t base, std::uint8_t index,
                                     std::uint8_t scale_log2, std::int32_t disp, bool /*full*/) {
        if (dst >= 8 || (base != rx::none && base >= 8) || (index != rx::none && index >= 8)) throw Error("x86 emitter: no r8+");
        buf_.push_back(0x8B);

        emit_modrm_mem(
            dst & 7,
            base,
            index,
            scale_log2,
            disp
        );
    }

    void X86Emitter::mov_mem_sib_reg(std::uint8_t base, std::uint8_t index, std::uint8_t scale_log2,
                                     std::int32_t disp, std::uint8_t src, bool /*full*/) {
        if (src >= 8 || (base != rx::none && base >= 8) || (index != rx::none && index >= 8)) throw Error("x86 emitter: no r8+");
        buf_.push_back(0x89);

        emit_modrm_mem(
            src & 7,
            base,
            index,
            scale_log2,
            disp
        );
    }

    void X86Emitter::mov_reg_mem_size(std::uint8_t dst, std::uint8_t base, std::int32_t disp,
                                      std::uint8_t size_bytes, bool sign_extend) {
        if (size_bytes == 8) {
            // no 64-bit load in 32-bit mode. just pull the low 32 bits and discard
            // the high half. split it yourself.
            mov_reg_mem(
                dst,
                base,
                disp,
                true
            );
            return;
        }

        if (size_bytes == 4) {
            mov_reg_mem(
                dst,
                base,
                disp,
                true
            );
            return; 
        }

        if (size_bytes == 2) {
            buf_.push_back(0x0F);
            buf_.push_back(sign_extend ? 0xBF : 0xB7);
            emit_modrm_mem(
                dst & 7,
                base,
                rx::none,
                0,
                disp
            );
            return;
        }

        if (size_bytes == 1) {
            buf_.push_back(0x0F);
            buf_.push_back(sign_extend ? 0xBE : 0xB6);
            emit_modrm_mem(
                dst & 7,
                base,
                rx::none,
                0,
                disp
            );
            return;
        }

        throw Error("mov_reg_mem_size: bad size");
    }

    void X86Emitter::mov_mem_reg_size(std::uint8_t base, std::int32_t disp, std::uint8_t src,
                                      std::uint8_t size_bytes) {
        if (size_bytes == 8) {
            mov_mem_reg(
                base,
                disp,
                src,
                true
            ); 
            return;
        }  // same deal, 32-bit store
                               
        if (size_bytes == 4) {
            mov_mem_reg(
                base,
                disp,
                src,
                true
            ); 
            return; 
        }

        if (size_bytes == 2) {
            buf_.push_back(0x66);
            buf_.push_back(0x89);
            emit_modrm_mem(
                src & 7,
                base,
                rx::none,
                0,
                disp
            );
            return;
        }

        if (size_bytes == 1) {
            // in 32-bit MOV r/m8, r8 src codes 0..3 are al/cl/dl/bl and 4..7
            // are ah/ch/dh/bh, not spl/bpl/sil/dil. caller MUST pass 0..3 only
            // or the byte store goes to the wrong half-register and fucks
            // everything up
            buf_.push_back(0x88); // MOV r/m8, r8
            emit_modrm_mem(
                src & 7,
                base,
                rx::none,
                0,
                disp
            );
            return;
        }

        throw Error("mov_mem_reg_size: bad size");
    }

    std::size_t X86Emitter::lea_reg_rip(std::uint8_t /*dst*/, std::int32_t /*disp*/) {
        // ia-32 has no rip-relative 
        throw Error("x86 has no rip-relative addressing");
    }

    void X86Emitter::lea_reg_mem(std::uint8_t dst, std::uint8_t base, std::uint8_t index,
                                 std::uint8_t scale_log2, std::int32_t disp) {
        if (dst >= 8) throw Error("x86 emitter: no r8+");
        buf_.push_back(0x8D);
        emit_modrm_mem(
            dst & 7,
            base,
            index,
            scale_log2,
            disp
        );
    }

    static void x86_alu_rr(X86Emitter& e, std::uint8_t op_rr,
                           std::uint8_t dst, std::uint8_t src) {
        if (dst >= 8 || src >= 8) throw Error("x86 emitter: no r8+");
        e.u8(op_rr);
        e.emit_modrm(3, src & 7, dst & 7);
    }

    void X86Emitter::add_reg_reg(std::uint8_t d, std::uint8_t s, bool) {
        x86_alu_rr(
            *this,
            0x01,
            d,
            s
        ); 
    }

    void X86Emitter::sub_reg_reg(std::uint8_t d, std::uint8_t s, bool) {
        x86_alu_rr(
            *this,
            0x29,
            d,
            s
        );
    }

    void X86Emitter::xor_reg_reg(std::uint8_t d, std::uint8_t s, bool) {
        x86_alu_rr(
            *this,
            0x31,
            d,
            s
        );
    }

    void X86Emitter::and_reg_reg(std::uint8_t d, std::uint8_t s, bool) {
        x86_alu_rr(
            *this,
            0x21,
            d,
            s
        ); 
    }

    void X86Emitter::or_reg_reg (std::uint8_t d, std::uint8_t s, bool) { 
        x86_alu_rr(
            *this,
            0x09,
            d,
            s
        ); 
    }

    void X86Emitter::cmp_reg_reg(std::uint8_t d, std::uint8_t s, bool) { 
        x86_alu_rr(
            *this,
            0x39,
            d,
            s
        ); 
    }

    void X86Emitter::test_reg_reg(std::uint8_t d, std::uint8_t s, bool) { 
        x86_alu_rr(
            *this,
            0x85,
            d,
            s
        ); 
    }

    static void x86_alu_ri(X86Emitter& e, std::uint8_t op_ext, std::uint8_t dst, std::int32_t imm) {
        if (dst >= 8) throw Error("x86 emitter: no r8+");
        e.u8(0x81);
        e.emit_modrm(3, op_ext, dst & 7);
        e.u32(static_cast<std::uint32_t>(imm));
    }

    void X86Emitter::add_reg_imm32(std::uint8_t d, std::int32_t i, bool) {
        x86_alu_ri(
            *this,
            0,
            d,
            i
        ); 
    }

    void X86Emitter::or_reg_imm32 (std::uint8_t d, std::int32_t i, bool) {
        x86_alu_ri(
            *this,
            1,
            d,
            i
        ); 
    }

    void X86Emitter::and_reg_imm32(std::uint8_t d, std::int32_t i, bool) {
        x86_alu_ri(
            *this,
            4,
            d,
            i
        ); 
    }

    void X86Emitter::sub_reg_imm32(std::uint8_t d, std::int32_t i, bool) { 
        x86_alu_ri(
            *this,
            5,
            d,
            i
        ); 
    }

    void X86Emitter::xor_reg_imm32(std::uint8_t d, std::int32_t i, bool) { 
        x86_alu_ri(
            *this,
            6,
            d,
            i
        ); 
    }

    void X86Emitter::cmp_reg_imm32(std::uint8_t d, std::int32_t i, bool) { 
        x86_alu_ri(
            *this,
            7,
            d,
            i
        ); 
    }

    static void x86_shift_ri(X86Emitter& e, std::uint8_t op_ext, std::uint8_t dst, std::uint8_t s) {
        if (dst >= 8) throw Error("x86 emitter: no r8+");
        e.u8(0xC1);
        e.emit_modrm(3, op_ext, dst & 7);
        e.u8(s);
    }

    static void x86_shift_cl(X86Emitter& e, std::uint8_t op_ext, std::uint8_t dst) {
        if (dst >= 8) throw Error("x86 emitter: no r8+");
        e.u8(0xD3);
        e.emit_modrm(3, op_ext, dst & 7);
    }

    void X86Emitter::shl_reg_imm8(std::uint8_t d, std::uint8_t s, bool) { 
        x86_shift_ri(
            *this,
            4,
            d,
            s
        ); 
    }

    void X86Emitter::shr_reg_imm8(std::uint8_t d, std::uint8_t s, bool) { 
        x86_shift_ri(
            *this,
            5,
            d,
            s
        ); 
    }

    void X86Emitter::sar_reg_imm8(std::uint8_t d, std::uint8_t s, bool) { 
        x86_shift_ri(
            *this,
            7,
            d,
            s
        ); 
    }

    void X86Emitter::rol_reg_imm8(std::uint8_t d, std::uint8_t s, bool) { 
        x86_shift_ri(
            *this,
            0,
            d,
            s
        ); 
    }

    void X86Emitter::ror_reg_imm8(std::uint8_t d, std::uint8_t s, bool) { 
        x86_shift_ri(
            *this,
            1,
            d,
            s
        ); 
    }

    void X86Emitter::shl_reg_cl  (std::uint8_t d, bool) { x86_shift_cl(*this, 4, d); }
    void X86Emitter::shr_reg_cl  (std::uint8_t d, bool) { x86_shift_cl(*this, 5, d); }
    void X86Emitter::sar_reg_cl  (std::uint8_t d, bool) { x86_shift_cl(*this, 7, d); }
    void X86Emitter::rol_reg_cl  (std::uint8_t d, bool) { x86_shift_cl(*this, 0, d); }
    void X86Emitter::ror_reg_cl  (std::uint8_t d, bool) { x86_shift_cl(*this, 1, d); }

    // inc/dec have short 0x40+r and 0x48+r forms in 32-bit mode but we stick to
    // the FF or F7 form so the encoding matches the x64 emitter
    void X86Emitter::inc_reg(std::uint8_t r, bool) {
        if (r >= 8) throw Error("x86 emitter: no r8+");
        u8(0xFF); emit_modrm(3, 0, r & 7);
    }

    void X86Emitter::dec_reg(std::uint8_t r, bool) {
        if (r >= 8) throw Error("x86 emitter: no r8+");
        u8(0xFF); emit_modrm(3, 1, r & 7);
    }

    void X86Emitter::neg_reg(std::uint8_t r, bool) {
        if (r >= 8) throw Error("x86 emitter: no r8+");
        u8(0xF7); emit_modrm(3, 3, r & 7);
    }

    void X86Emitter::not_reg(std::uint8_t r, bool) {
        if (r >= 8) throw Error("x86 emitter: no r8+");
        u8(0xF7); emit_modrm(3, 2, r & 7);
    }

    void X86Emitter::bswap_reg(std::uint8_t r, bool) {
        if (r >= 8) throw Error("x86 emitter: no r8+");
        u8(0x0F);
        u8(static_cast<std::uint8_t>(0xC8 + (r & 7)));
    }

    void X86Emitter::push_reg(std::uint8_t r) {
        if (r >= 8) throw Error("x86 emitter: no r8+");
        u8(static_cast<std::uint8_t>(0x50 + (r & 7)));
    }

    void X86Emitter::pop_reg(std::uint8_t r) {
        if (r >= 8) throw Error("x86 emitter: no r8+");
        u8(static_cast<std::uint8_t>(0x58 + (r & 7)));
    }

    void X86Emitter::push_imm32(std::int32_t imm) {
        u8(0x68); u32(static_cast<std::uint32_t>(imm));
    }

    void X86Emitter::pushfq() { u8(0x9C); } // pushfd in 32-bit
    void X86Emitter::popfq()  { u8(0x9D); } // popfd in 32-bit

    void X86Emitter::ret() { u8(0xC3); }
    void X86Emitter::call_reg(std::uint8_t r) {
        if (r >= 8) throw Error("x86 emitter: no r8+");
        u8(0xFF); emit_modrm(3, 2, r & 7);
    }

    void X86Emitter::jmp_reg(std::uint8_t r) {
        if (r >= 8) throw Error("x86 emitter: no r8+");
        u8(0xFF); emit_modrm(3, 4, r & 7);
    }

    void X86Emitter::call_rel32(std::int32_t rel) { u8(0xE8); u32(static_cast<std::uint32_t>(rel)); }
    void X86Emitter::jmp_rel32 (std::int32_t rel) { u8(0xE9); u32(static_cast<std::uint32_t>(rel)); }
    void X86Emitter::jmp_mem_disp32(std::uint8_t base, std::int32_t disp32) {
        if (base >= 8) throw Error("x86 emitter: no r8+");

        u8(0xFF);
        const std::uint8_t rm = base & 7;
        u8(static_cast<std::uint8_t>(0x80 | (4 << 3) | rm));
        if (rm == 4) u8(0x24);
        u32(static_cast<std::uint32_t>(disp32));
    }

    void X86Emitter::jcc_rel32 (std::uint8_t c, std::int32_t rel) {
        u8(0x0F); u8(static_cast<std::uint8_t>(0x80 + (c & 0xF)));
        u32(static_cast<std::uint32_t>(rel));
    }

    void X86Emitter::jmp_rel8  (std::int8_t rel) { u8(0xEB); u8(static_cast<std::uint8_t>(rel)); }
    void X86Emitter::jcc_rel8  (std::uint8_t c, std::int8_t rel) {
        u8(static_cast<std::uint8_t>(0x70 + (c & 0xF)));
        u8(static_cast<std::uint8_t>(rel));
    }

    void X86Emitter::jmp_label(LabelId l) {
        if (l >= label_pos_.size()) throw Error("jmp_label: bad label");

        if (label_pos_[l] >= 0) {
            const std::int64_t rel = label_pos_[l] - (static_cast<std::int64_t>(buf_.size()) + 5);
            jmp_rel32(static_cast<std::int32_t>(rel));
        }
        else {
            u8(0xE9);
            pending_[l].push_back(buf_.size());
            u32(0);
        }
    }

    void X86Emitter::jcc_label(std::uint8_t c, LabelId l) {
        if (l >= label_pos_.size()) throw Error("jcc_label: bad label");

        if (label_pos_[l] >= 0) {
            const std::int64_t rel = label_pos_[l] - (static_cast<std::int64_t>(buf_.size()) + 6);
            jcc_rel32(c, static_cast<std::int32_t>(rel));
        }
        else {
            u8(0x0F); u8(static_cast<std::uint8_t>(0x80 + (c & 0xF)));
            pending_[l].push_back(buf_.size());
            u32(0);
        }
    }

    void X86Emitter::call_label(LabelId l) {
        if (l >= label_pos_.size()) throw Error("call_label: bad label");

        if (label_pos_[l] >= 0) {
            const std::int64_t rel = label_pos_[l] - (static_cast<std::int64_t>(buf_.size()) + 5);
            call_rel32(static_cast<std::int32_t>(rel));
        }
        else {
            u8(0xE8);
            pending_[l].push_back(buf_.size());
            u32(0);
        }
    }

    // r64 forms just route to the r32 form. there's no 64-bit register here.
    void X86Emitter::movzx_r32_r8 (std::uint8_t d, std::uint8_t s) {
        if (d >= 8 || s >= 8) throw Error("x86 emitter: no r8+");
        u8(0x0F); u8(0xB6); emit_modrm(3, d & 7, s & 7);
    }

    void X86Emitter::movzx_r32_r16(std::uint8_t d, std::uint8_t s) {
        if (d >= 8 || s >= 8) throw Error("x86 emitter: no r8+");
        u8(0x0F); u8(0xB7); emit_modrm(3, d & 7, s & 7);
    }

    void X86Emitter::movzx_r64_r8 (std::uint8_t d, std::uint8_t s) { movzx_r32_r8(d, s); }
    void X86Emitter::movzx_r64_r16(std::uint8_t d, std::uint8_t s) { movzx_r32_r16(d, s); }
    void X86Emitter::movsx_r32_r8 (std::uint8_t d, std::uint8_t s) {
        if (d >= 8 || s >= 8) throw Error("x86 emitter: no r8+");
        u8(0x0F); u8(0xBE); emit_modrm(3, d & 7, s & 7);
    }

    void X86Emitter::movsx_r32_r16(std::uint8_t d, std::uint8_t s) {
        if (d >= 8 || s >= 8) throw Error("x86 emitter: no r8+");
        u8(0x0F); u8(0xBF); emit_modrm(3, d & 7, s & 7);
    }

    void X86Emitter::movsx_r64_r8 (std::uint8_t d, std::uint8_t s) { movsx_r32_r8(d, s); }
    void X86Emitter::movsx_r64_r16(std::uint8_t d, std::uint8_t s) { movsx_r32_r16(d, s); }
    void X86Emitter::movsxd_r64_r32(std::uint8_t d, std::uint8_t s) {
        // movsxd doesn't exist in 32-bit 
        mov_reg_reg(d, s, true);
    }

    void X86Emitter::mov_reg_seg_disp32(std::uint8_t dst, std::uint8_t seg,
                                        std::int32_t disp, bool /*full*/) {
        if (dst >= 8) throw Error("x86 emitter: no r8+");
        if (seg == 1)      u8(0x64); // FS prefix
        else if (seg == 2) u8(0x65); // GS prefix
        u8(0x8B);                    // MOV r32, r/m32
        
        // absolute disp32 form: mod=00 rm=101.
        emit_modrm(0, dst & 7, 5);
        u32(static_cast<std::uint32_t>(disp));
    }

    void X86Emitter::nop()  { u8(0x90); }
    void X86Emitter::int3() { u8(0xCC); }
}