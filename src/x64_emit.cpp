#include "mkpivm/x64_emit.h"

#include <cstring>

namespace mkpivm {
    void X64Emitter::u16(std::uint16_t v) {
        buf_.push_back(static_cast<std::uint8_t>(v));
        buf_.push_back(static_cast<std::uint8_t>(v >> 8));
    }
    
    void X64Emitter::u32(std::uint32_t v) {
        for (int i = 0; i < 4; ++i) buf_.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
    }

    void X64Emitter::u64(std::uint64_t v) {
        for (int i = 0; i < 8; ++i) buf_.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
    }

    void X64Emitter::bytes(std::initializer_list<std::uint8_t> bs) {
        for (auto b : bs) buf_.push_back(b);
    }

    void X64Emitter::bytes(const std::uint8_t* p, std::size_t n) {
        buf_.insert(buf_.end(), p, p + n);
    }

    void X64Emitter::zero(std::size_t n) {
        buf_.insert(buf_.end(), n, std::uint8_t{0});
    }

    void X64Emitter::patch_u32(std::size_t at, std::uint32_t v) {
        if (at + 4 > buf_.size()) throw Error("patch_u32: oob");
        std::memcpy(buf_.data() + at, &v, 4);
    }

    void X64Emitter::patch_u8(std::size_t at, std::uint8_t v) {
        if (at + 1 > buf_.size()) throw Error("patch_u8: oob");
        buf_[at] = v;
    }

    X64Emitter::LabelId X64Emitter::new_label() {
        label_pos_.push_back(-1);
        pending_.emplace_back();
        return static_cast<LabelId>(label_pos_.size() - 1);
    }

    bool X64Emitter::bound(LabelId l) const noexcept {
        return l < label_pos_.size() && label_pos_[l] >= 0;
    }

    std::int64_t X64Emitter::pos_of(LabelId l) const noexcept {
        return (l < label_pos_.size()) ? label_pos_[l] : -1;
    }

    void X64Emitter::bind(LabelId l) {
        if (l >= label_pos_.size()) throw Error("bind: bad label");
        label_pos_[l] = static_cast<std::int64_t>(buf_.size());

        // every pending site here is a rel32 slot whose 4 bytes end at the next-insn boundary.
        for (auto site : pending_[l]) {
            const std::int64_t rel = static_cast<std::int64_t>(buf_.size()) - (static_cast<std::int64_t>(site) + 4);
            if (rel < INT32_MIN || rel > INT32_MAX) throw Error("bind: rel32 overflow");
            const std::uint32_t v = static_cast<std::uint32_t>(static_cast<std::int32_t>(rel));
            patch_u32(site, v);
        }
        pending_[l].clear();
    }

    std::size_t X64Emitter::emit_rel32_fixup(std::uint32_t kind, std::uint64_t data, std::int64_t addend) {
        const std::size_t at = buf_.size();
        u32(0);
        fixups_.push_back({at, addend, kind, data});

        return at;
    }

    void X64Emitter::emit_rex(bool w, bool r, bool x, bool b) {
        const std::uint8_t v = 0x40 | (w ? 0x08 : 0) | (r ? 0x04 : 0) | (x ? 0x02 : 0) | (b ? 0x01 : 0);
        if (v != 0x40) buf_.push_back(v);
    }

    void X64Emitter::emit_modrm(std::uint8_t mod, std::uint8_t reg, std::uint8_t rm) {
        buf_.push_back(static_cast<std::uint8_t>(((mod & 0x3) << 6) | ((reg & 0x7) << 3) | (rm  & 0x7)));
    }

    void X64Emitter::emit_sib(std::uint8_t scale_log2, std::uint8_t index, std::uint8_t base) {
        buf_.push_back(static_cast<std::uint8_t>(((scale_log2 & 0x3) << 6) | ((index & 0x7) << 3) | (base  & 0x7)));
    }

    // emits the ModR/M plus optional SIB plus optional disp for a memory operand 
    std::size_t X64Emitter::emit_modrm_mem(std::uint8_t reg_field,
                                           std::uint8_t base,
                                           std::uint8_t index,
                                           std::uint8_t scale_log2,
                                           std::int32_t disp) {
        std::size_t disp_offset = 0;

        // rip-relative form
        if (base == rx::none && index == rx::none) {
            emit_modrm(0, reg_field, 5); // mod=00 rm=101 -> rip+disp32
            disp_offset = buf_.size();
            u32(static_cast<std::uint32_t>(disp));
            return disp_offset;
        }

        const bool need_sib = (index != rx::none) || ((base & 7) == 4);
        const bool zero_disp = (disp == 0) && ((base & 7) != 5); // base==5/13 needs a disp byte
        const bool disp8 = disp >= -128 && disp <= 127;

        std::uint8_t mod;
        if (zero_disp)  mod = 0;
        else if (disp8) mod = 1;
        else            mod = 2;

        if (need_sib) {
            emit_modrm(mod, reg_field, 4); // rm=100 means a SIB byte follows
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

    void X64Emitter::mov_reg_reg(std::uint8_t dst, std::uint8_t src, bool w64) {
        emit_rex(
            w64,
            src >= 8,
            false,
            dst >= 8
        );
        buf_.push_back(0x89); // MOV r/m, r
        emit_modrm(3, src & 7, dst & 7);
    }

    void X64Emitter::mov_reg_imm32(std::uint8_t dst, std::int32_t imm, bool w64) {
        if (w64) {
            // sign-extended 32-bit imm into r64
            emit_rex(
                true,
                false,
                false,
                dst >= 8
            );
            buf_.push_back(0xC7);
            emit_modrm(3, 0, dst & 7);
            u32(static_cast<std::uint32_t>(imm));
        } 
        else {
            // short B8+rd id form for r32, imm32
            emit_rex(
                false,
                false,
                false,
                dst >= 8
            );
            buf_.push_back(static_cast<std::uint8_t>(0xB8 + (dst & 7)));
            u32(static_cast<std::uint32_t>(imm));
        }
    }

    void X64Emitter::mov_reg_imm64(std::uint8_t dst, std::uint64_t imm) {
        emit_rex(
            true,
            false,
            false,
            dst >= 8
        );
        buf_.push_back(static_cast<std::uint8_t>(0xB8 + (dst & 7)));
        u64(imm);
    }

    void X64Emitter::mov_reg_mem(std::uint8_t dst, std::uint8_t base, std::int32_t disp, bool w64) {
        emit_rex(
            w64,
            dst >= 8,
            false,
            base >= 8
        );
        buf_.push_back(0x8B);
        emit_modrm_mem(
            dst & 7,
            base,
            rx::none,
            0,
            disp
        );
    }

    void X64Emitter::mov_mem_reg(std::uint8_t base, std::int32_t disp, std::uint8_t src, bool w64) {
        emit_rex(
            w64,
            src >= 8,
            false,
            base >= 8
        );
        buf_.push_back(0x89);
        emit_modrm_mem(
            src & 7,
            base,
            rx::none,
            0,
            disp
        );
    }

    void X64Emitter::mov_reg_mem_sib(std::uint8_t dst, std::uint8_t base, std::uint8_t index,
                                     std::uint8_t scale_log2, std::int32_t disp, bool w64) {
        emit_rex(
            w64,
            dst >= 8,
            index >= 8 && index != rx::none,
            base >= 8
        );
        buf_.push_back(0x8B);
        emit_modrm_mem(
            dst & 7,
            base,
            index,
            scale_log2,
            disp
        );
    }

    void X64Emitter::mov_mem_sib_reg(std::uint8_t base, std::uint8_t index, std::uint8_t scale_log2,
                                     std::int32_t disp, std::uint8_t src, bool w64) {
        emit_rex(
            w64,
            src >= 8,
            index >= 8 && index != rx::none,
            base >= 8
        );
        buf_.push_back(0x89);
        emit_modrm_mem(
            src & 7,
            base,
            index,
            scale_log2,
            disp
        );
    }

    void X64Emitter::mov_reg_mem_size(std::uint8_t dst, std::uint8_t base, std::int32_t disp,
                                      std::uint8_t size_bytes, bool sign_extend) {
        if (size_bytes == 8) {
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
                false
            ); 
            return;
        }

        if (size_bytes == 2) {
            if (sign_extend) {
                emit_rex(
                    true,
                    dst >= 8,
                    false,
                    base >= 8
                );
                buf_.push_back(0x0F); buf_.push_back(0xBF);
                emit_modrm_mem(
                    dst & 7,
                    base,
                    rx::none,
                    0,
                    disp
                );
            }
            else {
                emit_rex(
                    true,
                    dst >= 8,
                    false,
                    base >= 8
                );
                buf_.push_back(0x0F); buf_.push_back(0xB7);
                emit_modrm_mem(
                    dst & 7,
                    base,
                    rx::none,
                    0,
                    disp
                );
            }
            return;
        }
        if (size_bytes == 1) {
            if (sign_extend) {
                emit_rex(
                    true,
                    dst >= 8,
                    false,
                    base >= 8
                );
                buf_.push_back(0x0F); buf_.push_back(0xBE);
                emit_modrm_mem(
                    dst & 7,
                    base,
                    rx::none,
                    0,
                    disp
                );
            }
            else {
                emit_rex(
                    true,
                    dst >= 8,
                    false,
                    base >= 8
                );
                buf_.push_back(0x0F); buf_.push_back(0xB6);
                emit_modrm_mem(
                    dst & 7,
                    base,
                    rx::none,
                    0,
                    disp
                );
            }
            return;
        }
        throw Error("mov_reg_mem_size: bad size");
    }

    void X64Emitter::mov_mem_reg_size(std::uint8_t base, std::int32_t disp, std::uint8_t src,
                                      std::uint8_t size_bytes) {
        if (size_bytes == 8) {
            mov_mem_reg(
                base,
                disp,
                src,
                true
            ); 
            return;
        }

        if (size_bytes == 4) { 
            mov_mem_reg(
                base,
                disp,
                src,
                false
            ); 
            return; 
        }

        if (size_bytes == 2) {
            buf_.push_back(0x66); // operand-size override
            emit_rex(
                false,
                src >= 8,
                false,
                base >= 8
            );
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
            // force a REX so src codes 4..7 mean spl/bpl/sil/dil and not the
            // legacy ah/ch/dh/bh. without REX a byte store from rsp/rbp/rsi/rdi
            // silently writes some other register's high byte like a dumbass
            const std::uint8_t rex = static_cast<std::uint8_t>(0x40 | (src >= 8 ? 0x04 : 0) | (base >= 8 ? 0x01 : 0));
            buf_.push_back(rex);
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

    std::size_t X64Emitter::lea_reg_rip(std::uint8_t dst, std::int32_t disp) {
        emit_rex(
            true,
            dst >= 8,
            false,
            false
        );
        buf_.push_back(0x8D);
        return emit_modrm_mem(
            dst & 7,
            rx::none,
            rx::none,
            0,
            disp
        );
    }

    void X64Emitter::lea_reg_mem(std::uint8_t dst, std::uint8_t base, std::uint8_t index,
                                 std::uint8_t scale_log2, std::int32_t disp) {
        emit_rex(
            true,
            dst >= 8,
            index >= 8 && index != rx::none,
            base >= 8
        );
        buf_.push_back(0x8D);
        emit_modrm_mem(
            dst & 7,
            base,
            index,
            scale_log2,
            disp
        );
    }

    static void emit_alu_rr(X64Emitter& e, std::uint8_t op_rr,
                            std::uint8_t dst, std::uint8_t src, bool w64) {
        e.emit_rex(
            w64,
            src >= 8,
            false,
            dst >= 8
        );
        e.u8(op_rr);
        e.emit_modrm(3, src & 7, dst & 7);
    }

    void X64Emitter::add_reg_reg(std::uint8_t d, std::uint8_t s, bool w) { 
        emit_alu_rr(
            *this,
            0x01,
            d,
            s,
            w
        ); 
    }

    void X64Emitter::sub_reg_reg(std::uint8_t d, std::uint8_t s, bool w) { 
        emit_alu_rr(
            *this,
            0x29,
            d,
            s,
            w
        ); 
    }

    void X64Emitter::xor_reg_reg(std::uint8_t d, std::uint8_t s, bool w) { 
        emit_alu_rr(
            *this,
            0x31,
            d,
            s,
            w
        ); 
    }

    void X64Emitter::and_reg_reg(std::uint8_t d, std::uint8_t s, bool w) { 
        emit_alu_rr(
            *this,
            0x21,
            d,
            s,
            w
        ); 
    }

    void X64Emitter::or_reg_reg(std::uint8_t d, std::uint8_t s, bool w) { 
        emit_alu_rr(
            *this,
            0x09,
            d,
            s,
            w
        ); 
    }

    void X64Emitter::cmp_reg_reg(std::uint8_t d, std::uint8_t s, bool w) { 
        emit_alu_rr(
            *this,
            0x39,
            d,
            s,
            w
        ); 
    }

    void X64Emitter::test_reg_reg(std::uint8_t d, std::uint8_t s, bool w) { 
        emit_alu_rr(
            *this,
            0x85,
            d,
            s,
            w
        ); 
    }

    // ALU reg, imm32 via 81 /op with a full 32-bit immediate.
    static void emit_alu_ri(X64Emitter& e, std::uint8_t op_ext,
                            std::uint8_t dst, std::int32_t imm, bool w64) {
        e.emit_rex(
            w64,
            false,
            false,
            dst >= 8
        );
        e.u8(0x81);
        e.emit_modrm(3, op_ext, dst & 7);
        e.u32(static_cast<std::uint32_t>(imm));
    }

    void X64Emitter::add_reg_imm32(std::uint8_t d, std::int32_t i, bool w) {
        emit_alu_ri(
            *this,
            0,
            d,
            i,
            w
        ); 
    }

    void X64Emitter::or_reg_imm32 (std::uint8_t d, std::int32_t i, bool w) { 
        emit_alu_ri(
            *this,
            1,
            d,
            i,
            w
        ); 
    }

    void X64Emitter::and_reg_imm32(std::uint8_t d, std::int32_t i, bool w) { 
        emit_alu_ri(
            *this,
            4,
            d,
            i,
            w
        ); 
    }

    void X64Emitter::sub_reg_imm32(std::uint8_t d, std::int32_t i, bool w) { 
        emit_alu_ri(
            *this,
            5,
            d,
            i,
            w
        ); 
    }

    void X64Emitter::xor_reg_imm32(std::uint8_t d, std::int32_t i, bool w) { 
        emit_alu_ri(
            *this,
            6,
            d,
            i,
            w
        ); 
    }

    void X64Emitter::cmp_reg_imm32(std::uint8_t d, std::int32_t i, bool w) { 
        emit_alu_ri(
            *this,
            7,
            d,
            i,
            w
        ); 
    }

    // group 2 shifts. C1 /op, imm8 or D3 /op, CL.
    static void emit_shift_ri(X64Emitter& e, std::uint8_t op_ext,
                              std::uint8_t dst, std::uint8_t s, bool w64) {
        e.emit_rex(
            w64,
            false,
            false,
            dst >= 8
        );
        e.u8(0xC1);
        e.emit_modrm(3, op_ext, dst & 7);
        e.u8(s);
    }

    static void emit_shift_cl(X64Emitter& e, std::uint8_t op_ext,
                              std::uint8_t dst, bool w64) {
        e.emit_rex(
            w64,
            false,
            false,
            dst >= 8
        );
        e.u8(0xD3);
        e.emit_modrm(3, op_ext, dst & 7);
    }

    void X64Emitter::shl_reg_imm8(std::uint8_t d, std::uint8_t s, bool w) { 
        emit_shift_ri(
            *this,
            4,
            d,
            s,
            w
        ); 
    }

    void X64Emitter::shr_reg_imm8(std::uint8_t d, std::uint8_t s, bool w) { 
        emit_shift_ri(
            *this,
            5,
            d,
            s,
            w
        ); 
    }

    void X64Emitter::sar_reg_imm8(std::uint8_t d, std::uint8_t s, bool w) { 
        emit_shift_ri(
            *this,
            7,
            d,
            s,
            w
        ); 
    }

    void X64Emitter::rol_reg_imm8(std::uint8_t d, std::uint8_t s, bool w) { 
        emit_shift_ri(
            *this,
            0,
            d,
            s,
            w
        );
    }

    void X64Emitter::ror_reg_imm8(std::uint8_t d, std::uint8_t s, bool w) { 
        emit_shift_ri(
            *this,
            1,
            d,
            s,
            w
        ); 
    }

    void X64Emitter::shl_reg_cl(std::uint8_t d, bool w) { 
        emit_shift_cl(
            *this,
            4,
            d,
            w
        ); 
    }

    void X64Emitter::shr_reg_cl(std::uint8_t d, bool w) { 
        emit_shift_cl(
            *this,
            5,
            d,
            w
        ); 
    }

    void X64Emitter::sar_reg_cl(std::uint8_t d, bool w) { 
        emit_shift_cl(
            *this,
            7,
            d,
            w
        ); 
    }

    void X64Emitter::rol_reg_cl(std::uint8_t d, bool w) { 
        emit_shift_cl(
            *this,
            0,
            d,
            w
        ); 
    }

    void X64Emitter::ror_reg_cl(std::uint8_t d, bool w) { 
        emit_shift_cl(
            *this,
            1,
            d,
            w
        ); 
    }

    // inc/dec/neg/not via FF or F7.
    void X64Emitter::inc_reg(std::uint8_t r, bool w) {
        emit_rex(
            w,
            false,
            false,
            r >= 8
        );
        u8(0xFF); emit_modrm(3, 0, r & 7);
    }

    void X64Emitter::dec_reg(std::uint8_t r, bool w) {
        emit_rex(
            w,
            false,
            false,
            r >= 8
        );
        u8(0xFF); emit_modrm(3, 1, r & 7);
    }

    void X64Emitter::neg_reg(std::uint8_t r, bool w) {
        emit_rex(
            w,
            false,
            false,
            r >= 8
        );
        u8(0xF7); emit_modrm(3, 3, r & 7);
    }

    void X64Emitter::not_reg(std::uint8_t r, bool w) {
        emit_rex(
            w,
            false,
            false,
            r >= 8
        );
        u8(0xF7); emit_modrm(3, 2, r & 7);
    }

    void X64Emitter::bswap_reg(std::uint8_t r, bool w) {
        emit_rex(
            w,
            false,
            false,
            r >= 8
        );
        u8(0x0F);
        u8(static_cast<std::uint8_t>(0xC8 + (r & 7)));
    }

    void X64Emitter::push_reg(std::uint8_t r) {
        if (r >= 8) {
            emit_rex(
                false,
                false,
                false,
                true
            );
        }
        u8(static_cast<std::uint8_t>(0x50 + (r & 7)));
    }

    void X64Emitter::pop_reg(std::uint8_t r) {
        if (r >= 8) {
            emit_rex(
                false,
                false,
                false,
                true
            );
        }
        u8(static_cast<std::uint8_t>(0x58 + (r & 7)));
    }
    
    void X64Emitter::push_imm32(std::int32_t imm) {
        u8(0x68); u32(static_cast<std::uint32_t>(imm));
    }

    void X64Emitter::pushfq() { u8(0x9C); }
    void X64Emitter::popfq()  { u8(0x9D); }

    void X64Emitter::ret() { u8(0xC3); }
    void X64Emitter::call_reg(std::uint8_t r) {
        if (r >= 8) {
            emit_rex(false, false, false, true);
        }
        u8(0xFF); emit_modrm(3, 2, r & 7);
    }

    void X64Emitter::jmp_reg(std::uint8_t r) {
        if (r >= 8) {
            emit_rex(false, false, false, true);
        }
        u8(0xFF); emit_modrm(3, 4, r & 7);
    }

    void X64Emitter::call_rel32(std::int32_t rel) { u8(0xE8); u32(static_cast<std::uint32_t>(rel)); }
    void X64Emitter::jmp_rel32 (std::int32_t rel) { u8(0xE9); u32(static_cast<std::uint32_t>(rel)); }
    void X64Emitter::jmp_mem_disp32(std::uint8_t base, std::int32_t disp32) {
        if (base >= 8) {
            emit_rex(false, false, false, true);
        }
        u8(0xFF);

        const std::uint8_t rm = base & 7;
        u8(static_cast<std::uint8_t>(0x80 | (4 << 3) | rm));
        if (rm == 4) u8(0x24); // rsp/r12 base needs a SIB

        u32(static_cast<std::uint32_t>(disp32));
    }

    void X64Emitter::jcc_rel32 (std::uint8_t c, std::int32_t rel) {
        u8(0x0F); u8(static_cast<std::uint8_t>(0x80 + (c & 0xF)));
        u32(static_cast<std::uint32_t>(rel));
    }

    void X64Emitter::jmp_rel8(std::int8_t rel) { u8(0xEB); u8(static_cast<std::uint8_t>(rel)); }
    void X64Emitter::jcc_rel8(std::uint8_t c, std::int8_t rel) {
        u8(static_cast<std::uint8_t>(0x70 + (c & 0xF)));
        u8(static_cast<std::uint8_t>(rel));
    }

    void X64Emitter::jmp_label(LabelId l) {
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

    void X64Emitter::jcc_label(std::uint8_t c, LabelId l) {
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

    void X64Emitter::call_label(LabelId l) {
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

    void X64Emitter::movzx_r32_r8 (std::uint8_t d, std::uint8_t s) {
        emit_rex(false, d >= 8, false, s >= 8);
        u8(0x0F); u8(0xB6); emit_modrm(3, d & 7, s & 7);
    }

    void X64Emitter::movzx_r32_r16(std::uint8_t d, std::uint8_t s) {
        emit_rex(false, d >= 8, false, s >= 8);
        u8(0x0F); u8(0xB7); emit_modrm(3, d & 7, s & 7);
    }

    void X64Emitter::movzx_r64_r8 (std::uint8_t d, std::uint8_t s) {
        emit_rex(true, d >= 8, false, s >= 8);
        u8(0x0F); u8(0xB6); emit_modrm(3, d & 7, s & 7);
    }

    void X64Emitter::movzx_r64_r16(std::uint8_t d, std::uint8_t s) {
        emit_rex(true, d >= 8, false, s >= 8);
        u8(0x0F); u8(0xB7); emit_modrm(3, d & 7, s & 7);
    }

    void X64Emitter::movsx_r32_r8 (std::uint8_t d, std::uint8_t s) {
        emit_rex(false, d >= 8, false, s >= 8);
        u8(0x0F); u8(0xBE); emit_modrm(3, d & 7, s & 7);
    }

    void X64Emitter::movsx_r32_r16(std::uint8_t d, std::uint8_t s) {
        emit_rex(false, d >= 8, false, s >= 8);
        u8(0x0F); u8(0xBF); emit_modrm(3, d & 7, s & 7);
    }

    void X64Emitter::movsx_r64_r8 (std::uint8_t d, std::uint8_t s) {
        emit_rex(true, d >= 8, false, s >= 8);
        u8(0x0F); u8(0xBE); emit_modrm(3, d & 7, s & 7);
    }

    void X64Emitter::movsx_r64_r16(std::uint8_t d, std::uint8_t s) {
        emit_rex(true, d >= 8, false, s >= 8);
        u8(0x0F); u8(0xBF); emit_modrm(3, d & 7, s & 7);
    }

    void X64Emitter::movsxd_r64_r32(std::uint8_t d, std::uint8_t s) {
        emit_rex(true, d >= 8, false, s >= 8);
        u8(0x63); emit_modrm(3, d & 7, s & 7);
    }

    void X64Emitter::mov_reg_seg_disp32(std::uint8_t dst, std::uint8_t seg,
                                        std::int32_t disp, bool w64) {
        // REX.W + 65 for gs / 64 for fs, then 8B /r with ModR/M + disp32.
        if (seg == 1)      u8(0x64);
        else if (seg == 2) u8(0x65);
        emit_rex(w64, dst >= 8, false, false);
        u8(0x8B);
        
        // mod=00, rm=100 with SIB scale=0 index=4=none base=5, then disp32.
        emit_modrm(0, dst & 7, 4);
        emit_sib(0, 4, 5);
        u32(static_cast<std::uint32_t>(disp));
    }

    void X64Emitter::nop()  { u8(0x90); }
    void X64Emitter::int3() { u8(0xCC); }
}