#include "mkpivm/lifter.h"

#include <algorithm>
#include <stdexcept>

namespace mkpivm {
    Width width_from_zsize(std::uint16_t bits) noexcept {
        switch (bits) {
            case 8:  return Width::B;
            case 16: return Width::W;
            case 32: return Width::D;
            default: return Width::Q;
        }
    }

    DecodedReg decode_zreg(ZydisRegister r) noexcept {
        switch (r) {
            // 8-bit low aliases, the legacy four
            case ZYDIS_REGISTER_AL:   return {XReg::AX, Width::B, false};
            case ZYDIS_REGISTER_CL:   return {XReg::CX, Width::B, false};
            case ZYDIS_REGISTER_DL:   return {XReg::DX, Width::B, false};
            case ZYDIS_REGISTER_BL:   return {XReg::BX, Width::B, false};

            // 8-bit high
            case ZYDIS_REGISTER_AH:   return {XReg::AX, Width::B, true};
            case ZYDIS_REGISTER_CH:   return {XReg::CX, Width::B, true};
            case ZYDIS_REGISTER_DH:   return {XReg::DX, Width::B, true};
            case ZYDIS_REGISTER_BH:   return {XReg::BX, Width::B, true};

            // 8-bit REX-encoded
            case ZYDIS_REGISTER_SPL:  return {XReg::SP, Width::B, false};
            case ZYDIS_REGISTER_BPL:  return {XReg::BP, Width::B, false};
            case ZYDIS_REGISTER_SIL:  return {XReg::SI, Width::B, false};
            case ZYDIS_REGISTER_DIL:  return {XReg::DI, Width::B, false};
            case ZYDIS_REGISTER_R8B:  return {XReg::R8, Width::B, false};
            case ZYDIS_REGISTER_R9B:  return {XReg::R9, Width::B, false};
            case ZYDIS_REGISTER_R10B: return {XReg::R10,Width::B, false};
            case ZYDIS_REGISTER_R11B: return {XReg::R11,Width::B, false};
            case ZYDIS_REGISTER_R12B: return {XReg::R12,Width::B, false};
            case ZYDIS_REGISTER_R13B: return {XReg::R13,Width::B, false};
            case ZYDIS_REGISTER_R14B: return {XReg::R14,Width::B, false};
            case ZYDIS_REGISTER_R15B: return {XReg::R15,Width::B, false};

            // 16-bit
            case ZYDIS_REGISTER_AX:   return {XReg::AX, Width::W, false};
            case ZYDIS_REGISTER_CX:   return {XReg::CX, Width::W, false};
            case ZYDIS_REGISTER_DX:   return {XReg::DX, Width::W, false};
            case ZYDIS_REGISTER_BX:   return {XReg::BX, Width::W, false};
            case ZYDIS_REGISTER_SP:   return {XReg::SP, Width::W, false};
            case ZYDIS_REGISTER_BP:   return {XReg::BP, Width::W, false};
            case ZYDIS_REGISTER_SI:   return {XReg::SI, Width::W, false};
            case ZYDIS_REGISTER_DI:   return {XReg::DI, Width::W, false};
            case ZYDIS_REGISTER_R8W:  return {XReg::R8, Width::W, false};
            case ZYDIS_REGISTER_R9W:  return {XReg::R9, Width::W, false};
            case ZYDIS_REGISTER_R10W: return {XReg::R10,Width::W, false};
            case ZYDIS_REGISTER_R11W: return {XReg::R11,Width::W, false};
            case ZYDIS_REGISTER_R12W: return {XReg::R12,Width::W, false};
            case ZYDIS_REGISTER_R13W: return {XReg::R13,Width::W, false};
            case ZYDIS_REGISTER_R14W: return {XReg::R14,Width::W, false};
            case ZYDIS_REGISTER_R15W: return {XReg::R15,Width::W, false};

            // 32-bit
            case ZYDIS_REGISTER_EAX:  return {XReg::AX, Width::D, false};
            case ZYDIS_REGISTER_ECX:  return {XReg::CX, Width::D, false};
            case ZYDIS_REGISTER_EDX:  return {XReg::DX, Width::D, false};
            case ZYDIS_REGISTER_EBX:  return {XReg::BX, Width::D, false};
            case ZYDIS_REGISTER_ESP:  return {XReg::SP, Width::D, false};
            case ZYDIS_REGISTER_EBP:  return {XReg::BP, Width::D, false};
            case ZYDIS_REGISTER_ESI:  return {XReg::SI, Width::D, false};
            case ZYDIS_REGISTER_EDI:  return {XReg::DI, Width::D, false};
            case ZYDIS_REGISTER_R8D:  return {XReg::R8, Width::D, false};
            case ZYDIS_REGISTER_R9D:  return {XReg::R9, Width::D, false};
            case ZYDIS_REGISTER_R10D: return {XReg::R10,Width::D, false};
            case ZYDIS_REGISTER_R11D: return {XReg::R11,Width::D, false};
            case ZYDIS_REGISTER_R12D: return {XReg::R12,Width::D, false};
            case ZYDIS_REGISTER_R13D: return {XReg::R13,Width::D, false};
            case ZYDIS_REGISTER_R14D: return {XReg::R14,Width::D, false};
            case ZYDIS_REGISTER_R15D: return {XReg::R15,Width::D, false};
            
            // 64-bit
            case ZYDIS_REGISTER_RAX:  return {XReg::AX, Width::Q, false};
            case ZYDIS_REGISTER_RCX:  return {XReg::CX, Width::Q, false};
            case ZYDIS_REGISTER_RDX:  return {XReg::DX, Width::Q, false};
            case ZYDIS_REGISTER_RBX:  return {XReg::BX, Width::Q, false};
            case ZYDIS_REGISTER_RSP:  return {XReg::SP, Width::Q, false};
            case ZYDIS_REGISTER_RBP:  return {XReg::BP, Width::Q, false};
            case ZYDIS_REGISTER_RSI:  return {XReg::SI, Width::Q, false};
            case ZYDIS_REGISTER_RDI:  return {XReg::DI, Width::Q, false};
            case ZYDIS_REGISTER_R8:   return {XReg::R8, Width::Q, false};
            case ZYDIS_REGISTER_R9:   return {XReg::R9, Width::Q, false};
            case ZYDIS_REGISTER_R10:  return {XReg::R10,Width::Q, false};
            case ZYDIS_REGISTER_R11:  return {XReg::R11,Width::Q, false};
            case ZYDIS_REGISTER_R12:  return {XReg::R12,Width::Q, false};
            case ZYDIS_REGISTER_R13:  return {XReg::R13,Width::Q, false};
            case ZYDIS_REGISTER_R14:  return {XReg::R14,Width::Q, false};
            case ZYDIS_REGISTER_R15:  return {XReg::R15,Width::Q, false};

            case ZYDIS_REGISTER_RIP:
            case ZYDIS_REGISTER_EIP:
            case ZYDIS_REGISTER_IP:
            case ZYDIS_REGISTER_NONE:
            default: return {XReg::Invalid, Width::Q, false};
        }
    }

    VirReg zreg_to_virreg(ZydisRegister r, Width fallback) {
        const auto d = decode_zreg(r);
        if (d.reg == XReg::Invalid) {
            return {XReg::Invalid, fallback, false};
        }
        return {d.reg, d.width, d.is_high_byte};
    }

    static std::uint8_t seg_to_id(ZydisRegister seg) noexcept {
        if (seg == ZYDIS_REGISTER_FS) return 1;
        if (seg == ZYDIS_REGISTER_GS) return 2;
        return 0;
    }

    Mem zmem_to_mem(const ZydisDecodedOperand& op, Width w) {
        Mem m;
        m.width = w;

        if (op.mem.base != ZYDIS_REGISTER_NONE) {
            m.base = decode_zreg(op.mem.base).reg;
        }

        if (op.mem.index != ZYDIS_REGISTER_NONE) {
            m.index = decode_zreg(op.mem.index).reg;
            m.scale = static_cast<std::uint8_t>(op.mem.scale);
        }

        if (op.mem.disp.has_displacement) {
            m.disp = static_cast<std::int32_t>(op.mem.disp.value);
        }

        m.seg_override = seg_to_id(op.mem.segment);
        return m;
    }

    Imm zimm_to_imm(const ZydisDecodedOperand& op, Width w) {
        Imm im{};
        im.width = w;

        if (op.imm.is_signed) {
            im.value = op.imm.value.s;
        }
        else {
            im.value = static_cast<std::int64_t>(op.imm.value.u);
        }

        return im;
    }

    // convert one Zydis operand into an IR Operand, applying override
    // width when the operand is an immediate or memory ref
    static Operand convert_operand(const ZydisDecodedOperand& op, Width fallback_width) {
        if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            return zreg_to_virreg(op.reg.value, fallback_width);
        }

        if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            return zmem_to_mem(op, fallback_width);
        }

        if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            return zimm_to_imm(op, fallback_width);
        }

        // POINTER, UNUSED etc, never seen in shellcode
        return Imm{0, fallback_width};
    }

    static Width insn_width(const ZydisDecodedInstruction& insn) {
        return width_from_zsize(insn.operand_width);
    }

    // emits a binary op dst op= src 
    static void emit_binop_with_mem(IRBuilder& b, IROp op, FlagsOp fk, Width w,
                                    const ZydisDecodedOperand& dst,
                                    const ZydisDecodedOperand& src) {
        if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            Mem m = zmem_to_mem(dst, w);
            b.push(IROp::LOAD, w).add(VirReg{XReg::Tmp0, w, false}).add(m);
            
            auto& ir = b.push(op, w);
            ir.flags_kind = fk;
            ir.add(VirReg{XReg::Tmp0, w, false});
            ir.add(convert_operand(src, w));
            b.push(IROp::STORE, w).add(m).add(VirReg{XReg::Tmp0, w, false});

            return;
        }

        auto& ir = b.push(op, w);
        ir.flags_kind = fk;
        ir.add(convert_operand(dst, w));
        ir.add(convert_operand(src, w));
    }

    static void emit_unaryop_with_mem(IRBuilder& b, IROp op, FlagsOp fk, Width w,
                                      const ZydisDecodedOperand& dst) {
        if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            Mem m = zmem_to_mem(dst, w);
            b.push(IROp::LOAD, w).add(VirReg{XReg::Tmp0, w, false}).add(m);
            
            auto& ir = b.push(op, w);
            ir.flags_kind = fk;
            ir.add(VirReg{XReg::Tmp0, w, false});
            b.push(IROp::STORE, w).add(m).add(VirReg{XReg::Tmp0, w, false});
            
            return;
        }

        auto& ir = b.push(op, w);
        ir.flags_kind = fk;
        ir.add(convert_operand(dst, w));
    }

    LifterRegistry::LifterRegistry() {
        register_lifter(std::make_unique<MovLifter>());
        register_lifter(std::make_unique<MovExtLifter>());
        register_lifter(std::make_unique<LeaLifter>());
        register_lifter(std::make_unique<AddSubLifter>());
        register_lifter(std::make_unique<LogicLifter>());
        register_lifter(std::make_unique<NegNotLifter>());
        register_lifter(std::make_unique<IncDecLifter>());
        register_lifter(std::make_unique<ShiftLifter>());
        register_lifter(std::make_unique<CmpTestLifter>());
        register_lifter(std::make_unique<JmpLifter>());
        register_lifter(std::make_unique<JccLifter>());
        register_lifter(std::make_unique<CallLifter>());
        register_lifter(std::make_unique<RetLifter>());
        register_lifter(std::make_unique<PushPopLifter>());
        register_lifter(std::make_unique<XchgLifter>());
        register_lifter(std::make_unique<SetccLifter>());
        register_lifter(std::make_unique<StringOpLifter>());
        register_lifter(std::make_unique<LoopLifter>());
        register_lifter(std::make_unique<CdqeLifter>());
        register_lifter(std::make_unique<NopLifter>());
        register_lifter(std::make_unique<BswapLifter>());
        register_lifter(std::make_unique<ImulLifter>());
        register_lifter(std::make_unique<JcxzLifter>());
        register_lifter(std::make_unique<PushadPopadLifter>());
        register_lifter(std::make_unique<LeaveLifter>());
        register_lifter(std::make_unique<CdqLifter>());
        register_lifter(std::make_unique<CmovccLifter>());
    }

    void LifterRegistry::register_lifter(std::unique_ptr<InstructionLifter> lf) {
        for (auto mn : lf->mnemonics()) {
            by_mnemonic_[mn] = lf.get();
        }
        owners_.push_back(std::move(lf));
    }

    const InstructionLifter* LifterRegistry::find(ZydisMnemonic mn) const {
        auto it = by_mnemonic_.find(mn);
        return it == by_mnemonic_.end() ? nullptr : it->second;
    }

    IRProgram LifterRegistry::lift_program(const CFGBuilder& cfg) const {
        IRProgram prog;
        prog.arch = cfg.arch();
        prog.entry_va = cfg.base_va();

        ZydisDecoder decoder{};
        const auto mm = (cfg.arch() == Arch::X64) ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32;
        const auto sw = (cfg.arch() == Arch::X64) ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32;
        if (ZYAN_FAILED(ZydisDecoderInit(&decoder, mm, sw))) {
            throw Error("ZydisDecoderInit failed");
        }

        const auto code = cfg.code();
        const auto base = cfg.base_va();

        // collect every unsupported mnemonic, then report them all after
        // the full pass 
        std::set<std::string> unsupported_mnems;

        prog.blocks.reserve(cfg.blocks().size());
        const auto& cfg_blocks = cfg.blocks();
        for (std::size_t bi = 0; bi < cfg_blocks.size(); ++bi) {
            const auto& cb = cfg_blocks[bi];
            IRBlock blk;
            blk.id = static_cast<std::uint32_t>(prog.blocks.size());
            blk.start_va = cb.start_va;
            prog.va_to_block.emplace_back(cb.start_va, blk.id);

            IRBuilder builder{blk};
            for (std::uint64_t va : cb.insn_vas) {
                const std::size_t off = static_cast<std::size_t>(va - base);
                const std::size_t avail = code.size - off;

                ZydisDecodedInstruction insn{};
                ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
                if (ZYAN_FAILED(ZydisDecoderDecodeFull(
                                    &decoder,
                                    code.data + off,
                                    avail,
                                    &insn,
                                    ops
                                ))) {
                    throw Error("decoder failed mid-lift");
                }

                LiftContext ctx{
                    cfg.arch(),
                    va,
                    va + insn.length,
                    insn,
                    ops,
                    cfg,
                };

                const auto* lf = find(insn.mnemonic);
                if (!lf) {
                    // record and skip so the rest of the lift can keep
                    // going and surface every missing mnemonic in one
                    // shot 
                    unsupported_mnems.insert(ZydisMnemonicGetString(insn.mnemonic));
                    continue;
                }
                const auto before = blk.insns.size();
                lf->lift(builder, ctx);
                for (auto i = before; i < blk.insns.size(); ++i) blk.insns[i].src_pc = va;
            }

            // cipher-state resync invariant 
            const auto is_hard_terminator = [](IROp op) {
                return op == IROp::BR         || op == IROp::RET_VM     ||
                       op == IROp::RET_NATIVE || op == IROp::JMP_NATIVE ||
                       op == IROp::EXIT;
            };

            const auto reaches_next_byte = [](IROp op) {
                // true if after this insn's handler the runtime naturally
                // continues with the next encoded insn 
                return op == IROp::BR_CC || op == IROp::CALL_VM || op == IROp::LOOP_DEC || op == IROp::CALL_NATIVE;
            };

            const bool need_terminator = blk.insns.empty() || (!is_hard_terminator(blk.insns.back().op) && !reaches_next_byte(blk.insns.back().op));

            if (need_terminator && bi + 1 < cfg_blocks.size()) {
                const std::uint64_t next_va = cfg_blocks[bi + 1].start_va;
                const std::uint64_t src_pc  = blk.insns.empty() ? cb.start_va : blk.insns.back().src_pc;
                auto& ir = builder.push(IROp::BR, Width::Q);
                ir.target_va = next_va;
                ir.src_pc    = src_pc;
            }

            prog.blocks.push_back(std::move(blk));
        }

        // sort by va for fast lookup.
        std::sort(prog.va_to_block.begin(), prog.va_to_block.end());

        // carry forward data ranges.
        for (const auto& dr : cfg.data_ranges()) {
            IRProgram::DataChunk dc;
            dc.start_va = dr.start_va;
            const auto* src = code.data + (dr.start_va - base);
            dc.bytes.assign(src, src + (dr.end_va - dr.start_va));
            prog.data_chunks.push_back(std::move(dc));
        }

        if (!unsupported_mnems.empty()) {
            std::string msg = "unsupported mnemonics:";
            for (const auto& m : unsupported_mnems) { msg += ' '; msg += m; }
            throw Error(msg);
        }

        return prog;
    }

    std::uint32_t IRProgram::block_id_for(std::uint64_t va) const {
        auto it = std::lower_bound(va_to_block.begin(), va_to_block.end(), std::pair<std::uint64_t, std::uint32_t>{va, 0});
        if (it != va_to_block.end() && it->first == va) return it->second;
        throw Error("no block at va " + std::to_string(va));
    }

    std::optional<std::pair<std::size_t, std::size_t>>
    IRProgram::data_chunk_for(std::uint64_t va) const {
        for (std::size_t i = 0; i < data_chunks.size(); ++i) {
            const auto& dc = data_chunks[i];
            if (va >= dc.start_va && va < dc.start_va + dc.bytes.size()) {
                return std::make_pair(i, static_cast<std::size_t>(va - dc.start_va));
            }
        }
        return std::nullopt;
    }

    const char* ir_op_name(IROp o) noexcept {
        switch (o) {
            case IROp::IMM:         return "IMM";
            case IROp::MOV:         return "MOV";
            case IROp::ZEXT:        return "ZEXT";
            case IROp::SEXT:        return "SEXT";
            case IROp::BSWAP:       return "BSWAP";
            case IROp::LOAD:        return "LOAD";
            case IROp::STORE:       return "STORE";
            case IROp::LEA:         return "LEA";
            case IROp::READ_SEG:    return "READ_SEG";
            case IROp::ADD:         return "ADD";
            case IROp::ADC:         return "ADC";
            case IROp::SUB:         return "SUB";
            case IROp::SBB:         return "SBB";
            case IROp::NEG:         return "NEG";
            case IROp::INC:         return "INC";
            case IROp::DEC:         return "DEC";
            case IROp::IMUL:        return "IMUL";
            case IROp::MUL:         return "MUL";
            case IROp::IDIV:        return "IDIV";
            case IROp::DIV:         return "DIV";
            case IROp::AND:         return "AND";
            case IROp::OR:          return "OR";
            case IROp::XOR:         return "XOR";
            case IROp::NOT:         return "NOT";
            case IROp::SHL:         return "SHL";
            case IROp::SHR:         return "SHR";
            case IROp::SAR:         return "SAR";
            case IROp::ROL:         return "ROL";
            case IROp::ROR:         return "ROR";
            case IROp::RCL:         return "RCL";
            case IROp::RCR:         return "RCR";
            case IROp::CMP:         return "CMP";
            case IROp::TEST:        return "TEST";
            case IROp::SETCC:       return "SETCC";
            case IROp::BR_CC:       return "BR_CC";
            case IROp::BR:          return "BR";
            case IROp::BR_IND:      return "BR_IND";
            case IROp::CALL_VM:     return "CALL_VM";
            case IROp::RET_VM:      return "RET_VM";
            case IROp::CALL_NATIVE: return "CALL_NATIVE";
            case IROp::JMP_NATIVE:  return "JMP_NATIVE";
            case IROp::RET_NATIVE:  return "RET_NATIVE";
            case IROp::PUSH:        return "PUSH";
            case IROp::POP:         return "POP";
            case IROp::XCHG:        return "XCHG";
            case IROp::CLD:         return "CLD";
            case IROp::STD:         return "STD";
            case IROp::NOP:         return "NOP";
            case IROp::EXIT:        return "EXIT";
            case IROp::LOOP_DEC:    return "LOOP_DEC";
            case IROp::CDQE:        return "CDQE";
            case IROp::STOSB:       return "STOSB";
            case IROp::LODSB:       return "LODSB";
            case IROp::MOVSB:       return "MOVSB";
            case IROp::CMPSB:       return "CMPSB";
            case IROp::SCASB:       return "SCASB";
            case IROp::REP_PREFIX:  return "REP_PREFIX";
        }

        return "?";
    }

    const char* ir_op_family(IROp o) noexcept {
        switch (o) {
            case IROp::IMM:         return "IMM";
            case IROp::MOV:         return "MOV";
            case IROp::ZEXT:
            case IROp::SEXT:        return "EXT";
            case IROp::BSWAP:       return "BSWAP";
            case IROp::LOAD:        return "LOAD";
            case IROp::STORE:       return "STORE";
            case IROp::LEA:         return "LEA";
            case IROp::READ_SEG:    return "READ_SEG";
            case IROp::ADD:
            case IROp::ADC:
            case IROp::SUB:
            case IROp::SBB:
            case IROp::NEG:
            case IROp::INC:
            case IROp::DEC:         return "ARITH";
            case IROp::IMUL:
            case IROp::MUL:         return "MUL";
            case IROp::IDIV:
            case IROp::DIV:         return "DIV";
            case IROp::AND:
            case IROp::OR:
            case IROp::XOR:
            case IROp::NOT:         return "LOGIC";
            case IROp::SHL:
            case IROp::SHR:
            case IROp::SAR:
            case IROp::ROL:
            case IROp::ROR:
            case IROp::RCL:
            case IROp::RCR:         return "SHIFT";
            case IROp::CMP:
            case IROp::TEST:        return "CMP";
            case IROp::SETCC:       return "SETCC";
            case IROp::BR_CC:       return "BRCC";
            case IROp::BR:          return "BR";
            case IROp::BR_IND:      return "BRIND";
            case IROp::CALL_VM:     return "CALLVM";
            case IROp::RET_VM:      return "RETVM";
            case IROp::CALL_NATIVE: return "CALLNATIVE";
            case IROp::JMP_NATIVE:  return "JMPNATIVE";
            case IROp::RET_NATIVE:  return "RETNATIVE";
            case IROp::PUSH:        return "PUSH";
            case IROp::POP:         return "POP";
            case IROp::XCHG:        return "XCHG";
            case IROp::CLD:
            case IROp::STD:         return "DF";
            case IROp::NOP:         return "NOP";
            case IROp::EXIT:        return "EXIT";
            case IROp::LOOP_DEC:    return "LOOP";
            case IROp::CDQE:        return "CDQE";
            case IROp::STOSB:
            case IROp::LODSB:
            case IROp::MOVSB:
            case IROp::CMPSB:
            case IROp::SCASB:       return "STRING";
            case IROp::REP_PREFIX:  return "REP";
        }
        
        return "?";
    }

    std::vector<ZydisMnemonic> MovLifter::mnemonics() const {
        return {ZYDIS_MNEMONIC_MOV};
    }

    void MovLifter::lift(IRBuilder& b, const LiftContext& ctx) const {
        const auto& insn = ctx.insn;
        const auto& dst = ctx.ops[0];
        const auto& src = ctx.ops[1];
        const Width w = insn_width(insn);

        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            b.push(IROp::MOV, w).add(zreg_to_virreg(dst.reg.value, w)).add(zreg_to_virreg(src.reg.value, w));
        } 
        else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            b.push(IROp::IMM, w).add(zreg_to_virreg(dst.reg.value, w)).add(zimm_to_imm(src, w));
        } 
        else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            b.push(IROp::LOAD, w).add(zreg_to_virreg(dst.reg.value, w)).add(zmem_to_mem(src, w));
        } 
        else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            b.push(IROp::STORE, w).add(zmem_to_mem(dst, w)).add(zreg_to_virreg(src.reg.value, w));
        } 
        else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            b.push(IROp::STORE, w).add(zmem_to_mem(dst, w)).add(zimm_to_imm(src, w));
        } 
        else {
            throw Error("mov: unsupported operand combo");
        }
    }

    std::vector<ZydisMnemonic> MovExtLifter::mnemonics() const {
        return {ZYDIS_MNEMONIC_MOVZX, ZYDIS_MNEMONIC_MOVSX, ZYDIS_MNEMONIC_MOVSXD};
    }

    void MovExtLifter::lift(IRBuilder& b, const LiftContext& ctx) const {
        const auto& insn = ctx.insn;
        const auto& dst = ctx.ops[0];
        const auto& src = ctx.ops[1];

        if (dst.type != ZYDIS_OPERAND_TYPE_REGISTER) {
            throw Error("movext: destination must be a register");
        }

        const auto dst_d = decode_zreg(dst.reg.value);
        const Width dst_w = dst_d.width;
        Width src_w = Width::B;

        if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            src_w = decode_zreg(src.reg.value).width;
        }
        else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            src_w = width_from_zsize(src.size);
        }

        const bool is_signed = (insn.mnemonic == ZYDIS_MNEMONIC_MOVSX) || (insn.mnemonic == ZYDIS_MNEMONIC_MOVSXD);
        const IROp op = is_signed ? IROp::SEXT : IROp::ZEXT;

        auto& ir = b.push(op, dst_w);
        ir.add(VirReg{dst_d.reg, dst_w, dst_d.is_high_byte});
        if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            ir.add(zreg_to_virreg(src.reg.value, src_w));
        }
        else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            ir.add(zmem_to_mem(src, src_w));
        }
        else {
            throw Error("movext: bad source operand");
        }

        // source width rides along in the destination's aux slot as an Imm mark.
        ir.add(Imm{static_cast<std::int64_t>(width_bytes(src_w)), Width::B});
    }

    // LeaLifter, LEA reg, mem. the mem expr is the address, never derefed.

    std::vector<ZydisMnemonic> LeaLifter::mnemonics() const {
        return {ZYDIS_MNEMONIC_LEA};
    }

    void LeaLifter::lift(IRBuilder& b, const LiftContext& ctx) const {
        const auto& insn = ctx.insn;
        const auto& dst = ctx.ops[0];
        const auto& src = ctx.ops[1];
        if (dst.type != ZYDIS_OPERAND_TYPE_REGISTER) throw Error("lea: bad dst");
        if (src.type != ZYDIS_OPERAND_TYPE_MEMORY)   throw Error("lea: bad src");

        // rip-relative: collapse to absolute as next_va + disp 
        Mem m = zmem_to_mem(src, insn_width(insn));
        if (src.mem.base == ZYDIS_REGISTER_RIP || src.mem.base == ZYDIS_REGISTER_EIP) {
            // encode as a label-style ref
            const std::int64_t abs_va = static_cast<std::int64_t>(ctx.next_va) + m.disp;
            b.push(IROp::LEA, insn_width(insn))
             .add(zreg_to_virreg(dst.reg.value, insn_width(insn)))
             .add(Imm{abs_va, Width::Q})
             .add(Imm{1, Width::B}); // marker: rip-rel data island
            return;
        }

        b.push(IROp::LEA, insn_width(insn))
         .add(zreg_to_virreg(dst.reg.value, insn_width(insn)))
         .add(m)
         .add(Imm{0, Width::B}); // marker: normal address calc
    }

    std::vector<ZydisMnemonic> AddSubLifter::mnemonics() const {
        return {ZYDIS_MNEMONIC_ADD, ZYDIS_MNEMONIC_ADC, ZYDIS_MNEMONIC_SUB, ZYDIS_MNEMONIC_SBB};
    }

    void AddSubLifter::lift(IRBuilder& b, const LiftContext& ctx) const {
        const Width w = insn_width(ctx.insn);
        IROp op = IROp::ADD;
        FlagsOp fk = FlagsOp::ADD;

        switch (ctx.insn.mnemonic) {
            case ZYDIS_MNEMONIC_ADD: op = IROp::ADD; fk = FlagsOp::ADD; break;
            case ZYDIS_MNEMONIC_ADC: op = IROp::ADC; fk = FlagsOp::ADD; break;
            case ZYDIS_MNEMONIC_SUB: op = IROp::SUB; fk = FlagsOp::SUB; break;
            case ZYDIS_MNEMONIC_SBB: op = IROp::SBB; fk = FlagsOp::SUB; break;
            default: break;
        }

        emit_binop_with_mem(
            b,
            op,
            fk,
            w,
            ctx.ops[0],
            ctx.ops[1]
        );
    }

    // LogicLifter: AND/OR/XOR

    std::vector<ZydisMnemonic> LogicLifter::mnemonics() const {
        return {ZYDIS_MNEMONIC_AND, ZYDIS_MNEMONIC_OR, ZYDIS_MNEMONIC_XOR};
    }

    void LogicLifter::lift(IRBuilder& b, const LiftContext& ctx) const {
        const Width w = insn_width(ctx.insn);
        IROp op = IROp::AND;
        switch (ctx.insn.mnemonic) {
            case ZYDIS_MNEMONIC_AND: op = IROp::AND; break;
            case ZYDIS_MNEMONIC_OR:  op = IROp::OR;  break;
            case ZYDIS_MNEMONIC_XOR: op = IROp::XOR; break;
            default: break;
        }
        emit_binop_with_mem(
            b,
            op,
            FlagsOp::LOGIC,
            w,
            ctx.ops[0],
            ctx.ops[1]
        );
    }

    std::vector<ZydisMnemonic> NegNotLifter::mnemonics() const {
        return {ZYDIS_MNEMONIC_NEG, ZYDIS_MNEMONIC_NOT};
    }

    void NegNotLifter::lift(IRBuilder& b, const LiftContext& ctx) const {
        const Width w = insn_width(ctx.insn);
        const IROp op = (ctx.insn.mnemonic == ZYDIS_MNEMONIC_NEG) ? IROp::NEG : IROp::NOT;
        const FlagsOp fk = (op == IROp::NEG) ? FlagsOp::NEG : FlagsOp::NONE;
        emit_unaryop_with_mem(
            b,
            op,
            fk,
            w,
            ctx.ops[0]
        );
    }

    std::vector<ZydisMnemonic> IncDecLifter::mnemonics() const {
        return {ZYDIS_MNEMONIC_INC, ZYDIS_MNEMONIC_DEC};
    }

    void IncDecLifter::lift(IRBuilder& b, const LiftContext& ctx) const {
        const Width w = insn_width(ctx.insn);
        const IROp op = (ctx.insn.mnemonic == ZYDIS_MNEMONIC_INC) ? IROp::INC : IROp::DEC;
        const FlagsOp fk = (op == IROp::INC) ? FlagsOp::INC : FlagsOp::DEC;
        emit_unaryop_with_mem(
            b,
            op,
            fk,
            w,
            ctx.ops[0]
        );
    }

    std::vector<ZydisMnemonic> ShiftLifter::mnemonics() const {
        return {ZYDIS_MNEMONIC_SHL, ZYDIS_MNEMONIC_SHR, ZYDIS_MNEMONIC_SAR,
                ZYDIS_MNEMONIC_ROL, ZYDIS_MNEMONIC_ROR,
                ZYDIS_MNEMONIC_RCL, ZYDIS_MNEMONIC_RCR};
    }

    void ShiftLifter::lift(IRBuilder& b, const LiftContext& ctx) const {
        const Width w = insn_width(ctx.insn);
        IROp op = IROp::SHL;
        FlagsOp fk = FlagsOp::SHL;

        switch (ctx.insn.mnemonic) {
            case ZYDIS_MNEMONIC_SHL: op = IROp::SHL; fk = FlagsOp::SHL; break;
            case ZYDIS_MNEMONIC_SHR: op = IROp::SHR; fk = FlagsOp::SHR; break;
            case ZYDIS_MNEMONIC_SAR: op = IROp::SAR; fk = FlagsOp::SAR; break;
            case ZYDIS_MNEMONIC_ROL: op = IROp::ROL; fk = FlagsOp::LOGIC; break;
            case ZYDIS_MNEMONIC_ROR: op = IROp::ROR; fk = FlagsOp::LOGIC; break;
            case ZYDIS_MNEMONIC_RCL: op = IROp::RCL; fk = FlagsOp::LOGIC; break;
            case ZYDIS_MNEMONIC_RCR: op = IROp::RCR; fk = FlagsOp::LOGIC; break;
            default: break;
        }

        const auto& dst = ctx.ops[0];
        if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            Mem m = zmem_to_mem(dst, w);
            b.push(IROp::LOAD, w).add(VirReg{XReg::Tmp0, w, false}).add(m);
            auto& ir = b.push(op, w);
            ir.flags_kind = fk;
            ir.add(VirReg{XReg::Tmp0, w, false});
            ir.add(convert_operand(ctx.ops[1], Width::B));
            b.push(IROp::STORE, w).add(m).add(VirReg{XReg::Tmp0, w, false});
            return;
        }

        auto& ir = b.push(op, w);
        ir.flags_kind = fk;
        ir.add(convert_operand(ctx.ops[0], w));
        ir.add(convert_operand(ctx.ops[1], Width::B));
    }

    std::vector<ZydisMnemonic> CmpTestLifter::mnemonics() const {
        return {ZYDIS_MNEMONIC_CMP, ZYDIS_MNEMONIC_TEST};
    }

    void CmpTestLifter::lift(IRBuilder& b, const LiftContext& ctx) const {
        const Width w = insn_width(ctx.insn);
        const bool is_test = (ctx.insn.mnemonic == ZYDIS_MNEMONIC_TEST);
        const IROp irop = is_test ? IROp::TEST : IROp::CMP;
        const FlagsOp fk = is_test ? FlagsOp::LOGIC : FlagsOp::SUB;

        auto materialize = [&](const ZydisDecodedOperand& op, XReg tmp) -> Operand {
            if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                Mem m = zmem_to_mem(op, w);
                b.push(IROp::LOAD, w)
                 .add(VirReg{tmp, w, false})
                 .add(m);
                return VirReg{tmp, w, false};
            }
            return convert_operand(op, w);
        };

        auto a = materialize(ctx.ops[0], XReg::Tmp0);
        auto bop = materialize(ctx.ops[1], XReg::Tmp1);
        auto& ir = b.push(irop, w);
        ir.flags_kind = fk;
        ir.add(std::move(a));
        ir.add(std::move(bop));
    }

    std::vector<ZydisMnemonic> JmpLifter::mnemonics() const {
        return {ZYDIS_MNEMONIC_JMP};
    }

    void JmpLifter::lift(IRBuilder& b, const LiftContext& ctx) const {
        const auto& op0 = ctx.ops[0];
        if (op0.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op0.imm.is_relative) {
            ZyanU64 abs = 0;
            ZydisCalcAbsoluteAddress(
                &ctx.insn,
                &op0,
                ctx.va,
                &abs
            );

            if (ctx.cfg.in_lifted(abs)) {
                auto& ir = b.push(IROp::BR, Width::Q);
                ir.target_va = abs;
            } 
            else {
                // target sits outside the lifted region
                auto& ir = b.push(IROp::JMP_NATIVE, Width::Q);
                ir.add(Imm{static_cast<std::int64_t>(abs), Width::Q});
            }

            return;
        }

        if (op0.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            // indirect jmp via register 
            auto& ir = b.push(IROp::JMP_NATIVE, Width::Q);
            ir.add(zreg_to_virreg(op0.reg.value, insn_width(ctx.insn)));
            return;
        }

        if (op0.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            // jmp mem. load then jump, the loaded value better be a native ptr
            auto& ir = b.push(IROp::JMP_NATIVE, Width::Q);
            ir.add(zmem_to_mem(op0, insn_width(ctx.insn)));
            return;
        }

        throw Error("jmp: unsupported operand");
    }

    static Cond zmn_to_cond(ZydisMnemonic m) {
        switch (m) {
            case ZYDIS_MNEMONIC_JO:   return Cond::O;
            case ZYDIS_MNEMONIC_JNO:  return Cond::NO;
            case ZYDIS_MNEMONIC_JB:   return Cond::B;
            case ZYDIS_MNEMONIC_JNB:  return Cond::NB;
            case ZYDIS_MNEMONIC_JZ:   return Cond::Z;
            case ZYDIS_MNEMONIC_JNZ:  return Cond::NZ;
            case ZYDIS_MNEMONIC_JBE:  return Cond::BE;
            case ZYDIS_MNEMONIC_JNBE: return Cond::NBE;
            case ZYDIS_MNEMONIC_JS:   return Cond::S;
            case ZYDIS_MNEMONIC_JNS:  return Cond::NS;
            case ZYDIS_MNEMONIC_JP:   return Cond::P;
            case ZYDIS_MNEMONIC_JNP:  return Cond::NP;
            case ZYDIS_MNEMONIC_JL:   return Cond::L;
            case ZYDIS_MNEMONIC_JNL:  return Cond::NL;
            case ZYDIS_MNEMONIC_JLE:  return Cond::LE;
            case ZYDIS_MNEMONIC_JNLE: return Cond::NLE;
            default: throw Error("zmn_to_cond: not a jcc mnemonic");
        }
    }

    std::vector<ZydisMnemonic> JccLifter::mnemonics() const {
        return {
            ZYDIS_MNEMONIC_JO,  ZYDIS_MNEMONIC_JNO,
            ZYDIS_MNEMONIC_JB,  ZYDIS_MNEMONIC_JNB,
            ZYDIS_MNEMONIC_JZ,  ZYDIS_MNEMONIC_JNZ,
            ZYDIS_MNEMONIC_JBE, ZYDIS_MNEMONIC_JNBE,
            ZYDIS_MNEMONIC_JS,  ZYDIS_MNEMONIC_JNS,
            ZYDIS_MNEMONIC_JP,  ZYDIS_MNEMONIC_JNP,
            ZYDIS_MNEMONIC_JL,  ZYDIS_MNEMONIC_JNL,
            ZYDIS_MNEMONIC_JLE, ZYDIS_MNEMONIC_JNLE,
        };
    }

    void JccLifter::lift(IRBuilder& b, const LiftContext& ctx) const {
        const auto& op0 = ctx.ops[0];
        if (op0.type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !op0.imm.is_relative) {
            throw Error("jcc: non-relative target");
        }

        ZyanU64 abs = 0;
        ZydisCalcAbsoluteAddress(
            &ctx.insn,
            &op0,
            ctx.va,
            &abs
        );

        // if the target is outside the shellcode, drop the branch 
        if (!ctx.cfg.in_code(abs)) {
            b.push(IROp::NOP, Width::Q);
            return;
        }

        auto& ir = b.push(IROp::BR_CC, Width::Q);
        ir.cond = zmn_to_cond(ctx.insn.mnemonic);
        ir.target_va = abs;
    }

    std::vector<ZydisMnemonic> CallLifter::mnemonics() const {
        return {ZYDIS_MNEMONIC_CALL};
    }

    void CallLifter::lift(IRBuilder& b, const LiftContext& ctx) const {
        const auto& op0 = ctx.ops[0];
        const std::uint64_t ret_va = ctx.va + ctx.insn.length;
        if (op0.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op0.imm.is_relative) {
            ZyanU64 abs = 0;
            ZydisCalcAbsoluteAddress(
                &ctx.insn,
                &op0,
                ctx.va,
                &abs
            );

            if (ctx.cfg.in_lifted(abs)) {
                auto& ir = b.push(IROp::CALL_VM, Width::Q);
                ir.target_va = abs;
                ir.return_va = ret_va;
            } 
            else {
                auto& ir = b.push(IROp::CALL_NATIVE, Width::Q);
                ir.add(Imm{static_cast<std::int64_t>(abs), Width::Q});
                ir.return_va = ret_va;
            }

            return;
        }

        if (op0.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            auto& ir = b.push(IROp::CALL_NATIVE, Width::Q);
            ir.add(zreg_to_virreg(op0.reg.value, Width::Q));
            ir.return_va = ret_va;
            return;
        }

        if (op0.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            auto& ir = b.push(IROp::CALL_NATIVE, Width::Q);
            ir.add(zmem_to_mem(op0, Width::Q));
            ir.return_va = ret_va;
            return;
        }

        throw Error("call: unsupported operand");
    }

    std::vector<ZydisMnemonic> RetLifter::mnemonics() const {
        return {ZYDIS_MNEMONIC_RET};
    }

    void RetLifter::lift(IRBuilder& b, const LiftContext& ctx) const {
        auto& ir = b.push(IROp::RET_VM, Width::Q);
        if (ctx.insn.operand_count >= 1 &&
            ctx.ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            ir.add(zimm_to_imm(ctx.ops[0], Width::W));
        } 
        else {
            ir.add(Imm{0, Width::W});
        }
    }

    std::vector<ZydisMnemonic> PushPopLifter::mnemonics() const {
        return {ZYDIS_MNEMONIC_PUSH, ZYDIS_MNEMONIC_POP};
    }

    void PushPopLifter::lift(IRBuilder& b, const LiftContext& ctx) const {
        const Width w = (ctx.arch == Arch::X64) ? Width::Q : Width::D;
        const auto& op0 = ctx.ops[0];

        if (ctx.insn.mnemonic == ZYDIS_MNEMONIC_PUSH) {
            auto& ir = b.push(IROp::PUSH, w);
            ir.add(convert_operand(op0, w));
        }
        else {
            auto& ir = b.push(IROp::POP, w);
            ir.add(convert_operand(op0, w));
        }
    }

    std::vector<ZydisMnemonic> XchgLifter::mnemonics() const {
        return {ZYDIS_MNEMONIC_XCHG};
    }

    void XchgLifter::lift(IRBuilder& b, const LiftContext& ctx) const {
        const Width w = insn_width(ctx.insn);
        auto& ir = b.push(IROp::XCHG, w);
        ir.add(convert_operand(ctx.ops[0], w));
        ir.add(convert_operand(ctx.ops[1], w));
    }

    static Cond setcc_to_cond(ZydisMnemonic m) {
        switch (m) {
            case ZYDIS_MNEMONIC_SETO:   return Cond::O;
            case ZYDIS_MNEMONIC_SETNO:  return Cond::NO;
            case ZYDIS_MNEMONIC_SETB:   return Cond::B;
            case ZYDIS_MNEMONIC_SETNB:  return Cond::NB;
            case ZYDIS_MNEMONIC_SETZ:   return Cond::Z;
            case ZYDIS_MNEMONIC_SETNZ:  return Cond::NZ;
            case ZYDIS_MNEMONIC_SETBE:  return Cond::BE;
            case ZYDIS_MNEMONIC_SETNBE: return Cond::NBE;
            case ZYDIS_MNEMONIC_SETS:   return Cond::S;
            case ZYDIS_MNEMONIC_SETNS:  return Cond::NS;
            case ZYDIS_MNEMONIC_SETP:   return Cond::P;
            case ZYDIS_MNEMONIC_SETNP:  return Cond::NP;
            case ZYDIS_MNEMONIC_SETL:   return Cond::L;
            case ZYDIS_MNEMONIC_SETNL:  return Cond::NL;
            case ZYDIS_MNEMONIC_SETLE:  return Cond::LE;
            case ZYDIS_MNEMONIC_SETNLE: return Cond::NLE;
            default: throw Error("setcc: not a setcc mnemonic");
        }
    }

    std::vector<ZydisMnemonic> SetccLifter::mnemonics() const {
        return {
            ZYDIS_MNEMONIC_SETO, ZYDIS_MNEMONIC_SETNO,
            ZYDIS_MNEMONIC_SETB, ZYDIS_MNEMONIC_SETNB,
            ZYDIS_MNEMONIC_SETZ, ZYDIS_MNEMONIC_SETNZ,
            ZYDIS_MNEMONIC_SETBE,ZYDIS_MNEMONIC_SETNBE,
            ZYDIS_MNEMONIC_SETS, ZYDIS_MNEMONIC_SETNS,
            ZYDIS_MNEMONIC_SETP, ZYDIS_MNEMONIC_SETNP,
            ZYDIS_MNEMONIC_SETL, ZYDIS_MNEMONIC_SETNL,
            ZYDIS_MNEMONIC_SETLE,ZYDIS_MNEMONIC_SETNLE,
        };
    }

    void SetccLifter::lift(IRBuilder& b, const LiftContext& ctx) const {
        auto& ir = b.push(IROp::SETCC, Width::B);
        ir.cond = setcc_to_cond(ctx.insn.mnemonic);
        ir.add(convert_operand(ctx.ops[0], Width::B));
    }

    std::vector<ZydisMnemonic> StringOpLifter::mnemonics() const {
        return {ZYDIS_MNEMONIC_LODSB, ZYDIS_MNEMONIC_STOSB, ZYDIS_MNEMONIC_MOVSB,
                ZYDIS_MNEMONIC_LODSW, ZYDIS_MNEMONIC_STOSW, ZYDIS_MNEMONIC_MOVSW,
                ZYDIS_MNEMONIC_LODSD, ZYDIS_MNEMONIC_STOSD, ZYDIS_MNEMONIC_MOVSD,
                ZYDIS_MNEMONIC_LODSQ, ZYDIS_MNEMONIC_STOSQ, ZYDIS_MNEMONIC_MOVSQ,
                ZYDIS_MNEMONIC_CMPSB, ZYDIS_MNEMONIC_SCASB};
    }

    void StringOpLifter::lift(IRBuilder& b, const LiftContext& ctx) const {
        Width w = Width::B;
        IROp op = IROp::LODSB;
        switch (ctx.insn.mnemonic) {
            case ZYDIS_MNEMONIC_LODSB: w = Width::B; op = IROp::LODSB; break;
            case ZYDIS_MNEMONIC_LODSW: w = Width::W; op = IROp::LODSB; break;
            case ZYDIS_MNEMONIC_LODSD: w = Width::D; op = IROp::LODSB; break;
            case ZYDIS_MNEMONIC_LODSQ: w = Width::Q; op = IROp::LODSB; break;
            case ZYDIS_MNEMONIC_STOSB: w = Width::B; op = IROp::STOSB; break;
            case ZYDIS_MNEMONIC_STOSW: w = Width::W; op = IROp::STOSB; break;
            case ZYDIS_MNEMONIC_STOSD: w = Width::D; op = IROp::STOSB; break;
            case ZYDIS_MNEMONIC_STOSQ: w = Width::Q; op = IROp::STOSB; break;
            case ZYDIS_MNEMONIC_MOVSB: w = Width::B; op = IROp::MOVSB; break;
            case ZYDIS_MNEMONIC_MOVSW: w = Width::W; op = IROp::MOVSB; break;
            case ZYDIS_MNEMONIC_MOVSD: w = Width::D; op = IROp::MOVSB; break;
            case ZYDIS_MNEMONIC_MOVSQ: w = Width::Q; op = IROp::MOVSB; break;
            case ZYDIS_MNEMONIC_CMPSB: w = Width::B; op = IROp::CMPSB; break;
            case ZYDIS_MNEMONIC_SCASB: w = Width::B; op = IROp::SCASB; break;
            default: break;
        }

        // detect REP / REPE / REPNE.
        bool has_rep = false;
        for (std::uint8_t i = 0; i < ctx.insn.attributes ? 1 : 0; ++i) {}  // attributes is a bitset

        if (ctx.insn.attributes & ZYDIS_ATTRIB_HAS_REP)   has_rep = true;
        if (ctx.insn.attributes & ZYDIS_ATTRIB_HAS_REPE)  has_rep = true;
        if (ctx.insn.attributes & ZYDIS_ATTRIB_HAS_REPNE) has_rep = true;
        if (has_rep) {
            b.push(IROp::REP_PREFIX, w);
        }

        b.push(op, w);
    }

    std::vector<ZydisMnemonic> LoopLifter::mnemonics() const {
        return {ZYDIS_MNEMONIC_LOOP, ZYDIS_MNEMONIC_LOOPE, ZYDIS_MNEMONIC_LOOPNE};
    }

    void LoopLifter::lift(IRBuilder& b, const LiftContext& ctx) const {
        const auto& op0 = ctx.ops[0];
        ZyanU64 abs = 0;
        if (op0.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op0.imm.is_relative) {
            ZydisCalcAbsoluteAddress(
                &ctx.insn,
                &op0,
                ctx.va,
                &abs
            );
        }
        auto& ir = b.push(IROp::LOOP_DEC, Width::Q);
        ir.target_va = abs;
    }

    std::vector<ZydisMnemonic> CdqeLifter::mnemonics() const {
        return {ZYDIS_MNEMONIC_CDQE, ZYDIS_MNEMONIC_CWDE, ZYDIS_MNEMONIC_CBW};
    }

    void CdqeLifter::lift(IRBuilder& b, const LiftContext&) const {
        b.push(IROp::CDQE, Width::Q);
    }

    std::vector<ZydisMnemonic> NopLifter::mnemonics() const {
        return {
            ZYDIS_MNEMONIC_NOP, ZYDIS_MNEMONIC_CLD, ZYDIS_MNEMONIC_STD,

            // CET landing pads
            ZYDIS_MNEMONIC_ENDBR64, ZYDIS_MNEMONIC_ENDBR32,
            
            // spin-loop hint
            ZYDIS_MNEMONIC_PAUSE,
            
            // int3
            ZYDIS_MNEMONIC_INT3
        };
    }

    void NopLifter::lift(IRBuilder& b, const LiftContext& ctx) const {
        switch (ctx.insn.mnemonic) {
            case ZYDIS_MNEMONIC_CLD: b.push(IROp::CLD, Width::B); break;
            case ZYDIS_MNEMONIC_STD: b.push(IROp::STD, Width::B); break;

            // NOP, ENDBR64, ENDBR32, PAUSE, INT3 all lift to IROp::NOP.
            default: b.push(IROp::NOP, Width::B); break;
        }
    }

    std::vector<ZydisMnemonic> BswapLifter::mnemonics() const {
        return {ZYDIS_MNEMONIC_BSWAP};
    }

    void BswapLifter::lift(IRBuilder& b, const LiftContext& ctx) const {
        const Width w = insn_width(ctx.insn);
        auto& ir = b.push(IROp::BSWAP, w);
        ir.add(convert_operand(ctx.ops[0], w));
    }

    std::vector<ZydisMnemonic> ImulLifter::mnemonics() const {
        return {ZYDIS_MNEMONIC_IMUL, ZYDIS_MNEMONIC_MUL, ZYDIS_MNEMONIC_IDIV, ZYDIS_MNEMONIC_DIV};
    }

    void ImulLifter::lift(IRBuilder& b, const LiftContext& ctx) const {
        const Width w = insn_width(ctx.insn);
        IROp op = IROp::IMUL;

        switch (ctx.insn.mnemonic) {
            case ZYDIS_MNEMONIC_IMUL: op = IROp::IMUL; break;
            case ZYDIS_MNEMONIC_MUL:  op = IROp::MUL;  break;
            case ZYDIS_MNEMONIC_IDIV: op = IROp::IDIV; break;
            case ZYDIS_MNEMONIC_DIV:  op = IROp::DIV;  break;
            default: break;
        }

        auto& ir = b.push(op, w);
        for (std::uint8_t i = 0; i < ctx.insn.operand_count; ++i) {
            const auto& zop = ctx.ops[i];
            if (zop.visibility != ZYDIS_OPERAND_VISIBILITY_EXPLICIT) continue;
            ir.add(convert_operand(zop, w));
        }
    }

    std::vector<ZydisMnemonic> JcxzLifter::mnemonics() const {
        return {ZYDIS_MNEMONIC_JCXZ, ZYDIS_MNEMONIC_JECXZ, ZYDIS_MNEMONIC_JRCXZ};
    }

    void JcxzLifter::lift(IRBuilder& b, const LiftContext& ctx) const {
        const auto& op0 = ctx.ops[0];
        if (op0.type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !op0.imm.is_relative) {
            throw Error("jcxz family: non-relative target");
        }

        ZyanU64 abs = 0;
        ZydisCalcAbsoluteAddress(
            &ctx.insn,
            &op0,
            ctx.va,
            &abs
        );

        Width w = Width::Q;
        switch (ctx.insn.mnemonic) {
            case ZYDIS_MNEMONIC_JCXZ:  w = Width::W; break;
            case ZYDIS_MNEMONIC_JECXZ: w = Width::D; break;
            case ZYDIS_MNEMONIC_JRCXZ: w = Width::Q; break;
            default: break;
        }

        if (!ctx.cfg.in_code(abs)) {
            b.push(IROp::NOP, Width::Q);
            return;
        }

        // test cx/ecx/rcx against itself, ZF=1 if zero.
        auto& test = b.push(IROp::TEST, w);
        test.flags_kind = FlagsOp::LOGIC;
        test.add(VirReg{XReg::CX, w, false});
        test.add(VirReg{XReg::CX, w, false});

        auto& br = b.push(IROp::BR_CC, Width::Q);
        br.cond = Cond::Z;
        br.target_va = abs;
    }

    std::vector<ZydisMnemonic> PushadPopadLifter::mnemonics() const {
        return {ZYDIS_MNEMONIC_PUSHAD, ZYDIS_MNEMONIC_POPAD, ZYDIS_MNEMONIC_PUSHA,  ZYDIS_MNEMONIC_POPA};
    }

    void PushadPopadLifter::lift(IRBuilder& b, const LiftContext& ctx) const {
        const Width w = Width::D;
        if (ctx.insn.mnemonic == ZYDIS_MNEMONIC_PUSHAD ||
            ctx.insn.mnemonic == ZYDIS_MNEMONIC_PUSHA) {
            // stash original ESP in Tmp0 first so we can push it after the
            // earlier pushes have decremented ESP
            {
                auto& mov = b.push(IROp::MOV, w);
                mov.add(VirReg{XReg::Tmp0, w, false});
                mov.add(VirReg{XReg::SP,   w, false});
            }

            const XReg order[] = {
                XReg::AX,   XReg::CX, XReg::DX, XReg::BX,
                XReg::Tmp0, XReg::BP, XReg::SI, XReg::DI
            };

            for (auto r : order) {
                auto& p = b.push(IROp::PUSH, w);
                p.add(VirReg{r, w, false});
            }
        }
        else {
            // POPAD: pop EDI, ESI, EBP, discard saved ESP, EBX, EDX, ECX, EAX.
            const XReg order[] = {
                XReg::DI, XReg::SI, XReg::BP, XReg::Tmp0,
                XReg::BX, XReg::DX, XReg::CX, XReg::AX
            };

            for (auto r : order) {
                auto& p = b.push(IROp::POP, w);
                p.add(VirReg{r, w, false});
            }
        }
    }

    std::vector<ZydisMnemonic> LeaveLifter::mnemonics() const {
        return {ZYDIS_MNEMONIC_LEAVE};
    }

    void LeaveLifter::lift(IRBuilder& b, const LiftContext& ctx) const {
        const Width w = (ctx.arch == Arch::X64) ? Width::Q : Width::D;
        b.push(IROp::MOV, w)
         .add(VirReg{XReg::SP, w, false})
         .add(VirReg{XReg::BP, w, false});
        b.push(IROp::POP, w)
         .add(VirReg{XReg::BP, w, false});
    }

    static Cond cmov_to_cond(ZydisMnemonic m) {
        switch (m) {
            case ZYDIS_MNEMONIC_CMOVO:   return Cond::O;
            case ZYDIS_MNEMONIC_CMOVNO:  return Cond::NO;
            case ZYDIS_MNEMONIC_CMOVB:   return Cond::B;
            case ZYDIS_MNEMONIC_CMOVNB:  return Cond::NB;
            case ZYDIS_MNEMONIC_CMOVZ:   return Cond::Z;
            case ZYDIS_MNEMONIC_CMOVNZ:  return Cond::NZ;
            case ZYDIS_MNEMONIC_CMOVBE:  return Cond::BE;
            case ZYDIS_MNEMONIC_CMOVNBE: return Cond::NBE;
            case ZYDIS_MNEMONIC_CMOVS:   return Cond::S;
            case ZYDIS_MNEMONIC_CMOVNS:  return Cond::NS;
            case ZYDIS_MNEMONIC_CMOVP:   return Cond::P;
            case ZYDIS_MNEMONIC_CMOVNP:  return Cond::NP;
            case ZYDIS_MNEMONIC_CMOVL:   return Cond::L;
            case ZYDIS_MNEMONIC_CMOVNL:  return Cond::NL;
            case ZYDIS_MNEMONIC_CMOVLE:  return Cond::LE;
            case ZYDIS_MNEMONIC_CMOVNLE: return Cond::NLE;
            default: throw Error("cmov_to_cond: not a cmov mnemonic");
        }
    }

    std::vector<ZydisMnemonic> CmovccLifter::mnemonics() const {
        return {
            ZYDIS_MNEMONIC_CMOVO,  ZYDIS_MNEMONIC_CMOVNO,
            ZYDIS_MNEMONIC_CMOVB,  ZYDIS_MNEMONIC_CMOVNB,
            ZYDIS_MNEMONIC_CMOVZ,  ZYDIS_MNEMONIC_CMOVNZ,
            ZYDIS_MNEMONIC_CMOVBE, ZYDIS_MNEMONIC_CMOVNBE,
            ZYDIS_MNEMONIC_CMOVS,  ZYDIS_MNEMONIC_CMOVNS,
            ZYDIS_MNEMONIC_CMOVP,  ZYDIS_MNEMONIC_CMOVNP,
            ZYDIS_MNEMONIC_CMOVL,  ZYDIS_MNEMONIC_CMOVNL,
            ZYDIS_MNEMONIC_CMOVLE, ZYDIS_MNEMONIC_CMOVNLE,
        };
    }

    void CmovccLifter::lift(IRBuilder& b, const LiftContext& ctx) const {
        const Width w = insn_width(ctx.insn);
        const Cond cc = cmov_to_cond(ctx.insn.mnemonic);
        const auto& dst_op = ctx.ops[0]; // always a register per CMOVcc spec
        const auto& src_op = ctx.ops[1]; // register or memory

        // setcc cc into Tmp0 B
        {
            auto& ir = b.push(IROp::SETCC, Width::B);
            ir.cond = cc;
            ir.add(VirReg{XReg::Tmp0, Width::B, false});
        }

        // zext Tmp0 B to w, masks to 0 or 1 in target width
        {
            auto& ir = b.push(IROp::ZEXT, w);
            ir.add(VirReg{XReg::Tmp0, w, false});
            ir.add(VirReg{XReg::Tmp0, Width::B, false});
        }

        // neg Tmp0, 0/1 becomes 0/-1
        {
            auto& ir = b.push(IROp::NEG, w);
            ir.flags_kind = FlagsOp::NONE;
            ir.add(VirReg{XReg::Tmp0, w, false});
        }

        // Tmp1 = src, LOAD for memory operand else MOV
        if (src_op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            auto& ir = b.push(IROp::LOAD, w);
            ir.add(VirReg{XReg::Tmp1, w, false});
            ir.add(zmem_to_mem(src_op, w));
        } 
        else {
            auto& ir = b.push(IROp::MOV, w);
            ir.add(VirReg{XReg::Tmp1, w, false});
            ir.add(convert_operand(src_op, w));
        }

        // Tmp1 &= Tmp0, src or zero
        {
            auto& ir = b.push(IROp::AND, w);
            ir.flags_kind = FlagsOp::NONE;
            ir.add(VirReg{XReg::Tmp1, w, false});
            ir.add(VirReg{XReg::Tmp0, w, false});
        }

        // not Tmp0, 0/-1 becomes -1/0
        {
            auto& ir = b.push(IROp::NOT, w);
            ir.flags_kind = FlagsOp::NONE;
            ir.add(VirReg{XReg::Tmp0, w, false});
        }

        // dst &= Tmp0, dst or zero
        {
            auto& ir = b.push(IROp::AND, w);
            ir.flags_kind = FlagsOp::NONE;
            ir.add(convert_operand(dst_op, w));
            ir.add(VirReg{XReg::Tmp0, w, false});
        }

        // dst |= Tmp1
        {
            auto& ir = b.push(IROp::OR, w);
            ir.flags_kind = FlagsOp::NONE;
            ir.add(convert_operand(dst_op, w));
            ir.add(VirReg{XReg::Tmp1, w, false});
        }
    }

    std::vector<ZydisMnemonic> CdqLifter::mnemonics() const {
        return {ZYDIS_MNEMONIC_CWD, ZYDIS_MNEMONIC_CDQ, ZYDIS_MNEMONIC_CQO};
    }

    void CdqLifter::lift(IRBuilder& b, const LiftContext& ctx) const {
        Width w = Width::D;
        std::int8_t shift = 31;

        switch (ctx.insn.mnemonic) {
            case ZYDIS_MNEMONIC_CWD: w = Width::W; shift = 15; break;
            case ZYDIS_MNEMONIC_CDQ: w = Width::D; shift = 31; break;
            case ZYDIS_MNEMONIC_CQO: w = Width::Q; shift = 63; break;
            default: break;
        }

        b.push(IROp::MOV, w)
         .add(VirReg{XReg::DX, w, false})
         .add(VirReg{XReg::AX, w, false});
        auto& sar = b.push(IROp::SAR, w);
        sar.flags_kind = FlagsOp::SAR;
        sar.add(VirReg{XReg::DX, w, false});
        sar.add(Imm{shift, Width::B});
    }
}