#pragma once

#include "mkpivm/arch.h"
#include "mkpivm/util.h"

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace mkpivm {
    // logical x86 reg names the IR uses. physical width is 32 or 64 depending
    // on arch. sub-register stuff gets lowered to width-typed ops.
    enum class XReg : std::uint8_t {
        AX = 0, CX, DX, BX, SP, BP, SI, DI,
        R8, R9, R10, R11, R12, R13, R14, R15,
        Tmp0 = 16, Tmp1 = 17, Tmp2 = 18, Tmp3 = 19,
        Invalid = 0xFF,
    };

    constexpr bool xreg_valid_for(XReg r, Arch a) noexcept {
        if (r == XReg::Invalid) return false;
        if (a == Arch::X86 && static_cast<std::uint8_t>(r) >= 8) return false;
        return true;
    }

    constexpr const char* xreg_name(XReg r) noexcept {
        switch (r) {
            case XReg::AX:   return "rax";
            case XReg::CX:   return "rcx";
            case XReg::DX:   return "rdx";
            case XReg::BX:   return "rbx";
            case XReg::SP:   return "rsp";
            case XReg::BP:   return "rbp";
            case XReg::SI:   return "rsi";
            case XReg::DI:   return "rdi";
            case XReg::R8:   return "r8";
            case XReg::R9:   return "r9";
            case XReg::R10:  return "r10";
            case XReg::R11:  return "r11";
            case XReg::R12:  return "r12";
            case XReg::R13:  return "r13";
            case XReg::R14:  return "r14";
            case XReg::R15:  return "r15";
            case XReg::Tmp0: return "tmp0";
            case XReg::Tmp1: return "tmp1";
            case XReg::Tmp2: return "tmp2";
            case XReg::Tmp3: return "tmp3";
            default:         return "?";
        }
    }

    // operand width. LOAD/STORE size, CMP width, ADD width, etc.
    enum class Width : std::uint8_t {
        B = 1, W = 2, D = 4, Q = 8,
    };

    constexpr std::uint8_t width_bytes(Width w) noexcept { return static_cast<std::uint8_t>(w); }
    constexpr std::uint8_t width_bits(Width w)  noexcept { return width_bytes(w) * 8u; }

    // branch conditions, mapped from the x86 cc nibble at lift time.
    enum class Cond : std::uint8_t {
        O,  NO,
        B,  NB, // also C and NC
        Z,  NZ,
        BE, NBE,
        S,  NS,
        P,  NP,
        L,  NL,
        LE, NLE,
    };

    constexpr const char* cond_name(Cond c) noexcept {
        switch (c) {
            case Cond::O:  return "o";  case Cond::NO:  return "no";
            case Cond::B:  return "b";  case Cond::NB:  return "nb";
            case Cond::Z:  return "z";  case Cond::NZ:  return "nz";
            case Cond::BE: return "be"; case Cond::NBE: return "nbe";
            case Cond::S:  return "s";  case Cond::NS:  return "ns";
            case Cond::P:  return "p";  case Cond::NP:  return "np";
            case Cond::L:  return "l";  case Cond::NL:  return "nl";
            case Cond::LE: return "le"; case Cond::NLE: return "nle";
        }
        return "?";
    }

    // last flag-setting op. BR_CC uses this plus the cached operands to
    // compute the condition lazily. same idea as QEMU's lazy flags
    enum class FlagsOp : std::uint8_t {
        NONE  = 0,
        LOGIC = 1, // AND/OR/XOR/TEST. CF=OF=0, ZF/SF/PF from result.
        ADD   = 2,
        SUB   = 3, // covers CMP too
        INC   = 4,
        DEC   = 5,
        SHL   = 6,
        SHR   = 7,
        SAR   = 8,
        NEG   = 9,
    };

    // operand variants
    struct Imm    { std::int64_t  value; Width width; };
    struct VirReg {
        XReg  reg{XReg::Invalid};
        Width width{Width::Q};
        bool  is_high_byte{false}; // AH/CH/DH/BH. width must be B.
    };
    struct Mem {
        XReg base    {XReg::Invalid};
        XReg index   {XReg::Invalid};
        std::uint8_t scale {1}; // 1, 2, 4, or 8
        std::int32_t disp  {0};
        Width        width {Width::Q};
        std::uint8_t seg_override{0}; // 0 default, 1 fs, 2 gs
    };
    struct Label { std::uint32_t bb_id; }; // bytecode-relative branch target

    // op tags. each one names a codec family.
    enum class IROp : std::uint16_t {
        // data movement
        IMM, MOV, ZEXT, SEXT, BSWAP,
        LOAD, STORE, LEA, READ_SEG,

        // integer arith
        ADD, ADC, SUB, SBB, NEG, INC, DEC,
        IMUL, MUL, IDIV, DIV,

        // bitwise zzzzzz
        AND, OR, XOR, NOT, SHL, SHR, SAR, ROL, ROR, RCL, RCR,

        // comparisons set the lazy flag context
        CMP, TEST,

        // conditional set
        SETCC,

        // control flow
        BR_CC, BR, BR_IND,
        CALL_VM, RET_VM,
        CALL_NATIVE, JMP_NATIVE, RET_NATIVE,

        // stack
        PUSH, POP,

        // specials
        XCHG, CLD, STD, NOP, EXIT,
        LOOP_DEC, // dec rcx then branch if non-zero, fused
        CDQE,     // sign-extend RAX
        STOSB, LODSB, MOVSB, CMPSB, SCASB, REP_PREFIX,
    };

    const char* ir_op_name(IROp o) noexcept;
    const char* ir_op_family(IROp o) noexcept; // codec lookup key

    using Operand = std::variant<Imm, VirReg, Mem, Label>;

    // one insn. up to 4 operands in an inline array so we don't heap-alloc
    // per instruction.
    struct IRInsn {
        IROp op{IROp::NOP};
        Width width{Width::Q};
        Cond cond{Cond::Z};                // BR_CC and SETCC
        FlagsOp flags_kind{FlagsOp::NONE}; // set by arith ops, read by BR_CC
        std::array<Operand, 4> ops{};
        std::uint8_t op_count{0};

        // source PC of the original x86 insn. for crash diagnostics rlly.
        std::uint64_t src_pc{0};

        // BR and BR_CC carry both the x86 target VA for cross-block resolution
        // and the final block id for the encoder.
        std::uint64_t target_va{0};
        std::uint32_t target_block_id{0xFFFFFFFFu};

        // CALL_VM stashes the byte immediately after the call so call+pop
        // self-locate idioms see the same value a real CPU would have pushed.
        std::uint64_t return_va{0};

        IRInsn() = default;
        IRInsn(IROp o, Width w) : op{o}, width{w} {}

        IRInsn& add(Operand x) {
            if (op_count >= ops.size()) throw Error("IRInsn: too many operands");
            ops[op_count++] = std::move(x);
            return *this;
        }
    };

    // basic block. straight-line ops up to a terminator.
    struct IRBlock {
        std::uint32_t id{0};
        std::uint64_t start_va{0};
        std::vector<IRInsn> insns;

        bool is_terminator() const noexcept {
            if (insns.empty()) return false;
            switch (insns.back().op) {
                case IROp::BR:
                case IROp::BR_CC:
                case IROp::BR_IND:
                case IROp::RET_VM:
                case IROp::RET_NATIVE:
                case IROp::EXIT:
                case IROp::JMP_NATIVE:
                    return true;
                default:
                    return false;
            }
        }
    };

    // the whole lifted program
    struct IRProgram {
        Arch arch{Arch::X64};
        std::uint64_t entry_va{0};
        std::vector<IRBlock> blocks;

        // string literals and other data baked into the shellcode
        // carried to data island
        struct DataChunk {
            std::uint64_t start_va{0};
            std::vector<std::uint8_t> bytes;
        };
        std::vector<DataChunk> data_chunks;

        // VA ... block id, built by CFG construction
        std::vector<std::pair<std::uint64_t, std::uint32_t>> va_to_block;

        // VAs of `call X; X: pop reg` ret-addrs
        std::vector<std::uint64_t> rip_via_call_targets;

        std::uint32_t block_id_for(std::uint64_t va) const;

        // offset of va inside its data chunk if it's in one
        std::optional<std::pair<std::size_t, std::size_t>>
        data_chunk_for(std::uint64_t va) const;
    };

    // helper used by lifters
    class IRBuilder {
        public:
            explicit IRBuilder(IRBlock& block) noexcept : block_{&block} {}

            IRInsn& push(IROp op, Width w = Width::Q) {
                block_->insns.emplace_back(op, w);
                return block_->insns.back();
            }

            IRBlock& block() noexcept { return *block_; }

        private:
            IRBlock* block_;
    };
}