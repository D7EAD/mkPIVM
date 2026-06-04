#pragma once

#include "mkpivm/arch.h"
#include "mkpivm/cfg.h"
#include "mkpivm/ir.h"

#include <Zydis/Zydis.h>
#include <memory>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace mkpivm {
    struct LiftContext {
        Arch arch;
        std::uint64_t va;
        std::uint64_t next_va;
        const ZydisDecodedInstruction& insn;
        const ZydisDecodedOperand*     ops;
        const CFGBuilder&              cfg;
        IRProgram*                     prog;  // stash rip-via-call targets here

        // emitted IRInsns carry an optional FlagsOp tag. JCC SHOULD read the tag
        // that the previous flag-setting insn left behind.
    };

    // one subclass per mnemonic family. lifters are stateless and emit pure
    // IR. they never touch bytecode state afaik
    class InstructionLifter {
        public:
            virtual ~InstructionLifter() = default;
            virtual std::vector<ZydisMnemonic> mnemonics() const = 0;
            virtual void lift(IRBuilder& builder, const LiftContext& ctx) const = 0;
            virtual std::string_view family() const noexcept = 0;
    };

    // tegistry indexes concrete lifters by Zydis mnemonic.
    class LifterRegistry {
        public:
            LifterRegistry();

            // null if the mnemonic isn't supported
            const InstructionLifter* find(ZydisMnemonic mn) const;

            // lift the whole shellcode to IR, throws if a reachable insn isn't
            // supported.
            IRProgram lift_program(const CFGBuilder& cfg) const;

        private:
            std::vector<std::unique_ptr<InstructionLifter>> owners_;
            std::unordered_map<ZydisMnemonic, const InstructionLifter*> by_mnemonic_;

            void register_lifter(std::unique_ptr<InstructionLifter> lf);
    };

    class MovLifter final : public InstructionLifter {
        public:
            std::vector<ZydisMnemonic> mnemonics() const override;
            void lift(IRBuilder&, const LiftContext&) const override;
            std::string_view family() const noexcept override { return "MOV"; }
    };

    class MovExtLifter final : public InstructionLifter {
        public:
            std::vector<ZydisMnemonic> mnemonics() const override;
            void lift(IRBuilder&, const LiftContext&) const override;
            std::string_view family() const noexcept override { return "MOVEXT"; }
    };

    class LeaLifter final : public InstructionLifter {
        public:
            std::vector<ZydisMnemonic> mnemonics() const override;
            void lift(IRBuilder&, const LiftContext&) const override;
            std::string_view family() const noexcept override { return "LEA"; }
    };

    class AddSubLifter final : public InstructionLifter {
        public:
            std::vector<ZydisMnemonic> mnemonics() const override;
            void lift(IRBuilder&, const LiftContext&) const override;
            std::string_view family() const noexcept override { return "ADDSUB"; }
    };

    class LogicLifter final : public InstructionLifter {
        public:
            std::vector<ZydisMnemonic> mnemonics() const override;
            void lift(IRBuilder&, const LiftContext&) const override;
            std::string_view family() const noexcept override { return "LOGIC"; }
    };

    class NegNotLifter final : public InstructionLifter {
        public:
            std::vector<ZydisMnemonic> mnemonics() const override;
            void lift(IRBuilder&, const LiftContext&) const override;
            std::string_view family() const noexcept override { return "NEGNOT"; }
    };

    class IncDecLifter final : public InstructionLifter {
        public:
            std::vector<ZydisMnemonic> mnemonics() const override;
            void lift(IRBuilder&, const LiftContext&) const override;
            std::string_view family() const noexcept override { return "INCDEC"; }
    };

    class ShiftLifter final : public InstructionLifter {
        public:
            std::vector<ZydisMnemonic> mnemonics() const override;
            void lift(IRBuilder&, const LiftContext&) const override;
            std::string_view family() const noexcept override { return "SHIFT"; }
    };

    class CmpTestLifter final : public InstructionLifter {
        public:
            std::vector<ZydisMnemonic> mnemonics() const override;
            void lift(IRBuilder&, const LiftContext&) const override;
            std::string_view family() const noexcept override { return "CMPTEST"; }
    };

    class JmpLifter final : public InstructionLifter {
        public:
            std::vector<ZydisMnemonic> mnemonics() const override;
            void lift(IRBuilder&, const LiftContext&) const override;
            std::string_view family() const noexcept override { return "JMP"; }
    };

    class JccLifter final : public InstructionLifter {
        public:
            std::vector<ZydisMnemonic> mnemonics() const override;
            void lift(IRBuilder&, const LiftContext&) const override;
            std::string_view family() const noexcept override { return "JCC"; }
    };

    class CallLifter final : public InstructionLifter {
        public:
            std::vector<ZydisMnemonic> mnemonics() const override;
            void lift(IRBuilder&, const LiftContext&) const override;
            std::string_view family() const noexcept override { return "CALL"; }
    };

    class RetLifter final : public InstructionLifter {
        public:
            std::vector<ZydisMnemonic> mnemonics() const override;
            void lift(IRBuilder&, const LiftContext&) const override;
            std::string_view family() const noexcept override { return "RET"; }
    };

    class PushPopLifter final : public InstructionLifter {
        public:
            std::vector<ZydisMnemonic> mnemonics() const override;
            void lift(IRBuilder&, const LiftContext&) const override;
            std::string_view family() const noexcept override { return "STACK"; }
    };

    class XchgLifter final : public InstructionLifter {
        public:
            std::vector<ZydisMnemonic> mnemonics() const override;
            void lift(IRBuilder&, const LiftContext&) const override;
            std::string_view family() const noexcept override { return "XCHG"; }
    };

    class SetccLifter final : public InstructionLifter {
        public:
            std::vector<ZydisMnemonic> mnemonics() const override;
            void lift(IRBuilder&, const LiftContext&) const override;
            std::string_view family() const noexcept override { return "SETCC"; }
    };

    class StringOpLifter final : public InstructionLifter {
        public:
            std::vector<ZydisMnemonic> mnemonics() const override;
            void lift(IRBuilder&, const LiftContext&) const override;
            std::string_view family() const noexcept override { return "STRING"; }
    };

    class LoopLifter final : public InstructionLifter {
        public:
            std::vector<ZydisMnemonic> mnemonics() const override;
            void lift(IRBuilder&, const LiftContext&) const override;
            std::string_view family() const noexcept override { return "LOOP"; }
    };

    class CdqeLifter final : public InstructionLifter {
        public:
            std::vector<ZydisMnemonic> mnemonics() const override;
            void lift(IRBuilder&, const LiftContext&) const override;
            std::string_view family() const noexcept override { return "CDQE"; }
    };

    class NopLifter final : public InstructionLifter {
        public:
            std::vector<ZydisMnemonic> mnemonics() const override;
            void lift(IRBuilder&, const LiftContext&) const override;
            std::string_view family() const noexcept override { return "NOP"; }
    };

    class BswapLifter final : public InstructionLifter {
        public:
            std::vector<ZydisMnemonic> mnemonics() const override;
            void lift(IRBuilder&, const LiftContext&) const override;
            std::string_view family() const noexcept override { return "BSWAP"; }
    };

    class ImulLifter final : public InstructionLifter {
        public:
            std::vector<ZydisMnemonic> mnemonics() const override;
            void lift(IRBuilder&, const LiftContext&) const override;
            std::string_view family() const noexcept override { return "IMUL"; }
    };

    // JCXZ family. short jump if r/e/cx is zero
    class JcxzLifter final : public InstructionLifter {
        public:
            std::vector<ZydisMnemonic> mnemonics() const override;
            void lift(IRBuilder&, const LiftContext&) const override;
            std::string_view family() const noexcept override { return "JCXZ"; }
    };

    // PUSHAD and POPAD. push or pop all 8 x86 GPRs
    class PushadPopadLifter final : public InstructionLifter {
        public:
            std::vector<ZydisMnemonic> mnemonics() const override;
            void lift(IRBuilder&, const LiftContext&) const override;
            std::string_view family() const noexcept override { return "PUSHAD"; }
    };

    // LEAVE. mov rsp,rbp then pop rbp on x64, same with esp/ebp on x86
    class LeaveLifter final : public InstructionLifter {
        public:
            std::vector<ZydisMnemonic> mnemonics() const override;
            void lift(IRBuilder&, const LiftContext&) const override;
            std::string_view family() const noexcept override { return "STACK"; }
    };

    // CWD/CDQ/CQO. sign-extend AX/EAX/RAX into DX/EDX/RDX
    class CdqLifter final : public InstructionLifter {
        public:
            std::vector<ZydisMnemonic> mnemonics() const override;
            void lift(IRBuilder&, const LiftContext&) const override;
            std::string_view family() const noexcept override { return "SHIFT"; }
    };

    // real CMOVcc doesn't touch EFLAGS but our AND/OR codecs always do 
    class CmovccLifter final : public InstructionLifter {
        public:
            std::vector<ZydisMnemonic> mnemonics() const override;
            void lift(IRBuilder&, const LiftContext&) const override;
            std::string_view family() const noexcept override { return "CMOV"; }
    };

    // turn a Zydis register id into XReg + Width. is_high_byte is set when the
    // register is AH/CH/DH/BH.
    struct DecodedReg {
        XReg reg{XReg::Invalid};
        Width width{Width::Q};
        bool is_high_byte{false};
    };

    DecodedReg decode_zreg(ZydisRegister r) noexcept;

    VirReg zreg_to_virreg(ZydisRegister r, Width fallback = Width::Q);
    Mem    zmem_to_mem(const ZydisDecodedOperand& op, Width w);
    Imm    zimm_to_imm(const ZydisDecodedOperand& op, Width w);
    Width  width_from_zsize(std::uint16_t bits) noexcept;
}