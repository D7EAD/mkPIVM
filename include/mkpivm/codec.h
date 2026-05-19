#pragma once

#include "mkpivm/bytecode.h"
#include "mkpivm/ir.h"
#include "mkpivm/seed.h"
#include "mkpivm/vm_isa.h"
#include "mkpivm/x64_emit.h"
#include "mkpivm/x86_emit.h"

#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace mkpivm {
    // tags for X64Emitter rel32 fixups. packager resolves these at layout time.
    enum class FixupKind : std::uint32_t {
        HandlerTable       = 1,  // HOT
        Bytecode           = 2,  // bytecode base
        DataIsland         = 3,  // data island base
        Handler            = 4,  // specific handler, target_data is the opcode byte
        VMEntry            = 5,  // VM entry
        VMExit             = 6,  // exit-restore epilogue
        NativeBridge       = 7,  // call_native helper entry
        DataItem           = 8,  // a specific original VA inside the data island
        BlockTable         = 9,  // va_offset to bytecode_offset lookup table
        TrampolineBase     = 10, // per-call-site trampoline region base
        TrampolineOffset   = 11, // offset of a specific call site's trampoline
        InitFlag           = 12, // 1-byte "decrypt already ran" marker
        DataIslandInitFlag = 13, // 1-byte marker for the deferred data-island
                                 // decrypt. fires once on first native-handler
                                 // entry, keeps the big decrypt body out of the
                                 // prologue.
        RuntimeNonce       = 14, // 8-byte blob slot for the runtime nonce.
                                 // had this in VMState first like a dumbass,
                                 // but VMState lives on the host stack and
                                 // dies between range entries, so entry 2
                                 // read garbage and dispatch XORed the
                                 // handler table with shit.
    };

    // one codec per IR op family. subclasses define the bytecode shape via
    // encode() and the runtime handler via emit_handler(). everything routes
    // through the shared VMConfig
    class Codec {
        public:
            virtual ~Codec() = default;

            virtual std::string_view family() const noexcept = 0;
            std::string key() const { return std::string{family()}; }

            // encode the IR insn. write the opcode byte first, then operand bytes.
            virtual void encode(
                BytecodeBuilder& out,
                const IRInsn& insn,
                const VMConfig& vm
            ) const = 0;

            // emit the handler at the cursor. handlers end with emit_dispatch_tail
            // to fetch and jump to the next opcode. one overload per host emitter.
            virtual void emit_handler(X64Emitter& e, const VMConfig& vm) const = 0;
            virtual void emit_handler(X86Emitter& e, const VMConfig& vm) const = 0;
    };

    // registry of codecs, one per family. 
    class CodecRegistry {
        public:
            explicit CodecRegistry(VMConfig& vm, SeedRng& rng);

            // codec count, same as opcode count
            std::size_t size() const noexcept { return order_.size(); }

            const Codec* by_family(std::string_view fam) const;
            const Codec* by_opcode(std::uint8_t b) const;

            // codecs in opcode order, same order handlers get emitted in
            const std::vector<const Codec*>& by_order() const noexcept { return order_; }

        private:
            std::vector<std::unique_ptr<Codec>>             owners_;
            std::unordered_map<std::string, const Codec*>   by_family_;
            std::vector<const Codec*>                       order_; // index = opcode
    };

    // preproc to make my life easier
    #define MKPIVM_CODEC(Name, FamLit)                                                    \
        class Name##Codec final : public Codec {                                          \
        public:                                                                           \
            std::string_view family() const noexcept override { return FamLit; }          \
            void encode(BytecodeBuilder&, const IRInsn&, const VMConfig&) const override; \
            void emit_handler(X64Emitter&, const VMConfig&) const override;               \
            void emit_handler(X86Emitter&, const VMConfig&) const override;               \
        }

    MKPIVM_CODEC(Imm,         "IMM");
    MKPIVM_CODEC(Mov,         "MOV");
    MKPIVM_CODEC(Load,        "LOAD");
    MKPIVM_CODEC(Store,       "STORE");
    MKPIVM_CODEC(Lea,         "LEA");
    MKPIVM_CODEC(ReadSeg,     "READ_SEG");
    MKPIVM_CODEC(Add,         "ADD");
    MKPIVM_CODEC(Sub,         "SUB");
    MKPIVM_CODEC(And,         "AND");
    MKPIVM_CODEC(Or,          "OR");
    MKPIVM_CODEC(Xor,         "XOR");
    MKPIVM_CODEC(Not,         "NOT");
    MKPIVM_CODEC(Neg,         "NEG");
    MKPIVM_CODEC(Inc,         "INC");
    MKPIVM_CODEC(Dec,         "DEC");
    MKPIVM_CODEC(Shl,         "SHL");
    MKPIVM_CODEC(Shr,         "SHR");
    MKPIVM_CODEC(Sar,         "SAR");
    MKPIVM_CODEC(Rol,         "ROL");
    MKPIVM_CODEC(Ror,         "ROR");
    MKPIVM_CODEC(Cmp,         "CMP");
    MKPIVM_CODEC(Test,        "TEST");
    MKPIVM_CODEC(Br,          "BR");
    MKPIVM_CODEC(BrCc,        "BRCC");
    MKPIVM_CODEC(CallVm,      "CALLVM");
    MKPIVM_CODEC(RetVm,       "RETVM");
    MKPIVM_CODEC(CallNative,  "CALLNATIVE");
    MKPIVM_CODEC(JmpNative,   "JMPNATIVE");
    MKPIVM_CODEC(Push,        "PUSH");
    MKPIVM_CODEC(Pop,         "POP");
    MKPIVM_CODEC(Xchg,        "XCHG");
    MKPIVM_CODEC(Zext,        "ZEXT");
    MKPIVM_CODEC(Sext,        "SEXT");
    MKPIVM_CODEC(Setcc,       "SETCC");
    MKPIVM_CODEC(Bswap,       "BSWAP");
    MKPIVM_CODEC(Nop,         "NOP");
    MKPIVM_CODEC(Exit,        "EXIT");
    MKPIVM_CODEC(LoopDec,     "LOOP");
    MKPIVM_CODEC(Cdqe,        "CDQE");
    MKPIVM_CODEC(Lodsb,       "LODSB");
    MKPIVM_CODEC(Stosb,       "STOSB");
    MKPIVM_CODEC(Movsb,       "MOVSB");
    MKPIVM_CODEC(Cmpsb,       "CMPSB");
    MKPIVM_CODEC(Scasb,       "SCASB");
    MKPIVM_CODEC(Df,          "DF"); // CLD/STD, sets the df flag
    MKPIVM_CODEC(Imul,        "IMUL");
    MKPIVM_CODEC(BrInd,       "BRIND");
    MKPIVM_CODEC(RetNative,   "RETNATIVE");

    #undef MKPIVM_CODEC

    // pick the codec family name for an IR op 
    std::string codec_family_for(IROp op);

    // inline byte fetch. reads one byte at [ip], decrypts with the current
    // cipher state, advances ip, updates cipher state. byte goes in lo 8 dst
    void emit_fetch_byte_dec(X64Emitter& e, const VMConfig& vm, std::uint8_t dst);
    void emit_fetch_byte_dec(X86Emitter& e, const VMConfig& vm, std::uint8_t dst);

    // 4-byte little-endian fetch, four byte fetches composed.
    void emit_fetch_u32_dec(X64Emitter& e, const VMConfig& vm, std::uint8_t dst);
    void emit_fetch_u32_dec(X86Emitter& e, const VMConfig& vm, std::uint8_t dst);

    // N-byte little-endian fetch, n must be 1 to 8.
    void emit_fetch_uN_dec(
        X64Emitter& e,
        const VMConfig& vm,
        std::uint8_t dst,
        std::uint8_t n
    );

    void emit_fetch_uN_dec(
        X86Emitter& e,
        const VMConfig& vm,
        std::uint8_t dst,
        std::uint8_t n
    );

    // fetch next opcode and indirect-jmp to its handler. every handler ends
    // with this.
    void emit_dispatch_tail(X64Emitter& e, const VMConfig& vm);
    void emit_dispatch_tail(X86Emitter& e, const VMConfig& vm);

    // inline junk that does nothing semantically. length and content vary
    // per call.
    void emit_junk(X64Emitter& e, const VMConfig& vm, SeedRng& rng);
    void emit_junk(X86Emitter& e, const VMConfig& vm, SeedRng& rng);

    // load or store a VM reg slot 
    void emit_load_slot(
        X64Emitter& e,
        const VMConfig& vm,
        std::uint8_t out_reg,
        std::uint8_t slot_reg
    );

    void emit_store_slot(
        X64Emitter& e,
        const VMConfig& vm,
        std::uint8_t slot_reg,
        std::uint8_t in_reg
    );
}