#include "mkpivm/packager.h"
#include "mkpivm/bytecode.h"
#include "mkpivm/cfg.h"
#include "mkpivm/codec.h"
#include "mkpivm/lifter.h"
#include "mkpivm/seed.h"
#include "mkpivm/vm_codegen.h"
#include "mkpivm/vm_isa.h"
#include "mkpivm/x64_emit.h"

#include <fmt/format.h>
#include <cstdio>
#include <algorithm>
#include <cstring>
#include <deque>
#include <set>
#include <string>
#include <unordered_set>

namespace mkpivm {
    // fixes up every branch target_va to target_block_id
    static void resolve_branch_targets(IRProgram& prog, CFGBuilder& cfg) {
        struct Pending {
            std::size_t   blk_idx;
            std::size_t   insn_idx;
            std::uint64_t target_va;
        };
        std::vector<Pending> pending;

        for (std::size_t bi = 0; bi < prog.blocks.size(); ++bi) {
            for (std::size_t ii = 0; ii < prog.blocks[bi].insns.size(); ++ii) {
                const auto& insn = prog.blocks[bi].insns[ii];
                switch (insn.op) {
                    case IROp::BR:
                    case IROp::BR_CC:
                    case IROp::CALL_VM:
                    case IROp::LOOP_DEC: {
                        auto it = std::lower_bound(
                            prog.va_to_block.begin(),
                            prog.va_to_block.end(),
                            std::pair<std::uint64_t, std::uint32_t>{insn.target_va, 0}
                        );

                        if (it != prog.va_to_block.end() && it->first == insn.target_va) {
                            prog.blocks[bi].insns[ii].target_block_id = it->second;
                            break;
                        }

                        if (insn.op == IROp::CALL_VM) {
                            throw Error(
                                fmt::format(
                                    "call_vm target va 0x{:x} has no ir block, src_pc 0x{:x}",
                                    insn.target_va,
                                    insn.src_pc
                                )
                            );
                        }

                        if (!cfg.in_code(insn.target_va)) {
                            throw Error(
                                fmt::format(
                                    "branch target va 0x{:x} has no ir block and isn't code, src_pc 0x{:x}",
                                    insn.target_va,
                                    insn.src_pc
                                )
                            );
                        }

                        pending.push_back({bi, ii, insn.target_va});
                        break;
                    }
                    default: break;
                }
            }
        }

        // one JMP_NATIVE block per unique outside target 
        std::unordered_map<std::uint64_t, std::uint32_t> outside_to_block;
        for (const auto& p : pending) {
            if (outside_to_block.count(p.target_va)) continue;
            IRBlock sb;
            const auto sb_id = static_cast<std::uint32_t>(prog.blocks.size());
            sb.id = sb_id;

            // bogus VA past the input so block-table emission skips it.
            sb.start_va = 0xFFFFFFFFFFFFFFFFULL;
            IRInsn ir;
            ir.op       = IROp::JMP_NATIVE;
            ir.width    = Width::Q;
            ir.ops[0]   = Imm{static_cast<std::int64_t>(p.target_va), Width::Q};
            ir.op_count = 1;
            ir.src_pc   = p.target_va;
            sb.insns.push_back(std::move(ir));
            prog.blocks.push_back(std::move(sb));
            outside_to_block.emplace(p.target_va, sb_id);
        }

        // patch each pending branch's target_block_id.
        for (const auto& p : pending) {
            prog.blocks[p.blk_idx].insns[p.insn_idx].target_block_id = outside_to_block.at(p.target_va);
        }
    }

    // dead-IR injection
    static void obfuscate_ir_dead_inject(IRProgram& prog, const SeedRng& master, unsigned density_pct = 20) {
        SeedRng sub = master.derive("obfuscate_dead_inject");
        for (auto& blk : prog.blocks) {
            if (blk.start_va == 0xFFFFFFFFFFFFFFFFULL) continue; // synthetic block
            if (blk.insns.empty()) continue;
            std::vector<IRInsn> out;
            out.reserve(blk.insns.size() * 2);

            for (auto& insn : blk.insns) {
                if (sub.uniform(0, 99) < static_cast<int>(density_pct)) {
                    const XReg tmp_reg = (sub.pick(2) == 0) ? XReg::Tmp2 : XReg::Tmp3;

                    IRInsn dead;
                    dead.op       = IROp::IMM;
                    dead.width    = Width::Q;
                    dead.ops[0]   = VirReg{tmp_reg, Width::Q, false};
                    dead.ops[1]   = Imm{static_cast<std::int64_t>(sub.next()), Width::Q};
                    dead.op_count = 2;
                    dead.src_pc   = insn.src_pc;

                    out.push_back(std::move(dead));
                }

                out.push_back(std::move(insn));
            }

            blk.insns = std::move(out);
        }
    }

    // opaque predicates via block splitting 
    static void obfuscate_ir_opaque_predicates(IRProgram& prog, const SeedRng& master, unsigned density_pct = 25) {
        SeedRng sub = master.derive("obfuscate_opaque_predicates");

        std::vector<std::uint32_t> real_block_ids;
        real_block_ids.reserve(prog.blocks.size());

        for (const auto& b : prog.blocks) {
            if (b.start_va != 0xFFFFFFFFFFFFFFFFULL) real_block_ids.push_back(b.id);
        }

        if (real_block_ids.size() < 2) return;

        struct Split { std::size_t blk_idx; std::uint32_t target_id; };
        std::vector<Split> splits;
        for (std::size_t bi = 0; bi < prog.blocks.size(); ++bi) {
            auto& blk = prog.blocks[bi];
            if (blk.start_va == 0xFFFFFFFFFFFFFFFFULL) continue; // synthetic
            if (blk.insns.empty()) continue;
            const auto first = blk.insns[0].op;

            // skip blocks whose first insn reads flags or our TEST trashes them
            if (first == IROp::BR_CC || first == IROp::SETCC) continue;
            if (sub.uniform(0, 99) >= density_pct) continue;

            std::uint32_t target_id = blk.id;
            for (int tries = 0; tries < 8; ++tries) {
                const auto pick = real_block_ids[sub.uniform(0, real_block_ids.size() - 1)];
                if (pick != blk.id) { target_id = pick; break; }
            }
            if (target_id == blk.id) continue;

            splits.push_back({bi, target_id});
        }

        // apply splits in reverse so earlier indices stay valid
        for (auto it = splits.rbegin(); it != splits.rend(); ++it) {
            const std::size_t bi      = it->blk_idx;
            const std::uint32_t tgt_id = it->target_id;

            IRBlock              tail;
            tail.id            = static_cast<std::uint32_t>(prog.blocks.size());
            tail.start_va      = 0xFFFFFFFFFFFFFFFFULL;
            tail.insns         = std::move(prog.blocks[bi].insns);
            const std::uint64_t src_pc = tail.insns.empty() ? prog.blocks[bi].start_va : tail.insns[0].src_pc;

            auto& blk = prog.blocks[bi];
            blk.insns.clear();

            IRInsn               imm;
            imm.op             = IROp::IMM;
            imm.width          = Width::Q;
            imm.ops[0]         = VirReg{XReg::Tmp3, Width::Q, false};
            imm.ops[1]         = Imm{0, Width::Q};
            imm.op_count       = 2;
            imm.src_pc         = src_pc;
            blk.insns.push_back(std::move(imm));

            IRInsn               tst;
            tst.op             = IROp::TEST;
            tst.width          = Width::Q;
            tst.flags_kind     = FlagsOp::LOGIC;
            tst.ops[0]         = VirReg{XReg::Tmp3, Width::Q, false};
            tst.ops[1]         = VirReg{XReg::Tmp3, Width::Q, false};
            tst.op_count       = 2;
            tst.src_pc         = src_pc;
            blk.insns.push_back(std::move(tst));

            IRInsn               br;
            br.op              = IROp::BR_CC;
            br.width           = Width::Q;
            br.cond            = Cond::NZ;
            br.target_block_id = tgt_id;
            br.op_count        = 0;
            br.src_pc          = src_pc;
            blk.insns.push_back(std::move(br));

            prog.blocks.insert(prog.blocks.begin() + bi + 1, std::move(tail));
        }
    }

    // runs the IR through the codecs and hands back raw plaintext bytecode
    static std::vector<std::uint8_t> encode_bytecode(const IRProgram& prog, const VMConfig& vm, const CodecRegistry& codecs) {
        BytecodeBuilder bb;

        // data refs get resolved later once the data island layout is known 
        for (const auto& blk : prog.blocks) {
            bb.mark_block(blk.id);

            for (const auto& insn : blk.insns) {
                const std::string fam = codec_family_for(insn.op);
                const Codec* c = codecs.by_family(fam);
                if (!c) throw Error("no codec for family " + fam);
                c->encode(bb, insn, vm);
            }
        }

        bb.resolve_branches();
        return std::move(bb).take();
    }

    PackageResult package_shellcode(Span<std::uint8_t> shellcode, const PackageOptions& opt) {
        SeedRng rng{opt.seed};

        // range mode bounds check + lifter restriction 
        if (!opt.ranges.empty()) {
            for (const auto& [s, e] : opt.ranges) {
                if (e > shellcode.size) {
                    throw Error(
                        fmt::format(
                            "ranges entry 0x{:x}:0x{:x} extends past input size 0x{:x}",
                            s,
                            e,
                            static_cast<std::uint32_t>(shellcode.size)
                        )
                    );
                }
            }

            if (opt.verbose) {
                std::fprintf(stderr, "ranges hybrid mode: %zu range/s\n", opt.ranges.size());
                for (const auto& [s, e] : opt.ranges) {
                    std::fprintf(
                        stderr,
                        "  va 0x%x..0x%x  %u bytes\n",
                        s,
                        e,
                        e - s
                    );
                }
            }
        }

        // pack + ranges: build the range-mode blob first then pack-wrap it 
        if (opt.pack_mode && !opt.ranges.empty()) {
            PackageOptions inner = opt;
            inner.pack_mode = false; // inner pass: just range-mode
            auto inner_pkg = package_shellcode(shellcode, inner);
            PackageOptions outer = opt;
            outer.ranges.clear(); // outer pass: pure pack
            Span<std::uint8_t> inner_bytes{inner_pkg.blob.data(), static_cast<std::uint32_t>(inner_pkg.blob.size())};

            auto outer_pkg = package_shellcode(inner_bytes, outer);
            outer_pkg.stats = fmt::format(
                "{}\n  pack+ranges chain: inner range-mode blob = {} B",
                outer_pkg.stats, inner_pkg.blob.size()
            );
            
            return outer_pkg;
        }

        // lift
        CFGBuilder cfg{opt.arch, shellcode, opt.base_va};
        IRProgram prog;
        if (opt.pack_mode) {
            // single synthetic JMP_NATIVE
            prog.arch = opt.arch;
            prog.entry_va = opt.base_va;
            IRBlock blk;
            blk.id = 0;
            blk.start_va = opt.base_va;
            IRInsn jmp(IROp::JMP_NATIVE, Width::Q);
            jmp.add(Imm{0, Width::Q});
            jmp.src_pc = opt.base_va;
            blk.insns.push_back(std::move(jmp));
            prog.blocks.push_back(std::move(blk));
            prog.va_to_block.emplace_back(opt.base_va, 0u);
        }
        else {
            if (!opt.ranges.empty()) {
                std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges_va;
                ranges_va.reserve(opt.ranges.size());
                for (const auto& [s, e] : opt.ranges) {
                    ranges_va.emplace_back(opt.base_va + s, opt.base_va + e);
                }
                cfg.set_lifted_ranges(std::move(ranges_va));
            }

            cfg.build();
            LifterRegistry lifters;
            prog = lifters.lift_program(cfg);
            resolve_branch_targets(prog, cfg);

            // ir-level obfuscation. use sub-rng so we dont fuck up
            // downstream
            obfuscate_ir_dead_inject(prog, rng, /*density_pct=*/20);
            obfuscate_ir_opaque_predicates(prog, rng, /*density_pct=*/25);
        }

        // vmconfig + codecs
        VMConfig vm{opt.arch, rng};
        if (!opt.ranges.empty()) {
            vm.set_range_mode(true);
        }
        if (opt.pack_mode) {
            vm.set_pack_mode(true);
        }
        if (opt.range_leak_nvs) {
            vm.set_range_leak_nvs(true);
        }

        // headroom scan
        {
            std::int32_t max_pos_disp = 0;
            for (const auto& blk : prog.blocks) {
                for (const auto& insn : blk.insns) {
                    for (const auto& op : insn.ops) {
                        if (!std::holds_alternative<Mem>(op)) continue;
                        const auto& m = std::get<Mem>(op);
                        if (m.disp <= 0) continue;
                        if (m.base == XReg::SP || m.base == XReg::BP) {
                            if (m.disp > max_pos_disp) max_pos_disp = m.disp;
                        }
                    }
                }
            }
            if (max_pos_disp > 0) {
                vm.set_vm_sp_headroom(static_cast<std::uint32_t>(max_pos_disp) + 64u);
            }
            if (opt.verbose) {
                std::fprintf(stderr, "headroom scan: max_pos_disp=0x%x set headroom=0x%x\n",
                    max_pos_disp, vm.vm_sp_headroom());
            }
        }

        CodecRegistry codecs{vm, rng};

        if (opt.verbose) {
            std::fprintf(stderr, "ir dump\n");
            for (const auto& blk : prog.blocks) {
                std::fprintf(
                    stderr,
                    "  block %u @ va=0x%llx:\n",
                    blk.id,
                    static_cast<unsigned long long>(blk.start_va)
                );

                for (const auto& insn : blk.insns) {
                    std::fprintf(
                        stderr,
                        "    [src=0x%llx]  %-12s width=%u",
                        static_cast<unsigned long long>(insn.src_pc),
                        ir_op_name(insn.op),
                        static_cast<unsigned>(width_bytes(insn.width))
                    );

                    if (insn.op == IROp::BR || insn.op == IROp::BR_CC ||
                        insn.op == IROp::CALL_VM || insn.op == IROp::LOOP_DEC) {
                        std::fprintf(
                            stderr,
                            "  target_va=0x%llx target_block=%u",
                            static_cast<unsigned long long>(insn.target_va),
                            insn.target_block_id
                        );
                    }

                    std::fprintf(stderr, "\n");
                }
            }
        }

        // range-mode hybrid pipeline 
        if (!opt.ranges.empty()) {
            // every range needs 5 bytes for the jmp rel32 patch.
            for (const auto& [s, e] : opt.ranges) {
                if (e - s < 5) {
                    throw Error(
                        fmt::format(
                            "ranges 0x{:x}:0x{:x}: range too short for a 5-byte entry patch, {} bytes, need 5",
                            s,
                            e,
                            e - s
                        )
                    );
                }
            }

            // coroutine gate is intentionally not enforced at lift time
            (void)opt.coroutines_allowed;

            // encode lifted IR
            BytecodeBuilder bb;
            std::unordered_set<std::string> used_families;

            for (const auto& blk : prog.blocks) {
                bb.mark_block(blk.id);
                for (const auto& insn : blk.insns) {
                    const std::string fam = codec_family_for(insn.op);
                    const Codec* c = codecs.by_family(fam);

                    if (!c) throw Error("no codec for family " + fam);
                    used_families.insert(fam);
                    c->encode(bb, insn, vm);
                }
            }

            bb.resolve_branches();
            auto data_fixups = bb.data_fixups();
            auto tramp_fixups = bb.trampoline_fixups();
            const auto block_starts = bb.block_start_offsets();
            std::unordered_map<std::uint32_t, std::uint32_t> block_id_to_bc_off;

            for (const auto& blk : prog.blocks) {
                block_id_to_bc_off.emplace(blk.id, bb.block_offset(blk.id));
            }

            std::vector<std::uint8_t> bytecode = bb.take();

            // each range's first VA is a block leader, so block_id_for hits.
            std::vector<std::uint32_t> range_bc_offsets;
            range_bc_offsets.reserve(opt.ranges.size());

            for (const auto& [s, e] : opt.ranges) {
                (void)e;
                const std::uint64_t entry_va = opt.base_va + s;
                std::uint32_t bid;

                try {
                    bid = prog.block_id_for(entry_va);
                }
                catch (...) {
                    throw Error(fmt::format("ranges 0x{:x}: no ir block at this va, probably not on an insn boundary", s));
                }

                range_bc_offsets.push_back(block_id_to_bc_off.at(bid));
            }

            // rip-via-call. each unique ret_va that the shellcode treats as
            // a self-pointer needs its own entry stub so the eventual native
            // `call reg` doesnt fly into the int3 fill. dormant for now,
            // lifter side of the pattern detect isnt wired up yet, see
            // feedback_cobalt_stager_range_limit mental note
            std::vector<std::pair<std::uint32_t /*va_off*/, std::uint32_t /*stub_idx*/>> rip_via_call_stubs;
            {
                std::unordered_set<std::uint64_t> seen;
                for (const auto va : prog.rip_via_call_targets) {
                    if (!seen.insert(va).second) continue;
                    if (va < opt.base_va || va >= opt.base_va + shellcode.size) continue;
                    std::uint32_t bid;
                    try { bid = prog.block_id_for(va); }
                    catch (...) { continue; }
                    const std::uint32_t stub_idx = static_cast<std::uint32_t>(range_bc_offsets.size());
                    range_bc_offsets.push_back(block_id_to_bc_off.at(bid));
                    rip_via_call_stubs.emplace_back(static_cast<std::uint32_t>(va - opt.base_va), stub_idx);
                }
            }

            // collect unique CALL_VM/CALL_NATIVE return-VAs that need a
            // trampoline so the API's ret lands back in our stub and
            // resumes VM dispatch at the post-call block
            std::vector<std::uint32_t> trampoline_block_ids;
            std::unordered_map<std::uint64_t, std::uint32_t> return_va_to_trampoline_idx;
            for (const auto& blk : prog.blocks) {
                for (const auto& ins : blk.insns) {
                    if (ins.op != IROp::CALL_VM && ins.op != IROp::CALL_NATIVE) continue;
                    if (return_va_to_trampoline_idx.count(ins.return_va)) continue;
                    std::uint32_t block_id = 0xFFFFFFFFu;

                    try {
                        block_id = prog.block_id_for(ins.return_va); 
                    }
                    catch (...) {
                        continue; 
                    }

                    if (block_id == 0xFFFFFFFFu) continue;
                    const std::uint32_t idx = static_cast<std::uint32_t>(trampoline_block_ids.size());
                    return_va_to_trampoline_idx.emplace(ins.return_va, idx);
                    trampoline_block_ids.push_back(block_id);
                }
            }

            // lifted data refs resolve into the native passthrough region.
            std::vector<std::uint8_t> island;
            std::vector<std::uint8_t> block_table_bytes;
            const std::uint32_t block_table_count = 0;

            // emit the VM stub
            auto finalize_range = [&](auto& emit) -> std::vector<std::uint8_t> {
                vm.set_data_island_size(static_cast<std::uint32_t>(island.size()));
                VMCodeGen gen{vm, codecs, rng};
                gen.set_used_families(used_families);
                gen.set_range_mode(range_bc_offsets);
                gen.emit_full(
                    emit,
                    bytecode.size(),
                    island.size(),
                    block_table_count
                );

                // trampolines: one per unique in-range return-VA
                const std::size_t trampoline_region_offset = emit.size();
                std::vector<std::size_t> trampoline_offsets;
                for (auto blk_id : trampoline_block_ids) {
                    trampoline_offsets.push_back(emit.size() - trampoline_region_offset);
                    const std::uint32_t bc_off = block_id_to_bc_off.at(blk_id);
                    gen.emit_trampoline(emit, bc_off);
                }

                // post-stub layout matches default mode so the existing fixup
                // kinds resolve correctly
                const std::size_t sbox_inv_offset    = emit.size();
                const std::size_t bytecode_offset    = sbox_inv_offset + 256;
                const std::size_t data_island_offset = bytecode_offset + bytecode.size();
                const std::size_t block_table_offset = data_island_offset + island.size();
                (void)data_island_offset; (void)block_table_offset;

                // patch trampoline_fixups in the bytecode
                for (const auto& tf : tramp_fixups) {
                    auto it = return_va_to_trampoline_idx.find(tf.return_va);
                    std::int64_t off;

                    if (it != return_va_to_trampoline_idx.end()) {
                        off = static_cast<std::int64_t>(trampoline_offsets[it->second]);
                    } 
                    else if (tf.return_va > opt.base_va && tf.return_va < opt.base_va + shellcode.size) {
                        off = static_cast<std::int64_t>(tf.return_va - opt.base_va) -
                            static_cast<std::int64_t>(shellcode.size) -
                            static_cast<std::int64_t>(trampoline_region_offset);
                    }
                    else {
                        off = 0;
                    }

                    if (off < INT32_MIN || off > INT32_MAX) throw Error("ranges: trampoline offset doesn't fit in int32");
                    const std::uint32_t v = static_cast<std::uint32_t>(static_cast<std::int32_t>(off));
                    for (int i = 0; i < 4; ++i) bytecode[tf.patch_pos + i] = static_cast<std::uint8_t>(v >> (8 * i));
                }

                // patch data_fixups in the bytecode 
                for (const auto& df : data_fixups) {
                    if (df.va < opt.base_va || df.va >= opt.base_va + shellcode.size) {
                        throw Error(
                            fmt::format(
                                "ranges: data ref to va 0x{:x} outside shellcode",
                                static_cast<unsigned long long>(df.va)
                            )
                        );
                    }
                    
                    const std::uint32_t off = static_cast<std::uint32_t>(df.va - opt.base_va);
                    for (int i = 0; i < 4; ++i) bytecode[df.patch_pos + i] = static_cast<std::uint8_t>(off >> (8 * i));
                }

                // encrypt bytecode AFTER patching trampoline/data fixups.
                vm.encrypt_inplace(bytecode, block_starts);

                // sbox_inv table
                {
                    const auto& sbox = vm.cipher_sbox();
                    std::array<std::uint8_t, 256> sbox_inv{};
                    for (std::size_t i = 0; i < 256; ++i) sbox_inv[sbox[i]] = static_cast<std::uint8_t>(i);
                    emit.bytes(sbox_inv.data(), sbox_inv.size());
                }
                emit.bytes(bytecode.data(), bytecode.size());
                emit.bytes(island.data(), island.size());
                emit.bytes(block_table_bytes.data(), block_table_bytes.size());

                // resolve fixups within the stub 
                auto& bytes = const_cast<std::vector<std::uint8_t>&>(emit.bytes());
                const auto& fixups = emit.fixups();

                for (const auto& fx : fixups) {
                    const std::int64_t cur_end = static_cast<std::int64_t>(fx.patch_offset) + 4;
                    std::int64_t target = 0;
                    switch (static_cast<FixupKind>(fx.target_kind)) {
                        case FixupKind::HandlerTable:
                            target = static_cast<std::int64_t>(gen.offsets().handler_table);
                            break;
                        case FixupKind::Bytecode:
                            target = static_cast<std::int64_t>(bytecode_offset);
                            break;
                        case FixupKind::DataIsland:
                            if (fx.target_data == 0xFFFFFFFFFFFFFFFFULL) {
                                // sbox_inv self-locate, lives in the stub
                                target = static_cast<std::int64_t>(sbox_inv_offset);
                            }
                            else {
                                // data_island_base is the start of the final blob,
                                // where the native passthrough bytes live
                                target = -static_cast<std::int64_t>(shellcode.size);
                            }
                            break;
                        case FixupKind::BlockTable:
                            target = static_cast<std::int64_t>(block_table_offset);
                            break;
                        case FixupKind::TrampolineBase:
                            target = static_cast<std::int64_t>(trampoline_region_offset);
                            break;
                        case FixupKind::VMExit:
                            target = static_cast<std::int64_t>(gen.offsets().exit_handler);
                            break;
                        case FixupKind::InitFlag:
                            target = static_cast<std::int64_t>(gen.offsets().init_flag);
                            break;
                        case FixupKind::DataIslandInitFlag:
                            target = static_cast<std::int64_t>(gen.offsets().data_island_init_flag);
                            break;
                        case FixupKind::RuntimeNonce:
                            target = static_cast<std::int64_t>(gen.offsets().runtime_nonce_slot);
                            break;
                        case FixupKind::TrampolineOffset:
                            throw Error("ranges: trampoline fixup leaked into stub, that's a bug. great.");
                        default:
                            throw Error(fmt::format("ranges: unknown fixup kind {}", fx.target_kind));
                    }

                    const std::int64_t rel = target - cur_end + fx.addend;
                    if (rel < INT32_MIN || rel > INT32_MAX) throw Error("ranges: rel32 fixup oob");
                    const std::uint32_t v = static_cast<std::uint32_t>(static_cast<std::int32_t>(rel));
                    for (int i = 0; i < 4; ++i) bytes[fx.patch_offset + i] = static_cast<std::uint8_t>(v >> (8 * i));
                }

                // resolve handler-table entries 
                for (std::size_t op = 0; op < 256; ++op) {
                    const auto h = gen.offsets().handler_offsets[op];
                    if (h == static_cast<std::size_t>(-1)) continue;
                    const std::int64_t off = static_cast<std::int64_t>(h) - static_cast<std::int64_t>(gen.offsets().handler_table);

                    if (off < INT32_MIN || off > INT32_MAX) throw Error("handler table entry oob");
                    const std::uint32_t v = static_cast<std::uint32_t>(static_cast<std::int32_t>(off));

                    for (int i = 0; i < 4; ++i) bytes[gen.offsets().handler_table + op * 4 + i] = static_cast<std::uint8_t>(v >> (8 * i));
                }

                // encrypt the resolved handler table in place 
                {
                    const std::size_t HT = gen.offsets().handler_table;
                    std::vector<std::uint8_t> ht(&bytes[HT], &bytes[HT + 256 * 4]);
                    vm.encrypt_inplace(ht, {});
                    std::copy(ht.begin(), ht.end(), bytes.begin() + HT);
                }

                // final blob is native shellcode then the VM stub
                std::vector<std::uint8_t> blob;
                blob.reserve(shellcode.size + bytes.size());
                blob.insert(blob.end(), shellcode.data, shellcode.data + shellcode.size);
                const std::size_t stub_base = blob.size();
                blob.insert(blob.end(), bytes.begin(), bytes.end());

                // patch each range start with jmp rel32 to vm_entry_K
                const auto& range_entries = gen.offsets().range_entries;
                for (std::size_t k = 0; k < opt.ranges.size(); ++k) {
                    const std::uint32_t start        = opt.ranges[k].first;
                    const std::uint32_t end          = opt.ranges[k].second;
                    const std::uint32_t patch_end    = start + 5;
                    const std::uint64_t vm_entry_abs = stub_base + range_entries[k];
                    const std::int64_t  rel          = static_cast<std::int64_t>(vm_entry_abs) - static_cast<std::int64_t>(patch_end);

                    if (rel < INT32_MIN || rel > INT32_MAX) throw Error("ranges: jmp rel32 to vm stub out of range");
                    blob[start] = 0xE9;
                    const std::uint32_t r = static_cast<std::uint32_t>(static_cast<std::int32_t>(rel));

                    for (int i = 0; i < 4; ++i) blob[start + 1 + i] = static_cast<std::uint8_t>(r >> (8 * i));

                    // fill the rest of the range with int3
                    for (std::uint32_t p = patch_end; p < end; ++p) blob[p] = 0xCC;
                }

                // splat a jmp rel32 over the int3 fill at each rip-via-call
                // ret_va so native `call reg` lands on the mid-range stub
                for (const auto& [va_off, stub_idx] : rip_via_call_stubs) {
                    if (va_off + 5 > shellcode.size) continue; // not enough room
                    const std::uint32_t patch_end    = va_off + 5;
                    const std::uint64_t vm_entry_abs = stub_base + range_entries[stub_idx];
                    const std::int64_t  rel          = static_cast<std::int64_t>(vm_entry_abs) - static_cast<std::int64_t>(patch_end);
                    if (rel < INT32_MIN || rel > INT32_MAX) throw Error("ranges: rip-via-call jmp rel32 out of range");
                    blob[va_off] = 0xE9;
                    const std::uint32_t r = static_cast<std::uint32_t>(static_cast<std::int32_t>(rel));
                    for (int i = 0; i < 4; ++i) blob[va_off + 1 + i] = static_cast<std::uint8_t>(r >> (8 * i));
                }

                if (opt.verbose) {
                    std::fprintf(
                        stderr,
                        "ranges hybrid blob: shellcode=%u + vm_stub=%zu = %zu bytes\n",
                        static_cast<unsigned>(shellcode.size),
                        bytes.size(),
                        blob.size()
                    );
                    
                    for (std::size_t k = 0; k < opt.ranges.size(); ++k) {
                        std::fprintf(
                            stderr,
                            "  range %zu: va 0x%x..0x%x -> vm_entry @ blob+0x%zx bc_off=0x%x\n",
                            k,
                            opt.ranges[k].first,
                            opt.ranges[k].second,
                            stub_base + range_entries[k],
                            range_bc_offsets[k]
                        );
                    }
                }

                return blob;
            };

            PackageResult out;
            if (opt.arch == Arch::X86) {
                X86Emitter emit;
                out.blob = finalize_range(emit);
            } 
            else {
                X64Emitter emit;
                out.blob = finalize_range(emit);
            }

            out.stats = fmt::format(
                "range-mode hybrid blob: {} bytes, shellcode={}, ranges={}",
                out.blob.size(),
                shellcode.size,
                opt.ranges.size()
            );

            return out;
        }

        // bytecode encoding
        BytecodeBuilder bb;
        std::unordered_set<std::string> used_families;
        for (const auto& blk : prog.blocks) {
            bb.mark_block(blk.id);
            for (const auto& insn : blk.insns) {
                const std::string fam = codec_family_for(insn.op);
                const Codec* c = codecs.by_family(fam);
                if (!c) throw Error("no codec for family " + fam);
                used_families.insert(fam);
                c->encode(bb, insn, vm);
            }
        }

        // build the va to bytecode-offset block table BEFORE we move the
        // builder buffer 
        std::vector<std::pair<std::uint32_t, std::uint32_t>> block_table_pairs;
        block_table_pairs.reserve(prog.blocks.size());

        for (const auto& blk : prog.blocks) {
            if (blk.start_va < opt.base_va || blk.start_va >= opt.base_va + shellcode.size) continue;
            const auto va_off = static_cast<std::uint32_t>(blk.start_va - opt.base_va);
            const auto bc_off = static_cast<std::uint32_t>(bb.block_offset(blk.id));
            block_table_pairs.emplace_back(va_off, bc_off);
        }

        std::sort(block_table_pairs.begin(), block_table_pairs.end(), [](const auto& a, const auto& b) { return a.first < b.first; });

        // per-call-site trampoline metadata 
        std::vector<std::uint32_t> trampoline_block_ids;
        std::unordered_map<std::uint64_t, std::uint32_t> return_va_to_trampoline_idx;
        for (const auto& blk : prog.blocks) {
            for (const auto& ins : blk.insns) {
                if (ins.op != IROp::CALL_VM && ins.op != IROp::CALL_NATIVE) continue;
                if (return_va_to_trampoline_idx.count(ins.return_va)) continue;

                // post-call VA may not be a block start
                std::uint32_t block_id = 0xFFFFFFFFu;

                try { 
                    block_id = prog.block_id_for(ins.return_va);
                }
                catch (...) { 
                    continue; 
                }

                if (block_id == 0xFFFFFFFFu) continue;
                const std::uint32_t idx = static_cast<std::uint32_t>(trampoline_block_ids.size());
                return_va_to_trampoline_idx.emplace(ins.return_va, idx);
                trampoline_block_ids.push_back(block_id);
            }
        }

        bb.resolve_branches();
        auto data_fixups = bb.data_fixups();
        auto tramp_fixups = bb.trampoline_fixups();
        const auto block_starts = bb.block_start_offsets();

        // data audit logging happens later, after kept_ranges is built 
        std::unordered_map<std::uint32_t, std::uint32_t> block_id_to_bc_off;
        for (const auto& blk : prog.blocks) {
            block_id_to_bc_off.emplace(blk.id, bb.block_offset(blk.id));
        }
        std::vector<std::uint8_t> bytecode = bb.take();

        std::vector<std::uint8_t> block_table_bytes(block_table_pairs.size() * 8);
        for (std::size_t i = 0; i < block_table_pairs.size(); ++i) {
            const auto va_off = block_table_pairs[i].first;
            const auto bc_off = block_table_pairs[i].second;
            for (int b = 0; b < 4; ++b) {
                block_table_bytes[i * 8 + b]     = static_cast<std::uint8_t>(va_off >> (8 * b));
                block_table_bytes[i * 8 + 4 + b] = static_cast<std::uint8_t>(bc_off >> (8 * b));
            }
        }
        const std::uint32_t block_table_count = static_cast<std::uint32_t>(block_table_pairs.size());

        // encrypt block table at rest 
        vm.encrypt_inplace(block_table_bytes, {});

        // compact data region 
        std::vector<bool> is_code(shellcode.size, false);
        for (const auto& b : cfg.blocks()) {
            const std::uint64_t s = b.start_va < opt.base_va ? 0 : (b.start_va - opt.base_va);
            const std::uint64_t e = b.end_va  < opt.base_va ? 0 : (b.end_va   - opt.base_va);
            for (std::uint64_t i = s; i < e && i < shellcode.size; ++i) is_code[i] = true;
        }

        // promote any data-fixup-referenced VA back into data even if the
        // CFG called it code 
        constexpr std::uint32_t kFixupPromoteSpan = 1024;
        for (const auto& df : data_fixups) {
            if (df.va < opt.base_va || df.va >= opt.base_va + shellcode.size) continue;

            const std::uint32_t vo = static_cast<std::uint32_t>(df.va - opt.base_va);
            for (std::uint32_t k = 0; k < kFixupPromoteSpan && vo + k < shellcode.size; ++k) {
                is_code[vo + k] = false;
            }
        }

        // walk the shellcode and emit contiguous data ranges.
        std::vector<std::pair<std::uint32_t, std::uint32_t>> kept_ranges;
        {
            std::uint32_t p = 0;
            while (p < shellcode.size) {
                if (is_code[p]) { ++p; continue; }
                std::uint32_t s = p;
                while (p < shellcode.size && !is_code[p]) ++p;
                kept_ranges.emplace_back(s, p);
            }
        }
        std::vector<std::uint8_t> island;

        // per-VA-offset map into the compact buffer 
        std::unordered_map<std::uint32_t, std::uint32_t> va_to_compact;
        for (auto [s, e] : kept_ranges) {
            const std::uint32_t base = static_cast<std::uint32_t>(island.size());
            island.insert(island.end(), shellcode.data + s, shellcode.data + e);
            for (std::uint32_t v = s; v < e; ++v) {
                va_to_compact.emplace(v, base + (v - s));
            }
        }

        auto va_offset = [&](std::uint64_t va)->std::uint32_t {
            if (va < opt.base_va || va >= opt.base_va + shellcode.size) {
                throw Error(fmt::format("va 0x{:x} outside shellcode", va));
            }
            const std::uint32_t vo = static_cast<std::uint32_t>(va - opt.base_va);

            auto it = va_to_compact.find(vo);
            if (it == va_to_compact.end()) {
                throw Error(
                    fmt::format(
                        "va 0x{:x} offset 0x{:x} referenced but not in any compact data range",
                        va, vo
                    )
                );
            }

            return it->second;
        };

        // encrypt the data region.
        vm.encrypt_inplace(island, {});

        if (opt.verbose) {
            std::fprintf(
                stderr,
                "data audit: shellcode=%llu B, kept data ranges=%zu, ~%zu B = %.1f%% of shellcode, encrypted\n",
                static_cast<unsigned long long>(shellcode.size),
                kept_ranges.size(),
                island.size(),
                100.0 * island.size() / shellcode.size
            );

            for (auto [s, e] : kept_ranges) {
                std::fprintf(
                    stderr,
                    "  va 0x%04x..0x%04x %u B  bytes: ",
                    s,
                    e,
                    e - s
                );

                for (std::uint32_t k = s; k < e && k - s < 32; ++k) {
                    std::fprintf(stderr, "%02x ", shellcode.data[k]);
                }

                if (e - s > 32) std::fprintf(stderr, "...");
                std::fprintf(stderr, "  ascii: \"");

                for (std::uint32_t k = s; k < e && k - s < 32; ++k) {
                    unsigned char c = shellcode.data[k];
                    std::fprintf(stderr, "%c", (c >= 0x20 && c < 0x7F) ? c : '.');
                }

                std::fprintf(stderr, "\"\n");
            }
        }

        // resolve data fixups inside bytecode
        for (const auto& df : data_fixups) {
            const std::uint32_t off = va_offset(df.va);
            for (int i = 0; i < 4; ++i) bytecode[df.patch_pos + i] = static_cast<std::uint8_t>(off >> (8 * i));
        }

        // trampoline fixups in the bytecode get resolved inside finalize
        // because trampoline offsets depend on per-arch emitter stub size,
        // only known once emit_full has run 
        vm.set_data_island_size(static_cast<std::uint32_t>(island.size()));
        VMCodeGen gen{vm, codecs, rng};
        gen.set_used_families(used_families);
        auto finalize = [&](auto& emit) -> std::vector<std::uint8_t> {
            // stub first.
            gen.emit_full(
                emit,
                bytecode.size(),
                island.size(),
                block_table_count
            );

            // per-call-site trampolines right after the stub 
            const std::size_t trampoline_region_offset = emit.size();
            std::vector<std::size_t> trampoline_offsets;
            trampoline_offsets.reserve(trampoline_block_ids.size());
            for (auto blk_id : trampoline_block_ids) {
                trampoline_offsets.push_back(emit.size() - trampoline_region_offset);
                const std::uint32_t bc_off = block_id_to_bc_off.at(blk_id);
                gen.emit_trampoline(emit, bc_off);
            }

            // compute layout offsets analytically 
            const std::size_t sbox_inv_offset = emit.size();
            const std::size_t bytecode_offset = sbox_inv_offset + 256;
            const std::size_t data_island_offset = bytecode_offset + bytecode.size();
            const std::size_t block_table_offset = data_island_offset + island.size();

            // patch TrampolineOffset fixups
            const std::int64_t island_to_tramp_delta = static_cast<std::int64_t>(data_island_offset) - static_cast<std::int64_t>(trampoline_region_offset);
            for (const auto& tf : tramp_fixups) {
                auto it = return_va_to_trampoline_idx.find(tf.return_va);
                std::uint32_t off;
                
                if (it != return_va_to_trampoline_idx.end()) {
                    off = static_cast<std::uint32_t>(trampoline_offsets[it->second]);
                }
                else {
                    if (tf.return_va <= opt.base_va || tf.return_va >= opt.base_va + shellcode.size) {
                        // JMP_NATIVE's unset default of base_va or past end 
                        off = 0;
                    }
                    else {
                        const std::uint32_t vo = static_cast<std::uint32_t>(tf.return_va - opt.base_va);

                        auto vit = va_to_compact.find(vo);
                        if (vit == va_to_compact.end()) {
                            // shouldn't happen, anchor_va_offsets put this VA into some kept range
                            throw Error(fmt::format("trampoline fixup va offset 0x{:x} not in any compact range", vo));
                        }

                        const std::int64_t rel = island_to_tramp_delta + static_cast<std::int64_t>(vit->second);
                        if (rel < 0 || rel > UINT32_MAX) {
                            throw Error("trampoline fixup: compact-data offset oob");
                        }
                        off = static_cast<std::uint32_t>(rel);
                    }
                }

                for (int i = 0; i < 4; ++i) bytecode[tf.patch_pos + i] = static_cast<std::uint8_t>(off >> (8 * i));
            }
            vm.encrypt_inplace(bytecode, block_starts);

            {
                const auto& sbox = vm.cipher_sbox();
                std::array<std::uint8_t, 256> sbox_inv{};
                for (std::size_t i = 0; i < 256; ++i) sbox_inv[sbox[i]] = static_cast<std::uint8_t>(i);
                emit.bytes(sbox_inv.data(), sbox_inv.size());
            }
            emit.bytes(bytecode.data(), bytecode.size());
            emit.bytes(island.data(), island.size());

            if (!block_table_bytes.empty()) {
                emit.bytes(block_table_bytes.data(), block_table_bytes.size());
            }
            (void)trampoline_region_offset; // used in the fixup resolver below

            auto& bytes = const_cast<std::vector<std::uint8_t>&>(emit.bytes());
            const auto& fixups = emit.fixups();
            for (const auto& fx : fixups) {
                const std::int64_t cur_end = static_cast<std::int64_t>(fx.patch_offset) + 4;
                std::int64_t target = 0;
                switch (static_cast<FixupKind>(fx.target_kind)) {
                    case FixupKind::HandlerTable:
                        target = static_cast<std::int64_t>(gen.offsets().handler_table);
                        break;
                    case FixupKind::Bytecode:
                        target = static_cast<std::int64_t>(bytecode_offset);
                        break;
                    case FixupKind::DataIsland:
                        if (fx.target_data == 0xFFFFFFFFFFFFFFFFULL) {
                            target = static_cast<std::int64_t>(sbox_inv_offset);
                        }
                        else {
                            target = static_cast<std::int64_t>(data_island_offset);
                        }
                        break;
                    case FixupKind::VMExit:
                        target = static_cast<std::int64_t>(gen.offsets().exit_handler);
                        break;
                    case FixupKind::InitFlag:
                        target = static_cast<std::int64_t>(gen.offsets().init_flag);
                        break;
                    case FixupKind::DataIslandInitFlag:
                        target = static_cast<std::int64_t>(gen.offsets().data_island_init_flag);
                        break;
                    case FixupKind::RuntimeNonce:
                        target = static_cast<std::int64_t>(gen.offsets().runtime_nonce_slot);
                        break;
                    case FixupKind::Handler: {
                        const std::uint8_t b = static_cast<std::uint8_t>(fx.target_data);
                        target = static_cast<std::int64_t>(gen.offsets().handler_offsets[b]);
                        break;
                    }
                    case FixupKind::BlockTable:
                        target = static_cast<std::int64_t>(block_table_offset);
                        break;
                    case FixupKind::TrampolineBase:
                        target = static_cast<std::int64_t>(trampoline_region_offset);
                        break;
                    case FixupKind::TrampolineOffset:
                        throw Error("TrampolineOffset fixups must be patched in the bytecode buffer, not as rel32");
                    default: throw Error("unknown fixup kind");
                }

                const std::int64_t rel = target - cur_end + fx.addend;
                if (rel < INT32_MIN || rel > INT32_MAX) throw Error("fixup rel32 oob");

                const std::uint32_t v = static_cast<std::uint32_t>(static_cast<std::int32_t>(rel));
                for (int i = 0; i < 4; ++i) bytes[fx.patch_offset + i] = static_cast<std::uint8_t>(v >> (8*i));
            }

            for (std::size_t op = 0; op < 256; ++op) {
                const auto h = gen.offsets().handler_offsets[op];
                if (h == static_cast<std::size_t>(-1)) continue;

                const std::int64_t off = static_cast<std::int64_t>(h) - static_cast<std::int64_t>(gen.offsets().handler_table);
                if (off < INT32_MIN || off > INT32_MAX) throw Error("handler table entry oob");

                const std::uint32_t v = static_cast<std::uint32_t>(static_cast<std::int32_t>(off));
                for (int i = 0; i < 4; ++i) bytes[gen.offsets().handler_table + op * 4 + i] = static_cast<std::uint8_t>(v >> (8*i));
            }

            // encrypt the resolved handler table in place 
            {
                const std::size_t HT = gen.offsets().handler_table;
                std::vector<std::uint8_t> ht(&bytes[HT], &bytes[HT + 256 * 4]);
                vm.encrypt_inplace(ht, {});
                std::copy(ht.begin(), ht.end(), bytes.begin() + HT);
            }

            return emit.take();
        };

        PackageResult out;
        if (opt.arch == Arch::X86) {
            X86Emitter emit;
            out.blob = finalize(emit);
        }
        else {
            X64Emitter emit;
            out.blob = finalize(emit);
        }
        const auto& dr = vm.dispatcher_regs();

        auto rn = [](std::uint8_t r) -> const char* {
            static const char* n[] = {
                "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                "r8","r9","r10","r11","r12","r13","r14","r15"
            };
            return n[r & 15];
        };

        out.stats = fmt::format(
            "mkpivm: arch={} blocks={} bytecode={} bytes data_island={} bytes stub={} bytes total={} bytes\n"
            "  cipher={} reg_count={} regs_base={} cipher_extra=0x{:x}\n"
            "  dispatcher: state_ptr={} ip={} handler_base={} cipher_state={} scratch_a={} scratch_b={}\n"
            "  slot_of SP={} AX={} CX={} DX={} BX={} BP={} SI={} DI={}\n"
            "  slot_of: Tmp0={} Tmp1={} Tmp2={} Tmp3={}",
            arch_name(opt.arch),
            prog.blocks.size(),
            bytecode.size(),
            island.size(),
            gen.offsets().exit_handler,
            out.blob.size(),
            static_cast<int>(vm.cipher_kind()),
            vm.reg_count(),
            vm.state_layout().regs_base,
            vm.state_layout().cipher_extra,
            rn(dr.state_ptr),
            rn(dr.ip),
            rn(dr.handler_base),
            rn(dr.cipher_state),
            rn(dr.scratch_a),
            rn(dr.scratch_b),
            vm.slot_of_xreg(XReg::SP),
            vm.slot_of_xreg(XReg::AX),
            vm.slot_of_xreg(XReg::CX),
            vm.slot_of_xreg(XReg::DX),
            vm.slot_of_xreg(XReg::BX),
            vm.slot_of_xreg(XReg::BP),
            vm.slot_of_xreg(XReg::SI),
            vm.slot_of_xreg(XReg::DI),
            vm.slot_of_xreg(XReg::Tmp0),
            vm.slot_of_xreg(XReg::Tmp1),
            vm.slot_of_xreg(XReg::Tmp2),
            vm.slot_of_xreg(XReg::Tmp3)
        );

        return out;
    }
}
