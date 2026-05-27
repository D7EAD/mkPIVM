#include "mkpivm/pe_embed.h"

#include <Zydis/Zydis.h>
#include <fmt/format.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <numeric>

#include <windows.h>

namespace mkpivm {
    namespace {
        constexpr std::uint16_t kDosMagic = 0x5A4D;     // MZ
        constexpr std::uint32_t kPeMagic  = 0x00004550; // PE\0\0
        constexpr std::uint16_t kOpt32    = 0x010B;     // PE32
        constexpr std::uint16_t kOpt64    = 0x020B;     // PE32+

        inline std::uint32_t align_up(std::uint32_t v, std::uint32_t a) {
            return (v + a - 1) & ~(a - 1);
        }

        // splitmix64
        inline std::uint64_t splitmix64_step(std::uint64_t& s) {
            s += 0x9E3779B97F4A7C15ULL;
            std::uint64_t z = s;
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
            return z ^ (z >> 31);
        }

        // pick a plausible-looking section name derived from the blob bytes
        std::string pick_section_name(Span<std::uint8_t> blob) {
            static constexpr const char* kPrefixes[] = {
                ".text", ".code", ".CODE", ".init", ".text0",
            };
            constexpr std::size_t n_pre = sizeof(kPrefixes) / sizeof(kPrefixes[0]);
            static constexpr char kSfxChars[] = "abcdefghijklmnopqrstuvwxyz0123456789";
            constexpr std::size_t n_sfx = sizeof(kSfxChars) - 1;

            // fnv-1a over the blob.
            std::uint64_t h = 0xcbf29ce484222325ULL;
            for (std::size_t i = 0; i < blob.size; ++i) {
                h ^= static_cast<std::uint64_t>(blob[i]);
                h *= 0x100000001b3ULL;
            }

            std::string out(kPrefixes[splitmix64_step(h) % n_pre]);

            // ~25% get the msvc-linker '$' group marker shape.
            if ((splitmix64_step(h) & 0x3) == 0 && out.size() + 2 <= 8) {
                out += '$';
            }

            const std::size_t slots = 8 - out.size();
            if (slots == 0) return out;
            const std::size_t want = 1 + (splitmix64_step(h) % std::min<std::size_t>(slots, 3));

            for (std::size_t i = 0; i < want; ++i) {
                out += kSfxChars[splitmix64_step(h) % n_sfx];
            }

            return out;
        }

        std::vector<std::uint8_t> read_file_bytes(const std::string& path) {
            std::ifstream in(path, std::ios::binary | std::ios::ate);
            if (!in) throw Error("cannot open target PE: " + path);
            const auto sz = static_cast<std::size_t>(in.tellg());
            in.seekg(0);
            std::vector<std::uint8_t> v(sz);
            if (!in.read(reinterpret_cast<char*>(v.data()), static_cast<std::streamsize>(sz))) throw Error("read target PE failed: " + path);
            return v;
        }

        // view into the PE. all offsets are file offsets.
        struct PeView {
            std::vector<std::uint8_t> bytes;
            bool                      is64{false};
            std::size_t               nt_off{0}; // PE\0\0
            std::size_t               file_hdr_off{0};
            std::size_t               opt_hdr_off{0};
            std::size_t               section_tbl_off{0};
            std::uint16_t             num_sections{0};
            std::uint32_t             file_alignment{0};
            std::uint32_t             section_alignment{0};
            std::uint32_t             size_of_headers{0};
            std::uint32_t             size_of_image{0};
            std::uint16_t             dll_characteristics{0};
            std::uint64_t             image_base{0};
            std::uint32_t             old_reloc_rva{0};
            std::uint32_t             old_reloc_size{0};
        };

        // iat slot for a named import like kernel32!CreateThread
        struct ImportLookup {
            std::uint32_t iat_rva{0};
            std::size_t   iat_file_off{0};
            bool          found{false};
        };

        PeView parse_pe(std::vector<std::uint8_t> raw) {
            PeView v;
            v.bytes = std::move(raw);
            if (v.bytes.size() < sizeof(IMAGE_DOS_HEADER)) throw Error("target PE too small for DOS header");

            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(v.bytes.data());
            if (dos->e_magic != kDosMagic) throw Error("target PE: bad DOS magic");

            v.nt_off = static_cast<std::size_t>(dos->e_lfanew);
            if (v.nt_off + sizeof(std::uint32_t) + sizeof(IMAGE_FILE_HEADER) > v.bytes.size()) throw Error("target PE: NT headers out of range");

            const std::uint32_t sig = *reinterpret_cast<std::uint32_t*>(v.bytes.data() + v.nt_off);
            if (sig != kPeMagic) throw Error("target PE: bad NT signature");

            v.file_hdr_off = v.nt_off + 4;
            auto* fh = reinterpret_cast<IMAGE_FILE_HEADER*>(v.bytes.data() + v.file_hdr_off);

            v.num_sections = fh->NumberOfSections;
            v.opt_hdr_off  = v.file_hdr_off + sizeof(IMAGE_FILE_HEADER);

            const std::uint16_t opt_magic = *reinterpret_cast<std::uint16_t*>(v.bytes.data() + v.opt_hdr_off);
            if (opt_magic == kOpt64) {
                v.is64 = true;
                if (v.opt_hdr_off + sizeof(IMAGE_OPTIONAL_HEADER64) > v.bytes.size()) throw Error("target PE: PE32+ optional header out of range");
                auto* o = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(v.bytes.data() + v.opt_hdr_off);

                v.file_alignment      = o->FileAlignment;
                v.section_alignment   = o->SectionAlignment;
                v.size_of_headers     = o->SizeOfHeaders;
                v.size_of_image       = o->SizeOfImage;
                v.dll_characteristics = o->DllCharacteristics;
                v.image_base          = o->ImageBase;
                v.old_reloc_rva       = o->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                v.old_reloc_size      = o->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
            }
            else if (opt_magic == kOpt32) {
                if (v.opt_hdr_off + sizeof(IMAGE_OPTIONAL_HEADER32) > v.bytes.size()) throw Error("target PE: PE32 optional header out of range");
                auto* o = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>( v.bytes.data() + v.opt_hdr_off);
                
                v.file_alignment      = o->FileAlignment;
                v.section_alignment   = o->SectionAlignment;
                v.size_of_headers     = o->SizeOfHeaders;
                v.size_of_image       = o->SizeOfImage;
                v.dll_characteristics = o->DllCharacteristics;
                v.image_base          = o->ImageBase;
                v.old_reloc_rva       = o->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                v.old_reloc_size      = o->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
            } 
            else {
                throw Error(fmt::format("target PE: unknown OptionalHeader magic 0x{:04x}", opt_magic));
            }

            v.section_tbl_off = v.opt_hdr_off + fh->SizeOfOptionalHeader;
            if (v.section_tbl_off + v.num_sections * sizeof(IMAGE_SECTION_HEADER) > v.bytes.size()) throw Error("target PE: section table out of range");
            if (v.file_alignment == 0 || v.section_alignment == 0) throw Error("target PE: zero alignment values");

            return v;
        }

        IMAGE_SECTION_HEADER& section_at(PeView& v, std::size_t i) {
            return *reinterpret_cast<IMAGE_SECTION_HEADER*>(v.bytes.data() + v.section_tbl_off + i * sizeof(IMAGE_SECTION_HEADER));
        }

        // returns the section covering rva, or nullptr.
        const IMAGE_SECTION_HEADER* section_for_rva(PeView& v, std::uint32_t rva) {
            for (std::size_t i = 0; i < v.num_sections; ++i) {
                const auto& s = section_at(v, i);
                const std::uint32_t va  = s.VirtualAddress;
                const std::uint32_t vsz = std::max<std::uint32_t>(s.Misc.VirtualSize, s.SizeOfRawData);

                if (rva >= va && rva < va + vsz) return &s;
            }

            return nullptr;
        }

        // rva -> file offset for write-back patches.
        std::size_t rva_to_file_off(const IMAGE_SECTION_HEADER& s, std::uint32_t rva) {
            return static_cast<std::size_t>(s.PointerToRawData) + static_cast<std::size_t>(rva - s.VirtualAddress);
        }

        // same as rva_to_file_off but finds the owning section first. 0 if nothing covers it.
        std::size_t any_rva_to_file_off(PeView& v, std::uint32_t rva) {
            for (std::size_t i = 0; i < v.num_sections; ++i) {
                const auto& s = section_at(v, i);
                const std::uint32_t va = s.VirtualAddress;
                const std::uint32_t sz = std::max<std::uint32_t>(s.Misc.VirtualSize, s.SizeOfRawData);

                if (rva >= va && rva < va + sz) return rva_to_file_off(s, rva);
            }

            return 0;
        }

        // look up an iat slot for module!sym. module match is case-insensitive,
        // trailing ".dll" is tolerated.
        ImportLookup find_iat_slot(PeView& v, const char* module, const char* sym) {
            ImportLookup out;
            std::uint32_t imp_rva = 0, imp_size = 0;

            if (v.is64) {
                auto* o = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(v.bytes.data() + v.opt_hdr_off);
                imp_rva  = o->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                imp_size = o->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
            }
            else {
                auto* o = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(v.bytes.data() + v.opt_hdr_off);
                imp_rva  = o->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                imp_size = o->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
            }

            if (imp_rva == 0 || imp_size < sizeof(IMAGE_IMPORT_DESCRIPTOR)) return out;
            const std::size_t imp_file = any_rva_to_file_off(v, imp_rva);
            if (imp_file == 0) return out;
            auto* descs = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(v.bytes.data() + imp_file);

            const std::size_t n_desc = imp_size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
            auto eq_ci = [](char a, char b){
                if (a >= 'A' && a <= 'Z') a = static_cast<char>(a - 'A' + 'a');
                if (b >= 'A' && b <= 'Z') b = static_cast<char>(b - 'A' + 'a');
                return a == b;
            };

            for (std::size_t d = 0; d < n_desc; ++d) {
                const auto& desc = descs[d];
                if (desc.Name == 0 || desc.OriginalFirstThunk == 0 || desc.FirstThunk == 0) continue;

                const std::size_t name_off = any_rva_to_file_off(v, desc.Name);
                if (name_off == 0) continue;
                const char* dll_name = reinterpret_cast<const char*>(v.bytes.data() + name_off);

                // module arg is the bare name without extension; ci prefix match.
                std::size_t mi = 0;
                bool match = true;

                for (; module[mi]; ++mi) {
                    if (!dll_name[mi] || !eq_ci(dll_name[mi], module[mi])) {
                        match = false; break;
                    }
                }

                // tolerate trailing ".dll" or similar.
                if (match) {
                    const char tail = dll_name[mi];
                    if (tail != 0 && tail != '.' && tail != '\0') match = false;

                }
                if (!match) continue;

                // walk ILT and IAT in lockstep.
                const std::size_t ilt_off = any_rva_to_file_off(v, desc.OriginalFirstThunk);
                if (ilt_off == 0) continue;

                const std::size_t thunk_size = v.is64 ? 8u : 4u;
                std::uint32_t k = 0;
                while (true) {
                    const std::size_t cur = ilt_off + k * thunk_size;
                    if (cur + thunk_size > v.bytes.size()) break;
                    std::uint64_t thunk_val = 0;
                    if (v.is64) thunk_val = *reinterpret_cast<std::uint64_t*>(v.bytes.data() + cur);
                    else        thunk_val = *reinterpret_cast<std::uint32_t*>(v.bytes.data() + cur);
                    if (thunk_val == 0) break;
                    
                    // high bit = import-by-ordinal, we only match by name so skip.
                    const std::uint64_t ord_bit = v.is64 ? (1ULL << 63) : (1ULL << 31);
                    if (thunk_val & ord_bit) { ++k; continue; }
                    const std::uint32_t name_rva = static_cast<std::uint32_t>(thunk_val);
                    const std::size_t hint_off = any_rva_to_file_off(v, name_rva);
                    if (hint_off == 0) { ++k; continue; }
                    
                    // IMAGE_IMPORT_BY_NAME: u16 hint then asciiz name.
                    const char* fname = reinterpret_cast<const char*>(v.bytes.data() + hint_off + 2);
                    if (std::strcmp(fname, sym) == 0) {
                        out.iat_rva = desc.FirstThunk + static_cast<std::uint32_t>(k * thunk_size);
                        out.iat_file_off = any_rva_to_file_off(v, out.iat_rva);
                        out.found = (out.iat_file_off != 0);
                        return out;
                    }

                    ++k;
                }
            }

            return out;
        }

        // decode insns from `bytes` until total length >= 5
        struct DisasmRun {
            std::vector<ZydisDecodedInstruction> insns;
            std::vector<std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT>> ops;
            std::uint32_t total_bytes{0};
        };

        DisasmRun disasm_min_5(const std::uint8_t* bytes, std::size_t cap, bool is64) {
            ZydisDecoder dec;

            ZydisDecoderInit(
                &dec,
                is64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32,
                is64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32
            );

            DisasmRun out;
            std::uint32_t consumed = 0;
            while (out.total_bytes < 5) {
                ZydisDecodedInstruction i{};
                std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> o{};
                if (consumed >= cap) throw Error("displaced run hit end of section before 5 bytes");

                if (ZYAN_FAILED(ZydisDecoderDecodeFull(
                        &dec,
                        bytes + consumed,
                        cap - consumed,
                        &i,
                        o.data()
                    ))) throw Error(fmt::format("disasm failed at displaced offset +{}", consumed));

                out.insns.push_back(i);
                out.ops.push_back(o);
                consumed         += i.length;
                out.total_bytes  += i.length;
            }

            return out;
        }

        // reject displaced insns we can't safely move to a new section
        void validate_displaced(const DisasmRun& run, bool is64) {
            for (std::size_t k = 0; k < run.insns.size(); ++k) {
                const auto& i = run.insns[k];
                const auto& ops = run.ops[k];
                const auto cat = i.meta.category;

                // relative call/jcc/jmp/ret: target would need re-relocation, just refuse
                if (cat == ZYDIS_CATEGORY_COND_BR ||
                    cat == ZYDIS_CATEGORY_UNCOND_BR ||
                    cat == ZYDIS_CATEGORY_CALL ||
                    cat == ZYDIS_CATEGORY_RET) {
                    throw Error(
                        fmt::format(
                            "displaced run has a control-flow insn at +{} "
                            "mnemonic {}, pick a different --at",
                            std::accumulate(
                                run.insns.begin(),
                                run.insns.begin() + k,
                                0u,
                                [](unsigned acc, const auto& ii){
                                    return acc + ii.length;
                                }
                            ),
                            ZydisMnemonicGetString(i.mnemonic)
                        )
                    );
                }

                for (std::uint8_t oi = 0; oi < i.operand_count_visible; ++oi) {
                    const auto& op = ops[oi];
                    if (op.type != ZYDIS_OPERAND_TYPE_MEMORY) continue;

                    // x64 rip-relative disp is computed off the next insn's rva
                    if (is64 && op.mem.base == ZYDIS_REGISTER_RIP) {
                        throw Error(
                            "displaced run has a rip-relative memory operand, "
                            "pick a different --at"
                        );
                    }
                }
            }
        }

        // x64 wrapper
        struct WrapperLayout {
            std::vector<std::uint8_t> bytes;
            std::size_t call_rel32_off{0}; // rel32 field of the call vm_blob
            std::size_t jmp_rel32_off{0};  // rel32 field of the final jmp resume_rva
            std::size_t vm_blob_off{0};    // where vm_blob bytes start
        };

        // same save/restore shape as the inline wrapper but the body is
        // CreateThread, NULL, 0, vm_blob, NULL, 0, NULL through the iat slot
        struct ThreadedFixups {
            std::size_t call_iat_disp32_off{0}; // disp32 in call qword ptr [rip + disp32]
            std::size_t lea_blob_disp32_off{0}; // disp32 in lea r8, [rip + blob]
        };
        WrapperLayout emit_wrapper_x64_threaded(const std::uint8_t* displaced,
                                                std::uint32_t dlen,
                                                ThreadedFixups& fx) {
            WrapperLayout w;
            auto& b = w.bytes;

            // pushfq
            b.push_back(0x9C);

            // push rax/rcx/rdx/rsi/rdi
            b.push_back(0x50); b.push_back(0x51); b.push_back(0x52);
            b.push_back(0x56); b.push_back(0x57);

            // push r8/r9/r10/r11
            b.push_back(0x41); b.push_back(0x50);
            b.push_back(0x41); b.push_back(0x51);
            b.push_back(0x41); b.push_back(0x52);
            b.push_back(0x41); b.push_back(0x53);

            // push rbp, used as align-save
            b.push_back(0x55);

            // mov rbp, rsp
            b.push_back(0x48); b.push_back(0x89); b.push_back(0xE5);

            // and rsp, -16
            b.push_back(0x48); b.push_back(0x83); b.push_back(0xE4);
            b.push_back(static_cast<std::uint8_t>(-16));

            // sub rsp, 0x38: shadow 0x20 + spill 2 args 0x10 + 0x08 align
            b.push_back(0x48); b.push_back(0x83); b.push_back(0xEC); b.push_back(0x38);

            // xor ecx, ecx -> lpThreadAttributes = NULL
            b.push_back(0x33); b.push_back(0xC9);

            // xor edx, edx -> dwStackSize = 0
            b.push_back(0x33); b.push_back(0xD2);

            // lea r8, [rip + disp32] -> lpStartAddress = vm_blob
            b.push_back(0x4C); b.push_back(0x8D); b.push_back(0x05);
            fx.lea_blob_disp32_off = b.size();
            b.push_back(0); b.push_back(0); b.push_back(0); b.push_back(0);

            // xor r9d, r9d -> lpParameter = NULL
            b.push_back(0x45); b.push_back(0x33); b.push_back(0xC9);

            // mov qword ptr [rsp+0x20], 0 -> dwCreationFlags = 0
            b.push_back(0x48); b.push_back(0xC7); b.push_back(0x44); b.push_back(0x24);
            b.push_back(0x20); b.push_back(0); b.push_back(0); b.push_back(0); b.push_back(0);

            // mov qword ptr [rsp+0x28], 0 -> lpThreadId = NULL
            b.push_back(0x48); b.push_back(0xC7); b.push_back(0x44); b.push_back(0x24);
            b.push_back(0x28); b.push_back(0); b.push_back(0); b.push_back(0); b.push_back(0);

            // call qword ptr [rip + disp32] -> CreateThread via iat slot
            b.push_back(0xFF); b.push_back(0x15);
            fx.call_iat_disp32_off = b.size();
            b.push_back(0); b.push_back(0); b.push_back(0); b.push_back(0);

            // mov rsp, rbp
            b.push_back(0x48); b.push_back(0x89); b.push_back(0xEC);

            // pop rbp
            b.push_back(0x5D);

            // pop r11/r10/r9/r8
            b.push_back(0x41); b.push_back(0x5B);
            b.push_back(0x41); b.push_back(0x5A);
            b.push_back(0x41); b.push_back(0x59);
            b.push_back(0x41); b.push_back(0x58);

            // pop rdi/rsi/rdx/rcx/rax
            b.push_back(0x5F); b.push_back(0x5E); b.push_back(0x5A);
            b.push_back(0x59); b.push_back(0x58);

            // popfq
            b.push_back(0x9D);

            // displaced original bytes
            b.insert(b.end(), displaced, displaced + dlen);

            // jmp rel32 resume_rva placeholder
            b.push_back(0xE9);
            w.jmp_rel32_off = b.size();
            b.push_back(0); b.push_back(0); b.push_back(0); b.push_back(0);
            
            // vm_blob bytes start here
            w.vm_blob_off = b.size();

            // no inline call vm_blob in threaded mode, the iat call slot is tracked
            // in fx. mark 0 here.
            w.call_rel32_off = 0;
            return w;
        }

        WrapperLayout emit_wrapper_x64(const std::uint8_t* displaced, std::uint32_t dlen) {
            WrapperLayout w;
            auto& b = w.bytes;

            // pushfq
            b.push_back(0x9C);

            // push rax/rcx/rdx/rsi/rdi
            b.push_back(0x50); b.push_back(0x51); b.push_back(0x52);
            b.push_back(0x56); b.push_back(0x57);

            // push r8/r9/r10/r11
            b.push_back(0x41); b.push_back(0x50);
            b.push_back(0x41); b.push_back(0x51);
            b.push_back(0x41); b.push_back(0x52);
            b.push_back(0x41); b.push_back(0x53);

            // push rbp, used as align-save scratch
            b.push_back(0x55);

            // mov rbp, rsp -> 48 89 E5
            b.push_back(0x48); b.push_back(0x89); b.push_back(0xE5);

            // and rsp, -16 -> 48 83 E4 F0
            b.push_back(0x48); b.push_back(0x83); b.push_back(0xE4);
            b.push_back(static_cast<std::uint8_t>(-16));

            // sub rsp, 0x28 shadow+align -> 48 83 EC 28
            b.push_back(0x48); b.push_back(0x83); b.push_back(0xEC); b.push_back(0x28);

            // call rel32 placeholder -> E8 ?? ?? ?? ??
            b.push_back(0xE8);
            w.call_rel32_off = b.size();
            b.push_back(0); b.push_back(0); b.push_back(0); b.push_back(0);

            // mov rsp, rbp -> 48 89 EC
            b.push_back(0x48); b.push_back(0x89); b.push_back(0xEC);

            // pop rbp
            b.push_back(0x5D);

            // pop r11/r10/r9/r8
            b.push_back(0x41); b.push_back(0x5B);
            b.push_back(0x41); b.push_back(0x5A);
            b.push_back(0x41); b.push_back(0x59);
            b.push_back(0x41); b.push_back(0x58);

            // pop rdi/rsi/rdx/rcx/rax
            b.push_back(0x5F); b.push_back(0x5E); b.push_back(0x5A);
            b.push_back(0x59); b.push_back(0x58);

            // popfq
            b.push_back(0x9D);

            // we overwrote the original bytes at the patch site with
            // the jmp rel32, so re-execute them here so flow continues
            b.insert(b.end(), displaced, displaced + dlen);

            // jmp rel32 resume_rva placeholder
            b.push_back(0xE9);
            w.jmp_rel32_off = b.size();
            b.push_back(0); b.push_back(0); b.push_back(0); b.push_back(0);

            // vm_blob bytes start here
            w.vm_blob_off = b.size();
            return w;
        }

        // x86 threaded wrapper uses absolute addressing for the indirect iat call
        struct ThreadedFixupsX86 {
            std::size_t call_iat_abs32_off{0};  // absolute va of iat slot
            std::size_t push_blob_abs32_off{0}; // absolute va to push for arg3, vm_blob
        };
        WrapperLayout emit_wrapper_x86_threaded(const std::uint8_t* displaced, std::uint32_t dlen, ThreadedFixupsX86& fx) {
            WrapperLayout w;
            auto& b = w.bytes;

            // pushfd; pushad
            b.push_back(0x9C); b.push_back(0x60);

            // stdcall CreateThread, args pushed right to left
            for (int j = 0; j < 3; ++j) { b.push_back(0x6A); b.push_back(0x00); }

            // 68 imm32 -> push vm_blob_va. placeholder, caller fixes up.
            b.push_back(0x68);
            fx.push_blob_abs32_off = b.size();
            b.push_back(0); b.push_back(0); b.push_back(0); b.push_back(0);

            // two more push 0
            for (int j = 0; j < 2; ++j) { b.push_back(0x6A); b.push_back(0x00); }

            // call dword ptr [iat_va] -> FF 15 abs32
            b.push_back(0xFF); b.push_back(0x15);
            fx.call_iat_abs32_off = b.size();
            b.push_back(0); b.push_back(0); b.push_back(0); b.push_back(0);
            
            // popad; popfd
            b.push_back(0x61); b.push_back(0x9D);
            b.insert(b.end(), displaced, displaced + dlen);
            b.push_back(0xE9);
            w.jmp_rel32_off = b.size();
            b.push_back(0); b.push_back(0); b.push_back(0); b.push_back(0);
            w.vm_blob_off = b.size();
            w.call_rel32_off = 0;
            return w;
        }

        WrapperLayout emit_wrapper_x86(const std::uint8_t* displaced, std::uint32_t dlen) {
            WrapperLayout w;
            auto& b = w.bytes;

            // pushfd -> 9C
            b.push_back(0x9C);

            // pushad -> 60
            b.push_back(0x60);

            // call rel32 -> E8 ?? ?? ?? ??
            b.push_back(0xE8);
            w.call_rel32_off = b.size();
            b.push_back(0); b.push_back(0); b.push_back(0); b.push_back(0);

            // popad -> 61
            b.push_back(0x61);

            // popfd -> 9D
            b.push_back(0x9D);

            // displaced original bytes
            b.insert(b.end(), displaced, displaced + dlen);

            // jmp rel32 resume_rva
            b.push_back(0xE9);
            w.jmp_rel32_off = b.size();
            b.push_back(0); b.push_back(0); b.push_back(0); b.push_back(0);
            w.vm_blob_off = b.size();
            return w;
        }
    }

    EmbedResult embed_vm_blob(Span<std::uint8_t> vm_blob, Arch arch, const EmbedOptions& opt) {
        PeView pe = parse_pe(read_file_bytes(opt.target_pe_path));

        // PE arch must match the vm blob.
        const bool blob_is64 = (arch == Arch::X64);
        if (pe.is64 != blob_is64) {
            throw Error(
                fmt::format(
                    "target PE arch is {} but vm blob arch is {}",
                    pe.is64   ? "x64" : "x86",
                    blob_is64 ? "x64" : "x86"
                )
            );
        }

        // --at must point into an executable section.
        const auto* patch_sec = section_for_rva(pe, opt.at_rva);
        if (!patch_sec) throw Error(fmt::format("--at rva 0x{:x} is not inside any section", opt.at_rva));
        if (!(patch_sec->Characteristics & IMAGE_SCN_MEM_EXECUTE))
            throw Error(
                fmt::format(
                    "--at rva 0x{:x} is in non-executable section '{:.8s}'",
                    opt.at_rva,
                    reinterpret_cast<const char*>(patch_sec->Name)
                )
            );

        // disasm at --at to find the smallest insn boundary >= 5 bytes.
        const std::size_t patch_file_off = rva_to_file_off(*patch_sec, opt.at_rva);
        const std::uint32_t section_end_rva = patch_sec->VirtualAddress + patch_sec->SizeOfRawData;
        const std::uint32_t cap_in_section = section_end_rva - opt.at_rva;
        const DisasmRun run = disasm_min_5(pe.bytes.data() + patch_file_off, cap_in_section, pe.is64);
        validate_displaced(run, pe.is64);
        const std::uint32_t dlen = run.total_bytes;

        // grab the displaced bytes before they get clobbered.
        std::vector<std::uint8_t> displaced(
            pe.bytes.begin() + patch_file_off,
            pe.bytes.begin() + patch_file_off + dlen
        );

        // new section raw content = wrapper + vm_blob.
        ImportLookup ct_iat;
        ThreadedFixups tfx{};
        ThreadedFixupsX86 tfx86{};
        bool use_thread = opt.spawn_thread;
        if (use_thread) {
            ct_iat = find_iat_slot(pe, "kernel32", "CreateThread");
            if (!ct_iat.found) {
                throw Error(
                    "threaded detour is the default but the target PE doesn't "
                    "import kernel32!CreateThread. pick a target that does, or "
                    "pass --detour-inline for a synchronous call that blocks "
                    "the host thread until the vm payload returns."
                );
            }
        }

        WrapperLayout w;
        if (pe.is64) {
            w = use_thread ? emit_wrapper_x64_threaded(displaced.data(), dlen, tfx) : emit_wrapper_x64(displaced.data(), dlen);
        }
        else {
            w = use_thread ? emit_wrapper_x86_threaded(displaced.data(), dlen, tfx86) : emit_wrapper_x86(displaced.data(), dlen);
        }

        // append vm_blob verbatim.
        w.bytes.insert(w.bytes.end(), vm_blob.data, vm_blob.data + vm_blob.size);

        // place the new section past the highest existing va, aligned up.
        std::uint32_t high_va_end = 0;
        for (std::size_t i = 0; i < pe.num_sections; ++i) {
            const auto& s = section_at(pe, i);
            const std::uint32_t vsz = std::max<std::uint32_t>(s.Misc.VirtualSize, s.SizeOfRawData);
            high_va_end = std::max<std::uint32_t>(high_va_end, s.VirtualAddress + vsz);
        }

        const std::uint32_t new_va = align_up(high_va_end, pe.section_alignment);
        const std::uint32_t new_raw_off = align_up(static_cast<std::uint32_t>(pe.bytes.size()), pe.file_alignment);

        // new_raw_size / new_v_size are computed AFTER the optional reloc-table
        // append below
        std::uint32_t headers_end = pe.size_of_headers;
        if (pe.num_sections > 0) {
            const auto& s0 = section_at(pe, 0);
            if (s0.PointerToRawData > 0 && s0.PointerToRawData < headers_end) headers_end = s0.PointerToRawData;
        }

        const std::size_t new_sec_hdr_off = pe.section_tbl_off + static_cast<std::size_t>(pe.num_sections) * sizeof(IMAGE_SECTION_HEADER);
        if (new_sec_hdr_off + sizeof(IMAGE_SECTION_HEADER) > headers_end) {
            throw Error(
                "no room in the section header table for another entry. "
                "would need to grow SizeOfHeaders, not implemented yet."
            );
        }

        // resolve the wrapper's call/jmp rel32s now that the section va is known.
        // both live in the wrapper's own address space.
        const std::uint32_t wrapper_va = new_va;
        const std::uint32_t vm_blob_va = new_va + static_cast<std::uint32_t>(w.vm_blob_off);

        auto write_rel32 = [&](std::size_t off, std::int32_t v) {
            for (int i = 0; i < 4; ++i) w.bytes[off + i] = static_cast<std::uint8_t>(v >> (8 * i));
        };

        if (use_thread && pe.is64) {
            // lea r8, [rip + disp32] -> vm_blob_va
            const std::uint32_t lea_end_va = new_va + static_cast<std::uint32_t>(tfx.lea_blob_disp32_off) + 4;
            write_rel32(tfx.lea_blob_disp32_off, static_cast<std::int32_t>(static_cast<std::int64_t>(vm_blob_va) - lea_end_va));

            // call qword ptr [rip + disp32] -> iat slot for CreateThread
            const std::uint32_t call_end_va = new_va + static_cast<std::uint32_t>(tfx.call_iat_disp32_off) + 4;
            const std::int64_t  call_disp   = static_cast<std::int64_t>(ct_iat.iat_rva) - call_end_va;

            if (call_disp < INT32_MIN || call_disp > INT32_MAX) throw Error("iat slot too far for rip-relative call, >2GB");
            write_rel32(tfx.call_iat_disp32_off, static_cast<std::int32_t>(call_disp));
        } 
        else if (use_thread && !pe.is64) {
            // x86 threaded: write absolute va initial values, ImageBase + rva 
            const std::uint32_t blob_va32 = static_cast<std::uint32_t>(pe.image_base) + vm_blob_va;
            const std::uint32_t iat_va32  = static_cast<std::uint32_t>(pe.image_base) + ct_iat.iat_rva;
            write_rel32(tfx86.push_blob_abs32_off, static_cast<std::int32_t>(blob_va32));
            write_rel32(tfx86.call_iat_abs32_off, static_cast<std::int32_t>(iat_va32));
        }
        else {
            const std::uint32_t call_end_va = new_va + static_cast<std::uint32_t>(w.call_rel32_off) + 4;
            write_rel32(
                w.call_rel32_off,
                static_cast<std::int32_t>(
                static_cast<std::int64_t>(vm_blob_va) - call_end_va)
            );
        }

        const std::uint32_t resume_rva = opt.at_rva + dlen;
        const std::uint32_t jmp_end_va = new_va + static_cast<std::uint32_t>(w.jmp_rel32_off) + 4;
        write_rel32(
            w.jmp_rel32_off,
            static_cast<std::int32_t>(
            static_cast<std::int64_t>(resume_rva) - jmp_end_va)
        );

        // x86 threaded only: append a combined base-reloc table at the section
        // tail
        std::uint32_t new_reloc_table_va   = 0;
        std::uint32_t new_reloc_table_size = 0;
        if (use_thread && !pe.is64) {
            // 8-byte align inside the section.
            while (w.bytes.size() & 7u) w.bytes.push_back(0);
            new_reloc_table_va = new_va + static_cast<std::uint32_t>(w.bytes.size());

            // copy existing relocs verbatim if any.
            if (pe.old_reloc_size > 0) {
                const std::size_t old_off = any_rva_to_file_off(pe, pe.old_reloc_rva);
                if (old_off == 0) throw Error("existing base-reloc table rva doesn't resolve to a file offset");

                w.bytes.insert(
                    w.bytes.end(),
                    pe.bytes.begin() + old_off,
                    pe.bytes.begin() + old_off + pe.old_reloc_size
                );
            }

            // build a new block for our 2 abs32 fields 
            const std::uint32_t page_base = new_va & ~0xFFFu;
            const std::uint16_t off_a = static_cast<std::uint16_t>((new_va + tfx86.push_blob_abs32_off) - page_base);
            const std::uint16_t off_b = static_cast<std::uint16_t>((new_va + tfx86.call_iat_abs32_off) - page_base);
            if (off_a >= 0x1000 || off_b >= 0x1000) throw Error("reloc entries cross a 4KB page boundary, would need a second block");

            // IMAGE_REL_BASED_HIGHLOW = 3 for x86 abs32
            const std::uint16_t e_a = static_cast<std::uint16_t>((3u << 12) | off_a);
            const std::uint16_t e_b = static_cast<std::uint16_t>((3u << 12) | off_b);
            const std::uint32_t block_size = 8u + 2u * 2u; // header + 2 entries

            // block header: u32 VirtualAddress page base, u32 SizeOfBlock
            for (int i = 0; i < 4; ++i) w.bytes.push_back(static_cast<std::uint8_t>(page_base >> (8 * i)));
            for (int i = 0; i < 4; ++i) w.bytes.push_back(static_cast<std::uint8_t>(block_size >> (8 * i)));

            w.bytes.push_back(static_cast<std::uint8_t>(e_a & 0xFF));
            w.bytes.push_back(static_cast<std::uint8_t>((e_a >> 8) & 0xFF));
            w.bytes.push_back(static_cast<std::uint8_t>(e_b & 0xFF));
            w.bytes.push_back(static_cast<std::uint8_t>((e_b >> 8) & 0xFF));

            new_reloc_table_size = pe.old_reloc_size + block_size;
        }

        // section content is final, compute size headers.
        const std::uint32_t new_raw_size = align_up(static_cast<std::uint32_t>(w.bytes.size()), pe.file_alignment);
        const std::uint32_t new_v_size   = static_cast<std::uint32_t>(w.bytes.size());

        // patch-site jmp rel32: target = wrapper_va, source = at_rva+5.
        const std::int32_t patch_rel32 = static_cast<std::int32_t>(static_cast<std::int64_t>(wrapper_va) - (static_cast<std::int64_t>(opt.at_rva) + 5));

        // write jmp at the patch site, nop-fill the leftover displaced bytes.
        pe.bytes[patch_file_off + 0] = 0xE9;
        for (int i = 0; i < 4; ++i) pe.bytes[patch_file_off + 1 + i] = static_cast<std::uint8_t>(patch_rel32 >> (8 * i));
        for (std::uint32_t k = 5; k < dlen; ++k) pe.bytes[patch_file_off + k] = 0x90; // nop

        // append the new section bytes at new_raw_off, pad to file_alignment.
        if (pe.bytes.size() < new_raw_off) pe.bytes.resize(new_raw_off, 0);

        pe.bytes.insert(pe.bytes.end(), w.bytes.begin(), w.bytes.end());
        if (pe.bytes.size() < new_raw_off + new_raw_size) pe.bytes.resize(new_raw_off + new_raw_size, 0);

        // add the new IMAGE_SECTION_HEADER.
        auto* nh = reinterpret_cast<IMAGE_SECTION_HEADER*>(pe.bytes.data() + new_sec_hdr_off);
        std::memset(nh, 0, sizeof(*nh));
        const std::string nm = opt.section_name.empty() ? pick_section_name(vm_blob) : opt.section_name;

        std::memcpy(nh->Name, nm.data(), std::min<std::size_t>(nm.size(), 8));
        nh->Misc.VirtualSize = new_v_size;
        nh->VirtualAddress   = new_va;
        nh->SizeOfRawData    = new_raw_size;
        nh->PointerToRawData = new_raw_off;
        nh->Characteristics  = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;

        // bump file/optional header fields.
        auto* fh = reinterpret_cast<IMAGE_FILE_HEADER*>(pe.bytes.data() + pe.file_hdr_off);
        fh->NumberOfSections = static_cast<std::uint16_t>(pe.num_sections + 1);
        const std::uint32_t new_size_of_image = align_up(new_va + new_v_size, pe.section_alignment);
        if (pe.is64) {
            auto* o = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(pe.bytes.data() + pe.opt_hdr_off);
            o->SizeOfImage = new_size_of_image;
            o->CheckSum    = 0; // invalidate, loader doesn't enforce for exes
        }
        else {
            auto* o = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(pe.bytes.data() + pe.opt_hdr_off);
            o->SizeOfImage = new_size_of_image;
            o->CheckSum    = 0;
            if (new_reloc_table_size > 0) {
                o->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = new_reloc_table_va;
                o->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = new_reloc_table_size;
            }
        }

        EmbedResult out;
        out.patched_pe = std::move(pe.bytes);
        out.stats = fmt::format(
            "embedded: target_arch={} new_section='{}' va=0x{:x} raw=0x{:x}/0x{:x} "
            "wrapper={} B vm_blob={} B  patched jmp rel32 at rva 0x{:x}, "
            "{} B displaced, mode={}{}",
            pe.is64 ? "x64" : "x86",
            nm.c_str(),
            new_va,
            new_raw_off,
            new_raw_size,
            w.vm_blob_off,
            vm_blob.size,
            opt.at_rva,
            dlen,
            use_thread ? "threaded" : "inline",
            (use_thread && !pe.is64 && new_reloc_table_size > 0) ? "  x86 threaded uses base-reloc entries" : ""
        );

        if ((pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0) {
            out.stats += "  warn: target has CFG enabled, direct rel32 into the "
                         "new section may or may not survive depending on the "
                         "CFG bitmap scope";
        }

        return out;
    }
}