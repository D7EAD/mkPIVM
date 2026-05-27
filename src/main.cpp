#include "mkpivm/cfg.h"
#include "mkpivm/packager.h"
#include "mkpivm/pe_embed.h"
#include "mkpivm/util.h"

#include <Zydis/Zydis.h>

#include <fmt/format.h>
#include <deque>
#include <set>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
    #include <fcntl.h>
    #include <io.h>
#endif

namespace {
    enum class Format { Raw, Hex, C, Py, Ps1, B64, Nasm };

    void print_usage(const char* prog) {
        std::fprintf(stderr,
            "mkpivm: virtualizing your shellcode for fun and profit\n"
            "\n"
            "usage: %s [options] <input.bin> [<output>]\n"
            "\n"
            "options:\n"
            "  --arch x86|x64        force input arch. default x64.\n"
            "  --seed <u64>          prng seed, decimal or 0xHEX. default is time-based.\n"
            "  -o <path>             output path. default is stdout if no positional output.\n"
            "  --format <fmt>        output format: raw default, hex, c, py, ps1, b64, nasm.\n"
            "  --ranges <a:b,c:d>    hybrid mode: virtualize only these byte ranges of the\n"
            "                        input. bytes outside stay native in the output. offsets\n"
            "                        in decimal or 0xHEX, end-exclusive. without --ranges we\n"
            "                        still virtualize the whole shellcode.\n"
            "  --scan                enumerate eligible --ranges candidates: call-target\n"
            "                        functions ending in ret. doesn't package, just dumps a\n"
            "                        list of ranges and exits.\n"
            "  --coroutines          marker flag for ranges whose reachable subgraph has no\n"
            "                        ret-terminated block. coroutine style: enter via jmp,\n"
            "                        exit via jmp to native. use with --ranges. --scan lists\n"
            "                        these under 'coroutine candidates'. no lift-time check\n"
            "                        yet, the packager-time cfg can't reliably tell these\n"
            "                        from mid-exec-exit ranges.\n"
            "  --range-leak-nvs      opt-in. JMP_NATIVE imm-cleanup splats VMState NV slots\n"
            "                        back over the prologue stack saves so lifted writes to\n"
            "                        ebx/ebp/esi/edi and r12-r15 on x64 actually survive\n"
            "                        into the surrounding native bytes. dont flip this on a\n"
            "                        function-shaped range or mid-flow escapes will trash\n"
            "                        the caller's nvs. use it for straight-line partial\n"
            "                        lifts where downstream native bytes need to see what\n"
            "                        the lifted code wrote.\n"
            "  --coro-prelo N        coroutine pre-load: copy N qwords from real_stack[0..N*8]\n"
            "                        onto VM_RSP at range entry. needed when native code\n"
            "                        pushed values BEFORE the range entry that lifted POPs\n"
            "                        inside the range expect to pop. e.g. cobalt's API\n"
            "                        resolver enters via `call rbp` then does 5 startup pushes\n"
            "                        natively before the patched VM entry at 0x21; use --coro-prelo\n"
            "                        6 for that range.\n"
            "  --heap-stack          switch VM dispatcher to a blob-embedded 64 KB static\n"
            "                        stack region instead of running on the host's real\n"
            "                        stack. caller's rsp is saved at prologue and restored\n"
            "                        at every native dispatch so external Win APIs get full\n"
            "                        caller-stack frame room. resolves the conflict where\n"
            "                        chained API calls would otherwise have to share rsp with\n"
            "                        VM dispatcher scratch.\n"
            "  --pack                packer mode: don't lift the input. wrap it as encrypted\n"
            "                        data carried by the per-seed polymorphic vm: cipher,\n"
            "                        reg shuffle, handler-table encryption, all of it. at\n"
            "                        runtime the vm stub decrypts the data island in place\n"
            "                        and tail-jumps to byte 0 of the original shellcode.\n"
            "                        pair with --ranges for encrypted-at-rest + granular\n"
            "                        virt: range-mode blob is built first, then pack-wrapped.\n"
            "  --embed-into <target.exe> --at <rva>\n"
            "                        detour mode: input is already a built mkpivm vm blob.\n"
            "                        patch a jmp at rva in target.exe to a freshly added\n"
            "                        rwx section with a transparent wrapper that saves\n"
            "                        flags + volatile regs, kicks off CreateThread vm_blob,\n"
            "                        restores, runs the displaced original bytes, and jmps\n"
            "                        back. default is threaded so beacons/stagers run in\n"
            "                        the background without hanging the host's main thread.\n"
            "                        pass --detour-inline for a synchronous call vm_blob.\n"
            "                        host blocks until vm returns. required on x86 or when\n"
            "                        the target doesn't import CreateThread. skips virt\n"
            "                        entirely, use --arch to say what the blob is.\n"
            "  --detour-inline       with --embed-into, force a sync call instead of\n"
            "                        the default CreateThread.\n"
            "  --input-format <fmt>  force input decoder, bypasses auto-detection.\n"
            "                        auto default | raw | escape | 0x | hex | b64\n"
            "  --verbose             verbose stats\n"
            "\n"
            "input: bytes can be raw, \\xHH escapes, 0xHH c-array literals, continuous hex,\n"
            "       or base64. format is auto-detected from content. extension is ignored.\n"
            "       use --input-format to override.\n"
            , prog);
    }

    std::vector<std::uint8_t> read_file(const std::string& path) {
        std::ifstream in(path, std::ios::binary | std::ios::ate);
        if (!in) throw mkpivm::Error("cannot open input: " + path);
        const auto sz = in.tellg();
        in.seekg(0);

        std::vector<std::uint8_t> v(static_cast<std::size_t>(sz));
        if (!in.read(reinterpret_cast<char*>(v.data()), sz)) throw mkpivm::Error("read failed");
        return v;
    }

    int hex_nybble(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    // every byte past an optional utf-8 bom is printable ascii or common
    // whitespace
    bool looks_like_text(const std::vector<std::uint8_t>& v, std::size_t& body_start) {
        body_start = 0;
        if (v.size() >= 3 && v[0] == 0xEF && v[1] == 0xBB && v[2] == 0xBF) body_start = 3;
        if (v.size() <= body_start) return false;
        for (std::size_t i = body_start; i < v.size(); ++i) {
            const std::uint8_t b = v[i];
            if (b == 0x09 || b == 0x0A || b == 0x0D) continue;
            if (b >= 0x20 && b <= 0x7E) continue;
            return false;
        }
        return true;
    }

    // pull every \xHH escape out of s 
    std::vector<std::uint8_t> extract_backslash_x(std::string_view s) {
        std::vector<std::uint8_t> out;
        std::size_t i = 0;
        while (i + 3 < s.size()) {
            if (s[i] == '\\' && (s[i + 1] == 'x' || s[i + 1] == 'X')) {
                const int hi = hex_nybble(s[i + 2]);
                const int lo = hex_nybble(s[i + 3]);
                if (hi >= 0 && lo >= 0) {
                    out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
                    i += 4;
                    continue;
                }
            }
            ++i;
        }
        return out;
    }

    // pull every 0xHH literal out of s 
    std::vector<std::uint8_t> extract_0x(std::string_view s) {
        std::vector<std::uint8_t> out;
        std::size_t i = 0;
        while (i + 3 < s.size()) {
            if (s[i] == '0' && (s[i + 1] == 'x' || s[i + 1] == 'X')) {
                const int hi = hex_nybble(s[i + 2]);
                const int lo = hex_nybble(s[i + 3]);
                const int third = (i + 4 < s.size()) ? hex_nybble(s[i + 4]) : -1;
                if (hi >= 0 && lo >= 0 && third < 0) {
                    out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
                    i += 4;
                    continue;
                }
            }
            ++i;
        }
        return out;
    }

    // decode s as base64, whitespace ignored 
    std::vector<std::uint8_t> try_base64(std::string_view s) {
        static int lut[256];
        static bool inited = false;
        if (!inited) {
            for (int i = 0; i < 256; ++i) lut[i] = -1;
            const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                              "abcdefghijklmnopqrstuvwxyz"
                              "0123456789+/";
            for (int i = 0; i < 64; ++i) lut[static_cast<unsigned char>(tbl[i])] = i;
            inited = true;
        }
        std::string c;
        c.reserve(s.size());
        for (char ch : s) {
            if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r') continue;
            c.push_back(ch);
        }
        int pad = 0;
        while (pad < 2 && !c.empty() && c.back() == '=') { c.pop_back(); ++pad; }
        if (c.empty() || (c.size() % 4) == 1) return {};
        for (char ch : c) if (lut[static_cast<unsigned char>(ch)] < 0) return {};

        std::vector<std::uint8_t> out;
        out.reserve(c.size() * 3 / 4 + 2);
        std::size_t i = 0;
        for (; i + 4 <= c.size(); i += 4) {
            const std::uint32_t n = (std::uint32_t(lut[static_cast<unsigned char>(c[i])])     << 18) |
                                    (std::uint32_t(lut[static_cast<unsigned char>(c[i + 1])]) << 12) |
                                    (std::uint32_t(lut[static_cast<unsigned char>(c[i + 2])]) << 6)  |
                                     std::uint32_t(lut[static_cast<unsigned char>(c[i + 3])]);

            out.push_back(static_cast<std::uint8_t>((n >> 16) & 0xFF));
            out.push_back(static_cast<std::uint8_t>((n >> 8)  & 0xFF));
            out.push_back(static_cast<std::uint8_t>( n        & 0xFF));
        }
        const std::size_t rem = c.size() - i;

        if (rem == 2) {
            const std::uint32_t n = (std::uint32_t(lut[static_cast<unsigned char>(c[i])])     << 18) |
                                    (std::uint32_t(lut[static_cast<unsigned char>(c[i + 1])]) << 12);
            out.push_back(static_cast<std::uint8_t>((n >> 16) & 0xFF));
        } 
        else if (rem == 3) {
            const std::uint32_t n = (std::uint32_t(lut[static_cast<unsigned char>(c[i])])     << 18) |
                                    (std::uint32_t(lut[static_cast<unsigned char>(c[i + 1])]) << 12) |
                                    (std::uint32_t(lut[static_cast<unsigned char>(c[i + 2])]) << 6);
            out.push_back(static_cast<std::uint8_t>((n >> 16) & 0xFF));
            out.push_back(static_cast<std::uint8_t>((n >> 8)  & 0xFF));
        }
        
        return out;
    }

    // decode s as bare hex with permissive separators
    std::vector<std::uint8_t> try_bare_hex(std::string_view s) {
        std::string c;
        c.reserve(s.size());
        for (char ch : s) {
            if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' ||
                ch == ',' || ch == ';' || ch == ':' || ch == '-' || ch == '_') continue;
            if (hex_nybble(ch) < 0) return {};
            c.push_back(ch);
        }

        if (c.empty() || (c.size() & 1)) return {};
        std::vector<std::uint8_t> out;
        out.reserve(c.size() / 2);

        for (std::size_t i = 0; i < c.size(); i += 2) {
            const int hi = hex_nybble(c[i]);
            const int lo = hex_nybble(c[i + 1]);
            out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
        }

        return out;
    }

    enum class InputFormat { Auto, Raw, EscX, ZeroX, Hex, B64 };

    InputFormat parse_input_format(const std::string& s) {
        if (s == "auto")                                               return InputFormat::Auto;
        if (s == "raw" || s == "bin")                                  return InputFormat::Raw;
        if (s == "escape" || s == "escx" || s == "\\x"   || s == "py") return InputFormat::EscX;
        if (s == "0x"    || s == "c")                                  return InputFormat::ZeroX;
        if (s == "hex")                                                return InputFormat::Hex;
        if (s == "b64"   || s == "base64")                             return InputFormat::B64;
        throw mkpivm::Error("unknown --input-format: " + s + ", expected auto|raw|escape|0x|hex|b64");
    }

    // decode input bytes. `forced` overrides auto-detect
    std::vector<std::uint8_t> decode_input(std::vector<std::uint8_t> raw, InputFormat forced, const char** fmt_out) {
        if (forced == InputFormat::Raw) { *fmt_out = "raw forced"; return raw; }

        std::size_t bom = 0;
        const bool is_text = looks_like_text(raw, bom);
        const std::string_view s(reinterpret_cast<const char*>(raw.data() + bom), raw.size() - bom);

        auto fail = [&](const char* fmt_name) -> std::vector<std::uint8_t> {
            throw mkpivm::Error(std::string("--input-format ") + fmt_name + ": input doesn't decode as that format");
        };

        switch (forced) {
            case InputFormat::EscX: {
                auto v = extract_backslash_x(s);
                if (v.empty()) return fail("escape");
                *fmt_out = "\\xHH forced"; return v;
            }
            case InputFormat::ZeroX: {
                auto v = extract_0x(s);
                if (v.empty()) return fail("0x");
                *fmt_out = "0xHH forced"; return v;
            }
            case InputFormat::Hex: {
                auto v = try_bare_hex(s);
                if (v.empty()) return fail("hex");
                *fmt_out = "hex forced"; return v;
            }
            case InputFormat::B64: {
                auto v = try_base64(s);
                if (v.empty()) return fail("b64");
                *fmt_out = "base64 forced"; return v;
            }
            default: break;
        }

        // auto path
        if (!is_text) { *fmt_out = "raw"; return raw; }

        if (auto v = extract_backslash_x(s); !v.empty()) { *fmt_out = "\\xHH"; return v; }
        if (auto v = extract_0x(s);          !v.empty()) { *fmt_out = "0xHH"; return v; }

        // continuous hex is a valid base64 alphabet subset, so use the presence
        // of b64-only chars +, /, = to disambiguate 
        bool b64_marker = false;
        for (char ch : s) if (ch == '+' || ch == '/' || ch == '=') { b64_marker = true; break; }

        if (b64_marker) {
            if (auto v = try_base64(s); !v.empty()) { *fmt_out = "base64"; return v; }
        }

        if (auto v = try_bare_hex(s); !v.empty()) { *fmt_out = "hex"; return v; }
        if (auto v = try_base64(s);   !v.empty()) { *fmt_out = "base64"; return v; }
        throw mkpivm::Error(
            "input looks textual but no hex or base64 content found. "
            "use --input-format raw to force binary interpretation."
        );
    }

    std::uint64_t parse_u64(const char* s) {
        char* end = nullptr;
        std::uint64_t v = std::strtoull(s, &end, 0);
        if (end == s) throw mkpivm::Error(std::string("bad u64: ") + s);
        return v;
    }

    // parse a:b,c:d,... into a sorted, non-overlapping range list 
    std::vector<mkpivm::ByteRange> parse_ranges(const std::string& spec) {
        std::vector<mkpivm::ByteRange> out;

        std::size_t i = 0;
        while (i < spec.size()) {
            std::size_t comma = spec.find(',', i);
            const std::string tok = spec.substr(i, comma - i);
            const std::size_t colon = tok.find(':');
            if (colon == std::string::npos) throw mkpivm::Error("--ranges entry missing ':' separator: " + tok);

            const std::uint64_t a = parse_u64(tok.substr(0, colon).c_str());
            const std::uint64_t b = parse_u64(tok.substr(colon + 1).c_str());
            if (a >= b) throw mkpivm::Error("--ranges: start>=end in " + tok);

            if (b > 0xFFFFFFFFull) throw mkpivm::Error("--ranges: end > 4G in " + tok);
            out.emplace_back(static_cast<std::uint32_t>(a), static_cast<std::uint32_t>(b));

            if (comma == std::string::npos) break;
            i = comma + 1;
        }

        std::sort(out.begin(), out.end());
        for (std::size_t k = 1; k < out.size(); ++k) {
            if (out[k].first < out[k - 1].second) {
                throw mkpivm::Error(
                    "--ranges: ranges overlap: " +
                    std::to_string(out[k - 1].first) + ":" +
                    std::to_string(out[k - 1].second) + " and " +
                    std::to_string(out[k].first) + ":" +
                    std::to_string(out[k].second)
                );
            }
        }

        return out;
    }

    // --scan: build the cfg and dump every call-target function that's eligible
    // for --ranges virtualization 
    void run_scan(const std::vector<std::uint8_t>& bytes, mkpivm::Arch arch, std::uint64_t base_va) {
        mkpivm::Span<std::uint8_t> code{bytes.data(), bytes.size()};
        mkpivm::CFGBuilder cfg{arch, code, base_va};
        cfg.build();
        const auto& blocks = cfg.blocks();
        const auto& vam = cfg.va_to_block_id();

        std::fprintf(
            stderr,
            "scan: input %zu bytes, %s, %zu cfg blocks\n\n",
            bytes.size(),
            arch == mkpivm::Arch::X86 ? "x86" : "x64",
            blocks.size()
        );

        struct Candidate {
            std::uint64_t           entry_va;
            std::uint64_t           end_va; // exclusive
            std::size_t             block_count;
            std::size_t             body_len;
            bool                    contiguous;
            bool                    has_ret;
            bool                    is_call_target;
            bool                    is_jmp_target;
            bool                    external_entries;
            std::uint32_t           coro_prelo_n;     // max-depth-below-initial of stack balance
            bool                    needs_heap_stack; // range has a `jmp REG` or `jmp [MEM]`
            std::set<std::uint64_t> reachable_va_starts; // dedup helper
        };
        std::vector<Candidate> cands;

        ZydisDecoder zdec;
        if (arch == mkpivm::Arch::X64) {
            ZydisDecoderInit(&zdec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
        } else {
            ZydisDecoderInit(&zdec, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
        }

        auto analyze_range = [&](std::uint64_t start_va, std::uint64_t end_va,
                                 std::uint32_t& out_prelo, bool& out_heap_stack)
        {
            out_prelo = 0;
            out_heap_stack = false;

            std::int32_t balance     = 0;
            std::int32_t min_balance = 0;

            std::uint64_t va = start_va;
            while (va < end_va) {
                if (!cfg.code_vas().count(va)) {
                    // mid-instruction byte or data island; skip a byte
                    va += 1;
                    continue;
                }
                const std::size_t off = static_cast<std::size_t>(va - base_va);
                if (off >= bytes.size()) break;

                ZydisDecodedInstruction insn;
                ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT];
                const std::size_t avail = std::min<std::size_t>(15, bytes.size() - off);
                const ZyanStatus st = ZydisDecoderDecodeFull(
                    &zdec, bytes.data() + off, avail, &insn, ops
                );
                if (!ZYAN_SUCCESS(st)) {
                    va += 1;
                    continue;
                }

                switch (insn.mnemonic) {
                    case ZYDIS_MNEMONIC_PUSH:
                    case ZYDIS_MNEMONIC_PUSHF:
                    case ZYDIS_MNEMONIC_PUSHFD:
                    case ZYDIS_MNEMONIC_PUSHFQ:
                        balance += 1;
                        break;
                    case ZYDIS_MNEMONIC_POP:
                    case ZYDIS_MNEMONIC_POPF:
                    case ZYDIS_MNEMONIC_POPFD:
                    case ZYDIS_MNEMONIC_POPFQ:
                        balance -= 1;
                        if (balance < min_balance) min_balance = balance;
                        break;
                    case ZYDIS_MNEMONIC_PUSHA:
                    case ZYDIS_MNEMONIC_PUSHAD:
                        // x86 pushad/pusha pushes 8/4 registers
                        balance += 8;
                        break;
                    case ZYDIS_MNEMONIC_POPA:
                    case ZYDIS_MNEMONIC_POPAD:
                        balance -= 8;
                        if (balance < min_balance) min_balance = balance;
                        break;
                    case ZYDIS_MNEMONIC_JMP:
                        // indirect jmp
                        if (insn.operand_count_visible >= 1 &&
                            ops[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
                        {
                            out_heap_stack = true;
                        }
                        break;
                    default:
                        break;
                }

                va += insn.length;
            }

            if (min_balance < 0) {
                out_prelo = static_cast<std::uint32_t>(-min_balance);
            }
        };

        for (std::size_t bi = 0; bi < blocks.size(); ++bi) {
            // enumerate any block that's a static entry from somewhere else in
            // the shellcode 
            if (!blocks[bi].is_call_target && !blocks[bi].is_jmp_target) continue;

            // bfs the successor graph from this entry block.
            std::set<std::uint32_t> seen;
            std::deque<std::uint32_t> work;
            seen.insert(static_cast<std::uint32_t>(bi));
            work.push_back(static_cast<std::uint32_t>(bi));
            std::uint64_t min_va = blocks[bi].start_va;
            std::uint64_t max_va = blocks[bi].end_va;
            bool has_ret = false;

            while (!work.empty()) {
                const auto id = work.front(); work.pop_front();
                const auto& b = blocks[id];
                min_va = std::min(min_va, b.start_va);
                max_va = std::max(max_va, b.end_va);

                if (b.ends_with_ret) has_ret = true;

                for (auto succ_va : b.successors) {
                    auto it = vam.find(succ_va);
                    if (it == vam.end()) continue;
                    if (seen.insert(it->second).second) work.push_back(it->second);
                }
            }

            // walk every byte in min_va..max_va 
            const auto& code_vas = cfg.code_vas();
            bool contiguous = true;
            for (std::uint64_t v = min_va; v < max_va; ++v) {
                if (!code_vas.count(v)) {
                    // a byte that isn't a recognized insn start could just be
                    // mid-instruction, totally normal 
                    bool inside_visited = false;

                    for (auto id : seen) {
                        if (v >= blocks[id].start_va && v < blocks[id].end_va) {
                            inside_visited = true; break;
                        }
                    }

                    if (!inside_visited) { contiguous = false; break; }
                }
            }

            const std::size_t body_len = static_cast<std::size_t>(max_va - blocks[bi].start_va);
            std::set<std::uint64_t> reachable;
            for (auto id : seen) reachable.insert(blocks[id].start_va);

            // safety: in hybrid mode, range bytes from start+5 to end get
            // int3-filled, the 5-byte jmp vm_entry patch occupies the first 5 
            bool external_entries = false;
            for (std::size_t k = 0; k < blocks.size(); ++k) {
                if (seen.count(static_cast<std::uint32_t>(k))) continue;

                for (auto succ : blocks[k].successors) {
                    if (succ > blocks[bi].start_va && succ < max_va) {
                        external_entries = true; break;
                    }
                }

                if (external_entries) break;
            }

            std::uint32_t prelo_n = 0;
            bool          needs_heap = false;
            analyze_range(blocks[bi].start_va, max_va, prelo_n, needs_heap);

            cands.push_back(
                {
                    blocks[bi].start_va, max_va, seen.size(),
                    body_len, contiguous, has_ret,
                    blocks[bi].is_call_target,
                    blocks[bi].is_jmp_target,
                    external_entries,
                    prelo_n, needs_heap,
                    std::move(reachable)
                }
            );
        }

        auto is_eligible = [](const Candidate& c){
            return c.contiguous && c.has_ret && c.body_len >= 5 && !c.external_entries;
        };

        // coroutine candidate: same shape as an eligible range but no ret-
        // terminated block in the reachable subgraph 
        auto is_coroutine = [](const Candidate& c){
            return c.contiguous && !c.has_ret && c.body_len >= 5 && !c.external_entries;
        };

        auto is_acceptable = [&](const Candidate& c){
            return is_eligible(c) || is_coroutine(c);
        };

        // dedup: lots of jmp-targets are intra-function branch labels whose
        // bfs reachable set is a subset of an outer function entry's 
        std::sort(
            cands.begin(), 
            cands.end(),
            [&](const Candidate& a, const Candidate& b) {
                const bool ae = is_eligible(a), be = is_eligible(b);
                if (ae != be) return ae;

                const bool ac = is_coroutine(a), bc = is_coroutine(b);
                if (ac != bc) return ac;

                if (a.is_call_target != b.is_call_target) return a.is_call_target;

                return a.entry_va < b.entry_va;
            }
        );

        std::vector<bool> shadowed(cands.size(), false);
        for (std::size_t i = 0; i < cands.size(); ++i) {
            if (!is_acceptable(cands[i]) || shadowed[i]) continue;

            for (std::size_t j = i + 1; j < cands.size(); ++j) {
                if (shadowed[j]) continue;
                if (cands[i].reachable_va_starts.count(cands[j].entry_va)) shadowed[j] = true;
            }
        }

        auto entry_tag = [](const Candidate& c) -> const char* {
            if (c.is_call_target && c.is_jmp_target) return "call+jmp";
            if (c.is_call_target) return "call    ";
            return "jmp     "; // jmp-only entry, tail-call pattern
        };
        
        // helper: append " --coro-prelo N --heap-stack" if needed
        auto append_extras = [](char* buf, std::size_t cap, const Candidate& c) {
            std::size_t used = 0;
            if (c.coro_prelo_n > 0) {
                int n = std::snprintf(buf + used, cap - used, " --coro-prelo %u", c.coro_prelo_n);
                if (n > 0) used += static_cast<std::size_t>(n);
            }
            if (c.needs_heap_stack && used < cap) {
                int n = std::snprintf(buf + used, cap - used, " --heap-stack");
                if (n > 0) used += static_cast<std::size_t>(n);
            }
            return used;
        };

        std::fprintf(stderr, "eligible entry points:\n");
        std::size_t ok = 0;
        for (std::size_t i = 0; i < cands.size(); ++i) {
            if (shadowed[i]) continue;
            const auto& c = cands[i];
            if (!is_eligible(c)) continue;
            const std::uint64_t s = c.entry_va - base_va;
            const std::uint64_t e = c.end_va   - base_va;

            char extras[64] = {0};
            append_extras(extras, sizeof(extras), c);

            std::fprintf(
                stderr,
                "  %s  0x%06llx..0x%06llx  %4llu B, %2zu blocks  --ranges 0x%llx:0x%llx%s\n",
                entry_tag(c),
                static_cast<unsigned long long>(s),
                static_cast<unsigned long long>(e),
                static_cast<unsigned long long>(e - s),
                c.block_count,
                static_cast<unsigned long long>(s),
                static_cast<unsigned long long>(e),
                extras
            );

            ++ok;
        }
        if (ok == 0) std::fprintf(stderr, "  none\n");

        // coroutine candidates: not ret-terminated but otherwise clean
        std::size_t shown_coro = 0;
        for (std::size_t i = 0; i < cands.size(); ++i) {
            if (shadowed[i]) continue;
            const auto& c = cands[i];
            if (!is_coroutine(c)) continue;
            if (shown_coro == 0) std::fprintf(stderr, "\ncoroutine candidates, no ret terminator, requires --coroutines:\n");

            const std::uint64_t s = c.entry_va - base_va;
            const std::uint64_t e = c.end_va   - base_va;

            char extras[64] = {0};
            append_extras(extras, sizeof(extras), c);

            std::fprintf(
                stderr,
                "  %s  0x%06llx..0x%06llx  %4llu B, %2zu blocks  --coroutines --ranges 0x%llx:0x%llx%s\n",
                entry_tag(c),
                static_cast<unsigned long long>(s),
                static_cast<unsigned long long>(e),
                static_cast<unsigned long long>(e - s),
                c.block_count,
                static_cast<unsigned long long>(s),
                static_cast<unsigned long long>(e),
                extras
            );

            ++shown_coro;
        }

        std::size_t shown_near = 0;
        for (std::size_t i = 0; i < cands.size(); ++i) {
            if (shadowed[i]) continue;
            const auto& c = cands[i];
            if (is_acceptable(c)) continue; // already shown above
            if (shown_near == 0) std::fprintf(stderr, "\nnear-miss entry points:\n");
            const std::uint64_t s = c.entry_va - base_va;
            const std::uint64_t e = c.end_va   - base_va;

            std::fprintf(
                stderr,
                "  %s  0x%06llx..0x%06llx  %llu B, %zu blocks  reasons:%s%s%s%s\n",
                entry_tag(c),
                static_cast<unsigned long long>(s),
                static_cast<unsigned long long>(e),
                static_cast<unsigned long long>(e - s),
                c.block_count,
                c.body_len < 5    ? " body<5B" : "",
                !c.has_ret        ? " no-ret-terminated-block" : "",
                !c.contiguous     ? " fragmented-or-mid-fn-data" : "",
                c.external_entries? " native-branches-to-mid-range-bytes" : ""
            );

            ++shown_near;
        }

        std::size_t shown_internal = 0;
        for (std::size_t i = 0; i < cands.size(); ++i) {
            if (!shadowed[i]) continue;
            const auto& c = cands[i];
            if (!is_acceptable(c)) continue;
            if (shown_internal == 0) std::fprintf(stderr, "\ninternal entries, usually loop headers or branch labels inside an earlier function:\n");
            const std::uint64_t s = c.entry_va - base_va;
            const std::uint64_t e = c.end_va   - base_va;

            std::fprintf(
                stderr,
                "  %s  0x%06llx..0x%06llx  %llu B, %zu blocks\n",
                entry_tag(c),
                static_cast<unsigned long long>(s),
                static_cast<unsigned long long>(e),
                static_cast<unsigned long long>(e - s),
                c.block_count
            );

            ++shown_internal;
        }
        std::fprintf(stderr, "\n"
            "note: jmp-entered ranges work like call-entered when the original\n"
            "      control flow is a tail-call pattern. outer caller pushed a\n"
            "      retaddr via call, some intermediate function tail-jmps in,\n"
            "      this range's ret pops the outer retaddr. if the jmp entry\n"
            "      has no caller up the chain, exit_handler's final ret will\n"
            "      pop whatever happens to be at host rsp.\n");
    }

    Format parse_format(const std::string& s) {
        if (s == "raw")                         return Format::Raw;
        if (s == "hex")                         return Format::Hex;
        if (s == "c" || s == "cpp" || s == "h") return Format::C;
        if (s == "py" || s == "python")         return Format::Py;
        if (s == "ps1" || s == "powershell")    return Format::Ps1;
        if (s == "b64" || s == "base64")        return Format::B64;
        if (s == "nasm" || s == "asm")          return Format::Nasm;
        throw mkpivm::Error("unknown --format: " + s + ", expected raw|hex|c|py|ps1|b64|nasm");
    }

    std::string fmt_hex(const std::vector<std::uint8_t>& v) {
        std::string s;
        s.reserve(v.size() * 2 + 1);
        constexpr char d[] = "0123456789abcdef";
        for (auto b : v) { s.push_back(d[b >> 4]); s.push_back(d[b & 0xF]); }
        s.push_back('\n');
        return s;
    }

    std::string fmt_c(const std::vector<std::uint8_t>& v) {
        std::ostringstream os;
        os << "const unsigned int shellcode_len = " << v.size() << ";\n";
        os << "unsigned char shellcode[] = {";

        for (std::size_t i = 0; i < v.size(); ++i) {
            if ((i % 16) == 0) os << "\n    ";
            os << "0x" << "0123456789abcdef"[v[i] >> 4]
                       << "0123456789abcdef"[v[i] & 0xF];
            if (i + 1 != v.size()) os << ", ";
        }

        os << "\n};\n";
        return os.str();
    }

    std::string fmt_py(const std::vector<std::uint8_t>& v) {
        std::ostringstream os;
        os << "shellcode = b\"";

        for (auto b : v) {
            os << "\\x"
               << "0123456789abcdef"[b >> 4]
               << "0123456789abcdef"[b & 0xF];
        }

        os << "\"\n";
        os << "shellcode_len = " << v.size() << "\n";
        return os.str();
    }

    std::string fmt_ps1(const std::vector<std::uint8_t>& v) {
        std::ostringstream os;
        os << "[byte[]] $shellcode = @(";

        for (std::size_t i = 0; i < v.size(); ++i) {
            if ((i % 16) == 0) os << "\n    ";
            os << "0x" << "0123456789abcdef"[v[i] >> 4] << "0123456789abcdef"[v[i] & 0xF];
            if (i + 1 != v.size()) os << ",";
        }

        os << "\n)\n";
        os << "$shellcode_len = " << v.size() << "\n";
        return os.str();
    }

    std::string fmt_b64(const std::vector<std::uint8_t>& v) {
        static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string s;
        s.reserve((v.size() + 2) / 3 * 4 + 1);
        std::size_t i = 0;
        
        for (; i + 3 <= v.size(); i += 3) {
            const std::uint32_t n = (std::uint32_t(v[i])     << 16) |
                                    (std::uint32_t(v[i + 1]) << 8)  |
                                     std::uint32_t(v[i + 2]);
            s.push_back(tbl[(n >> 18) & 63]);
            s.push_back(tbl[(n >> 12) & 63]);
            s.push_back(tbl[(n >> 6) & 63]);
            s.push_back(tbl[n & 63]);
        }

        if (i < v.size()) {
            std::uint32_t n = std::uint32_t(v[i]) << 16;
            if (i + 1 < v.size()) n |= std::uint32_t(v[i + 1]) << 8;
            s.push_back(tbl[(n >> 18) & 63]);
            s.push_back(tbl[(n >> 12) & 63]);
            s.push_back(i + 1 < v.size() ? tbl[(n >> 6) & 63] : '=');
            s.push_back('=');
        }

        s.push_back('\n');
        return s;
    }

    std::string fmt_nasm(const std::vector<std::uint8_t>& v) {
        std::ostringstream os;
        os << "shellcode:\n";

        for (std::size_t i = 0; i < v.size(); i += 16) {
            os << "    db ";
            const std::size_t end = std::min(i + 16, v.size());

            for (std::size_t j = i; j < end; ++j) {
                os << "0x" << "0123456789abcdef"[v[j] >> 4] << "0123456789abcdef"[v[j] & 0xF];
                if (j + 1 != end) os << ", ";
            }

            os << "\n";
        }

        os << "shellcode_len equ $ - shellcode\n";
        return os.str();
    }

    // write either raw bytes or a text-formatted representation to path 
    void emit_output(const std::string& path, Format f, const std::vector<std::uint8_t>& v) {
        const bool to_stdout = path.empty();
        if (f == Format::Raw) {
            #ifdef _WIN32
                if (to_stdout) _setmode(_fileno(stdout), _O_BINARY);
            #endif
                if (to_stdout) {
                    std::fwrite(
                        v.data(),
                        1,
                        v.size(),
                        stdout
                    );
                    std::fflush(stdout);
                }
                else {
                    std::ofstream out(path, std::ios::binary);
                    if (!out) throw mkpivm::Error("cannot open output: " + path);
                    out.write(reinterpret_cast<const char*>(v.data()), static_cast<std::streamsize>(v.size()));
                }
                return;
        }

        std::string text;
        switch (f) {
            case Format::Hex:  text = fmt_hex(v);  break;
            case Format::C:    text = fmt_c(v);    break;
            case Format::Py:   text = fmt_py(v);   break;
            case Format::Ps1:  text = fmt_ps1(v);  break;
            case Format::B64:  text = fmt_b64(v);  break;
            case Format::Nasm: text = fmt_nasm(v); break;
            case Format::Raw:                      break;
        }

        if (to_stdout) {
            std::fwrite(
                text.data(),
                1,
                text.size(),
                stdout
            );
            std::fflush(stdout);
        }
        else {
            std::ofstream out(path, std::ios::binary);
            if (!out) throw mkpivm::Error("cannot open output: " + path);
            out.write(text.data(), static_cast<std::streamsize>(text.size()));
        }
    }
}

int main(int argc, char** argv) {
    try {
        mkpivm::PackageOptions opt;
        opt.seed = static_cast<std::uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count());

        std::string in_path, out_path;
        Format fmt = Format::Raw;
        InputFormat in_fmt_forced = InputFormat::Auto;
        bool scan_mode = false;
        std::string embed_target;
        std::uint32_t embed_at_rva = 0;
        bool embed_at_set = false;
        bool embed_inline = false;

        for (int i = 1; i < argc; ++i) {
            const std::string a = argv[i];
            if (a == "--arch" && i + 1 < argc) {
                const std::string v = argv[++i];
                opt.arch = (v == "x86") ? mkpivm::Arch::X86 : mkpivm::Arch::X64;
            } 
            else if (a == "--seed" && i + 1 < argc) {
                opt.seed = parse_u64(argv[++i]);
            } 
            else if (a == "--ranges" && i + 1 < argc) {
                opt.ranges = parse_ranges(argv[++i]);
            } 
            else if (a == "--coroutines") {
                opt.coroutines_allowed = true;
            } 
            else if (a == "--pack") {
                opt.pack_mode = true;
            }
            else if (a == "--range-leak-nvs") {
                opt.range_leak_nvs = true;
            }
            else if (a == "--coro-prelo" && i + 1 < argc) {
                opt.coro_prelo = static_cast<std::uint32_t>(std::stoul(argv[++i], nullptr, 0));
            }
            else if (a == "--heap-stack") {
                opt.heap_stack = true;
            }
            else if (a == "--embed-into" && i + 1 < argc) {
                embed_target = argv[++i];
            } 
            else if (a == "--at" && i + 1 < argc) {
                embed_at_rva = static_cast<std::uint32_t>(parse_u64(argv[++i]));
                embed_at_set = true;
            } 
            else if (a == "--detour-inline") {
                embed_inline = true;
            } 
            else if (a == "--scan") {
                scan_mode = true;
            } 
            else if ((a == "-o" || a == "--output") && i + 1 < argc) {
                out_path = argv[++i];
            } 
            else if (a == "--format" && i + 1 < argc) {
                fmt = parse_format(argv[++i]);
            } 
            else if (a == "--input-format" && i + 1 < argc) {
                in_fmt_forced = parse_input_format(argv[++i]);
            } 
            else if (a == "--verbose") {
                opt.verbose = true;
            } 
            else if (a == "-h" || a == "--help") {
                print_usage(argv[0]);
                return 0;
            } 
            else if (a.rfind("--", 0) == 0 || (a.size() > 1 && a[0] == '-')) {
                std::fprintf(stderr, "unknown option: %s\n", a.c_str());
                return 2;
            } 
            else if (in_path.empty()) {
                in_path = a;
            } 
            else if (out_path.empty()) {
                out_path = a; // back-compat positional output
            } 
            else {
                std::fprintf(stderr, "extra argument: %s\n", a.c_str());
                return 2;
            }
        }

        if (in_path.empty()) {
            print_usage(argv[0]);
            return 2;
        }

        const char* in_fmt = "raw";
        const auto bytes = decode_input(read_file(in_path), in_fmt_forced, &in_fmt);
        if (opt.verbose) {
            std::fprintf(
                stderr,
                "input: %zu bytes, format %s\n",
                bytes.size(),
                in_fmt
            );
        }

        if (scan_mode) {
            run_scan(bytes, opt.arch, opt.base_va);
            return 0;
        }

        if (!embed_target.empty()) {
            if (!embed_at_set) throw mkpivm::Error("--embed-into requires --at <rva>");
            if (out_path.empty()) throw mkpivm::Error("--embed-into requires -o <output.exe>");

            // input bytes are already a built vm blob, don't re-virtualize.
            mkpivm::EmbedOptions eo;
            eo.target_pe_path = embed_target;
            eo.at_rva         = embed_at_rva;
            eo.spawn_thread   = !embed_inline;
            eo.verbose        = opt.verbose;
            
            mkpivm::Span<std::uint8_t> blob{bytes.data(), bytes.size()};
            auto out = mkpivm::embed_vm_blob(blob, opt.arch, eo);
            std::ofstream of(out_path, std::ios::binary);
            if (!of) throw mkpivm::Error("cannot open output: " + out_path);
            of.write(reinterpret_cast<const char*>(out.patched_pe.data()), static_cast<std::streamsize>(out.patched_pe.size()));
            if (opt.verbose) std::fprintf(stderr, "%s\n", out.stats.c_str());

            std::fprintf(
                stderr,
                "wrote %zu-byte patched pe to %s, vm_blob=%zu B at rva 0x%x\n",
                out.patched_pe.size(),
                out_path.c_str(),
                bytes.size(),
                embed_at_rva
            );

            return 0;
        }

        mkpivm::Span<std::uint8_t> code{bytes.data(), bytes.size()};
        auto res = mkpivm::package_shellcode(code, opt);
        emit_output(out_path, fmt, res.blob);

        if (opt.verbose) std::fprintf(stderr, "%s\n", res.stats.c_str());
        std::fprintf(
            stderr,
            "wrote %zu bytes as %s to %s, seed=0x%llx\n",
            res.blob.size(),
            fmt == Format::Raw ? "raw"
            : fmt == Format::Hex ? "hex"
            : fmt == Format::C ? "c"
            : fmt == Format::Py ? "py"
            : fmt == Format::Ps1 ? "ps1"
            : fmt == Format::B64 ? "b64"
            : "nasm",
            out_path.empty() ? "<stdout>" : out_path.c_str(),
            static_cast<unsigned long long>(opt.seed)
        );

        return 0;
    } 
    catch (const std::exception& ex) {
        std::fprintf(stderr, "error: %s\n", ex.what());
        return 1;
    }
}