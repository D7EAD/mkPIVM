<p align="center">
  <img src="./images/mkpivm.png" width="30%" height="30%">
  <br>
  <a href="./research/mkpivm-research.pdf">Read</a> the research paper.
</p>

**mkPIVM** is a polymorphic position-independent shellcode virtualizer for Windows x86 and x64.

Feed it raw shellcode. It emits another raw blob: a small virtual machine that interprets a lifted, encrypted-at-rest version of your original instructions. The output is itself position-independent code and runs anywhere the original shellcode would, from a remote-thread loader to a code cave detour. Every per-seed knob varies independently: cipher family, register slot layout, opcode-to-handler permutation, dispatcher topology, junk-gadget pattern, IR obfuscation insertion points. Two builds from the same input share fewer than a hundred coincidental bytes out of tens of kilobytes.

Why: native shellcode is signature-trivial. Wrapping it in a per-instance VM with a per-instance cipher leaves nothing useful at rest, and lifting the instructions to bytecode puts another wall between disk bytes and any disassembler that knows what x86 looks like. As far as I can tell from a literature sweep, no public tool ships exactly this pipeline: raw PIC in, raw polymorphic VM PIC out. So, I mentioned that in the research paper it demanded. To be honest, if I am right about no one having done this (publicly) before, and I am pretty confident, I am surprised. _Nonetheless, enjoy._

## Quick start

```
mkpivm.exe shellcode.bin --arch x64 -o out.bin
```

Your PIVM is hot and ready. That's the simplest path. Several other modes vary how aggressively the original instructions get virtualized, whether the output is a standalone blob or a patched PE, and whether the lift runs at all.

# Showcase

I got the receipts. You can see a video of mkPIVM in action below, fully virtualizing a Meterpreter stager (vanilla btw), injecting into explorer.exe, and us capturing a callback. Of course this is just an example, and mkPIVM can be applied to much more, assuming the instructions in the shellcode are supported. If they aren't, make an Issue, send me the shellcode, I got you.

See it [here](https://github.com/D7EAD/mkPIVM/raw/refs/heads/main/media/mkpivm-showcase.mp4). Hosted in ./media, can't embed sadly.

Here is the VirusTotal report for that exact virtualized sample (as of 05/19/2026).

<img src="./images/vt.png">

...and the packed version, not even virtualized, notably higher entropy.

<img src="./images/packed.png">

There was careful attention paid to the entropy telemetry of the output of this tool, which results in shellcode of entropy less than typical Windows WinAPI DLLs (outside of packing mode), such as ntdll.dll or kernel32.dll. The entropy comparison is about...

| File | Bytes | Entropy |
|------|-------|---------|
| `p_m64.bin` | 3,969 | **7.1181** |
| `msvcrt.dll` | 699,888 | 6.5319 |
| `wininet.dll` | 2,724,528 | 6.4934 |
| `shell32.dll` | 7,839,992 | 6.3639 |
| `kernel32.dll` | 836,232 | 6.3597 |
| `crypt32.dll` | 1,538,632 | 6.3010 |
| `rpcrt4.dll` | 1,162,672 | 6.2405 |
| `ntdll.dll` | 2,522,104 | 6.1934 |
| `v.bin` | 29,229 | **6.0442** |

## Modes at a glance

| Mode | Flags | What changes |
|------|-------|--------------|
| Default | none | Lift the whole input. Everything virtualized. |
| Packer | `--pack` | Don't lift. Wrap input as encrypted data, decrypt at runtime, jump in. |
| Hybrid | `--ranges A:B,...` | Lift only the chosen byte ranges. Rest stays native. |
| Stacked | `--pack --ranges A:B` | Build the hybrid blob, then pack-wrap it. |
| Detour | `--embed-into PE --at RVA` | Take a pre-built blob, embed into a PE, patch a jmp at the chosen RVA. |
| Scan | `--scan` | Print eligible `--ranges` candidates from the input's CFG, then exit. |

Every mode honors `--seed`, `--arch`, `--input-format`, and `--format`. See the per-mode sections below for the build pipeline and the runtime flow.

## Default virtualization

The lifter walks the whole CFG and lowers every instruction to a custom IR. The IR goes through two obfuscation passes, then through codecs that encode each insn into the per-seed bytecode shape. The block table, handler table, and data island are encrypted with the same per-byte stream cipher as the bytecode. At runtime the prologue decrypts those three regions in place and the dispatcher loop fetches bytecode bytes one at a time, decrypting and dispatching to a handler that does the work.

### Build pipeline

Steps the build performs to turn raw shellcode into the emitted virtualized blob, end to end.

```mermaid
flowchart TB
    A[shellcode.bin] --> CFG[CFGBuilder: identify blocks via Zydis disasm + recursive descent]
    SEED[seed u64] --> VMC[VMConfig: pick cipher kind, reg perm, opcode map, dispatcher topology]
    CFG --> LIFT[LifterRegistry: lower each block to IR]
    LIFT --> RBT[resolve_branch_targets: link BR_CC/BR/CALL_VM/LOOP_DEC to target_block_id; synthesize JMP_NATIVE block for any out-of-range jcc]
    RBT --> OBF1[obfuscate_ir_dead_inject: 20% per insn-gap, IMM Tmp2/Tmp3 random]
    OBF1 --> OBF2[obfuscate_ir_opaque_predicates: 25% per block, split block with IMM Tmp3=0 + TEST + BR_CC NZ random_block, never taken]
    OBF2 --> ENC[BytecodeBuilder: each codec emits its variant for this seed]
    ENC --> CDATA[compact data island: bytes not covered by any CFG block]
    CDATA --> PROMO[promote LEA-fixup target VAs back into data island if CFG put them in code]
    ENC --> BTAB[build block table: va_off to bytecode_off pairs]
    PROMO --> ECIPH[encrypt data island with cipher_init]
    BTAB --> ECIPH2[encrypt block table with cipher_init]
    ENC --> ECIPH3[encrypt bytecode per-block with cipher_init reset at each block start]
    VMC --> STUB[VMCodeGen::emit_full: prologue, state init, dispatcher tail, handlers, sbox_inv, exit handler]
    STUB --> HTAB[handler table: 256 entries, each a 32-bit offset from handler_base; encrypted at rest]
    ECIPH --> ASM[finalize: stub + trampolines + sbox_inv + bytecode + data island + block table]
    ECIPH2 --> ASM
    ECIPH3 --> ASM
    HTAB --> ASM
    ASM --> OUT[out.bin]
```

### Runtime flow

What the emitted blob does when the host loader calls into it at byte 0, from prologue through dispatcher fetches and the various termination paths.

```mermaid
flowchart TB
    ENTRY[blob entry at byte 0] --> PROL[prologue: push NV regs in seed-shuffled order, pushfq, allocate frame, lea state_ptr]
    PROL --> SI[emit_state_init body, gated by init_flag byte]
    SI --> ZERO[zero VM regs via seed-permuted xor source]
    ZERO --> CINIT[set cipher_state register, store cipher_init at cipher_extra+48]
    CINIT --> SBOX[copy sbox_inv table from blob to cipher_extra+256]
    SBOX --> NONCE[derive runtime nonce: rdtsc XOR cipher_init, store at cipher_extra+80]
    NONCE --> DDI[decrypt data island in place via emit_fetch_byte_dec loop]
    DDI --> DBT[decrypt block table in place]
    DBT --> DHT[decrypt handler table in place]
    DHT --> XHT[XOR each handler table entry with the runtime nonce so memory image is process-variant]
    XHT --> SET_INIT[set init_flag = 1 to gate subsequent vm_entry invocations]
    SET_INIT --> DISP[dispatcher tail]
    DISP --> FB[fetch one byte via emit_fetch_byte_dec, decrypts using cipher_state]
    FB --> HLU["load handler offset: mov scratch_b_32, [handler_base + op*4]"]
    HLU --> UXOR["xor scratch_b_32, [state_ptr + cipher_extra + runtime_nonce_off]"]
    UXOR --> SXD[movsxd to 64 bit, lea handler_addr = handler_base + offset, jmp handler]
    SXD --> H[handler body: fetch operands via stream cipher, perform op, advance state]
    H --> NEXT{terminator?}
    NEXT -- no --> DISP
    NEXT -- BR/BR_CC --> CRESET[cipher_reset to cipher_init, advance ip to target block]
    CRESET --> DISP
    NEXT -- CALL_VM --> CRESET
    NEXT -- JMP_NATIVE imm --> MARSH["marshal VM regs to host regs, rsp = VM_RSP, jmp [target_slot]"]
    NEXT -- CALL_NATIVE --> PUSHTR[push trampoline addr to VM_RSP, marshal, jmp target]
    NEXT -- RET_VM --> POPSS[pop shadow stack, jmp to popped trampoline addr]
    POPSS --> CRESET
    NEXT -- exit_handler reached --> EPI[restore NV regs, ret to caller of vm_entry]
```

The runtime nonce trick is the key anti-memory-scan move: the handler table sits in memory XOR'd with a value derived from `rdtsc XOR cipher_init`, so two processes loading the same blob hold byte-different handler tables. The dispatcher unmasks at lookup time with one extra XOR.

## Packer mode: `--pack`

The opposite tradeoff. The lifter does not run. The original shellcode goes into the data island encrypted, and the IR is a single synthetic `JMP_NATIVE imm=0`. The prologue intentionally skips the data-island decrypt that default mode runs eagerly. Instead, the first time the lone JMP_NATIVE handler fires, it decrypts the data island in place, sets a marker byte, then transfers control to byte 0 of the now-plaintext shellcode. The shellcode runs natively from there.

Works on any shellcode, regardless of lifter coverage. Useful for stageless cobalt, exotic syscall-heavy payloads, anything too large or weird to virtualize. Loses the per-instruction virtualization defense but keeps the full per-seed VM polymorphism on the wrapper.

### Build pipeline

How `--pack` wraps the original shellcode as an encrypted data island behind a one-instruction synthetic IR program.

```mermaid
flowchart TB
    A[shellcode.bin] --> SKIP[skip CFG build, skip lift]
    SEED[seed u64] --> VMC[VMConfig polymorphism axes as in default mode]
    SKIP --> SYN[synthesize 1-insn IRProgram: one block with JMP_NATIVE Imm 0 Width Q]
    SYN --> SETF[VMConfig::set_pack_mode true, set_data_island_size shellcode.size]
    SETF --> ENC[BytecodeBuilder encodes the 1 insn into ~35 bytes]
    ENC --> CDATA[data island = entire shellcode bytes verbatim]
    CDATA --> ECIPH[encrypt shellcode bytes with cipher_init as the data island]
    ENC --> ECIPH2[encrypt bytecode + block table + handler table]
    VMC --> STUB[VMCodeGen::emit_full]
    STUB --> FLAG[data_island_init_flag byte starts at 0 because pack_mode true]
    STUB --> ASM[finalize layout]
    ECIPH --> ASM
    ECIPH2 --> ASM
    FLAG --> ASM
    ASM --> OUT[out.bin]
```

### Runtime flow

What the pack wrapper does on first entry, including the gated lazy decrypt of the data island and the single synthetic JMP_NATIVE that hands control to the now-plaintext shellcode.

```mermaid
flowchart TB
    ENTRY[blob entry] --> PROL[prologue + state init]
    PROL --> SKIP_DI[skip data island decrypt because data_island_size gated on pack_mode false at build]
    SKIP_DI --> DBT[decrypt block table in place]
    DBT --> DHT[decrypt handler table in place + runtime nonce XOR]
    DHT --> DISP[dispatcher fetches first opcode = JMP_NATIVE]
    DISP --> NH[emit_native_handler entry]
    NH --> GATE{data_island_init_flag == 0?}
    GATE -- yes --> SAVE[save cipher_state and ip to kPreDecryptCsOff/IpOff slots]
    SAVE --> RESET[reset cipher_state to cipher_init]
    RESET --> LOOP[decrypt data island in place byte by byte]
    LOOP --> RESTORE[restore cipher_state and ip from saved slots]
    RESTORE --> SETFLAG[set data_island_init_flag = 1]
    GATE -- no --> CONT[skip the decrypt body]
    SETFLAG --> CONT
    CONT --> FETCH_TGT[fetch JMP_NATIVE operand: tag = 0, imm = 0]
    FETCH_TGT --> COMPUTE[target = data_island_base + imm = start of decrypted shellcode]
    COMPUTE --> MARSH[marshal all VM regs to host regs, rsp = VM_RSP seeded with exit_handler]
    MARSH --> JMP["jmp [target_slot]"]
    JMP --> NATIVE[original shellcode runs natively]
    NATIVE --> RET{shellcode does ret?}
    RET -- yes --> POPSS[ret pops exit_handler from VM shadow stack]
    POPSS --> EPI[exit_handler restores NV regs, rets to original caller]
    RET -- ExitProcess --> DEAD[process terminates]
```

The deferred data-island decrypt is pack-mode-only. In default and hybrid mode the lifted code does VM LOAD/STORE on data-island bytes mid-execution and needs them plaintext from the start, so the prologue handles it eagerly. In pack mode there is exactly one consumer of the data island, the native escape after the synthetic JMP_NATIVE, so the decrypt can wait until then.

## Hybrid mode: `--ranges A:B,C:D`

Targeted virtualization. Pick byte ranges in the input that should be lifted. Everything else stays as the original native bytes in the output. At each range start the lifter patches a 5-byte `jmp rel32` to a `vm_entry_K` stub appended after the native shellcode region. External native code may only re-enter a lifted range through the patched start byte. Mid-range bytes are int3-filled, so any native branch that targets a mid-range byte is rejected at scan time. Lifted code that exits a range to bytes outside it becomes `JMP_NATIVE` or `CALL_NATIVE`.

Use `--scan` first to find eligible candidates. Scan classifies ranges with gaps, with no `ret`-terminated block, with body shorter than 5 bytes, or with external native branches into mid-range bytes as near-miss rather than eligible.

### Build pipeline

How `--ranges` lifts only the chosen byte ranges and patches the native shellcode in place so control redirects into the appended VM entry stubs.

```mermaid
flowchart TB
    A[shellcode.bin] --> RP[parse_ranges from --ranges flag]
    RP --> CFG[CFGBuilder with set_lifted_ranges restriction]
    CFG --> LIFT[lift_program: only blocks whose start_va is inside any range]
    LIFT --> XCG[branches/calls leaving the range become JMP_NATIVE/CALL_NATIVE]
    XCG --> OBF[IR obfuscation passes same as default]
    OBF --> ENC[encode bytecode]
    ENC --> BTAB[block table for RET_VM lookup]
    SEED[seed u64] --> VMC[VMConfig]
    VMC --> STUB[VMCodeGen::emit_range_mode: one vm_entry_K per range + dispatcher + handlers]
    STUB --> NSEC[start with verbatim copy of the native shellcode bytes]
    NSEC --> PATCH[at each range start, write 5-byte jmp rel32 to vm_entry_K]
    PATCH --> INT3[fill remaining bytes of the displaced run with int3]
    INT3 --> APPEND[append: VM stub + sbox_inv + bytecode + data island + block table]
    APPEND --> OUT[out.bin]
```

### Runtime flow

Control flow through a mixed native-and-VM blob, including the entry into VM dispatch when native code hits a patched range start and the native-escape paths used when lifted code branches back out.

```mermaid
flowchart TB
    ENTRY[blob byte 0 = native shellcode prologue] --> NAT[native shellcode runs]
    NAT --> HIT{control reaches a patched range start?}
    HIT -- no --> NAT
    HIT -- yes --> JMP[jmp rel32 to vm_entry_K]
    JMP --> RPROL[range prologue: push NV regs, allocate frame, lea state_ptr]
    RPROL --> MARSHIN[marshal host volatile regs to VM slots, NV regs preserved by Win64 ABI]
    MARSHIN --> SI[state init gated by init_flag for first-time decrypts]
    SI --> DISP[dispatcher loop]
    DISP --> HND[handler]
    HND --> NXT{terminator?}
    NXT -- BR/BR_CC inside range --> DISP
    NXT -- range ret reached --> CLEANUP[restore NV regs, pop frame, ret pops native retaddr from host stack]
    NXT -- JMP_NATIVE to byte outside range --> MIDEXIT[mid-exec cleanup: overwrite caller retaddr slot with target, jmp to exit_handler]
    NXT -- CALL_NATIVE to API --> APITAIL[push trampoline addr to VM_RSP, jmp resolved API]
    CLEANUP --> NAT
    MIDEXIT --> EH[exit_handler unwinds NV pushes, ret lands at the target we wrote]
    EH --> NAT
    APITAIL --> APIRET[API rets to trampoline in stub which resumes VM dispatch]
    APIRET --> DISP
```

Coroutine-style ranges, the ones with no `ret` that exit via a tail-jmp, are documented via `--coroutines` for `--scan` output. The flag does not change codegen at present. Range mode is best fit for self-contained leaf functions. Helper functions that depend on a specific caller-supplied register state cannot be lifted standalone; the API ends up called with garbage args.

## Stacked mode: `--pack --ranges A:B,C:D`

Run the hybrid build, then pack-wrap the result. The outer VM decrypts the inner hybrid blob in place and jumps to byte 0 of it. From there execution proceeds exactly like standalone hybrid mode, except the entire blob including the chosen-range bytecode is encrypted at rest. The two layers compose cleanly because the inner blob is a self-contained PIC region.

### Build pipeline

How stacked mode recursively invokes the packager: an inner `--ranges` build first, then an outer `--pack` wrap of that build.

```mermaid
flowchart TB
    A[shellcode.bin] --> INNER[invoke package_shellcode recursively in range-only mode]
    INNER --> RBLOB[range-mode bytes in memory]
    RBLOB --> WRAP[invoke package_shellcode again in pack-only mode with RBLOB as input]
    WRAP --> OUT[out.bin: outer pack VM wrapping the inner range-mode blob]
```

### Runtime flow

How the outer pack VM hands control to the inner range-mode VM, each running on its own independent VMState frame.

```mermaid
flowchart TB
    E[blob entry] --> OPROL[outer pack prologue + state init]
    OPROL --> ODISP[outer dispatcher fetches synthetic JMP_NATIVE]
    ODISP --> LAZY[lazy decrypt of inner range-mode blob via deferred data-island decrypt]
    LAZY --> JN[outer JMP_NATIVE imm 0 sets target = inner blob byte 0]
    JN --> INAT[inner native shellcode runs]
    INAT --> IHIT{inner patched range start hit?}
    IHIT -- yes --> IVM[inner range vm_entry_K]
    IHIT -- no --> INAT
    IVM --> IRDISP[inner dispatcher loop, separate VMState frame]
    IRDISP --> INAT
```

The inner VM and outer VM share no state. They are two independent VMs that happen to live in the same blob. The outer one's only job is to gate the inner one behind a decryption layer.

## Detour mode: `--embed-into target.exe --at RVA`

Different shape from the others. Input is raw shellcode, conventionally a VM blob already emitted by mkPIVM in another mode, though any PIC bytes will work. Output is a patched PE.

The tool parses `target.exe`, locates the chosen RVA in an executable section, disassembles enough instructions there to cover 5 bytes, refuses if the displaced run contains RIP-relative addressing or relative control flow that cannot survive being moved, then adds a fresh RWX section containing a wrapper plus the VM blob. The wrapper preserves caller state, transfers to the VM blob, restores state, executes the displaced original bytes, and jumps back to the byte after the patch. A 5-byte `jmp rel32` at the chosen RVA points at the wrapper.

Two sub-modes for how the wrapper transfers to the VM:

### Threaded sub-mode, the default

Two diagrams follow. The first is the build-time PE patching pipeline that injects the wrapper section, fixes up references, and writes the 5-byte jmp at the chosen RVA. The second is the runtime control flow when the host process eventually reaches that RVA.

```mermaid
flowchart TB
    BLOB[vm_blob.bin pre-built from any other mode] --> READ[read target.exe bytes]
    TGT[target.exe] --> READ
    READ --> PEHDR[parse DOS header, NT headers, sections, OptionalHeader, BASERELOC dir]
    PEHDR --> ARCHCHK[arch from PE32/PE32+ magic must match blob arch]
    ARCHCHK --> LOC[locate RVA inside an executable section]
    LOC --> DA[Zydis disassemble at RVA, accumulate insns until total length >= 5]
    DA --> VALID{any displaced insn has RIP-relative mem operand or is a rel32 branch?}
    VALID -- yes --> FAIL[error, pick a different RVA]
    VALID -- no --> IATSCAN[scan IMAGE_DIRECTORY_ENTRY_IMPORT for kernel32!CreateThread]
    IATSCAN --> IATFOUND{found?}
    IATFOUND -- no --> FAIL2[error, suggest --detour-inline or different target]
    IATFOUND -- yes --> EMITW[emit threaded wrapper bytes]
    EMITW --> APPEND[concatenate wrapper + vm_blob into new section content]
    APPEND --> ARCHBR{arch?}
    ARCHBR -- x64 --> X64FIX[fix wrapper rel32s: lea r8 to vm_blob; call qword ptr rip+iat_disp32]
    ARCHBR -- x86 --> X86FIX[fix wrapper abs32s: push vm_blob_va; call dword ptr iat_va; then append combined IMAGE_BASE_RELOCATION table with new HIGHLOW entries for those abs32s]
    X64FIX --> RJMP[compute jmp_rel32 from wrapper-tail back to RVA + displaced_len]
    X86FIX --> RJMP
    RJMP --> SEC[allocate next aligned VA + raw offset, write IMAGE_SECTION_HEADER with RWX + CNT_CODE]
    SEC --> BUMP[bump NumberOfSections, SizeOfImage, zero CheckSum]
    BUMP --> X86RELOC{x86?}
    X86RELOC -- yes --> RDIR[update DataDirectory BASERELOC to new combined table]
    X86RELOC -- no --> WJ[write 5-byte jmp rel32 at RVA, NOP-fill remaining displaced bytes]
    RDIR --> WJ
    WJ --> WRITE[serialize patched bytes to output path]
    WRITE --> OUT[patched.exe]
```

```mermaid
flowchart TB
    HOST[host main reaches patched RVA] --> RJMP[jmp rel32 to wrapper in new section]
    RJMP --> PUSH[pushfq, push all volatile regs and rbp]
    PUSH --> SAVE_RSP[mov rbp, rsp; and rsp, -16; sub rsp, 0x38 for shadow + spill alignment]
    SAVE_RSP --> ARGS[xor ecx,ecx; xor edx,edx; lea r8, vm_blob_rel32; xor r9d,r9d; spill 0 at rsp+0x20, 0 at rsp+0x28]
    ARGS --> CT["call qword ptr [rip + CreateThread_iat_disp32]"]
    CT --> WTHREAD[worker thread starts running vm_blob]
    CT --> REST[mov rsp, rbp; pop volatiles; popfq]
    REST --> DISP[execute the displaced original bytes verbatim]
    DISP --> RJMP2[jmp rel32 back to RVA + N_displaced]
    RJMP2 --> HOST_CONT[host main continues normally]
    WTHREAD --> VMBODY[vm_blob runs concurrently: stager beacons, mbox shows dialog, whatever]
```

The threaded sub-mode is the right shape for stagers and beacons. Host main never blocks. The worker thread inherits whatever lifecycle the payload needs. If the payload calls `ExitProcess`, the whole process dies, but for a non-terminating payload like every C2 beacon, the host runs forever in parallel with it.

### Inline sub-mode: `--detour-inline`

Same wrapper structure but the wrapper does a direct `call vm_blob` instead of `CreateThread`. Host main thread blocks until the VM returns. Useful when the target lacks `CreateThread` in its IAT, or as a fallback when the threaded base-reloc path cannot apply against a particular target.

```mermaid
flowchart TB
    HOST[host main reaches patched RVA] --> RJMP[jmp rel32 to wrapper]
    RJMP --> SAVE[save flags + volatile regs + align]
    SAVE --> CALL[call rel32 vm_blob synchronously]
    CALL --> BLOCK[host main thread blocks here for the duration]
    BLOCK --> RET{vm_blob returns?}
    RET -- via ret --> REST[restore rsp, pop volatiles, popfq]
    RET -- via ExitProcess in payload --> DEAD[process terminates, no further code runs]
    REST --> DISP[execute displaced original bytes]
    DISP --> RJMP2[jmp rel32 back to RVA + N_displaced]
    RJMP2 --> HOST_CONT[host continues]
```

## Scan mode: `--scan`

No output file. Builds the CFG from the input shellcode and prints `--ranges` candidates to stderr. Each candidate is classified as eligible, coroutine, near-miss, or internal, where internal means shadowed by a larger eligible candidate that already covers it. Use this to pick range arguments before invoking the tool again in hybrid mode.

```mermaid
flowchart TB
    INP[shellcode.bin] --> CFGB[CFGBuilder + recursive descent over the whole input]
    CFGB --> ITER[for each block that is a call_target or jmp_target]
    ITER --> BFS[BFS the reachable subgraph from this entry]
    BFS --> SPAN[compute min_va..max_va span]
    SPAN --> CONT_CHK{every byte in span belongs to a visited block or to a known insn boundary?}
    CONT_CHK -- yes --> RET_CHK{any visited block ends with ret?}
    CONT_CHK -- no --> NM1[near-miss: fragmented or mid-fn data]
    RET_CHK -- yes --> EXT_CHK{any non-visited block has a successor pointing inside the span?}
    RET_CHK -- no --> CORO[coroutine candidate, no ret terminator]
    EXT_CHK -- yes --> NM2[near-miss: native branches to mid-range bytes]
    EXT_CHK -- no --> SIZE_CHK{span >= 5 bytes for the entry patch?}
    SIZE_CHK -- yes --> ELIGIBLE[eligible: prints with --ranges hint]
    SIZE_CHK -- no --> NM3[near-miss: body too short]
    ELIGIBLE --> DEDUP[shadow dedupe: drop entries whose reachable set is fully contained in an earlier eligible's reachable set]
    CORO --> DEDUP
    NM1 --> DEDUP
    NM2 --> DEDUP
    NM3 --> DEDUP
    DEDUP --> PRINT[stderr table sorted by category]
    PRINT --> END[exit 0]
```

## Polymorphism axes per seed

Listed roughly in order of how much they affect the static signature.

* Cipher family. One of ARX, LcgSub, SBoxAdd, FeistelByte. Picks both the bytecode encryption used at build time and the inline decrypt emitted in the dispatcher fetch path. Encrypt and decrypt match by construction.
* Register slot layout. The VMState contains `reg_count` slots, sized 24 to 32 per seed. The 16 architectural GPRs plus 4 Tmp regs get a fresh permutation of slot indices each seed.
* Opcode-to-handler mapping. Each codec family is assigned a random opcode byte each seed. The 256-entry handler table indexes by opcode; the encoded bytecode references the mapped opcodes.
* Dispatcher topology. Threaded or central, picked per seed.
* Prologue self-locate strategy. `call $+5; pop`, `lea reg, [rip+0]`, or a jmp/call shuffle.
* Handler register temporaries. BR_CC handler permutes its 6 temporary roles across the volatile pool. Store handler does the same.
* Junk gadget density. 0 to 3, controls inter-handler garbage emission.
* IR obfuscation pass decisions. Dead-IR injection and opaque predicates each use their own sub-RNG so their decisions are deterministic per seed without disturbing other axes.
* Bytecode encryption initial state. Random 64-bit per seed.

## Tested payloads

This tool was validated against several Cobalt Strike, MSF, Sliver, and numerous other shellcode samples.

## Build

Requires Visual Studio 2022, CMake 3.21 or newer, and vcpkg. The CMake project pulls Zydis and fmt through vcpkg's manifest mode.

```
cmake -S . -B build
cmake --build build --config Release --target mkpivm
```

## Known limits

* Range mode for cobalt stagers does not work as a standalone leaf. The stager's helper functions depend on caller-supplied register state that the runner does not provide. Full virtualization or `--pack` are the routes that actually beacon.
* x86 threaded detour requires the target to either lack ASLR or accept added base relocation entries, which the tool emits when present. If the target's BASERELOC data dir is malformed or absent, the tool falls back to inline mode.
* The lifter does not currently cover SSE/AVX register moves, atomics, CMPXCHG, RDMSR, or privileged instructions. Pack mode is the workaround for shellcodes using those.
* Authenticode signatures on `--embed-into` output are invalidated. The PE checksum is zeroed.
* Output blobs require RWX at runtime because in-place decryption writes back to the blob's own pages. Most loaders that run shellcode allocate RWX anyway. There is no plan to move to RX-only because the trade buys RX at the cost of a PEB walk and a `VirtualAlloc` call, which is probably a worse signature than the RWX page it replaces.
* Virtualizing stageless payloads via default mode is not supported yet, as they are horribly complicated to wrap in the VM; prefer `--pack + --ranges`.

# Notes
* This project is largely proof-of-concept research. If it is well-received, I will extend it as requested and welcome contribution. However, it seemed stable for the tested samples.
* If your shellcode doesn't work, and you don't want to place it in an Issue, then unfortunately I can't help you. This was tested on Sliver, Cobalt Strike 4.12, MSF, Havoc, and a few other undisclosed samples.
* In my testing, injection of the VM into live processes worked fine. However, when it comes to embedding into PEs, this was not tested with commercial software like MS Word, only synthetic tests, but it probably works. If not, will fix.
* As of 5/20/2026, it appears the repo is being swarmed with bots. So, that's wonderful. Please ignore all blank Github accounts.

# Contributing
This is some cool shit, get real. If you want to contribute new ideas, fix your own bugs, submit Issues for me to fix, so on and so forth, go for it.
