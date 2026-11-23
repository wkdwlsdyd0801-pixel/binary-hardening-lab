# binary-hardening-lab

How much do modern Linux exploit mitigations (NX, ASLR/PIE, stack canaries, RELRO, FORTIFY_SOURCE, CET) actually stop classic memory-corruption bugs, and what do they cost? This repo answers both with a reproducible measurement matrix, plus a dependency-free ELF64 `checksec` analyser that agrees with binutils `readelf` on 2,823/2,823 system binaries.

> **Safety:** the programs in `vuln/` are **intentionally vulnerable**. Build and run them only on your own machine or in the provided container. Nothing here targets third-party systems.

## 1. Problem

Mitigation flags are usually discussed as a checklist ("is PIE on?"). The checklist hides two questions that matter when deciding what to ship: *which bug class does each flag stop on its own*, and *what does it cost in size and speed*. Vendor claims and blog posts rarely measure both on the same code with one flag changed at a time.

## 2. Threat model

- **Attacker:** controls the input of a local process (stdin), can read its output, and wants either control-flow hijack or a data-only win (privilege flag flip).
- **Bugs in scope:** stack buffer overflow (`read` past a 16-byte buffer), heap overflow into an adjacent chunk (data-only, glibc chunk header preserved), format string (`%p` leak and `%n` write).
- **Defender:** chooses compiler/linker flags only; source code is unchanged.
- **Out of scope:** kernel exploits, info-leak-assisted ROP chains, hardware attacks, CET enforcement (needs a CET-enabled kernel + glibc, see Limitations).

## 3. Design

- **One-flag-at-a-time matrix.** `build.mk` builds every program under 8 profiles: `none`, then exactly one mitigation on (`nx canary fortify pie relro cet`), then `all`. Every profile spells out the *off* flags too, because Ubuntu's gcc enables PIE, canary, FORTIFY, BIND_NOW and CET by default.
- **Static verification.** Each built binary is checked with `hardenlab.checksec` (pure-Python ELF parser: program headers, dynamic section, symbols, GNU property notes) so a profile can never silently differ from what it claims.
- **Behavioural measurement.** `scripts/measure.py` runs fixed payloads and classifies each run as `ok / exploited / blocked / crash` with a cause (`canary`, `fortify_objsize`, `fortify_percent_n`, `glibc_heap_check`, `segv`).
- **Cost measurement.** `scripts/benchmark.py` compiles a deterministic CPU workload with each profile's flags (read from `build.mk`, never duplicated), times the hot loop *inside* the process, 21 interleaved runs, median + IQR, and verifies every profile prints the same checksum.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the data flow.

## 4. Results

Environment: x86_64, Ubuntu 24.04.5, gcc 13.3.0, `randomize_va_space=2`, seed 0. Raw data in `results/*.csv`.

**What stops what** (`results/mitigation_matrix.csv`, 56 runs):

| Bug / payload | none | nx | canary | fortify | pie | relro | cet | all |
|---|---|---|---|---|---|---|---|---|
| stack overflow, 200 B | crash | crash | **blocked** | **blocked** | crash | crash | crash | **blocked** |
| heap overflow, careful (data-only) | exploited | exploited | exploited | **blocked** | exploited | exploited | exploited | **blocked** |
| heap overflow, sloppy | blocked¹ | blocked¹ | blocked¹ | **blocked** | blocked¹ | blocked¹ | blocked¹ | **blocked** |
| format string `%n` write | crash | crash | crash | **blocked** | crash | crash | crash | **blocked** |
| format string `%p` leak | leaked | leaked | leaked | leaked | leaked | leaked | leaked | leaked |

¹ SIGABRT from glibc's own heap consistency checks on the clobbered chunk header (cause recorded as `abort`) — not a compiler flag.

- The careful heap overflow escalates to `role=admin` under **6 of 8 profiles**; only FORTIFY_SOURCE=3 (object-size check in `__memcpy_chk`) stops it. NX, PIE, canary, RELRO and CET protect control flow, not data.
- FORTIFY also aborts the stack program on *benign* input: `read(fd, buf16, 256)` is a bug in the length argument, caught before any byte overflows.
- No flag stops the `%p` info leak.

**ASLR entropy** (`results/aslr_entropy.csv`, 300 runs/profile, varying address bits): code and data are fixed (**0 bits**) without PIE and get **30 bits** with PIE; heap goes from 18–19 to 30 bits; stack (30) and mmap (29) are randomised regardless.

**Cost** (`results/size_overhead.csv`, `results/runtime_overhead.csv`):

| Profile | code bytes (workload) | hot-loop time (median of 21) |
|---|---|---|
| canary | +18.7% | +1.0% |
| fortify | +3.4% | **+14.1%** |
| pie | +3.4% | +0.04% |
| relro | 0% (file +21%, page alignment) | +1.1% |
| cet | +14.0% | +0.2% |
| all | +40.0% | +16.5% |

Start-up time differs by <2% for every profile, inside the run-to-run IQR (~15%), so BIND_NOW's eager binding is not measurable on a small binary.

**Real-world adoption** (`results/system_checksec.csv`, 1,687 ELF files in Ubuntu 24.04): of 916 executables, NX 100%, PIE 98.1%, CET IBT+SHSTK 98.1%, canary 89.8%, Full RELRO 86.0%, FORTIFY 83.2%. Shared libraries lag on Full RELRO (63.2%) and FORTIFY (68.0%).

## 5. Limitations

- One machine, one compiler, a 2-vCPU shared VM; percentages under ~1% are within noise.
- CET is *compiled in* and detected, but not *enforced*: shadow-stack enforcement needs a CPU exposing `shstk`/`ibt`, kernel ≥ 6.6 and glibc support; the measurement VM's CPU exposes neither. Its row shows cost, not protection.
- The `libc` ASLR row reads 0 bits for non-PIE profiles because `(void *)printf` in a non-PIE binary resolves to its canonical PLT stub, not libc. The real libc base is randomised; the probe under-reports it.
- Bugs are minimal teaching programs; real exploits combine a leak (which nothing here stops) with a write primitive.
- Runtime checks assume x86_64 glibc chunk layout and skip on other architectures.

## Run

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q                        # 39 tests; compiles binaries with known flags
make -f build.mk                           # -> build/<profile>/<program>
python -m hardenlab.checksec /bin/ls --json
python scripts/measure.py --samples 300    # -> results/mitigation_matrix.csv, aslr_entropy.csv
python scripts/benchmark.py                # -> results/size_overhead.csv, runtime_overhead.csv, system_checksec.csv
python scripts/crosscheck_readelf.py /usr/bin/*
```

One-command reproducible run (Ubuntu 24.04 + gcc 13, unprivileged user, vulnerable binaries stay in the container):

```bash
docker build -t binary-hardening-lab . && docker run --rm binary-hardening-lab
```

The build file is named `build.mk` rather than `Makefile`, hence `make -f build.mk`. CI (`.github/workflows/ci.yml`) runs the tests, a fixed-seed measurement smoke run and the Docker run on every push.

## License

MIT, see [LICENSE](LICENSE).
