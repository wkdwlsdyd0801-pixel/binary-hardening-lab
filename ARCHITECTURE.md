# Architecture

```
            vuln/*.c ──┐                  bench/workload.c
                       │                         │
   build.mk (8 profiles: none nx canary fortify pie relro cet all)
       │  make -f build.mk            │  make -f build.mk flags P=<profile>
       ▼                              ▼
  build/<profile>/<program>     build/bench/<profile>/workload
       │                              │
       ├──► hardenlab.checksec ◄──────┤   (static: is the profile what it claims?)
       │        ▲                     │
       │   hardenlab.elf              │
       ▼                              ▼
  scripts/measure.py            scripts/benchmark.py
   ├ mitigation_matrix.csv       ├ size_overhead.csv
   └ aslr_entropy.csv            ├ runtime_overhead.csv
                                 └ system_checksec.csv  (survey of /usr/bin, /usr/sbin, /usr/lib)
```

## Components

**`hardenlab/elf.py`** — stdlib-only ELF64 reader. Parses the file header, program headers, section headers, `.dynamic`, `.dynsym`/`.symtab` names and `NT_GNU_PROPERTY_TYPE_0` notes. Falls back to `PT_DYNAMIC` + `DT_STRTAB` when section headers are stripped (`sstrip`). It never executes or maps the binary, so it is safe on untrusted input; malformed files raise `ElfError` instead of crashing.

**`hardenlab/checksec.py`** — turns parsed metadata into verdicts:

| Verdict | Evidence |
|---|---|
| NX | `PT_GNU_STACK` present and not `PF_X` |
| PIE | `e_type == ET_DYN` |
| RELRO | `PT_GNU_RELRO` → partial; plus `DT_BIND_NOW` / `DF_BIND_NOW` / `DF_1_NOW` → full |
| Canary | `__stack_chk_fail` / `__stack_chk_guard` symbols |
| FORTIFY | imported `__*_chk` functions (listed) |
| CET / BTI / PAC | GNU property note feature bits |

Correctness is checked two ways: unit tests on binaries compiled with known flags, and `scripts/crosscheck_readelf.py`, which compares every verdict to `readelf` output.

**`build.mk`** — the single source of truth for compiler flags. Each profile differs from `none` in exactly one mitigation and states the *off* flags explicitly, because distro compilers turn most mitigations on by default. `flags P=<profile>` prints a profile's flags so Python never duplicates them.

**`scripts/measure.py`** — runs each program × profile × payload, classifies by exit status and stderr signature (SIGABRT + "stack smashing" → `canary`, "buffer overflow detected" → `fortify_objsize`, "%n in writable segment" → `fortify_percent_n`, SIGSEGV → `crash`, exit 3 + `role=admin` → `exploited`). Also samples `aslr_probe` N times per profile and counts varying address bits per region.

**`scripts/benchmark.py`** — size (executable `PT_LOAD` bytes via our parser, not just file size, which is dominated by page padding), runtime (in-process `clock_gettime` timing of a deterministic loop, interleaved seeded run order, median/IQR, checksum equality across profiles), and a distro-wide checksec survey.

## Reproducibility

- Seeds (`--seed`, default 0) fix payload padding and benchmark run order; every CSV starts with a `#` header recording seed, arch, OS, gcc version and `randomize_va_space`.
- Tests build into a temporary directory (`BUILD=`) so they never reuse stale binaries.
- Built binaries (`build/`) are git-ignored; only source and result CSVs are committed.

## Design decisions

- **Pure Python, no `pyelftools`/`lief`:** the parser is small enough to audit and has no supply-chain surface; it is also the thing being taught.
- **Data-only heap bug:** keeps the demo independent of glibc allocator internals that change between versions, and shows the case control-flow mitigations cannot cover.
- **Classify, don't exploit:** the harness only reports whether corruption was stopped, crashed or flipped a flag; it contains no shellcode or ROP.
