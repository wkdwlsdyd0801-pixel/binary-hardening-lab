#!/usr/bin/env python3
"""Benchmark: what each mitigation costs, and how hardened a real distro is.

Three experiments, all written to CSV under results/:

1. Size overhead (results/size_overhead.csv)
   For every program (vuln/*.c + bench/workload.c) under every build.mk profile,
   record the file size and the executable-code bytes (sum of PT_LOAD segments
   with PF_X, read with our own ELF parser), and the % change versus `none`.
   WHY code bytes and not just file size: file size is dominated by page
   alignment padding, so a 40-byte canary epilogue can look like 0% or +4 KiB.

2. Runtime overhead (results/runtime_overhead.csv)
   bench/workload.c is compiled with each profile's exact flags (asked from
   build.mk, never duplicated here) and run --runs times:
     - loop:    hot-loop nanoseconds measured *inside* the process, so
                fork/exec/loader noise does not drown a ~1% effect;
     - startup: wall time of a whole process with 0 iterations, which is where
                RELRO's BIND_NOW (eager symbol resolution) pays its cost.
   Median and IQR are reported; medians are robust to the occasional noisy run
   on a shared machine. Profiles are interleaved in a seeded random order
   rather than run one after another, so slow drift (thermal, other tenants)
   hits all of them equally.
   Every profile must print the same checksum -- a mitigation that changed the
   program's result would be a bug, so the run fails loudly if they differ.

3. Distro hardening survey (results/system_checksec.csv)
   Run hardenlab.checksec over every ELF64 in the given directories (default
   /usr/bin /usr/sbin /usr/lib/<arch>-linux-gnu) and report what fraction has
   each mitigation. Shared libraries are counted separately because they are
   always "PIE" (ET_DYN) and would inflate the executable numbers.

Pure stdlib. Everything runs on binaries built from this repo or already
installed on the measuring machine; nothing touches a remote system.
"""
from __future__ import annotations

import argparse
import csv
import os
import platform
import random
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))  # import hardenlab without installing it

from hardenlab import checksec, elf  # noqa: E402

BENCH_SRC = ROOT / "bench" / "workload.c"


# ---------------------------------------------------------------- helpers ---

def make(*args: str) -> str:
    out = subprocess.run(["make", "-s", "-f", "build.mk", *args], cwd=ROOT,
                         capture_output=True, text=True, check=True)
    return out.stdout.strip()


def profiles() -> list[str]:
    return make("list").split()


def profile_flags(profile: str) -> list[str]:
    # build.mk is the single source of truth for the mitigation matrix.
    return make("flags", f"P={profile}").split()


def code_bytes(path: Path) -> int:
    """Bytes in executable PT_LOAD segments: the code a mitigation actually grows."""
    f = elf.parse(path)
    return sum(p.p_filesz for p in f.segments(elf.PT_LOAD) if p.p_flags & elf.PF_X)


def pct(value: float, base: float) -> float:
    # Relative change vs the `none` baseline; 0 baseline would be a broken build.
    return round((value - base) / base * 100.0, 2) if base else 0.0


def quartiles(xs: list[float]) -> tuple[float, float, float]:
    q = statistics.quantiles(xs, n=4, method="inclusive")
    return q[0], statistics.median(xs), q[2]


# ------------------------------------------------------- 1. size overhead ---

def build_all(build_dir: Path, profs: list[str]) -> dict[str, Path]:
    """Build vuln/ via build.mk and the workload with each profile's flags."""
    subprocess.run(["make", "-s", "-f", "build.mk", f"BUILD={build_dir}", "-j4"],
                   cwd=ROOT, check=True)
    cc = os.environ.get("CC", "gcc")
    out = {}
    for prof in profs:
        dst = build_dir / prof / "workload"
        dst.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([cc, *profile_flags(prof), str(BENCH_SRC), "-o", str(dst)],
                       check=True)
        out[prof] = dst
    return out


def size_rows(build_dir: Path, profs: list[str]) -> list[dict]:
    programs = sorted({p.stem for p in (ROOT / "vuln").glob("*.c")} | {"workload"})
    rows = []
    for prog in programs:
        base = build_dir / "none" / prog
        if not base.exists():
            continue
        b_file, b_code = base.stat().st_size, code_bytes(base)
        for prof in profs:
            path = build_dir / prof / prog
            if not path.exists():
                continue
            fsz, csz = path.stat().st_size, code_bytes(path)
            rows.append({"program": prog, "profile": prof,
                         "file_bytes": fsz, "file_pct": pct(fsz, b_file),
                         "code_bytes": csz, "code_pct": pct(csz, b_code)})
    return rows


# ---------------------------------------------------- 2. runtime overhead ---

def parse_workload(stdout: str) -> tuple[int, int]:
    """'checksum=<n> ns=<t>' -> (checksum, ns). Pure, so it is unit-testable."""
    kv = dict(part.split("=", 1) for part in stdout.split())
    return int(kv["checksum"]), int(kv["ns"])


def runtime_rows(binaries: dict[str, Path], runs: int, iters: int,
                 startup_runs: int, seed: int) -> list[dict]:
    rng = random.Random(seed)
    loop_ns: dict[str, list[int]] = {p: [] for p in binaries}
    start_us: dict[str, list[float]] = {p: [] for p in binaries}
    checksums: dict[str, set[int]] = {p: set() for p in binaries}
    order = list(binaries)

    for prof, path in binaries.items():  # one warm-up each: page cache, CPU freq
        subprocess.run([str(path), "1000"], capture_output=True, check=True)

    for _ in range(runs):
        rng.shuffle(order)  # interleave profiles so drift is shared fairly
        for prof in order:
            r = subprocess.run([str(binaries[prof]), str(iters)],
                               capture_output=True, text=True, check=True)
            cs, ns = parse_workload(r.stdout)
            checksums[prof].add(cs)
            loop_ns[prof].append(ns)

    for _ in range(startup_runs):
        rng.shuffle(order)
        for prof in order:
            t0 = time.perf_counter_ns()
            subprocess.run([str(binaries[prof]), "0"], capture_output=True, check=True)
            start_us[prof].append((time.perf_counter_ns() - t0) / 1000.0)

    # A mitigation must never change the computed result.
    all_cs = set().union(*checksums.values())
    if len(all_cs) != 1:
        raise SystemExit(f"checksum mismatch across profiles: {checksums}")

    base_loop = statistics.median(loop_ns["none"])
    base_start = statistics.median(start_us["none"])
    rows = []
    for prof in binaries:
        lq1, lmed, lq3 = quartiles(loop_ns[prof])
        sq1, smed, sq3 = quartiles(start_us[prof])
        rows.append({
            "profile": prof,
            "runs": runs, "iterations": iters,
            "loop_ms_median": round(lmed / 1e6, 3),
            "loop_ms_iqr": round((lq3 - lq1) / 1e6, 3),
            "loop_pct": pct(lmed, base_loop),
            "ns_per_iter": round(lmed / iters, 2),
            "startup_us_median": round(smed, 1),
            "startup_us_iqr": round(sq3 - sq1, 1),
            "startup_pct": pct(smed, base_start),
        })
    return rows


# --------------------------------------------------- 3. distro hardening ---

def iter_elves(dirs: list[Path]):
    """Yield (path, report) for every parseable ELF64 file; skip the rest."""
    seen = set()
    for d in dirs:
        if not d.is_dir():
            continue
        for p in sorted(d.iterdir()):
            try:
                real = p.resolve()
                if real in seen or not real.is_file():
                    continue  # symlinks to the same binary count once
                seen.add(real)
                with real.open("rb") as fh:
                    if fh.read(4) != elf.ELF_MAGIC:
                        continue  # shell/python scripts live in /usr/bin too
                yield real, checksec.analyse(str(real))
            except (OSError, elf.ElfError):
                continue  # 32-bit, big-endian, unreadable: out of scope


def survey_rows(dirs: list[Path]) -> list[dict]:
    groups: dict[str, list[dict]] = {"executable": [], "shared_library": []}
    for path, rep in iter_elves(dirs):
        f = elf.parse(path)
        # Relocatable objects (crt1.o, *.o in lib dirs) are never loaded as-is,
        # so their missing PT_GNU_STACK etc. would be false "unhardened" hits.
        if f.e_type not in (elf.ET_EXEC, elf.ET_DYN):
            continue
        # A PIE executable has PT_INTERP (asks for the dynamic loader); a plain
        # .so does not. Static ET_EXEC binaries also count as executables.
        is_exe = f.e_type == elf.ET_EXEC or bool(f.segments(elf.PT_INTERP))
        groups["executable" if is_exe else "shared_library"].append(rep)

    metrics = {
        "nx": lambda r: r["nx"],
        "pie": lambda r: r["pie"],
        "relro_full": lambda r: r["relro"] == "full",
        "relro_partial": lambda r: r["relro"] == "partial",
        "relro_none": lambda r: r["relro"] == "none",
        "canary": lambda r: r["canary"],
        "fortify": lambda r: r["fortify"],
        # IBT and SHSTK must both be set for CET to be enforceable.
        "cet_ibt_shstk": lambda r: bool(r["cfi"].get("ibt") and r["cfi"].get("shstk")),
    }
    rows = []
    for group, reps in groups.items():
        n = len(reps)
        for name, test in metrics.items():
            k = sum(1 for r in reps if test(r))
            rows.append({"group": group, "metric": name, "count": k, "total": n,
                         "percent": round(k / n * 100.0, 1) if n else 0.0})
    return rows


# ------------------------------------------------------------------- main ---

def write_csv(path: Path, rows: list[dict], header_comment: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as fh:
        fh.write(f"# {header_comment}\n")
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def os_name() -> str:
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip('"').replace(" ", "_")
    except OSError:
        pass
    return platform.system()


def gcc_version() -> str:
    try:
        return subprocess.run(["gcc", "-dumpfullversion"], capture_output=True,
                              text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--build-dir", default="build/bench", type=Path)
    ap.add_argument("--out", default="results", type=Path)
    ap.add_argument("--runs", type=int, default=21, help="timed runs per profile")
    ap.add_argument("--iterations", type=int, default=2_000_000)
    ap.add_argument("--startup-runs", type=int, default=200)
    ap.add_argument("--seed", type=int, default=0, help="shuffles run order")
    # The multiarch lib dir gives the shared-library half of the survey real
    # numbers; it is simply skipped on systems where it does not exist.
    libdir = Path("/usr/lib") / f"{platform.machine()}-linux-gnu"
    ap.add_argument("--survey", nargs="*", type=Path,
                    default=[Path("/usr/bin"), Path("/usr/sbin"), libdir],
                    help="directories to survey (pass none to skip)")
    args = ap.parse_args(argv)

    build_dir = args.build_dir if args.build_dir.is_absolute() else ROOT / args.build_dir
    out = args.out if args.out.is_absolute() else ROOT / args.out
    profs = profiles()
    prov = (f"seed={args.seed} arch={platform.machine()} os={os_name()} "
            f"gcc={gcc_version()} cpus={os.cpu_count()}")

    binaries = build_all(build_dir, profs)

    sizes = size_rows(build_dir, profs)
    write_csv(out / "size_overhead.csv", sizes, prov)
    print("size overhead vs none (code bytes):")
    for r in sizes:
        if r["program"] == "workload":
            print(f"  {r['profile']:<8} code={r['code_bytes']:>6} ({r['code_pct']:+.2f}%) "
                  f"file={r['file_bytes']:>6} ({r['file_pct']:+.2f}%)")

    rt = runtime_rows(binaries, args.runs, args.iterations, args.startup_runs, args.seed)
    write_csv(out / "runtime_overhead.csv", rt,
              f"{prov} runs={args.runs} iterations={args.iterations} "
              f"startup_runs={args.startup_runs}")
    print("\nruntime overhead vs none (median):")
    for r in rt:
        print(f"  {r['profile']:<8} loop={r['loop_ms_median']:>8.2f} ms ({r['loop_pct']:+6.2f}%, "
              f"IQR {r['loop_ms_iqr']:.2f})  startup={r['startup_us_median']:>7.1f} us "
              f"({r['startup_pct']:+6.2f}%)")

    if args.survey:
        sv = survey_rows(args.survey)
        write_csv(out / "system_checksec.csv", sv,
                  f"{prov} dirs={':'.join(str(d) for d in args.survey)}")
        print("\ndistro hardening survey:")
        for r in sv:
            print(f"  {r['group']:<15} {r['metric']:<14} {r['count']:>5}/{r['total']:<5} "
                  f"{r['percent']:5.1f}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
