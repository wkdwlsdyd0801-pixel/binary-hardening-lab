#!/usr/bin/env python3
"""Measurement harness: how each mitigation profile changes the outcome of a bug.

Two experiments, both written to CSV under results/:

1. Mitigation matrix (results/mitigation_matrix.csv)
   Run every vuln/*.c program, built under every build.mk profile, against a
   fixed set of crafted payloads, and classify what happened:
     - ok        exited 0, the program ran normally
     - exploited exited non-zero in the program's own "attack worked" way
                 (heap_overflow prints role=admin and exits 3)
     - blocked   killed by SIGABRT, i.e. a mitigation caught the bug on purpose
                 (stack canary, FORTIFY object-size check, glibc heap integrity)
     - crash     killed by SIGSEGV, the corruption derailed control flow and the
                 process died instead of being hijacked
   The payloads are deterministic, so with --seed fixed the whole table is
   reproducible; the seed only matters for the optional random padding below and
   is recorded in the CSV header comment for provenance.

2. ASLR entropy (results/aslr_entropy.csv)
   Run aslr_probe N times per profile and, for each memory region, count how
   many address bits actually vary across runs. That bit count is the practical
   ASLR entropy: it is ~0 for code/data without PIE (load address is fixed) and
   jumps to ~28-30 bits once PIE/ASLR randomise the region. Shannon entropy over
   the observed values is reported too, but it is capped at log2(N), so the
   varying-bit count is the number to trust.

Pure stdlib; nothing here targets anything outside this project's own binaries.
"""
from __future__ import annotations

import argparse
import csv
import platform
import random
import signal
import struct
import subprocess
import sys
from math import log2
from pathlib import Path

# Run from the repo root regardless of the caller's cwd.
ROOT = Path(__file__).resolve().parent.parent

# -signal.SIG* is how subprocess reports a child killed by that signal.
SIGSEGV, SIGABRT = -signal.SIGSEGV, -signal.SIGABRT

# The crafted heap payload from the test suite: a correct chunk header
# (size 0x20 | PREV_INUSE == 0x21) keeps glibc's free() checks happy so that
# only the adjacent `role` string is corrupted -- a "careful", data-only
# overflow that no code-pointer defence can see.
HEAP_CAREFUL = b"A" * 24 + struct.pack("<Q", 0x21) + b"admin\0"

# program -> list of (payload_name, bytes). One benign case plus the bug's
# interesting inputs, matching what the C comments and tests describe.
PAYLOADS: dict[str, list[tuple[str, bytes]]] = {
    "stack_overflow": [
        ("benign", b"hi"),
        ("overflow", b"A" * 200),  # smashes the saved return address
    ],
    "heap_overflow": [
        ("benign", b"bob\0"),
        ("careful", HEAP_CAREFUL),  # data-only privilege escalation
        ("sloppy", b"A" * 60),      # also clobbers the chunk header
    ],
    "format_string": [
        ("leak", b"%p.%p.%p\n"),    # read primitive: %p walks the stack
        ("write", b"%n%n\n"),       # write primitive: %n stores byte counts
    ],
}

# Substrings in stderr that identify *which* mitigation fired on a SIGABRT.
# Checked in order, so the more specific message wins.
ABORT_CAUSES = [
    ("stack smashing detected", "canary"),
    ("buffer overflow detected", "fortify_objsize"),
    ("%n in writable", "fortify_percent_n"),
    ("free(): ", "glibc_heap_check"),
    ("malloc(): ", "glibc_heap_check"),
    ("corrupted", "glibc_heap_check"),
]

# Per-program marker that an exploit actually achieved its goal (not just a
# non-zero exit). Keyed by program; value is (expected_returncode, stdout_mark).
EXPLOIT_MARK = {
    "heap_overflow": (3, b"role=admin"),
}

# The regions aslr_probe prints, in the fixed order the C program uses.
REGIONS = ["code", "data", "stack", "heap", "libc", "mmap"]


def profiles(build_mk: Path) -> list[str]:
    # Ask build.mk for the canonical profile list instead of hardcoding it,
    # so the two stay in sync if a profile is ever added or removed.
    out = subprocess.run(["make", "-s", "-f", str(build_mk), "list"],
                         cwd=ROOT, capture_output=True, text=True, check=True)
    return out.stdout.split()


def build_matrix(build_dir: Path) -> None:
    # Compile every program under every profile. build.mk is incremental, so a
    # re-run is cheap; -j speeds up the first build.
    subprocess.run(["make", "-s", "-f", "build.mk", f"BUILD={build_dir}", "-j4"],
                   cwd=ROOT, check=True)


def classify(program: str, rc: int, stdout: bytes, stderr: bytes) -> tuple[str, str]:
    """Map a process result to (outcome, cause). Pure, so it is unit-testable."""
    if rc == 0:
        return "ok", ""
    if rc == SIGABRT:
        for needle, cause in ABORT_CAUSES:
            if needle.encode() in stderr:
                return "blocked", cause
        return "blocked", "abort"  # aborted, but message not recognised
    if rc == SIGSEGV:
        return "crash", "segv"
    # Positive non-zero exit: did the program's own exploit path succeed?
    want = EXPLOIT_MARK.get(program)
    if want and rc == want[0] and want[1] in stdout:
        return "exploited", "priv_escalation"
    return "exit", f"rc={rc}"


def run_matrix(build_dir: Path, profs: list[str]) -> list[dict]:
    rows = []
    for prog, payloads in PAYLOADS.items():
        for prof in profs:
            binary = build_dir / prof / prog
            if not binary.exists():
                continue
            for pname, data in payloads:
                r = subprocess.run([str(binary)], input=data,
                                   capture_output=True, timeout=10)
                outcome, cause = classify(prog, r.returncode, r.stdout, r.stderr)
                rows.append({
                    "program": prog,
                    "profile": prof,
                    "payload": pname,
                    "returncode": r.returncode,
                    "outcome": outcome,
                    "cause": cause,
                    # First line of stdout, trimmed, for a human-readable trace.
                    "stdout": r.stdout.decode(errors="replace").splitlines()[0][:60]
                    if r.stdout else "",
                })
    return rows


def entropy_bits(values: list[int]) -> tuple[int, float]:
    """Return (varying_bits, shannon_bits) for a sample of addresses.

    varying_bits: number of bit positions that are not identical across all
      samples -- the width of the randomised field, the honest ASLR estimate.
    shannon_bits: -sum p*log2(p) over distinct values, capped at log2(len) by
      construction, so it under-reports once entropy exceeds log2(sample size).
    """
    if not values:
        return 0, 0.0
    # A bit "varies" if XOR-ing every sample against the first ever sets it.
    mask = 0
    first = values[0]
    for v in values:
        mask |= v ^ first
    varying = bin(mask).count("1")
    # Shannon entropy over the empirical distribution of observed addresses.
    n = len(values)
    counts: dict[int, int] = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    shannon = -sum((c / n) * log2(c / n) for c in counts.values())
    return varying, shannon or 0.0  # fold -0.0 (single distinct value) to 0.0


def run_aslr(build_dir: Path, profs: list[str], samples: int) -> list[dict]:
    rows = []
    # Measure every profile that built aslr_probe; PIE/all randomise code+data,
    # the rest leave them fixed, which is exactly the contrast we want to show.
    for prof in profs:
        binary = build_dir / prof / "aslr_probe"
        if not binary.exists():
            continue
        region_values: dict[str, list[int]] = {r: [] for r in REGIONS}
        for _ in range(samples):
            out = subprocess.run([str(binary)], capture_output=True,
                                 text=True, timeout=10).stdout.strip()
            # Line is "code=0x.. data=0x.. ..."; parse into the fixed regions.
            for kv in out.split():
                k, _, v = kv.partition("=")
                if k in region_values:
                    region_values[k].append(int(v, 16))
        for region in REGIONS:
            vals = region_values[region]
            varying, shannon = entropy_bits(vals)
            rows.append({
                "profile": prof,
                "region": region,
                "samples": len(vals),
                "distinct": len(set(vals)),
                "varying_bits": varying,
                "shannon_bits": round(shannon, 2),
            })
    return rows


def write_csv(path: Path, rows: list[dict], header_comment: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as fh:
        fh.write(f"# {header_comment}\n")  # provenance line, ignored by csv readers that skip '#'
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--build-dir", default="build", type=Path,
                    help="where build.mk output lives (default: build)")
    ap.add_argument("--samples", type=int, default=200,
                    help="aslr_probe runs per profile for the entropy estimate")
    ap.add_argument("--seed", type=int, default=0,
                    help="RNG seed; recorded for reproducibility (payloads are fixed)")
    ap.add_argument("--out", default="results", type=Path,
                    help="output directory for the CSV files")
    args = ap.parse_args(argv)

    # Fix the seed so any random choice (and the run's provenance) is reproducible.
    random.seed(args.seed)

    if platform.machine() != "x86_64":
        print("warning: payload offsets assume x86_64; outcomes may differ here",
              file=sys.stderr)

    build_dir = (ROOT / args.build_dir).resolve() if not args.build_dir.is_absolute() \
        else args.build_dir
    build_matrix(build_dir)
    profs = profiles(ROOT / "build.mk")

    # Record the kernel ASLR setting: entropy is meaningless if it is turned off.
    try:
        aslr = Path("/proc/sys/kernel/randomize_va_space").read_text().strip()
    except OSError:
        aslr = "unknown"

    matrix = run_matrix(build_dir, profs)
    aslr_rows = run_aslr(build_dir, profs, args.samples)

    prov = (f"seed={args.seed} arch={platform.machine()} "
            f"randomize_va_space={aslr} gcc={_gcc_version()}")
    out = ROOT / args.out if not args.out.is_absolute() else args.out
    write_csv(out / "mitigation_matrix.csv", matrix, prov)
    write_csv(out / "aslr_entropy.csv", aslr_rows,
              f"{prov} samples={args.samples}")

    # Human-readable summary so a run is informative without opening the CSVs.
    print(f"mitigation matrix: {len(matrix)} rows -> {out/'mitigation_matrix.csv'}")
    for row in matrix:
        print(f"  {row['program']:<14} {row['profile']:<7} {row['payload']:<8} "
              f"-> {row['outcome']:<9} {row['cause']}")
    print(f"\naslr entropy ({args.samples} samples, randomize_va_space={aslr}) "
          f"-> {out/'aslr_entropy.csv'}")
    for row in aslr_rows:
        print(f"  {row['profile']:<7} {row['region']:<6} "
              f"varying_bits={row['varying_bits']:<3} "
              f"distinct={row['distinct']:<4} shannon={row['shannon_bits']}")
    return 0


def _gcc_version() -> str:
    try:
        out = subprocess.run(["gcc", "-dumpfullversion"], capture_output=True,
                             text=True, check=True).stdout.strip()
        return out or "unknown"
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


if __name__ == "__main__":
    raise SystemExit(main())
