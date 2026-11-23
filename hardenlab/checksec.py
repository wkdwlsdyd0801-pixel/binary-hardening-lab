"""checksec-style mitigation report for ELF64 binaries.

Reports NX, PIE, RELRO (none/partial/full), stack canary, FORTIFY_SOURCE
and control-flow protection (x86 CET IBT/SHSTK, AArch64 BTI/PAC). Every
verdict is derived from static metadata only, so it is safe to run on
untrusted binaries: nothing is executed or loaded.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import elf

# Symbols that only exist when -fstack-protector instrumented a function:
# dynamic binaries import __stack_chk_fail, static ones also link the guard.
CANARY_SYMBOLS = {"__stack_chk_fail", "__stack_chk_guard", "__stack_chk_fail_local"}


def check_nx(f: elf.ElfFile) -> bool:
    # No PT_GNU_STACK means the loader falls back to an executable stack
    # on most architectures, so treat "missing" as NX disabled.
    stacks = f.segments(elf.PT_GNU_STACK)
    return bool(stacks) and not (stacks[0].p_flags & elf.PF_X)


def check_pie(f: elf.ElfFile) -> bool:
    # ET_DYN is randomised by ASLR whether it is a PIE executable or a
    # shared library, which is what matters for exploitation (checksec
    # reports both as PIE).
    return f.e_type == elf.ET_DYN


def check_relro(f: elf.ElfFile) -> str:
    # PT_GNU_RELRO protects .init_array/.dynamic etc., but the GOT stays
    # writable for lazy binding ("partial"). Only when the loader resolves
    # everything at start-up (BIND_NOW) can the GOT be made read-only too,
    # which kills GOT-overwrite attacks ("full").
    if not f.segments(elf.PT_GNU_RELRO):
        return "none"
    dyn = f.dynamic()
    tags = {t for t, _ in dyn}
    flags = {t: v for t, v in dyn}
    bind_now = (elf.DT_BIND_NOW in tags
                or flags.get(elf.DT_FLAGS, 0) & elf.DF_BIND_NOW
                or flags.get(elf.DT_FLAGS_1, 0) & elf.DF_1_NOW)
    return "full" if bind_now else "partial"


def check_canary(names: set[str]) -> bool:
    return bool(names & CANARY_SYMBOLS)


def fortified_functions(names: set[str]) -> list[str]:
    # _FORTIFY_SOURCE rewrites memcpy/strcpy/printf... into __*_chk
    # variants that know the destination size. __stack_chk_fail also ends
    # in _chk-ish naming but belongs to the canary, so exclude it.
    out = set()
    for n in names:
        base = n.split("@", 1)[0]
        if base.startswith("__") and base.endswith("_chk") and base not in CANARY_SYMBOLS:
            out.add(base)
    return sorted(out)


def check_cfi(f: elf.ElfFile) -> dict:
    # CET/BTI only work if *every* object linked in was built with it, so
    # the linker ANDs the bits; a single missing bit means "off" at runtime.
    props = f.gnu_properties()
    if f.e_machine == elf.EM_AARCH64:
        bits = props.get(elf.GNU_PROPERTY_AARCH64_FEATURE_1_AND, 0)
        return {"bti": bool(bits & elf.GNU_PROPERTY_AARCH64_FEATURE_1_BTI),
                "pac": bool(bits & elf.GNU_PROPERTY_AARCH64_FEATURE_1_PAC)}
    bits = props.get(elf.GNU_PROPERTY_X86_FEATURE_1_AND, 0)
    return {"ibt": bool(bits & elf.GNU_PROPERTY_X86_FEATURE_1_IBT),
            "shstk": bool(bits & elf.GNU_PROPERTY_X86_FEATURE_1_SHSTK)}


def analyse(path: str) -> dict:
    f = elf.parse(path)
    names = f.symbol_names()
    fortified = fortified_functions(names)
    return {
        "file": path,
        "nx": check_nx(f),
        "pie": check_pie(f),
        "relro": check_relro(f),
        "canary": check_canary(names),
        "fortify": bool(fortified),
        "fortified": fortified,
        "cfi": check_cfi(f),
    }


def _fmt(r: dict) -> str:
    cfi = " ".join(f"{k.upper()}={v}" for k, v in r["cfi"].items())
    return (f"{r['file']}: NX={r['nx']} PIE={r['pie']} RELRO={r['relro']} "
            f"CANARY={r['canary']} FORTIFY={r['fortify']}({len(r['fortified'])}) {cfi}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="ELF64 exploit-mitigation report")
    ap.add_argument("binaries", nargs="+")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    rc = 0
    reports = []
    for b in args.binaries:
        try:
            reports.append(analyse(b))
        except (OSError, elf.ElfError) as e:
            # Keep going on bad input so one broken file does not hide
            # results for the rest of a directory scan.
            print(f"{b}: error: {e}", file=sys.stderr)
            rc = 1
    if args.json:
        print(json.dumps(reports, indent=2))
    else:
        for r in reports:
            print(_fmt(r))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
