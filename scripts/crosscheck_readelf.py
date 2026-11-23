"""Cross-check hardenlab.checksec against binutils `readelf` on many binaries.

WHY: a home-grown ELF parser is only trustworthy if it agrees with the
reference tool. This derives the same verdicts independently from
`readelf` text output and reports every disagreement.

Usage: python scripts/crosscheck_readelf.py /usr/bin/* [--limit N]
Exit code 1 if any field disagrees.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from hardenlab import checksec, elf  # noqa: E402


def readelf_verdicts(path: str) -> dict:
    def run(*flags):
        return subprocess.run(["readelf", "-W", *flags, path], capture_output=True,
                              text=True, check=False).stdout

    hdr, ph, dyn, notes = run("-h"), run("-l"), run("-d"), run("-n")
    syms = run("-s", "--dyn-syms")
    # GNU_STACK line ends with "<flags> 0x<align>"; an E flag = executable stack.
    stack = re.search(r"GNU_STACK(?:\s+0x[0-9a-f]+){5}\s+([RWE ]+?)\s+0x", ph)
    relro = "GNU_RELRO" in ph
    # BIND_NOW can appear as its own tag, in FLAGS ("BIND_NOW") or FLAGS_1 ("NOW").
    bind_now = bool(re.search(r"\(BIND_NOW\)|\(FLAGS\).*\bBIND_NOW\b|\(FLAGS_1\).*\bNOW\b", dyn))
    # Symbol lines end with "name[@VERSION] [(n)]"; capture just the name.
    chk = set(re.findall(r"\s(__\w+_chk)(?:@\S*)?(?:\s+\(\d+\))?\s*$", syms, re.M))
    machine = re.search(r"Machine:\s+(.+)", hdr).group(1)
    ref = {
        "nx": bool(stack) and "E" not in stack.group(1),
        "pie": re.search(r"Type:\s+(\w+)", hdr).group(1) == "DYN",
        "relro": "none" if not relro else ("full" if bind_now else "partial"),
        "canary": bool(re.search(r"\s__stack_chk_(fail|guard)(@\S*)?(\s+\(\d+\))?\s*$", syms, re.M)),
        "fortify": bool(chk - checksec.CANARY_SYMBOLS),
    }
    # CET bits only make sense on x86-64; readelf prints them in the property note.
    if "X86-64" in machine:
        feat = re.search(r"x86 feature: (.*)", notes)
        ref["ibt"] = bool(feat) and "IBT" in feat.group(1)
        ref["shstk"] = bool(feat) and "SHSTK" in feat.group(1)
    return ref


def compare(path: str) -> list[str]:
    ours = checksec.analyse(path)
    ours.update(ours.pop("cfi"))
    ref = readelf_verdicts(path)
    return [f"{path}: {k} ours={ours[k]} readelf={v}" for k, v in ref.items()
            if k in ours and ours[k] != v]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args(argv)
    checked, diffs = 0, []
    for p in a.paths:
        try:
            # Skip scripts and other non-ELF64 files quietly; only real ELF64 counts.
            elf.parse(p)
        except (OSError, elf.ElfError):
            continue
        diffs += compare(p)
        checked += 1
        if a.limit and checked >= a.limit:
            break
    if diffs:
        print("\n".join(diffs))
    print(f"checked={checked} disagreements={len(diffs)}")
    return 1 if diffs else 0


if __name__ == "__main__":
    raise SystemExit(main())
