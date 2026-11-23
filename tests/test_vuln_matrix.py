"""Build vuln/*.c under every build.mk profile and check two things:
1. the static analyser sees exactly the mitigations the profile enabled;
2. each mitigation stops (or fails to stop) the bug the way the C comments claim.
Runtime checks assume x86_64 glibc chunk layout, so they skip elsewhere.
"""
import platform
import shutil
import signal
import struct
import subprocess
from pathlib import Path

import pytest

from hardenlab import checksec

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(
    shutil.which("gcc") is None or shutil.which("make") is None,
    reason="gcc/make not available")
X86_64 = platform.machine() == "x86_64"
runtime = pytest.mark.skipif(not X86_64, reason="payload offsets assume x86_64")

SIGSEGV, SIGABRT = -signal.SIGSEGV, -signal.SIGABRT
# Correct chunk header (size 0x20 | PREV_INUSE) keeps glibc's free() checks
# happy, so only the data in `role` changes: a "careful" overflow.
HEAP_PAYLOAD = b"A" * 24 + struct.pack("<Q", 0x21) + b"admin\0"


@pytest.fixture(scope="module")
def build(tmp_path_factory):
    out = tmp_path_factory.mktemp("matrix")
    subprocess.run(["make", "-s", "-f", "build.mk", f"BUILD={out}", "-j4"],
                   cwd=ROOT, check=True)
    return out


def run(build, profile, prog, data):
    return subprocess.run([str(build / profile / prog)], input=data,
                          capture_output=True, timeout=10)


# profile -> the single mitigation it switches on (relative to `none`)
EXPECT = {
    "none": {},
    "nx": {"nx": True},
    "canary": {"canary": True},
    "fortify": {"fortify": True},
    "pie": {"pie": True},
    "relro": {"relro": "full"},
    "all": {"nx": True, "canary": True, "fortify": True, "pie": True, "relro": "full"},
}
BASE = {"nx": False, "canary": False, "fortify": False, "pie": False, "relro": "none"}


@pytest.mark.parametrize("profile", sorted(EXPECT))
def test_profile_flags_match_checksec(build, profile):
    r = checksec.analyse(str(build / profile / "stack_overflow"))
    want = {**BASE, **EXPECT[profile]}
    assert {k: r[k] for k in want} == want


@pytest.mark.skipif(not X86_64, reason="CET is x86-only")
def test_cet_profile(build):
    assert checksec.analyse(str(build / "cet" / "stack_overflow"))["cfi"] == {"ibt": True, "shstk": True}
    assert checksec.analyse(str(build / "none" / "stack_overflow"))["cfi"] == {"ibt": False, "shstk": False}


@runtime
def test_stack_overflow(build):
    assert run(build, "none", "stack_overflow", b"hi").returncode == 0
    # No canary: the smashed return address is used -> crash.
    assert run(build, "none", "stack_overflow", b"A" * 200).returncode == SIGSEGV
    # Canary: detected before `ret`, controlled abort.
    r = run(build, "canary", "stack_overflow", b"A" * 200)
    assert r.returncode == SIGABRT and b"stack smashing" in r.stderr
    # NX alone does not stop the overwrite, only code execution on the stack.
    assert run(build, "nx", "stack_overflow", b"A" * 200).returncode == SIGSEGV
    # FORTIFY rejects read(buf, 256) into 16 bytes even for benign input.
    assert run(build, "fortify", "stack_overflow", b"hi").returncode == SIGABRT


@runtime
def test_heap_overflow_data_only(build):
    assert run(build, "none", "heap_overflow", b"bob\0").returncode == 0
    # Careful overflow: privilege escalation under every code-pointer defence.
    for p in ("none", "nx", "canary", "pie", "relro", "cet"):
        r = run(build, p, "heap_overflow", HEAP_PAYLOAD)
        assert r.returncode == 3 and b"role=admin" in r.stdout, p
    # Only FORTIFY (object-size check on memcpy) catches it.
    for p in ("fortify", "all"):
        r = run(build, p, "heap_overflow", HEAP_PAYLOAD)
        assert r.returncode == SIGABRT and b"buffer overflow detected" in r.stderr, p
    # Sloppy overflow: glibc's free() integrity check notices afterwards.
    assert run(build, "none", "heap_overflow", b"A" * 60).returncode == SIGABRT


@runtime
def test_format_string(build):
    # %p leak works everywhere -- FORTIFY does not block reads.
    for p in ("none", "all"):
        r = run(build, p, "format_string", b"%p.%p.%p\n")
        assert r.returncode == 0 and b"0x" in r.stdout, p
    # %n with a writable format string is refused by __printf_chk.
    r = run(build, "fortify", "format_string", b"%n%n\n")
    assert r.returncode == SIGABRT and b"%n in writable" in r.stderr


def test_aslr_probe_prints_all_regions(build):
    out = run(build, "all", "aslr_probe", b"").stdout.decode()
    keys = [kv.split("=")[0] for kv in out.split()]
    assert keys == ["code", "data", "stack", "heap", "libc", "mmap"]
