"""Compile tiny programs with known flags and check the analyser agrees."""
import shutil
import struct
import subprocess

import pytest

from hardenlab import checksec, elf

pytestmark = pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc not available")

SRC = "int main(void){return 0;}\n"
# Copies an unbounded argv string into a fixed stack buffer, so
# -fstack-protector inserts a canary and -D_FORTIFY_SOURCE=2 rewrites
# strcpy to __strcpy_chk (it knows sizeof(buf) but not the source length).
SRC_BUF = r"""
#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
    char buf[16];
    strcpy(buf, argv[argc - 1]);
    printf("%s\n", buf);
    return 0;
}
"""


def build(tmp_path, *flags, src=SRC):
    s = tmp_path / "t.c"
    s.write_text(src)
    out = tmp_path / "t.bin"
    subprocess.run(["gcc", *flags, str(s), "-o", str(out)], check=True)
    return str(out)


def test_hardened_defaults(tmp_path):
    r = checksec.analyse(build(tmp_path, "-fPIE", "-pie", "-Wl,-z,relro,-z,lazy"))
    assert r["nx"] and r["pie"] and r["relro"] == "partial"


def test_execstack_no_pie(tmp_path):
    r = checksec.analyse(build(tmp_path, "-no-pie", "-z", "execstack", "-Wl,-z,norelro"))
    assert not r["nx"] and not r["pie"] and r["relro"] == "none"


def test_full_relro(tmp_path):
    r = checksec.analyse(build(tmp_path, "-Wl,-z,relro,-z,now"))
    assert r["relro"] == "full"


def test_canary_and_fortify_on(tmp_path):
    r = checksec.analyse(build(tmp_path, "-O2", "-fstack-protector-all",
                               "-D_FORTIFY_SOURCE=2", src=SRC_BUF))
    assert r["canary"] and r["fortify"]
    assert "__strcpy_chk" in r["fortified"]


def test_canary_and_fortify_off(tmp_path):
    r = checksec.analyse(build(tmp_path, "-O2", "-fno-stack-protector",
                               "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0", src=SRC_BUF))
    assert not r["canary"] and not r["fortify"]


def test_static_canary(tmp_path):
    # Static binaries carry .symtab (unless stripped); the guard symbol
    # must still be recognised.
    try:
        p = build(tmp_path, "-static", "-fstack-protector-all", src=SRC_BUF)
    except subprocess.CalledProcessError:
        pytest.skip("static libc not installed")
    assert checksec.analyse(p)["canary"]


def test_cet_on_off(tmp_path):
    on = checksec.analyse(build(tmp_path, "-fcf-protection=full"))
    if elf.parse(on["file"]).e_machine != elf.EM_X86_64:
        pytest.skip("CET is x86-64 only")
    assert on["cfi"] == {"ibt": True, "shstk": True}
    off = checksec.analyse(build(tmp_path, "-fcf-protection=none"))
    assert off["cfi"] == {"ibt": False, "shstk": False}


def test_stripped_falls_back_to_dynstr(tmp_path):
    # Remove section headers entirely (what sstrip does): the canary import
    # must still be found through DT_STRTAB.
    p = build(tmp_path, "-fstack-protector-all", src=SRC_BUF)
    data = bytearray(open(p, "rb").read())
    struct.pack_into("<QHHH", data, 0x28, 0, 0, 0, 0)  # e_shoff, (flags/ehsize skipped)
    struct.pack_into("<HHH", data, 0x3A, 0, 0, 0)     # e_shentsize, e_shnum, e_shstrndx
    (tmp_path / "s.bin").write_bytes(bytes(data))
    f = elf.parse(tmp_path / "s.bin")
    assert f.shdrs == []
    assert checksec.check_canary(f.symbol_names())


def test_rejects_non_elf(tmp_path):
    p = tmp_path / "x"
    p.write_bytes(b"MZ\x90\x00")
    with pytest.raises(elf.ElfError):
        elf.parse(p)


def test_rejects_truncated(tmp_path):
    p = tmp_path / "x"
    p.write_bytes(b"\x7fELF\x02\x01" + b"\x00" * 10)
    with pytest.raises(elf.ElfError):
        elf.parse(p)


def test_garbage_after_header_never_crashes(tmp_path):
    # A minimal fuzz: random bytes behind a valid ident must give either a
    # report or ElfError, never another exception type.
    import random
    rnd = random.Random(1234)
    for i in range(300):
        blob = b"\x7fELF\x02\x01\x01" + bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 400)))
        p = tmp_path / f"g{i}"
        p.write_bytes(blob)
        try:
            checksec.analyse(str(p))
        except elf.ElfError:
            pass


@pytest.mark.skipif(shutil.which("readelf") is None, reason="readelf not available")
def test_matches_readelf(tmp_path):
    import importlib.util
    import pathlib
    spec = importlib.util.spec_from_file_location(
        "xc", pathlib.Path(__file__).parent.parent / "scripts" / "crosscheck_readelf.py")
    xc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(xc)
    paths = [build(tmp_path, "-O2", "-fstack-protector-all", "-D_FORTIFY_SOURCE=2",
                   "-Wl,-z,now", src=SRC_BUF)]
    paths += [p for p in ("/bin/ls", "/bin/bash", "/usr/bin/python3") if shutil.os.path.exists(p)]
    for p in paths:
        assert xc.compare(p) == []
