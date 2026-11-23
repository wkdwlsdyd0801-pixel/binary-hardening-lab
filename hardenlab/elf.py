"""Minimal, dependency-free ELF64 reader used by the checksec analyser.

Only the structures needed to judge exploit mitigations are parsed:
the ELF header (PIE), program headers (NX via PT_GNU_STACK, RELRO via
PT_GNU_RELRO), the dynamic section (BIND_NOW -> full RELRO), symbol
names (stack canary, FORTIFY) and the GNU property note (CET IBT/SHSTK,
AArch64 BTI/PAC). Parsing is defensive: a truncated or hostile file
raises ElfError instead of crashing, because the analyser is meant to
be pointed at untrusted binaries.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1

# e_type values: ET_EXEC is a fixed-address binary, ET_DYN is either a
# shared object or a position-independent executable (PIE).
ET_EXEC = 2
ET_DYN = 3

EM_X86_64 = 62
EM_AARCH64 = 183

# Program header types that encode mitigations.
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_GNU_STACK = 0x6474E551  # p_flags says whether the stack is executable
PT_GNU_RELRO = 0x6474E552  # region remapped read-only after relocation
PT_GNU_PROPERTY = 0x6474E553  # carries CET (IBT/SHSTK) feature bits

PF_X = 1

# Section header types holding symbol tables.
SHT_SYMTAB = 2
SHT_DYNSYM = 11

# Dynamic tags relevant to mitigations.
DT_NULL = 0
DT_STRTAB = 5
DT_STRSZ = 10
DT_BIND_NOW = 24
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1
DF_1_PIE = 0x08000000

# GNU property note (NT_GNU_PROPERTY_TYPE_0) and the feature bits that
# compilers emit for -fcf-protection / -mbranch-protection.
NT_GNU_PROPERTY_TYPE_0 = 5
GNU_PROPERTY_X86_FEATURE_1_AND = 0xC0000002
GNU_PROPERTY_X86_FEATURE_1_IBT = 0x1
GNU_PROPERTY_X86_FEATURE_1_SHSTK = 0x2
GNU_PROPERTY_AARCH64_FEATURE_1_AND = 0xC0000000
GNU_PROPERTY_AARCH64_FEATURE_1_BTI = 0x1
GNU_PROPERTY_AARCH64_FEATURE_1_PAC = 0x2


class ElfError(ValueError):
    """Raised for anything that is not a well-formed little-endian ELF64."""


@dataclass(frozen=True)
class ProgramHeader:
    p_type: int
    p_flags: int
    p_offset: int
    p_vaddr: int
    p_filesz: int
    p_memsz: int


@dataclass(frozen=True)
class SectionHeader:
    sh_name: int
    sh_type: int
    sh_offset: int
    sh_size: int
    sh_link: int
    sh_entsize: int


@dataclass
class ElfFile:
    path: str
    e_type: int
    e_machine: int
    e_entry: int
    phdrs: list[ProgramHeader] = field(default_factory=list)
    shdrs: list[SectionHeader] = field(default_factory=list)
    data: bytes = b""

    def segments(self, p_type: int) -> list[ProgramHeader]:
        return [p for p in self.phdrs if p.p_type == p_type]

    def vaddr_to_offset(self, vaddr: int) -> int | None:
        # Dynamic-section pointers are virtual addresses; map them back
        # to file offsets through the PT_LOAD segment that contains them.
        for p in self.segments(PT_LOAD):
            if p.p_vaddr <= vaddr < p.p_vaddr + p.p_filesz:
                return p.p_offset + (vaddr - p.p_vaddr)
        return None

    def dynamic(self) -> list[tuple[int, int]]:
        """(d_tag, d_val) pairs from PT_DYNAMIC; empty for static binaries."""
        dyn = self.segments(PT_DYNAMIC)
        if not dyn:
            return []
        p = dyn[0]
        out = []
        # Bound the walk by the segment size so a missing DT_NULL cannot
        # make us read past the segment.
        for i in range(p.p_filesz // 16):
            tag, val = _unpack("<qQ", self.data, p.p_offset + i * 16)
            if tag == DT_NULL:
                break
            out.append((tag, val))
        return out

    def symbol_names(self) -> set[str]:
        """Names from .symtab/.dynsym; falls back to the raw dynamic string
        table when section headers were stripped (sstrip), because imported
        function names such as __stack_chk_fail still live there."""
        names: set[str] = set()
        for sh in self.shdrs:
            if sh.sh_type not in (SHT_SYMTAB, SHT_DYNSYM) or sh.sh_entsize != 24:
                continue
            if sh.sh_link >= len(self.shdrs):
                raise ElfError("symbol table links to a missing string table")
            strtab = self.shdrs[sh.sh_link]
            for i in range(sh.sh_size // 24):
                (st_name,) = _unpack("<I", self.data, sh.sh_offset + i * 24)
                if st_name:
                    names.add(_cstr(self.data, strtab.sh_offset + st_name,
                                    strtab.sh_offset + strtab.sh_size))
        if names:
            return names
        dyn = dict(self.dynamic())
        if DT_STRTAB in dyn and DT_STRSZ in dyn:
            off = self.vaddr_to_offset(dyn[DT_STRTAB])
            if off is not None:
                blob = self.data[off:off + dyn[DT_STRSZ]]
                names.update(s.decode("latin-1") for s in blob.split(b"\0") if s)
        return names

    def gnu_properties(self) -> dict[int, int]:
        """pr_type -> 32-bit value from NT_GNU_PROPERTY_TYPE_0 notes."""
        notes = self.segments(PT_GNU_PROPERTY) or self.segments(PT_NOTE)
        props: dict[int, int] = {}
        for p in notes:
            off, end = p.p_offset, p.p_offset + p.p_filesz
            while off + 12 <= end:
                namesz, descsz, ntype = _unpack("<III", self.data, off)
                name_off = off + 12
                # ELF64 GNU property notes are 8-byte aligned; other notes
                # (build-id, ABI tag) use 4-byte alignment.
                align = 8 if ntype == NT_GNU_PROPERTY_TYPE_0 else 4
                desc_off = name_off + _align(namesz, 4)
                if ntype == NT_GNU_PROPERTY_TYPE_0 and \
                        self.data[name_off:name_off + namesz] == b"GNU\0":
                    _parse_props(self.data, desc_off, desc_off + descsz, props)
                off = desc_off + _align(descsz, align)
        return props


def _align(n: int, a: int) -> int:
    return (n + a - 1) & ~(a - 1)


def _cstr(data: bytes, off: int, limit: int) -> str:
    end = data.find(b"\0", off, limit)
    if off >= limit or end < 0:
        raise ElfError(f"unterminated string at offset {off:#x}")
    return data[off:end].decode("latin-1")


def _parse_props(data: bytes, off: int, end: int, props: dict[int, int]) -> None:
    while off + 8 <= end:
        pr_type, pr_datasz = _unpack("<II", data, off)
        if pr_datasz == 4:
            (props[pr_type],) = _unpack("<I", data, off + 8)
        off += 8 + _align(pr_datasz, 8)


def _unpack(fmt: str, data: bytes, off: int) -> tuple:
    # Every read goes through here so a bad offset becomes ElfError,
    # not an IndexError deep inside struct.
    size = struct.calcsize(fmt)
    if off < 0 or off + size > len(data):
        raise ElfError(f"truncated read at offset {off:#x}")
    return struct.unpack_from(fmt, data, off)


def parse(path: str | Path) -> ElfFile:
    data = Path(path).read_bytes()
    if data[:4] != ELF_MAGIC:
        raise ElfError("not an ELF file")
    # Only ELF64 little-endian (x86-64/aarch64) is in scope; failing
    # loudly is better than silently misreading 32-bit headers.
    if len(data) < 6 or data[4] != ELFCLASS64 or data[5] != ELFDATA2LSB:
        raise ElfError("only little-endian ELF64 is supported")

    (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, _flags,
     _ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, _shstrndx) = \
        _unpack("<HHIQQQIHHHHHH", data, 16)

    if e_phnum and e_phentsize != 56:
        raise ElfError(f"unexpected program header size {e_phentsize}")

    phdrs = []
    for i in range(e_phnum):
        p_type, p_flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, _align_ = \
            _unpack("<IIQQQQQQ", data, e_phoff + i * 56)
        phdrs.append(ProgramHeader(p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz))

    # Section headers are optional at runtime (sstrip removes them), so a
    # missing or odd table is tolerated rather than treated as an error.
    shdrs = []
    if e_shoff and e_shnum and e_shentsize == 64:
        for i in range(e_shnum):
            (sh_name, sh_type, _fl, _addr, sh_offset, sh_size, sh_link,
             _info, _al, sh_entsize) = _unpack("<IIQQQQIIQQ", data, e_shoff + i * 64)
            shdrs.append(SectionHeader(sh_name, sh_type, sh_offset, sh_size, sh_link, sh_entsize))

    return ElfFile(str(path), e_type, e_machine, e_entry, phdrs, shdrs, data)
