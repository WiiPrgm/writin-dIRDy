#!/usr/bin/env python3
"""makecard_restore.py -- drop your homebrew onto the boot-IRD 1.22A
SD-RESTORE exploit card (Entrypoint A / Bug #1).


  * makecard_restore.py  (Entrypoint A / SD-restore, path overflow):
        a tiny loader stub baked into the card runs, then loads
        A:/boot.dol  (a DOL) and executes it directly.

So on the restore card YOUR HOMEBREW IS boot.dol, loaded straight by the
stub's own DOL loader -- no savezelda layer. The probe shipped with a
DOL-wrapped savezelda as boot.dol only to prove the chain; any standalone
DOL homebrew works the same way.

    .dol in  ->  written to A:/boot.dol as-is
    .elf in  ->  converted to DOL (standard elf2dol) -> A:/boot.dol

The loader stub opens "A:/boot.dol" by name and the BOOT.DOL directory entry
keeps its exact, hardware-verified position (root slot 1). This tool only
repoints that entry's start-cluster + size and rewrites its data clusters;
it then PROVES every other byte -- the RABA restore tree that drives the
overflow, the loader stub, and the path/mode/fail strings -- is identical to
the stub.

Usage:
    python makecard_restore.py mygame.dol              # -> bootird_restore_sd.raw
    python makecard_restore.py mygame.elf -o card.raw
    python makecard_restore.py --verify card.raw
    python makecard_restore.py --inspect

Flash the WHOLE .raw (it is a raw MBR disk image, not a file copy):
    Linux/macOS : sudo dd if=bootird_restore_sd.raw of=/dev/sdX bs=4M conv=fsync
    Windows     : Win32DiskImager / Rufus (DD / image mode)

Fine print the tool enforces or warns about:
  * This exploit needs ONE title installed on the console for the menu to
    offer "restore" (the image targets title 'RABA'). On a VIRGIN console
    use the FREE bIRD card (makecard.py) instead.
  * Menu-version lock: boot-IRD 1.22A only.
  * Hardware only: relies on SJIS / dcache-icache behavior Dolphin gets
    wrong. It will not run in the emulator.
  * boot.dol must be a real GC/Wii DOL (or an ELF this tool converts). The
    loader copies DOL sections to their load addresses and jumps to the DOL
    entry; it does no ELF parsing of its own.
"""

import argparse
import struct
import sys
from pathlib import Path

SECTOR = 512
EOC = 0x0FFFFFFF
EOC_MIN = 0x0FFFFFF8
DEFAULT_STUB = "restore_probe_v41_mbr.raw"
DEFAULT_OUT = "bootird_restore_sd.raw"
BOOTDOL_NAME = b"BOOT    DOL"   # 8.3 short name; the loader opens A:/boot.dol

# The baked-in loader stub reads boot.dol flat into a fixed staging window
# before parsing it: STAGE=0x81740000 .. CAP=0x817C0000. It stops at CAP, so
# boot.dol is truncated past this size. This is the real size limit on the
# restore card -- not free space. (savezelda's own driver, on the FREE bIRD
# card, has no such cap.)
STAGING_LIMIT = 0x817C0000 - 0x81740000   # 512 KiB

DOL_TEXT = 7
DOL_DATA = 11
DOL_HEADER = 0x100
PF_X = 0x1


# ------------------------------------------------------------------ ELF -> DOL
def _in_ram(a):
    # valid cached load window: MEM1 (0x8000_0000..0x817F_FFFF) or
    # MEM2 (0x9000_0000..0x93FF_FFFF, Wii).
    return (0x80000000 <= a < 0x81800000) or (0x90000000 <= a < 0x94000000)


def is_elf(data: bytes) -> bool:
    return data[:4] == b"\x7fELF"


def is_dol(data: bytes) -> bool:
    if len(data) < DOL_HEADER:
        return False
    offs = struct.unpack_from(">18I", data, 0x00)
    addrs = struct.unpack_from(">18I", data, 0x48)
    sizes = struct.unpack_from(">18I", data, 0x90)
    entry = struct.unpack_from(">I", data, 0xE0)[0]
    any_section = False
    for off, addr, size in zip(offs, addrs, sizes):
        if size == 0:
            continue
        any_section = True
        if off + size > len(data):
            return False
        if not _in_ram(addr):
            return False
    return any_section and _in_ram(entry)


def elf_to_dol(elf: bytes) -> bytes:
    """Convert an ELF32 BE PPC executable into a GameCube/Wii DOL.

    PT_LOAD segments with filesz>0 become DOL sections: executable -> text,
    others -> data. Segments with memsz>filesz contribute to the single DOL
    .bss region (bounding span). This is the standard elf2dol mapping.
    """
    if not (elf[:4] == b"\x7fELF" and elf[4] == 1 and elf[5] == 2):
        sys.exit("error: not an ELF32 big-endian file (need ELFCLASS32/"
                 "ELFDATA2MSB PowerPC)")
    e_entry = struct.unpack_from(">I", elf, 24)[0]
    e_phoff = struct.unpack_from(">I", elf, 28)[0]
    e_phentsize = struct.unpack_from(">H", elf, 42)[0]
    e_phnum = struct.unpack_from(">H", elf, 44)[0]

    text, data = [], []        # each: [vaddr, bytes]
    bss_lo = bss_hi = None
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type = struct.unpack_from(">I", elf, o)[0]
        if p_type != 1:        # PT_LOAD only
            continue
        p_offset = struct.unpack_from(">I", elf, o + 4)[0]
        p_vaddr = struct.unpack_from(">I", elf, o + 8)[0]
        p_filesz = struct.unpack_from(">I", elf, o + 16)[0]
        p_memsz = struct.unpack_from(">I", elf, o + 20)[0]
        p_flags = struct.unpack_from(">I", elf, o + 24)[0]
        if p_filesz > 0:
            seg = elf[p_offset:p_offset + p_filesz]
            (text if (p_flags & PF_X) else data).append([p_vaddr, seg])
        if p_memsz > p_filesz:
            lo, hi = p_vaddr + p_filesz, p_vaddr + p_memsz
            bss_lo = lo if bss_lo is None else min(bss_lo, lo)
            bss_hi = hi if bss_hi is None else max(bss_hi, hi)

    if not text and not data:
        sys.exit("error: ELF has no loadable (PT_LOAD) segments")
    if len(text) > DOL_TEXT:
        sys.exit(f"error: {len(text)} executable segments > DOL's {DOL_TEXT} "
                 f"text slots (relink with fewer sections)")
    if len(data) > DOL_DATA:
        sys.exit(f"error: {len(data)} data segments > DOL's {DOL_DATA} data "
                 f"slots (relink with fewer sections)")

    header = bytearray(DOL_HEADER)
    body = bytearray()

    def place(sections, off_field, addr_field, size_field):
        for i, (addr, seg) in enumerate(sections):
            body.extend(b"\x00" * ((-len(body)) % 0x20))   # align 0x20
            struct.pack_into(">I", header, off_field + i * 4, DOL_HEADER + len(body))
            struct.pack_into(">I", header, addr_field + i * 4, addr)
            struct.pack_into(">I", header, size_field + i * 4, len(seg))
            body.extend(seg)

    place(text, 0x00, 0x48, 0x90)
    place(data, 0x1C, 0x64, 0xAC)
    if bss_lo is not None:
        struct.pack_into(">I", header, 0xD8, bss_lo)
        struct.pack_into(">I", header, 0xDC, bss_hi - bss_lo)
    struct.pack_into(">I", header, 0xE0, e_entry)
    return bytes(header) + bytes(body)


def load_homebrew(path: Path) -> bytes:
    raw = path.read_bytes()
    if not raw:
        sys.exit(f"error: {path} is empty")
    if is_dol(raw):
        return raw
    if is_elf(raw):
        print(f"  input is an ELF ({len(raw)} B) -> converting to DOL")
        dol = elf_to_dol(raw)
        print(f"  converted DOL: {len(dol)} B")
        return dol
    sys.exit(f"error: {path} is neither a valid DOL nor an ELF")


# --------------------------------------------------------------- FAT32 image
class Card:
    """A flashable boot-IRD stub image: MBR + one FAT32 partition."""

    def __init__(self, data: bytes):
        self.v = bytearray(data)
        self.part = self._find_partition()
        b = self.part
        self.bps = self._u16(b + 11)
        self.spc = self.v[b + 13]
        self.rsvd = self._u16(b + 14)
        self.nfats = self.v[b + 16]
        self.fatsz = self._u32(b + 36)
        self.root_cl0 = self._u32(b + 44)
        self.tot = self._u32(b + 32)
        if self.bps != SECTOR or self.spc != 1:
            sys.exit(f"error: unexpected BPB (bps={self.bps} spc={self.spc})")
        self.data_sec = self.rsvd + self.nfats * self.fatsz
        self.ncl = self.tot - self.data_sec

    def _u16(self, o): return struct.unpack_from("<H", self.v, o)[0]
    def _u32(self, o): return struct.unpack_from("<I", self.v, o)[0]

    def _find_partition(self) -> int:
        if self.v[510:512] == b"\x55\xaa":
            for i in range(4):
                e = 0x1BE + i * 16
                ptype = self.v[e + 4]
                lba = struct.unpack_from("<I", self.v, e + 8)[0]
                if ptype in (0x0B, 0x0C, 0x06, 0x0E, 0x01) and lba:
                    off = lba * SECTOR
                    if self.v[off + 11:off + 13] == b"\x00\x02":
                        return off
        if self.v[11:13] == b"\x00\x02":
            return 0
        sys.exit("error: no FAT32 BPB found (not a boot-IRD stub image?)")

    def fat_slot_off(self, copy, n):
        return self.part + (self.rsvd + copy * self.fatsz) * SECTOR + n * 4

    def fat_get(self, n):
        return struct.unpack_from("<I", self.v, self.fat_slot_off(0, n))[0] & EOC

    def fat_set(self, n, val):
        for f in range(self.nfats):
            struct.pack_into("<I", self.v, self.fat_slot_off(f, n), val & 0xFFFFFFFF)

    def clus_off(self, n):
        return self.part + (self.data_sec + n - 2) * SECTOR

    def chain(self, n):
        out, seen = [], set()
        while 2 <= n < EOC_MIN and n not in seen:
            seen.add(n)
            out.append(n)
            n = self.fat_get(n)
        return out

    def root_clusters(self):
        return self.chain(self.root_cl0)

    def find_dirent(self, name11):
        rc = self.root_clusters()
        for c in rc:
            base = self.clus_off(c)
            for p in range(0, SECTOR, 32):
                first = self.v[base + p]
                if first == 0x00:
                    return None
                if first == 0xE5 or self.v[base + p + 11] == 0x0F:
                    continue
                if self.v[base + p:base + p + 11] == name11:
                    hi = struct.unpack_from("<H", self.v, base + p + 20)[0]
                    lo = struct.unpack_from("<H", self.v, base + p + 26)[0]
                    size = struct.unpack_from("<I", self.v, base + p + 28)[0]
                    return (base + p, (hi << 16) | lo, size)
        return None

    def free_count(self):
        return sum(1 for n in range(2, self.ncl + 2) if self.fat_get(n) == 0)


# ------------------------------------------------------------------- inject
def inject(stub_path: Path, dol: bytes, out_path: Path):
    card = Card(stub_path.read_bytes())
    stub_bytes = bytes(card.v)

    hit = card.find_dirent(BOOTDOL_NAME)
    if not hit:
        sys.exit("error: no BOOT.DOL dirent in the stub -- wrong image? "
                 "(expected the SD-restore card)")
    if len(dol) > STAGING_LIMIT:
        sys.exit(f"error: boot.dol is {len(dol)} B but the restore card's "
                 f"loader stub only stages {STAGING_LIMIT} B "
                 f"({STAGING_LIMIT // 1024} KiB) before parsing it -- a larger "
                 f"DOL would be truncated and crash.\n"
                 f"       Shrink the build, or use the FREE bIRD card "
                 f"(makecard.py), whose savezelda loader streams with its own "
                 f"driver and has no such cap.")
    dirent_off, old_start, old_size = hit
    old_chain = card.chain(old_start)
    print(f"  stub: part@{card.part // SECTOR} LBA, {card.ncl} clusters, "
          f"{card.nfats} FATs")
    print(f"  placeholder A:/boot.dol: start cl {old_start}, {old_size} B, "
          f"{len(old_chain)} clusters")

    # 1) free the placeholder chain
    for c in old_chain:
        card.fat_set(c, 0)

    # 2) allocate a fresh chain -- no residue constraint on the restore card
    need = (len(dol) + SECTOR - 1) // SECTOR
    new_chain = []
    n = 2
    while len(new_chain) < need and n < card.ncl + 2:
        if card.fat_get(n) == 0:
            new_chain.append(n)
        n += 1
    if len(new_chain) < need:
        for a, b in zip(old_chain, old_chain[1:]):
            card.fat_set(a, b)
        if old_chain:
            card.fat_set(old_chain[-1], EOC)
        sys.exit(f"error: need {need} clusters for a {len(dol)} B DOL but only "
                 f"{len(new_chain)} are free. Rebuild on a larger volume.")

    # 3) link + write
    for a, b in zip(new_chain, new_chain[1:]):
        card.fat_set(a, b)
    card.fat_set(new_chain[-1], EOC)
    for i, c in enumerate(new_chain):
        seg = dol[i * SECTOR:(i + 1) * SECTOR].ljust(SECTOR, b"\x00")
        card.v[card.clus_off(c):card.clus_off(c) + SECTOR] = seg

    # 4) repoint the BOOT.DOL dirent (start hi/lo + size) -- the only
    #    directory bytes we touch; the name and slot stay put.
    struct.pack_into("<H", card.v, dirent_off + 20, (new_chain[0] >> 16) & 0xFFFF)
    struct.pack_into("<H", card.v, dirent_off + 26, new_chain[0] & 0xFFFF)
    struct.pack_into("<I", card.v, dirent_off + 28, len(dol))
    print(f"  new A:/boot.dol: start cl {new_chain[0]}, {len(dol)} B, "
          f"{len(new_chain)} clusters")

    verify_against_stub(card, stub_bytes, dirent_off, old_chain, new_chain)
    out_path.write_bytes(card.v)
    print(f"OK  wrote {out_path} ({len(card.v) // (1 << 20)} MiB)")


def permitted_mask(card, dirent_off, old_chain, new_chain):
    allow = bytearray(len(card.v))
    one = b"\x01"
    for a, b in ((20, 22), (26, 28), (28, 32)):
        allow[dirent_off + a:dirent_off + b] = one * (b - a)
    for c in set(old_chain) | set(new_chain):
        base = card.clus_off(c)
        allow[base:base + SECTOR] = one * SECTOR
        for f in range(card.nfats):
            o0 = card.fat_slot_off(f, c)
            allow[o0:o0 + 4] = one * 4
    return allow


def verify_against_stub(card, stub_bytes, dirent_off, old_chain, new_chain):
    if len(card.v) != len(stub_bytes):
        sys.exit("verify FAIL: output length changed")
    allow = permitted_mask(card, dirent_off, old_chain, new_chain)
    out = card.v
    step = 4096
    bad = []
    for i in range(0, len(out), step):
        a = out[i:i + step]
        b = stub_bytes[i:i + step]
        if a == b:
            continue
        for j in range(len(a)):
            if a[j] != b[j] and not allow[i + j]:
                bad.append(i + j)
                if len(bad) > 8:
                    break
        if len(bad) > 8:
            break
    if bad:
        sys.exit("verify FAIL: exploit bytes changed at offsets "
                 + ", ".join(f"0x{o:X}" for o in bad)
                 + " -- aborting, the card was NOT written.")

    # positive spot checks: the root cluster's RABA entry and the loader
    # stub + path strings (root offset 0x40..0x200) must be byte-identical,
    # and the RABA restore tree (every cluster but boot.dol's) untouched.
    rc = card.root_clusters()
    base = card.clus_off(rc[0])
    if out[base:base + 0x20] != stub_bytes[base:base + 0x20]:
        sys.exit("verify FAIL: RABA dirent changed")
    if out[base + 0x40:base + SECTOR] != stub_bytes[base + 0x40:base + SECTOR]:
        sys.exit("verify FAIL: loader stub / path strings changed")
    print("  verify OK: exploit bytes byte-identical to the stub")


def verify_existing(path: Path, stub_path: Path):
    card = Card(path.read_bytes())
    stub = Card(stub_path.read_bytes())
    if len(card.v) != len(stub.v):
        sys.exit("verify FAIL: size differs from stub")
    hit = card.find_dirent(BOOTDOL_NAME)
    shit = stub.find_dirent(BOOTDOL_NAME)
    if not hit or not shit:
        sys.exit("verify FAIL: BOOT.DOL dirent missing")
    dirent_off, start, size = hit
    new_chain = card.chain(start)
    old_chain = stub.chain(shit[1])
    data = b"".join(card.v[card.clus_off(c):card.clus_off(c) + SECTOR]
                    for c in new_chain)[:size]
    if not is_dol(data):
        sys.exit("verify FAIL: A:/boot.dol is not a valid DOL")
    verify_against_stub(card, bytes(stub.v), dirent_off, old_chain, new_chain)
    print(f"OK  {path} is a valid restore card: A:/boot.dol = {size} B, "
          f"{len(new_chain)} clusters, exploit intact")


def inspect(stub_path: Path):
    card = Card(stub_path.read_bytes())
    print(f"stub: {stub_path}")
    print(f"  partition @ LBA {card.part // SECTOR}, {card.ncl} clusters, "
          f"{card.nfats} FATs, fatsz {card.fatsz}")
    print(f"  root chain: {len(card.root_clusters())} cluster(s)")
    for name in (b"RABA       ", BOOTDOL_NAME):
        hit = card.find_dirent(name)
        if hit:
            off, start, size = hit
            ch = card.chain(start) if size or name == BOOTDOL_NAME else [start]
            print(f"  {name.decode().strip()!r}: start cl {start}, {size} B, "
                  f"{len(ch)} cluster(s)")
    free = card.free_count()
    print(f"  free clusters: {free} (~{free * SECTOR // 1024 // 1024} MiB), "
          f"no residue constraint")
    print(f"  boot.dol SIZE LIMIT: {STAGING_LIMIT} B ({STAGING_LIMIT // 1024} "
          f"KiB) -- the loader stub's staging window, the real cap")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Swap your homebrew A:/boot.dol onto a boot-IRD 1.22A "
                    "SD-restore exploit card without touching the exploit.")
    ap.add_argument("input", nargs="?", help="homebrew .dol or .elf")
    ap.add_argument("-o", "--out", default=DEFAULT_OUT,
                    help=f"output image (default {DEFAULT_OUT})")
    ap.add_argument("--stub", default=DEFAULT_STUB,
                    help=f"golden stub image (default {DEFAULT_STUB})")
    ap.add_argument("--verify", metavar="CARD",
                    help="re-check an existing card against the stub and exit")
    ap.add_argument("--inspect", action="store_true",
                    help="print the stub's layout and capacity, then exit")
    args = ap.parse_args(argv)

    stub = Path(args.stub)
    if not stub.exists():
        sys.exit(f"error: stub not found: {stub}")
    if args.inspect:
        inspect(stub)
        return
    if args.verify:
        verify_existing(Path(args.verify), stub)
        return
    if not args.input:
        ap.error("give a homebrew .dol/.elf, or use --verify / --inspect")
    src = Path(args.input)
    if not src.exists():
        sys.exit(f"error: input not found: {src}")
    print(f"makecard_restore: {src} -> {args.out}  (stub {stub.name})")
    dol = load_homebrew(src)
    inject(stub, dol, Path(args.out))


if __name__ == "__main__":
    main()
