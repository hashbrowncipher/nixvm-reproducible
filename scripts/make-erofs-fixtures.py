#!/usr/bin/env python3
"""Regenerate synthetic EROFS reader fixtures with erofs-utils 1.9.

All source data and metadata are declared here. No host directory is packed.
Requires mkfs.erofs and fsck.erofs; uses no Python packages or network.
"""

import hashlib
import io
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile


TIMESTAMP = 1_700_000_000
UUID = "00000000-0000-0000-0000-000000000001"
BIG = b"EROFS fixture data\n" * 4096


def entry(name, content=b"", kind=tarfile.REGTYPE, target="", xattrs=None, device=(0, 0), mode=None):
    node = tarfile.TarInfo(name)
    node.type = kind
    node.mode = 0o755 if kind == tarfile.DIRTYPE else 0o640
    if kind == tarfile.SYMTYPE:
        node.mode = 0o777
    if mode is not None:
        node.mode = mode
    node.mtime = TIMESTAMP
    node.uid = node.gid = 0
    node.linkname = target
    node.devmajor, node.devminor = device
    node.size = len(content)
    node.pax_headers = {f"SCHILY.xattr.{key}": value for key, value in (xattrs or {}).items()}
    return node, content


def exit_elf(code):
    """Static aarch64 ELF: movz x0,code; movz x8,93; svc (exit)."""
    body = struct.pack("<III", 0xD2800000 | (code << 5), 0xD2800BA8, 0xD4000001)
    image = bytearray(120 + len(body))
    image[:8] = b"\x7fELF\x02\x01\x01\x00"
    struct.pack_into("<HHI", image, 16, 2, 183, 1)
    struct.pack_into("<QQ", image, 24, 0x10000 + 120, 64)
    struct.pack_into("<HHH", image, 52, 64, 56, 1)
    struct.pack_into("<IIQQQQQQ", image, 64, 1, 5, 0, 0x10000, 0x10000, len(image), len(image), 4096)
    image[120:] = body
    return image


def archive(path, entries):
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as output:
        for node, content in entries:
            output.addfile(node, io.BytesIO(content))


def build(output, source, compressor=None):
    options = [
        "mkfs.erofs",
        "--quiet",
        "--tar=f",
        "--ovlfs-strip=0",
        "--workers=1",
        "-b4096",
        f"-T{TIMESTAMP}",
        f"-U{UUID}",
        "--all-root",
    ]
    if compressor:
        options.append(f"-z{compressor}")
    subprocess.run([*options, str(output), str(source)], check=True)
    subprocess.run(["fsck.erofs", "--extract", str(output)], check=True, capture_output=True)
    print(f"{output.name}: {hashlib.sha256(output.read_bytes()).hexdigest()}")


def main():
    root = Path(__file__).resolve().parents[1]
    destination = root / "tests/data/erofs"
    destination.mkdir(parents=True, exist_ok=True)
    (root / "target").mkdir(exist_ok=True)
    base = [
        entry(".", kind=tarfile.DIRTYPE),
        entry("init", exit_elf(42), mode=0o755),
        entry("etc", kind=tarfile.DIRTYPE),
        entry("etc/config", b"base configuration\n", xattrs={"user.fixture": "base"}),
        entry("etc/base-only", b"base only\n"),
        entry("hardlink", kind=tarfile.LNKTYPE, target="etc/config"),
        entry("link", kind=tarfile.SYMTYPE, target="etc/config"),
        entry("abslink", kind=tarfile.SYMTYPE, target="/etc/config"),
        entry("dirlink", kind=tarfile.SYMTYPE, target="etc"),
        entry("fifo", kind=tarfile.FIFOTYPE),
        entry("null", kind=tarfile.CHRTYPE, device=(1, 3)),
        entry("removed", b"remove me\n"),
        entry("opaque", kind=tarfile.DIRTYPE),
        entry("opaque/old", b"hidden by opacity\n"),
        entry("blocked", kind=tarfile.DIRTYPE),
        entry("blocked/old", b"hidden by a file\n"),
        entry("reborn", kind=tarfile.DIRTYPE),
        entry("reborn/old", b"hidden by an intervening file\n"),
        entry("big.bin", BIG),
    ]
    middle = [
        entry(".", kind=tarfile.DIRTYPE),
        entry("removed", kind=tarfile.CHRTYPE),
        entry("opaque", kind=tarfile.DIRTYPE, xattrs={"trusted.overlay.opaque": "y"}),
        entry("opaque/new", b"middle entry\n"),
        entry("blocked", b"middle file\n"),
        entry("reborn", b"intervening file\n"),
    ]
    top = [
        entry(".", kind=tarfile.DIRTYPE),
        entry("init", exit_elf(43), mode=0o755),
        entry("etc", kind=tarfile.DIRTYPE),
        entry("etc/config", b"top configuration\n", xattrs={"user.fixture": "top"}),
        entry("opaque", kind=tarfile.DIRTYPE),
        entry("opaque/top", b"top entry\n"),
        entry("reborn", kind=tarfile.DIRTYPE),
        entry("reborn/new", b"new subtree\n"),
    ]
    with tempfile.TemporaryDirectory(dir=root / "target", prefix="erofs-fixtures-") as scratch:
        source = Path(scratch) / "source.tar"
        archive(source, base)
        build(destination / "base.erofs", source)
        for compressor in ("lz4", "lzma", "deflate", "zstd"):
            build(destination / f"{compressor}.erofs", source, compressor)
        for name, entries in (("middle", middle), ("top", top)):
            archive(source, entries)
            build(destination / f"{name}.erofs", source)


if __name__ == "__main__":
    main()
