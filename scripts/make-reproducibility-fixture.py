#!/usr/bin/env python3
"""Build the synthetic x86-64 reproducibility probe with erofs-utils; no downloads."""

import hashlib
import io
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile


def elf(body):
    image = bytearray(120)
    image[:8] = b"\x7fELF\x02\x01\x01\x00"
    struct.pack_into("<HHI", image, 16, 2, 62, 1)
    struct.pack_into("<QQ", image, 24, 0x10078, 64)
    struct.pack_into("<HHH", image, 52, 64, 56, 1)
    size = len(image) + len(body)
    struct.pack_into("<IIQQQQQQ", image, 64, 1, 7, 0, 0x10000, 0x10000, size, size, 4096)
    return bytes(image) + body


def probe():
    code = bytearray()
    jumps = []
    labels = {}
    addresses = []

    def emit(*values):
        code.extend(values)

    def move(opcode, value):
        emit(opcode)
        code.extend(struct.pack("<I", value))

    def pointer(opcode, name):
        emit(opcode)
        addresses.append((len(code), name))
        code.extend(bytes(4))

    def syscall(number):
        move(0xB8, number)
        emit(0x0F, 0x05)

    def jump(condition, label):
        emit(0x0F, condition)
        jumps.append((len(code), label))
        code.extend(bytes(4))

    def check_zero():
        emit(0x48, 0x85, 0xC0)  # test rax,rax
        jump(0x85, "fail")

    # stdin remains an open guest descriptor whose reads always return zero.
    move(0xBF, 0)
    pointer(0xBE, "buffer")
    move(0xBA, 1)
    syscall(0)
    check_zero()
    move(0xBE, 1)  # F_GETFD
    syscall(72)
    check_zero()
    for request in [0x5401, 0x5402, 0x5413, 0x5414]:  # termios and window queries/setters
        move(0xBE, request)
        pointer(0xBA, "buffer")
        syscall(16)
        emit(0x83, 0xF8, 0xE7)  # cmp eax,-25 (ENOTTY)
        jump(0x85, "fail")

    syscall(57)  # fork
    emit(0x48, 0x85, 0xC0)
    jump(0x88, "fail")
    emit(0x49, 0x89, 0xC4)  # r12 = child pid or zero
    move(0xBB, 200)
    labels["compute"] = len(code)
    emit(0xFF, 0xCB)  # dec ebx
    jump(0x85, "compute")
    emit(0x9C, 0x58, 0xA9, 0, 1, 0, 0)  # pushfq; pop rax; test eax,TF
    jump(0x85, "fail")
    emit(0x4D, 0x85, 0xE4)
    jump(0x84, "done")
    emit(0x44, 0x89, 0xE7)  # edi = child pid
    pointer(0xBE, "buffer")
    move(0xBA, 0)
    emit(0x45, 0x31, 0xD2)  # r10 = 0
    syscall(61)  # wait4
    emit(0x4C, 0x39, 0xE0)
    jump(0x85, "fail")
    pointer(0xBE, "buffer")
    emit(0x83, 0x3E, 0)
    jump(0x85, "fail")

    move(0xBF, 2)
    pointer(0xBE, "message")
    move(0xBA, len(b"guest-stderr\n"))
    syscall(1)
    emit(0x83, 0xF8, len(b"guest-stderr\n"))
    jump(0x85, "fail")
    move(0xBB, 128)
    labels["write"] = len(code)
    move(0xBF, 1)
    pointer(0xBE, "output")
    move(0xBA, 1024)
    syscall(1)
    emit(0x3D)
    code.extend(struct.pack("<I", 1024))
    jump(0x85, "fail")
    emit(0xFF, 0xCB)
    jump(0x85, "write")
    move(0xBF, 1)  # CLOCK_MONOTONIC
    pointer(0xBE, "buffer")
    syscall(228)
    check_zero()
    move(0xBF, 1)
    pointer(0xBE, "buffer")
    move(0xBA, 16)
    syscall(1)
    labels["done"] = len(code)
    move(0xBF, 0)
    syscall(60)
    labels["fail"] = len(code)
    move(0xBF, 99)
    syscall(60)
    labels["buffer"] = len(code)
    code.extend(bytes(64))
    labels["message"] = len(code)
    code.extend(b"guest-stderr\n")
    labels["output"] = len(code)
    code.extend(b"R" * 1024)
    for offset, label in jumps:
        struct.pack_into("<i", code, offset, labels[label] - offset - 4)
    for offset, label in addresses:
        struct.pack_into("<I", code, offset, 0x10078 + labels[label])
    return elf(code)


def main():
    root = Path(__file__).resolve().parents[1]
    output = root / "tests/data/erofs/reproducible.erofs"
    with tempfile.TemporaryDirectory() as temporary:
        source = Path(temporary) / "probe.tar"
        with tarfile.open(source, "w", format=tarfile.USTAR_FORMAT) as archive:
            for name, content, mode in [
                (".", b"", 0o755),
                ("init", probe(), 0o755),
                ("fault", elf(b"\x0f\x0b"), 0o755),
                ("exit125", elf(b"\xbf\x7d\x00\x00\x00\xb8\x3c\x00\x00\x00\x0f\x05"), 0o755),
            ]:
                entry = tarfile.TarInfo(name)
                entry.mode = mode
                entry.mtime = 1_700_000_000
                entry.size = len(content)
                if name == ".":
                    entry.type = tarfile.DIRTYPE
                archive.addfile(entry, io.BytesIO(content))
        subprocess.run(
            [
                "mkfs.erofs",
                "--quiet",
                "--tar=f",
                "--workers=1",
                "-b4096",
                "-T1700000000",
                "-U00000000-0000-0000-0000-000000000002",
                "--all-root",
                str(output),
                str(source),
            ],
            check=True,
        )
        subprocess.run(["fsck.erofs", "--extract", str(output)], check=True, capture_output=True)
    print(f"{output.name}: {hashlib.sha256(output.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
