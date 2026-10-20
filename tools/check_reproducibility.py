#!/usr/bin/env python3
"""Repeat confined builds under host perturbations and compare exact output hashes.

Requires real Intel KVM/perf and a nixvm binary built with --features erofs.
Each guest run has a host timeout below 260 seconds. No network is used.

    python3 tools/check_reproducibility.py --nixvm target/debug/nixvm --self-test
    python3 tools/check_reproducibility.py --nixvm target/release/nixvm \
        --erofs root.erofs --erofs input.erofs -- /bin/sh /build.sh
"""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import resource
import select
import shutil
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def cpu_identity():
    fields = {"vendor_id", "cpu family", "model", "model name", "stepping", "microcode"}
    result = {}
    for line in Path("/proc/cpuinfo").read_text().split("\n\n", 1)[0].splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip() in fields:
            result[key.strip()] = value.strip()
    return result


def limits(cpu, file_limit=None, descriptors=512):
    def prepare():
        if cpu is not None:
            os.sched_setaffinity(0, {cpu})
        hard = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
        resource.setrlimit(
            resource.RLIMIT_NOFILE, (descriptors if hard == resource.RLIM_INFINITY else min(descriptors, hard), hard)
        )
        if file_limit is not None:
            hard = resource.getrlimit(resource.RLIMIT_FSIZE)[1]
            resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, hard))

    return prepare


def run_case(options, images, directory, scenario, repetition, cpu, failure=None):
    case = directory / f"{scenario}-{repetition}"
    case.mkdir()
    status = case / "status"
    argv = [
        str(options.nixvm),
        "run",
        "--reproducible",
        "--mem",
        options.mem,
        "--vcpu-capacity",
        "4",
        "--status-file",
        str(status),
        "--branch-quantum",
        str(options.branch_quantum),
        "--syscall-quantum",
        str(options.syscall_quantum),
    ]
    for image in images:
        argv.extend(["--erofs", str(image)])
    argv.extend(["--", *options.command])
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C" if repetition % 2 else "C.UTF-8",
        "TZ": "Pacific/Honolulu" if repetition % 2 else "Asia/Tokyo",
        "REPRODUCIBILITY_NOISE": str(repetition),
    }
    for index, image in enumerate(images):
        os.utime(image, (1_000_000_000 + repetition + index, 1_100_000_000 + repetition))
    terminal = None
    input_path = case / "stdin"
    input_path.write_bytes(b"undeclared synthetic host input\n")
    reader = None
    pipe_fds = None
    collected = bytearray()
    read_errors = []
    with (
        input_path.open("rb") as input_file,
        (case / "stdout").open("wb") as output_file,
        (case / "stderr").open("wb") as error_file,
    ):
        stdin = input_file
        stdout = output_file
        if scenario == "terminal":
            master, slave = pty.openpty()
            terminal = (master, slave)
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 7 + repetition, 31 + repetition, 0, 0))
            before = termios.tcgetattr(slave)
            window_before = fcntl.ioctl(slave, termios.TIOCGWINSZ, bytes(8))
            stdin = slave
        if scenario == "nonblocking-pipe":
            read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
            pipe_fds = (read_fd, write_fd)
            fcntl.fcntl(write_fd, fcntl.F_SETPIPE_SZ, 4096)
            fcntl.fcntl(write_fd, fcntl.F_SETFL, os.O_NONBLOCK)
            stdout = write_fd

            def drain():
                try:
                    if not select.select([read_fd], [], [], options.timeout)[0]:
                        raise RuntimeError("no pipe output before timeout")
                    time.sleep(0.02)
                    while chunk := os.read(read_fd, 65536):
                        collected.extend(chunk)
                except Exception as error:
                    read_errors.append(error)

            reader = threading.Thread(target=drain)
        if failure == "full":
            stdout = os.open("/dev/full", os.O_WRONLY | os.O_CLOEXEC)
        elif failure == "broken-pipe":
            read_fd, stdout = os.pipe2(os.O_CLOEXEC)
            os.close(read_fd)
        try:
            completed = subprocess.Popen(
                argv,
                cwd=case,
                env=environment,
                stdin=stdin,
                stdout=stdout,
                stderr=error_file,
                preexec_fn=limits(cpu, 1024 if failure == "file-limit" else None, 512 if repetition % 2 else 1024),
            )
            if reader:
                reader.start()
            try:
                completed.wait(timeout=options.timeout)
            except subprocess.TimeoutExpired:
                completed.kill()
                completed.wait(timeout=5)
                raise
            if pipe_fds:
                assert fcntl.fcntl(pipe_fds[1], fcntl.F_GETFL) & os.O_NONBLOCK, "shared O_NONBLOCK was cleared"
            if terminal:
                assert termios.tcgetattr(terminal[1]) == before, "guest changed host terminal"
                assert fcntl.ioctl(terminal[1], termios.TIOCGWINSZ, bytes(8)) == window_before, (
                    "guest changed host window size"
                )
            assert input_file.tell() == 0, "guest consumed host stdin"
        finally:
            if failure in {"full", "broken-pipe"}:
                os.close(stdout)
            if pipe_fds:
                os.close(pipe_fds[1])
                reader.join(options.timeout)
                os.close(pipe_fds[0])
                if reader.is_alive():
                    raise RuntimeError("pipe reader did not finish")
            if terminal:
                for fd in terminal:
                    os.close(fd)
    if read_errors:
        raise read_errors[0]
    if pipe_fds:
        (case / "stdout").write_bytes(collected)
    report = status.read_text()
    if failure:
        if (
            completed.returncode != 125
            or not report.startswith("sandbox-error\n")
            or "host output failed" not in report
        ):
            raise RuntimeError(f"{failure}: host failure was not reported: {completed.returncode}, {report}")
        return None
    if not report.startswith("guest-exit "):
        raise RuntimeError(f"{scenario}: sandbox failed: {report}")
    if report != f"guest-exit {completed.returncode}\n":
        raise RuntimeError("host exit status disagrees with the independent guest report")
    return {"stdout": digest(case / "stdout"), "stderr": digest(case / "stderr"), "status": report.strip()}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--nixvm", type=Path, required=True)
    parser.add_argument("--erofs", type=Path, action="append", default=[])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--mem", default="128M")
    parser.add_argument("--branch-quantum", type=int, default=65536)
    parser.add_argument("--syscall-quantum", type=int, default=1024)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    options = parser.parse_args()
    if not 0 < options.timeout < 260 or options.repeats < 2:
        parser.error("timeout must be in (0,260), and repeats must be at least two")
    options.nixvm = options.nixvm.resolve(strict=True)
    if options.self_test:
        if options.erofs or options.command:
            parser.error("--self-test supplies its own images and command")
        options.erofs = [Path(__file__).resolve().parents[1] / "tests/data/erofs/reproducible.erofs"]
        options.command = ["/init"]
        options.branch_quantum = 64
        options.syscall_quantum = 16
    else:
        options.command = options.command[1:] if options.command[:1] == ["--"] else options.command
        if not options.erofs or not options.command:
            parser.error("provide --erofs layers and a guest command, or --self-test")
    identities = [digest(image) for image in options.erofs]
    cpus = sorted(os.sched_getaffinity(0))
    baseline = None
    count = 0
    with tempfile.TemporaryDirectory(prefix="nixvm-repeat-") as temporary:
        directory = Path(temporary)
        images = []
        for index, image in enumerate(options.erofs):
            copied = directory / f"layer-{index}.erofs"
            shutil.copyfile(image, copied)
            images.append(copied)
        for scenario in ["files", "terminal", "nonblocking-pipe", "loaded"]:
            load = None
            try:
                if scenario == "loaded":
                    load = subprocess.Popen(
                        [sys.executable, "-c", "while True: pass"],
                        env={"PATH": "/usr/bin:/bin"},
                        preexec_fn=limits(cpus[0]),
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                for repetition in range(options.repeats):
                    cpu = cpus[0] if scenario == "loaded" else cpus[repetition % len(cpus)]
                    result = run_case(options, images, directory, scenario, repetition, cpu)
                    if baseline is None:
                        baseline = result
                    if result != baseline:
                        raise RuntimeError(f"{scenario}/{repetition}: output mismatch: {result} != {baseline}")
                    count += 1
            finally:
                if load:
                    load.terminate()
                    load.wait(timeout=5)
        if options.self_test:
            if baseline["status"] != "guest-exit 0":
                raise RuntimeError(f"probe failed: {baseline}")
            for failure in ["full", "broken-pipe", "file-limit"]:
                run_case(options, images, directory, failure, 0, cpus[0], failure=failure)
        if [digest(image) for image in images] != identities:
            raise RuntimeError("input image contents changed during the run")
    manifest = {
        "nixvm_sha256": digest(options.nixvm),
        "images_sha256": identities,
        "command": options.command,
        "branch_quantum": options.branch_quantum,
        "syscall_quantum": options.syscall_quantum,
        "mem": options.mem,
        "runs": count,
        "result": baseline,
        "cpu": cpu_identity(),
        "kernel": os.uname().release,
        "random_seed": "00" * 32,
    }
    if options.manifest:
        options.manifest.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    print(json.dumps(manifest, sort_keys=True))


if __name__ == "__main__":
    main()
