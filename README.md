# nixvm

[![CI](https://github.com/KarpelesLab/nixvm/actions/workflows/ci.yml/badge.svg)](https://github.com/KarpelesLab/nixvm/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/nixvm.svg)](https://crates.io/crates/nixvm)
[![docs.rs](https://img.shields.io/docsrs/nixvm)](https://docs.rs/nixvm)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Browser demo](https://img.shields.io/badge/demo-live-brightgreen.svg)](https://karpeleslab.github.io/nixvm/)

**A portable, VM-style sandbox that runs a real Linux userland by emulating
Linux syscalls directly — not by emulating hardware.**

nixvm lets you run normally-dangerous tasks (`npm install`, `pip install`,
untrusted build scripts, `apk add`, …) inside an isolated Linux environment,
with or without hardware virtualization.

## How it's different

A traditional VM (QEMU, Firecracker) boots a full guest Linux kernel and
emulates hardware: a CPU, interrupt controller, virtio devices, block devices.
That's heavy and slow to start.

nixvm takes the [gVisor](https://gvisor.dev/)-style approach instead: **there
is no guest kernel.** A real Linux *userland* (Alpine) runs directly on the
host CPU or a software interpreter. When a guest process executes a
`syscall`/`svc` instruction, control traps out and **nixvm's own "kernel" —
written in Rust — services the syscall.** Files, memory, processes, threads,
signals, and networking are all implemented in userspace, under our control.

## Try it in your browser

**▶ [karpeleslab.github.io/nixvm](https://karpeleslab.github.io/nixvm/)**

Because the whole thing — the CPU interpreters *and* the syscall kernel — is
portable Rust with no OS dependencies, it compiles to WebAssembly and runs
entirely in the page. There's no server: a real Alpine Linux userland boots
locally, in a sandbox, inside your browser's sandbox.

- **Pick a guest architecture** — arm64 or x86-64 — and press Start: the
  matching stock Alpine minirootfs boots to an interactive `busybox sh`
  (dynamic linking, real `ld-musl`, fork/exec — the same kernel the native
  build runs).
- Everything is client-side: the rootfs is repacked into an in-memory
  squashfs under a copy-on-write tmpfs upper, and the guest runs on the
  software CPU interpreter for whichever arch you picked.

CI rebuilds and redeploys it to GitHub Pages on every push to `master` (see
[`.github/workflows/pages.yml`](.github/workflows/pages.yml)); the frontend
is the Vue app in `web/` and the wasm entry point is `src/wasm.rs` (which
also still exposes the original static-ELF runner, `run_elf`).

## Status

Functional on the software-interpreter path: a real Rust syscall kernel, two
working CPU interpreters (aarch64 and a growing x86-64), static, static-PIE, and
**dynamically-linked** ELF loading (real `ld-musl` boots stock Alpine and loads
large C++ programs' full shared-library graphs, e.g. node's ~15 libs),
multi-threaded/multi-process scheduling with an SMP worker-thread pool
(POSIX threads share one fd table, so libuv's cross-thread wakeups work), an
in-VM network stack, and several filesystem backends — all covered by 505 tests
(`cargo test`). **Node.js runs** — on the software interpreter *and* the
hardware backends: `node -e …` executes real JavaScript to completion — event
loop, `setTimeout`/`setInterval`, promises, JSON, stdio — and exits cleanly,
including a hot loop that tiers up to V8's TurboFan JIT with concurrent
background compilation on. Floating point is a dependency-free **soft-float**
(bit-identical on native and wasm) that models what `f64` hardware can't:
**true 80-bit x87** extended precision and SSE **`MXCSR` directed rounding** +
IEEE exception flags — validated bit-for-bit against the host's native
arithmetic and against real x87/SSE hardware via KVM. Hardware acceleration is live on both target hosts: the **HVF
backend (macOS/arm64) runs a static program end-to-end**, and the **KVM backend
(Linux/x86-64) runs a real statically-linked glibc binary end-to-end on real
hardware** (long mode at ring 3, `syscall` trapped via an `LSTAR` trampoline,
TLS via `arch_prctl`). `vcpu::select` prefers hardware and falls back to the
interpreter, which remains the portable default and the everywhere-CI path.
See [ROADMAP.md](ROADMAP.md) for the phased plan and what's next.

## What works today

| Area | Status |
| --- | --- |
| **Guest architectures** | aarch64 (interpreter, primary target); x86-64 (interpreter, growing) |
| **Execution backends** | software interpreter — **working** (portable, CI-tested). HVF (macOS/arm64) — **runs a static program end-to-end on hardware** (guest MMU-off at EL0, `svc` trapped via an EL1 stub); needs a codesigned binary (`scripts/hvf-test.sh`). KVM (Linux/x86-64) — **runs a real static glibc binary end-to-end on hardware** (guest at CPL3 in long mode over fixed identity page tables, `syscall` → `LSTAR` trampoline → `KVM_EXIT_HLT`); no entitlement needed, its tests run under plain `cargo test` wherever `/dev/kvm` is accessible and skip elsewhere. `vcpu::select` prefers hardware and falls back to the interpreter (`NIXVM_INTERP=1` forces it); dynamic linking + multi-process on the hardware backends are the follow-up. KVM/arm64 — not started. |
| **ELF loading** | static (`ET_EXEC`), static-PIE (`ET_DYN` with `R_*_RELATIVE`/`R_*_IRELATIVE` fixups), and **dynamic linking** (`PT_INTERP` → `ld-musl`, file-backed `mmap` of `.so`s) — working; real Alpine boots on the interpreter. |
| **Processes & threads** | `clone`/`fork`/`execve`/`wait4`/`exit(_group)`; `CLONE_VM`+`CLONE_THREAD` shared-address-space threads; real `futex` WAIT/WAKE parking |
| **SMP scheduler** | a pool of `ncpus` host worker threads run guest compute in parallel; syscalls are serviced serially on the main thread (a big-kernel-lock model, `Kernel::set_ncpus`/`NIXVM_CPUS`) |
| **Signals** | `rt_sigaction`/`rt_sigprocmask`/`kill`/`tgkill` and default-disposition delivery (terminate/ignore) — **custom handler invocation (frame push + PC redirect) is not implemented** |
| **Filesystem** | `tmpfs` (rw in-memory), `overlay` (COW upper/lower), format-independent read-only layer stacks, `passthrough` (host dir, **symlink/TOCTOU-safe** — see below), `devfs`, `procfs`, `sysfs`; EROFS images (`erofs` feature) and squashfs/ext backends (`fstool` feature) |
| **Networking** | in-VM AF_UNIX + AF_INET/AF_INET6 loopback (TCP stream + UDP datagram), plus **host-passthrough egress** (opt-in `NIXVM_NET=host`, native only): guest TCP/UDP to routable addresses is bridged to real host sockets, so **`apk update && apk add` work over the real internet on x86-64**. DNS via a host UDP socket + injected `/etc/resolv.conf`. A browser (WebSocket/pktkit) transport and a `smoltcp` NAT stack are the follow-ups. |
| **I/O multiplexing** | `poll`/`ppoll`/`select`/`pselect6`, `epoll_create1`/`ctl`/`wait`/`pwait2`, `eventfd2`, `timerfd_*` |
| **Browser demo (wasm)** | working — [**live demo**](https://karpeleslab.github.io/nixvm/): `wasm32-unknown-unknown` + interpreter, built and deployed to GitHub Pages by CI on every push to `main` ([details](#try-it-in-your-browser)) |

The syscall dispatch table in `src/kernel/mod.rs` is broad: process/thread
lifecycle (incl. `waitid`/`clone3`/`execveat`), sessions & process groups
(`setsid`/`setpgid`/…), fd/file I/O including positioned/vectored
(`pread`/`pwrite`/`preadv`/`pwritev`) and copy (`sendfile`/`copy_file_range`),
`truncate`/`ftruncate`/`fallocate`, `statx`, `mmap`/`brk`/`mprotect`/`mremap`,
signals, networking (loopback + host egress, incl. `sendmsg`/`recvmsg`/
`sendmmsg`/`recvmmsg`), poll/epoll/eventfd/timerfd/`memfd_create`, and a set of
always-succeed/no-op syscalls (the `uid`/`gid` credential family, `sync`
family, `sched_*` setters, `Mlock*`, …) real programs probe at startup. A
busybox command battery, `apk`, and a dynamically-linked binary's startup all
dispatch with **zero** unsupported syscalls on x86-64. Anything not in the
table returns `ENOSYS` and is recorded in an `unsupported()` ledger you can
inspect after a run.

## Quickstart

```sh
cargo build --release
cargo test
```

### EROFS root layers

Build with `--features erofs` to read EROFS images through the locally vendored
`rust-fs-erofs` crate. Pass images in base-to-top order; the last image has
precedence:

```sh
cargo run --features erofs --bin nixvm -- run \
  --erofs base.erofs --erofs packages.erofs --erofs application.erofs \
  -- /bin/sh
```

The library API accepts the same order:

```rust
let code = nixvm::Sandbox::builder()
    .root_erofs_layers(["base.erofs", "packages.erofs", "application.erofs"])
    .command(["/bin/sh"])
    .run()?;
```

Images are opened read-only on the host at startup and read on demand. They do
not need extraction or a host filesystem mount. Directories merge; a higher
file or symlink hides the lower subtree. The generic `fs::LayerStack` handles
layer precedence, character-device `0:0` whiteouts, zero-length regular-file
whiteouts marked with `trusted.overlay.whiteout` or `user.overlay.whiteout`,
and opaque directories marked with `trusted.overlay.opaque=y` or
`user.overlay.opaque=y`. It keeps inode identities distinct across images and
preserves hard links within an image. `fs::ErofsMount` only reads the format;
the layer merger works with any `MountFs` backend.

Overlayfs directory redirects and metadata-only copies (`metacopy`) are
unsupported and return `EOPNOTSUPP` when encountered.

Guest writes go to the existing ephemeral tmpfs upper. Saving changes as a new
EROFS layer is deferred; [the writing task](tasks/erofs-writing.md) records that
work. The guest path interface uses UTF-8 strings, so names and symlink targets
that are not UTF-8 return `EILSEQ`.

On macOS/arm64 the HVF backend is exercised by a separate, `#[ignore]`d test
suite (it needs a binary codesigned with the `com.apple.security.hypervisor`
entitlement, which `cargo test` can't do for itself):

```sh
scripts/hvf-test.sh          # builds, ad-hoc codesigns, runs the HVF tests
```

The `nixvm` CLI and `Sandbox::run()` load the command from the selected guest
root. Use `--root <directory>` for an extracted rootfs or `--erofs` for images.
To run a static ELF directly, use the dev harnesses or `Sandbox::exec_elf()`:

```sh
# Run a statically-linked aarch64 ELF on the interpreter:
cargo run --bin run-elf -- ./some-static-aarch64-binary

# Same, for a statically-linked x86-64 ELF:
cargo run --bin run-elf-x86 -- ./some-static-x86_64-binary
```

Useful environment variables (both harnesses):

- `NIXVM_ROOT=/path/to/alpine-rootfs` — mount `/` as
  `overlay(passthrough(NIXVM_ROOT) read-only, tmpfs)` instead of a bare tmpfs,
  so the guest sees a real Alpine tree with a copy-on-write upper.
- `NIXVM_CPUS=N` — run guest compute on `N` host worker threads (the SMP
  scheduler); default is `1` (single-threaded cooperative scheduling).
- `NIXVM_TRACE=1` — log every dispatched syscall (`pid`, `pc`, name, raw
  number, args) to stderr.
- `NIXVM_INTERP=1` — skip the hardware-backend probe in `vcpu::select` and run
  on the software interpreter (a debugging/parity escape hatch).
- `NIXVM_NET=host` — enable host-passthrough network egress: guest sockets to
  routable addresses reach the real internet via host sockets (native only;
  off by default = loopback-only). Lets `apk`/`wget`/`curl` fetch from the
  network.

The x86 CPU identity and feature bits come from `cpuid.toml`, embedded at build
time for both KVM and the interpreter. The profile includes AVX/AVX2 and a fixed
832-byte x87/SSE/YMM XSAVE layout. KVM checks host support and rejects an
incompatible hardware backend; automatic backend selection can use the interpreter.
`/proc/cpuinfo` and ELF hardware capabilities use the same profile. KVM emulates
`RDTSC` and `RDTSCP` with a shared logical counter. See [CPU instruction policy](docs/cpu.md)
for timestamp and randomness behavior.

### Seeded randomness

`getrandom()` and the synthesized `/dev/random` and `/dev/urandom` devices
consume one sandbox-wide ChaCha20 byte stream from `rand_chacha`, without
reading host entropy or time. Explicitly passed-through host devices remain
host I/O.
The initial seed defaults to 32 zero bytes. Set it with
`Sandbox::builder().random_seed(seed)`, where `seed` is `[u8; 32]`, or pass
`--random-seed` followed by 64 hexadecimal digits to `nixvm run`.
Fixed seeds make output predictable.

A successful clone without `CLONE_VM` reseeds the shared stream for every
task and device mount. It consumes the next 32 bytes, XORs the child's
little-endian 32-bit PID into the first four bytes, and uses that as a fresh
ChaCha20 seed. Clones with `CLONE_VM`, including vfork, do not reseed.
Device writes are discarded, random-device mmap returns `ENODEV`, and
mounting devtmpfs joins the current stream.
Read boundaries preserve every byte. Replay requires the same seed, random
reads and clone order; host scheduling, clocks and external I/O remain separate.
ELF `AT_RANDOM` and CPU randomness instructions retain their own deterministic
policies.

## Default sandbox layout

```
/           tmpfs by default; overlay(read-only root, tmpfs) when selected
/work       the host's current working directory, passed through read-write
/tmp,/dev,  synthesized in-sandbox (tmpfs / devfs / procfs / sysfs)
/proc,/sys
```

## Design notes

- **Single crate, feature-gated deps.** Everything lives under one `nixvm`
  crate (`abi`, `vcpu`, `loader`, `fs`, `kernel`, `image`, `sandbox`) instead
  of a workspace; heavy or platform-specific dependencies are opt-in cargo
  features (`hvf`, `kvm`, `interp`, `fstool`, `wasm`, `cli`) rather than
  separate crates. The core builds fully offline with zero third-party
  dependencies.
- **`unsafe` policy.** `unsafe` is confined to four documented sites; the
  interpreter and kernel paths have none. (1) `vcpu::hvf` — the
  Hypervisor.framework FFI (`hv_vm_*`/`hv_vcpu_*`) — and `vcpu::kvm`, its
  Linux equivalent (hand-rolled `/dev/kvm` ioctls, structs verified against
  the kernel headers, plus the mmap'd per-vcpu `kvm_run` page).
  (2) `vcpu::region` — one 16 KiB-aligned `alloc_zeroed`
  allocation of guest RAM (a hardware backend maps its raw pointer into the
  guest; safe `std` can't express over-aligned allocation), with all raw
  pointer access wrapped in checked copy methods. (3) `fs::passthrough` —
  hand-declares a handful of dirfd-relative `*at(2)` FFI calls (`openat`/
  `unlinkat`/`mkdirat`/`symlinkat`/`renameat`/`readlinkat`/`fdopendir`/
  `readdir`) because safe, TOCTOU-free path confinement genuinely requires them
  and `std` exposes none of it. Resolution walks the host path one component at a time
  from a dirfd opened on the mount root, with `O_NOFOLLOW` on every
  component; a symlink is never handed to the kernel to auto-follow — its
  target is read and re-spliced into the walk, re-anchored so an absolute
  target or a `..` chain can never resolve above the mount root. The final,
  actual I/O syscall is always issued directly against `(parent_dirfd, name)`
  with `O_NOFOLLOW`, so even a symlink swapped in mid-race fails safely
  instead of redirecting the I/O.

## License

MIT — see [LICENSE](LICENSE).
