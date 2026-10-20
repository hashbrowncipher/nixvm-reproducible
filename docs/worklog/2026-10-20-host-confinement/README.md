# Linux host confinement

The Linux x86-64 CLI now confines its process before guest parsing or image
decompression. `/work` requires `--workdir`. Explicit directory roots and binds
use Landlock rules built from the same pinned descriptors used for traversal.
Image-only and in-memory runs deny path opens, directory enumeration and path
metadata. Directory runs permit `newfstatat`: it can disclose host metadata,
including timestamps of open EROFS archives. Landlock restricts contents, not
that metadata. Host symlinks and metadata changes fail safely; EROFS guest
symlinks remain supported.

Preparation closes inherited descriptors with `close_range`, rejects inherited
READ_IMPLIES_EXEC, and opens images, KVM slots, timers and PMU counters before
filtering. Capabilities, dumpability and new privileges are dropped. Seccompiler
checks the audit architecture and denies unapproved syscalls, executable host
mappings, networking and process creation. KVM and perf ioctls are scoped to
retained descriptors and exact requests. Those descriptors cannot be closed or
replaced. Landlock ABI 5, close_range and seccomp TSYNC are required.

`--vcpu-capacity` defaults to 128 concurrent guest tasks. Reusable slots reset
registers, debug/event state and XSAVE before reassignment. Exhaustion returns
EAGAIN before PID allocation or clone randomness. The default 8 GiB guest RAM pool
is configurable with `--mem`; it does not cap total host allocations or tmpfs.

Embedders remain unconfined unless they request `confine_host(true)` and use
`run`. Entry requires a dedicated single-threaded process. Perform one confined
run, then exit: restrictions persist when `run` returns. Unsupported requested
confinement fails closed. Other CLI targets retain their existing behavior.

The branch merged local master `fba3a0b` as `35d1a56`. It preserves master's
executable-only deterministic host getrandom wrapper, ASLR preparation and
measured virtual clock. The host stream remains independent of guest randomness.
Measured execution requires one scheduler CPU, rejected before confinement when
configured otherwise. An unused prepared scheduler seam was removed; existing
unconfined SMP tests remain. Synthetic prepared-thread tests verify Landlock
inheritance, privilege drops and TSYNC.

## Validation

Environment: Linux x86-64, installed Rust 1.93.1, committed Cargo.lock. All test
execution used the parent seal without network or credential stores. Synthetic
probes use their own temporary files, never real private files.

| Check | Result |
|---|---|
| Parent default test helper | 855 passed, 19 ignored |
| Full `cargo test --all-features --offline --locked` | 888 passed, 19 ignored |
| Confinement library tests with ignored hardware cases enabled |9 passed |
| Confined CLI suite with hardware cases enabled |5 passed |
| PMU suite with ignored hardware cases enabled |14 passed, including 13 hardware cases |
| Strict all-features/all-targets Clippy |passed |
| Strict all-features Rustdoc |passed; existing browser links corrected |
| Browser wasm library check, `--no-default-features --features wasm` |passed |
| Parent scoped Rust formatter |passed |
| `git diff --check` |passed |
| Vendor-only test step |incomplete, excluded per Owner |

The full-suite totals exclude the separate host-determinism executable's own
checks; that executable also passed. The 19 ignored tests comprise four library
hardware/manual cases, two CLI KVM cases and 13 PMU hardware cases. Explicit runs
above exercised the new KVM and PMU cases with `/dev/kvm` available. The two
remaining library ignores are existing manual semantic probes.

Negative subprocess probes verify forbidden filesystem, socket, process,
ptrace, architecture/x32, executable-mapping and personality calls terminate
with SIGSYS. Other probes verify inherited descriptor closure, prepared-thread
enforcement, allocator growth, passthrough stat/readdir/read, outside-root content
denial and accepted metadata access. KVM probes verify slot reuse beyond
capacity, exhaustion, register/XSAVE reset, protected close/dup denial and
wrong-role ioctl denial. Guest fork/exec and EAGAIN tests check guest-visible
behavior. The existing-API precision-tail PMU reproducer failed on `f903ee4` and
was committed before the fix as `047743c`; it passes on the merged source.

New approved dependencies are exactly pinned seccompiler 0.5.0 and landlock 0.4.7,
with Cargo.lock checksums. Existing pins were preserved; libc remains 0.2.186.
No vendor pin or toolchain file was changed. An attempted inherited parent
gate reached an unavailable vendor toolchain and uncached vendor-only test
dependencies. The Owner excluded that check and clarified that nixvm has no
landing gate. No vendor verification or landing-gate pass is claimed.

## Reusing the root checks

`checks.py` adapts absent npm layout and root Cargo ownership for the parent
helpers. Tests retain their sealed runner. The scoped formatter uses the parent
swept-language list. Parent helpers were not edited.

From the candidate checkout, set `PARENT_TOOLS` to the parent tools directory and
`CARGO_HOME` to the prepared locked cache, then run:

```sh
timeout --kill-after=5s 245s python3 docs/worklog/2026-10-20-host-confinement/checks.py \
  --tools "$PARENT_TOOLS" test .
python3 docs/worklog/2026-10-20-host-confinement/checks.py \
  --tools "$PARENT_TOOLS" format --check --swept --only rust src tests/pmu.rs tests/confinement.rs
```

## Debt and capital

1. A host syscall/resource inventory and reusable confinement subprocess harness
   would reduce work caused by libc fallbacks, teardown calls and hidden TLS
   descriptor ownership. This is cheap enough before adding a new host resource.
2. Standalone Cargo-root support in parent layout/format helpers would remove
   these adapters and make offline vendor test prerequisites visible sooner.
3. A directory broker would permit host symlinks without broad metadata authority;
   the current explicit limitation keeps this change scoped. Host memory limits
   would require a separate cgroup policy.

Implementation agent: Codex, GPT-6 family. Exact model variant, token counts and
tool-use counters were unavailable. Independent review was arranged separately;
final reconciliation remains with the integration owner.

Final feature diff against merged master: 21 files, 2176 insertions and 153 deletions.
