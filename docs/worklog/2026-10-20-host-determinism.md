# Linux host randomness and address layout

Linux executables now export `getrandom` at the executable link boundary and
forward to a separate, process-wide buffered ChaCha20 stream. The stream uses
`NIXVM_HOST_RANDOM_SEED` (exactly 64 hexadecimal digits), with 32 zero bytes
when unset. It never advances guest randomness or follows guest clone reseeding.
Lazy initialization allocates nothing and reads neither OS entropy nor time.
Malformed seeds use zeros before startup; explicit startup rejects the
configuration without printing its value. Calls obey Linux flag/errno rules
and return at most 256 bytes. The helper's safety contract requires a valid
writable buffer; it cannot diagnose arbitrary invalid addresses as EFAULT.

Every Linux binary prepares the host before parsing arguments. It preserves
existing personality bits, sets `ADDR_NO_RANDOMIZE`, verifies the real flag,
and re-executes `/proc/self/exe` when needed. There is no environment marker.
Personality/exec errors fail startup. Raw argv including argv[0], environment,
cwd, inherited stdio and PID survive. Non-Linux preparation is a no-op.
Linking the library exports no override and changes no personality. Embedders
opt in through `host::prepare` and an executable wrapper for
`host::prepared_getrandom`.

The tested Rust 1.93.1 stdlib explicitly uses a weak `getrandom` symbol in
`std/src/sys/random/linux.rs`; its HashMap keys use that route. Raw syscalls
and unrelated native entropy interfaces are outside this interception.
Repeatability requires the same toolchain and order of host RNG requests,
including thread ordering. The predictable stream is unsuitable for secrets
or hostile hash inputs. Initialization must not race environment mutation;
the host RNG mutex is not signal-safe. Linux must permit the personality
change and expose `/proc/self/exe`.

Validation used Rust 1.93.1 (`01f6ddf75`, x86_64-unknown-linux-gnu), the existing
Cargo.lock pins and cached artifacts, from baseline `f903ee4`. Regression
commit `2f7de6a` first demonstrated unequal std RandomState hashes from fresh
processes with the same seed. This record belongs to the implementation commit.
All Cargo commands below ran offline and sealed through the established
standalone-root adapter for the parent repository's test helper. Each operation
remained within the 260-second limit. No downloads or installs were needed.

- `cargo test --offline --locked`: passed, 817 harness-counted tests and eight
  existing ignores, plus the standalone host integration executable.
- `cargo test --offline --locked --features erofs,fstool,tunnel`: passed, 848
  harness-counted tests and eight existing ignores, plus host integration.
- `cargo test --offline --locked --test host_determinism`: passed. Fresh-thread
  std RandomState and HashMap hit the instrumented exported wrapper while
  seccomp denied real getrandom and random-device opens. Equal, changed and
  unset seeds behaved as expected. Tests cover real pre-main allocation-free
  initialization, concurrent first calls, invalid/non-UTF8 seeds and ABI errors.
- Host integration checked real enabled/re-exec and already-disabled startup,
  exactly one successful exec, raw non-UTF8 argv/env, cwd, PID and stdio, and
  equal final code addresses across three disabled layouts. Machine details
  stayed in local temporary logs. All three binaries reject invalid seeds.
- `cargo test --offline --locked --lib host::`: passed. This covers host/guest
  independence and narrow personality/exec failure seams. Existing guest clone
  and random tests passed unchanged in both full suites.
- `cargo clippy --offline --locked --all-targets --features erofs,fstool,tunnel -- -D warnings -A clippy::field_reassign_with_default`:
  passed. Only the existing baseline lint was allowed. Default all-target
  Clippy also passed.
- `cargo check --offline --locked --target wasm32-unknown-unknown --no-default-features --lib`:
  passed.
- `cargo rustdoc --offline --locked --lib -- -D warnings`: passed.
- `nm -D --defined-only`: all three executables export getrandom; the cdylib
  does not. Scoped Rust formatting and `git diff --check` passed.

Independent review is pending. Nothing was merged or pushed. Implementation
agent: Codex, inherited GPT-6 model; exact model variant and per-agent usage
counters were unavailable. Diff: 12 files, +1,041/-13 versus f903ee4.

Capital notes, ranked:

1. The standalone-root adapter was the main tooling friction. A supported
   parent-runner entry point for vendor worktrees would remove temporary
   bridges. This is cheap before another change in this crate.
2. Host policy spans the stdlib link boundary and exec lifecycle. The committed
   fresh-process probes and narrow process seam now make that boundary
   reviewable and provide a reusable test base for future startup changes.
