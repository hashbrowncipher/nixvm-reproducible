# Enforce reproducible KVM runs

Implemented the six short-term items from the reproducibility assessment, based
on `f7c4623`. The failing regressions were committed first as `615656e` and
`7ef6136`. They exposed backend directory order, host output errors becoming
guest EIO, injected TF in PUSHF and exception frames, and incorrect guest debug
traps. The watchdog configuration test also failed before the guard existed.

1. `--reproducible` requires EROFS, confinement and one measured KVM CPU. It
   rejects host directories, bind mounts, interpreter fallback and ambient
   `NIXVM_*` settings. Branch and syscall quanta have explicit flags. Guest
   stdin reads return zero without reading or closing host fd 0. Host terminal
   forwarding and its stdio ioctl permissions are disabled.
2. Precision stepping scrubs injected TF from PUSHF, syscall registers and
   exception frames. POPF emulation preserves stepping. Guest-owned TF and
   INT1 deliver debug traps consistently with and without precision stepping.
3. A shared output handler acknowledges complete guest writes, finishes partial
   host writes and polls nonblocking sinks without clearing shared flags. It
   latches permanent errors and fails the run after guest execution. Confined
   SIGPIPE and SIGXFSZ become write errors. A host-only status file separates
   sandbox failures from guest output and guest exit 125.
4. Measured KVM has no host watchdog. Nonzero or invalid `NIXVM_QUANTUM_MS`
   settings fail setup. Foreign interrupts resume the same execution slice.
   Direct-driver tests use branch allowances or virtual deadlines. A branchless
   infinite loop still requires an external process timeout.
5. `tools/check_reproducibility.py` compares outputs across changed cwd,
   environment, limits, image timestamps, CPU affinity, terminal settings, host
   load and nonblocking output. Its synthetic fixture forks competing tasks and
   checks stdin, terminal queries/setters, TF and virtual time. Its self-test
   also checks full sinks, broken pipes and file-size limits. A manual hardware
   workflow requires a self-hosted runner labeled `nixvm-pmu`.
6. Both getdents layouts sort names by bytes before applying directory cursors.
   The regression uses reversed backend order, short buffers and rewind.

Validation used Rust 1.93.1, the committed Cargo.lock, Linux
`7.0.0-rc3-local`, and an Intel i5-12500T, family 6/model 151/stepping 5,
microcode `0x3a`. Tests and the final harness ran through the enclosing
repository's sealed runner, outside the agent filesystem sandbox so KVM/perf
were available. All dependency access was offline. No dependencies changed.

```sh
cargo test --offline --locked --features fstool,erofs,tunnel
cargo test --offline --locked --features erofs \
  --test pmu --test confinement --test reproducible_cli \
  -- --include-ignored --test-threads=1
cargo test --offline --locked --features erofs --lib confinement::tests:: \
  -- --ignored --test-threads=1
cargo clippy --offline --locked --all-targets --features fstool,erofs,tunnel -- -D warnings
cargo clippy --offline --locked --all-targets -- -D warnings
cargo build --offline --locked --features erofs --bin nixvm
python3 tools/check_reproducibility.py --nixvm target/debug/nixvm --self-test --repeats 3
```

The native suite passed 899 tests with 27 ignored. The targeted PMU/confinement
suite passed all 30 tests, including the explicit hardware cases. The two
hardware-only library confinement tests also passed. Twelve host
perturbation runs produced identical output and guest status; all three output
failure cases produced sandbox errors. Rust/Python formatting and
`git diff --check` passed. The enclosing formatter's root-crate discovery does
not recognize this Cargo root, so its formatting helpers were invoked directly.

Reproduce the probe from the commit containing this record. Generate its image
with `python3 scripts/make-reproducibility-fixture.py`; the committed image is
independent erofs-utils output. Image SHA-256:
`8f4e210473ef180759aca47befc225453a3b3c7d12af4d4ea221b5931277e534`.
The command was `/init`, with a zero random seed, 128 MiB RAM, four vCPU slots,
branch quantum 64, syscall quantum 16, and one scheduler CPU. Expected results:

| Output | Expected |
| --- | --- |
| stdout SHA-256 | `fe85f9ba24934cdb11eb16d36cfa3a7eb5634a9c23d4a5571bdad6f176bf3aa6` |
| stderr SHA-256 | `7734e1b38f8572e874ec5fb004e1da8c1f0b37dcf5d62c313afa5d4f670d170c` |
| status | `guest-exit 0` |

The initial broad runs reached their configured timeouts on tests that relied
on the removed watchdog. Their replacements now pass. A confinement regression
also caught an empty ioctl rule list, which seccompiler treats as unconditional
permission. The policy omits ioctl when there are no authorized requests.

CPU portability, passthrough metadata virtualization, stable layer inode
numbering and faster precision tails remain separate work. CPU model/core type
and outer PMU virtualization remain declared environmental inputs.

Debt and capital, ranked:

1. Runtime configuration is read in several modules. The mode's blanket
   rejection of ambient `NIXVM_*` settings gives new knobs a safe default;
   central configuration would make future explicit inputs easier to audit.
2. A real hardware runner is necessary to catch stepping and signal failures.
   The committed probe and manual workflow make repeat checks cheap before
   the next scheduler or confinement change.
