# Merge runnable-task PMU gating

Resolved the pending merge of `2a50a3b` (`nixvm-pmu`) into `cf3a986`
(`master`). Kept the optional PMU run guard and the remaining wall-clock
budget across internal KVM exits. Kept both hardware tests and enabled
preemption explicitly in the timestamp-trap test.

Independent review found that disabling counting for solo execution also
removed its only preemption source. A solo compute loop could prevent a
sleeping peer or an embedder's budget from reaching the kernel. The fix keeps
the configured wall-clock quantum while PMU counting is disabled. Runnable
competition uses the exact branch quantum. `NIXVM_QUANTUM_MS=0` still disables
wall-clock yields.

## Validation

Checks use the unchanged `Cargo.lock`, Rust 1.93.1, Linux x86-64, and the
existing offline Cargo cache at `target/cargo-home`. Commands run through the
parent repository's seal with network access disabled. The seal needs sandbox
escalation to create its namespaces.

The direct solo-loop regression failed before the fix by reaching its external
timeout. Its plain and timestamp-trapping loops pass after the fix, leave branch
counts at zero, and use the exact branch budget when contention is enabled.
Separate test-first commits were not possible in the unresolved merge index.

An alarm probe exposed a separate existing limitation: KVM's
`async_signal_boundary()` always returns false, so a syscall-free guest defers
pending signal delivery. The baseline has the same behavior. The final kernel
regression checks `pump_for` returning control instead of requiring asynchronous
signal delivery.

Final checks passed:

- Full sealed `cargo test --offline --locked --features erofs,fstool --quiet`,
  through the standalone test-tool adapter: 756 library tests passed, two
  existing library tests ignored, and all integration and documentation tests
  passed. The six explicit hardware tests were ignored in this default run.
- Sealed `cargo test --offline --locked --test pmu -- --ignored
  --test-threads=1`, pinned to one permitted CPU: all six hardware tests passed.
  These include repeated plain and timestamp-trapping solo execution, exact
  contention budgets, mode transitions, syscall budget preservation, and two
  `pump_for` calls returning `Busy` from a syscall-free solo loop.
- Sealed `cargo clippy --offline --locked --all-targets --features erofs,fstool
  -- -D warnings -A clippy::field-reassign-with-default`: passed. The allowance
  covers the existing VM test initializer documented in the earlier worklogs.
- Parent formatter check for every changed Rust file, and `git diff --check`:
  passed.

The parent landing helper fails before planning checks because this standalone
crate has no root `package.json`. The full suite uses the established
in-process `layout.packages` adapter from the EROFS worklog. The formatter uses
the root-crate `layout.owner` adapter from the CPUID worklog. No parent tooling
was changed.

## Review and capital

An independent reviewer read the complete merge diff and found the solo timer
defect. A second agent implemented the focused regression and correction. Both
use the inherited GPT-6 based Codex model; exact model identifiers, token
counts, and tool-use counters are unavailable. The initial review covered
seven paths with 315 additions and 22 deletions. The reviewer then checked the
correction and final regressions and returned `MERGE`, with no open findings.
The final reviewed source and incoming worklog span seven paths with 403
additions and 36 deletions, excluding this merge record. The implementation
agent's four paths contain the timer correction, tests and README update.

1. Standalone Cargo-root support in the parent validation helpers would remove
   repeated adapters. This remains a small investment before the next change.
2. Deadline delivery and branch accounting need tests together when PMU policy
   changes. The hardware regressions added here cover that interaction.
