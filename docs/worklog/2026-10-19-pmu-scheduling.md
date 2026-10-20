# Add PMU scheduling to the KVM backend

Added opt-in conditional-branch quanta through `NIXVM_BRANCH_QUANTUM` and
`KvmBackend::with_branch_quantum`. The scheduler keeps a quantum across syscalls
and faults, and uses branch counts for task ordering. PMU mode requires one
scheduler CPU and disables wall-clock preemption.

The counter excludes host execution and guest supervisor code. Each hardware
entry pins the calling thread while selecting and using its CPU's PMU profile.
Overflow requests an early stop; single-stepping reaches the exact branch
boundary. Late overflows, unavailable counters and failed cleanup return errors.
Host interrupts are internal exits. Forked vCPUs retain the mode with fresh
counter state.

The implementation used rr's `src/PerfCounters.cc` at
`b5696b76b706d347ddb99eb7ab99bd8e7b8f13c2` and dhyve's
`dhyve/sys/amd64/vmm/intel/vmx_det.c` at
`55d90e06afefb158f68e6bbb6a7124f5f8c6af68` as references. It does not copy either
project's counter implementation.

Validation used Rust 1.93.1 and the unchanged Cargo.lock. The approved
`cargo fetch --locked` populated the registry cache without changing pins.
From the worktree, the commands were:

```sh
python3 ../../../../tools/sealed.py cargo test --offline --locked --quiet
python3 ../../../../tools/sealed.py cargo clippy --offline --locked --all-targets -- -D warnings -A clippy::field-reassign-with-default
```

The default suite passed, including 729 library tests. Two existing library
tests and the two new PMU hardware tests were ignored. Clippy's allowance is
for an existing test initializer in `src/vcpu/kvm/vm.rs`. Formatting used the
parent repository's `tools/format.py` runner with this crate's explicit manifest;
its CLI does not discover a standalone crate at the Git root.

Hardware validation remains open: this environment has no `/dev/kvm`. Run:

```sh
cargo test --offline --locked --test pmu -- --ignored --test-threads=1
```

Those tests require actual KVM and guest-only perf access. They compare PMU
counts and stopping PCs against a guest loop counter, exercise repeated slices
and syscall exits, and check that host stepping does not expose TF. They fail
when explicitly requested without the required hardware.

Guest clocks, entropy, filesystem publication and host-process forks are outside
this change. A branch-free loop cannot exhaust a conditional-branch budget.
The branch remains separate from the primary checkout.

Debt: the parent repository's test and formatter discovery assumes a Node root.
Supporting a root-level Rust crate would remove the manual wrapper invocation
before the next change here. The next PMU investment is a hardware test runner
that can exercise both Intel core types and overflow under host load.
