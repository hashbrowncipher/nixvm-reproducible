# Count branches only while guest tasks compete

Disabled the PMU counter when only one guest task is runnable. The serial
scheduler checks for runnable peers before each backend run, including after
clone and wakeups. Parked, stopped and exited tasks do not require preemption.
New contention starts a fresh quantum. Solo execution leaves the branch total
unchanged and does not open a perf counter, pin the host thread or single-step.
Direct vCPU callers set their policy through `set_preemption_required`.

Validation used Rust 1.93.1 and the unchanged Cargo.lock. From the PMU worktree:

```sh
python3 ../../../../tools/sealed.py cargo test --offline --locked --quiet
python3 ../../../../tools/sealed.py cargo test --offline --locked --test pmu -- --ignored --test-threads=1 --nocapture
python3 ../../../../tools/sealed.py cargo clippy --offline --locked --all-targets -- -D warnings -A clippy::field-reassign-with-default
```

The default suite passed, including 733 library tests with two ignored. All
three explicitly enabled PMU hardware tests passed on the Intel Core i5-12500T
outside the assistant sandbox. The new hardware test compares branch counts
with an independent guest loop register: solo execution exceeds the quantum
without counting, contention stops at exactly 16 branches, disabling leaves
the tail uncounted, and re-enabling grants another full quantum. Scheduler
tests exercise clone, wait, exit, explicit wakes and expired sleepers.

Clippy passed with the existing allowance for a test initializer in
`src/vcpu/kvm/vm.rs`. Rust formatting passed through the parent repository's
formatter helper with this crate's explicit manifest. The changes remain in
`.worktrees/pmu` on `nixvm-pmu`.

Debt: guest readiness still uses the existing timer checks. Integrating the
shared logical clock with sleeper wakeups is the next scheduling investment;
it will make readiness checks agree with syscall and timestamp time advances.
Root-level Rust crate discovery in the parent's tools remains the small tooling
investment recorded in the initial PMU worklog.
