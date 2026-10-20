# Drain PMU overflow notifications

Confined workers keep signal 41 blocked outside KVM_RUN. An overflow left it
pending, so subsequent KVM_RUN calls returned EINTR without executing guest
instructions. The counter now disables and drains its queued notifications
with a zero-timeout sigtimedwait before restoring the host mask. Guard cleanup
also drains on errors. The wait consumes only signal 41. Confinement permits
rt_sigtimedwait.

The regression tests were committed as afe1cee before the fix. Guard cleanup
left overflow signals pending, and the confined wait died with SIGSYS. Both
tests pass with the fix. The cleanup test queues three overflow notifications
and an unrelated signal, then checks that only overflow notifications were
consumed and the mask remains blocked.

Validation used Linux x86-64, Rust 1.93.1, the committed Cargo.lock, the
existing offline dependency cache and real KVM outside the agent sandbox.
The all-features suite passed: 894 tests, zero failures, 21 ignored. All 17
explicitly requested hardware tests passed: 13 PMU tests and four confined CLI
tests. New hardware cases cover competing tasks crossing repeated 4096-branch
quanta and solo computation interrupted by a 4096ns timer. Existing PMU tests
cover exact boundaries and restoring unconfined callers' affinity and masks.

Using the existing local Debian EROFS image, this command timed out at the
configured eight-second limit before the fix. It prints 2000 and exits zero
after the fix, with the default quantum and NIXVM_BRANCH_QUANTUM=65536:

```sh
nixvm run --erofs bookworm.erofs -- /bin/dash -c \
  'i=0; while test "$i" -lt 2000; do echo "$i"; i=$((i+1)); done | /usr/bin/wc -l'
```

The image SHA-256 is
`0cf879a77e81d846b9e07c49fea84aca074f2596ba54027228a23b704afc2510`.

The full suite and hardware suites used the parent sealed runner. Strict
all-features/all-targets Clippy, scoped formatting and git diff --check passed.
No dependencies were added or fetched.

Debt and capital:

1. Counter accounting and host-signal cleanup share a lifecycle. Testing guard
   cleanup without perf or KVM makes pending-signal failures cheap to reproduce.
2. The confined hardware suite needs compute spans longer than the PMU skid
   allowance. The new synthetic programs cover both fairness and timer paths
   without requiring an external root image.
