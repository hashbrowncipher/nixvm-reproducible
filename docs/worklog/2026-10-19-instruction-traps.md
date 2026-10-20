# KVM instruction interception

Added the approved iced-x86 1.21.0 dependency with only `std` and `decoder`
features, compiled on Linux x86-64. Cargo.lock records it and lazy_static 1.5.1
with checksums; existing dependency versions did not change.

KVM now sets CR4.TSD and installs #GP and #UD interrupt gates alongside #PF.
Exception handling recovers the user registers, stack and segments before
reporting a fault. iced-x86 identifies RDTSC at the saved RIP; emulation supplies
the logical timestamp in EDX:EAX and advances RIP by the decoded length.
One atomic counter belongs to the VM, shared across vcpus and address spaces.
RDTSC and each actual syscall entry advance it by one. Re-delivering a blocked
syscall does not advance it. Fork and exec retain the same VM timeline. The
interpreter retains its existing counter policy; this change targets KVM.
Unrelated #GP becomes ProtectionFault and #UD becomes IllegalInstruction.
RDTSCP, RDRAND and RDSEED remain masked in the existing CPUID profile.

Instruction fetching walks the cached CR3 without borrowing GuestMemory, checks
user execute permission and reads only as many bytes as decoding requires.
The shared page walker now checks canonical addresses and physical bounds and
combines permissions across all four levels. Preemption accounts for the whole
run, including repeated emulated instructions, so timestamp loops still yield.
Interrupted exception trampolines recover user state before yielding, so another
thread cannot overwrite a live exception frame. Noncanonical instruction fetches
remain protection faults, including when the missing byte is an instruction tail.

The vDSO stays mapped with its existing syscall fallback. KVM no longer supplies
a hardware-TSC calibration, since a counter of reads cannot measure elapsed
nanoseconds. Clock syscalls retain the existing clock policy; full environment
determinism remains further work.

Validation on Rust 1.93.1, Linux x86-64:

- The initial timestamp test failed against the old calibration behavior.
- Seven integration tests passed on real KVM: both run paths, fork/reset,
  preserved flags/registers, valid prefixes through the 15-byte limit, page
  boundaries, excessive length, unrelated #GP/#UD, masked instructions and
- Review reproduced shared exception-frame corruption when preempting a trap,
  noncanonical #GP misclassification as MemFault, and an interrupted user PC
  being mistaken for a supervisor frame. All three regressions failed first
  and were committed before their fixes, in d030943, 8cf7b71 and 461f6eb.
  The fixes pass. Two decoder unit tests cover permissions and missing bytes.
- The final offline sealed suite passed in 5.52 seconds: 767 passed, two
  existing ignored, including both review fixes and the shared syscall/timestamp
  clock. It ran through the parent repository's test tool with the
  established standalone-crate adapter documented in the CPUID worklog.
- The wasm32 library check with no default features passed. The repository
  formatter check and `git diff --check` passed.
- Independent review approved the final change. Its real-KVM checks, pinned to
  one CPU, included 2,500 alternating-vcpu slices and 10,000 user-PC/signal
  iterations. Final integration tests took 0.29 seconds excluding compilation;
  exception snapshot tests took 0.03 seconds. One reviewer used the parent
  model and made no source edits. Token and tool-use counters were unavailable.
  The reviewed source/test diff against 7ab9855 was 600 added and 153 removed
  lines across eleven files, excluding this record.

Capital notes, ranked:

1. A shared exception-frame recovery path now avoids repeating the old #PF
   logic when adding further intercepted instructions.
2. A clock policy shared by timestamp instructions and clock syscalls would
   make the next deterministic-time change coherent. It is separate from
   instruction interception and has not been implemented here.
