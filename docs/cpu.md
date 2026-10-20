# CPU instruction policy

The x86 CPU profile in `cpuid.toml` is shared by KVM and the interpreter.
It advertises `RDTSC`, `RDTSCP` and `RDPID`. `RDTSC` and `RDTSCP` return a logical
timestamp in EDX:EAX; `RDTSCP` also returns a fixed `TSC_AUX` of zero in ECX, and
`RDPID` returns the same zero. Host CPU identity and migration do not affect that
value.

KVM traps both timestamp instructions through CR4.TSD and the guest #GP handler.
The kernel and all vCPUs share one `VirtualClock`, including after fork and exec.
`RDTSC` and `RDTSCP` return its monotonic nanoseconds. Clock syscalls, timers and
generated virtual filesystem timestamps use the same authority. Realtime adds
the fixed Unix epoch of 1,700,000,000 seconds. These clocks and timers advance
independently of host time. Existing imported filesystem metadata remains input.
Passthrough filesystem metadata and time behavior remain host provided.

Each KVM retired conditional branch contributes one virtual nanosecond, even
when one task runs alone and never observes time. The x86 interpreter uses the
same conditional-branch metric. The ARM interpreter contributes one nanosecond
per emulated instruction. Genuine syscall entries contribute one additional
nanosecond; re-delivering a blocked syscall contributes none. Idle VMs jump
directly to their next timed event. Execution accounting excludes idle jumps and
accelerated observations.

Consecutive clock observations by one task advance time by 1, 2, 4, ...
nanoseconds, capped at 1,000,000 nanoseconds per observation. Timestamp
instructions and syscall getters share this streak. A non-clock syscall,
blocking or exec resets it. Observation advances stop at the earliest timer,
then hand control to the kernel before guest execution resumes.

KVM requires a supported Intel PMU and usable guest-only perf counters. Backend
selection runs a guest loop to check the counter; automatic selection falls
back to the interpreter when that probe fails. Explicit PMU requests fail when
unavailable. Counting is continuous. Exact interrupts target the earliest timer
or remaining fairness quantum, with an early overflow and single-stepped tail
to compensate for skid. The skid margin is not deducted from virtual time.
Timer signals can be delivered at these user instruction boundaries, including
in compute loops that make no syscalls. Completed syscall returns are restored
to user mode before precise execution resumes.

An unconditional loop such as `jmp .` retires no conditional branches and
advances no x86 execution time. While an exact target is armed, it cannot reach
that target. A different execution metric is required to guarantee timer
progress for every possible instruction stream. Branch counting refuses a host
watchdog: host time cannot choose a guest slice boundary. A nonzero or invalid
`NIXVM_QUANTUM_MS` fails KVM setup. Foreign interrupts resume the same slice.
Embedder wall-clock budgets cannot interrupt a syscall-free KVM run without a
virtual deadline or branch allowance. An external process timeout can stop it.

Precision stepping hides its injected TF from PUSHF, syscall return registers
and saved exception frames. POPF is emulated during the precision tail so it
cannot disable host stepping. Guest-owned TF and INT1 retain their debug traps.

KVM leaves the vDSO uncalibrated so clock functions use their syscall fallback.

CR4.TSD does not trap `RDPID`, so KVM executes it natively from the guest's
`IA32_TSC_AUX`. Creating a vCPU sets that MSR to zero, which covers new vCPUs,
fork children and recycled pool slots. Exec resets a vCPU in place, and user code
cannot write the MSR. The interpreter does not implement `RDPID`; see below.

## Hardware floor and interpreter coverage

The profile describes Intel Ice Lake-SP or newer, the fleet floor. Beyond
x86-64-v3 (AVX, AVX2, FMA, F16C, BMI1, BMI2, `LZCNT`, `MOVBE`) it advertises
AES-NI, `PCLMULQDQ`, ADX, SHA, GFNI, VAES, `VPCLMULQDQ`, `PREFETCHW`,
`CLFLUSHOPT`, `CLWB` and `RDPID`. Cascade Lake lacks SHA, GFNI, VAES,
`VPCLMULQDQ` and `RDPID`. KVM compares the profile with the host's supported
CPUID and rejects a host that lacks any advertised feature; it never removes a
feature from the profile. Automatic backend selection can then use the
interpreter.

The profile keeps `RDRAND`, `RDSEED`, TSX, AVX-512, PKU and FSGSBASE off, and
advertises no XSAVE extensions (`XSAVEOPT`, `XSAVEC`, `XSAVES`, `XGETBV` with
ECX = 1). XSAVE manages only the x87, SSE and YMM components.

Both backends report the same CPUID, but the interpreter executes only part of
the profile. This divergence is accepted:

| Features | KVM | Interpreter |
|---|---|---|
| FMA, F16C, `LZCNT`, `PREFETCHW`, `CLFLUSHOPT` | Executes | Executes |
| AES-NI, `PCLMULQDQ`, SHA, GFNI, VAES, `VPCLMULQDQ`, ADX, `RDPID`, `CLWB` | Executes | #UD, reported as IllegalInstruction |

A program that finds one of these features in CPUID and uses it runs on KVM and
receives `SIGILL` under the interpreter. The memory forms of `ADCX`, the AES-NI
rounds and `GF2P8MULB` read a 16-byte-aligned operand before the interpreter
rejects the opcode, so a misaligned operand raises #GP and an unmapped one a page
fault. `tests/cpuid.rs` executes one instruction per feature on both backends and
records each outcome.

## Randomness instructions: works as intended

`RDRAND` and `RDSEED` remain absent from CPUID. Their current execution behavior
is intentional and is not changed by timestamp emulation:

| Instruction | KVM | Interpreter |
|---|---|---|
| `RDRAND` | #UD, reported as IllegalInstruction | Deterministic splitmix64 output from a fixed initial seed; CF reports success |
| `RDSEED` | #UD, reported as IllegalInstruction | IllegalInstruction |

KVM tests execute both instructions directly to verify the faults and preserved
user state. The interpreter's `RDRAND` fallback supplies no host hardware entropy.
