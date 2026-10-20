# CPU instruction policy

The x86 CPU profile in `cpuid.toml` is shared by KVM and the interpreter.
It advertises both `RDTSC` and `RDTSCP`. Both return a logical timestamp in
EDX:EAX; `RDTSCP` also returns a fixed `TSC_AUX` of zero in ECX. Host CPU identity
and migration do not affect that value.

KVM traps both timestamp instructions through CR4.TSD and the guest #GP handler.
Each timestamp read advances the VM's shared counter by one and returns the new
value. Each syscall entry also advances it by one; re-delivering a blocked syscall
does not. All vcpus and address spaces in the VM share this counter, including
after fork and exec. The interpreter retains its existing per-vcpu timestamp
counter, advanced by timestamp reads.

KVM leaves the vDSO uncalibrated so clock functions use their syscall fallback.
Clock syscalls retain the existing clock policy; the timestamp counter is not yet
the source for the guest's whole view of time.

## Randomness instructions: works as intended

`RDRAND` and `RDSEED` remain absent from CPUID. Their current execution behavior
is intentional and is not changed by timestamp emulation:

| Instruction | KVM | Interpreter |
|---|---|---|
| `RDRAND` | #UD, reported as IllegalInstruction | Deterministic splitmix64 output from a fixed initial seed; CF reports success |
| `RDSEED` | #UD, reported as IllegalInstruction | IllegalInstruction |

KVM tests execute both instructions directly to verify the faults and preserved
user state. The interpreter's `RDRAND` fallback supplies no host hardware entropy.
