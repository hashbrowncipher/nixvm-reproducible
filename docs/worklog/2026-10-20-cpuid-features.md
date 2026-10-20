# Ice Lake-SP CPUID features

Added FMA, F16C, LZCNT, AES-NI, PCLMULQDQ, ADX, PREFETCHW, CLFLUSHOPT, CLWB,
SHA, GFNI, VAES, VPCLMULQDQ and RDPID to `cpuid.toml`. The fleet floor is now
Intel Ice Lake-SP; Cascade Lake lacks SHA, GFNI, VAES, VPCLMULQDQ and RDPID.

| Word | Before | After | New bits |
|---|---|---|---|
| 1.ECX | `0x9CD82201` | `0xBED83203` | 1 PCLMULQDQ, 12 FMA, 25 AES, 29 F16C |
| 7.0.EBX | `0x001003A8` | `0x219803A8` | 19 ADX, 23 CLFLUSHOPT, 24 CLWB, 29 SHA |
| 7.0.ECX | `0x00000000` | `0x00400700` | 8 GFNI, 9 VAES, 10 VPCLMULQDQ, 22 RDPID |
| 0x80000001.ECX | `0x00000001` | `0x00000121` | 5 ABM/LZCNT, 8 PREFETCHW |

Each position matches the Intel SDM CPUID tables. The profile SHA256 changed
from `25d313e4fff5e13b37ece0f0a7a5a794517543adcbf5ca7da671ac3c4cda5d40` to
`fb731f21b6684276f63a10b618b477aa7d458a316274950605a7a6094b75701b`.
RDRAND, RDSEED, TSX, AVX-512, PKU, FSGSBASE and leaf 0xD subleaf 1 stay off.
The XSAVE layout is unchanged.

- `/proc/cpuinfo` maps the new bits by their Linux names, including a 7.0.ECX word
  and `3dnowprefetch`. x86-64 HWCAP is leaf 1 EDX and HWCAP2 is zero, so neither changed.
- KVM's host check already compared 7.0.ECX and 0x80000001.ECX completely and
  1.ECX apart from OSXSAVE and HYPERVISOR. A unit test removes each new bit from
  a synthetic supported table and expects rejection that names the bit.
- RDPID runs natively from IA32_TSC_AUX. It already returned 0 on new, exec-reset,
  forked, sibling and pooled vCPUs, because KVM starts the MSR at zero. vCPU
  creation now writes zero explicitly. A regression test that leaves TSC_AUX = 7
  in a recycled pool slot failed before that write (`82c6de1`) and passes after it.
- Interpreter execution is unchanged. It executes FMA, F16C, LZCNT, PREFETCHW and
  CLFLUSHOPT, and faults on the other nine. This accepted divergence is documented
  in its module comment and `docs/cpu.md`.
- `tests/cpuid.rs` runs one instruction per feature on KVM against known results.
  The interpreter test records which probes execute and which fault. The expected
  values come from SDM models in `docs/worklog/2026-10-20-cpuid-features/expected.py`,
  which reproduces the AESENC example from Intel's AES-NI white paper. The same
  machine code run natively on the host matched every result except RDPID, which
  returned the host's TSC_AUX. `probes.S` in the same directory is the probe source.

Pre-existing interpreter defect, left unfixed because the interpreter was out of
scope: the memory forms of ADCX, the AES-NI rounds and GF2P8MULB read a 16-byte
aligned operand before the opcode is rejected (`src/vcpu/interp_x86/sse/sse4.rs`,
`exec_0f38`). The ADX probe's misaligned `[rbx+8]` therefore raises #GP instead of
#UD. The test records this outcome as `MisalignedOperand`.

## Validation

Baseline `f7c4623`, Rust 1.93.1, offline with `--locked`, `CARGO_BUILD_JOBS=4`.

- `cargo fmt --all --check`: pass.
- `cargo clippy --all-targets -- -D warnings`: pass.
- `cargo clippy --all-targets --features erofs -- -D warnings`: pass.
- `cargo test`: pass, 868 passed, 21 ignored, 14 s. Real KVM CPUID, probe and RDPID
  tests ran.
- `cargo test --features fstool`: pass, 883 passed, 21 ignored, 25 s.
- Ignored KVM pool, confinement and PMU tests (`--ignored`, pinned to CPU 11): pass, 19 passed.
- `cargo check --offline --locked --lib --no-default-features --target wasm32-unknown-unknown`: pass.
- `git diff --check`: pass.
- Mutants (`docs/worklog/2026-10-20-cpuid-features/mutants.sh`): 8 of 8 killed.
  They clear the RDPID, AES, PREFETCHW and SHA bits, rename `3dnowprefetch`, unmask
  7.0.ECX in the host check, drop the TSC_AUX write and set RDRAND.

## Technical debt and capital

1. Interpreter decode order: unknown `66 0F 38` opcodes fetch their operand before
   rejecting the opcode, so faults depend on alignment. Rejecting the opcode first is cheap.
2. Feature probes are hand-assembled bytes. A shared probe table that both backends
   and a native-hardware check consume would make the next profile change mechanical.
3. The feature list exists in four places: `cpuid.toml`, `flag_string`, and the unit
   and integration tests. Generating cpuinfo names from annotated TOML would remove one.
