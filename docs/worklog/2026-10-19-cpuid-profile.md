# Fixed guest CPUID profile

Copied the existing deterministic CPU definition into `cpuid.toml` and enabled
XSAVE, OSXSAVE, AVX, and AVX2. `build.rs` parses and validates it, then embeds a
sorted table. The interpreter and KVM use that table for guest CPUID. KVM checks
host instruction support and rejects an incompatible backend without changing the
profile. ELF HWCAP and `/proc/cpuinfo` derive their data from the same definition.
Frequency leaves remain zero while KVM supplies the clock. Topology enumeration
termination echoes the subleaf number, matching KVM's architectural behavior.

The host-only build dependencies are exactly pinned to serde 1.0.228 and toml
0.8.23, with checksums in Cargo.lock. Existing package versions were preserved.
The profile SHA256 is
`9d7acd19b7b7d3939cc286821e60d7077f027068712b667d83e3566acbc536a1`.

KVM now copies full XSAVE state across fork, exposes the 832-byte x87/SSE/YMM
image for signal delivery, and initializes that state on exec. Host ioctl buffers
use the VM's XSAVE2 size, with the legacy 4096-byte fallback. Signal restoration
normalizes absent SSE state so MXCSR agrees with native XRSTOR and the interpreter.

## Validation

Baseline: `d54df8a`. Toolchain: Rust 1.93.1, Linux x86-64. Dependencies were fetched
from the committed lockfile into a clean Cargo cache. All validation ran offline.

- The fork regression failed on real KVM before the fix: all 32 stored YMM0 bytes
  were zero instead of the input bytes 1 through 32. The regression was committed
  first as `2015ab6`; it passes with full XSAVE copying.
- The signal regression failed before the review fix: guest STMXCSR returned
  `0x1f80` for XSTATE_BV=0 instead of the supplied `0x5f80`. Guest STMXCSR and
  VMOVDQU now verify MXCSR and both YMM halves for all eight presence-bit combinations.
- The sealed full suite passed: 756 tests, including 722 library tests, and two
  existing ignored tests. Real KVM CPUID, AVX2, fork, and float differential tests ran.
- `cargo check --offline --locked --lib --no-default-features --target wasm32-unknown-unknown`
  passed. An initial check without `--lib` reached the existing native-only
  `run-elf` harness imports, which do not compile for wasm32.
- The repository formatter's check and `git diff --check` passed.
- An independent reviewer approved the change after checking 3,192 CPUID queries
  across both backends and comparing the MXCSR edge case against native XRSTOR.
  No findings remain open. Review probes and report are retained in
  `/tmp/nixvm-cpuid-review.F33kEeNq/`.

The inherited parent helpers need two in-process layout adaptations for this
standalone root Cargo crate. No parent helper was edited. From this checkout,
the full sealed test command was:

```sh
CARGO_HOME=/tmp/nixvm-cpuid-cargo timeout 250s python3 - <<'PY'
import sys
sys.path.insert(0, '../../tools')
import layout
import test
original = layout.packages
layout.packages = lambda root: original(root) if (root / 'package.json').exists() else ([], [])
raise SystemExit(test.main(['.']))
PY
```

The formatting check used the same helper for root-crate ownership:

```sh
python3 - <<'PY'
import sys
sys.path.insert(0, '../../tools')
import format as formatting
import layout
original = layout.owner
layout.owner = lambda path, directories: original(path, directories) or ('.' if '.' in directories else None)
raise SystemExit(formatting.main(['--check', '--only', 'rust', 'src', 'tests/cpuid.rs', 'build.rs']))
PY
```

The execution sandbox hides `/dev/kvm` and prevents the seal's network namespace
setup. Hardware tests and the sealed full suite ran outside that sandbox.

## Remaining work and technical capital

1. CPUID masking does not intercept instructions or virtualize time. RDTSC and
   hardware randomness still need their own enforcement and deterministic sources.
2. Supporting standalone root Cargo crates in the parent validation helpers would
   remove the layout adaptations. This is cheap enough to do before the next change.
3. A reusable cross-backend state and CPUID sweep would preserve the broader review
   probes. Guest instructions exposed a restore defect that serializer comparisons missed.
