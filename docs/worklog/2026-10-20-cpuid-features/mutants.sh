#!/bin/bash
# Mutants for the 2026-10-20 CPUID feature change. Each applies one edit, runs the test
# that should catch it, and restores the file. Expect every line to read "killed".
cd "$(git rev-parse --show-toplevel)" || exit 1
mkdir -p target/scratch
# Set CARGO_HOME and CARGO_BUILD_JOBS in the environment as for any offline build.
run() { # name file sed-expr test-args...
  local name=$1 file=$2 expr=$3; shift 3
  cp "$file" target/scratch/mutant.bak
  sed -i "$expr" "$file"
  if cmp -s "$file" target/scratch/mutant.bak; then echo "$name: INVALID (no change)"; return; fi
  if timeout 200 cargo test --offline --locked "$@" > "target/scratch/mutant-$name.log" 2>&1; then
    echo "$name: SURVIVED"
  else
    if grep -q "^error\[" "target/scratch/mutant-$name.log"; then echo "$name: INVALID (compile)"; else echo "$name: killed"; fi
  fi
  cp target/scratch/mutant.bak "$file"
}
run rdpid-bit cpuid.toml 's/^ecx = 0x00400700/ecx = 0x00000700/' --test cpuid -- kvm_cpuid_reports_each_ice_lake_feature
run aes-bit cpuid.toml 's/^ecx = 0xBED83203/ecx = 0xBCD83203/' --test cpuid -- kvm_cpuid_reports_each_ice_lake_feature
run prefetchw-bit cpuid.toml 's/^ecx = 0x00000121/ecx = 0x00000021/' --test cpuid -- kvm_cpuid_reports_each_ice_lake_feature
run sha-bit-unit cpuid.toml 's/^ebx = 0x219803A8/ebx = 0x019803A8/' --lib -- vcpu::cpuid::tests::profile_advertises
run cpuinfo-name src/vcpu/cpuid.rs 's/(8, "3dnowprefetch")/(8, "prefetchw")/' --lib -- vcpu::cpuid::tests::cpuinfo_flags
run host-mask-7ecx src/vcpu/kvm/vm.rs 's/(7, 0, \[0, u32::MAX, u32::MAX, u32::MAX\])/(7, 0, [0, u32::MAX, 0, u32::MAX])/' --lib -- vcpu::kvm::vm::tests::missing_any_ice_lake_feature
run tsc-aux-reset src/vcpu/kvm/vcpu.rs '/(sys::MSR_TSC_AUX, 0),/d' --lib -- vcpu::kvm::vcpu::tests::recycled_slot
run keep-rdrand-off cpuid.toml 's/^ecx = 0xBED83203/ecx = 0xFED83203/' --lib -- vcpu::cpuid::tests::profile_advertises
