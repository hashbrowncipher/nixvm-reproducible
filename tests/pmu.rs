//! Hardware checks deliberately fail when explicitly requested without KVM or
//! PMU access. Run with `cargo test --test pmu -- --ignored --test-threads=1`.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use nixvm::vcpu::mem::PAGE_SIZE;
use nixvm::vcpu::{Backend, Exit, GuestMemory, Prot, kvm::KvmBackend};

const BASE: u64 = 0x1_0000;

#[test]
fn invalid_quantum_is_rejected_before_opening_kvm() {
    assert!(KvmBackend::with_branch_quantum(0).is_err());
    assert!(KvmBackend::with_branch_quantum(u64::MAX).is_err());
}

#[test]
#[ignore = "requires KVM and guest-only perf counters on a supported Intel CPU"]
fn branch_quantum_lands_at_the_same_instruction_on_repeated_runs() {
    for quantum in [64, 20_000] {
        for _ in 0..3 {
            let backend = KvmBackend::with_branch_quantum(quantum).unwrap();
            let mut memory = GuestMemory::new(BASE, 64 * 1024);
            memory.map(BASE, PAGE_SIZE, Prot::rwx()).unwrap();
            // INC RBX; TEST RBX,RBX; JNZ start. One conditional branch per increment.
            memory
                .write_init(BASE, &[0x48, 0xff, 0xc3, 0x48, 0x85, 0xdb, 0x75, 0xf8])
                .unwrap();
            let mut cpu = backend.new_vcpu(BASE, BASE + 0x8000).unwrap();
            for slice in 1..=3 {
                cpu.begin_slice();
                assert_eq!(cpu.run(&mut memory).unwrap(), Exit::Interrupted);
                assert_eq!(cpu.pc(), BASE);
                assert_eq!(cpu.reg(3), quantum * slice, "guest loop counter");
                assert_eq!(cpu.retired_branches(), Some(quantum * slice));
                assert_eq!(cpu.rflags() & 0x100, 0, "host stepping must not leak TF");
            }
        }
    }
}

#[test]
#[ignore = "requires KVM and guest-only perf counters on a supported Intel CPU"]
fn syscalls_preserve_the_branch_budget_and_forks_inherit_the_mode() {
    let backend = KvmBackend::with_branch_quantum(16).unwrap();
    let mut memory = GuestMemory::new(BASE, 64 * 1024);
    memory.map(BASE, PAGE_SIZE, Prot::rwx()).unwrap();
    // INC RBX; SYSCALL; TEST RBX,RBX; JNZ start.
    memory
        .write_init(
            BASE,
            &[0x48, 0xff, 0xc3, 0x0f, 0x05, 0x48, 0x85, 0xdb, 0x75, 0xf6],
        )
        .unwrap();
    let mut parent = backend.new_vcpu(BASE, BASE + 0x8000).unwrap();
    parent.begin_slice();
    let mut syscalls = 0;
    loop {
        match parent.run(&mut memory).unwrap() {
            Exit::Syscall => {
                syscalls += 1;
                parent.set_syscall_ret(0);
            }
            Exit::Interrupted => break,
            other => panic!("unexpected exit: {other:?}"),
        }
        assert!(syscalls <= 16, "syscalls must not restart the budget");
    }
    assert_eq!(syscalls, 16);
    assert_eq!(parent.reg(3), 16);
    assert_eq!(parent.pc(), BASE);
    let child = parent.fork();
    assert_eq!(child.retired_branches(), Some(0));
}
