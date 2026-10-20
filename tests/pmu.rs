//! Hardware checks deliberately fail when explicitly requested without KVM or
//! PMU access. Run with `cargo test --test pmu -- --ignored --test-threads=1`.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use nixvm::vcpu::mem::PAGE_SIZE;
use nixvm::vcpu::{Backend, Exit, GuestMemory, Prot, kvm::KvmBackend};
use nixvm::{
    abi::Arch,
    fs::MountTable,
    kernel::{Kernel, Pumped},
};
use std::time::Duration;

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
                cpu.set_preemption_required(true);
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
    parent.set_preemption_required(true);
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

#[test]
#[ignore = "requires KVM and guest-only perf counters on a supported Intel CPU"]
fn timestamp_traps_preserve_branch_quanta() {
    for quantum in [16, 2048] {
        let backend = KvmBackend::with_branch_quantum(quantum).unwrap();
        let mut memory = GuestMemory::new(BASE, 64 * 1024);
        memory.map(BASE, PAGE_SIZE, Prot::rx()).unwrap();
        // INC RBX; RDTSC; RDTSCP; TEST RBX,RBX; JNZ start.
        memory
            .write_init(
                BASE,
                &[
                    0x48, 0xff, 0xc3, 0x0f, 0x31, 0x0f, 0x01, 0xf9, 0x48, 0x85, 0xdb, 0x75, 0xf3,
                ],
            )
            .unwrap();
        let mut cpu = backend.new_vcpu(BASE, BASE + 0x8000).unwrap();
        cpu.set_preemption_required(true);
        for slice in 1..=2 {
            cpu.begin_slice();
            assert_eq!(cpu.run(&mut memory).unwrap(), Exit::Interrupted);
            assert_eq!(cpu.pc(), BASE);
            assert_eq!(cpu.reg(3), quantum * slice);
            assert_eq!(cpu.retired_branches(), Some(quantum * slice));
            assert_eq!(cpu.rflags() & 0x100, 0);
        }
    }
}

#[test]
#[ignore = "requires KVM and guest-only perf counters on a supported Intel CPU"]
fn solo_compute_loops_yield_without_counting_before_contention() {
    let loops: [&[u8]; 2] = [
        // INC RBX; TEST RBX,RBX; JNZ start.
        &[0x48, 0xff, 0xc3, 0x48, 0x85, 0xdb, 0x75, 0xf8],
        // INC RBX; RDTSC; RDTSCP; TEST RBX,RBX; JNZ start.
        &[
            0x48, 0xff, 0xc3, 0x0f, 0x31, 0x0f, 0x01, 0xf9, 0x48, 0x85, 0xdb, 0x75, 0xf3,
        ],
    ];
    for code in loops {
        let quantum = 16;
        let backend = KvmBackend::with_branch_quantum(quantum).unwrap();
        let mut memory = GuestMemory::new(BASE, 64 * 1024);
        memory.map(BASE, PAGE_SIZE, Prot::rx()).unwrap();
        memory.write_init(BASE, code).unwrap();
        let mut cpu = backend.new_vcpu(BASE, BASE + 0x8000).unwrap();
        cpu.begin_slice();
        assert_eq!(cpu.run(&mut memory).unwrap(), Exit::Interrupted);
        assert!(cpu.reg(3) > 0, "solo guest loop must make progress");
        assert_eq!(cpu.retired_branches(), Some(0));

        // Start contention at a known instruction boundary to check its budget.
        cpu.reset(BASE, BASE + 0x8000);
        cpu.set_preemption_required(true);
        cpu.begin_slice();
        assert_eq!(cpu.run(&mut memory).unwrap(), Exit::Interrupted);
        assert_eq!(cpu.pc(), BASE);
        assert_eq!(cpu.reg(3), quantum);
        assert_eq!(cpu.retired_branches(), Some(quantum));
        assert_eq!(cpu.rflags() & 0x100, 0);
    }
}

#[test]
#[ignore = "requires KVM"]
fn solo_compute_loop_returns_to_the_kernel_pump() {
    let backend = KvmBackend::with_branch_quantum(16).unwrap();
    let mut memory = GuestMemory::new(BASE, 64 * 1024);
    memory.map(BASE, PAGE_SIZE, Prot::rx()).unwrap();
    // INC RBX; TEST RBX,RBX; JNZ start. The guest never returns through a syscall.
    memory
        .write_init(BASE, &[0x48, 0xff, 0xc3, 0x48, 0x85, 0xdb, 0x75, 0xf8])
        .unwrap();
    let cpu = backend.new_vcpu(BASE, BASE + 0x8000).unwrap();
    let mut kernel = Kernel::new(Arch::X86_64, MountTable::new());
    kernel.boot(cpu, memory);
    for _ in 0..2 {
        assert_eq!(
            kernel.pump_for(Duration::from_millis(20)).unwrap(),
            Pumped::Busy
        );
    }
    assert!(
        kernel.unsupported().is_empty(),
        "{:?}",
        kernel.unsupported()
    );
}

#[test]
#[ignore = "requires KVM and guest-only perf counters on a supported Intel CPU"]
fn solo_execution_does_not_count_and_contention_can_be_enabled_and_disabled() {
    let quantum = 16;
    let backend = KvmBackend::with_branch_quantum(quantum).unwrap();
    let mut memory = GuestMemory::new(BASE, 64 * 1024);
    memory.map(BASE, PAGE_SIZE, Prot::rwx()).unwrap();
    // MOV EBX,1000; DEC EBX; JNZ dec; SYSCALL. Solo execution exceeds a quantum.
    memory
        .write_init(
            BASE,
            &[0xbb, 0xe8, 0x03, 0, 0, 0xff, 0xcb, 0x75, 0xfc, 0x0f, 0x05],
        )
        .unwrap();
    let mut cpu = backend.new_vcpu(BASE, BASE + 0x8000).unwrap();
    cpu.begin_slice();
    assert_eq!(cpu.run(&mut memory).unwrap(), Exit::Syscall);
    assert_eq!(cpu.retired_branches(), Some(0));
    assert_eq!(cpu.reg(3), 0);

    cpu.reset(BASE, BASE + 0x8000);
    cpu.set_preemption_required(true);
    assert_eq!(cpu.run(&mut memory).unwrap(), Exit::Interrupted);
    assert_eq!(cpu.retired_branches(), Some(quantum));
    assert_eq!(cpu.reg(3), 1000 - quantum);

    cpu.set_preemption_required(false);
    assert_eq!(cpu.run(&mut memory).unwrap(), Exit::Syscall);
    assert_eq!(cpu.reg(3), 0);
    assert_eq!(
        cpu.retired_branches(),
        Some(quantum),
        "solo tail stays uncounted"
    );

    cpu.reset(BASE, BASE + 0x8000);
    cpu.set_preemption_required(true);
    assert_eq!(cpu.run(&mut memory).unwrap(), Exit::Interrupted);
    assert_eq!(cpu.retired_branches(), Some(quantum * 2));
    assert_eq!(
        cpu.reg(3),
        1000 - quantum,
        "new contention gets a full quantum"
    );
}

#[test]
#[ignore = "requires KVM and guest-only perf counters on a supported Intel CPU"]
fn precision_tail_steps_multiple_branches_after_a_syscall_return() {
    let backend = KvmBackend::with_branch_quantum(16).unwrap();
    let mut memory = GuestMemory::new(BASE, 64 * 1024);
    memory.map(BASE, PAGE_SIZE, Prot::rx()).unwrap();
    // SYSCALL; TEST RBX,RBX; JZ next; TEST RBX,RBX; JZ next; JMP start.
    // SYSRET must not clear the host's precision stepping and execute both
    // conditional branches in one KVM_RUN.
    memory
        .write_init(
            BASE,
            &[
                0x0f, 0x05, 0x48, 0x85, 0xdb, 0x74, 1, 0x90, 0x48, 0x85, 0xdb, 0x74, 1, 0x90, 0xeb,
                0xf0,
            ],
        )
        .unwrap();
    let mut cpu = backend.new_vcpu(BASE, BASE + 0x8000).unwrap();
    loop {
        if cpu.run(&mut memory).unwrap() == Exit::Syscall {
            break;
        }
    }
    cpu.set_syscall_ret(0);
    cpu.set_preemption_required(true);
    cpu.begin_slice();
    loop {
        match cpu.run(&mut memory).unwrap() {
            Exit::Syscall => cpu.set_syscall_ret(0),
            Exit::Interrupted => break,
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(cpu.retired_branches(), Some(16));
    assert_eq!(
        cpu.rflags() & 0x100,
        0,
        "host TF must not leak to the guest"
    );
}

#[test]
#[ignore = "requires KVM and guest-only perf counters on a supported Intel CPU"]
fn unconfined_pmu_restores_the_callers_affinity_and_signal_mask() {
    fn state() -> ([u64; 16], i32) {
        let mut affinity = [0; 16];
        let mut mask = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: complete CPU/signal-set buffers for the calling thread.
        unsafe {
            assert!(libc::syscall(libc::SYS_sched_getaffinity, 0, 128, affinity.as_mut_ptr()) >= 0);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), mask.as_mut_ptr()),
                0
            );
            (affinity, libc::sigismember(&mask.assume_init(), 41))
        }
    }
    let before = state();
    let backend = KvmBackend::with_branch_quantum(16).unwrap();
    let mut memory = GuestMemory::new(BASE, 64 * 1024);
    memory.map(BASE, PAGE_SIZE, Prot::rx()).unwrap();
    memory
        .write_init(BASE, &[0x48, 0xff, 0xc3, 0x48, 0x85, 0xdb, 0x75, 0xf8])
        .unwrap();
    let mut cpu = backend.new_vcpu(BASE, BASE + 0x8000).unwrap();
    cpu.set_preemption_required(true);
    assert_eq!(cpu.run(&mut memory).unwrap(), Exit::Interrupted);
    assert_eq!(
        state(),
        before,
        "host state must be restored before run returns"
    );
    drop(cpu);
    drop(backend);
    drop(memory);
    assert_eq!(state(), before);
}
