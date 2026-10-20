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
fn solo_compute_loops_count_before_contention() {
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
        assert!(cpu.retired_branches().unwrap() > 0);
        let solo = cpu.retired_branches().unwrap();

        // Start contention at a known instruction boundary to check its budget.
        cpu.reset(BASE, BASE + 0x8000);
        cpu.set_preemption_required(true);
        cpu.begin_slice();
        assert_eq!(cpu.run(&mut memory).unwrap(), Exit::Interrupted);
        assert_eq!(cpu.pc(), BASE);
        assert_eq!(cpu.reg(3), quantum);
        assert_eq!(cpu.retired_branches(), Some(solo + quantum));
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
fn solo_execution_counts_and_fairness_can_be_enabled_and_disabled() {
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
    assert_eq!(cpu.retired_branches(), Some(1000));
    assert_eq!(cpu.reg(3), 0);

    cpu.reset(BASE, BASE + 0x8000);
    cpu.set_preemption_required(true);
    assert_eq!(cpu.run(&mut memory).unwrap(), Exit::Interrupted);
    assert_eq!(cpu.retired_branches(), Some(1000 + quantum));
    assert_eq!(cpu.reg(3), 1000 - quantum);

    cpu.set_preemption_required(false);
    assert_eq!(cpu.run(&mut memory).unwrap(), Exit::Syscall);
    assert_eq!(cpu.reg(3), 0);
    assert_eq!(
        cpu.retired_branches(),
        Some(2000),
        "solo tail contributes virtual execution time"
    );

    cpu.reset(BASE, BASE + 0x8000);
    cpu.set_preemption_required(true);
    assert_eq!(cpu.run(&mut memory).unwrap(), Exit::Interrupted);
    assert_eq!(cpu.retired_branches(), Some(2000 + quantum));
    assert_eq!(
        cpu.reg(3),
        1000 - quantum,
        "new contention gets a full quantum"
    );
}

#[test]
#[ignore = "requires KVM and guest-only perf counters on a supported Intel CPU"]
fn solo_branches_advance_virtual_time_without_clock_reads() {
    use nixvm::clock::VirtualClock;
    use std::sync::Arc;
    let backend = KvmBackend::with_branch_quantum(16).unwrap();
    let clock = Arc::new(VirtualClock::default());
    let mut memory = GuestMemory::new(BASE, 64 * 1024);
    memory.map(BASE, PAGE_SIZE, Prot::rx()).unwrap();
    // MOV EBX,1000; DEC EBX; JNZ dec; SYSCALL.
    memory
        .write_init(
            BASE,
            &[0xbb, 0xe8, 0x03, 0, 0, 0xff, 0xcb, 0x75, 0xfc, 0x0f, 0x05],
        )
        .unwrap();
    let mut cpu = backend.new_vcpu(BASE, BASE + 0x8000).unwrap();
    cpu.set_clock(clock.clone(), 1);
    assert_eq!(cpu.run(&mut memory).unwrap(), Exit::Syscall);
    assert_eq!(cpu.reg(3), 0, "independent guest loop counter");
    assert_eq!(cpu.retired_branches(), Some(1000));
    assert_eq!(clock.now_monotonic().as_nanos(), 1001);
    assert_eq!(clock.execution_ns(), 1000);
    assert_eq!(cpu.run(&mut memory).unwrap(), Exit::Syscall);
    assert_eq!(
        clock.now_monotonic().as_nanos(),
        1001,
        "blocked retry does not advance"
    );
}

#[test]
#[ignore = "requires KVM and guest-only perf counters on a supported Intel CPU"]
fn timers_interrupt_solo_execution_before_fairness_quantum() {
    use nixvm::clock::VirtualClock;
    use std::sync::Arc;
    for timer in [16, 2048] {
        let backend = KvmBackend::with_branch_quantum(4000).unwrap();
        let clock = Arc::new(VirtualClock::default());
        clock.set_deadline(Some(timer));
        let mut memory = GuestMemory::new(BASE, 64 * 1024);
        memory.map(BASE, PAGE_SIZE, Prot::rx()).unwrap();
        memory
            .write_init(BASE, &[0x48, 0xff, 0xc3, 0x48, 0x85, 0xdb, 0x75, 0xf8])
            .unwrap();
        let mut cpu = backend.new_vcpu(BASE, BASE + 0x8000).unwrap();
        cpu.set_clock(clock.clone(), 1);
        assert_eq!(cpu.run(&mut memory).unwrap(), Exit::Interrupted);
        assert_eq!(cpu.reg(3), timer as u64);
        assert_eq!(cpu.pc(), BASE);
        assert_eq!(clock.now_monotonic().as_nanos(), timer);
        clock.set_deadline(Some(timer + 17));
        assert_eq!(cpu.run(&mut memory).unwrap(), Exit::Interrupted);
        assert_eq!(cpu.reg(3), timer as u64 + 17);
        assert_eq!(clock.now_monotonic().as_nanos(), timer + 17);
    }
}

#[test]
#[ignore = "requires KVM and guest-only perf counters on a supported Intel CPU"]
fn geometric_clock_reads_return_to_kernel_at_timer_boundary() {
    use nixvm::clock::VirtualClock;
    use std::sync::Arc;
    let backend = KvmBackend::with_branch_quantum(4000).unwrap();
    let clock = Arc::new(VirtualClock::default());
    clock.set_deadline(Some(25));
    let mut memory = GuestMemory::new(BASE, 64 * 1024);
    memory.map(BASE, PAGE_SIZE, Prot::rx()).unwrap();
    // INC RBX; RDTSC; JMP start. No conditional branches retire.
    memory
        .write_init(BASE, &[0x48, 0xff, 0xc3, 0x0f, 0x31, 0xeb, 0xf9])
        .unwrap();
    let mut cpu = backend.new_vcpu(BASE, BASE + 0x8000).unwrap();
    cpu.set_clock(clock.clone(), 1);
    assert_eq!(cpu.run(&mut memory).unwrap(), Exit::Interrupted);
    assert_eq!(clock.now_monotonic().as_nanos(), 25);
    assert_eq!(clock.execution_ns(), 0);
    assert_eq!(cpu.reg(3), 5, "reads advance by 1,2,4,8,then clamp at25");
    assert_eq!(cpu.reg(0), 25);
    assert_eq!(cpu.pc(), BASE + 5, "handoff follows completed RDTSC");
}

#[test]
#[ignore = "requires KVM and guest-only perf counters on a supported Intel CPU"]
fn timer_handoff_preserves_the_remaining_fairness_quantum() {
    use nixvm::clock::VirtualClock;
    use std::sync::Arc;
    let backend = KvmBackend::with_branch_quantum(64).unwrap();
    let clock = Arc::new(VirtualClock::default());
    clock.set_deadline(Some(17));
    let mut memory = GuestMemory::new(BASE, 64 * 1024);
    memory.map(BASE, PAGE_SIZE, Prot::rx()).unwrap();
    memory
        .write_init(BASE, &[0x48, 0xff, 0xc3, 0x48, 0x85, 0xdb, 0x75, 0xf8])
        .unwrap();
    let mut cpu = backend.new_vcpu(BASE, BASE + 0x8000).unwrap();
    cpu.set_clock(clock.clone(), 1);
    cpu.set_preemption_required(true);
    cpu.begin_slice();
    assert_eq!(cpu.run(&mut memory).unwrap(), Exit::Interrupted);
    assert_eq!(cpu.reg(3), 17);
    clock.set_deadline(None);
    assert_eq!(cpu.run(&mut memory).unwrap(), Exit::Interrupted);
    assert_eq!(
        cpu.reg(3),
        64,
        "timer handoff must not grant another quantum"
    );
    assert_eq!(clock.execution_ns(), 64);
}

#[test]
#[ignore = "requires KVM and guest-only perf counters on a supported Intel CPU"]
fn timer_signal_reaches_a_syscall_free_compute_loop() {
    for handled in [false, true] {
        let backend = KvmBackend::with_branch_quantum(4000).unwrap();
        let data = BASE + PAGE_SIZE;
        let handler = BASE + 0x200;
        let mut memory = GuestMemory::new(BASE, 64 * 1024);
        memory.map(BASE, PAGE_SIZE, Prot::rx()).unwrap();
        memory.map(data, PAGE_SIZE, Prot::rw()).unwrap();
        memory.map(BASE + 0x7000, PAGE_SIZE, Prot::rw()).unwrap();
        let mut code = Vec::new();
        if handled {
            // rt_sigaction(SIGALRM, action, NULL, 8).
            code.extend_from_slice(&[0xbf, 14, 0, 0, 0, 0xbe]);
            code.extend_from_slice(&((data + 32) as u32).to_le_bytes());
            code.extend_from_slice(&[
                0x31, 0xd2, 0x41, 0xba, 8, 0, 0, 0, 0xb8, 13, 0, 0, 0, 0x0f, 0x05,
            ]);
        }
        // setitimer(ITIMER_REAL, {interval=0,value=1us}, NULL).
        code.extend_from_slice(&[0x31, 0xff, 0xbe]);
        code.extend_from_slice(&(data as u32).to_le_bytes());
        code.extend_from_slice(&[0x31, 0xd2, 0xb8, 38, 0, 0, 0, 0x0f, 0x05]);
        // The interrupted PC differs from SYSCALL's saved RCX.
        code.extend_from_slice(&[0xbb, 0, 0, 0, 0]);
        let loop_pc = BASE + code.len() as u64;
        code.extend_from_slice(&[0x48, 0xff, 0xc3, 0x48, 0x85, 0xdb, 0x75, 0xf8]);
        memory.write_init(BASE, &code).unwrap();
        memory.write_init(data, &[0; 64]).unwrap();
        memory.write_init(data + 24, &1u64.to_le_bytes()).unwrap();
        if handled {
            for (offset, value) in [
                (32, handler),
                (40, 0x0400_0004),
                (48, BASE + 0x300),
                (56, 0),
            ] {
                memory
                    .write_init(data + offset, &value.to_le_bytes())
                    .unwrap();
            }
            // Check the independent loop counter and the saved user RIP in
            // ucontext. A stale syscall RCX must not replace interrupted RIP.
            let mut signal_code = vec![0x81, 0xfb, 0xe8, 0x03, 0, 0, 0x75, 0];
            signal_code.push(0xb9);
            signal_code.extend_from_slice(&(loop_pc as u32).to_le_bytes());
            signal_code.extend_from_slice(&[0x48, 0x39, 0x8a, 0xa8, 0, 0, 0, 0x75, 0]);
            signal_code.extend_from_slice(&[0xbf, 42, 0, 0, 0, 0xb8, 60, 0, 0, 0, 0x0f, 0x05]);
            let failure = signal_code.len();
            signal_code[7] = (failure - 8) as u8;
            signal_code[21] = (failure - 22) as u8;
            signal_code.extend_from_slice(&[0xbf, 99, 0, 0, 0, 0xb8, 60, 0, 0, 0, 0x0f, 0x05]);
            memory.write_init(handler, &signal_code).unwrap();
        }
        let cpu = backend.new_vcpu(BASE, BASE + 0x8000).unwrap();
        let mut kernel = Kernel::new(Arch::X86_64, MountTable::new());
        kernel.boot(cpu, memory);
        let mut state = Pumped::Busy;
        for _ in 0..4 {
            state = kernel.pump_for(Duration::from_millis(100)).unwrap();
            if matches!(state, Pumped::Exited(_)) {
                break;
            }
        }
        assert_eq!(state, Pumped::Exited(if handled { 42 } else { 142 }));
    }
}
