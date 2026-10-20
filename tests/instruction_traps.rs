//! Ring-3 instruction interception on real KVM.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use nixvm::vcpu::kvm::KvmBackend;
use nixvm::vcpu::mem::PAGE_SIZE;
use nixvm::vcpu::{Backend, Exit, GuestMemory, Prot, Vcpu};

const BASE: u64 = 0x1_0000;
const STACK: u64 = BASE + 0x8000;

fn backend() -> Option<KvmBackend> {
    match KvmBackend::new() {
        Ok(backend) => Some(backend),
        Err(error) => {
            eprintln!("skipping KVM instruction traps: {error}");
            None
        }
    }
}

fn run(v: &mut dyn Vcpu, mem: &mut GuestMemory, bare: bool) -> Exit {
    if bare {
        v.reconcile(mem).unwrap();
    }
    for _ in 0..100 {
        let exit = if bare { v.run_bare() } else { v.run(mem) }.unwrap();
        if exit != Exit::Interrupted {
            return exit;
        }
    }
    panic!("guest did not make progress");
}

#[test]
fn rdtsc_rdtscp_and_syscall_entry_advance_one_vm_counter() {
    let Some(backend) = backend() else { return };
    let mut mem = GuestMemory::new(BASE, 64 * 1024);
    mem.map(BASE, PAGE_SIZE, Prot::rx()).unwrap();
    // RDTSC; SYSCALL; MOV RCX, -1; RDTSCP; MOV RSI, RCX; SYSCALL.
    // Save all 64 bits of TSC_AUX before SYSCALL overwrites RCX.
    let mut code = vec![0x0f, 0x31, 0x0f, 0x05, 0x48, 0xb9];
    code.extend_from_slice(&u64::MAX.to_le_bytes());
    code.extend_from_slice(&[0x0f, 0x01, 0xf9, 0x48, 0x89, 0xce, 0x0f, 0x05]);
    mem.write_init(BASE, &code).unwrap();
    let mut v = backend.new_vcpu(BASE, STACK).unwrap();
    assert!(
        v.vdso_calibration().is_none(),
        "logical TSC has no host-clock calibration"
    );
    v.set_reg(0, u64::MAX);
    v.set_reg(2, u64::MAX);
    v.set_reg(3, 0x1234_5678_9abc_def0);
    assert_eq!(run(v.as_mut(), &mut mem, false), Exit::Syscall);
    assert_eq!((v.reg(0), v.reg(2)), (1, 0));
    assert_eq!(v.reg(3), 0x1234_5678_9abc_def0);
    assert_eq!(v.reg(4), STACK);
    // A parked syscall is re-delivered without another entry or another tick.
    assert_eq!(run(v.as_mut(), &mut mem, false), Exit::Syscall);
    v.set_syscall_ret(0);
    v.set_reg(0, u64::MAX);
    v.set_reg(2, u64::MAX);
    v.set_reg(6, u64::MAX);
    assert_eq!(run(v.as_mut(), &mut mem, true), Exit::Syscall);
    assert_eq!((v.reg(0), v.reg(2)), (4, 0));
    assert_eq!(v.reg(6), 0, "RDTSCP zero-extends the fixed TSC_AUX");
    assert_eq!(v.reg(3), 0x1234_5678_9abc_def0);
    assert_eq!(v.reg(4), STACK);

    // Fork and reset share the VM timeline; neither copies nor resets its clock.
    let mut child = v.fork();
    for (cpu, expected) in [(&mut v, 6), (&mut child, 8)] {
        cpu.reset(BASE, STACK);
        assert_eq!(run(cpu.as_mut(), &mut mem, true), Exit::Syscall);
        assert_eq!((cpu.reg(0), cpu.reg(2)), (expected, 0));
    }
    let mut sibling = backend.new_vcpu(BASE + 4, STACK).unwrap();
    sibling.set_reg(1, u64::MAX);
    assert_eq!(run(sibling.as_mut(), &mut mem, false), Exit::Syscall);
    assert_eq!((sibling.reg(0), sibling.reg(2)), (10, 0));
    assert_eq!(sibling.reg(6), 0);
}

#[test]
fn rdpid_reads_a_fixed_zero_tsc_aux_on_every_vcpu() {
    let Some(backend) = backend() else { return };
    let mut mem = GuestMemory::new(BASE, 64 * 1024);
    mem.map(BASE, PAGE_SIZE, Prot::rx()).unwrap();
    // MOV RAX, -1; RDPID RAX; SYSCALL. RDPID runs natively and reads IA32_TSC_AUX.
    mem.write_init(
        BASE,
        &[
            0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0xf3, 0x0f, 0xc7, 0xf8, 0x0f, 0x05,
        ],
    )
    .unwrap();
    let mut v = backend.new_vcpu(BASE, STACK).unwrap();
    assert_eq!(run(v.as_mut(), &mut mem, false), Exit::Syscall);
    assert_eq!(v.reg(0), 0, "new vCPU");
    // Fork creates a vCPU; exec resets the caller's vCPU in place.
    let mut child = v.fork();
    for (name, cpu) in [("exec", &mut v), ("fork", &mut child)] {
        cpu.reset(BASE, STACK);
        assert_eq!(run(cpu.as_mut(), &mut mem, true), Exit::Syscall);
        assert_eq!(cpu.reg(0), 0, "{name}");
    }
    let mut sibling = backend.new_vcpu(BASE, STACK).unwrap();
    assert_eq!(run(sibling.as_mut(), &mut mem, false), Exit::Syscall);
    assert_eq!(sibling.reg(0), 0, "sibling vCPU");

    // Confined sandboxes hand a dropped vCPU's slot to the next one.
    let pooled = KvmBackend::new().unwrap();
    pooled.prepare_confinement(1, &mem).unwrap();
    for owner in 0..3 {
        let mut cpu = pooled.new_vcpu(BASE, STACK).unwrap();
        assert_eq!(run(cpu.as_mut(), &mut mem, false), Exit::Syscall);
        assert_eq!(cpu.reg(0), 0, "pooled slot owner {owner}");
    }
}

#[test]
fn prefixed_timestamps_can_end_at_a_page_boundary() {
    for opcode in [&[0x0f, 0x31][..], &[0x0f, 0x01, 0xf9][..]] {
        for prefixes in [
            vec![],
            vec![0x66],
            vec![0x67, 0xf3, 0x48],
            vec![0x66; 15 - opcode.len()],
        ] {
            let Some(backend) = backend() else { return };
            let mut mem = GuestMemory::new(BASE, 64 * 1024);
            mem.map(BASE, PAGE_SIZE, Prot::rx()).unwrap();
            let pc = BASE + PAGE_SIZE - (opcode.len() + prefixes.len()) as u64;
            let mut code = prefixes;
            code.extend_from_slice(opcode);
            mem.write_init(pc, &code).unwrap();
            let mut v = backend.new_vcpu(pc, STACK).unwrap();
            v.set_reg(1, u64::MAX);
            // The following fetch faults, but the timestamp read has completed.
            assert_eq!(
                run(v.as_mut(), &mut mem, true),
                Exit::MemFault {
                    addr: BASE + PAGE_SIZE,
                    write: false
                }
            );
            assert_eq!(v.pc(), BASE + PAGE_SIZE);
            assert_eq!((v.reg(0), v.reg(2)), (1, 0));
            assert_eq!(v.reg(1), if opcode.len() == 3 { 0 } else { u64::MAX });
        }
    }
}

#[test]
fn timestamps_can_cross_a_page_boundary() {
    for opcode in [&[0x0f, 0x31][..], &[0x0f, 0x01, 0xf9][..]] {
        for split in 1..opcode.len() {
            let Some(backend) = backend() else { return };
            let mut mem = GuestMemory::new(BASE, 64 * 1024);
            mem.map(BASE, 2 * PAGE_SIZE, Prot::rx()).unwrap();
            let pc = BASE + PAGE_SIZE - split as u64;
            let mut code = opcode.to_vec();
            code.extend_from_slice(&[0x0f, 0x05]);
            mem.write_init(pc, &code).unwrap();
            let mut v = backend.new_vcpu(pc, STACK).unwrap();
            assert_eq!(run(v.as_mut(), &mut mem, true), Exit::Syscall);
            assert_eq!((v.reg(0), v.reg(2)), (1, 0));
        }
    }
}

#[test]
fn noncanonical_instruction_fetch_is_a_protection_fault() {
    let Some(backend) = backend() else { return };
    let boundary = 1 << 47;
    for (code, expected_pc, expected_tsc) in [
        (&[0x0f, 0x31][..], boundary, 1),
        (&[0x0f][..], boundary - 1, 0),
    ] {
        let base = boundary - PAGE_SIZE;
        let mut mem = GuestMemory::new(base, PAGE_SIZE);
        mem.map(base, PAGE_SIZE, Prot::rx()).unwrap();
        let pc = boundary - code.len() as u64;
        mem.write_init(pc, code).unwrap();
        let mut v = backend.new_vcpu(pc, base + 128).unwrap();
        assert_eq!(
            run(v.as_mut(), &mut mem, true),
            Exit::ProtectionFault { pc: expected_pc }
        );
        assert_eq!(v.pc(), expected_pc);
        assert_eq!(v.reg(0), expected_tsc);
    }
}

#[test]
fn unrelated_gp_and_ud_recover_the_original_user_state() {
    for (code, illegal) in [
        (&[0xfa][..], false),            // CLI: #GP(0)
        (&[0xcd, 0x81][..], false),      // INT: #GP with a nonzero error code
        (&[0x0f, 0x0b][..], true),       // UD2
        (&[0xf0, 0x0f, 0x31][..], true), // LOCK RDTSC
        (
            &[
                0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                0x0f, 0x31,
            ][..],
            false,
        ), // 16 bytes: #GP
        (&[0xf0, 0x0f, 0x01, 0xf9][..], true), // LOCK RDTSCP
        (&[0x48, 0x0f, 0xc7, 0xf0][..], true), // masked RDRAND RAX
        (&[0x48, 0x0f, 0xc7, 0xf8][..], true), // masked RDSEED RAX
    ] {
        let Some(backend) = backend() else { return };
        let mut mem = GuestMemory::new(BASE, 64 * 1024);
        mem.map(BASE, PAGE_SIZE, Prot::rx()).unwrap();
        mem.write_init(BASE, code).unwrap();
        let mut v = backend.new_vcpu(BASE, STACK).unwrap();
        for i in 0..16 {
            if i != 4 {
                v.set_reg(i, 0x1234_0000 + i as u64);
            }
        }
        let expected = if illegal {
            Exit::IllegalInstruction { pc: BASE }
        } else {
            Exit::ProtectionFault { pc: BASE }
        };
        assert_eq!(run(v.as_mut(), &mut mem, true), expected, "{code:x?}");
        assert_eq!(v.pc(), BASE);
        assert_eq!(v.reg(4), STACK);
        for i in 0..16 {
            if i != 4 {
                assert_eq!(v.reg(i), 0x1234_0000 + i as u64, "register {i}, {code:x?}");
            }
        }
        // Redirect to user code, proving CPL3 and its exception stack were restored.
        v.set_pc(BASE + 32);
        mem.write_init(BASE + 32, &[0x0f, 0x31, 0x0f, 0x05])
            .unwrap();
        assert_eq!(run(v.as_mut(), &mut mem, false), Exit::Syscall);
        assert_eq!(v.reg(0), 1);
    }
}

#[test]
fn timestamp_reads_preserve_flags() {
    for opcode in [&[0x0f, 0x31][..], &[0x0f, 0x01, 0xf9][..]] {
        let Some(backend) = backend() else { return };
        let mut mem = GuestMemory::new(BASE, 64 * 1024);
        mem.map(BASE, PAGE_SIZE, Prot::rx()).unwrap();
        mem.map(STACK - PAGE_SIZE, PAGE_SIZE, Prot::rw()).unwrap();
        mem.write_init(STACK - 8, &[0; 8]).unwrap();
        // STD; STC; timestamp read; PUSHFQ; POP RBX; SYSCALL.
        let mut code = vec![0xfd, 0xf9];
        code.extend_from_slice(opcode);
        code.extend_from_slice(&[0x9c, 0x5b, 0x0f, 0x05]);
        mem.write_init(BASE, &code).unwrap();
        let mut v = backend.new_vcpu(BASE, STACK).unwrap();
        assert_eq!(run(v.as_mut(), &mut mem, true), Exit::Syscall);
        assert_eq!(v.reg(0), 1);
        assert_eq!(v.reg(3), 0x603, "CF, DF, IF and the fixed bit survive");
        assert_eq!(v.reg(11), 0x603, "SYSCALL's saved flags");
        assert_eq!(v.reg(4), STACK);
    }
}

#[test]
fn timestamp_trap_loop_still_yields() {
    for code in [
        &[0x0f, 0x31, 0xeb, 0xfc][..],
        &[0x0f, 0x01, 0xf9, 0xeb, 0xfb][..],
    ] {
        let Some(backend) = backend() else { return };
        let mut mem = GuestMemory::new(BASE, 64 * 1024);
        mem.map(BASE, PAGE_SIZE, Prot::rx()).unwrap();
        mem.write_init(BASE, code).unwrap(); // timestamp read; JMP back
        let mut v = backend.new_vcpu(BASE, STACK).unwrap();
        v.reconcile(&mut mem).unwrap();
        let started = std::time::Instant::now();
        for _ in 0..3 {
            assert_eq!(v.run_bare().unwrap(), Exit::Interrupted);
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }
}
