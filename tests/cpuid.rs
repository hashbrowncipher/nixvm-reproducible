//! Execute CPUID and AVX instructions through the public vcpu interface.

use nixvm::abi::Arch;
use nixvm::vcpu::mem::PAGE_SIZE;
use nixvm::vcpu::{Backend, Exit, GuestMemory, Prot, Vcpu};

const BASE: u64 = 0x1_0000;
const DATA: u64 = BASE + PAGE_SIZE;

fn until_syscall(vcpu: &mut dyn Vcpu, mem: &mut GuestMemory, bare: bool) {
    if bare {
        vcpu.reconcile(mem).unwrap();
    }
    for _ in 0..100 {
        let exit = if bare { vcpu.run_bare() } else { vcpu.run(mem) }.unwrap();
        match exit {
            Exit::Interrupted => {}
            Exit::Syscall => return,
            other => panic!("unexpected guest exit: {other:?}"),
        }
    }
    panic!("guest did not reach syscall");
}

fn cpuid_answers(backend: &dyn Backend) -> Vec<[u64; 4]> {
    let mut mem = GuestMemory::new(BASE, 64 * 1024);
    mem.map(BASE, PAGE_SIZE, Prot::rwx()).unwrap();
    // CPUID; MOV ESI, ECX; SYSCALL. SYSCALL clobbers RCX, so preserve it first.
    mem.write_init(BASE, &[0x0f, 0xa2, 0x89, 0xce, 0x0f, 0x05])
        .unwrap();
    let mut vcpu = backend.new_vcpu(BASE, BASE + 0x8000).unwrap();
    let queries = [
        (0, 0),
        (0, u32::MAX),
        (1, 0),
        (1, u32::MAX),
        (3, 0),
        (4, 0),
        (7, 0),
        (7, 1),
        (0xb, 0),
        (0xb, 1),
        (0xb, 2),
        (0xd, 0),
        (0xd, 1),
        (0xd, 2),
        (0xd, 3),
        (0x15, 0),
        (0x16, 0),
        (0x17, 0),
        (0x4000_0000, 0),
        (0x8000_0000, 0),
        (0x8000_0001, 0),
        (0x8000_0002, 0),
        (0x8000_0003, 0),
        (0x8000_0004, 0),
        (0x8000_0008, 0),
        (0x8000_0009, 0),
        (u32::MAX, u32::MAX),
        (0xb, u32::MAX),
    ];
    queries
        .into_iter()
        .enumerate()
        .map(|(index, (leaf, subleaf))| {
            vcpu.reset(BASE, BASE + 0x8000);
            vcpu.set_reg(0, 0xffff_ffff_0000_0000 | u64::from(leaf));
            vcpu.set_reg(1, 0xffff_ffff_0000_0000 | u64::from(subleaf));
            until_syscall(
                vcpu.as_mut(),
                &mut mem,
                index % 2 == 0 && backend.name() == "kvm",
            );
            [vcpu.reg(0), vcpu.reg(3), vcpu.reg(6), vcpu.reg(2)]
        })
        .collect()
}

#[test]
fn interpreter_reports_the_fixed_identity_and_avx_profile() {
    let backend = nixvm::vcpu::interp_x86::X86Backend::new(Arch::X86_64).unwrap();
    let answers = cpuid_answers(&backend);
    assert_eq!(answers[0], [0x16, 0x756e_6547, 0x6c65_746e, 0x4965_6e69]);
    assert_eq!(
        answers[2],
        [0x0005_06e3, 0x0001_0800, 0x9cd8_2201, 0x078b_ebfd]
    );
    assert_eq!(answers[6], [0, 0x0010_03a8, 0, 0x2000_0000]);
    assert_eq!(answers[11], [7, 832, 832, 0]);
    assert_eq!(answers[13], [256, 576, 0, 0]);
    assert_ne!(answers[20][3] & (1 << 27), 0, "RDTSCP is advertised");
}

#[test]
fn interpreter_rdtscp_returns_a_logical_timestamp_and_fixed_aux() {
    let backend = nixvm::vcpu::interp_x86::X86Backend::new(Arch::X86_64).unwrap();
    let mut mem = GuestMemory::new(BASE, 64 * 1024);
    mem.map(BASE, PAGE_SIZE, Prot::rx()).unwrap();
    // RDTSCP; MOV RSI, RCX; SYSCALL. Preserve TSC_AUX before SYSCALL clobbers RCX.
    mem.write_init(BASE, &[0x0f, 0x01, 0xf9, 0x48, 0x89, 0xce, 0x0f, 0x05])
        .unwrap();
    let mut v = backend.new_vcpu(BASE, BASE + 0x8000).unwrap();
    for index in [0, 1, 2] {
        v.set_reg(index, u64::MAX);
    }
    until_syscall(v.as_mut(), &mut mem, false);
    assert_eq!((v.reg(0), v.reg(2), v.reg(6)), (1, 0, 0));
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn kvm_and_interpreter_report_identical_cpuid() {
    let kvm = match nixvm::vcpu::kvm::KvmBackend::new() {
        Ok(backend) => backend,
        Err(error) => {
            eprintln!("skipping KVM CPUID test: {error}");
            return;
        }
    };
    let interpreter = nixvm::vcpu::interp_x86::X86Backend::new(Arch::X86_64).unwrap();
    let expected = cpuid_answers(&interpreter);
    let actual = cpuid_answers(&kvm);
    for (index, (hardware, software)) in actual.iter().zip(&expected).enumerate() {
        assert_eq!(hardware, software, "CPUID query {index}");
    }
}

fn check_ymm_state(backend: &dyn Backend) {
    let mut mem = GuestMemory::new(BASE, 64 * 1024);
    mem.map(BASE, 2 * PAGE_SIZE, Prot::rwx()).unwrap();
    let input: Vec<u8> = (1..=8u32).flat_map(u32::to_le_bytes).collect();
    mem.write_init(DATA, &input).unwrap();
    let mut code = vec![0x48, 0xbb]; // mov rbx, DATA
    code.extend_from_slice(&DATA.to_le_bytes());
    code.extend_from_slice(&[
        0xc5, 0xfe, 0x6f, 0x03, // vmovdqu ymm0, [rbx]
        0x0f, 0x05, // syscall
        0xc5, 0xfd, 0xfe, 0xc0, // vpaddd ymm0, ymm0, ymm0 (AVX2)
    ]);
    let store_pc = BASE + code.len() as u64;
    code.extend_from_slice(&[
        0xc5, 0xfe, 0x7f, 0x43, 0x20, // vmovdqu [rbx+32], ymm0
        0x0f, 0x05, // syscall
    ]);
    mem.write_init(BASE, &code).unwrap();
    let mut vcpu = backend.new_vcpu(BASE, BASE + 0x8000).unwrap();
    until_syscall(vcpu.as_mut(), &mut mem, false);
    let saved = vcpu.simd_state();
    assert_eq!(saved.len(), 832);
    assert_eq!(&saved[160..176], &input[..16]);
    assert_eq!(&saved[576..592], &input[16..]);

    let mut changed = saved.clone();
    changed[576..592].fill(0);
    vcpu.set_simd_state(&changed);
    vcpu.set_simd_state(&saved);
    vcpu.set_syscall_ret(0);
    until_syscall(vcpu.as_mut(), &mut mem, false);
    let doubled: Vec<u8> = (1..=8u32)
        .flat_map(|value| (value * 2).to_le_bytes())
        .collect();
    assert_eq!(mem.read_vec(DATA + 32, 32).unwrap(), doubled);

    vcpu.reset(store_pc, BASE + 0x8000);
    vcpu.set_reg(3, DATA);
    until_syscall(vcpu.as_mut(), &mut mem, false);
    assert_eq!(mem.read_vec(DATA + 32, 32).unwrap(), vec![0; 32]);

    vcpu.reset(store_pc, BASE + 0x8000);
    vcpu.set_simd_state(&saved[..512]);
    vcpu.set_reg(3, DATA);
    until_syscall(vcpu.as_mut(), &mut mem, false);
    let mut legacy = input;
    legacy[16..].fill(0);
    assert_eq!(mem.read_vec(DATA + 32, 32).unwrap(), legacy);

    // XRSTOR restores MXCSR even when XSTATE_BV marks XMM/YMM state as initial.
    // Observe the actual guest registers, rather than comparing XSAVE serializers.
    mem.write_init(
        BASE,
        &[
            0x0f, 0xae, 0x1b, // stmxcsr [rbx]
            0xc5, 0xfe, 0x7f, 0x43, 0x20, // vmovdqu [rbx+32], ymm0
            0x0f, 0x05, // syscall
        ],
    )
    .unwrap();
    for components in 0..=7u64 {
        let mut image = saved.clone();
        image[24..28].copy_from_slice(&0x5f80u32.to_le_bytes());
        image[512..520].copy_from_slice(&components.to_le_bytes());
        vcpu.reset(BASE, BASE + 0x8000);
        vcpu.set_simd_state(&image);
        vcpu.set_reg(3, DATA);
        until_syscall(vcpu.as_mut(), &mut mem, false);
        assert_eq!(
            mem.read_u32(DATA).unwrap(),
            0x5f80,
            "MXCSR, XSTATE_BV={components}"
        );
        let mut expected = saved[160..176].to_vec();
        expected.extend_from_slice(&saved[576..592]);
        if components & 2 == 0 {
            expected[..16].fill(0);
        }
        if components & 4 == 0 {
            expected[16..].fill(0);
        }
        assert_eq!(
            mem.read_vec(DATA + 32, 32).unwrap(),
            expected,
            "YMM, XSTATE_BV={components}"
        );
    }
}

#[test]
fn interpreter_preserves_avx_state_and_executes_avx2() {
    let backend = nixvm::vcpu::interp_x86::X86Backend::new(Arch::X86_64).unwrap();
    check_ymm_state(&backend);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn kvm_preserves_avx_state_and_executes_avx2() {
    let backend = match nixvm::vcpu::kvm::KvmBackend::new() {
        Ok(backend) => backend,
        Err(error) => {
            eprintln!("skipping KVM AVX test: {error}");
            return;
        }
    };
    check_ymm_state(&backend);
}
