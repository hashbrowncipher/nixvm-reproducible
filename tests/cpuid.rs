//! Execute CPUID, AVX and the Ice Lake-SP floor's instructions through the public vcpu
//! interface.

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
        [0x0005_06e3, 0x0001_0800, 0xbed8_3203, 0x078b_ebfd]
    );
    assert_eq!(answers[6], [0, 0x2198_03a8, 0x0040_0700, 0x2000_0000]);
    assert_eq!(answers[11], [7, 832, 832, 0]);
    assert_eq!(answers[13], [256, 576, 0, 0]);
    assert_ne!(answers[20][3] & (1 << 27), 0, "RDTSCP is advertised");
    assert_eq!(answers[20][2], 0x121, "LAHF, LZCNT and PREFETCHW");
    assert_reports_ice_lake_features(&answers);
}

/// The Ice Lake-SP floor's extensions: (name, `cpuid_answers` row, register, bit).
/// Registers are indexed EAX, EBX, ECX, EDX.
const ICE_LAKE_FEATURES: [(&str, usize, usize, u32); 14] = [
    ("PCLMULQDQ", 2, 2, 1),
    ("FMA", 2, 2, 12),
    ("AES", 2, 2, 25),
    ("F16C", 2, 2, 29),
    ("ADX", 6, 1, 19),
    ("CLFLUSHOPT", 6, 1, 23),
    ("CLWB", 6, 1, 24),
    ("SHA", 6, 1, 29),
    ("GFNI", 6, 2, 8),
    ("VAES", 6, 2, 9),
    ("VPCLMULQDQ", 6, 2, 10),
    ("RDPID", 6, 2, 22),
    ("LZCNT", 20, 2, 5),
    ("PREFETCHW", 20, 2, 8),
];

fn assert_reports_ice_lake_features(answers: &[[u64; 4]]) {
    for (name, row, register, bit) in ICE_LAKE_FEATURES {
        assert_ne!(
            answers[row][register] & (1 << bit),
            0,
            "{name} is advertised"
        );
    }
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

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn kvm_cpuid_reports_each_ice_lake_feature() {
    let kvm = match nixvm::vcpu::kvm::KvmBackend::new() {
        Ok(backend) => backend,
        Err(error) => {
            eprintln!("skipping KVM CPUID feature test: {error}");
            return;
        }
    };
    assert_reports_ice_lake_features(&cpuid_answers(&kvm));
}

/// Whether the interpreter executes a probe's instruction. The CPUID profile is shared,
/// and the interpreter implements only part of it: see docs/cpu.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Interpreter {
    Executes,
    /// `#UD` at the feature's first instruction.
    Undefined,
    /// `#GP` at the feature's first instruction. Unknown `66 0F 38` opcodes read a
    /// 16-byte-aligned source before the interpreter rejects the opcode, so a misaligned
    /// memory operand faults before the `#UD` a CPU without the feature would raise.
    MisalignedOperand,
}

/// One instruction from an advertised feature, checked against a known result.
///
/// RBX holds `DATA`. The probe reads `input` from `DATA`, writes `output` at `DATA + 0x40`,
/// and ends with SYSCALL. Output bytes start as 0xAA, so partial stores remain visible.
/// The expected values come from SDM models in
/// `docs/worklog/2026-10-20-cpuid-features/expected.py`, which hardware also matched.
struct Probe {
    feature: &'static str,
    code: &'static [u8],
    /// The offset of the feature's first instruction in `code`.
    at: u64,
    input: &'static str,
    output: &'static str,
    interpreter: Interpreter,
}

const PROBES: &[Probe] = &[
    Probe {
        feature: "FMA",
        // vmovsd xmm0, [rbx]; vmovsd xmm1, [rbx+8]; vfmadd213sd xmm0, xmm1, [rbx+16]
        // vmovsd [rbx+0x40], xmm0; syscall
        // (1 + 2^-30)(1 - 2^-30) - 1 = -2^-60, which only a fused multiply-add keeps.
        code: &[
            0xc5, 0xfb, 0x10, 0x03, 0xc5, 0xfb, 0x10, 0x4b, 0x08, 0xc4, 0xe2, 0xf1, 0xa9, 0x43,
            0x10, 0xc5, 0xfb, 0x11, 0x43, 0x40, 0x0f, 0x05,
        ],
        at: 9,
        input: "000040000000f03f000080ffffffef3f000000000000f0bf",
        output: "00000000000030bc",
        interpreter: Interpreter::Executes,
    },
    Probe {
        feature: "F16C",
        // vcvtph2ps xmm0, [rbx]; vmovdqu [rbx+0x40], xmm0; syscall
        // Halves 1.0, -2.0, 65504 and 2^-24 widen to the same singles.
        code: &[
            0xc4, 0xe2, 0x79, 0x13, 0x03, 0xc5, 0xfa, 0x7f, 0x43, 0x40, 0x0f, 0x05,
        ],
        at: 0,
        input: "003c00c0ff7b0100",
        output: "0000803f000000c000e07f4700008033",
        interpreter: Interpreter::Executes,
    },
    Probe {
        feature: "LZCNT",
        // lzcnt rax, [rbx]; mov [rbx+0x40], rax; setc [rbx+0x48]
        // lzcnt rax, [rbx+8]; mov [rbx+0x50], rax; setc [rbx+0x58]; syscall
        // LZCNT(0) = 64 with CF set; LZCNT(1) = 63, where BSR would give 0.
        code: &[
            0xf3, 0x48, 0x0f, 0xbd, 0x03, 0x48, 0x89, 0x43, 0x40, 0x0f, 0x92, 0x43, 0x48, 0xf3,
            0x48, 0x0f, 0xbd, 0x43, 0x08, 0x48, 0x89, 0x43, 0x50, 0x0f, 0x92, 0x43, 0x58, 0x0f,
            0x05,
        ],
        at: 0,
        input: "00000000000000000100000000000000",
        output: "400000000000000001aaaaaaaaaaaaaa3f0000000000000000aaaaaaaaaaaaaa",
        interpreter: Interpreter::Executes,
    },
    Probe {
        feature: "PREFETCHW",
        // prefetchw [rbx]; mov dword [rbx+0x40], 0x600d; syscall
        code: &[
            0x0f, 0x0d, 0x0b, 0xc7, 0x43, 0x40, 0x0d, 0x60, 0x00, 0x00, 0x0f, 0x05,
        ],
        at: 0,
        input: "",
        output: "0d600000",
        interpreter: Interpreter::Executes,
    },
    Probe {
        feature: "CLFLUSHOPT",
        // clflushopt [rbx]; mov dword [rbx+0x40], 0x600d; syscall
        code: &[
            0x66, 0x0f, 0xae, 0x3b, 0xc7, 0x43, 0x40, 0x0d, 0x60, 0x00, 0x00, 0x0f, 0x05,
        ],
        at: 0,
        input: "",
        output: "0d600000",
        interpreter: Interpreter::Executes,
    },
    Probe {
        feature: "AES-NI",
        // movdqu xmm0, [rbx]; aesenc xmm0, [rbx+16]; movdqu [rbx+0x40], xmm0; syscall
        // The AESENC example from Intel's AES-NI white paper.
        code: &[
            0xf3, 0x0f, 0x6f, 0x03, 0x66, 0x0f, 0x38, 0xdc, 0x43, 0x10, 0xf3, 0x0f, 0x7f, 0x43,
            0x40, 0x0f, 0x05,
        ],
        at: 4,
        input: "5d47535d726f74636556747365545b7b5d6e6f726575475b2979616853286948",
        output: "95e5d7de584b108bc5a3db9f2f1c31a8",
        interpreter: Interpreter::Undefined,
    },
    Probe {
        feature: "PCLMULQDQ",
        // movdqu xmm0, [rbx]; pclmulqdq xmm0, [rbx+16], 0x01; movdqu [rbx+0x40], xmm0
        // syscall
        code: &[
            0xf3, 0x0f, 0x6f, 0x03, 0x66, 0x0f, 0x3a, 0x44, 0x43, 0x10, 0x01, 0xf3, 0x0f, 0x7f,
            0x43, 0x40, 0x0f, 0x05,
        ],
        at: 4,
        input: "efcdab896745230101000000000000808796a5b4c3d2e1f0ffffffffffffffff",
        output: "8796a5b4c3d2e17043cb52da61e97078",
        interpreter: Interpreter::Undefined,
    },
    Probe {
        feature: "ADX",
        // xor eax, eax; mov rax, [rbx]; mov rdx, rax
        // adcx rax, [rbx+8]; adox rdx, [rbx+8]; adcx rax, [rbx+16]; adox rdx, [rbx+16]
        // with setc/seto after each into [rbx+0x50..0x58]
        // mov [rbx+0x40], rax; mov [rbx+0x48], rdx; syscall
        // MAX + 1 carries through CF and OF independently.
        code: &[
            0x31, 0xc0, 0x48, 0x8b, 0x03, 0x48, 0x89, 0xc2, 0x66, 0x48, 0x0f, 0x38, 0xf6, 0x43,
            0x08, 0x0f, 0x92, 0x43, 0x50, 0x0f, 0x90, 0x43, 0x51, 0xf3, 0x48, 0x0f, 0x38, 0xf6,
            0x53, 0x08, 0x0f, 0x92, 0x43, 0x52, 0x0f, 0x90, 0x43, 0x53, 0x66, 0x48, 0x0f, 0x38,
            0xf6, 0x43, 0x10, 0x0f, 0x92, 0x43, 0x54, 0x0f, 0x90, 0x43, 0x55, 0xf3, 0x48, 0x0f,
            0x38, 0xf6, 0x53, 0x10, 0x0f, 0x92, 0x43, 0x56, 0x0f, 0x90, 0x43, 0x57, 0x48, 0x89,
            0x43, 0x40, 0x48, 0x89, 0x53, 0x48, 0x0f, 0x05,
        ],
        at: 8,
        input: "ffffffffffffffff01000000000000000000000000000000",
        output: "010000000000000001000000000000000100010100010000",
        interpreter: Interpreter::MisalignedOperand,
    },
    Probe {
        feature: "CLWB",
        // clwb [rbx]; mov dword [rbx+0x40], 0x600d; syscall
        code: &[
            0x66, 0x0f, 0xae, 0x33, 0xc7, 0x43, 0x40, 0x0d, 0x60, 0x00, 0x00, 0x0f, 0x05,
        ],
        at: 0,
        input: "",
        output: "0d600000",
        interpreter: Interpreter::Undefined,
    },
    Probe {
        feature: "SHA",
        // movdqu xmm1, [rbx]; movdqu xmm2, [rbx+16]; movdqu xmm0, [rbx+32]
        // sha256rnds2 xmm1, xmm2, xmm0; movdqu [rbx+0x40], xmm1; syscall
        // Two SHA-256 rounds from the initial hash state with K0 and K1 as WK.
        code: &[
            0xf3, 0x0f, 0x6f, 0x0b, 0xf3, 0x0f, 0x6f, 0x53, 0x10, 0xf3, 0x0f, 0x6f, 0x43, 0x20,
            0x0f, 0x38, 0xcb, 0xca, 0xf3, 0x0f, 0x7f, 0x4b, 0x40, 0x0f, 0x05,
        ],
        at: 14,
        input: concat!(
            "19cde05babd9831f3af54fa572f36e3c8c68059b7f520e5185ae67bb67e6096a",
            "982f8a42914437710000000000000000",
        ),
        output: "a2e2c79816b2f19d4d8808fc9062d97a",
        interpreter: Interpreter::Undefined,
    },
    Probe {
        feature: "GFNI",
        // movdqu xmm0, [rbx]; gf2p8mulb xmm0, [rbx+16]; movdqu [rbx+0x40], xmm0; syscall
        // 0x53 * 0xCA = 1 and 2 * 0x80 = 0x1B in the AES field.
        code: &[
            0xf3, 0x0f, 0x6f, 0x03, 0x66, 0x0f, 0x38, 0xcf, 0x43, 0x10, 0xf3, 0x0f, 0x7f, 0x43,
            0x40, 0x0f, 0x05,
        ],
        at: 4,
        input: "530203ff00018d571011121314151617ca8003ff77770283f0f1f2f3f4f5f6f7",
        output: "011b0513007701c1997846a724c5fb1a",
        interpreter: Interpreter::Undefined,
    },
    Probe {
        feature: "VAES",
        // vmovdqu ymm0, [rbx]; vaesenc ymm0, ymm0, [rbx+32]; vmovdqu [rbx+0x40], ymm0
        // syscall. Lane 1 swaps the white-paper state and key.
        code: &[
            0xc5, 0xfe, 0x6f, 0x03, 0xc4, 0xe2, 0x7d, 0xdc, 0x43, 0x20, 0xc5, 0xfe, 0x7f, 0x43,
            0x40, 0x0f, 0x05,
        ],
        at: 4,
        input: concat!(
            "5d47535d726f74636556747365545b7b5d6e6f726575475b2979616853286948",
            "5d6e6f726575475b29796168532869485d47535d726f74636556747365545b7b",
        ),
        output: "95e5d7de584b108bc5a3db9f2f1c31a8c452b15f9005a67bf941e569fb22bde2",
        interpreter: Interpreter::Undefined,
    },
    Probe {
        feature: "VPCLMULQDQ",
        // vmovdqu ymm0, [rbx]; vpclmulqdq ymm0, ymm0, [rbx+32], 0x10
        // vmovdqu [rbx+0x40], ymm0; syscall
        code: &[
            0xc5, 0xfe, 0x6f, 0x03, 0xc4, 0xe3, 0x7d, 0x44, 0x43, 0x20, 0x10, 0xc5, 0xfe, 0x7f,
            0x43, 0x40, 0x0f, 0x05,
        ],
        at: 4,
        input: concat!(
            "efcdab8967452301111100000000000003000000efbeadde2222000000000000",
            "33330000000000008796a5b4c3d2e1f044440000000000000500000000000080",
        ),
        output: "0d840357c1f3cf202da42377e1d3ef000f00000053451b240200008077df566f",
        interpreter: Interpreter::Undefined,
    },
    Probe {
        feature: "RDPID",
        // mov rax, -1; rdpid rax; mov [rbx+0x40], rax; syscall
        // TSC_AUX is fixed at zero.
        code: &[
            0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0xf3, 0x0f, 0xc7, 0xf8, 0x48, 0x89, 0x43,
            0x40, 0x0f, 0x05,
        ],
        at: 7,
        input: "",
        output: "0000000000000000",
        interpreter: Interpreter::Undefined,
    },
];

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn run_probe(backend: &dyn Backend, probe: &Probe) -> (Exit, Vec<u8>) {
    let mut mem = GuestMemory::new(BASE, 64 * 1024);
    mem.map(BASE, 2 * PAGE_SIZE, Prot::rwx()).unwrap();
    mem.write_init(BASE, probe.code).unwrap();
    mem.write_init(DATA, &hex(probe.input)).unwrap();
    let output = probe.output.len() / 2;
    mem.write_init(DATA + 0x40, &vec![0xaa; output]).unwrap();
    let mut vcpu = backend.new_vcpu(BASE, BASE + 0x8000).unwrap();
    vcpu.set_reg(3, DATA);
    for _ in 0..100 {
        match vcpu.run(&mut mem).unwrap() {
            Exit::Interrupted => {}
            exit => return (exit, mem.read_vec(DATA + 0x40, output).unwrap()),
        }
    }
    panic!("{} probe made no progress", probe.feature);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn kvm_executes_one_instruction_from_each_ice_lake_feature() {
    let kvm = match nixvm::vcpu::kvm::KvmBackend::new() {
        Ok(backend) => backend,
        Err(error) => {
            eprintln!("skipping KVM feature execution test: {error}");
            return;
        }
    };
    assert_eq!(PROBES.len(), ICE_LAKE_FEATURES.len());
    for probe in PROBES {
        let (exit, output) = run_probe(&kvm, probe);
        assert_eq!(exit, Exit::Syscall, "{}", probe.feature);
        assert_eq!(output, hex(probe.output), "{}", probe.feature);
    }
}

/// The accepted divergence: the interpreter shares the profile but faults on the advertised
/// instructions it does not implement.
#[test]
fn interpreter_executes_or_rejects_each_ice_lake_feature_as_documented() {
    let backend = nixvm::vcpu::interp_x86::X86Backend::new(Arch::X86_64).unwrap();
    for probe in PROBES {
        let (exit, output) = run_probe(&backend, probe);
        match probe.interpreter {
            Interpreter::Executes => {
                assert_eq!(exit, Exit::Syscall, "{}", probe.feature);
                assert_eq!(output, hex(probe.output), "{}", probe.feature);
            }
            Interpreter::Undefined => {
                let pc = BASE + probe.at;
                assert_eq!(exit, Exit::IllegalInstruction { pc }, "{}", probe.feature);
            }
            Interpreter::MisalignedOperand => {
                let pc = BASE + probe.at;
                assert_eq!(exit, Exit::ProtectionFault { pc }, "{}", probe.feature);
            }
        }
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
