//! The public `Sandbox` API runs a static ELF end-to-end (loader → interpreter
//! → kernel), computing the heap/mmap/stack layout itself. This is the whole
//! pipeline exercised through the embeddable entry point (ROADMAP Phases 1-2).

use nixvm::Sandbox;
use nixvm::abi::Arch;

const EHDR_LEN: usize = 64;
const PHDR_LEN: usize = 56;
const PAGE: u64 = 4096;

/// Minimal ET_EXEC aarch64 ELF: one RWX PT_LOAD at `vaddr` covering headers +
/// `body`, entry at the start of `body`.
fn build_elf(vaddr: u64, body: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8; EHDR_LEN + PHDR_LEN];
    f[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    f[4] = 2;
    f[5] = 1;
    f[6] = 1;
    f[16..18].copy_from_slice(&2u16.to_le_bytes());
    f[18..20].copy_from_slice(&183u16.to_le_bytes()); // EM_AARCH64
    f[20..24].copy_from_slice(&1u32.to_le_bytes());
    let body_off = (EHDR_LEN + PHDR_LEN) as u64;
    f[24..32].copy_from_slice(&(vaddr + body_off).to_le_bytes());
    f[32..40].copy_from_slice(&(EHDR_LEN as u64).to_le_bytes());
    f[52..54].copy_from_slice(&(EHDR_LEN as u16).to_le_bytes());
    f[54..56].copy_from_slice(&(PHDR_LEN as u16).to_le_bytes());
    f[56..58].copy_from_slice(&1u16.to_le_bytes());
    let total = body_off + body.len() as u64;
    let p = EHDR_LEN;
    f[p..p + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    f[p + 4..p + 8].copy_from_slice(&7u32.to_le_bytes()); // RWX
    f[p + 16..p + 24].copy_from_slice(&vaddr.to_le_bytes());
    f[p + 24..p + 32].copy_from_slice(&vaddr.to_le_bytes());
    f[p + 32..p + 40].copy_from_slice(&total.to_le_bytes());
    f[p + 40..p + 48].copy_from_slice(&total.to_le_bytes());
    f[p + 48..p + 56].copy_from_slice(&PAGE.to_le_bytes());
    f.extend_from_slice(body);
    f
}

#[test]
fn sandbox_runs_static_elf_and_returns_exit_code() {
    // movz x0,#42 ; movz x8,#93 ; svc   -> exit(42)
    let program: [u32; 3] = [0xD280_0540, 0xD280_0BA8, 0xD400_0001];
    let mut body = Vec::new();
    for w in program {
        body.extend_from_slice(&w.to_le_bytes());
    }
    let elf = build_elf(0x1_0000, &body);

    let code = Sandbox::builder()
        // The ELF is aarch64; force that arch so the test is host-independent
        // (the default arch follows the host — x86-64 on a Linux CI runner).
        .arch(Arch::Aarch64)
        .command(["prog"])
        .prefer_interp(true)
        .mem_bytes(8 * 1024 * 1024)
        .build()
        .exec_elf(&elf)
        .expect("sandbox should run the ELF");

    assert_eq!(code, 42);
}

fn random_byte_elf() -> Vec<u8> {
    // getrandom(&byte, 1, 0); exit(byte). The scratch byte is in the ELF's RWX page.
    let program: [u32; 10] = [
        0xd280_2009, // movz x9, #0x100
        0xf2a0_0029, // movk x9, #1, lsl #16
        0xaa09_03e0, // mov x0, x9
        0xd280_0021, // movz x1, #1
        0xd280_0002, // movz x2, #0
        0xd280_22c8, // movz x8, #278 (getrandom)
        0xd400_0001, // svc #0
        0x3940_0120, // ldrb w0, [x9]
        0xd280_0ba8, // movz x8, #93 (exit)
        0xd400_0001, // svc #0
    ];
    let body: Vec<_> = program.into_iter().flat_map(u32::to_le_bytes).collect();
    build_elf(0x1_0000, &body)
}

#[test]
fn sandbox_seed_controls_each_exec_elf_run() {
    use rand_chacha::ChaCha20Rng;
    use rand_chacha::rand_core::{Rng, SeedableRng};

    let elf = random_byte_elf();
    for seed in [[0; 32], [42; 32], std::array::from_fn(|index| index as u8)] {
        let mut expected = [0; 4];
        ChaCha20Rng::from_seed(seed).fill_bytes(&mut expected);
        let sandbox = Sandbox::builder()
            .random_seed(seed)
            .arch(Arch::Aarch64)
            .prefer_interp(true)
            .mem_bytes(8 * 1024 * 1024)
            .build();
        assert_eq!(sandbox.config().random_seed, seed);
        for _ in 0..2 {
            assert_eq!(sandbox.exec_elf(&elf).unwrap(), i32::from(expected[0]));
        }
    }
}

#[cfg(feature = "cli")]
#[test]
fn cli_seed_reaches_the_guest() {
    use rand_chacha::ChaCha20Rng;
    use rand_chacha::rand_core::{Rng, SeedableRng};

    let root = std::env::temp_dir().join(format!("nixvm-random-cli-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("random-byte"), random_byte_elf()).unwrap();
    let seed = std::array::from_fn(|index| index as u8);
    let mut expected = [0; 4];
    ChaCha20Rng::from_seed(seed).fill_bytes(&mut expected);
    let encoded = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_nixvm"))
        .args(["run", "--mem", "8M", "--arch", "aarch64", "--root"])
        .arg(&root)
        .args(["--random-seed", encoded, "--", "/random-byte"])
        .output()
        .unwrap();
    std::fs::remove_dir_all(&root).unwrap();
    assert_eq!(
        output.status.code(),
        Some(i32::from(expected[0])),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
