//! Subprocess checks for the default CLI confinement boundary.
#![cfg(all(feature = "cli", target_os = "linux", target_arch = "x86_64"))]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Root(PathBuf);
impl Root {
    fn new(tag: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("nixvm-confined-{}-{tag}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn write(&self, name: &str, code: &[u8]) {
        std::fs::write(self.0.join(name), elf(code)).unwrap();
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn elf(code: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 120];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x1_0078u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
    bytes[68..72].copy_from_slice(&7u32.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x1_0000u64.to_le_bytes());
    let size = 120 + code.len() as u64;
    bytes[96..104].copy_from_slice(&size.to_le_bytes());
    bytes[104..112].copy_from_slice(&size.to_le_bytes());
    bytes[112..120].copy_from_slice(&4096u64.to_le_bytes());
    bytes.extend_from_slice(code);
    bytes
}
fn mov32(code: &mut Vec<u8>, opcode: u8, value: u32) {
    code.push(opcode);
    code.extend_from_slice(&value.to_le_bytes());
}
fn syscall(code: &mut Vec<u8>, number: u32) {
    mov32(code, 0xb8, number);
    code.extend_from_slice(&[0x0f, 0x05]);
}
fn exit(code: &mut Vec<u8>, value: u32) {
    mov32(code, 0xbf, value);
    syscall(code, 60);
}
fn jump(code: &mut Vec<u8>, condition: u8) -> usize {
    code.extend_from_slice(&[0x0f, condition, 0, 0, 0, 0]);
    code.len() - 4
}
fn target(code: &mut [u8], offset: usize, destination: usize) {
    code[offset..offset + 4]
        .copy_from_slice(&((destination as i32) - (offset as i32 + 4)).to_le_bytes());
}

fn run(root: &Path, args: &[&str], environment: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nixvm"));
    command
        .args(["run", "--mem", "8M", "--root"])
        .arg(root)
        .args(args)
        .args(["--", "/init"]);
    command
        .env_remove("NIXVM_NET")
        .env_remove("NIXVM_BRANCH_QUANTUM")
        .env_remove("NIXVM_INTERP")
        .env_remove("NIXVM_CPUS");
    command.envs(environment.iter().copied());
    command.output().unwrap()
}
fn assert_code(output: &Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn directory_root_runs_and_host_symlinks_fail_safely() {
    let root = Root::new("root");
    let mut code = Vec::new();
    exit(&mut code, 42);
    root.write("init", &code);
    assert_code(&run(&root.0, &[], &[("NIXVM_INTERP", "1")]), 42);
    std::fs::remove_file(root.0.join("init")).unwrap();
    std::os::unix::fs::symlink("real", root.0.join("init")).unwrap();
    root.write("real", &code);
    let output = run(&root.0, &[], &[("NIXVM_INTERP", "1")]);
    assert_code(&output, 1);
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot read PID 1"));
}

#[test]
fn work_is_opt_in_and_non_symlink_file_access_works() {
    let root = Root::new("work");
    let work = Root::new("shared");
    std::fs::write(work.0.join("input"), [23]).unwrap();
    let mut code = Vec::new();
    mov32(&mut code, 0xbf, (-100i32) as u32);
    code.extend_from_slice(&[0x48, 0xbe]);
    let path = code.len();
    code.extend_from_slice(&0u64.to_le_bytes());
    code.extend_from_slice(&[0x31, 0xd2]);
    syscall(&mut code, 257);
    code.extend_from_slice(&[0x48, 0x85, 0xc0]);
    let missing = jump(&mut code, 0x88);
    code.extend_from_slice(&[0x48, 0x89, 0xc7, 0x48, 0x83, 0xec, 8, 0x48, 0x89, 0xe6]);
    mov32(&mut code, 0xba, 1);
    syscall(&mut code, 0);
    code.extend_from_slice(&[0x0f, 0xb6, 0x3c, 0x24]);
    syscall(&mut code, 60);
    let denied = code.len();
    exit(&mut code, 7);
    target(&mut code, missing, denied);
    let address = 0x1_0078 + code.len() as u64;
    code[path..path + 8].copy_from_slice(&address.to_le_bytes());
    code.extend_from_slice(b"/work/input\0");
    root.write("init", &code);
    assert_code(&run(&root.0, &[], &[("NIXVM_INTERP", "1")]), 7);
    assert_code(
        &run(
            &root.0,
            &["--workdir", work.0.to_str().unwrap()],
            &[("NIXVM_INTERP", "1")],
        ),
        23,
    );
}

fn fork_exec_program(iterations: u32) -> Vec<u8> {
    let mut code = vec![0x41];
    mov32(&mut code, 0xbc, iterations);
    let start = code.len();
    syscall(&mut code, 57);
    code.extend_from_slice(&[0x48, 0x85, 0xc0]);
    let failed = jump(&mut code, 0x88);
    let child = jump(&mut code, 0x84);
    code.extend_from_slice(&[
        0x48, 0x89, 0xc7, 0x48, 0x83, 0xec, 8, 0x48, 0x89, 0xe6, 0x31, 0xd2, 0x45, 0x31, 0xd2,
    ]);
    syscall(&mut code, 61);
    code.extend_from_slice(&[0x48, 0x83, 0xc4, 8, 0x41, 0xff, 0xcc]);
    let again = jump(&mut code, 0x85);
    target(&mut code, again, start);
    exit(&mut code, 0);
    let child_start = code.len();
    target(&mut code, child, child_start);
    code.extend_from_slice(&[0x48, 0xbf]);
    let path = code.len();
    code.extend_from_slice(&0u64.to_le_bytes());
    code.extend_from_slice(&[0x31, 0xf6, 0x31, 0xd2]);
    syscall(&mut code, 59);
    let failure = code.len();
    target(&mut code, failed, failure);
    exit(&mut code, 99);
    let address = 0x1_0078 + code.len() as u64;
    code[path..path + 8].copy_from_slice(&address.to_le_bytes());
    code.extend_from_slice(b"/done\0");
    code
}

#[test]
#[ignore = "requires real KVM and guest-only Intel perf counters"]
fn kvm_fork_exec_reuses_slots_and_measured_smp_is_rejected() {
    nixvm::vcpu::kvm::KvmBackend::new().expect("hardware test requires KVM");
    let root = Root::new("fork");
    root.write("init", &fork_exec_program(8));
    let mut done = Vec::new();
    exit(&mut done, 37);
    root.write("done", &done);
    for environment in [
        vec![],
        vec![("NIXVM_CPUS", "4")],
        vec![("NIXVM_BRANCH_QUANTUM", "8")],
    ] {
        let output = run(&root.0, &["--vcpu-capacity", "2"], &environment);
        if environment.iter().any(|(name, _)| *name == "NIXVM_CPUS") {
            assert_code(&output, 1);
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("virtual execution requires one scheduler CPU")
            );
        } else {
            assert_code(&output, 0);
        }
    }
}

#[cfg(feature = "erofs")]
#[test]
fn strict_erofs_cli_parses_and_decompresses_after_confinement() {
    for name in ["base", "lz4", "lzma", "deflate", "zstd"] {
        let image = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(format!("tests/data/erofs/{name}.erofs"));
        let output = Command::new(env!("CARGO_BIN_EXE_nixvm"))
            .args(["run", "--mem", "8M", "--erofs"])
            .arg(image)
            .args(["--", "/init"])
            .env("NIXVM_INTERP", "1")
            .output()
            .unwrap();
        assert_code(&output, 42);
    }
}

#[test]
#[ignore = "requires real KVM"]
fn pool_exhaustion_is_guest_eagain_without_pid_or_randomness_side_effects() {
    nixvm::vcpu::kvm::KvmBackend::new().expect("hardware test requires KVM");
    let root = Root::new("exhaustion");
    let mut code = vec![0x48, 0x83, 0xec, 16];
    let mut failures = Vec::new();
    for (index, expected) in [0x76u8, 0xb8].into_iter().enumerate() {
        code.extend_from_slice(&[0x48, 0x89, 0xe7]);
        mov32(&mut code, 0xbe, 1);
        code.extend_from_slice(&[0x31, 0xd2]);
        syscall(&mut code, 318);
        code.extend_from_slice(&[0x80, 0x3c, 0x24, expected]);
        failures.push(jump(&mut code, 0x85));
        if index == 0 {
            syscall(&mut code, 57);
            code.extend_from_slice(&[0x48, 0x83, 0xf8, 0xf5]);
            failures.push(jump(&mut code, 0x85));
            syscall(&mut code, 39);
            code.extend_from_slice(&[0x83, 0xf8, 1]);
            failures.push(jump(&mut code, 0x85));
            // No partial child exists after rejected fork: wait4 returns ECHILD.
            mov32(&mut code, 0xbf, u32::MAX);
            code.extend_from_slice(&[0x31, 0xf6]);
            mov32(&mut code, 0xba, 1);
            code.extend_from_slice(&[0x45, 0x31, 0xd2]);
            syscall(&mut code, 61);
            code.extend_from_slice(&[0x48, 0x83, 0xf8, 0xf6]);
            failures.push(jump(&mut code, 0x85));
        }
    }
    exit(&mut code, 0);
    let failure = code.len();
    exit(&mut code, 99);
    for offset in failures {
        target(&mut code, offset, failure);
    }
    root.write("init", &code);
    assert_code(&run(&root.0, &["--vcpu-capacity", "1"], &[]), 0);
}
