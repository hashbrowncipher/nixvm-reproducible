//! Exec must resolve the linker and finish loading before replacing the caller.

use super::testutil::{BASE, call, e, put_str, setup};
use crate::abi::arch::Sysno;
use crate::abi::errno::Errno;
use crate::fs::MountTable;
use crate::vcpu::mem::PAGE_SIZE;

/// One loadable AArch64 segment, optionally naming a dynamic interpreter.
fn elf(interpreter: Option<&str>) -> Vec<u8> {
    let headers = if interpreter.is_some() { 2 } else { 1 };
    let code_offset = 64 + headers * 56;
    // mov x0, #42; mov x8, #93; svc #0
    let code = [0xd280_0540u32, 0xd280_0ba8, 0xd400_0001];
    let mut bytes = vec![0; code_offset];
    for word in code {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    let interpreter_offset = bytes.len();
    if let Some(path) = interpreter {
        bytes.extend_from_slice(path.as_bytes());
        bytes.push(0);
    }
    bytes[..8].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    bytes[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
    bytes[18..20].copy_from_slice(&183u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&(code_offset as u64).to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&(headers as u16).to_le_bytes());
    let length = bytes.len() as u64;
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    bytes[68..72].copy_from_slice(&5u32.to_le_bytes()); // RX
    bytes[96..104].copy_from_slice(&length.to_le_bytes());
    bytes[104..112].copy_from_slice(&length.to_le_bytes());
    bytes[112..120].copy_from_slice(&PAGE_SIZE.to_le_bytes());
    if interpreter.is_some() {
        bytes[120..124].copy_from_slice(&3u32.to_le_bytes()); // PT_INTERP
        bytes[128..136].copy_from_slice(&(interpreter_offset as u64).to_le_bytes());
        bytes[152..160].copy_from_slice(&(length - interpreter_offset as u64).to_le_bytes());
    }
    bytes
}

fn file(mounts: &mut MountTable, path: &str, bytes: &[u8]) {
    mounts.create(path, 0o755).unwrap();
    mounts.write_at(path, 0, bytes).unwrap();
}

#[test]
fn dynamic_exec_follows_linker_symlinks() {
    for syscall in [Sysno::Execve, Sysno::Execveat] {
        for target in ["/linker", "linker"] {
            let (kernel, _, mut vcpu, mut context) = setup();
            let mut memory = crate::vcpu::GuestMemory::new(BASE, 512 * PAGE_SIZE);
            memory
                .map(BASE, PAGE_SIZE, crate::vcpu::mem::Prot::rw())
                .unwrap();
            {
                let mut mounts = kernel.vfs.lock().unwrap();
                file(&mut mounts, "/program", &elf(Some("/ld.so")));
                file(&mut mounts, "/linker", &elf(None));
                mounts.symlink(target, "/ld.so").unwrap();
            }
            put_str(&mut memory, BASE, "/program");
            let arguments = if matches!(syscall, Sysno::Execve) {
                [BASE, 0, 0, 0, 0, 0]
            } else {
                [(-100i64) as u64, BASE, 0, 0, 0, 0]
            };
            assert_eq!(
                call(
                    &kernel,
                    &mut context,
                    &mut memory,
                    &mut vcpu,
                    syscall,
                    arguments
                ),
                0,
                "{syscall:?}, linker target {target}"
            );
            assert!(context.exec_ok);
            assert_eq!(context.cur.exe, "/program");
        }
    }
}

#[test]
fn failed_exec_preserves_memory_identity_handlers_and_cloexec_fds() {
    for failure in ["missing linker", "bad linker", "bad program"] {
        let (kernel, mut memory, mut vcpu, mut context) = setup();
        {
            let mut mounts = kernel.vfs.lock().unwrap();
            let mut program = elf(Some("/ld.so"));
            if failure == "bad program" {
                program[54..56].copy_from_slice(&0u16.to_le_bytes());
            }
            file(&mut mounts, "/program", &program);
            if failure != "missing linker" {
                file(&mut mounts, "/ld.so", b"invalid linker");
            }
        }
        context.cur.exe = "/original".into();
        context.cur.comm = "original".into();
        context.cur.cmdline = b"original\0".to_vec();
        context.cur.handlers[1].handler = BASE + 0x100;
        context.cur.fds.set_cloexec(1, true);
        put_str(&mut memory, BASE, "/program");
        let original_cr3 = memory.cr3();
        let expected = if failure == "missing linker" {
            Errno::ENOENT
        } else {
            Errno::ENOEXEC
        };
        assert_eq!(
            call(
                &kernel,
                &mut context,
                &mut memory,
                &mut vcpu,
                Sysno::Execve,
                [BASE, 0, 0, 0, 0, 0]
            ),
            e(expected),
            "{failure}"
        );
        assert_eq!(
            memory.read_cstr(BASE, 64).unwrap(),
            b"/program",
            "{failure}"
        );
        assert_eq!(memory.cr3(), original_cr3);
        assert_eq!(context.cur.exe, "/original");
        assert_eq!(context.cur.comm, "original");
        assert_eq!(context.cur.cmdline, b"original\0");
        assert_eq!(context.cur.handlers[1].handler, BASE + 0x100);
        assert!(context.cur.fds.get(1).is_some());
        assert!(context.cur.fds.is_cloexec(1));
        assert!(!context.exec_ok);
    }
}
