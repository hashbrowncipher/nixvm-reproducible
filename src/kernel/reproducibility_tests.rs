use super::testutil::{BASE, call, setup};
use super::*;
use crate::fs::{DirEntry, MountFs, TmpFs};

#[derive(Debug)]
struct ReverseDirectory(TmpFs);

impl MountFs for ReverseDirectory {
    fn stat(&mut self, path: &str) -> Option<Attrs> {
        self.0.stat(path)
    }
    fn read_at(&mut self, path: &str, offset: u64, bytes: &mut [u8]) -> io::Result<usize> {
        self.0.read_at(path, offset, bytes)
    }
    fn readdir(&mut self, path: &str) -> io::Result<Vec<DirEntry>> {
        let mut entries = self.0.readdir(path)?;
        entries.sort_by(|a, b| b.name.as_bytes().cmp(a.name.as_bytes()));
        Ok(entries)
    }
}

#[test]
fn directory_order_ignores_backend_order_across_short_reads_and_rewinds() {
    let (mut kernel, mut memory, mut cpu, mut context) = setup();
    let mut directory = TmpFs::new();
    for name in ["c", "a", "b"] {
        directory.create(name, 0o644).unwrap();
    }
    kernel
        .vfs
        .get_mut()
        .unwrap()
        .mount("/", Box::new(ReverseDirectory(directory)));
    for syscall in [Sysno::Getdents64, Sysno::Getdents] {
        context.cur.fds.insert(
            3,
            Fd::Dir {
                path: "/".into(),
                pos: 0,
            },
        );
        let mut names = Vec::new();
        loop {
            let size = call(
                &kernel,
                &mut context,
                &mut memory,
                &mut cpu,
                syscall,
                [3, BASE, 24, 0, 0, 0],
            );
            assert!(size >= 0);
            if size == 0 {
                break;
            }
            let bytes = memory.read_vec(BASE, size as usize).unwrap();
            let offset = if matches!(syscall, Sysno::Getdents64) {
                19
            } else {
                18
            };
            names.push(
                String::from_utf8(
                    bytes[offset..]
                        .iter()
                        .copied()
                        .take_while(|b| *b != 0)
                        .collect(),
                )
                .unwrap(),
            );
        }
        assert_eq!(names, [".", "..", "a", "b", "c"]);
        assert_eq!(
            call(
                &kernel,
                &mut context,
                &mut memory,
                &mut cpu,
                Sysno::Lseek,
                [3, 0, 0, 0, 0, 0]
            ),
            0
        );
        assert_eq!(
            call(
                &kernel,
                &mut context,
                &mut memory,
                &mut cpu,
                syscall,
                [3, BASE, 24, 0, 0, 0]
            ),
            24
        );
    }
}

struct FailedOutput;
impl Write for FailedOutput {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::from_raw_os_error(28))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn host_output_failure_is_not_a_guest_syscall_result() {
    for destination in [1, 2] {
        for operation in [Sysno::Write, Sysno::Writev, Sysno::Sendfile, Sysno::Splice] {
            let (mut kernel, mut memory, mut cpu, mut context) = setup();
            kernel.set_stdout(Box::new(FailedOutput));
            kernel.set_stderr(Box::new(FailedOutput));
            memory.write_init(BASE, b"abc").unwrap();
            memory.write_u64(BASE + 32, BASE).unwrap();
            memory.write_u64(BASE + 40, 3).unwrap();
            let args = match operation {
                Sysno::Write => [destination, BASE, 3, 0, 0, 0],
                Sysno::Writev => [destination, BASE + 32, 1, 0, 0, 0],
                Sysno::Sendfile => {
                    kernel
                        .vfs
                        .get_mut()
                        .unwrap()
                        .create("/input", 0o644)
                        .unwrap();
                    kernel
                        .vfs
                        .get_mut()
                        .unwrap()
                        .write_at("/input", 0, b"abc")
                        .unwrap();
                    context.cur.fds.insert(
                        3,
                        Fd::File {
                            path: "/input".into(),
                            offset: FileOffset::new(0),
                            readable: true,
                            writable: false,
                        },
                    );
                    [destination, 3, 0, 3, 0, 0]
                }
                Sysno::Splice => {
                    assert_eq!(
                        call(
                            &kernel,
                            &mut context,
                            &mut memory,
                            &mut cpu,
                            Sysno::Pipe2,
                            [BASE + 64, 0, 0, 0, 0, 0]
                        ),
                        0
                    );
                    let reader = u64::from(memory.read_u32(BASE + 64).unwrap());
                    let writer = u64::from(memory.read_u32(BASE + 68).unwrap());
                    assert_eq!(
                        call(
                            &kernel,
                            &mut context,
                            &mut memory,
                            &mut cpu,
                            Sysno::Write,
                            [writer, BASE, 3, 0, 0, 0]
                        ),
                        3
                    );
                    [reader, 0, destination, 0, 3, 0]
                }
                _ => unreachable!(),
            };
            assert_eq!(
                call(
                    &kernel,
                    &mut context,
                    &mut memory,
                    &mut cpu,
                    operation,
                    args
                ),
                3,
                "{operation:?} on guest fd {destination}"
            );
            assert!(
                kernel.check_output().is_err(),
                "host failure must fail the run"
            );
        }
    }
}
