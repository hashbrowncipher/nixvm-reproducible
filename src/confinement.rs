//! Linux process confinement. Opt in only from a dedicated host process.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, Ruleset, RulesetAttr,
    RulesetCreatedAttr,
};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

use crate::Error;

static RETAINED: OnceLock<BTreeSet<i32>> = OnceLock::new();

pub(crate) fn retained(fd: i32) -> bool {
    RETAINED.get().is_some_and(|fds| fds.contains(&fd))
}
pub(crate) fn active() -> bool {
    RETAINED.get().is_some()
}

/// Host resources prepared before guest input is parsed.
#[derive(Debug, Default)]
pub struct Resources {
    pub(crate) protected: Vec<i32>,
    pub(crate) vcpus: Vec<i32>,
    pub(crate) images: Vec<i32>,
    pub(crate) perf: Vec<i32>,
}

fn error(value: impl std::fmt::Display) -> Error {
    Error::Config(format!("host confinement: {value}"))
}

#[cfg(feature = "erofs")]
pub(crate) fn descriptors() -> Result<Vec<i32>, Error> {
    let entries = std::fs::read_dir("/proc/self/fd").map_err(error)?;
    let mut fds: Vec<_> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
        .collect();
    // The read_dir handle is gone; omit its now-closed descriptor.
    fds.retain(|&fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0);
    Ok(fds)
}

/// Close inherited capabilities before opening any runtime resources.
/// Entry from a multi-threaded embedder is rejected before changing anything.
pub(crate) fn begin() -> Result<(), Error> {
    if std::fs::read_dir("/proc/self/task").map_err(error)?.count() != 1 {
        return Err(error("requires a dedicated single-threaded process"));
    }
    // READ_IMPLIES_EXEC can make data mappings executable, including mappings
    // inherited before entry. Reject it without altering the caller's other
    // personality flags, including ADDR_NO_RANDOMIZE.
    let personality = unsafe { libc::personality(0xffff_ffff) };
    if personality < 0 {
        return Err(error(std::io::Error::last_os_error()));
    }
    if personality & libc::READ_IMPLIES_EXEC != 0 {
        return Err(error(
            "READ_IMPLIES_EXEC must be disabled before confinement",
        ));
    }
    for fd in 0..=2 {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: valid descriptor and output buffer. Missing stdio is refused.
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
            return Err(error("stdio must be open"));
        }
        let mode = unsafe { stat.assume_init() }.st_mode & libc::S_IFMT;
        if !matches!(mode, libc::S_IFREG | libc::S_IFIFO | libc::S_IFCHR) {
            return Err(error("stdio must be regular files, pipes or terminals"));
        }
    }
    crate::vcpu::kvm::clear_inactive_thread_resources();
    // Future CLI arguments that designate inherited resource FDs may need
    // explicit exemptions from close_range. No such arguments exist today.
    // SAFETY: single-threaded entry; only the explicitly retained stdio survives.
    if unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) } != 0 {
        return Err(error(std::io::Error::last_os_error()));
    }
    std::env::set_current_dir("/").map_err(error)?;
    // Warm std's thread-local hash keys before getrandom is forbidden.
    let _ = std::collections::hash_map::RandomState::new();
    Ok(())
}

/// Install on the single main thread before workers are spawned, so they inherit
/// the exact same filesystem domain. ABI 5 includes device-ioctl restrictions.
pub(crate) fn restrict_filesystem(
    directories: &[(std::sync::Arc<std::fs::File>, bool)],
) -> Result<(), Error> {
    let handled = AccessFs::from_all(ABI::V5);
    let mut rules = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(handled)
        .map_err(error)?
        .create()
        .map_err(error)?;
    for (root, read_only) in directories {
        let allowed = if *read_only {
            AccessFs::ReadFile | AccessFs::ReadDir
        } else {
            handled
                & !(AccessFs::Execute
                    | AccessFs::IoctlDev
                    | AccessFs::MakeChar
                    | AccessFs::MakeBlock
                    | AccessFs::MakeSock
                    | AccessFs::MakeFifo)
        };
        rules = rules
            .add_rule(PathBeneath::new(root.as_ref(), allowed))
            .map_err(error)?;
    }
    rules.restrict_self().map_err(error)?;
    Ok(())
}

pub(crate) fn drop_thread_privileges() -> Result<(), Error> {
    // SAFETY: these prctls affect only this process/thread and use scalar args.
    for (option, value) in [(libc::PR_SET_NO_NEW_PRIVS, 1), (libc::PR_SET_DUMPABLE, 0)] {
        if unsafe { libc::prctl(option, value, 0, 0, 0) } != 0 {
            return Err(error(std::io::Error::last_os_error()));
        }
    }
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [
        Data {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        Data {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    // SAFETY: Linux capability v3 uses this header and two data records.
    if unsafe { libc::syscall(libc::SYS_capset, &raw const header, data.as_ptr()) } != 0 {
        return Err(error(std::io::Error::last_os_error()));
    }
    Ok(())
}

fn condition(arg: u8, op: SeccompCmpOp, value: u64) -> SeccompCondition {
    SeccompCondition::new(arg, SeccompCmpArgLen::Qword, op, value).expect("valid syscall argument")
}
fn eq(arg: u8, value: u64) -> SeccompCondition {
    condition(arg, SeccompCmpOp::Eq, value)
}
fn rule(conditions: Vec<SeccompCondition>) -> SeccompRule {
    SeccompRule::new(conditions).expect("nonempty syscall rule")
}
fn fd_rules(fds: &[i32]) -> Vec<SeccompRule> {
    fds.iter().map(|&fd| rule(vec![eq(0, fd as u64)])).collect()
}

impl Resources {
    pub(crate) fn install(mut self, directories: bool) -> Result<(), Error> {
        self.protected.extend(&self.perf);
        RETAINED
            .set(self.protected.iter().copied().collect())
            .map_err(|_| error("already installed"))?;
        let mut calls = BTreeMap::<i64, Vec<SeccompRule>>::new();
        for syscall in [
            libc::SYS_brk,
            libc::SYS_munmap,
            libc::SYS_mremap,
            libc::SYS_madvise,
            libc::SYS_clock_gettime,
            libc::SYS_clock_nanosleep,
            libc::SYS_nanosleep,
            libc::SYS_rt_sigreturn,
            libc::SYS_exit,
            libc::SYS_exit_group,
            libc::SYS_timer_settime,
            libc::SYS_sigaltstack,
            libc::SYS_rt_sigprocmask,
        ] {
            calls.insert(syscall, Vec::new());
        }
        for syscall in [libc::SYS_mmap, libc::SYS_mprotect] {
            let mut conditions = vec![condition(
                2,
                SeccompCmpOp::MaskedEq(libc::PROT_EXEC as u64),
                0,
            )];
            if syscall == libc::SYS_mmap {
                conditions.push(
                    SeccompCondition::new(
                        4,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::Eq,
                        u64::from(u32::MAX),
                    )
                    .expect("fd argument"),
                );
            }
            calls.insert(syscall, vec![rule(conditions)]);
        }
        calls.insert(
            libc::SYS_futex,
            [
                libc::FUTEX_WAIT,
                libc::FUTEX_WAKE,
                libc::FUTEX_WAIT_BITSET,
                libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
                libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
                libc::FUTEX_WAIT_BITSET | libc::FUTEX_PRIVATE_FLAG,
                libc::FUTEX_WAIT_BITSET | libc::FUTEX_CLOCK_REALTIME,
                libc::FUTEX_WAIT_BITSET | libc::FUTEX_CLOCK_REALTIME | libc::FUTEX_PRIVATE_FLAG,
            ]
            .into_iter()
            .map(|op| rule(vec![eq(1, op as u64)]))
            .collect(),
        );
        let mut reads = fd_rules(&[0]);
        reads.extend(fd_rules(&self.perf));
        let mut writes = fd_rules(&[1, 2]);
        let mut ordinary = Vec::new();
        let mut directory_fcntl = Vec::new();
        let mut start = 3;
        for fd in self.protected.iter().copied().collect::<BTreeSet<_>>() {
            if start < fd {
                let range = vec![
                    condition(0, SeccompCmpOp::Ge, start as u64),
                    condition(0, SeccompCmpOp::Lt, fd as u64),
                ];
                ordinary.push(rule(range.clone()));
                let mut setfd = range.clone();
                setfd.extend([eq(1, libc::F_SETFD as u64), eq(2, libc::FD_CLOEXEC as u64)]);
                directory_fcntl.push(rule(setfd));
                let mut getfl = range;
                getfl.push(eq(1, libc::F_GETFL as u64));
                directory_fcntl.push(rule(getfl));
            }
            start = fd + 1;
        }
        let tail = vec![
            condition(0, SeccompCmpOp::Ge, start as u64),
            condition(0, SeccompCmpOp::Le, i32::MAX as u64),
        ];
        ordinary.push(rule(tail.clone()));
        let mut setfd = tail.clone();
        setfd.extend([eq(1, libc::F_SETFD as u64), eq(2, libc::FD_CLOEXEC as u64)]);
        directory_fcntl.push(rule(setfd));
        let mut getfl = tail;
        getfl.push(eq(1, libc::F_GETFL as u64));
        directory_fcntl.push(rule(getfl));
        calls.insert(libc::SYS_close, ordinary.clone());
        // Rust's OwnedFd drop checks for EBADF in debug builds. F_GETFD cannot
        // create, duplicate or change a descriptor capability.
        calls.insert(
            libc::SYS_fcntl,
            vec![rule(vec![eq(1, libc::F_GETFD as u64)])],
        );
        if directories {
            calls
                .get_mut(&libc::SYS_fcntl)
                .unwrap()
                .extend(directory_fcntl);
            reads.extend(ordinary.clone());
            writes.extend(ordinary);
            calls.insert(
                libc::SYS_openat,
                vec![rule(vec![condition(
                    2,
                    SeccompCmpOp::MaskedEq(
                        (libc::O_PATH | (libc::O_TMPFILE & !libc::O_DIRECTORY)) as u64,
                    ),
                    0,
                )])],
            );
            for syscall in [
                libc::SYS_getdents64,
                libc::SYS_fstat,
                // Passthrough metadata can reveal information about open FDs,
                // including timestamps of our EROFS image/archive FDs.
                // Landlock still restricts file contents, not this metadata.
                libc::SYS_newfstatat,
                libc::SYS_lseek,
                libc::SYS_ftruncate,
                libc::SYS_fsync,
                libc::SYS_fdatasync,
                libc::SYS_unlinkat,
                libc::SYS_mkdirat,
                libc::SYS_renameat,
                libc::SYS_linkat,
                libc::SYS_symlinkat,
            ] {
                calls.insert(syscall, Vec::new());
            }
        }
        calls.insert(libc::SYS_read, reads);
        calls.insert(libc::SYS_write, writes.clone());
        calls.insert(libc::SYS_writev, writes);
        if !self.images.is_empty() {
            calls.insert(libc::SYS_pread64, fd_rules(&self.images));
        }
        let mut ioctls = Vec::new();
        for fd in 0..=2 {
            for request in [
                libc::TCGETS,
                libc::TCSETS,
                libc::TCSETSW,
                libc::TCSETSF,
                libc::TIOCGWINSZ,
                libc::TIOCSWINSZ,
            ] {
                ioctls.push(rule(vec![eq(0, fd), eq(1, request)]));
            }
        }
        // Existing prepared resources may leave gaps between vCPU numbers.
        // Compact only consecutive exact vCPU descriptors; never include gaps.
        let mut ranges: Vec<(i32, i32)> = Vec::new();
        for fd in self.vcpus.iter().copied().collect::<BTreeSet<_>>() {
            if let Some((_, last)) = ranges.last_mut()
                && *last + 1 == fd
            {
                *last = fd;
            } else {
                ranges.push((fd, fd));
            }
        }
        for (first, last) in ranges {
            for request in crate::vcpu::kvm::runtime_requests() {
                ioctls.push(rule(vec![
                    condition(0, SeccompCmpOp::Ge, first as u64),
                    condition(0, SeccompCmpOp::Le, last as u64),
                    eq(1, request),
                ]));
            }
        }
        for &fd in &self.perf {
            for request in [0x2400, 0x2401, 0x2403, 0x4008_2404] {
                ioctls.push(rule(vec![eq(0, fd as u64), eq(1, request)]));
            }
        }
        calls.insert(libc::SYS_ioctl, ioctls);
        let program: BpfProgram = SeccompFilter::new(
            calls,
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .map_err(error)?
        .try_into()
        .map_err(error)?;
        seccompiler::apply_filter_all_threads(&program).map_err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn child(action: impl FnOnce(), signal: Option<i32>) {
        // SAFETY: the child performs no inherited application work and exits;
        // this isolates irreversible filters from the test harness.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            action();
            unsafe {
                libc::_exit(0);
            }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &raw mut status, 0) }, pid);
        if let Some(signal) = signal {
            assert!(libc::WIFSIGNALED(status), "child status {status:#x}");
            assert_eq!(libc::WTERMSIG(status), signal);
        } else {
            assert!(libc::WIFEXITED(status), "child status {status:#x}");
            assert_eq!(libc::WEXITSTATUS(status), 0);
        }
    }

    fn strict() {
        begin().unwrap();
        restrict_filesystem(&[]).unwrap();
        drop_thread_privileges().unwrap();
        Resources::default().install(false).unwrap();
    }

    #[test]
    fn pending_pmu_signal_can_be_drained_after_confinement() {
        child(
            || {
                // Queue on this thread before filtering; only signal waiting
                // and process exit are needed after confinement takes effect.
                unsafe {
                    let mut blocked: libc::sigset_t = std::mem::zeroed();
                    libc::sigemptyset(&raw mut blocked);
                    libc::sigaddset(&raw mut blocked, 41);
                    assert_eq!(
                        libc::pthread_sigmask(
                            libc::SIG_BLOCK,
                            &raw const blocked,
                            std::ptr::null_mut()
                        ),
                        0
                    );
                    assert_eq!(libc::pthread_kill(libc::pthread_self(), 41), 0);
                    strict();
                    let timeout = libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    };
                    assert_eq!(
                        libc::sigtimedwait(
                            &raw const blocked,
                            std::ptr::null_mut(),
                            &raw const timeout
                        ),
                        41
                    );
                    assert_eq!(
                        libc::sigtimedwait(
                            &raw const blocked,
                            std::ptr::null_mut(),
                            &raw const timeout
                        ),
                        -1
                    );
                    assert_eq!(
                        std::io::Error::last_os_error().raw_os_error(),
                        Some(libc::EAGAIN)
                    );
                }
            },
            None,
        );
    }

    #[test]
    fn unauthorized_host_syscalls_kill_the_subprocess() {
        for number in [
            libc::SYS_open,
            libc::SYS_openat,
            libc::SYS_getdents64,
            libc::SYS_newfstatat,
            libc::SYS_readlinkat,
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_execve,
            libc::SYS_execveat,
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_fork,
            libc::SYS_vfork,
            libc::SYS_ptrace,
            libc::SYS_mount,
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_io_uring_setup,
            libc::SYS_getrandom,
            libc::SYS_fcntl,
            libc::SYS_prctl,
            libc::SYS_personality,
            libc::SYS_perf_event_open,
            libc::SYS_sched_setaffinity,
            libc::SYS_timer_create,
            libc::SYS_rt_sigaction,
        ] {
            child(
                || {
                    strict();
                    unsafe {
                        libc::syscall(number, 0, 0, 0, 0, 0, 0);
                    }
                },
                Some(libc::SIGSYS),
            );
        }
    }

    #[test]
    fn x32_and_unapproved_ioctl_and_executable_mappings_are_denied() {
        child(
            || {
                strict();
                // int 0x80 reports AUDIT_ARCH_I386 even in an x86-64 process.
                unsafe {
                    std::arch::asm!("int 0x80", inlateout("eax") 20u32 => _, options(nostack));
                }
            },
            Some(libc::SIGSYS),
        );
        for (number, arguments) in [
            (libc::SYS_write | 0x4000_0000, [1, 0, 0, 0, 0, 0]),
            (libc::SYS_ioctl, [1, libc::TIOCSTI, 0, 0, 0, 0]),
            (
                libc::SYS_mmap,
                [
                    0,
                    4096,
                    libc::PROT_EXEC as u64,
                    (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
                    u64::MAX,
                    0,
                ],
            ),
            (
                libc::SYS_mprotect,
                [0, 4096, libc::PROT_EXEC as u64, 0, 0, 0],
            ),
        ] {
            child(
                || {
                    strict();
                    unsafe {
                        libc::syscall(
                            number,
                            arguments[0],
                            arguments[1],
                            arguments[2],
                            arguments[3],
                            arguments[4],
                            arguments[5],
                        );
                    }
                },
                Some(libc::SIGSYS),
            );
        }
    }

    #[test]
    fn retained_resources_cannot_be_closed_and_reused() {
        child(
            || {
                use std::os::fd::IntoRawFd;
                begin().unwrap();
                let fd = std::fs::File::open("/dev/null").unwrap().into_raw_fd();
                restrict_filesystem(&[]).unwrap();
                drop_thread_privileges().unwrap();
                Resources {
                    protected: vec![fd],
                    ..Default::default()
                }
                .install(false)
                .unwrap();
                unsafe {
                    libc::close(fd);
                }
            },
            Some(libc::SIGSYS),
        );
    }

    #[test]
    fn inherited_read_implies_exec_is_rejected_before_confinement() {
        child(
            || {
                let current = unsafe { libc::personality(0xffff_ffff) };
                assert!(current >= 0);
                assert!(
                    unsafe {
                        libc::personality((current | libc::READ_IMPLIES_EXEC) as libc::c_ulong)
                    } >= 0
                );
                let error = begin().unwrap_err();
                assert!(error.to_string().contains("READ_IMPLIES_EXEC"));
            },
            None,
        );
    }

    #[test]
    fn inherited_descriptors_are_closed_and_allocator_growth_works() {
        child(
            || {
                use std::os::fd::IntoRawFd;
                let inherited = std::fs::File::open("/dev/null").unwrap().into_raw_fd();
                begin().unwrap();
                assert_eq!(unsafe { libc::fcntl(inherited, libc::F_GETFD) }, -1);
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EBADF)
                );
                restrict_filesystem(&[]).unwrap();
                drop_thread_privileges().unwrap();
                Resources::default().install(false).unwrap();
                let mut bytes = vec![1u8; 1024 * 1024];
                bytes.resize(32 * 1024 * 1024, 2);
                assert_eq!(bytes[0], 1);
                assert_eq!(bytes[bytes.len() - 1], 2);
                let mut map = std::collections::HashMap::new();
                map.insert("post-boundary", bytes.len());
                assert_eq!(map["post-boundary"], 32 * 1024 * 1024);
            },
            None,
        );
    }

    #[test]
    fn filter_covers_prepared_workers() {
        child(
            || {
                begin().unwrap();
                restrict_filesystem(&[]).unwrap();
                let (ready_tx, ready_rx) = std::sync::mpsc::channel();
                let (run_tx, run_rx) = std::sync::mpsc::channel();
                let worker = std::thread::spawn(move || {
                    let _ = std::collections::hash_map::RandomState::new();
                    drop_thread_privileges().unwrap();
                    ready_tx.send(()).unwrap();
                    run_rx.recv().unwrap();
                    let mut map = std::collections::HashMap::new();
                    map.insert("worker", 42);
                    assert_eq!(map["worker"], 42);
                    unsafe {
                        libc::syscall(libc::SYS_socket, libc::AF_INET, libc::SOCK_STREAM, 0);
                    }
                });
                ready_rx.recv().unwrap();
                drop_thread_privileges().unwrap();
                Resources::default().install(false).unwrap();
                run_tx.send(()).unwrap();
                // Joining verifies that the prepared worker executes the forbidden call.
                worker.join().unwrap();
            },
            Some(libc::SIGSYS),
        );
    }

    #[test]
    fn directory_profile_enforces_landlock_and_rejects_metadata_bypasses() {
        let root = std::env::temp_dir().join(format!("nixvm-confinement-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("file"), b"visible").unwrap();
        let outside = root.with_extension("outside");
        std::fs::write(&outside, b"must stay inaccessible").unwrap();
        let outside_c = std::ffi::CString::new(outside.as_os_str().as_encoded_bytes()).unwrap();
        std::os::unix::fs::symlink("file", root.join("link")).unwrap();
        child(
            || {
                begin().unwrap();
                let mut mount = crate::fs::Passthrough::prepared(root.clone(), false).unwrap();
                restrict_filesystem(&[(mount.pinned_root(), false)]).unwrap();
                drop_thread_privileges().unwrap();
                Resources::default().install(true).unwrap();
                use crate::fs::MountFs;
                assert_eq!(mount.stat("file").unwrap().size, 7);
                assert!(
                    mount
                        .readdir("")
                        .unwrap()
                        .iter()
                        .any(|entry| entry.name == "file")
                );
                let mut bytes = [0; 7];
                assert_eq!(mount.read_at("file", 0, &mut bytes).unwrap(), 7);
                assert_eq!(&bytes, b"visible");
                assert!(mount.read_at("link", 0, &mut bytes).is_err());
                assert!(mount.readlink("link").is_err());
                let path = outside_c.as_c_str();
                let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
                assert_eq!(
                    unsafe {
                        libc::syscall(
                            libc::SYS_newfstatat,
                            libc::AT_FDCWD,
                            path.as_ptr(),
                            metadata.as_mut_ptr(),
                            0,
                        )
                    },
                    0
                );
                assert_eq!(
                    unsafe { libc::openat(libc::AT_FDCWD, path.as_ptr(), libc::O_RDONLY) },
                    -1
                );
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EACCES)
                );
            },
            None,
        );
        for number in [libc::SYS_readlinkat, libc::SYS_statx] {
            child(
                || {
                    begin().unwrap();
                    restrict_filesystem(&[(
                        std::sync::Arc::new(std::fs::File::open(&root).unwrap()),
                        false,
                    )])
                    .unwrap();
                    drop_thread_privileges().unwrap();
                    Resources::default().install(true).unwrap();
                    unsafe {
                        libc::syscall(
                            number,
                            libc::AT_FDCWD,
                            outside_c.as_c_str().as_ptr(),
                            0,
                            0,
                            0,
                        );
                    }
                },
                Some(libc::SIGSYS),
            );
        }
        child(
            || {
                begin().unwrap();
                restrict_filesystem(&[(
                    std::sync::Arc::new(std::fs::File::open(&root).unwrap()),
                    false,
                )])
                .unwrap();
                drop_thread_privileges().unwrap();
                Resources::default().install(true).unwrap();
                unsafe {
                    libc::openat(libc::AT_FDCWD, outside_c.as_c_str().as_ptr(), libc::O_PATH);
                }
            },
            Some(libc::SIGSYS),
        );
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_file(outside).unwrap();
    }

    #[test]
    #[ignore = "requires real KVM"]
    fn kvm_pool_resets_state_and_reuses_slots() {
        child(
            || {
                use crate::vcpu::{Backend, Exit, GuestMemory, Prot};
                begin().unwrap();
                let backend = crate::vcpu::kvm::KvmBackend::new().expect("requires real KVM");
                let base = 0x1_0000;
                let mut memory = GuestMemory::new(base, 64 * 1024);
                memory.map(base, 4096, Prot::rwx()).unwrap();
                memory
                    .write_init(base, &[0xb8, 39, 0, 0, 0, 0x0f, 0x05])
                    .unwrap();
                let resources = backend.prepare_confinement(2, &memory).unwrap();
                crate::vcpu::kvm::prepare_thread().unwrap();
                restrict_filesystem(&[]).unwrap();
                drop_thread_privileges().unwrap();
                resources.install(false).unwrap();
                for _ in 0..8 {
                    let mut cpu = backend.new_vcpu(base, base + 0x8000).unwrap();
                    assert_eq!(cpu.reg(3), 0);
                    let fresh = cpu.simd_state();
                    assert!(fresh[160..416].iter().all(|byte| *byte == 0));
                    assert!(fresh[576..].iter().all(|byte| *byte == 0));
                    let mut child_cpu = cpu.try_fork().unwrap();
                    assert!(cpu.try_fork().is_err());
                    child_cpu.set_reg(3, 0x1234);
                    let mut dirty = fresh;
                    dirty[160..416].fill(0x77);
                    dirty[576..].fill(0x88);
                    dirty[512..520].copy_from_slice(&7u64.to_le_bytes());
                    child_cpu.set_simd_state(&dirty);
                    drop(child_cpu);
                    loop {
                        match cpu.run(&mut memory).unwrap() {
                            Exit::Interrupted => (),
                            Exit::Syscall => break,
                            other => panic!("unexpected {other:?}"),
                        }
                    }
                    cpu.set_reg(3, 0x5678);
                }
            },
            None,
        );
    }

    #[test]
    #[ignore = "requires real KVM"]
    fn kvm_descriptors_cannot_be_replaced_or_used_as_a_different_role() {
        for attack in 0..6 {
            child(
                || {
                    use crate::vcpu::{Backend, GuestMemory};
                    begin().unwrap();
                    let backend = crate::vcpu::kvm::KvmBackend::new().expect("requires real KVM");
                    let memory = GuestMemory::new(0x1_0000, 64 * 1024);
                    let resources = backend.prepare_confinement(2, &memory).unwrap();
                    let vcpu = resources.vcpus[0];
                    let system = resources.protected[0];
                    let vm = resources.protected[1];
                    crate::vcpu::kvm::prepare_thread().unwrap();
                    restrict_filesystem(&[]).unwrap();
                    drop_thread_privileges().unwrap();
                    resources.install(false).unwrap();
                    unsafe {
                        match attack {
                            0 => {
                                libc::close(vcpu);
                            }
                            1 => {
                                libc::dup2(0, vcpu);
                            }
                            2 => {
                                libc::dup3(0, vcpu, 0);
                            }
                            3 => {
                                libc::ioctl(system, 0xae80u64, 0);
                            } // KVM_RUN on system
                            4 => {
                                libc::ioctl(vm, 0xae80u64, 0);
                            } // KVM_RUN on VM
                            _ => {
                                libc::ioctl(vcpu, 0x2400u64, 0);
                            } // perf ENABLE on vCPU
                        }
                    }
                },
                Some(libc::SIGSYS),
            );
        }
    }
}
