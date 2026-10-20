//! A standalone integration executable so raw non-UTF8 argv can reach startup.

#[cfg(not(target_os = "linux"))]
fn main() {}

#[cfg(target_os = "linux")]
fn main() {
    linux::run();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::collections::{HashMap, hash_map::RandomState};
    use std::ffi::{OsStr, OsString};
    use std::fs::OpenOptions;
    use std::hash::BuildHasher;
    use std::io::{Read, Write};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::{Command, Output, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingAllocator;
    static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

    // SAFETY: all allocation and deallocation operations forward their exact
    // layouts/pointers to System; the counter changes no allocator contract.
    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
            // SAFETY: GlobalAlloc's caller supplies a valid allocation layout.
            unsafe { System.alloc(layout) }
        }
        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            // SAFETY: the original System allocation/layout passes unchanged.
            unsafe { System.dealloc(pointer, layout) }
        }
    }

    #[global_allocator]
    static ALLOCATOR: CountingAllocator = CountingAllocator;

    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static LAST_FLAGS: AtomicUsize = AtomicUsize::new(0);
    static PREMAIN_BYTE: AtomicUsize = AtomicUsize::new(usize::MAX);
    static PREMAIN_ALLOCATIONS: AtomicUsize = AtomicUsize::new(usize::MAX);

    // ELF runs this callback before Rust main. Only the dedicated subprocess
    // opts in, keeping other probes' expected stream positions unchanged.
    #[used]
    #[unsafe(link_section = ".init_array")]
    static INITIALIZER: extern "C" fn() = premain_probe;

    extern "C" fn premain_probe() {
        // SAFETY: libc supplies the live startup environment, before threads
        // can mutate it. We only test the returned pointer for null.
        if unsafe { libc::getenv(c"NIXVM_HOST_TEST_PREMAIN".as_ptr()) }.is_null() {
            return;
        }
        let before = ALLOCATIONS.load(Ordering::Relaxed);
        let mut byte = 0u8;
        // SAFETY: the local byte is valid and exclusively writable.
        let result = unsafe { getrandom((&raw mut byte).cast(), 1, 0) };
        if result == 1 {
            PREMAIN_BYTE.store(byte as usize, Ordering::Relaxed);
        }
        PREMAIN_ALLOCATIONS.store(
            ALLOCATIONS.load(Ordering::Relaxed) - before,
            Ordering::Relaxed,
        );
    }

    /// # Safety
    /// The buffer must meet prepared_getrandom's writable-buffer contract.
    #[unsafe(no_mangle)]
    unsafe extern "C" fn getrandom(
        buffer: *mut libc::c_void,
        length: usize,
        flags: libc::c_uint,
    ) -> isize {
        CALLS.fetch_add(1, Ordering::Relaxed);
        LAST_FLAGS.store(flags as usize, Ordering::Relaxed);
        // SAFETY: the exported ABI carries the helper's buffer contract.
        unsafe { nixvm::host::prepared_getrandom(buffer, length, flags) }
    }

    pub fn run() {
        match std::env::var("NIXVM_HOST_TEST_MODE").as_deref() {
            Ok("premain") => {
                assert_eq!(PREMAIN_BYTE.load(Ordering::Relaxed), 0x76);
                assert_eq!(PREMAIN_ALLOCATIONS.load(Ordering::Relaxed), 0);
                nixvm::host::prepare().unwrap();
            }
            Ok("randomness") => randomness_probe(),
            Ok("layout") => layout_probe(),
            Ok("invalid") => {
                // Exercise deterministic pre-startup behavior before rejection.
                let before = CALLS.load(Ordering::Relaxed);
                let _ = std::thread::spawn(|| RandomState::new().hash_one("before startup"))
                    .join()
                    .unwrap();
                assert!(CALLS.load(Ordering::Relaxed) > before);
                let error = nixvm::host::prepare().unwrap_err();
                assert!(error.to_string().contains("exactly 64 hexadecimal digits"));
                println!("INVALID_SEED_REJECTED");
            }
            Ok("abi") => abi_probe(),
            Ok("concurrent") => concurrent_probe(),
            _ => {
                checked(
                    command("premain")
                        .env("NIXVM_HOST_TEST_PREMAIN", "1")
                        .output()
                        .unwrap(),
                );
                host_std_randomness_is_repeatable();
                invalid_seed_is_rejected_after_prestartup_randomness();
                abi_conventions();
                checked(command("concurrent").output().unwrap());
                layout_reexec_preserves_process_state();
                binary_startup();
                println!("host determinism integration checks passed");
            }
        }
    }

    fn command(mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.env("NIXVM_HOST_TEST_MODE", mode);
        command.env_remove("NIXVM_HOST_RANDOM_SEED");
        command
    }

    fn checked(output: Output) -> Output {
        assert!(
            output.status.success(),
            "probe failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn forbid_entropy() {
        // Applied only to the fresh worker thread, after startup. Any real
        // getrandom or random-device fallback fails instead of supplying data.
        let mut denied = vec![libc::SYS_getrandom, libc::SYS_openat];
        #[cfg(target_arch = "x86_64")]
        denied.push(libc::SYS_open);
        let mut filter = vec![libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        }];
        for syscall in denied {
            filter.push(libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 1,
                k: syscall as u32,
            });
            filter.push(libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
            });
        }
        filter.push(libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        });
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        // SAFETY: prctl receives valid numeric arguments and a live filter
        // array. The filter only restricts this test thread's syscall access.
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            assert_eq!(
                libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    &raw const program
                ),
                0
            );
            // Independently prove that the kernel enforced the entropy denial.
            assert_eq!(
                libc::syscall(libc::SYS_getrandom, std::ptr::null_mut::<u8>(), 0, 0),
                -1
            );
            assert_eq!(*libc::__errno_location(), libc::EPERM);
            assert_eq!(libc::open(c"/dev/urandom".as_ptr(), libc::O_RDONLY), -1);
            assert_eq!(*libc::__errno_location(), libc::EPERM);
        }
    }

    fn randomness_probe() {
        // Fresh thread avoids std's per-thread RandomState cache. No helper
        // call initializes its keys: RandomState and HashMap must hit the ABI.
        let hashes = std::thread::spawn(|| {
            forbid_entropy();
            let before = CALLS.load(Ordering::Relaxed);
            let state = RandomState::new();
            let mut map = HashMap::new();
            map.insert("key", 17);
            assert_eq!(map.get("key"), Some(&17));
            assert_eq!(CALLS.load(Ordering::Relaxed) - before, 1);
            assert_eq!(
                LAST_FLAGS.load(Ordering::Relaxed),
                libc::GRND_INSECURE as usize
            );
            [
                state.hash_one("first"),
                state.hash_one("second"),
                map.hasher().hash_one("third"),
            ]
        })
        .join()
        .unwrap();
        println!("HOST_HASHES {hashes:?}");
    }

    fn hashes(seed: Option<&OsStr>) -> Vec<u8> {
        let mut command = command("randomness");
        if let Some(seed) = seed {
            command.env("NIXVM_HOST_RANDOM_SEED", seed);
        }
        checked(command.output().unwrap()).stdout
    }

    fn host_std_randomness_is_repeatable() {
        let seed = "00".repeat(32);
        let first = hashes(Some(OsStr::new(&seed)));
        assert_eq!(
            first,
            hashes(Some(OsStr::new(&seed))),
            "the same host seed must replay std hashes"
        );
        assert_eq!(first, hashes(None), "unset uses the zero seed");
        assert_ne!(
            first,
            hashes(Some(OsStr::new(&"01".repeat(32)))),
            "changed seed changes std hashes"
        );
    }

    fn invalid_seed_is_rejected_after_prestartup_randomness() {
        for seed in [
            OsString::from("invalid"),
            OsString::from("0".repeat(63)),
            OsString::from("0".repeat(65)),
            OsString::from("g".repeat(64)),
            OsString::from_vec(vec![0xff; 64]),
        ] {
            let output = checked(
                command("invalid")
                    .env("NIXVM_HOST_RANDOM_SEED", seed)
                    .output()
                    .unwrap(),
            );
            assert_eq!(output.stdout, b"INVALID_SEED_REJECTED\n");
        }
    }

    fn concurrent_probe() {
        use rand_chacha::ChaCha20Rng;
        use rand_chacha::rand_core::{Rng, SeedableRng};
        use std::sync::{Arc, Barrier};

        let barrier = Arc::new(Barrier::new(8));
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let mut bytes = [0; 17];
                    barrier.wait();
                    // SAFETY: the buffer supplies all 17 exclusively writable bytes.
                    unsafe {
                        assert_eq!(getrandom(bytes.as_mut_ptr().cast(), bytes.len(), 0), 17);
                    }
                    bytes
                })
            })
            .collect();
        let mut actual: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        let mut reference = [0; 8 * 17];
        ChaCha20Rng::from_seed([0; 32]).fill_bytes(&mut reference);
        let mut expected: Vec<[u8; 17]> = reference
            .chunks_exact(17)
            .map(|chunk| chunk.try_into().unwrap())
            .collect();
        actual.sort_unstable();
        expected.sort_unstable();
        assert_eq!(
            actual, expected,
            "concurrent initial calls must consume one complete stream"
        );
    }

    fn abi_probe() {
        use rand_chacha::ChaCha20Rng;
        use rand_chacha::rand_core::{Rng, SeedableRng};

        let mut expected = [0; 2048];
        ChaCha20Rng::from_seed([0; 32]).fill_bytes(&mut expected);
        let mut actual = Vec::new();
        let before = ALLOCATIONS.load(Ordering::Relaxed);
        let mut first = [0; 1];
        // SAFETY: the first call gets one exclusively writable byte.
        unsafe {
            assert_eq!(getrandom(first.as_mut_ptr().cast(), 1, 0), 1);
        }
        assert_eq!(
            ALLOCATIONS.load(Ordering::Relaxed),
            before,
            "lazy initialization must allocate nothing"
        );
        actual.extend(first);
        for flags in [0, 1, 2, 3, 4, 5] {
            let mut buffer = [0; 300];
            // SAFETY: each buffer has the requested writable capacity; null
            // zero-length and error cases never dereference the pointer.
            unsafe {
                *libc::__errno_location() = libc::E2BIG;
                assert_eq!(getrandom(std::ptr::null_mut(), 0, flags), 0);
                assert_eq!(
                    getrandom(buffer.as_mut_ptr().cast(), buffer.len(), flags),
                    256
                );
                assert_eq!(*libc::__errno_location(), libc::E2BIG);
            }
            actual.extend_from_slice(&buffer[..256]);
        }
        for flags in [6, 7, 8, u32::MAX] {
            // SAFETY: invalid flags return before accessing this null pointer.
            unsafe {
                assert_eq!(getrandom(std::ptr::null_mut(), 0, flags), -1);
                assert_eq!(*libc::__errno_location(), libc::EINVAL);
            }
        }
        // SAFETY: the helper handles null explicitly; huge requested length
        // is shortened to the 256 writable bytes supplied here.
        unsafe {
            assert_eq!(getrandom(std::ptr::null_mut(), 1, 0), -1);
            assert_eq!(*libc::__errno_location(), libc::EFAULT);
            let mut buffer = [0; 256];
            assert_eq!(getrandom(buffer.as_mut_ptr().cast(), usize::MAX, 0), 256);
            actual.extend(buffer);
        }
        assert_eq!(actual, expected[..actual.len()]);
    }

    fn abi_conventions() {
        checked(command("abi").output().unwrap());
    }

    fn personality() -> libc::c_int {
        // SAFETY: the sentinel queries personality without changing it.
        let personality = unsafe { libc::personality(0xffff_ffff) };
        assert_ne!(personality, -1, "personality query failed");
        personality
    }

    fn layout_probe() {
        let log = std::env::var_os("NIXVM_HOST_TEST_LOG").unwrap();
        let snapshot = format!(
            "{:?}|{:?}|{:?}",
            std::env::args_os().collect::<Vec<_>>(),
            std::env::var_os("NIXVM_HOST_TEST_RAW"),
            std::env::current_dir().unwrap().as_os_str().as_bytes()
        );
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)
            .unwrap();
        writeln!(
            file,
            "{}|{}|{}|{}",
            personality() & libc::ADDR_NO_RANDOMIZE != 0,
            layout_probe as *const () as usize,
            std::process::id(),
            snapshot
        )
        .unwrap();
        drop(file);
        nixvm::host::prepare().unwrap();
        assert_ne!(personality() & libc::ADDR_NO_RANDOMIZE, 0);
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input).unwrap();
        assert_eq!(input, "inherited stdin");
        println!("inherited stdout");
        eprintln!("inherited stderr");
    }

    fn layout_run(directory: &Path, disabled: bool, name: &str) -> Vec<Vec<String>> {
        let log = directory.join(name);
        let mut command = command("layout");
        command
            .arg0(OsString::from_vec(b"raw-argv0-\xff".to_vec()))
            .args([
                OsString::from_vec(b"raw-argument-\xfe".to_vec()),
                OsString::from("last"),
            ])
            .env(
                "NIXVM_HOST_TEST_RAW",
                OsString::from_vec(b"raw-env-\xfd".to_vec()),
            )
            .env("NIXVM_HOST_TEST_LOG", &log)
            .current_dir(directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: only async-signal-safe personality calls occur in pre_exec.
        // This changes the child alone, preserving all unrelated bits.
        unsafe {
            command.pre_exec(move || {
                let current = libc::personality(0xffff_ffff);
                if current == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                let target = if disabled {
                    current | libc::ADDR_NO_RANDOMIZE
                } else {
                    current & !libc::ADDR_NO_RANDOMIZE
                };
                if libc::personality(target as libc::c_ulong) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command
            .spawn()
            .expect("real personality setup must succeed");
        let pid = child.id();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"inherited stdin")
            .unwrap();
        let output = checked(child.wait_with_output().unwrap());
        assert_eq!(output.stdout, b"inherited stdout\n");
        assert_eq!(output.stderr, b"inherited stderr\n");
        let records: Vec<Vec<String>> = std::fs::read_to_string(log)
            .unwrap()
            .lines()
            .map(|line| line.splitn(4, '|').map(str::to_string).collect())
            .collect();
        assert_eq!(
            records.len(),
            if disabled { 1 } else { 2 },
            "exactly one exec when ASLR starts enabled"
        );
        for record in &records {
            assert_eq!(record[2], pid.to_string(), "exec must preserve PID");
            assert_eq!(
                record[3], records[0][3],
                "exec must preserve argv, env and cwd"
            );
            assert!(
                record[3].contains("raw-argv0-")
                    && record[3].contains("raw-argument-")
                    && record[3].contains("raw-env-")
            );
        }
        assert_eq!(records[0][0], disabled.to_string());
        assert_eq!(records.last().unwrap()[0], "true");
        records
    }

    fn layout_reexec_preserves_process_state() {
        let directory =
            std::env::temp_dir().join(format!("nixvm-host-layout-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let ready = layout_run(&directory, true, "already-disabled.log");
        let first = layout_run(&directory, false, "enabled-first.log");
        let second = layout_run(&directory, false, "enabled-second.log");
        assert_eq!(
            ready[0][1],
            first.last().unwrap()[1],
            "code addresses must match across ASLR-disabled starts"
        );
        assert_eq!(ready[0][1], second.last().unwrap()[1]);
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn binary_startup() {
        let binaries = [
            #[cfg(feature = "cli")]
            env!("CARGO_BIN_EXE_nixvm"),
            env!("CARGO_BIN_EXE_run-elf"),
            env!("CARGO_BIN_EXE_run-elf-x86"),
        ];
        for binary in binaries {
            let output = Command::new(binary)
                .env("NIXVM_HOST_RANDOM_SEED", "invalid")
                .output()
                .unwrap();
            assert!(!output.status.success());
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("NIXVM_HOST_RANDOM_SEED must contain exactly 64 hexadecimal digits")
            );
        }
        #[cfg(feature = "cli")]
        let output = Command::new(env!("CARGO_BIN_EXE_nixvm"))
            .arg("version")
            .env_remove("NIXVM_HOST_RANDOM_SEED")
            .output()
            .unwrap();
        #[cfg(feature = "cli")]
        {
            assert!(output.status.success());
            assert!(output.stdout.starts_with(b"nixvm "));
        }
    }
}
