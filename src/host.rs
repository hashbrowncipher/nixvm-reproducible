//! Explicit host-process preparation for deterministic Linux executables.
//!
//! [`prepare`] validates `NIXVM_HOST_RANDOM_SEED`, disables ASLR through the
//! process personality, and re-executes `/proc/self/exe` if the flag was clear.
//! Call it before other application work. Non-Linux targets do nothing.
//!
//! Linking this library exports no `getrandom` symbol and changes no host
//! policy. Linux embedders can explicitly export a C `getrandom` wrapper that
//! forwards to `prepared_getrandom`, then call [`prepare`] at startup.
//! The wrapper supplies a process-wide ChaCha20 stream separate from guests.
//! This predictable stream is unsuitable for secrets or hostile hash inputs.
//!
//! The seed is exactly 64 hexadecimal digits, or 32 zero bytes when unset.
//! Initialization is lazy and uses no allocation, OS entropy or clock. Invalid
//! configuration uses zeros for calls before startup; [`prepare`] rejects it
//! before VM work. The initial environment value is retained for the process.
//! Set the environment before launch and do not mutate it concurrently with
//! initialization. Calls serialize on a leaf mutex and are not signal-safe.
//! Replay also requires the same toolchain and host random-call/thread order.

use std::io;

/// Validate the host seed and disable Linux ASLR, re-executing once if needed.
///
/// Re-execution preserves raw argv (including `argv[0]`), environment, cwd,
/// inherited stdio and PID. The real personality flag determines readiness;
/// no environment marker is used. Personality or exec failure stops startup.
/// Other platforms return success without changing the process.
pub fn prepare() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::validate_seed()?;
        linux::prepare_layout(&mut linux::NativeProcess)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub use linux::prepared_getrandom;

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::{CStr, c_void};
    use std::io;
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::sync::{Mutex, MutexGuard};

    use crate::random::RandomState;

    // A small, always-representable short read also bounds each lock hold.
    const MAX_READ: usize = 256;
    const QUERY_PERSONALITY: libc::c_ulong = 0xffff_ffff;
    const NO_RANDOMIZE: libc::c_ulong = libc::ADDR_NO_RANDOMIZE as libc::c_ulong;
    static RANDOM: Mutex<Option<HostRandom>> = Mutex::new(None);

    struct HostRandom {
        stream: RandomState,
        valid_seed: bool,
    }

    fn parse_seed(value: &[u8]) -> Option<[u8; 32]> {
        if value.len() != 64 {
            return None;
        }
        let mut seed = [0; 32];
        for (pair, byte) in value.chunks_exact(2).zip(&mut seed) {
            let digit = |value: u8| match value {
                b'0'..=b'9' => Some(value - b'0'),
                b'a'..=b'f' => Some(value - b'a' + 10),
                b'A'..=b'F' => Some(value - b'A' + 10),
                _ => None,
            };
            *byte = digit(pair[0])? * 16 + digit(pair[1])?;
        }
        Some(seed)
    }

    fn initial_random() -> HostRandom {
        // SAFETY: getenv borrows the NUL-terminated process environment. The
        // startup contract forbids concurrent environment mutation. No pointer
        // escapes initialization and neither getenv nor this path allocates.
        let value = unsafe { libc::getenv(c"NIXVM_HOST_RANDOM_SEED".as_ptr()) };
        let seed = if value.is_null() {
            Some([0; 32])
        } else {
            // SAFETY: non-null getenv output names a live C string until an
            // environment mutation, excluded by the startup contract above.
            parse_seed(unsafe { CStr::from_ptr(value) }.to_bytes())
        };
        HostRandom {
            stream: RandomState::new(seed.unwrap_or([0; 32])),
            valid_seed: seed.is_some(),
        }
    }

    fn random() -> MutexGuard<'static, Option<HostRandom>> {
        // No allocation, hashing, callbacks or additional lock occurs while
        // this leaf lock is held, including first-call initialization.
        let mut guard = RANDOM
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.get_or_insert_with(initial_random);
        guard
    }

    pub(super) fn validate_seed() -> io::Result<()> {
        if random().as_ref().is_some_and(|random| random.valid_seed) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NIXVM_HOST_RANDOM_SEED must contain exactly 64 hexadecimal digits",
            ))
        }
    }

    fn failure(errno: libc::c_int) -> libc::ssize_t {
        // SAFETY: Linux libc provides a writable, thread-local errno slot.
        unsafe { *libc::__errno_location() = errno };
        -1
    }

    /// Supply deterministic bytes for an executable's exported `getrandom`.
    ///
    /// Accepts Linux `GRND_NONBLOCK`, `GRND_RANDOM` and `GRND_INSECURE` flags.
    /// `GRND_RANDOM | GRND_INSECURE` and unknown bits fail with `EINVAL`.
    /// Valid zero-length calls accept a null buffer. Other null buffers fail
    /// with `EFAULT`. Reads return at most 256 bytes and preserve errno on
    /// success. Flags do not select distinct streams or cause blocking.
    ///
    /// There is no OS fallback. This function contains no panicking operation;
    /// an exported `extern "C"` wrapper also aborts on any unexpected panic,
    /// rather than allowing unwinding across the ABI. It is not signal-safe.
    ///
    /// # Safety
    /// For nonzero length and a non-null pointer, `buffer` must identify a live,
    /// exclusively writable allocation containing at least `min(length, 256)`
    /// bytes. It must remain valid for the call. Arbitrary invalid pointers
    /// cannot be diagnosed as `EFAULT` by a userspace interposer.
    pub unsafe fn prepared_getrandom(
        buffer: *mut c_void,
        length: libc::size_t,
        flags: libc::c_uint,
    ) -> libc::ssize_t {
        let accepted = libc::GRND_NONBLOCK | libc::GRND_RANDOM | libc::GRND_INSECURE;
        if flags & !accepted != 0
            || flags & (libc::GRND_RANDOM | libc::GRND_INSECURE)
                == libc::GRND_RANDOM | libc::GRND_INSECURE
        {
            return failure(libc::EINVAL);
        }
        if length == 0 {
            return 0;
        }
        if buffer.is_null() {
            return failure(libc::EFAULT);
        }
        let count = length.min(MAX_READ);
        // SAFETY: the caller guarantees count writable bytes and exclusive
        // access; count is nonzero and bounded below isize::MAX.
        let output = unsafe { std::slice::from_raw_parts_mut(buffer.cast::<u8>(), count) };
        // SAFETY: Linux libc provides a writable errno slot local to this
        // thread. Its address remains valid through acquisition and release.
        let errno_location = unsafe { libc::__errno_location() };
        let caller_errno = unsafe { *errno_location };
        // Contended mutex futex calls can change errno even on success. Keep
        // initialization, filling and guard destruction inside this scope so
        // every errno write below occurs after the final mutex operation.
        let result = {
            let mut guard = random();
            // Matching avoids a panic path across the executable's C ABI.
            if let Some(random) = guard.as_mut() {
                random.stream.fill(output);
                Ok(count as libc::ssize_t)
            } else {
                Err(libc::EIO)
            }
        };
        match result {
            Ok(count) => {
                // SAFETY: this is the calling thread's live errno slot above.
                unsafe { *errno_location = caller_errno };
                count
            }
            Err(errno) => failure(errno),
        }
    }

    pub(super) trait Process {
        fn personality(&mut self, value: libc::c_ulong) -> io::Result<libc::c_ulong>;
        fn exec(&mut self) -> io::Error;
    }

    pub(super) struct NativeProcess;

    impl Process for NativeProcess {
        fn personality(&mut self, value: libc::c_ulong) -> io::Result<libc::c_ulong> {
            // SAFETY: personality takes a value, not a pointer. Query uses its
            // documented sentinel; writes preserve all other personality bits.
            let result = unsafe { libc::personality(value) };
            if result == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(result as libc::c_ulong)
            }
        }

        fn exec(&mut self) -> io::Error {
            let mut arguments = std::env::args_os();
            Command::new("/proc/self/exe")
                .arg0(arguments.next().unwrap_or_default())
                .args(arguments)
                .exec()
        }
    }

    fn context(operation: &str, error: &io::Error) -> io::Error {
        io::Error::new(error.kind(), format!("{operation}: {error}"))
    }

    pub(super) fn prepare_layout(process: &mut impl Process) -> io::Result<()> {
        let current = process
            .personality(QUERY_PERSONALITY)
            .map_err(|error| context("query Linux personality", &error))?;
        if current & NO_RANDOMIZE != 0 {
            return Ok(());
        }
        process
            .personality(current | NO_RANDOMIZE)
            .map_err(|error| context("disable host ASLR with Linux personality", &error))?;
        let updated = process
            .personality(QUERY_PERSONALITY)
            .map_err(|error| context("verify Linux personality", &error))?;
        if updated & NO_RANDOMIZE == 0 {
            return Err(io::Error::other(
                "Linux personality did not disable host ASLR",
            ));
        }
        Err(context(
            "re-execute /proc/self/exe after disabling host ASLR",
            &process.exec(),
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::collections::VecDeque;

        struct FakeProcess {
            replies: VecDeque<io::Result<libc::c_ulong>>,
            calls: Vec<libc::c_ulong>,
            executions: usize,
        }

        impl Process for FakeProcess {
            fn personality(&mut self, value: libc::c_ulong) -> io::Result<libc::c_ulong> {
                self.calls.push(value);
                self.replies.pop_front().unwrap()
            }
            fn exec(&mut self) -> io::Error {
                self.executions += 1;
                io::Error::from_raw_os_error(libc::ENOENT)
            }
        }

        fn process(replies: Vec<io::Result<libc::c_ulong>>) -> FakeProcess {
            FakeProcess {
                replies: replies.into(),
                calls: Vec::new(),
                executions: 0,
            }
        }

        #[test]
        fn personality_and_exec_failures_stop_startup() {
            for (replies, expected_calls, expected_execs, diagnostic) in [
                (
                    vec![Err(io::Error::from_raw_os_error(libc::EPERM))],
                    vec![QUERY_PERSONALITY],
                    0,
                    "query Linux personality",
                ),
                (
                    vec![Ok(8), Err(io::Error::from_raw_os_error(libc::EPERM))],
                    vec![QUERY_PERSONALITY, 8 | NO_RANDOMIZE],
                    0,
                    "disable host ASLR",
                ),
                (
                    vec![Ok(8), Ok(8), Err(io::Error::from_raw_os_error(libc::EPERM))],
                    vec![QUERY_PERSONALITY, 8 | NO_RANDOMIZE, QUERY_PERSONALITY],
                    0,
                    "verify Linux personality",
                ),
                (
                    vec![Ok(8), Ok(8), Ok(8)],
                    vec![QUERY_PERSONALITY, 8 | NO_RANDOMIZE, QUERY_PERSONALITY],
                    0,
                    "did not disable",
                ),
                (
                    vec![Ok(8), Ok(8), Ok(8 | NO_RANDOMIZE)],
                    vec![QUERY_PERSONALITY, 8 | NO_RANDOMIZE, QUERY_PERSONALITY],
                    1,
                    "re-execute",
                ),
            ] {
                let mut fake = process(replies);
                assert!(
                    prepare_layout(&mut fake)
                        .unwrap_err()
                        .to_string()
                        .contains(diagnostic)
                );
                assert_eq!(fake.calls, expected_calls);
                assert_eq!(fake.executions, expected_execs);
            }
            let mut ready = process(vec![Ok(8 | NO_RANDOMIZE)]);
            prepare_layout(&mut ready).unwrap();
            assert_eq!(ready.calls, [QUERY_PERSONALITY]);
            assert_eq!(ready.executions, 0);
        }

        #[test]
        fn host_stream_is_independent_of_guest_reads_and_clone_reseeds() {
            use rand_chacha::ChaCha20Rng;
            use rand_chacha::rand_core::{Rng, SeedableRng};

            let guest = crate::random::RandomSource::new([42; 32]);
            let mut host_reference = initial_random().stream;
            let mut host_bytes = [0; 128];
            let mut guest_bytes = [0; 64];
            // SAFETY: the host buffers are live and exclusively writable.
            unsafe {
                assert_eq!(
                    crate::host::prepared_getrandom(host_bytes.as_mut_ptr().cast(), 64, 0),
                    64
                );
            }
            guest.fill(&mut guest_bytes);
            let mut expected_guest = [0; 64];
            ChaCha20Rng::from_seed([42; 32]).fill_bytes(&mut expected_guest);
            assert_eq!(guest_bytes, expected_guest);
            guest.reseed_for_clone(19);
            // SAFETY: the second half supplies the requested 64 writable bytes.
            unsafe {
                assert_eq!(
                    crate::host::prepared_getrandom(host_bytes[64..].as_mut_ptr().cast(), 64, 0),
                    64
                );
            }
            let mut expected_host = [0; 128];
            host_reference.fill(&mut expected_host);
            assert_eq!(host_bytes, expected_host);
        }

        #[test]
        fn seed_requires_exact_ascii_hex() {
            assert_eq!(parse_seed(&[b'0'; 64]), Some([0; 32]));
            assert_eq!(parse_seed(&[b'A'; 64]), Some([0xaa; 32]));
            for value in [&b""[..], &[b'0'; 63], &[b'0'; 65], &[0xff; 64], &[b'g'; 64]] {
                assert_eq!(parse_seed(value), None);
            }
        }
    }
}
