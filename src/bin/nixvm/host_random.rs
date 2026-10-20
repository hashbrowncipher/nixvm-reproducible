//! Executable-only getrandom interposition for std's hash-key entropy.
//! Guest randomness is a separate, explicitly seeded stream in the library.

use rand_chacha::{
    ChaCha20Rng,
    rand_core::{Rng, SeedableRng},
};
use std::ffi::{c_uint, c_void};
use std::sync::Mutex;

static GENERATOR: Mutex<Option<ChaCha20Rng>> = Mutex::new(None);

pub(super) fn prepare() -> std::io::Result<()> {
    let mut seed = [0u8; 32];
    let mut filled = 0;
    while filled < seed.len() {
        // SAFETY: seed's remaining bytes are writable. This is the one explicit
        // host entropy read before the irreversible confinement boundary.
        let count = unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                seed[filled..].as_mut_ptr(),
                seed.len() - filled,
                0u32,
            )
        };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if count == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        filled += count as usize;
    }
    *GENERATOR
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(ChaCha20Rng::from_seed(seed));
    Ok(())
}

/// Fill a valid writable caller buffer, with libc getrandom's flag convention.
/// Before preparation this forwards startup calls directly to the kernel.
///
/// # Safety
/// `buffer` must address `length` writable bytes when nonnull, like libc's call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getrandom(buffer: *mut c_void, length: usize, flags: c_uint) -> isize {
    let failure = |code| {
        // SAFETY: libc exposes this thread's errno slot.
        unsafe {
            *libc::__errno_location() = code;
        }
        -1
    };
    if flags & !7 != 0 || flags & 6 == 6 {
        return failure(libc::EINVAL);
    }
    if length > isize::MAX as usize {
        return failure(libc::EINVAL);
    }
    if length == 0 {
        return 0;
    }
    if buffer.is_null() {
        return failure(libc::EFAULT);
    }
    let mut generator = GENERATOR
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(generator) = generator.as_mut() {
        // SAFETY: the ABI contract requires a valid writable buffer. Length and
        // null checks above satisfy slice's remaining structural requirements.
        generator
            .fill_bytes(unsafe { std::slice::from_raw_parts_mut(buffer.cast::<u8>(), length) });
        length as isize
    } else {
        // SAFETY: forward the unchanged libc arguments during process startup.
        unsafe { libc::syscall(libc::SYS_getrandom, buffer, length, flags) as isize }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::Barrier;

    #[test]
    fn prepared_generator_serves_main_and_workers_without_host_entropy() {
        // SAFETY: isolate the irreversible filter from the test harness.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            prepare().unwrap();
            let barrier = Arc::new(Barrier::new(2));
            let worker_barrier = barrier.clone();
            let worker = std::thread::spawn(move || {
                worker_barrier.wait();
                let mut output = [0u8; 64];
                assert_eq!(
                    unsafe { getrandom(output.as_mut_ptr().cast(), output.len(), 0) },
                    64
                );
                assert!(output.iter().any(|&byte| byte != 0));
                let mut map = std::collections::HashMap::new();
                map.insert(1, 2);
                assert_eq!(map[&1], 2);
            });
            let program: seccompiler::BpfProgram = seccompiler::SeccompFilter::new(
                std::collections::BTreeMap::from([
                    (libc::SYS_getrandom, Vec::new()),
                    (libc::SYS_openat, Vec::new()),
                ]),
                seccompiler::SeccompAction::Allow,
                seccompiler::SeccompAction::KillProcess,
                seccompiler::TargetArch::x86_64,
            )
            .unwrap()
            .try_into()
            .unwrap();
            seccompiler::apply_filter_all_threads(&program).unwrap();
            barrier.wait();
            let mut output = [0u8; 64];
            assert_eq!(
                unsafe { getrandom(output.as_mut_ptr().cast(), output.len(), 0) },
                64
            );
            let mut map = std::collections::HashMap::new();
            map.insert(3, 4);
            assert_eq!(map[&3], 4);
            assert_eq!(unsafe { getrandom(std::ptr::null_mut(), 1, 0) }, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EFAULT)
            );
            assert_eq!(unsafe { getrandom(output.as_mut_ptr().cast(), 1, 8) }, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINVAL)
            );
            worker.join().unwrap();
            unsafe {
                libc::_exit(0);
            }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &raw mut status, 0) }, pid);
        assert_eq!(status, 0);
    }
}
