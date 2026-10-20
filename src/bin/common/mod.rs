//! Executable-only host policy; the library exports no interposition symbol.

pub fn prepare() {
    if let Err(error) = nixvm::host::prepare() {
        eprintln!("nixvm: host preparation failed: {error}");
        std::process::exit(1);
    }
}

/// # Safety
/// `buffer` must satisfy `nixvm::host::prepared_getrandom`'s buffer contract.
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
unsafe extern "C" fn getrandom(
    buffer: *mut libc::c_void,
    length: libc::size_t,
    flags: libc::c_uint,
) -> libc::ssize_t {
    // SAFETY: the exported ABI carries the helper's writable-buffer contract.
    unsafe { nixvm::host::prepared_getrandom(buffer, length, flags) }
}
