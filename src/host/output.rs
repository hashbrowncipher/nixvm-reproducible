//! Blocking completion of host writes without changing shared descriptor flags.

use std::io::{self, Write};

#[derive(Debug)]
pub(crate) struct HostWriter(pub(crate) i32);

impl Write for HostWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        loop {
            // SAFETY: borrowed input buffer and an inherited output descriptor.
            let size = unsafe { libc::write(self.0, bytes.as_ptr().cast(), bytes.len()) };
            if size >= 0 {
                return Ok(size as usize);
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => {}
                io::ErrorKind::WouldBlock => {
                    let mut descriptor = libc::pollfd {
                        fd: self.0,
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    loop {
                        // SAFETY: one initialized pollfd. Polling leaves the shared
                        // open file description's O_NONBLOCK flag unchanged.
                        if unsafe { libc::poll(&raw mut descriptor, 1, -1) } >= 0 {
                            break;
                        }
                        let error = io::Error::last_os_error();
                        if error.kind() != io::ErrorKind::Interrupted {
                            return Err(error);
                        }
                    }
                }
                _ => return Err(error),
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
