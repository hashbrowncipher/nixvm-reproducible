//! Host output failures belong to the run, rather than to guest syscalls.

use std::io::{self, Write};

pub(super) struct Output {
    writer: Box<dyn Write + Send>,
    failure: Option<io::Error>,
}

impl Output {
    pub fn new(writer: Box<dyn Write + Send>) -> Self {
        Self {
            writer,
            failure: None,
        }
    }

    pub fn host(fd: i32) -> Self {
        #[cfg(target_os = "linux")]
        {
            Self::new(Box::new(crate::host::output::HostWriter(fd)))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self::new(if fd == 1 {
                Box::new(io::stdout())
            } else {
                Box::new(io::stderr())
            })
        }
    }

    pub fn result(&mut self) -> Result<(), crate::vcpu::VcpuError> {
        let _ = self.flush();
        match &self.failure {
            Some(error) => Err(crate::vcpu::VcpuError::Backend(format!(
                "host output failed: {error}"
            ))),
            None => Ok(()),
        }
    }
}

impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.failure.is_none()
            && let Err(error) = self.writer.write_all(bytes)
        {
            self.failure = Some(error);
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.failure.is_none()
            && let Err(error) = self.writer.flush()
        {
            self.failure = Some(error);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct PartialWriter(Arc<Mutex<Vec<u8>>>);
    impl Write for PartialWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let size = bytes.len().min(2);
            self.0.lock().unwrap().extend_from_slice(&bytes[..size]);
            Ok(size)
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("flush failed"))
        }
    }

    #[test]
    fn partial_writes_preserve_bytes_and_flush_errors_fail_the_run() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let mut output = Output::new(Box::new(PartialWriter(Arc::clone(&bytes))));
        assert_eq!(output.write(b"abcdef").unwrap(), 6);
        assert_eq!(&*bytes.lock().unwrap(), b"abcdef");
        assert!(output.result().is_err());
        assert_eq!(output.write(b"discarded after failure").unwrap(), 23);
        assert_eq!(&*bytes.lock().unwrap(), b"abcdef");
    }
}
