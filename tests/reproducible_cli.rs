#![cfg(all(feature = "cli", target_os = "linux", target_arch = "x86_64"))]

#[test]
fn branch_counting_refuses_an_enabled_watchdog_before_opening_resources() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_nixvm"))
        .args([
            "run",
            "--root",
            "/nonexistent-reproducibility-root",
            "--",
            "/init",
        ])
        .env("NIXVM_BRANCH_QUANTUM", "64")
        .env("NIXVM_QUANTUM_MS", "1")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("watchdog"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

struct Report(std::path::PathBuf);
impl Report {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "nixvm-repro-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> std::path::PathBuf {
        self.0.join("status")
    }
    fn text(&self) -> String {
        std::fs::read_to_string(self.path()).unwrap()
    }
}
impl Drop for Report {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn command(report: &Report) -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_nixvm"));
    command
        .env_clear()
        .args([
            "run",
            "--reproducible",
            "--mem",
            "16M",
            "--vcpu-capacity",
            "4",
            "--status-file",
        ])
        .arg(report.path())
        .arg("--erofs")
        .arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/data/erofs/reproducible.erofs"),
        )
        .args(["--branch-quantum", "64", "--syscall-quantum", "16"]);
    command
}

#[test]
fn reproducible_mode_rejects_ambient_configuration_and_host_directories() {
    for args in [vec!["--workdir", "/"], vec!["--root", "/"], vec![]] {
        let report = Report::new();
        let mut command = command(&report);
        command.args(&args).args(["--", "/init"]);
        if args.is_empty() {
            command.env("NIXVM_SLICE", "7");
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        // Conflicting root sources fail during CLI parsing, before opening a report.
        if !args.contains(&"--root") {
            assert!(report.text().starts_with("sandbox-error\n"));
            assert!(output.stderr.is_empty());
        }
    }
}

#[test]
#[cfg(feature = "erofs")]
fn library_reproducible_policy_cannot_be_bypassed_by_builder_order() {
    let image = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/erofs/reproducible.erofs");
    for bypass in 0..5 {
        let builder = nixvm::Sandbox::builder()
            .reproducible(true)
            .root_erofs_layers([&image])
            .command(["/init"]);
        let builder = match bypass {
            0 => builder.confine_host(false),
            1 => builder.prefer_interp(true),
            2 => builder.ncpus(2),
            3 => builder.bind("/", "/host"),
            4 => builder.arch(nixvm::Arch::Aarch64),
            _ => unreachable!(),
        };
        let error = builder.run().unwrap_err().to_string();
        assert!(error.contains("reproducible mode"), "{error}");
    }
}

#[test]
#[cfg(feature = "erofs")]
#[ignore = "requires real KVM and guest-only Intel perf counters"]
fn reproducible_stdin_returns_zero_without_closing_or_consuming_host_input() {
    use std::io::{Seek, Write};
    let report = Report::new();
    let path = report.0.join("stdin");
    std::fs::write(&path, b"synthetic host input").unwrap();
    let mut input = std::fs::File::open(path).unwrap();
    let output = command(&report)
        .args(["--", "/init"])
        .stdin(std::process::Stdio::from(input.try_clone().unwrap()))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", report.text());
    assert_eq!(input.stream_position().unwrap(), 0);
    assert_eq!(output.stdout.len(), 128 * 1024 + 16);
    assert_eq!(output.stderr, b"guest-stderr\n");
    assert_eq!(report.text(), "guest-exit 0\n");
    // The parent descriptor remains usable too.
    let mut sibling = std::fs::OpenOptions::new()
        .append(true)
        .open(report.0.join("stdin"))
        .unwrap();
    sibling.write_all(b"still open").unwrap();
}

#[test]
#[cfg(feature = "erofs")]
#[ignore = "requires real KVM and guest-only Intel perf counters"]
fn reproducible_output_failures_are_reported_without_guest_eio() {
    for destination in [1, 2] {
        let report = Report::new();
        let mut command = command(&report);
        command.args(["--", "/init"]);
        let full = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap();
        if destination == 1 {
            command.stdout(full);
        } else {
            command.stderr(full);
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(125));
        assert!(report.text().starts_with("sandbox-error\n"));
        assert!(
            report.text().contains("host output failed"),
            "{}",
            report.text()
        );
        if destination == 2 {
            assert_eq!(output.stdout.len(), 128 * 1024 + 16);
        }
    }
}

#[test]
#[cfg(feature = "erofs")]
#[ignore = "requires real KVM and guest-only Intel perf counters"]
fn guest_fault_diagnostics_and_exit_125_stay_distinct_from_sandbox_errors() {
    for (program, code) in [("/fault", 132), ("/exit125", 125)] {
        let report = Report::new();
        let output = command(&report).args(["--", program]).output().unwrap();
        assert_eq!(output.status.code(), Some(code), "{}", report.text());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
        assert_eq!(report.text(), format!("guest-exit {code}\n"));
    }
}
