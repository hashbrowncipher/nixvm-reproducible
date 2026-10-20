#![cfg(all(feature = "cli", target_os = "linux", target_arch = "x86_64"))]

#[test]
fn branch_counting_refuses_an_enabled_watchdog_before_opening_resources() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_nixvm"))
        .args(["run", "--root", "/nonexistent-reproducibility-root", "--", "/init"])
        .env("NIXVM_BRANCH_QUANTUM", "64")
        .env("NIXVM_QUANTUM_MS", "1")
        .output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("watchdog"), "{}", String::from_utf8_lossy(&output.stderr));
}
