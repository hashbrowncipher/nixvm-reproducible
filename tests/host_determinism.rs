#![cfg(target_os = "linux")]

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::process::Command;

#[test]
fn randomness_probe() {
    if std::env::var_os("NIXVM_HOST_TEST_RANDOMNESS").is_none() {
        return;
    }
    // A fresh thread avoids the test harness's per-thread RandomState cache.
    let hashes = std::thread::spawn(|| {
        let state = RandomState::new();
        [state.hash_one("first"), state.hash_one("second")]
    })
    .join()
    .unwrap();
    println!("HOST_HASHES {hashes:?}");
}

fn hashes(seed: &str) -> Vec<u8> {
    let result = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "randomness_probe", "--nocapture"])
        .env("NIXVM_HOST_TEST_RANDOMNESS", "1")
        .env("NIXVM_HOST_RANDOM_SEED", seed)
        .output()
        .unwrap();
    assert!(result.status.success());
    result
        .stdout
        .split(|byte| *byte == b'\n')
        .find(|line| line.starts_with(b"HOST_HASHES "))
        .expect("fresh-process RandomState output")
        .to_vec()
}

#[test]
fn host_std_randomness_is_repeatable() {
    let seed = "00".repeat(32);
    let first = hashes(&seed);
    assert_eq!(
        first,
        hashes(&seed),
        "the same host seed must replay std hashes"
    );
    assert_ne!(
        first,
        hashes(&"01".repeat(32)),
        "the host seed must affect std hashes"
    );
}
