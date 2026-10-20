#![cfg(feature = "cli")]

fn run(args: &[&str]) -> String {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_nixvm"))
        .args(args)
        .output()
        .unwrap();
    assert!(!output.status.success());
    String::from_utf8(output.stderr).unwrap()
}

#[test]
fn erofs_options_require_paths_and_cannot_mix_root_sources() {
    for args in [
        vec!["run", "--erofs"],
        vec!["run", "--erofs", "--", "/init"],
    ] {
        assert!(run(&args).contains("--erofs needs an image path"));
    }
    for args in [
        vec![
            "run",
            "--root",
            "root",
            "--erofs",
            "root.erofs",
            "--",
            "/init",
        ],
        vec![
            "run",
            "--erofs",
            "root.erofs",
            "--root",
            "root",
            "--",
            "/init",
        ],
    ] {
        assert!(run(&args).contains("--root and --erofs cannot be combined"));
    }
}

#[cfg(not(feature = "erofs"))]
#[test]
fn selecting_erofs_without_the_feature_is_a_clear_error() {
    assert!(
        run(&["run", "--erofs", "root.erofs", "--", "/init"])
            .contains("requires the `erofs` feature")
    );
}
