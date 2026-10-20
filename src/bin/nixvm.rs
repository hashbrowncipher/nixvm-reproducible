//! The `nixvm` command-line tool.
//!
//! A deliberately small, std-only argument handler for the scaffold. A richer
//! parser (clap) and structured logging arrive with the `cli` feature deps in a
//! later phase. Usage:
//!
//! ```text
//! nixvm run [--mem <bytes>] [--workdir <dir>] [--root <dir>] [--arch <arch>]
//!           [--random-seed <64 hex digits>] -- <cmd> [args...]
//! nixvm run --erofs <base> [--erofs <layer>]... -- <cmd> [args...]
//! nixvm shell
//! nixvm version
//! ```

mod common;

use std::process::ExitCode;

use nixvm::{Arch, Sandbox};

fn main() -> ExitCode {
    common::prepare();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("run") => cmd_run(&args[1..]),
        Some("shell") => cmd_run(&["--".into(), "/bin/sh".into()]),
        Some("version" | "--version" | "-V") => {
            println!("nixvm {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("help" | "--help" | "-h") | None => {
            print_usage();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("nixvm: unknown subcommand `{other}`\n");
            print_usage();
            ExitCode::FAILURE
        }
    }
}

fn cmd_run(args: &[String]) -> ExitCode {
    use std::io::Write;
    let mut builder =
        Sandbox::builder().confine_host(cfg!(all(target_os = "linux", target_arch = "x86_64")));
    let mut reproducible = false;
    let mut status_path = None;
    let mut explicit_quanta = false;
    let mut erofs_layers = Vec::new();
    let mut directory_root = false;
    let mut i = 0;
    // Parse options until the `--` separator, then the rest is the command.
    let command: Vec<String> = loop {
        match args.get(i).map(String::as_str) {
            Some("--") => break args[i + 1..].to_vec(),
            Some("--reproducible") => {
                reproducible = true;
                builder = builder.reproducible(true);
                i += 1;
            }
            Some("--status-file") => {
                let Some(path) = args.get(i + 1).filter(|path| !path.starts_with("--")) else {
                    eprintln!("nixvm: --status-file needs a path");
                    return ExitCode::FAILURE;
                };
                status_path = Some(path);
                i += 2;
            }
            Some(option @ ("--branch-quantum" | "--syscall-quantum")) => {
                let Some(value) = args.get(i + 1).and_then(|value| value.parse::<u64>().ok())
                else {
                    eprintln!("nixvm: {option} needs an unsigned integer");
                    return ExitCode::FAILURE;
                };
                builder = if option == "--branch-quantum" {
                    builder.branch_quantum(value)
                } else {
                    let Ok(value) = u32::try_from(value) else {
                        eprintln!("nixvm: --syscall-quantum must fit in u32");
                        return ExitCode::FAILURE;
                    };
                    builder.syscall_quantum(value)
                };
                explicit_quanta = true;
                i += 2;
            }
            Some("--mem") => {
                let Some(v) = args.get(i + 1).and_then(|s| parse_size(s)) else {
                    eprintln!("nixvm: --mem needs a size (e.g. 512M, 2G)");
                    return ExitCode::FAILURE;
                };
                builder = builder.mem_bytes(v);
                i += 2;
            }
            Some("--random-seed") => {
                let Some(seed) = args.get(i + 1).and_then(|s| parse_random_seed(s)) else {
                    eprintln!("nixvm: --random-seed needs exactly 64 hexadecimal digits");
                    return ExitCode::FAILURE;
                };
                builder = builder.random_seed(seed);
                i += 2;
            }
            Some("--vcpu-capacity") => {
                let Some(capacity) = args
                    .get(i + 1)
                    .and_then(|value| value.parse::<usize>().ok())
                    .filter(|value| (1..=1024).contains(value))
                else {
                    eprintln!("nixvm: --vcpu-capacity needs a number in 1..=1024");
                    return ExitCode::FAILURE;
                };
                builder = builder.vcpu_capacity(capacity);
                i += 2;
            }
            Some("--workdir") => {
                let Some(dir) = args.get(i + 1) else {
                    eprintln!("nixvm: --workdir needs a path");
                    return ExitCode::FAILURE;
                };
                builder = builder.work_dir(dir);
                i += 2;
            }
            Some("--root") => {
                if !erofs_layers.is_empty() {
                    eprintln!("nixvm: --root and --erofs cannot be combined");
                    return ExitCode::FAILURE;
                }
                let Some(dir) = args.get(i + 1) else {
                    eprintln!("nixvm: --root needs a directory");
                    return ExitCode::FAILURE;
                };
                builder = builder.root_dir(dir);
                directory_root = true;
                i += 2;
            }
            Some("--erofs") => {
                if directory_root {
                    eprintln!("nixvm: --root and --erofs cannot be combined");
                    return ExitCode::FAILURE;
                }
                let Some(path) = args.get(i + 1).filter(|path| !path.starts_with("--")) else {
                    eprintln!("nixvm: --erofs needs an image path");
                    return ExitCode::FAILURE;
                };
                erofs_layers.push(path.clone());
                i += 2;
            }
            Some("--arch") => {
                let Some(arch) = args.get(i + 1).and_then(|s| Arch::from_name(s)) else {
                    eprintln!("nixvm: --arch needs aarch64 (arm64) or x86_64 (amd64)");
                    return ExitCode::FAILURE;
                };
                builder = builder.arch(arch);
                i += 2;
            }
            Some("--env" | "-e") => {
                let Some(kv) = args.get(i + 1) else {
                    eprintln!("nixvm: --env needs KEY=VALUE");
                    return ExitCode::FAILURE;
                };
                builder = builder.env(kv);
                i += 2;
            }
            Some(_) => break args[i..].to_vec(), // no `--`: rest is the command
            None => break Vec::new(),
        }
    };

    if command.is_empty() {
        eprintln!("nixvm run: no command given");
        return ExitCode::FAILURE;
    }

    if !erofs_layers.is_empty() {
        builder = builder.root_erofs_layers(erofs_layers);
    }
    if explicit_quanta && !reproducible {
        eprintln!("nixvm: explicit quanta require --reproducible");
        return ExitCode::FAILURE;
    }
    if reproducible && status_path.is_none() {
        eprintln!(
            "nixvm: --reproducible requires --status-file to separate sandbox failures from guest output"
        );
        return ExitCode::from(125);
    }
    let report = match status_path {
        Some(path) => {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(path) {
                Ok(file) => Some(std::sync::Arc::new(file)),
                Err(error) => {
                    eprintln!("nixvm: cannot open status file: {error}");
                    return ExitCode::from(125);
                }
            }
        }
        None => None,
    };
    if let Some(file) = &report {
        builder = builder.report_file(std::sync::Arc::clone(file));
    }
    let result = builder.command(command).run();
    if let Some(file) = &report {
        let written = match &result {
            Ok(code) => writeln!(file.as_ref(), "guest-exit {}", code & 0xff),
            Err(error) => writeln!(file.as_ref(), "sandbox-error\n{error}"),
        };
        if written.is_err() {
            return ExitCode::from(125);
        }
    }
    match result {
        Ok(code) => ExitCode::from(u8::try_from(code & 0xff).unwrap_or(1)),
        Err(e) => {
            if !reproducible {
                eprintln!("nixvm: {e}");
            }
            ExitCode::from(if reproducible { 125 } else { 1 })
        }
    }
}

/// Parse a byte size with an optional K/M/G suffix.
fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, mult) = match s.chars().last()? {
        'k' | 'K' => (&s[..s.len() - 1], 1024),
        'm' | 'M' => (&s[..s.len() - 1], 1024 * 1024),
        'g' | 'G' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ => (s, 1),
    };
    num.trim().parse::<u64>().ok().map(|n| n * mult)
}

fn parse_random_seed(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut seed = [0; 32];
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(seed)
}

fn print_usage() {
    eprintln!(
        "nixvm — a portable Linux syscall sandbox\n\n\
         USAGE:\n    \
         nixvm run [--mem <size>] [--workdir <dir>] [--root <dir> | --erofs <image>...]\n              \
                   [--arch <arch>] [--random-seed <64 hex digits>]\n              \
                   [--env KEY=VAL]... -- <cmd> [args...]\n    \
         nixvm shell\n    \
         nixvm version\n\n\
         --workdir explicitly exposes a host directory at /work.\n\
         --vcpu-capacity bounds simultaneous guest CPUs (default 128).\n\
         --reproducible requires EROFS, KVM/perf and --status-file; host NIXVM_* settings are refused.\n\
         --branch-quantum and --syscall-quantum set its fairness budgets (defaults 100000 and 1024).\n\
         Guest stdin reads return zero; stdout/stderr contain guest output only.\n\
         Linux x86-64 runs irreversibly confine the host process before parsing guest files.\n\
         Host-directory symlinks and metadata changes are unavailable when confined;\n\
         EROFS guest symlinks remain supported. Host networking is unavailable.\n\
         --root uses an extracted host rootfs directory as the guest root.\n\
         --erofs loads root layers in base-to-top order (repeat for more layers;\n\
         requires the erofs feature). Guest writes use an ephemeral tmpfs upper.\n\
         --random-seed sets the 32-byte seed (default: all zero). Guest randomness\n\
         uses a shared deterministic ChaCha20 stream, with no host entropy.\n\
         The guest architecture follows the command's ELF binary (an x86_64\n\
         root runs as x86_64 on any host); --arch aarch64|x86_64 pins it."
    );
}

#[cfg(test)]
mod tests {
    use super::parse_random_seed;

    #[test]
    fn random_seed_decodes_each_byte() {
        let encoded = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let expected = std::array::from_fn(|index| index as u8);
        assert_eq!(parse_random_seed(encoded), Some(expected));
        assert_eq!(parse_random_seed(&encoded.to_uppercase()), Some(expected));
    }

    #[test]
    fn random_seed_rejects_malformed_values() {
        for encoded in [
            String::new(),
            "0".repeat(63),
            "0".repeat(65),
            "g".repeat(64),
            "+1".repeat(32),
            "é".repeat(32),
        ] {
            assert_eq!(parse_random_seed(&encoded), None);
        }
    }
}
