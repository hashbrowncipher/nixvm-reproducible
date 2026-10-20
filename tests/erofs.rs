#![cfg(feature = "erofs")]

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use nixvm::fs::{ErofsMount, LayerStack, MountFs, MountTable, NodeKind, Overlay, SetTime, TmpFs};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("tests/data/erofs/{name}.erofs"))
}

fn image(name: &str) -> ErofsMount {
    ErofsMount::open(&fixture(name)).unwrap()
}

fn stack() -> LayerStack {
    LayerStack::new(vec![
        Box::new(image("base")),
        Box::new(image("middle")),
        Box::new(image("top")),
    ])
    .unwrap()
}

fn read(fs: &mut dyn MountFs, path: &str) -> Vec<u8> {
    let mut bytes = vec![0; fs.try_stat(path).unwrap().size as usize];
    assert_eq!(fs.read_at(path, 0, &mut bytes).unwrap(), bytes.len());
    bytes
}

fn names(fs: &mut dyn MountFs, path: &str) -> Vec<String> {
    let mut names: Vec<_> = fs
        .readdir(path)
        .unwrap()
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    names.sort();
    names
}

#[test]
fn reads_metadata_hard_links_symlinks_and_xattrs_from_an_independent_image() {
    let mut fs = image("base");
    let attrs = fs.try_stat("etc/config").unwrap();
    assert_eq!(attrs.kind, NodeKind::File);
    assert_eq!(attrs.mode, 0o100640);
    assert_eq!((attrs.uid, attrs.gid), (0, 0));
    assert_eq!(attrs.mtime, 1_700_000_000);
    assert_eq!(attrs.nlink, 2);
    assert_eq!(attrs.inode, fs.stat("hardlink").unwrap().inode);
    assert_eq!(read(&mut fs, "hardlink"), b"base configuration\n");
    assert_eq!(fs.readlink("link").unwrap(), "etc/config");
    assert_eq!(fs.readlink("abslink").unwrap(), "/etc/config");
    assert_eq!(fs.stat("link").unwrap().kind, NodeKind::Symlink);
    assert_eq!(fs.stat("fifo").unwrap().kind, NodeKind::Fifo);
    assert_eq!(fs.stat("null").unwrap().kind, NodeKind::CharDevice);
    assert_eq!(fs.stat("null").unwrap().rdev, 0x103);
    assert_eq!(fs.getxattr("etc/config", "user.fixture").unwrap(), b"base");
    assert_eq!(fs.listxattr("etc/config").unwrap(), ["user.fixture"]);
    assert_eq!(names(&mut fs, "etc"), ["base-only", "config"]);
}

#[test]
fn reads_all_codecs_at_block_boundaries_and_returns_short_reads_at_eof() {
    let expected = b"EROFS fixture data\n".repeat(4096);
    for codec in ["base", "lz4", "lzma", "deflate", "zstd"] {
        let mut fs = image(codec);
        assert_eq!(read(&mut fs, "big.bin"), expected, "{codec}");
        for offset in [
            0,
            4095,
            4096,
            8190,
            expected.len() - 2,
            expected.len(),
            usize::MAX,
        ] {
            let mut buf = [0xcc; 23];
            let count = fs.read_at("big.bin", offset as u64, &mut buf).unwrap();
            let want = expected.len().saturating_sub(offset).min(buf.len());
            assert_eq!(count, want, "{codec} offset {offset}");
            if want > 0 {
                assert_eq!(&buf[..count], &expected[offset..offset + want]);
            }
            assert!(buf[count..].iter().all(|byte| *byte == 0xcc));
        }
    }
}

#[test]
fn reports_posix_lookup_errors_and_refuses_mutations() {
    let mut fs = image("base");
    assert_eq!(
        fs.read_at("missing", 0, &mut [0])
            .unwrap_err()
            .raw_os_error(),
        Some(2)
    );
    assert_eq!(
        fs.read_at("etc", 0, &mut [0]).unwrap_err().raw_os_error(),
        Some(21)
    );
    assert_eq!(
        fs.readdir("etc/config").unwrap_err().raw_os_error(),
        Some(20)
    );
    assert_eq!(
        fs.try_stat("etc/config/child").unwrap_err().raw_os_error(),
        Some(20)
    );
    assert_eq!(
        fs.readlink("etc/config").unwrap_err().raw_os_error(),
        Some(22)
    );
    assert_eq!(
        fs.getxattr("etc/config", "user.missing")
            .unwrap_err()
            .raw_os_error(),
        Some(61)
    );
    assert!(fs.read_only());
    for result in [
        fs.create("new", 0o644),
        fs.mkdir("new", 0o755),
        fs.unlink("etc/config"),
        fs.rename("etc/config", "new"),
        fs.truncate("etc/config", 0),
        fs.set_mode("etc/config", 0o777),
        fs.set_owner("etc/config", Some(123), None),
        fs.set_times("etc/config", SetTime::Now, SetTime::Now),
        fs.setxattr("etc/config", "user.x", b"x"),
        fs.removexattr("etc/config", "user.fixture"),
        fs.link("etc/config", "new"),
        fs.symlink("etc/config", "new"),
    ] {
        assert_eq!(result.unwrap_err().raw_os_error(), Some(30));
    }
    assert_eq!(
        fs.write_at("etc/config", 0, b"change")
            .unwrap_err()
            .raw_os_error(),
        Some(30)
    );
}

#[test]
fn merges_native_whiteouts_opacity_and_directory_replacements() {
    let mut fs = stack();
    assert_eq!(read(&mut fs, "etc/config"), b"top configuration\n");
    assert_eq!(read(&mut fs, "etc/base-only"), b"base only\n");
    assert_eq!(fs.getxattr("etc/config", "user.fixture").unwrap(), b"top");
    assert!(fs.stat("removed").is_none());
    assert!(!names(&mut fs, "").contains(&"removed".to_string()));
    assert_eq!(names(&mut fs, "opaque"), ["new", "top"]);
    assert!(fs.stat("opaque/old").is_none());
    assert_eq!(fs.stat("blocked").unwrap().kind, NodeKind::File);
    assert_eq!(
        fs.try_stat("blocked/old").unwrap_err().raw_os_error(),
        Some(20)
    );
    assert_eq!(names(&mut fs, "reborn"), ["new"]);
    assert!(fs.stat("reborn/old").is_none());
    assert_ne!(
        fs.stat("etc/config").unwrap().inode,
        fs.stat("hardlink").unwrap().inode
    );
    for path in ["", "etc", "opaque", "reborn"] {
        for entry in fs.readdir(path).unwrap() {
            let child = if path.is_empty() {
                entry.name
            } else {
                format!("{path}/{}", entry.name)
            };
            assert_eq!(entry.inode, fs.stat(&child).unwrap().inode);
        }
    }
}

#[test]
fn mount_table_resolves_symlinks_in_the_merged_namespace() {
    let mut mounts = MountTable::new();
    mounts.mount("/", Box::new(stack()));
    for path in ["/link", "/abslink", "/dirlink/config"] {
        assert_eq!(
            mounts.read_file(path).unwrap(),
            b"top configuration\n",
            "{path}"
        );
    }
    // A hard link names the base inode even when its other name is shadowed.
    assert_eq!(
        mounts.read_file("/hardlink").unwrap(),
        b"base configuration\n"
    );
}

#[test]
fn writable_upper_changes_leave_the_images_untouched() {
    let before: Vec<_> = ["base", "middle", "top"]
        .map(|name| std::fs::read(fixture(name)).unwrap())
        .into();
    let mut overlay = Overlay::new(Box::new(stack()), Box::new(TmpFs::new()));
    overlay.write_at("etc/config", 0, b"new").unwrap();
    overlay.unlink("etc/base-only").unwrap();
    overlay.create("created", 0o600).unwrap();
    assert!(read(&mut overlay, "etc/config").starts_with(b"new"));
    assert!(overlay.stat("etc/base-only").is_none());
    assert!(overlay.stat("created").is_some());
    for (name, bytes) in ["base", "middle", "top"].into_iter().zip(before) {
        assert_eq!(std::fs::read(fixture(name)).unwrap(), bytes);
    }
    assert_eq!(
        read(&mut image("base"), "etc/config"),
        b"base configuration\n"
    );
}

struct Bytes(Vec<u8>);

impl fs_core::BlockRead for Bytes {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_core::Result<()> {
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        let data = self
            .0
            .get(start..start.saturating_add(buf.len()))
            .ok_or_else(|| fs_core::Error::Io(io::Error::from(io::ErrorKind::UnexpectedEof)))?;
        buf.copy_from_slice(data);
        Ok(())
    }
    fn size_bytes(&self) -> u64 {
        self.0.len() as u64
    }
}

#[test]
fn rejects_invalid_or_truncated_images() {
    assert!(ErofsMount::from_device(Arc::new(Bytes(vec![0; 8192]))).is_err());
    let bytes = std::fs::read(fixture("base")).unwrap();
    for length in [0, 1024, 1100] {
        assert!(ErofsMount::from_device(Arc::new(Bytes(bytes[..length].to_vec()))).is_err());
    }
    let mut fs = ErofsMount::from_device(Arc::new(Bytes(bytes))).unwrap();
    assert_eq!(read(&mut fs, "etc/config"), b"base configuration\n");
}

#[test]
fn sandbox_loads_pid1_from_a_single_image_and_from_the_highest_layer() {
    for (layers, expected) in [
        (vec![fixture("base")], 42),
        (vec![fixture("base"), fixture("middle"), fixture("top")], 43),
    ] {
        let code = nixvm::Sandbox::builder()
            .root_erofs_layers(layers)
            .command(["/init"])
            .prefer_interp(true)
            .mem_bytes(8 << 20)
            .run()
            .unwrap();
        assert_eq!(code, expected);
    }
}

#[cfg(feature = "cli")]
#[test]
fn cli_loads_repeated_erofs_options_in_base_to_top_order() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_nixvm"))
        .args(["run", "--mem", "8M", "--erofs"])
        .arg(fixture("base"))
        .arg("--erofs")
        .arg(fixture("top"))
        .args(["--", "/init"])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(43),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn the_open_image_handle_survives_replacing_its_host_path() {
    let scratch = std::env::temp_dir().join(format!("nixvm-erofs-open-{}", std::process::id()));
    std::fs::create_dir(&scratch).unwrap();
    let path = scratch.join("root.erofs");
    std::fs::copy(fixture("base"), &path).unwrap();
    let mut fs = ErofsMount::open(&path).unwrap();
    std::fs::rename(&path, scratch.join("original.erofs")).unwrap();
    std::fs::copy(fixture("top"), &path).unwrap();
    assert_eq!(read(&mut fs, "etc/config"), b"base configuration\n");
    std::fs::remove_dir_all(&scratch).unwrap();
}
