# Read layered EROFS roots

Vendored the unmodified crates.io release of `rust-fs-erofs` 0.4.1 in commit
`3fba6fd`. `vendor/README.md` records its archive checksum and upstream revision.
Cargo uses a local path dependency. The new direct dependencies are exactly
pinned; the root lockfile preserves every existing package version and checksum.

Added `ErofsMount` for on-demand image reads and a separate, format-independent
`LayerStack` over `MountFs`. The merger supports precedence, directory merging,
native and xattr whiteouts, opaque directories, ancestor shadowing, and distinct
inode identities across images while retaining hard links within each image.
`MountFs::try_stat` lets the merger distinguish an absent entry from an unreadable
one, so an error in a higher layer cannot expose older data.

The reader owns open host file handles for the run. `root_erofs`,
`root_erofs_layers`, and repeated CLI `--erofs` options select images in
base-to-top order beneath the existing writable tmpfs overlay. Writing is
deferred; `tasks/erofs-writing.md` records saving the root upper at lifecycle
checkpoints, especially exit.

The guest path interface uses UTF-8 strings. Invalid UTF-8 names and symlink
targets return `EILSEQ`. Overlayfs directory redirects and metadata-only copies
are refused with `EOPNOTSUPP`; they need separate lower-path data resolution.

## Validation

Baseline: `7ab9855`. Toolchain: Rust 1.93.1, Linux x86-64. All Rust checks ran
offline inside the parent repository's test seal, using the worktree's isolated
Cargo cache at `target/cargo-home`.

- Full default suite: 768 passed, 2 existing ignored tests; 732 library tests.
- Full `erofs,fstool` suite: 791 passed, 2 existing ignored tests; 740 library
  tests. This includes ten EROFS tests, the CLI validation test, and eight
  format-independent merger tests.
- The tests read committed images generated independently by erofs-utils 1.9.
  `scripts/make-erofs-fixtures.py` declares all source bytes and metadata, builds
  uncompressed/LZ4/LZMA/DEFLATE/Zstandard images, and validates them with
  `fsck.erofs --extract`. `tests/data/erofs/README.md` records image checksums.
  Regeneration needs the EROFS tools; the Rust tests do not.
- Verified startup and CLI precedence with executable images, merged symlink
  resolution, native whiteouts and opacity, hard links, xattrs, reads across
  block boundaries and EOF, invalid images, 80 in-memory layers, error
  propagation, and retention of the original open image after path replacement.
- `cargo doc --offline --locked --no-deps --features erofs,fstool` passed with
  `RUSTDOCFLAGS='-D warnings -D rustdoc::broken_intra_doc_links'`.
- Strict all-target Clippy found the baseline
  `clippy::field_reassign_with_default` in `src/vcpu/kvm/vm.rs:300`. That file
  matches the baseline and was left untouched. The same check passed with
  `-D warnings -A clippy::field_reassign_with_default`.
- Changed Rust and Python files were formatted through `tools/format.py`'s
  helpers. The CI `cargo fmt --all --check` passed, including the vendored
  crate. Source whitespace checks passed. The pristine vendored pull-request
  template contains upstream trailing whitespace on line 19, which was kept.

The inherited parent test and landing helpers assume a root `package.json` and
fail unadapted in this standalone Cargo repository. The existing CPUID worklog
documents the same limitation. The final full-suite command used the test
helper with its in-process layout adaptation; no parent helper was changed:

```python
import layout
import offline
import test
original = layout.packages
layout.packages = lambda root: original(root) if (root / 'package.json').exists() else ([], [])
for features in [(), ('--features', 'erofs,fstool')]:
    offline.CARGO_TEST = ('cargo', 'test', '--offline', '--locked', *features)
    assert test.main(['.']) == 0
```

Run from the worktree with the parent `tools` directory on `sys.path`,
`PYTHONDONTWRITEBYTECODE=1` and `CARGO_HOME=$PWD/target/cargo-home`. The execution
sandbox prevents the seal's network namespace setup, so the sealed commands
ran with sandbox escalation. No branch was merged or pushed.

## Library choice

No additional overlay crate was added. The published API of
[`vfs` 0.13.0](https://docs.rs/vfs/0.13.0/vfs/filesystem/trait.FileSystem.html)
lacks symlink and xattr operations; its overlay uses a private `.whiteout`
directory. [`microsandbox-filesystem` 0.3.7](https://docs.rs/crate/microsandbox-filesystem/0.3.7)
documents host-directory layers and libkrun-related dependencies. Its detailed
overlay source page could not be retrieved. Those interfaces did not provide
a demonstrated fit for the existing `MountFs` backends.

## Technical debt and capital

1. Parent validation helpers need standalone Cargo-root support. The repeated
   layout adaptations consumed more effort than the checks themselves. A small
   shared-tool change would pay off before the next change to this crate.
2. The VFS convenience `stat` interface loses error details. Moving callers to
   result-bearing metadata would preserve errno throughout the kernel and
   reduce the need for parallel convenience and detailed methods.
