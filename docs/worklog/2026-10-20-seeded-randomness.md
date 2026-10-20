# Seeded guest randomness

Started from master at `3e25af8` in the `seeded-randomness` worktree.
Replaced host entropy and clock seeding for getrandom and the random devices
with one shared ChaCha20 byte stream. Pinned `rand_chacha` to 0.10.0 with
default features disabled and recorded dependency checksums in Cargo.lock.
Its runtime dependency tree contains no OS entropy provider. Existing pins
were unchanged; the new dependencies were already cached locally.

The initial 32-byte seed defaults to zero. The builder, kernel and standalone
DevFs accept explicit seeds; the CLI accepts 64 hexadecimal digits through
`--random-seed`. Device mounts attached to a kernel share its stream, including
guest-created devtmpfs mounts. Buffering preserves unused bytes between reads.

A successful clone without CLONE_VM consumes 32 stream bytes, XORs the child's
little-endian PID into the first four, and restarts the shared stream from that
seed. This affects every task and device mount. The hook is at the successful
end of the common clone core, covering clone, clone3 and fork. CLONE_VM skips
reseeding even for vfork, whose memory implementation makes a copy. Failed
clones do not touch the stream. AT_RANDOM and CPU randomness policies were
left separate.

Validation used Rust 1.93.1 and the sealed, offline parent test helper with
the standalone-crate adapter documented in the CPUID worklog:

- Both default-replay regression tests failed first, then passed. They were
  committed before the implementation in `ed0f4d3`.
- `cargo test --offline --locked`: 796 passed, two existing ignored.
- The same suite with `--features erofs,fstool,tunnel`: 827 passed, two existing
  ignored. Coverage includes known ChaCha20 bytes, split reads, shared mounts,
  PID reseeding, repeated clones, CLONE_VM/vfork, failed clones, flags, faults,
  device writes, remounts, builder replay and a CLI guest run.
- wasm32 core check passed with `--lib --no-default-features`.
- Strict all-target Clippy with the native features found the existing
  `field_reassign_with_default` in unchanged `src/vcpu/kvm/vm.rs`. It passed
  with only that lint allowed. The new CLI test's empty-string lint was fixed.
- The repository formatter's Rust check and `git diff --check` passed.
- Public documentation built with warnings and broken-link warnings denied.

Capital notes:

1. The parent validation helpers still assume an npm root. Adding standalone
   root-Cargo support would remove the adapters; it is cheap enough to do before
   the next change. The shared randomness source now provides one place for
   future seed and replay policy changes.
