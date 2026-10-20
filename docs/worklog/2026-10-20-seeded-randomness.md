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

## Review corrections

Independent review reproduced two gaps: constructor binding skipped DevFs behind
Overlay or LayerStack, and mmap could cache random-device bytes and discarded
writes. Added regression tests and confirmed four expected failures before
committing the tests in `3f9b5ce`. The fixes bind every nested DevFs through a
recursive visitor and reject random-character-device mmap with `ENODEV` before
address-space or stream changes. Metadata identifies the devices through aliases
and wrappers. Clone reseeding and its seed recipe are unchanged. The README now
states that deliberate host-device passthrough remains host I/O.

Validation used the same sealed offline environment and Rust 1.93.1:

- Focused random tests: 12 passed, including nested composition and clone reseeding,
  private/shared/shared-validate mmap denial, MAP_FIXED preservation, arena and
  stream preservation, syscall writes/reads and the `/dev/zero` control.
- Default suite: 801 passed; erofs,fstool,tunnel suite: 832 passed. Each retained
  two existing ignored tests.
- Strict all-target Clippy passed with only the known existing
  `field_reassign_with_default` lint allowed. wasm32 core, public rustdoc with
  warnings denied, scoped root-crate Rust formatting and `git diff --check` passed.
- Independent re-review closed both findings at `6b06ea8`.

Capital notes, ranked:

1. Recursive filesystem capabilities remove assumptions about mount depth. The
   visitor addresses this debt within the correction.
2. Syscall-level random-device tests exercise page-cache interactions omitted by
   direct backend reads. The added tests address this gap without another Vcpu harness.
3. Standalone-crate support in the parent validation helpers would remove the
   adapter and avoid unrelated vendor-toolchain discovery during formatting.

Fix agent: GPT-6 family; exact model identifier and token/tool counters were not
exposed. The correction changed nine files (342 insertions, 19 deletions).

## Independent review outcome

A separate reviewer audited `3e25af8..4f90a46`, reproduced both findings through
public APIs, and independently passed the original 796-test default suite. A
different agent added the failing regressions and implemented the corrections.
The original reviewer then audited `4f90a46..6b06ea8` and closed both findings.
Its three original stream-sharing probes, three adapted mapping/control probes
(72 configurations), and 12 focused regression tests passed. The reviewer found
no additional actionable defect in the correction. It did not repeat the broad
feature, portability, lint or documentation checks recorded above.

The expanded probes exposed a separate existing composition limitation: writing
through an embedder-provided writable Overlay with DevFs in its lower subtree
copies the special node into an ordinary upper file. This does not affect the
default direct DevFs mount or guest-created devtmpfs. Preserving special-device
semantics in arbitrary writable compositions is a separate filesystem follow-up;
the current correction does not claim to provide that behavior.

Reviewer: GPT-6 family; exact model identifier and token/tool counters were not
exposed. The initial review covered 15 files (810 insertions, 88 deletions); the
re-review covered the nine-file correction. Both reviews left source unchanged.
Detailed reports and independent probe sources are retained in the review
scratch directory. No merge or push was performed.
