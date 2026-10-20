# Merge virtual time with seeded randomness

Checked `nixvm-pmu` at `395278e` against local master `f903ee4` with
`git merge-tree --write-tree master nixvm-pmu`. It found conflicts in DevFs,
Overlay and Kernel initialization. Resolved those on the feature branch before
merging into master. The combined constructor binds both the VM clock and
seeded random source; filesystem wrappers retain both propagation hooks.
Removed the superseded clock-seeded random state while preserving DevFs shm
clock binding. Passthrough host timestamps and the requested inline comment
remain unchanged.

Integration review found that LayerStack's newly supported nested DevFs
received seeded randomness but kept its standalone shm clock. Added clock
forwarding to every layer and a constructor regression covering
`Overlay -> LayerStack -> Overlay -> DevFs`. Before the fix, the regression
failed with timestamps at 1700000000 instead of 1700000004 after four seconds
of explicit virtual execution. It passes after forwarding is added. The
guest-devtmpfs regression also checks that repeated mounts retain both the
advanced clock and the uninterrupted random stream. A separate test-first
commit was unavailable while the merge index was unresolved.

Validation used Rust 1.93.1, Linux/x86-64, the existing offline Cargo cache,
and the parent's sealed runner. Each operation was bounded by 250 seconds.
The lockfile is exactly master's, SHA-256
`31020e61a367e6c271da840bfc734ac05d35f10fec4258b798142484fd1107de`.
No dependency version or parent tool changed during integration.

- Full sealed `cargo test --offline --locked --features erofs,fstool --quiet`:
  801 library tests passed, two existing manual corpus scans ignored; all
  integration and documentation tests passed.
- Sealed explicit hardware run with `--test pmu --test instruction_traps --
  --include-ignored --test-threads=1`: 12 PMU and seven instruction-trap cases
  passed.
- Sealed Clippy for all targets with `erofs,fstool`, `-D warnings` and the
  existing `field-reassign-with-default` allowance: passed.
- Sealed `cargo check --offline --locked --target wasm32-unknown-unknown
  --no-default-features --lib`: passed.
- Parent Rust formatter/check over `src` and `tests`, plus
  `git diff --check`: passed.
- Implementer's focused random filter: 25 passed; clock filter: 13 passed.
- Independent source review of both parents, automatic merges and final
  resolutions: MERGE, no open findings. The reviewer read focused validation
  evidence and confirmed the untouched virtual-time files match their
  previously reviewed parent.

The parent landing helper still cannot plan this standalone crate without a
root package.json. The full test and formatting runs used the established
in-process adapters recorded in [the implementation worklog](2026-10-20-virtual-time.md).
The parent integration tool targets main and requires a detached primary
checkout; this repository uses master checked out in the primary worktree.
The requested master merge therefore used Git after validating the resolved
feature tree. Master remained at `f903ee4` throughout validation.

One resolver and one independent reviewer used the inherited Codex model
configuration; exact model identifiers, token counts and tool-use counters
were unavailable. The resolver edited five source/test files. Their final
combined diff against master spans 410 additions and 168 deletions, including
the previously reviewed virtual-time changes in those files. The specific
LayerStack forwarding and coexistence tests add 78 lines. Reviewer source
diff: zero. The supervisor formatted, ran broad validation and committed the
integration.

Ranked capital notes:

1. Independent filesystem authority hooks can diverge when a wrapper gains
   support for a new child type. The combined clock/randomness regression is
   the small investment made here; it catches that omission on the present
   nested path.
2. Standalone Cargo-root support and configurable trunk naming in the parent
   validation/integration tools would remove repeated adapters. This remains
   a small tooling investment before the next merge of this kind.
