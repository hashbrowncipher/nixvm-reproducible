# Dynamic exec

The kernel read a PT_INTERP symlink using the link's metadata size. EROFS
followed the link when reading, so the loader received a truncated linker.
The initial-process loader already used the symlink-aware MountTable reader.
Exec now uses that reader too.

Exec loads into a separate address space in the existing physical pool before
changing the caller. Failed loads preserve memory, identity, handlers and
close-on-exec descriptors. Successful loads keep the KVM memslot and replace
the page tables. Temporary images return their frames on failure. Exhaustion
returns ENOMEM. NIXVM_TRACE includes the loader error.

Validation started at fd7aa99 with the committed Cargo.lock and installed
Rust 1.93.1 on Linux x86-64. Both kernel regression tests failed before the fix:
the symlink lookup returned ENOENT on tmpfs, and a missing linker left the
caller's memory unmapped. They pass after the fix. Tests also cover relative
and absolute linker symlinks through execve and execveat, allocation failure
during replacement setup, and repeated temporary-image cleanup.

The sealed default suite passed through the existing host-confinement
checks.py adapter. All dependencies came from the existing offline cache.
Real Debian glibc programs passed under default Linux CLI confinement:
initial /bin/true, a static syscall-only parent executing /bin/true, dash
executing /bin/true, and fork/exec of true and false. Each passed on the
interpreter and KVM. The KVM cases also passed with
NIXVM_BRANCH_QUANTUM=65536. The interpreter rejects that explicit setting by
design. The Debian EROFS image was reused locally; nothing was downloaded.

Debt and capital:

1. The kernel and initial-process file readers had separate symlink behavior.
   Keeping executable reads on MountTable::read_file prevents that drift.
2. Small syscall fixtures need enough space for the loader's stack floor.
   A dedicated exec fixture would make future image-replacement tests cheaper.
