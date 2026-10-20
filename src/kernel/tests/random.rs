use super::*;
use crate::fs::{DevFs, LayerStack, MountFs, Overlay};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{Rng, SeedableRng};

fn seeded(seed: [u8; 32]) -> (Kernel, GuestMemory, DummyVcpu, ServiceCtx) {
    let mut mounts = MountTable::new();
    mounts.mount("/", Box::new(TmpFs::new()));
    // Constructor wiring must replace both standalone sources, wherever mounted.
    mounts.mount("/dev", Box::new(DevFs::with_random_seed([99; 32])));
    mounts.mount("/devices", Box::new(DevFs::new()));
    seeded_mounts(seed, mounts)
}

fn seeded_mounts(
    seed: [u8; 32],
    mounts: MountTable,
) -> (Kernel, GuestMemory, DummyVcpu, ServiceCtx) {
    let (_, mem, vcpu, context) = setup();
    let mut kernel = Kernel::with_random_seed(Arch::Aarch64, mounts, seed);
    kernel
        .shared
        .get_mut()
        .unwrap()
        .mmap_areas
        .push(Arena::new(0x1_8000, 0x1_5000));
    (kernel, mem, vcpu, context)
}

fn reference(seed: [u8; 32], count: usize) -> Vec<u8> {
    let mut bytes = vec![0; count];
    ChaCha20Rng::from_seed(seed).fill_bytes(&mut bytes);
    bytes
}

fn clone_seed(seed: [u8; 32], consumed: usize, pid: i32) -> [u8; 32] {
    let bytes = reference(seed, consumed + 32);
    let mut result = [0; 32];
    result.copy_from_slice(&bytes[consumed..]);
    for (byte, pid_byte) in result.iter_mut().zip(pid.to_le_bytes()) {
        *byte ^= pid_byte;
    }
    result
}

fn getrandom(
    kernel: &Kernel,
    memory: &mut GuestMemory,
    vcpu: &mut DummyVcpu,
    context: &mut ServiceCtx,
    count: usize,
    flags: u64,
) -> Vec<u8> {
    assert_eq!(
        call(
            kernel,
            context,
            memory,
            vcpu,
            Sysno::Getrandom,
            [0x1_0000, count as u64, flags, 0, 0, 0]
        ),
        count as i64
    );
    memory.read_vec(0x1_0000, count).unwrap()
}

fn device(kernel: &Kernel, path: &str, count: usize) -> Vec<u8> {
    let mut bytes = vec![0; count];
    assert_eq!(
        kernel
            .vfs
            .lock()
            .unwrap()
            .read_at(path, 123, &mut bytes)
            .unwrap(),
        count
    );
    bytes
}

#[test]
fn all_interfaces_and_mounts_share_the_seeded_byte_stream() {
    for arch in [Arch::Aarch64, Arch::X86_64] {
        let (mut kernel, mut memory, mut vcpu, mut context) = seeded([7; 32]);
        kernel.arch = arch;
        let mut actual = getrandom(&kernel, &mut memory, &mut vcpu, &mut context, 3, 0);
        actual.extend(device(&kernel, "/dev/urandom", 65));
        actual.extend(device(&kernel, "/devices/random", 1));
        actual.extend(getrandom(
            &kernel,
            &mut memory,
            &mut vcpu,
            &mut context,
            7,
            2,
        ));
        actual.extend(device(&kernel, "/dev/random", 257));
        assert_eq!(actual, reference([7; 32], actual.len()));
    }
}

#[test]
fn seeds_select_different_streams() {
    let (first, _, _, _) = seeded([1; 32]);
    let (second, _, _, _) = seeded([2; 32]);
    assert_ne!(
        device(&first, "/dev/random", 64),
        device(&second, "/dev/random", 64)
    );
}

#[test]
fn getrandom_flags_zero_length_and_faults() {
    for flags in [0, 1, 2, 3, 4, 5] {
        let (kernel, mut memory, mut vcpu, mut context) = seeded([0; 32]);
        assert_eq!(
            getrandom(&kernel, &mut memory, &mut vcpu, &mut context, 64, flags),
            reference([0; 32], 64)
        );
    }
    let (kernel, mut memory, mut vcpu, mut context) = seeded([0; 32]);
    for flags in [6, 7, 8, 1 << 32] {
        assert_eq!(
            call(
                &kernel,
                &mut context,
                &mut memory,
                &mut vcpu,
                Sysno::Getrandom,
                [0x1_0000, 32, flags, 0, 0, 0]
            ),
            err(Errno::EINVAL)
        );
    }
    assert_eq!(
        call(
            &kernel,
            &mut context,
            &mut memory,
            &mut vcpu,
            Sysno::Getrandom,
            [u64::MAX, 0, 0, 0, 0, 0]
        ),
        0
    );
    assert_eq!(device(&kernel, "/dev/random", 64), reference([0; 32], 64));
    assert_eq!(
        call(
            &kernel,
            &mut context,
            &mut memory,
            &mut vcpu,
            Sysno::Getrandom,
            [u64::MAX, 1, 0, 0, 0, 0]
        ),
        err(Errno::EFAULT)
    );
    memory.protect(0x1_0000, PAGE, Prot::rx()).unwrap();
    assert_eq!(
        call(
            &kernel,
            &mut context,
            &mut memory,
            &mut vcpu,
            Sysno::Getrandom,
            [0x1_0000, 1, 0, 0, 0, 0]
        ),
        err(Errno::EFAULT)
    );
}

#[test]
fn successful_process_clones_reseed_the_shared_stream() {
    for syscall in [Sysno::Clone, Sysno::Clone3, Sysno::Fork] {
        let (mut kernel, mut memory, mut vcpu, mut context) = seeded([7; 32]);
        let pid = 0x1234_5678;
        kernel.shared.get_mut().unwrap().next_pid = pid;
        assert_eq!(
            getrandom(&kernel, &mut memory, &mut vcpu, &mut context, 1, 0),
            reference([7; 32], 1)
        );
        let args = if syscall == Sysno::Clone3 {
            memory.write_init(0x1_1000, &[0; 64]).unwrap();
            [0x1_1000, 64, 0, 0, 0, 0]
        } else {
            [0x11, 0, 0, 0, 0, 0]
        };
        assert_eq!(
            call(&kernel, &mut context, &mut memory, &mut vcpu, syscall, args),
            i64::from(pid)
        );
        let expected_seed = clone_seed([7; 32], 1, pid);
        let mut actual = getrandom(&kernel, &mut memory, &mut vcpu, &mut context, 1, 0);
        actual.extend(device(&kernel, "/dev/urandom", 31));
        actual.extend(device(&kernel, "/devices/random", 32));
        assert_eq!(actual, reference(expected_seed, 64));

        assert_eq!(
            call(
                &kernel,
                &mut context,
                &mut memory,
                &mut vcpu,
                Sysno::Clone,
                [0x11, 0, 0, 0, 0, 0]
            ),
            i64::from(pid + 1)
        );
        assert_eq!(
            device(&kernel, "/dev/random", 128),
            reference(clone_seed(expected_seed, 64, pid + 1), 128)
        );
    }
}

#[test]
fn clone_vm_and_vfork_leave_the_stream_running() {
    for flags in [
        CLONE_VM,
        CLONE_VM | CLONE_SIGHAND | CLONE_THREAD,
        CLONE_VM | CLONE_VFORK,
    ] {
        for syscall in [Sysno::Clone, Sysno::Clone3] {
            let (kernel, mut memory, mut vcpu, mut context) = seeded([7; 32]);
            getrandom(&kernel, &mut memory, &mut vcpu, &mut context, 3, 0);
            let args = if syscall == Sysno::Clone3 {
                memory.write_init(0x1_1000, &[0; 64]).unwrap();
                memory.write_u64(0x1_1000, flags).unwrap();
                [0x1_1000, 64, 0, 0, 0, 0]
            } else {
                [flags, 0, 0, 0, 0, 0]
            };
            assert_eq!(
                call(&kernel, &mut context, &mut memory, &mut vcpu, syscall, args),
                2
            );
            assert_eq!(
                device(&kernel, "/dev/random", 65),
                reference([7; 32], 68)[3..]
            );
        }
    }
    let (kernel, mut memory, mut vcpu, mut context) = seeded([7; 32]);
    assert_eq!(
        call(
            &kernel,
            &mut context,
            &mut memory,
            &mut vcpu,
            Sysno::Vfork,
            [0; 6]
        ),
        2
    );
    assert_eq!(device(&kernel, "/dev/random", 64), reference([7; 32], 64));
}

#[test]
fn failed_clones_do_not_reseed_or_consume_bytes() {
    let (kernel, mut memory, mut vcpu, mut context) = seeded([7; 32]);
    getrandom(&kernel, &mut memory, &mut vcpu, &mut context, 1, 0);
    for flags in [CLONE_THREAD, CLONE_SIGHAND, 1 << 63] {
        assert_eq!(
            call(
                &kernel,
                &mut context,
                &mut memory,
                &mut vcpu,
                Sysno::Clone,
                [flags, 0, 0, 0, 0, 0]
            ),
            err(Errno::EINVAL)
        );
    }
    assert_eq!(
        call(
            &kernel,
            &mut context,
            &mut memory,
            &mut vcpu,
            Sysno::Clone3,
            [0x1_1000, 63, 0, 0, 0, 0]
        ),
        err(Errno::EINVAL)
    );
    assert_eq!(
        device(&kernel, "/dev/random", 65),
        reference([7; 32], 66)[1..]
    );
    assert_eq!(kernel.shared.lock().unwrap().next_pid, 2);
}

#[test]
fn device_writes_and_new_mounts_do_not_restart_the_stream() {
    let (kernel, mut memory, mut vcpu, mut context) = seeded([7; 32]);
    kernel.clock.advance_execution(4_000_000_123);
    getrandom(&kernel, &mut memory, &mut vcpu, &mut context, 3, 0);
    {
        let mut mounts = kernel.vfs.lock().unwrap();
        for path in ["/dev/random", "/dev/urandom"] {
            assert_eq!(mounts.write_at(path, 0, b"guest seed").unwrap(), 10);
        }
        mounts.mkdir("/extra", 0o755).unwrap();
    }
    memory.write_init(0x1_1000, b"/extra\0").unwrap();
    memory.write_init(0x1_1100, b"devtmpfs\0").unwrap();
    for consumed in [3, 68] {
        assert_eq!(
            call(
                &kernel,
                &mut context,
                &mut memory,
                &mut vcpu,
                Sysno::Mount,
                [0, 0x1_1000, 0x1_1100, 0, 0, 0]
            ),
            0
        );
        {
            let mut mounts = kernel.vfs.lock().unwrap();
            mounts.create("/extra/shm/clock-binding", 0o600).unwrap();
            let attributes = mounts.stat("/extra/shm/clock-binding").unwrap();
            let expected = crate::clock::DEFAULT_EPOCH_SECS as i64 + 4;
            assert_eq!((attributes.atime, attributes.mtime), (expected, expected));
        }
        assert_eq!(
            device(&kernel, "/extra/random", 65),
            reference([7; 32], consumed + 65)[consumed..]
        );
        assert_eq!(
            call(
                &kernel,
                &mut context,
                &mut memory,
                &mut vcpu,
                Sysno::Umount2,
                [0x1_1000, 0, 0, 0, 0, 0]
            ),
            0
        );
    }
}

fn composed_mounts() -> MountTable {
    let devfs = || -> Box<dyn MountFs> { Box::new(DevFs::with_random_seed([99; 32])) };
    let tmpfs = || -> Box<dyn MountFs> { Box::new(TmpFs::new()) };
    let mut mounts = MountTable::new();
    mounts.mount("/", tmpfs());
    mounts.mount("/overlay-lower", Box::new(Overlay::new(devfs(), tmpfs())));
    mounts.mount("/overlay-upper", Box::new(Overlay::new(tmpfs(), devfs())));
    mounts.mount(
        "/layer-base",
        Box::new(LayerStack::new(vec![devfs(), tmpfs()]).unwrap()),
    );
    mounts.mount(
        "/layer-top",
        Box::new(LayerStack::new(vec![tmpfs(), devfs()]).unwrap()),
    );
    mounts.mount(
        "/nested",
        Box::new(Overlay::new(
            Box::new(
                LayerStack::new(vec![tmpfs(), Box::new(Overlay::new(devfs(), tmpfs()))]).unwrap(),
            ),
            tmpfs(),
        )),
    );
    mounts
}

const COMPOSED_DEVICES: [&str; 5] = [
    "/overlay-lower/random",
    "/overlay-upper/urandom",
    "/layer-base/random",
    "/layer-top/urandom",
    "/nested/random",
];

#[test]
fn composed_devfs_mounts_share_the_kernel_stream() {
    let (kernel, mut memory, mut vcpu, mut context) = seeded_mounts([7; 32], composed_mounts());
    let mut actual = getrandom(&kernel, &mut memory, &mut vcpu, &mut context, 3, 0);
    for path in COMPOSED_DEVICES {
        actual.extend(device(&kernel, path, 17));
    }
    actual.extend(getrandom(
        &kernel,
        &mut memory,
        &mut vcpu,
        &mut context,
        7,
        0,
    ));
    assert_eq!(actual, reference([7; 32], actual.len()));
}

// Keep test access to a child backend even when guest writes are blocked by a layer stack.
#[derive(Debug)]
struct SharedDevFs(Arc<Mutex<DevFs>>);

impl MountFs for SharedDevFs {
    fn set_clock(&mut self, clock: Arc<crate::clock::VirtualClock>) {
        self.0.lock().unwrap().set_clock(clock);
    }

    fn visit_devfs_mut(&mut self, visitor: &mut dyn FnMut(&mut DevFs)) {
        visitor(&mut self.0.lock().unwrap());
    }

    fn stat(&mut self, rel: &str) -> Option<Attrs> {
        self.0.lock().unwrap().stat(rel)
    }

    fn read_at(&mut self, rel: &str, off: u64, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().read_at(rel, off, bytes)
    }

    fn readdir(&mut self, rel: &str) -> std::io::Result<Vec<crate::fs::DirEntry>> {
        self.0.lock().unwrap().readdir(rel)
    }
}

#[test]
fn composed_devfs_mounts_bind_clock_and_randomness_together() {
    let devfs = Arc::new(Mutex::new(DevFs::with_random_seed([99; 32])));
    let mut mounts = MountTable::new();
    mounts.mount("/", Box::new(TmpFs::new()));
    mounts.mount(
        "/nested",
        Box::new(Overlay::new(
            Box::new(
                LayerStack::new(vec![Box::new(Overlay::new(
                    Box::new(TmpFs::new()),
                    Box::new(SharedDevFs(Arc::clone(&devfs))),
                ))])
                .unwrap(),
            ),
            Box::new(TmpFs::new()),
        )),
    );
    let (kernel, mut memory, mut vcpu, mut context) = seeded_mounts([7; 32], mounts);
    kernel.clock.advance_execution(4_000_000_123);
    devfs
        .lock()
        .unwrap()
        .create("shm/clock-binding", 0o600)
        .unwrap();
    let attributes = kernel
        .vfs
        .lock()
        .unwrap()
        .stat("/nested/shm/clock-binding")
        .unwrap();
    let expected = crate::clock::DEFAULT_EPOCH_SECS as i64 + 4;
    assert_eq!((attributes.atime, attributes.mtime), (expected, expected));
    let mut actual = getrandom(&kernel, &mut memory, &mut vcpu, &mut context, 3, 0);
    actual.extend(device(&kernel, "/nested/random", 17));
    assert_eq!(actual, reference([7; 32], actual.len()));
}

#[test]
fn composed_devfs_mounts_follow_clone_reseeding() {
    let (kernel, mut memory, mut vcpu, mut context) = seeded_mounts([7; 32], composed_mounts());
    getrandom(&kernel, &mut memory, &mut vcpu, &mut context, 3, 0);
    assert_eq!(
        call(
            &kernel,
            &mut context,
            &mut memory,
            &mut vcpu,
            Sysno::Fork,
            [0; 6]
        ),
        2
    );
    let mut actual = Vec::new();
    for path in COMPOSED_DEVICES {
        actual.extend(device(&kernel, path, 17));
    }
    actual.extend(getrandom(
        &kernel,
        &mut memory,
        &mut vcpu,
        &mut context,
        7,
        0,
    ));
    assert_eq!(actual, reference(clone_seed([7; 32], 3, 2), actual.len()));
}

fn open_device(
    kernel: &Kernel,
    memory: &mut GuestMemory,
    vcpu: &mut DummyVcpu,
    context: &mut ServiceCtx,
    path: &str,
) -> u64 {
    memory
        .write_init(0x1_1000, format!("{path}\0").as_bytes())
        .unwrap();
    let fd = call(
        kernel,
        context,
        memory,
        vcpu,
        Sysno::Openat,
        [AT_CWD, 0x1_1000, 2, 0, 0, 0],
    );
    assert!(fd >= 3, "open {path}: {fd}");
    fd as u64
}

#[test]
fn random_device_mmap_is_denied_before_memory_or_stream_changes() {
    for path in [
        "/dev/random",
        "/dev/urandom",
        "/devices/random",
        "/nested/urandom",
    ] {
        // MAP_SHARED, MAP_PRIVATE, MAP_SHARED_VALIDATE; with and without MAP_FIXED.
        for mapping_type in [1, 2, 3] {
            for fixed in [0, 0x10] {
                let (kernel, mut memory, mut vcpu, mut context) = seeded([7; 32]);
                // Rejection must also recognize a random device inside wrappers.
                kernel.vfs.lock().unwrap().mount(
                    "/nested",
                    Box::new(Overlay::new(
                        Box::new(LayerStack::new(vec![Box::new(DevFs::new())]).unwrap()),
                        Box::new(TmpFs::new()),
                    )),
                );
                let fd = open_device(&kernel, &mut memory, &mut vcpu, &mut context, path);
                getrandom(&kernel, &mut memory, &mut vcpu, &mut context, 3, 0);
                let guard = 0x1_7000;
                memory.map(guard, PAGE, Prot::rw()).unwrap();
                memory.write_init(guard, &[0x5a; PAGE as usize]).unwrap();
                let result = call(
                    &kernel,
                    &mut context,
                    &mut memory,
                    &mut vcpu,
                    Sysno::Mmap,
                    [
                        if fixed == 0 { 0 } else { guard },
                        PAGE,
                        3,
                        mapping_type | fixed,
                        fd,
                        0,
                    ],
                );
                assert_eq!(
                    result,
                    err(Errno::ENODEV),
                    "{path}, flags={:#x}",
                    mapping_type | fixed
                );
                assert_eq!(
                    memory.read_vec(guard, PAGE as usize).unwrap(),
                    [0x5a; PAGE as usize]
                );
                assert_eq!(memory.page_prot(guard), Some(Prot::rw()));
                assert!(context.cur.shared_maps.is_empty());
                assert_eq!(
                    getrandom(&kernel, &mut memory, &mut vcpu, &mut context, 65, 0),
                    reference([7; 32], 68)[3..],
                    "failed mmap consumed random bytes"
                );
                // Denial must leave the allocator's next page available, even for MAP_FIXED.
                assert_eq!(
                    call(
                        &kernel,
                        &mut context,
                        &mut memory,
                        &mut vcpu,
                        Sysno::Mmap,
                        [0, PAGE, 3, 0x22, u64::MAX, 0]
                    ),
                    guard as i64,
                    "failed mmap claimed arena space"
                );
            }
        }
    }
}

#[test]
fn denied_random_mmaps_leave_syscall_reads_contiguous_and_writes_discarded() {
    for path in ["/dev/random", "/dev/urandom", "/devices/urandom"] {
        let (kernel, mut memory, mut vcpu, mut context) = seeded([7; 32]);
        let fd = open_device(&kernel, &mut memory, &mut vcpu, &mut context, path);
        getrandom(&kernel, &mut memory, &mut vcpu, &mut context, 3, 0);
        assert_eq!(
            call(
                &kernel,
                &mut context,
                &mut memory,
                &mut vcpu,
                Sysno::Mmap,
                [0, PAGE, 3, 1, fd, 0]
            ),
            err(Errno::ENODEV)
        );
        memory.write_init(0x1_2000, &[0xa5; 64]).unwrap();
        for syscall in [Sysno::Write, Sysno::Pwrite64] {
            assert_eq!(
                call(
                    &kernel,
                    &mut context,
                    &mut memory,
                    &mut vcpu,
                    syscall,
                    [fd, 0x1_2000, 64, 0, 0, 0]
                ),
                64
            );
        }
        assert_eq!(
            call(
                &kernel,
                &mut context,
                &mut memory,
                &mut vcpu,
                Sysno::Read,
                [fd, 0x1_2000, 65, 0, 0, 0]
            ),
            65
        );
        let mut actual = memory.read_vec(0x1_2000, 65).unwrap();
        actual.extend(getrandom(
            &kernel,
            &mut memory,
            &mut vcpu,
            &mut context,
            7,
            0,
        ));
        assert_eq!(actual, reference([7; 32], 75)[3..]);
    }
}

#[test]
fn zero_device_mmap_still_succeeds_for_all_mapping_types() {
    for mapping_type in [1, 2, 3] {
        let (kernel, mut memory, mut vcpu, mut context) = seeded([7; 32]);
        let fd = open_device(&kernel, &mut memory, &mut vcpu, &mut context, "/dev/zero");
        let base = call(
            &kernel,
            &mut context,
            &mut memory,
            &mut vcpu,
            Sysno::Mmap,
            [0, PAGE, 3, mapping_type, fd, 0],
        );
        assert_eq!(base, 0x1_7000);
        assert_eq!(
            memory.read_vec(base as u64, PAGE as usize).unwrap(),
            [0; PAGE as usize]
        );
    }
}
