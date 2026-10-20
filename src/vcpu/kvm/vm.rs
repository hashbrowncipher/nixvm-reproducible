//! The KVM virtual machine: fds, the single guest-RAM memslot, and CPUID.
//!
//! One [`Vm`] per [`super::KvmBackend`] (KVM has no per-process VM quota, so —
//! unlike HVF's process-global VM — each backend owns its own, which keeps
//! parallel `cargo test` kernels from sharing one guest-physical space).
//!
//! Since the Phase-3 MMU refactor the guest-physical space is trivial: **one**
//! RAM memslot mapping the whole shared physical pool
//! ([`crate::vcpu::phys::PhysMem`]) at `guest_phys == 0`, registered once (on the
//! first run) and never re-pointed. Every process has real page tables over that
//! pool and its own `CR3`; a context switch is just a `KVM_SET_SREGS` of `cr3`,
//! not a memslot swap. The supervisor scaffold (GDT/IDT/TSS/trampolines) lives in
//! pinned pool frames mapped into every address space by [`crate::vcpu::ctrl`];
//! there is no separate control-block slot and no shadow page-table builder.
//!
//! A guest `syscall` at CPL3 vectors to the `hlt; sysretq` trampoline at CPL0;
//! `hlt` exits to the host (`KVM_EXIT_HLT`), the kernel services the syscall, and
//! the resumed `sysretq` drops back to CPL3. A `#PF` vectors (via the IDT's only
//! gate) to the `#PF` trampoline (`hlt`); the host reads the exception frame the
//! CPU pushed onto the kernel stack out of the pool.

use super::sys;
use crate::vcpu::VcpuError;
use crate::vcpu::mem::GuestMemory;
use crate::vcpu::phys::PhysMem;
use std::ffi::c_int;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// Re-export the control-block virtual addresses and selectors the vcpu wires into
// its sregs/MSRs, so vcpu.rs keeps importing them from `super::vm`.
pub use crate::vcpu::ctrl::{
    FAULT_TRAMP_VA, GDT_BASE, GDT_LIMIT, GP_TRAMP_VA, IDT_BASE, LSTAR_VA, SEL_TSS, SEL_UCODE,
    SEL_UDATA, STAR_VALUE, TSS_BASE, UD_TRAMP_VA,
};

/// An owned Unix fd that closes on drop.
#[derive(Debug)]
pub struct Fd(pub c_int);

impl Drop for Fd {
    fn drop(&mut self) {
        if self.0 < 0 || crate::confinement::retained(self.0) {
            return;
        }
        // SAFETY: `self.0` is a live fd owned by this value, closed only here.
        unsafe { sys::close(self.0) };
    }
}

/// Result of `ioctl` calls: `Ok(ret)` for `ret >= 0`, else the OS error.
pub fn check(ret: c_int, what: &str) -> Result<c_int, VcpuError> {
    if ret >= 0 {
        Ok(ret)
    } else {
        Err(VcpuError::Backend(format!(
            "{what} failed: {}",
            std::io::Error::last_os_error()
        )))
    }
}

/// One KVM virtual machine. Holds `/dev/kvm`, the VM fd, the guest CPUID
/// profile, and — once the first vcpu runs — a handle on the shared pool whose
/// single memslot it registered.
#[derive(Debug)]
pub struct Vm {
    system_fd: Fd,
    fd: Fd,
    vcpu_mmap_size: usize,
    cpuid: Box<sys::kvm_cpuid2>,
    xsave_size: usize,
    xsave_get: std::ffi::c_ulong,
    /// The shared physical pool, registered as the one RAM memslot on the first
    /// run. `None` until then. Kept so the fault path can read the exception frame
    /// out of the control block without a `GuestMemory` borrow (the SMP path holds
    /// none). All address spaces share this pool, so it is registered exactly once.
    pool: Mutex<Option<std::sync::Arc<PhysMem>>>,
    next_vcpu_id: AtomicU32,
    /// Logical time shared by every vcpu and address space in this VM. RDTSC,
    /// RDTSCP and syscall entry each advance it by one tick.
    tsc: AtomicU64,
    slots: Mutex<Option<Vec<Slot>>>,
    event_flags: AtomicU32,
}

#[derive(Debug)]
struct Slot {
    fd: c_int,
    run: usize,
    reset: sys::kvm_sregs,
}

// SAFETY: `Vm` is shared (`Arc`) across the vcpus of one kernel. The pool handle
// lives behind a `Mutex`; the fds/ids are ioctl handles the kernel serializes
// internally. `PhysMem`'s bytes are the shared physical RAM — concurrent access
// to distinct frames is the model, serialized where it matters by the kernel lock.
unsafe impl Send for Vm {}
// SAFETY: see the `Send` note above.
unsafe impl Sync for Vm {}

impl Vm {
    /// Open `/dev/kvm` and build a VM. No memslot is registered yet — the pool
    /// isn't known until the first `GuestMemory` runs.
    pub fn new() -> Result<Self, VcpuError> {
        // SAFETY: a NUL-terminated path literal; `Fd` owns the returned fd.
        let raw = unsafe { sys::open(c"/dev/kvm".as_ptr(), sys::O_RDWR | sys::O_CLOEXEC) };
        let sys_fd = Fd(check(raw, "open(/dev/kvm)")?);

        // SAFETY: `KVM_GET_API_VERSION` takes no argument; the fd is live.
        let version = unsafe { sys::ioctl(sys_fd.0, sys::KVM_GET_API_VERSION, 0) };
        if version != sys::KVM_API_VERSION {
            return Err(VcpuError::Backend(format!(
                "KVM API version {version} (want {})",
                sys::KVM_API_VERSION
            )));
        }

        // SAFETY: `KVM_CREATE_VM` takes the machine type (0 = default).
        let raw = unsafe { sys::ioctl(sys_fd.0, sys::KVM_CREATE_VM, 0) };
        let fd = Fd(check(raw, "KVM_CREATE_VM")?);

        // Intel without "unrestricted guest" needs a TSS window; harmless else.
        // SAFETY: takes a plain GPA argument; the fd is live.
        unsafe { sys::ioctl(fd.0, sys::KVM_SET_TSS_ADDR, 0xFFFB_D000u64) };

        // SAFETY: `KVM_GET_VCPU_MMAP_SIZE` takes no argument.
        let raw = unsafe { sys::ioctl(sys_fd.0, sys::KVM_GET_VCPU_MMAP_SIZE, 0) };
        let vcpu_mmap_size = check(raw, "KVM_GET_VCPU_MMAP_SIZE")? as usize;

        // Host capabilities validate the profile; they never supply guest identity.
        let mut supported = Box::new(sys::kvm_cpuid2 {
            nent: sys::CPUID_CAP as u32,
            ..Default::default()
        });
        // SAFETY: `supported` is a live, writable allocation whose `nent` bounds the
        // entry array; the kernel fills entries and shrinks `nent`.
        let raw = unsafe {
            sys::ioctl(
                sys_fd.0,
                sys::KVM_GET_SUPPORTED_CPUID,
                std::ptr::from_mut(supported.as_mut()),
            )
        };
        check(raw, "KVM_GET_SUPPORTED_CPUID")?;
        let cpuid = guest_cpuid(&supported)?;

        // SET_XSAVE consumes the VM's full buffer size, including any dynamically
        // enabled host components. Only x87/SSE/YMM are exposed to the guest.
        // SAFETY: CHECK_EXTENSION takes a capability number on a live VM fd.
        let raw = unsafe { sys::ioctl(fd.0, sys::KVM_CHECK_EXTENSION, sys::KVM_CAP_XSAVE2) };
        let size = check(raw, "KVM_CHECK_EXTENSION(XSAVE2)")? as usize;
        let xsave_size = size.max(4096);
        let xsave_get = if size > 0 {
            sys::KVM_GET_XSAVE2
        } else {
            sys::KVM_GET_XSAVE
        };

        Ok(Self {
            system_fd: sys_fd,
            fd,
            vcpu_mmap_size,
            cpuid,
            xsave_size,
            xsave_get,
            pool: Mutex::new(None),
            next_vcpu_id: AtomicU32::new(0),
            tsc: AtomicU64::new(0),
            slots: Mutex::new(None),
            event_flags: AtomicU32::new(0),
        })
    }

    /// Issue `KVM_SET_USER_MEMORY_REGION` for `slot`.
    fn set_slot(&self, slot: u32, gpa: u64, size: u64, host: *mut u8) -> Result<(), VcpuError> {
        let region = sys::kvm_userspace_memory_region {
            slot,
            flags: 0,
            guest_phys_addr: gpa,
            memory_size: size,
            userspace_addr: host as u64,
        };
        // SAFETY: `region` is valid for the ioctl's duration; `host` points at a
        // live allocation of at least `size` bytes owned by the pool for its life.
        let ret = unsafe {
            sys::ioctl(
                self.fd.0,
                sys::KVM_SET_USER_MEMORY_REGION,
                std::ptr::from_ref(&region),
            )
        };
        check(ret, "KVM_SET_USER_MEMORY_REGION").map(drop)
    }

    /// Register the shared pool as the one RAM memslot. In production this fires
    /// exactly once: every address space (fork child, execve image) shares the one
    /// pool minted for pid 1, so the memslot is never re-pointed. The pool-changed
    /// branch exists only for tests that drive one backend across several
    /// independent `GuestMemory::new` pools; a serial run makes re-pointing safe.
    pub fn ensure_memslot(&self, mem: &GuestMemory) -> Result<(), VcpuError> {
        let mut pool = self.pool.lock().unwrap();
        let want = mem.phys_ptr();
        if pool.as_ref().map(|p| p.as_ptr()) != Some(want) {
            if pool.is_some() {
                self.set_slot(0, 0, 0, std::ptr::null_mut())?; // delete the stale slot
            }
            self.set_slot(0, 0, mem.phys_len(), want)?;
            *pool = Some(mem.phys_arc());
        }
        Ok(())
    }

    /// Create a vcpu: its fd and the shared `kvm_run` page.
    pub fn create_vcpu(&self) -> Result<(Fd, *mut sys::kvm_run), VcpuError> {
        let mut slots = self.slots.lock().unwrap();
        if let Some(pool) = slots.as_mut() {
            let slot = pool
                .pop()
                .ok_or_else(|| VcpuError::Backend("guest vCPU capacity exhausted".into()))?;
            let fd = Fd(slot.fd);
            let events = sys::kvm_vcpu_events {
                flags: self.event_flags.load(Ordering::Relaxed),
                ..Default::default()
            };
            let debugregs = sys::kvm_debugregs {
                dr6: 0xffff_0ff0,
                dr7: 0x400,
                ..Default::default()
            };
            // SAFETY: pool slots remain mapped and open throughout the run.
            unsafe {
                check(
                    sys::ioctl(fd.0, sys::KVM_SET_VCPU_EVENTS, &events),
                    "reset pooled events",
                )?;
                check(
                    sys::ioctl(fd.0, sys::KVM_SET_DEBUGREGS, &debugregs),
                    "reset pooled debug registers",
                )?;
                check(
                    sys::ioctl(fd.0, sys::KVM_SET_MP_STATE, &0u32),
                    "reset pooled MP state",
                )?;
                check(
                    sys::ioctl(fd.0, sys::KVM_SET_SREGS, &slot.reset),
                    "reset pooled sregs",
                )?;
                check(
                    sys::ioctl(
                        fd.0,
                        sys::KVM_SET_GUEST_DEBUG,
                        &sys::kvm_guest_debug::default(),
                    ),
                    "reset pooled debugger",
                )?;
            }
            return Ok((fd, slot.run as *mut sys::kvm_run));
        }
        self.create_raw_vcpu()
    }

    fn create_raw_vcpu(&self) -> Result<(Fd, *mut sys::kvm_run), VcpuError> {
        let id = self.next_vcpu_id.fetch_add(1, Ordering::Relaxed);
        // SAFETY: `KVM_CREATE_VCPU` takes the vcpu id; the fd is owned below.
        let raw = unsafe { sys::ioctl(self.fd.0, sys::KVM_CREATE_VCPU, u64::from(id)) };
        let fd = Fd(check(raw, "KVM_CREATE_VCPU")?);
        // SAFETY: mapping `vcpu_mmap_size` bytes of the vcpu fd as documented; the
        // result is checked against MAP_FAILED.
        let run = unsafe {
            sys::mmap(
                std::ptr::null_mut(),
                self.vcpu_mmap_size,
                sys::PROT_READ | sys::PROT_WRITE,
                sys::MAP_SHARED,
                fd.0,
                0,
            )
        };
        if run == sys::MAP_FAILED {
            return Err(VcpuError::Backend(format!(
                "mmap(kvm_run) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok((fd, run.cast()))
    }

    pub fn prepare_pool(
        &self,
        capacity: usize,
    ) -> Result<crate::confinement::Resources, VcpuError> {
        if capacity == 0 || capacity > 1024 {
            return Err(VcpuError::Backend(
                "vCPU capacity must be in 1..=1024".into(),
            ));
        }
        let mut resources = crate::confinement::Resources::default();
        resources.protected.extend([self.system_fd.0, self.fd.0]);
        let mut slots = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            let (fd, run) = self.create_raw_vcpu()?;
            let mut reset = sys::kvm_sregs::default();
            let mut events = sys::kvm_vcpu_events::default();
            // SAFETY: live preallocated vCPU and writable ABI-sized buffer.
            check(
                unsafe { sys::ioctl(fd.0, sys::KVM_GET_SREGS, &raw mut reset) },
                "snapshot pooled sregs",
            )?;
            // The getter returns this VM's supported event-validity flags;
            // enabling unsupported optional event fields would fail reset.
            check(
                unsafe { sys::ioctl(fd.0, sys::KVM_GET_VCPU_EVENTS, &raw mut events) },
                "snapshot pooled event flags",
            )?;
            self.event_flags.store(events.flags, Ordering::Relaxed);
            resources.vcpus.push(fd.0);
            resources.protected.push(fd.0);
            slots.push(Slot {
                fd: fd.0,
                run: run as usize,
                reset,
            });
            std::mem::forget(fd);
        }
        *self.slots.lock().unwrap() = Some(slots);
        Ok(resources)
    }

    pub fn recycle(&self, fd: i32, run: *mut sys::kvm_run, reset: &sys::kvm_sregs) -> bool {
        if let Some(pool) = self.slots.lock().unwrap().as_mut() {
            pool.push(Slot {
                fd,
                run: run as usize,
                reset: *reset,
            });
            true
        } else {
            false
        }
    }

    pub fn vcpu_mmap_size(&self) -> usize {
        self.vcpu_mmap_size
    }

    pub fn cpuid(&self) -> &sys::kvm_cpuid2 {
        &self.cpuid
    }

    pub fn tick(&self) -> u64 {
        self.tsc.fetch_add(1, Ordering::Relaxed).wrapping_add(1)
    }

    pub fn xsave_size(&self) -> usize {
        self.xsave_size
    }

    pub fn xsave_get(&self) -> std::ffi::c_ulong {
        self.xsave_get
    }
}

fn guest_cpuid(supported: &sys::kvm_cpuid2) -> Result<Box<sys::kvm_cpuid2>, VcpuError> {
    use crate::vcpu::cpuid::{ENTRIES, indexed, query};

    // Feature words describe instructions and control state. Identity, topology,
    // cache sizes, and frequencies are deliberately excluded from this comparison.
    for (leaf, subleaf, masks) in [
        (1, 0, [0, 0, !(1 << 27 | 1 << 31), u32::MAX]),
        (7, 0, [0, u32::MAX, u32::MAX, u32::MAX]),
        (0xd, 0, [u32::MAX, 0, 0, u32::MAX]),
        (0x8000_0001, 0, [0, 0, u32::MAX, u32::MAX]),
    ] {
        let expected = query(leaf, subleaf);
        let available = supported.entries[..supported.nent as usize]
            .iter()
            .find(|entry| entry.function == leaf && entry.index == subleaf)
            .copied()
            .unwrap_or_default();
        for ((required, present), mask) in [expected.eax, expected.ebx, expected.ecx, expected.edx]
            .into_iter()
            .zip([available.eax, available.ebx, available.ecx, available.edx])
            .zip(masks)
        {
            let missing = required & mask & !present;
            if missing != 0 {
                return Err(VcpuError::Backend(format!(
                    "KVM cannot execute the CPUID profile: leaf {leaf:#x}/{subleaf:#x} missing bits {missing:#x}"
                )));
            }
        }
    }

    let mut result = Box::new(sys::kvm_cpuid2::default());
    if ENTRIES.len() > result.entries.len() {
        return Err(VcpuError::Backend(
            "CPUID profile exceeds KVM table capacity".into(),
        ));
    }
    result.nent = ENTRIES.len() as u32;
    for (target, entry) in result.entries.iter_mut().zip(ENTRIES) {
        *target = sys::kvm_cpuid_entry2 {
            function: entry.leaf,
            index: entry.subleaf,
            flags: u32::from(indexed(entry.leaf)),
            eax: entry.eax,
            ebx: entry.ebx,
            ecx: entry.ecx,
            edx: entry.edx,
            padding: [0; 3],
        };
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::{guest_cpuid, sys};
    use crate::vcpu::cpuid::ENTRIES;

    fn supported_profile() -> sys::kvm_cpuid2 {
        let mut supported = sys::kvm_cpuid2 {
            nent: ENTRIES.len() as u32,
            ..Default::default()
        };
        for (target, source) in supported.entries.iter_mut().zip(ENTRIES) {
            target.function = source.leaf;
            target.index = source.subleaf;
            target.eax = source.eax;
            target.ebx = source.ebx;
            target.ecx = source.ecx;
            target.edx = source.edx;
        }
        supported
    }

    #[test]
    fn host_identity_and_extra_features_do_not_enter_the_profile() {
        let mut supported = supported_profile();
        for entry in &mut supported.entries[..supported.nent as usize] {
            match entry.function {
                0 => entry.ebx = 0x1234_5678,
                1 => {
                    entry.eax = u32::MAX;
                    entry.ebx = u32::MAX;
                    entry.ecx |= 1 << 30; // Host RDRAND stays hidden.
                    entry.ecx &= !(1 << 27); // OSXSAVE comes from guest CR4.
                }
                0x8000_0002..=0x8000_0004 => entry.eax = u32::MAX,
                _ => {}
            }
        }
        let guest = guest_cpuid(&supported).unwrap();
        for (actual, expected) in guest.entries.iter().zip(ENTRIES) {
            assert_eq!(
                (
                    actual.function,
                    actual.index,
                    actual.eax,
                    actual.ebx,
                    actual.ecx,
                    actual.edx
                ),
                (
                    expected.leaf,
                    expected.subleaf,
                    expected.eax,
                    expected.ebx,
                    expected.ecx,
                    expected.edx
                )
            );
        }
    }

    #[test]
    fn missing_avx2_rejects_hardware_instead_of_changing_guest_cpuid() {
        let mut supported = supported_profile();
        let structured = supported
            .entries
            .iter_mut()
            .find(|entry| entry.function == 7)
            .unwrap();
        structured.ebx &= !(1 << 5);
        let error = guest_cpuid(&supported).unwrap_err().to_string();
        assert!(error.contains("leaf 0x7/0x0 missing bits 0x20"), "{error}");
    }
}
