//! The KVM virtual CPU: one guest thread on a KVM vcpu fd.
//!
//! Execution model (long mode, guest at CPL3):
//! * Guest RAM is a shared physical pool, mapped as slot 0 of the VM. Each
//!   address space has its own page tables, selected by CR3.
//! * A guest `syscall` vectors to the `hlt; sysretq` trampoline at CPL0; the
//!   `hlt` exits to the host as `KVM_EXIT_HLT` → [`Exit::Syscall`]. The kernel
//!   completes the syscall through [`KvmVcpu::set_syscall_ret`], which restores
//!   CPL3 at the user `rip`/`rflags` saved in `rcx`/`r11`, then writes `rax`.
//!   Software return keeps SYSRETQ from clearing KVM's stepping flag.
//! * #PF, #GP and #UD enter supervisor HLT trampolines through the IDT. The
//!   host recovers the original user state from the exception frame. CR4.TSD
//!   traps RDTSC/RDTSCP through #GP; we decode them and observe the VM clock.
//!
//! Register state is cached host-side: refreshed from the vcpu after every
//! `KVM_RUN`, flushed back (when dirty) before the next. That makes the
//! accessors cheap, and — because the refresh includes the special registers —
//! `fork` clones the *true* mid-trap state (CPL0, in the trampoline), so the
//! child's first `sysretq` returns to user mode exactly like the parent's.

use super::vm::{
    FAULT_TRAMP_VA, GDT_BASE, GDT_LIMIT, GP_TRAMP_VA, LSTAR_VA, SEL_UCODE, SEL_UDATA, STAR_VALUE,
    UD_TRAMP_VA, Vm, check,
};
use super::{pmu, sys};
use crate::vcpu::ctrl::KSTACK_TOP;
use crate::vcpu::phys::PhysMem;
use crate::vcpu::{Exit, GuestMemory, Vcpu, VcpuError};
use iced_x86::Code;
use std::sync::Arc;

/// `RFLAGS` for fresh user code: just the always-one bit and IF (interrupts
/// are never injected, but a clear IF would make a guest `pushf` look odd).
const RFLAGS_USER: u64 = 0x202;
/// `IA32_FMASK`: `syscall` clears TF|IF|DF for the trampoline.
const FMASK_VALUE: u64 = 0x700;
/// `CR0`: PE|MP|ET|NE|WP|AM|PG — protected, paged, natural FPU error handling.
const CR0_LONG: u64 = 0x8005_0033;
/// `CR4`: PAE (long mode requires it) + OSFXSR|OSXMMEXCPT (SSE enabled) +
/// OSXSAVE (bit 18) so `xgetbv`/AVX state is usable — paired with `XCR0` set to
/// x87|SSE|AVX via `KVM_SET_XCRS`. Without OSXSAVE a runtime's AVX probe (which
/// checks OSXSAVE then `xgetbv`) reports AVX unavailable and may fall back to a
/// slower/rarer path.
// TSD (bit 2) makes CPL3 RDTSC/RDTSCP fault so they cannot expose the hardware clock.
const CR4_LONG: u64 = 0x620 | 0x4_0000 | (1 << 2);

/// `XCR0` value: enable x87 (bit 0), SSE (bit 1) and AVX (bit 2) xsave state.
const XCR0_AVX: u64 = 0x7;
/// `EFER`: SCE (`syscall`) | LME | LMA | **NXE** (bit 11) — NXE lets the page
/// tables' `NX` bit take effect, so non-executable pages actually fault.
const EFER_LONG: u64 = 0xD01;

#[allow(clippy::struct_excessive_bools)] // independent per-vcpu flags
pub struct KvmVcpu {
    initial_sregs: sys::kvm_sregs,
    vm: Arc<Vm>,
    fd: super::vm::Fd,
    /// Kernel-shared run page, mapped for the fd's lifetime.
    run: *mut sys::kvm_run,
    regs: sys::kvm_regs,
    regs_dirty: bool,
    sregs: sys::kvm_sregs,
    sregs_dirty: bool,
    /// Trapped in a syscall whose return value has not been written yet. A
    /// *blocked* syscall (kernel parks the task, sets no return) is retried
    /// by simply running the vcpu again — the interpreter re-executes the
    /// `syscall` instruction because its pc still points at it, but this vcpu
    /// is already past the trampoline's `hlt`, so "running" it would `sysretq`
    /// back to user code with a stale rax. Instead, while this flag is set,
    /// [`KvmVcpu::run`] re-delivers [`Exit::Syscall`] from the cached
    /// registers without entering the guest; [`KvmVcpu::set_syscall_ret`]
    /// (and `reset`) clear it.
    in_syscall: bool,
    /// Whether precision stepping injected TF into the current user frame.
    injected_tf: bool,
    guest_debug: Option<(u64, Option<u64>)>,
    pmu: pmu::Pmu,
    clock: Arc<crate::clock::VirtualClock>,
    observer: u64,
    /// Optional execution allowance supplied by a direct vCPU driver.
    execution_limit: Option<u64>,
    /// The `CR3` this vcpu's `sregs` currently name, so a context switch (execve
    /// installs fresh page tables; a forked child runs a different address space)
    /// is picked up as a single `KVM_SET_SREGS` before the next run. `None` until
    /// the first run sets it from the guest memory's `cr3()`.
    cur_cr3: Option<u64>,
    /// Set by [`Vcpu::flush_tlb`]: force a guest-TLB flush before the next run
    /// because the host edited this address space's page tables in place (a fork's
    /// copy-on-write downgrade of the parent) without the guest reloading cr3.
    tlb_flush_pending: bool,
    /// The shared physical pool, cached from the running `GuestMemory` so the
    /// fault path can read the pushed `#PF` exception frame lock-free (no
    /// `GuestMemory` borrow — the SMP path holds none). Set on the first run.
    phys: Option<Arc<PhysMem>>,
    /// Physical address of the running address space's private kernel-stack frame
    /// (see [`GuestMemory::kstack_pa`]): where this vcpu reads the exception frame
    /// the CPU pushed, so sibling vcpus faulting at once never read each other's.
    /// Refreshed from `mem` on every reconcile (it changes on execve/fork).
    kstack_pa: u64,
}

// The register caches and run page are noise in a debug dump; the fd
// identifies the vcpu.
#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for KvmVcpu {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KvmVcpu").field("fd", &self.fd).finish()
    }
}

// SAFETY: a `KvmVcpu` is owned and run by one thread at a time — the SMP
// scheduler hands each vcpu to a single worker for the duration of a run and
// only moves it between workers between runs (never issuing its ioctls
// concurrently), and KVM permits that migration. Distinct vcpus of one VM *do*
// run concurrently on different workers, which their per-vcpu fds and the
// shared VM's internally-serialized state (the `guest_slot` Mutex, atomic
// page-table stores) support. The raw `run` pointer is a per-vcpu mapping owned
// by this value.
unsafe impl Send for KvmVcpu {}

impl KvmVcpu {
    /// Create a vcpu for a fresh thread, entering user code at `entry` with
    /// stack `stack`. Returns a boxed trait object (a factory, not `Self`).
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        vm: Arc<Vm>,
        entry: u64,
        stack: u64,
        branch_quantum: u64,
    ) -> Result<Box<dyn Vcpu>, VcpuError> {
        let mut v = Self::create(vm, branch_quantum)?;
        v.regs = sys::kvm_regs {
            rip: entry,
            rsp: stack,
            rflags: RFLAGS_USER,
            ..Default::default()
        };
        v.regs_dirty = true;
        Ok(Box::new(v))
    }

    /// Create and fully configure a vcpu (CPUID, MSRs, long-mode sregs) with
    /// zeroed general registers; the caller sets rip/rsp.
    fn create(vm: Arc<Vm>, branch_quantum: u64) -> Result<Self, VcpuError> {
        let (fd, run) = vm.create_vcpu()?;

        // SAFETY: `fd` is a live vcpu fd; the cpuid2 struct is valid for the
        // call and the kernel only reads it.
        let ret = unsafe { sys::ioctl(fd.0, sys::KVM_SET_CPUID2, std::ptr::from_ref(vm.cpuid())) };
        check(ret, "KVM_SET_CPUID2")?;

        // The syscall trampoline wiring (see `super::vm`).
        let entries = [
            (sys::MSR_IA32_STAR, STAR_VALUE),
            (sys::MSR_IA32_LSTAR, LSTAR_VA),
            (sys::MSR_IA32_CSTAR, 0),
            (sys::MSR_IA32_FMASK, FMASK_VALUE),
            (sys::MSR_KERNEL_GS_BASE, 0),
        ];
        let mut msrs = sys::kvm_msrs {
            nmsrs: entries.len() as u32,
            ..Default::default()
        };
        for (i, (index, data)) in entries.into_iter().enumerate() {
            msrs.entries[i] = sys::kvm_msr_entry {
                index,
                reserved: 0,
                data,
            };
        }
        // SAFETY: `msrs` is a valid struct whose `nmsrs` bounds the entries.
        let ret = unsafe { sys::ioctl(fd.0, sys::KVM_SET_MSRS, std::ptr::from_ref(&msrs)) };
        // KVM_SET_MSRS returns the number of MSRs set; a short count is a failure.
        if check(ret, "KVM_SET_MSRS")? != entries.len() as i32 {
            return Err(VcpuError::Backend(
                "KVM_SET_MSRS set fewer MSRs than requested".into(),
            ));
        }

        // Start from the vcpu's current sregs (sane reset values for the
        // fields we keep, e.g. apic_base) and switch it into flat long mode.
        let mut sregs = sys::kvm_sregs::default();
        // SAFETY: valid out-pointer; the fd is live.
        let ret = unsafe { sys::ioctl(fd.0, sys::KVM_GET_SREGS, std::ptr::from_mut(&mut sregs)) };
        check(ret, "KVM_GET_SREGS")?;
        init_user_sregs(&mut sregs);

        // Enable AVX xsave state (XCR0 = x87|SSE|AVX). CR4.OSXSAVE is set in
        // sregs above; a CPL3 guest can't run `xsetbv`, so the host sets XCR0.
        let mut xcrs = sys::kvm_xcrs {
            nr_xcrs: 1,
            ..sys::kvm_xcrs::default()
        };
        xcrs.xcrs[0] = sys::kvm_xcr {
            xcr: 0,
            reserved: 0,
            value: XCR0_AVX,
        };
        // SAFETY: valid struct pointer; the fd is live.
        let ret = unsafe { sys::ioctl(fd.0, sys::KVM_SET_XCRS, std::ptr::from_ref(&xcrs)) };
        check(ret, "KVM_SET_XCRS")?;

        // Precision stepping owns KVM guest-debug state. Breakpoints need a
        // separate debugger integration before they can coexist with it.
        let ebp = std::env::var("NIXVM_EBP")
            .ok()
            .and_then(|s| u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok());
        let watchpoints: Vec<u64> = std::env::var("NIXVM_WATCHPOINT")
            .ok()
            .map(|s| {
                s.split(',')
                    .filter_map(|p| u64::from_str_radix(p.trim().trim_start_matches("0x"), 16).ok())
                    .take(4)
                    .collect()
            })
            .unwrap_or_default();
        if ebp.is_some() || !watchpoints.is_empty() {
            return Err(VcpuError::Backend(
                "PMU scheduling cannot share the guest debugger with breakpoints".into(),
            ));
        }
        let clock = vm.clock();
        let observer = clock.allocate_observer();
        let initial_sregs = sregs;
        let vcpu = Self {
            initial_sregs,
            vm,
            fd,
            run,
            regs: sys::kvm_regs::default(),
            regs_dirty: true,
            sregs,
            sregs_dirty: true,
            in_syscall: false,
            injected_tf: false,
            guest_debug: None,
            pmu: pmu::Pmu::new(branch_quantum),
            clock,
            observer,
            execution_limit: None,
            cur_cr3: None,
            tlb_flush_pending: false,
            phys: None,
            kstack_pa: 0,
        };
        // Reset all guest-visible floating point state when a pool slot changes
        // owner. The full host XSAVE buffer is zeroed by write_xsave.
        let mut state = vec![0; crate::vcpu::X86_XSAVE_SIZE];
        state[..2].copy_from_slice(&0x037fu16.to_le_bytes());
        state[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
        state[512..520].copy_from_slice(&3u64.to_le_bytes());
        vcpu.write_xsave(&state)?;
        Ok(vcpu)
    }

    /// Point the vcpu's `sregs.cr3` at `mem`'s address space if it isn't already —
    /// the per-process page-table switch. One `KVM_SET_SREGS` (deferred via the
    /// dirty flag) on a change, nothing on the common same-process run.
    fn sync_cr3(&mut self, mem: &GuestMemory) {
        let cr3 = mem.cr3();
        if self.cur_cr3 != Some(cr3) {
            self.sregs.cr3 = cr3;
            self.sregs_dirty = true;
            self.cur_cr3 = Some(cr3);
        }
        // Cache the pool handle (once) and this address space's private kstack
        // frame so the fault path reads the pushed exception frame from *this*
        // vcpu's kstack — never a sibling's — without a `GuestMemory` borrow.
        if self.phys.is_none() {
            self.phys = Some(mem.phys_arc());
        }
        self.kstack_pa = mem.kstack_pa();
    }

    /// Flush dirty caches to the vcpu, run it once, and refresh the caches.
    fn run_once(&mut self, target: Option<u64>) -> Result<(u32, bool), VcpuError> {
        if self.regs_dirty {
            // SAFETY: valid struct pointer; the fd is live.
            let ret =
                unsafe { sys::ioctl(self.fd.0, sys::KVM_SET_REGS, std::ptr::from_ref(&self.regs)) };
            check(ret, "KVM_SET_REGS")?;
            self.regs_dirty = false;
        }
        if self.tlb_flush_pending {
            // Force the guest TLB to be flushed before this run. KVM skips the
            // flush when `KVM_SET_SREGS` leaves cr3 unchanged, so first push a cr3
            // that differs only in an ignored bit (PCD, bit 4 — CR4.PCIDE is off,
            // so it does not select a page table), which KVM treats as a pgd
            // switch and flushes. The real cr3 is restored by the `sregs_dirty`
            // write below (also a change → flushed), and the run uses it.
            let real = self.sregs.cr3;
            self.sregs.cr3 = real ^ (1 << 4);
            // SAFETY: valid struct pointer; the fd is live.
            let ret = unsafe {
                sys::ioctl(
                    self.fd.0,
                    sys::KVM_SET_SREGS,
                    std::ptr::from_ref(&self.sregs),
                )
            };
            check(ret, "KVM_SET_SREGS")?;
            self.sregs.cr3 = real;
            self.sregs_dirty = true;
            self.tlb_flush_pending = false;
        }
        if self.sregs_dirty {
            // SAFETY: valid struct pointer; the fd is live.
            let ret = unsafe {
                sys::ioctl(
                    self.fd.0,
                    sys::KVM_SET_SREGS,
                    std::ptr::from_ref(&self.sregs),
                )
            };
            check(ret, "KVM_SET_SREGS")?;
            self.sregs_dirty = false;
        }

        let counter = pmu::Pmu::start(self.fd.0, target)?;
        let stepping = counter.stepping;
        let user = self.sregs.cs.selector == SEL_UCODE;
        let guest_tf = self.regs.rflags & 0x100;
        if user {
            self.injected_tf = stepping && self.regs.rflags & 0x100 == 0;
        }
        let instruction = if stepping && user {
            super::instruction::decode(self.sregs.cr3, self.phys.as_ref().unwrap(), self.regs.rip)
                .ok()
        } else {
            None
        };
        self.guest_debug = if let Some(instruction) =
            instruction.filter(|instruction| instruction.code() == Code::Int1)
        {
            Some((1, Some(instruction.next_ip())))
        } else if stepping && user && self.regs.rflags & 0x100 != 0 {
            Some((2, None))
        } else {
            None
        };
        let pushed_flags = instruction
            .filter(|instruction| matches!(instruction.code(), Code::Pushfq | Code::Pushfw))
            .map(|instruction| (instruction.next_ip(), self.regs.rflags & 0x100));
        // SAFETY: `KVM_RUN` takes no argument; the fd is live and not run
        // concurrently (see the `Send` note).
        let ret = unsafe { sys::ioctl(self.fd.0, sys::KVM_RUN, 0) };
        let run_error = (ret < 0).then(std::io::Error::last_os_error);
        let branches = self.pmu.finish(counter)?;
        self.clock.advance_execution(branches);
        if let Some(remaining) = &mut self.execution_limit {
            *remaining = remaining.saturating_sub(branches);
        }
        let interrupted = if let Some(err) = run_error {
            // EINTR/EAGAIN: a host signal broke us out of the guest.
            if !matches!(err.raw_os_error(), Some(4 | 11)) {
                return Err(VcpuError::Backend(format!("KVM_RUN failed: {err}")));
            }
            true
        } else {
            false
        };

        // Refresh both caches so accessors (and `fork`) see the true state.
        // SAFETY: valid out-pointers; the fd is live.
        let ret = unsafe {
            sys::ioctl(
                self.fd.0,
                sys::KVM_GET_REGS,
                std::ptr::from_mut(&mut self.regs),
            )
        };
        check(ret, "KVM_GET_REGS")?;
        // SAFETY: as above.
        let ret = unsafe {
            sys::ioctl(
                self.fd.0,
                sys::KVM_GET_SREGS,
                std::ptr::from_mut(&mut self.sregs),
            )
        };
        check(ret, "KVM_GET_SREGS")?;
        if stepping && user && self.sregs.cs.selector == SEL_UCODE {
            // Clearing KVM's debugger also clears hardware TF. Guest-owned TF
            // survives independently of that temporary debugger state.
            self.regs.rflags = (self.regs.rflags & !0x100) | guest_tf;
            self.regs_dirty = true;
        }

        if let Some((next, guest_tf)) = pushed_flags
            && self.regs.rip == next
            && self.sregs.cs.selector == SEL_UCODE
        {
            // PUSHF saves the injected hardware TF. Change only that bit
            // after successful retirement, including across a page boundary.
            let phys = self.phys.as_ref().unwrap();
            let address = self.regs.rsp.wrapping_add(1);
            let translation =
                crate::vcpu::pagetable::AddrSpace::translate_cr3(self.sregs.cr3, address, phys)
                    .filter(|entry| {
                        !entry.supervisor && entry.prot.contains(crate::vcpu::Prot::WRITE)
                    })
                    .ok_or_else(|| {
                        VcpuError::Backend("retired PUSHF has no writable stack".into())
                    })?;
            let mut byte = [0];
            phys.read(translation.paddr, &mut byte);
            byte[0] = (byte[0] & !1) | (guest_tf >> 8) as u8;
            phys.write(translation.paddr, &byte);
        }

        if interrupted {
            return Ok((sys::KVM_EXIT_INTR, stepping));
        }
        // SAFETY: the run page is a live mapping; the kernel just wrote the
        // exit reason for the KVM_RUN that returned.
        Ok((unsafe { (*self.run).exit_reason }, stepping))
    }

    /// Drive KVM through incidental traps until a kernel event or exact limit.
    fn run_loop(&mut self) -> Result<Exit, VcpuError> {
        loop {
            if self.clock.deadline_due() || self.execution_limit == Some(0) || self.pmu.finished() {
                return Ok(Exit::Interrupted);
            }
            let timer = self.clock.next_deadline().map(|deadline| {
                u64::try_from(deadline.saturating_sub(self.clock.now_monotonic().as_nanos()))
                    .unwrap_or(i64::MAX as u64)
                    .min(i64::MAX as u64)
            });
            let target = [timer, self.execution_limit, self.pmu.remaining()]
                .into_iter()
                .flatten()
                .min();
            if target.is_some_and(|target| target <= pmu::SKID)
                && self.sregs.cs.selector == SEL_UCODE
                && let Ok(instruction) = super::instruction::decode(
                    self.sregs.cr3,
                    self.phys.as_ref().unwrap(),
                    self.regs.rip,
                )
                && matches!(instruction.code(), Code::Popfq | Code::Popfw)
            {
                let tracing = self.regs.rflags & 0x100 != 0;
                if let Some(exit) = self.emulate_popf(instruction) {
                    return Ok(exit);
                }
                if tracing {
                    return Ok(Exit::Breakpoint {
                        pc: self.regs.rip,
                        code: 2,
                    });
                }
                continue;
            }
            let (reason, stepping) = self.run_once(target)?;
            if reason == sys::KVM_EXIT_DEBUG {
                if let Some((code, next)) = self.guest_debug {
                    if let Some(next) = next {
                        self.regs.rip = next;
                        self.regs_dirty = true;
                    }
                    return Ok(Exit::Breakpoint {
                        pc: self.regs.rip,
                        code,
                    });
                }
                // The precision tail remains inside this slice. Recalculate
                // its limit after charging actual retired branches.
                continue;
            }
            if reason == sys::KVM_EXIT_INTR {
                // Overflow is an early warning; an unrelated host interrupt
                // must not turn it into an inexact scheduling boundary.
                continue;
            }
            let Some(exit) = self.decode_exit(reason)? else {
                continue;
            };
            if exit == Exit::Syscall {
                if stepping && self.injected_tf {
                    // SYSCALL copies KVM's host single-step TF into R11. It is
                    // not guest state and must not survive the return to CPL3.
                    self.regs.r11 &= !0x100;
                    self.regs_dirty = true;
                }
                // Count actual guest entry once. A blocked syscall is delivered
                // again through in_syscall without running or ticking here.
                self.clock.advance_event();
                self.in_syscall = true;
            }
            return Ok(exit);
        }
    }

    /// POPF must not clear the hardware flag enforcing the precision tail.
    fn emulate_popf(&mut self, instruction: iced_x86::Instruction) -> Option<Exit> {
        let width = if instruction.code() == Code::Popfw {
            2
        } else {
            8
        };
        let phys = self.phys.as_ref().unwrap();
        let mut bytes = [0u8; 8];
        for (offset, byte) in bytes[..width].iter_mut().enumerate() {
            let address = self.regs.rsp.wrapping_add(offset as u64);
            if !crate::vcpu::pagetable::is_canonical(address) {
                return Some(Exit::ProtectionFault { pc: self.regs.rip });
            }
            let Some(entry) =
                crate::vcpu::pagetable::AddrSpace::translate_cr3(self.sregs.cr3, address, phys)
                    .filter(|entry| !entry.supervisor)
            else {
                return Some(Exit::MemFault {
                    addr: address,
                    write: false,
                });
            };
            phys.read(entry.paddr, std::slice::from_mut(byte));
        }
        // CPL3 may change status, TF, DF, NT, AC and ID; IF and IOPL stay fixed.
        let mask = if width == 2 { 0x4dd5 } else { 0x24_4dd5 };
        self.regs.rflags =
            ((self.regs.rflags & !mask) | (u64::from_le_bytes(bytes) & mask)) & !(1 << 16);
        self.regs.rsp = self.regs.rsp.wrapping_add(width as u64);
        self.regs.rip = instruction.next_ip();
        self.regs_dirty = true;
        None
    }

    /// Recover a CPL3 exception frame and restore the state exposed to the kernel.
    /// #PF and #GP push an error code; #UD pushes only RIP, CS, RFLAGS, RSP, SS.
    fn restore_exception(&mut self, error_code: bool) -> Result<u64, VcpuError> {
        let words = if error_code { 6 } else { 5 };
        let expected_sp = KSTACK_TOP - words * 8;
        if self.regs.rsp != expected_sp || self.sregs.cs.selector != crate::vcpu::ctrl::SEL_KCODE {
            return Err(VcpuError::Backend(
                "exception outside the user exception stack".into(),
            ));
        }
        let phys = self
            .phys
            .as_ref()
            .ok_or_else(|| VcpuError::Backend("missing exception stack".into()))?;
        let pa = self.kstack_pa + crate::vcpu::mem::PAGE_SIZE - words * 8;
        let offset = u64::from(error_code) * 8;
        let at = |i: u64| phys.read_u64(pa + offset + i * 8);
        if at(1) != u64::from(SEL_UCODE) || at(4) != u64::from(SEL_UDATA) {
            return Err(VcpuError::Backend(
                "exception did not originate in user mode".into(),
            ));
        }
        let err = if error_code { phys.read_u64(pa) } else { 0 };
        self.regs.rip = at(0);
        self.regs.rflags = at(2);
        if self.injected_tf {
            self.regs.rflags &= !0x100;
        }
        self.regs.rsp = at(3);
        self.regs_dirty = true;
        self.sregs.cs = user_cs();
        self.sregs.ss = user_ss();
        self.sregs_dirty = true;
        Ok(err)
    }

    /// `None` means an intercepted instruction completed; resume internally.
    fn decode_exit(&mut self, reason: u32) -> Result<Option<Exit>, VcpuError> {
        let exit = match reason {
            sys::KVM_EXIT_HLT if self.regs.rip == crate::vcpu::ctrl::DB_TRAMP_VA + 1 => {
                self.restore_exception(false)?;
                let mut debug = sys::kvm_debugregs::default();
                // SAFETY: live vCPU and initialized debug-register buffer.
                check(
                    unsafe { sys::ioctl(self.fd.0, sys::KVM_GET_DEBUGREGS, &raw mut debug) },
                    "KVM_GET_DEBUGREGS",
                )?;
                let code = if debug.dr6 & (1 << 14) == 0 { 1 } else { 2 };
                debug.dr6 = 0xffff_0ff0;
                // SAFETY: clear the consumed debug status on this same vCPU.
                check(
                    unsafe { sys::ioctl(self.fd.0, sys::KVM_SET_DEBUGREGS, &raw const debug) },
                    "KVM_SET_DEBUGREGS",
                )?;
                Exit::Breakpoint {
                    pc: self.regs.rip,
                    code,
                }
            }
            sys::KVM_EXIT_HLT if self.regs.rip == FAULT_TRAMP_VA + 1 => {
                let err = self.restore_exception(true)?;
                Exit::MemFault {
                    addr: self.sregs.cr2,
                    write: err & 2 != 0,
                }
            }
            sys::KVM_EXIT_HLT if self.regs.rip == GP_TRAMP_VA + 1 => {
                let err = self.restore_exception(true)?;
                if err == 0 {
                    let decoded = super::instruction::decode(
                        self.sregs.cr3,
                        self.phys
                            .as_ref()
                            .expect("exception recovery requires physical memory"),
                        self.regs.rip,
                    );
                    match decoded {
                        Ok(instruction)
                            if matches!(instruction.code(), Code::Rdtsc | Code::Rdtscp) =>
                        {
                            let tsc = self.clock.observe(self.observer).as_nanos() as u64;
                            self.regs.rax = u64::from(tsc as u32);
                            self.regs.rdx = tsc >> 32;
                            if instruction.code() == Code::Rdtscp {
                                // Fixed TSC_AUX: neither host CPU identity nor
                                // guest thread migration affects this value.
                                self.regs.rcx = 0;
                            }
                            self.regs.rip = instruction.next_ip();
                            // Fault delivery sets RF in the saved image. The
                            // emulated instruction completed, so consume RF.
                            self.regs.rflags &= !(1 << 16);
                            return Ok(None);
                        }
                        Err(exit) => return Ok(Some(exit)),
                        _ => {}
                    }
                }
                Exit::ProtectionFault { pc: self.regs.rip }
            }
            sys::KVM_EXIT_HLT if self.regs.rip == UD_TRAMP_VA + 1 => {
                self.restore_exception(false)?;
                Exit::IllegalInstruction { pc: self.regs.rip }
            }
            // SYSCALL enters CPL0; the next run resumes at SYSRETQ.
            sys::KVM_EXIT_HLT if self.regs.rip == LSTAR_VA + 1 => Exit::Syscall,
            sys::KVM_EXIT_MMIO => {
                // SAFETY: the union's `mmio` arm is the one the kernel wrote
                // for this exit reason; all fields are plain old data.
                let mmio = unsafe { (*self.run).exit.mmio };
                Exit::MemFault {
                    addr: mmio.phys_addr,
                    write: mmio.is_write != 0,
                }
            }
            // Exceptions without an IDT gate still escalate to a triple fault.
            sys::KVM_EXIT_SHUTDOWN => Exit::IllegalInstruction { pc: self.regs.rip },
            sys::KVM_EXIT_INTR => {
                // The address space's exception stack is shared by its threads.
                // Consume any live frame before yielding the memory lock to a
                // sibling. On the next slice, retry the original user instruction.
                let pc = self.regs.rip;
                // User RIP may name a trampoline before its supervisor-page
                // fetch faults; an interrupted CPL3 fetch has no frame to recover.
                if self.sregs.cs.selector == crate::vcpu::ctrl::SEL_KCODE {
                    if (FAULT_TRAMP_VA..=FAULT_TRAMP_VA + 1).contains(&pc)
                        || (GP_TRAMP_VA..=GP_TRAMP_VA + 1).contains(&pc)
                    {
                        self.restore_exception(true)?;
                    } else if (UD_TRAMP_VA..=UD_TRAMP_VA + 1).contains(&pc) {
                        self.restore_exception(false)?;
                    }
                }
                Exit::Interrupted
            }
            sys::KVM_EXIT_FAIL_ENTRY => {
                // SAFETY: as `mmio` — the arm matching the exit reason.
                let fail = unsafe { (*self.run).exit.fail_entry };
                return Err(VcpuError::Backend(format!(
                    "KVM_EXIT_FAIL_ENTRY (hardware reason {:#x})",
                    fail.hardware_entry_failure_reason
                )));
            }
            sys::KVM_EXIT_INTERNAL_ERROR => {
                // SAFETY: as `mmio` — the arm matching the exit reason.
                let internal = unsafe { (*self.run).exit.internal };
                return Err(VcpuError::Backend(format!(
                    "KVM_EXIT_INTERNAL_ERROR (suberror {})",
                    internal.suberror
                )));
            }
            other => {
                return Err(VcpuError::Backend(format!(
                    "unexpected KVM exit reason {other}"
                )));
            }
        };
        Ok(Some(exit))
    }

    /// Architectural x86 register index → cached `kvm_regs` field. The trait
    /// uses encoding order (rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8–r15),
    /// matching `interp_x86`; `kvm_regs` declares them in a different order.
    fn gpr(&self, idx: usize) -> u64 {
        let r = &self.regs;
        match idx {
            0 => r.rax,
            1 => r.rcx,
            2 => r.rdx,
            3 => r.rbx,
            4 => r.rsp,
            5 => r.rbp,
            6 => r.rsi,
            7 => r.rdi,
            8 => r.r8,
            9 => r.r9,
            10 => r.r10,
            11 => r.r11,
            12 => r.r12,
            13 => r.r13,
            14 => r.r14,
            15 => r.r15,
            _ => 0,
        }
    }

    fn set_gpr(&mut self, idx: usize, value: u64) {
        let r = &mut self.regs;
        match idx {
            0 => r.rax = value,
            1 => r.rcx = value,
            2 => r.rdx = value,
            3 => r.rbx = value,
            4 => r.rsp = value,
            5 => r.rbp = value,
            6 => r.rsi = value,
            7 => r.rdi = value,
            8 => r.r8 = value,
            9 => r.r9 = value,
            10 => r.r10 = value,
            11 => r.r11 = value,
            12 => r.r12 = value,
            13 => r.r13 = value,
            14 => r.r14 = value,
            15 => r.r15 = value,
            _ => return,
        }
        self.regs_dirty = true;
    }

    fn read_xsave(&self) -> Result<Vec<u8>, VcpuError> {
        let mut state = vec![0; self.vm.xsave_size()];
        // SAFETY: the writable buffer has the VM's reported XSAVE size. GET_XSAVE
        // is used only for the fixed-size legacy ABI; GET_XSAVE2 uses the full size.
        let ret = unsafe { sys::ioctl(self.fd.0, self.vm.xsave_get(), state.as_mut_ptr()) };
        check(ret, "KVM_GET_XSAVE")?;
        Ok(state)
    }

    fn write_xsave(&self, state: &[u8]) -> Result<(), VcpuError> {
        let mut buffer = vec![0; self.vm.xsave_size()];
        if state.len() > buffer.len() {
            return Err(VcpuError::Backend(
                "XSAVE state exceeds KVM buffer size".into(),
            ));
        }
        buffer[..state.len()].copy_from_slice(state);
        // SAFETY: SET_XSAVE reads the VM's full reported size. Unexposed state
        // components and reserved bytes outside the supplied image are zeroed.
        let ret = unsafe { sys::ioctl(self.fd.0, sys::KVM_SET_XSAVE, buffer.as_ptr()) };
        check(ret, "KVM_SET_XSAVE").map(drop)
    }
}

/// The flat 64-bit user code segment (CPL3).
fn user_cs() -> sys::kvm_segment {
    sys::kvm_segment {
        base: 0,
        limit: 0xFFFF_FFFF,
        selector: SEL_UCODE,
        type_: 0xB, // execute/read, accessed
        present: 1,
        dpl: 3,
        db: 0,
        s: 1,
        l: 1,
        g: 1,
        avl: 0,
        unusable: 0,
        padding: 0,
    }
}

/// The flat 64-bit user data segment (CPL3).
fn user_ss() -> sys::kvm_segment {
    sys::kvm_segment {
        limit: 0xFFFF_FFFF,
        selector: SEL_UDATA,
        type_: 0x3, // read/write, accessed
        dpl: 3,
        db: 1,
        l: 0,
        ..user_cs()
    }
}

/// Switch `sregs` into flat 64-bit user mode: the control block's GDT and
/// page tables, user code/data segments, long mode enabled. Everything not
/// set here (apic_base, interrupt_bitmap) keeps its current value.
fn init_user_sregs(sregs: &mut sys::kvm_sregs) {
    let code = user_cs();
    let data = user_ss();
    sregs.cs = code;
    sregs.ss = data;
    sregs.ds = data;
    sregs.es = data;
    sregs.fs = data;
    sregs.gs = data;
    // The real TSS (base = TSS_BASE, RSP0 set): the CPU switches to RSP0 on a
    // CPL3→CPL0 exception (a #PF vectoring through the IDT), where it pushes the
    // exception frame the host reads back.
    sregs.tr = sys::kvm_segment {
        base: super::vm::TSS_BASE,
        limit: 0x67,
        selector: super::vm::SEL_TSS,
        type_: 0xB, // busy 64-bit TSS
        present: 1,
        dpl: 0,
        db: 0,
        s: 0,
        l: 0,
        g: 0,
        avl: 0,
        unusable: 0,
        padding: 0,
    };
    sregs.ldt = sys::kvm_segment {
        unusable: 1,
        ..sys::kvm_segment::default()
    };
    sregs.gdt = sys::kvm_dtable {
        base: GDT_BASE,
        limit: GDT_LIMIT,
        padding: [0; 3],
    };
    // #PF, #GP and #UD gates preserve the user register state on the kernel stack.
    sregs.idt = sys::kvm_dtable {
        base: super::vm::IDT_BASE,
        limit: 0xFFF,
        padding: [0; 3],
    };
    sregs.cr0 = CR0_LONG;
    sregs.cr2 = 0;
    // cr3 is this process's real PML4, loaded per-run from the guest memory's
    // `cr3()` (see `sync_cr3`); a placeholder here, overwritten before the first
    // `KVM_RUN`.
    sregs.cr3 = 0;
    sregs.cr4 = CR4_LONG;
    sregs.efer = EFER_LONG;
}

impl Vcpu for KvmVcpu {
    fn run(&mut self, mem: &mut GuestMemory) -> Result<Exit, VcpuError> {
        // A trapped syscall whose return was never written is being retried
        // (it blocked) — re-deliver it without touching the guest.
        if self.in_syscall {
            return Ok(Exit::Syscall);
        }
        // Register the pool memslot (once) and point cr3 at this process's page
        // tables, then run under the caller's held memory lock.
        self.vm.ensure_memslot(mem)?;
        self.sync_cr3(mem);
        self.run_loop()
    }

    fn begin_slice(&mut self) {
        self.pmu.begin_slice();
    }

    fn set_preemption_required(&mut self, required: bool) {
        self.pmu.set_fairness(required);
    }

    fn set_clock(&mut self, clock: Arc<crate::clock::VirtualClock>, task: u64) {
        self.clock = clock;
        self.observer = task;
    }

    fn set_execution_limit(&mut self, limit: Option<u64>) {
        self.execution_limit = limit;
    }

    fn retired_branches(&self) -> Option<u64> {
        Some(self.pmu.total())
    }

    fn needs_locked_run(&self) -> bool {
        // KVM executes against the mapped memslot: `KVM_RUN` needs no Rust borrow
        // of GuestMemory, so the SMP scheduler runs it with the lock dropped.
        false
    }

    fn reconcile(&mut self, mem: &mut GuestMemory) -> Result<(), VcpuError> {
        // Re-delivering a blocked syscall: `run_bare` returns Syscall without a
        // KVM_RUN, so nothing to prepare.
        if self.in_syscall {
            return Ok(());
        }
        // The one memory-touching step before a lockless run: register the pool
        // memslot (once) and load this process's cr3. With one always-mapped
        // memslot and real per-process page tables there is nothing else to sync —
        // sibling vcpus of any address space run concurrently against the same slot.
        self.vm.ensure_memslot(mem)?;
        self.sync_cr3(mem);
        Ok(())
    }

    fn run_bare(&mut self) -> Result<Exit, VcpuError> {
        if self.in_syscall {
            return Ok(Exit::Syscall);
        }
        self.run_loop()
    }

    fn syscall_nr(&self) -> u64 {
        self.regs.rax
    }

    fn syscall_args(&self) -> [u64; 6] {
        [
            self.regs.rdi,
            self.regs.rsi,
            self.regs.rdx,
            self.regs.r10,
            self.regs.r8,
            self.regs.r9,
        ]
    }

    fn set_syscall_ret(&mut self, value: u64) {
        // Completion is explicit here. Normalize to CPL3 before precision
        // stepping: hardware SYSRETQ could restore R11 without the stepping TF
        // and let the next exact target run without any debug exit.
        if self.in_syscall {
            self.settle_syscall_return();
        }
        self.regs.rax = value;
        self.regs_dirty = true;
        self.in_syscall = false;
    }

    fn reg(&self, idx: usize) -> u64 {
        self.gpr(idx)
    }
    fn set_reg(&mut self, idx: usize, value: u64) {
        self.set_gpr(idx, value);
    }

    fn pc(&self) -> u64 {
        self.regs.rip
    }
    fn set_pc(&mut self, pc: u64) {
        self.regs.rip = pc;
        self.regs_dirty = true;
    }
    fn sp(&self) -> u64 {
        self.regs.rsp
    }
    fn set_sp(&mut self, sp: u64) {
        self.regs.rsp = sp;
        self.regs_dirty = true;
    }
    fn rflags(&self) -> u64 {
        self.regs.rflags
    }
    fn set_rflags(&mut self, value: u64) {
        // Force the always-set reserved bit and keep interrupts enabled at CPL3;
        // clearing IF or the reserved bit would make the vcpu unrunnable.
        self.regs.rflags = (value & 0x00dd_5dd5) | 0x0000_0202;
        self.regs_dirty = true;
    }

    fn set_tls(&mut self, value: u64) {
        self.sregs.fs.base = value;
        self.sregs_dirty = true;
    }

    fn simd_state(&self) -> Vec<u8> {
        let mut state = self.read_xsave().expect("read XSAVE state (signal)");
        state.truncate(crate::vcpu::X86_XSAVE_SIZE);
        state
    }

    fn set_simd_state(&mut self, bytes: &[u8]) {
        if bytes.len() < 512 {
            return;
        }
        // Match the interpreter's FXRSTOR contract: reserved MXCSR bits leave
        // state untouched. Guest signal frames cannot supply other components
        // or compacted-format/reserved XSAVE header fields to the host kernel.
        let mxcsr = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
        if mxcsr & !0xffff != 0 {
            return;
        }
        let mut state = vec![0; crate::vcpu::X86_XSAVE_SIZE];
        state[..512].copy_from_slice(&bytes[..512]);
        let components = if bytes.len() >= state.len() {
            state[576..].copy_from_slice(&bytes[576..crate::vcpu::X86_XSAVE_SIZE]);
            u64::from_le_bytes(bytes[512..520].try_into().unwrap()) & XCR0_AVX
        } else {
            3 // A bare FXSAVE image resets the upper YMM halves.
        };
        // XRSTOR restores MXCSR independently of the SSE/YMM presence bits.
        // KVM_SET_XSAVE initializes it when both are absent. Materialize the
        // initial XMM registers and mark SSE present so the supplied MXCSR survives.
        if components & 2 == 0 {
            state[160..416].fill(0);
        }
        state[512..520].copy_from_slice(&(components | 2).to_le_bytes());
        self.write_xsave(&state)
            .expect("restore XSAVE state (signal)");
    }

    fn fork(&self) -> Box<dyn Vcpu> {
        self.try_fork().expect("create KVM vcpu (fork)")
    }

    fn try_fork(&self) -> Result<Box<dyn Vcpu>, VcpuError> {
        // A sibling vcpu in the same VM, cloned from the cached (just
        // refreshed) register state — including the mid-trap CPL0 segment
        // state, so the child's resume path is identical to the parent's. The
        // child re-issues the guest slot for its own (forked) memory on its
        // first `run` via the backing-generation seam.
        let mut child = Self::create(self.vm.clone(), self.pmu.quantum())?;
        child.regs = self.regs;
        child.regs_dirty = true;
        child.sregs = self.sregs;
        child.sregs_dirty = true;
        child.in_syscall = self.in_syscall;
        child.clock = self.clock.clone();
        child.observer = self.clock.allocate_observer();
        // The child runs the *child's* address space (a different cr3); force a
        // re-sync on its first run rather than inheriting the parent's cached one.
        child.cur_cr3 = None;
        // XSAVE includes the upper YMM halves and the component presence bits
        // needed to restore the complete x87/SSE/AVX register file.
        let state = self.read_xsave()?;
        child.write_xsave(&state)?;
        Ok(Box::new(child))
    }

    fn reset(&mut self, entry: u64, sp: u64) {
        self.clock.reset_observations(self.observer);
        self.regs = sys::kvm_regs {
            rip: entry,
            rsp: sp,
            rflags: RFLAGS_USER,
            ..Default::default()
        };
        self.regs_dirty = true;
        // Back to flat user mode (an execve can land mid-trap, with the vcpu
        // still in the trampoline's CPL0 state) and clear TLS.
        init_user_sregs(&mut self.sregs);
        self.sregs.fs.base = 0;
        self.sregs_dirty = true;
        self.in_syscall = false;
        let mut state = vec![0; crate::vcpu::X86_XSAVE_SIZE];
        state[..2].copy_from_slice(&0x037fu16.to_le_bytes());
        state[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
        state[512..520].copy_from_slice(&3u64.to_le_bytes());
        self.write_xsave(&state)
            .expect("reset XSAVE state (execve)");
        // execve installed fresh page tables in the same GuestMemory: its `cr3()`
        // changed, so drop the cached value and re-sync on the next run.
        self.cur_cr3 = None;
    }

    fn vdso_calibration(&self) -> Option<crate::vcpu::VdsoCal> {
        // vDSO arithmetic cannot perform accelerated observations or hand off
        // at timers. Use syscalls to observe the shared clock through the kernel.
        None
    }

    fn settle_syscall_return(&mut self) {
        // Async signals can arrive at an ordinary user instruction boundary.
        // RCX/R11 then belong to the guest, not to a pending SYSRETQ.
        if self.sregs.cs.selector == SEL_UCODE {
            return;
        }
        // Software `sysretq`: what the trampoline's `sysretq` would have done to
        // return the guest from CPL0 to CPL3 — rip←rcx, rflags←r11, and the flat
        // user segments. Called when the host is about to redirect the guest away
        // from that pending `sysretq` (signal delivery / `rt_sigreturn`), so the
        // handler and the resumed user code run at CPL3 rather than supervisor.
        self.regs.rip = self.regs.rcx;
        self.regs.rflags = self.regs.r11;
        self.regs_dirty = true;
        self.sregs.cs = user_cs();
        self.sregs.ss = user_ss();
        self.sregs.ds = user_ss();
        self.sregs.es = user_ss();
        self.sregs_dirty = true;
        // The trampoline `sysretq` will not run; the syscall is logically done.
        self.in_syscall = false;
    }

    /// Precision tails and completed timestamp traps expose cached CPL3 state.
    /// Supervisor syscall scaffolding must finish before asynchronous delivery.
    fn async_signal_boundary(&self) -> bool {
        self.sregs.cs.selector == SEL_UCODE
            && self.sregs.ss.selector == SEL_UDATA
            && !self.in_syscall
    }

    fn flush_tlb(&mut self) {
        // Arm the cr3-reload dance in `run_once` (a plain same-cr3 `KVM_SET_SREGS`
        // does not flush), so a host-side page-table change (fork's parent CoW
        // downgrade) is seen by the vcpu instead of shadowed by a stale TLB entry.
        self.tlb_flush_pending = true;
    }
}

impl Drop for KvmVcpu {
    fn drop(&mut self) {
        if self.vm.recycle(self.fd.0, self.run, &self.initial_sregs) {
            self.fd.0 = -1;
            return;
        }
        // SAFETY: `run` is the live mapping created in `Vm::create_vcpu`,
        // unmapped exactly once here; the fd closes via its own Drop.
        unsafe { sys::munmap(self.run.cast(), self.vm.vcpu_mmap_size()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vcpu::ctrl::{KSTACK_TOP, SEL_KCODE};

    #[test]
    fn interrupted_exception_frames_are_recovered_before_yielding() {
        let vm = match Vm::new() {
            Ok(vm) => Arc::new(vm),
            Err(error) => {
                eprintln!("skipping KVM exception interruption test: {error}");
                return;
            }
        };
        let mem = GuestMemory::new(0x1_0000, 64 * 1024);
        let mut v = KvmVcpu::create(vm, 100_000).unwrap();
        v.sync_cr3(&mem);
        let phys = mem.phys_arc();
        // Model the register snapshot returned by an interrupted KVM_RUN.
        // The CPU has pushed the frame, but userspace has not consumed it.
        for (trampoline, error_code) in [
            (FAULT_TRAMP_VA, true),
            (FAULT_TRAMP_VA + 0x10, true),  // #GP
            (FAULT_TRAMP_VA + 0x20, false), // #UD
        ] {
            for past_hlt in [0, 1] {
                let mut frame = vec![
                    0x12345,
                    u64::from(SEL_UCODE),
                    0x1_0247,
                    0x18765,
                    u64::from(SEL_UDATA),
                ];
                if error_code {
                    frame.insert(0, 2);
                }
                let size = frame.len() as u64 * 8;
                for (index, value) in frame.into_iter().enumerate() {
                    phys.write(
                        v.kstack_pa + crate::vcpu::mem::PAGE_SIZE - size + index as u64 * 8,
                        &value.to_le_bytes(),
                    );
                }
                v.regs.rip = trampoline + past_hlt;
                v.regs.rsp = KSTACK_TOP - size;
                v.sregs.cs.selector = SEL_KCODE;
                v.sregs.cs.dpl = 0;
                v.decode_exit(sys::KVM_EXIT_INTR).unwrap();
                assert_eq!(v.regs.rip, 0x12345, "trampoline {trampoline:#x}+{past_hlt}");
                assert_eq!(v.regs.rsp, 0x18765);
                assert_eq!(v.regs.rflags, 0x1_0247);
                assert_eq!(v.sregs.cs.selector, SEL_UCODE);
                assert_eq!(v.sregs.ss.selector, SEL_UDATA);
                assert!(v.regs_dirty && v.sregs_dirty);
            }
        }
    }

    #[test]
    fn interrupted_user_pc_is_not_a_supervisor_exception_frame() {
        let vm = match Vm::new() {
            Ok(vm) => Arc::new(vm),
            Err(error) => {
                eprintln!("skipping KVM user interruption test: {error}");
                return;
            }
        };
        let mut v = KvmVcpu::create(vm, 100_000).unwrap();
        for trampoline in [FAULT_TRAMP_VA, FAULT_TRAMP_VA + 0x10, FAULT_TRAMP_VA + 0x20] {
            for past_hlt in [0, 1] {
                v.regs.rip = trampoline + past_hlt;
                v.regs.rsp = 0x18000;
                v.regs.rflags = 0x246;
                v.regs_dirty = false;
                v.sregs_dirty = false;
                v.decode_exit(sys::KVM_EXIT_INTR).unwrap();
                assert_eq!(v.regs.rip, trampoline + past_hlt);
                assert_eq!(v.regs.rsp, 0x18000);
                assert_eq!(v.regs.rflags, 0x246);
                assert_eq!(v.sregs.cs.selector, SEL_UCODE);
                assert!(!v.regs_dirty && !v.sregs_dirty);
            }
        }
    }
}
