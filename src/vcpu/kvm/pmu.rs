//! Guest-only conditional-branch counting and exact slice boundaries.
//!
//! Overflow is an early warning. Only single-stepped instruction boundaries
//! may finish an execution limit. A late interrupt is an error, including an interrupt
//! at the target count: uncounted instructions may already have run after it.

use super::{
    sys,
    vm::{Fd, check},
};
use crate::vcpu::VcpuError;
use std::cell::{Cell, RefCell};
use std::sync::OnceLock;

const SIGNAL: i32 = 41;
// Headroom, not a guarantee: overruns are detected and fail the run.
const SKID: u64 = 1024;
const DISABLE: u64 = 0x2401;
const RESET: u64 = 0x2403;
const PERIOD: u64 = 0x4008_2404;
const ENABLE: u64 = 0x2400;

fn error(message: impl Into<String>) -> VcpuError {
    VcpuError::Backend(format!("PMU: {}", message.into()))
}

pub(super) fn parse_quantum(value: &str) -> Result<u64, VcpuError> {
    value
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|&value| value > 0 && i64::try_from(value).is_ok())
        .ok_or_else(|| error("NIXVM_BRANCH_QUANTUM must be in 1..=i64::MAX"))
}

#[derive(Debug)]
struct Budget {
    quantum: u64,
    used: u64,
    total: u64,
}

impl Budget {
    fn remaining(&self) -> u64 {
        self.quantum.saturating_sub(self.used)
    }

    fn account(
        &mut self,
        branches: u64,
        stepping: bool,
        target: Option<u64>,
        fairness: bool,
    ) -> Result<(), VcpuError> {
        if target.is_some_and(|target| branches > target || (!stepping && branches == target)) {
            return Err(error(
                "overflow arrived too late for an exact branch boundary",
            ));
        }
        if stepping && branches > 1 {
            return Err(error(
                "single step retired more than one conditional branch",
            ));
        }
        self.total = self
            .total
            .checked_add(branches)
            .ok_or_else(|| error("total count overflow"))?;
        if fairness {
            self.used = self
                .used
                .checked_add(branches)
                .ok_or_else(|| error("count overflow"))?;
        }
        Ok(())
    }
}

/// Raw event selectors vary across Intel families and hybrid core types.
/// These profiles follow the event semantics documented in rr's PerfCounters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Profile {
    event: u64,
    event_type: u32,
}

impl Profile {
    fn select(
        vendor: &[u8; 12],
        family: u32,
        model: u32,
        core_type: u32,
        hybrid_cpu: bool,
    ) -> Result<Self, VcpuError> {
        if vendor != b"GenuineIntel" || family != 6 {
            return Err(error(
                "conditional-branch counting currently requires a supported Intel CPU",
            ));
        }
        let event = match model {
            0x1a | 0x1e | 0x1f | 0x2e | 0x25 | 0x2c | 0x2f | 0x2a | 0x2d | 0x3a | 0x3e | 0x3c
            | 0x3f | 0x45 | 0x46 | 0x3d | 0x47 | 0x4f | 0x56 | 0x4e | 0x5e | 0x55 | 0x8e | 0x9e
            | 0xa5 | 0xa6 => 0x01c4,
            0x6a | 0x6c | 0x7d | 0x7e | 0x8c | 0x8d | 0xa7 | 0x8f | 0xcf => 0x11c4,
            0x97 | 0x9a | 0xb7 | 0xba | 0xbf => match core_type {
                // P-core-only parts do not advertise CPUID's hybrid feature
                // and can return zero for the core-type leaf.
                0 if !hybrid_cpu => 0x11c4,
                0x40 => 0x11c4,
                0x20 => 0x7ec4,
                _ => return Err(error("unknown Intel hybrid core type")),
            },
            _ => return Err(error(format!("unsupported Intel CPU model {model:#x}"))),
        };
        Ok(Self {
            event,
            event_type: 4,
        })
    }

    fn hybrid_event_type(atom: bool) -> Result<u32, VcpuError> {
        static CORE: OnceLock<Result<u32, String>> = OnceLock::new();
        static ATOM: OnceLock<Result<u32, String>> = OnceLock::new();
        let cache = if atom { &ATOM } else { &CORE };
        cache
            .get_or_init(|| {
                let path = if atom {
                    "/sys/bus/event_source/devices/cpu_atom/type"
                } else {
                    "/sys/bus/event_source/devices/cpu_core/type"
                };
                match std::fs::read_to_string(path) {
                    Ok(value) => value
                        .trim()
                        .parse()
                        .map_err(|_| "invalid hybrid PMU type".into()),
                    // Some Alder Lake parts contain only performance cores and use
                    // the generic CPU PMU instead of registering hybrid PMUs.
                    Err(error) if !atom && error.kind() == std::io::ErrorKind::NotFound => Ok(4),
                    Err(error) => Err(format!("hybrid PMU unavailable: {error}")),
                }
            })
            .clone()
            .map_err(error)
    }

    fn detect() -> Result<Self, VcpuError> {
        // SAFETY: CPUID is available on x86-64. Affinity is fixed by the caller.
        let (identity, signature, hybrid, structured) = unsafe {
            (
                std::arch::x86_64::__cpuid(0),
                std::arch::x86_64::__cpuid(1),
                std::arch::x86_64::__cpuid(0x1a),
                std::arch::x86_64::__cpuid_count(7, 0),
            )
        };
        let mut vendor = [0u8; 12];
        vendor[..4].copy_from_slice(&identity.ebx.to_le_bytes());
        vendor[4..8].copy_from_slice(&identity.edx.to_le_bytes());
        vendor[8..].copy_from_slice(&identity.ecx.to_le_bytes());
        let family = (signature.eax >> 8) & 15;
        let model = ((signature.eax >> 4) & 15) | ((signature.eax >> 12) & 0xf0);
        let core_type = if identity.eax >= 0x1a {
            hybrid.eax >> 24
        } else {
            0
        };
        let hybrid_cpu = identity.eax >= 7 && structured.edx & (1 << 15) != 0;
        let mut profile = Self::select(&vendor, family, model, core_type, hybrid_cpu)?;
        // Hybrid PMUs have separate kernel type ids. PERF_TYPE_RAW alone can
        // select the wrong PMU on an efficiency core, even with CPU affinity.
        if matches!(core_type, 0x20 | 0x40) {
            profile.event_type = Self::hybrid_event_type(core_type == 0x20)?;
        }
        Ok(profile)
    }
}

/// PERF_ATTR_SIZE_VER0 from linux/perf_event.h. Later fields stay absent.
#[repr(C)]
#[derive(Default)]
struct EventAttr {
    event_type: u32,
    size: u32,
    config: u64,
    period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    breakpoint_type: u32,
    config1: u64,
}

impl EventAttr {
    fn new(profile: Profile) -> Self {
        Self {
            event_type: profile.event_type,
            size: 64,
            config: profile.event,
            period: i64::MAX as u64,
            read_format: 3, // TOTAL_TIME_ENABLED | TOTAL_TIME_RUNNING
            // disabled | pinned | exclude_kernel | exclude_hv | exclude_host.
            // Guest CPL3 only: host work and the syscall/fault scaffold do not count.
            flags: (1 << 0) | (1 << 2) | (1 << 5) | (1 << 6) | (1 << 19),
            wakeup_events: 1,
            ..Self::default()
        }
    }
}

extern "C" fn interrupt(_signal: i32) {}

fn install_handler() -> Result<(), VcpuError> {
    static INSTALLED: OnceLock<Result<(), String>> = OnceLock::new();
    INSTALLED
        .get_or_init(|| {
            let action = sys::sigaction {
                sa_handler: interrupt as *const () as usize,
                ..Default::default()
            };
            // SAFETY: a valid libc sigaction with an empty mask and no SA_RESTART.
            let result = unsafe { sys::sigaction(SIGNAL, &raw const action, std::ptr::null_mut()) };
            if result == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error().to_string())
            }
        })
        .clone()
        .map_err(error)
}

thread_local! {
    // One counter belongs to the host worker, while guest budgets belong to vCPUs.
    static WORKER: RefCell<Option<Counter>> = const { RefCell::new(None) };
    static PREPARED: Cell<bool> = const { Cell::new(false) };
}

struct HostScope {
    affinity: [u64; 16],
    mask: [u64; 16],
    restore: bool,
}

impl HostScope {
    fn acquire() -> Result<Self, VcpuError> {
        let mut scope = Self {
            affinity: [0; 16],
            mask: [0; 16],
            restore: false,
        };
        // SAFETY: a complete cpu_set_t and pid zero for this thread.
        check(
            unsafe { sys::sched_getaffinity(0, 128, &raw mut scope.affinity) },
            "PMU get affinity",
        )?;
        // SAFETY: no arguments.
        let cpu = check(unsafe { sys::sched_getcpu() }, "PMU current CPU")? as usize;
        if cpu >= 1024 {
            return Err(error("CPU id exceeds affinity mask"));
        }
        let mut pinned = [0u64; 16];
        pinned[cpu / 64] = 1 << (cpu % 64);
        // SAFETY: this CPU belongs to the caller's original mask.
        check(
            unsafe { sys::sched_setaffinity(0, 128, &raw const pinned) },
            "PMU pin CPU",
        )?;
        // First read the mask, so error cleanup can restore both resources.
        let result = unsafe { sys::pthread_sigmask(0, std::ptr::null(), &raw mut scope.mask) };
        if result != 0 {
            unsafe {
                sys::sched_setaffinity(0, 128, &raw const scope.affinity);
            }
            return Err(error(std::io::Error::from_raw_os_error(result).to_string()));
        }
        scope.restore = true;
        let mut blocked = [0u64; 16];
        blocked[0] = 1 << (SIGNAL - 1);
        // SAFETY: valid libc signal sets; SIG_BLOCK is zero.
        let result = unsafe { sys::pthread_sigmask(0, &raw const blocked, std::ptr::null_mut()) };
        if result != 0 {
            return Err(error(std::io::Error::from_raw_os_error(result).to_string()));
        }
        Ok(scope)
    }

    fn restore(&mut self) -> Result<(), VcpuError> {
        if !self.restore {
            return Ok(());
        }
        // SAFETY: restore this same thread's saved state; attempt both on error.
        let signal = unsafe { sys::pthread_sigmask(2, &raw const self.mask, std::ptr::null_mut()) };
        let affinity = unsafe { sys::sched_setaffinity(0, 128, &raw const self.affinity) };
        if signal != 0 {
            return Err(error(std::io::Error::from_raw_os_error(signal).to_string()));
        }
        check(affinity, "PMU restore affinity")?;
        self.restore = false;
        Ok(())
    }
}
impl Drop for HostScope {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

fn ensure_counter(mask: u64) -> Result<(), VcpuError> {
    let profile = Profile::detect()?;
    WORKER.with(|slot| {
        let mut counter = slot.borrow_mut();
        if counter
            .as_ref()
            .is_none_or(|counter| counter.profile != profile)
        {
            // SAFETY: gettid takes no arguments.
            *counter = Some(Counter::open(unsafe { sys::gettid() }, profile)?);
        }
        counter.as_mut().unwrap().guest_mask = mask & !(1 << (SIGNAL - 1));
        Ok(())
    })
}

pub(super) fn prepare_thread() -> Result<(), VcpuError> {
    if PREPARED.get() {
        return Ok(());
    }
    let mut scope = HostScope::acquire()?;
    ensure_counter(scope.mask[0])?;
    // Dedicated confined workers retain their pin and blocked overflow signal.
    // Every preparation error above restores the caller through HostScope.
    scope.restore = false;
    PREPARED.set(true);
    Ok(())
}

pub(super) fn worker_fd() -> Option<i32> {
    WORKER.with(|slot| slot.borrow().as_ref().map(|counter| counter.fd.0))
}

pub(super) fn clear_inactive_thread_resources() {
    // A previous unconfined VM may have populated the thread cache. Drop it
    // before inherited-FD cleanup can close and reuse its numeric descriptor.
    WORKER.with(|slot| {
        slot.borrow_mut().take();
    });
    PREPARED.set(false);
}

struct Counter {
    fd: Fd,
    profile: Profile,
    guest_mask: u64,
}

impl Counter {
    fn open(thread: i32, profile: Profile) -> Result<Self, VcpuError> {
        install_handler()?;
        let attributes = EventAttr::new(profile);
        // SAFETY: x86-64 __NR_perf_event_open=298, valid 64-byte attributes,
        // pid 0 means this thread, cpu/group -1, PERF_FLAG_FD_CLOEXEC=8.
        let raw = unsafe { sys::syscall(298, &attributes, 0i32, -1i32, -1i32, 8u64) };
        if raw < 0 {
            return Err(error(format!(
                "perf_event_open: {}",
                std::io::Error::last_os_error()
            )));
        }
        let fd = Fd(raw as i32);
        #[repr(C)]
        struct Owner {
            kind: i32,
            thread: i32,
        }
        let owner = Owner { kind: 0, thread }; // F_OWNER_TID
        // SAFETY: F_SETOWN_EX=15 consumes a valid f_owner_ex; remaining fcntls
        // take integer arguments. Every error closes the owned event descriptor.
        unsafe {
            check(sys::fcntl(fd.0, 15, &owner), "PMU F_SETOWN_EX")?;
            check(sys::fcntl(fd.0, 10, SIGNAL), "PMU F_SETSIG")?;
            check(sys::fcntl(fd.0, 4, 0x2000), "PMU O_ASYNC")?;
        }
        Ok(Self {
            fd,
            profile,
            guest_mask: 0,
        })
    }
}

pub(super) struct Pmu {
    fairness: bool,
    budget: Budget,
}

impl Pmu {
    pub fn new(quantum: u64) -> Self {
        Self {
            fairness: false,
            budget: Budget {
                quantum,
                used: 0,
                total: 0,
            },
        }
    }
    pub fn quantum(&self) -> u64 {
        self.budget.quantum
    }
    pub fn total(&self) -> u64 {
        self.budget.total
    }
    pub fn begin_slice(&mut self) {
        self.budget.used = 0;
    }
    pub fn set_fairness(&mut self, fairness: bool) {
        if fairness && !self.fairness {
            self.begin_slice();
        }
        self.fairness = fairness;
    }
    pub fn remaining(&self) -> Option<u64> {
        self.fairness.then(|| self.budget.remaining())
    }
    pub fn finished(&self) -> bool {
        self.remaining() == Some(0)
    }

    /// Count every run; optional targets add exact virtual-time boundaries.
    pub fn start(vcpu: i32, target: Option<u64>) -> Result<RunGuard, VcpuError> {
        let host = if PREPARED.get() {
            None
        } else {
            let scope = HostScope::acquire()?;
            ensure_counter(scope.mask[0])?;
            Some(scope)
        };
        let (counter, guest_mask) = WORKER.with(|slot| {
            let counter = slot.borrow();
            let counter = counter.as_ref().unwrap();
            (counter.fd.0, counter.guest_mask)
        });
        let stepping = target.is_some_and(|target| target <= SKID);
        let guard = RunGuard {
            counter,
            vcpu,
            stepping,
            host,
            target,
        };
        // Overflow stays blocked on the host, and KVM unblocks it only in guest.
        let mask = sys::kvm_signal_mask {
            len: 8,
            mask: guest_mask.to_ne_bytes(),
        };
        let debug = sys::kvm_guest_debug {
            control: if stepping {
                sys::KVM_GUESTDBG_ENABLE | sys::KVM_GUESTDBG_SINGLESTEP | sys::KVM_GUESTDBG_BLOCKIRQ
            } else {
                0
            },
            ..Default::default()
        };
        let period = match target {
            Some(target) if !stepping => target - SKID,
            _ => i64::MAX as u64,
        };
        // SAFETY: owned event and vcpu descriptors; all ioctl pointers have the
        // layouts specified by linux/perf_event.h and linux/kvm.h.
        unsafe {
            check(
                sys::ioctl(vcpu, sys::KVM_SET_SIGNAL_MASK, &mask),
                "PMU KVM signal mask",
            )?;
            check(
                sys::ioctl(vcpu, sys::KVM_SET_GUEST_DEBUG, &debug),
                "PMU single step",
            )?;
            check(sys::ioctl(counter, DISABLE, 0), "PMU disable")?;
            check(sys::ioctl(counter, RESET, 0), "PMU reset")?;
            check(sys::ioctl(counter, PERIOD, &period), "PMU period")?;
            check(sys::ioctl(counter, ENABLE, 0), "PMU enable")?;
        }
        Ok(guard)
    }

    pub fn finish(&mut self, mut guard: RunGuard) -> Result<u64, VcpuError> {
        // SAFETY: the guard keeps the descriptor live and the CPU pinned.
        check(
            unsafe { sys::ioctl(guard.counter, DISABLE, 0) },
            "PMU disable",
        )?;
        let mut sample = [0u64; 3];
        // SAFETY: writable 24-byte buffer matching read_format.
        let size = unsafe { sys::read(guard.counter, sample.as_mut_ptr().cast(), 24) };
        if size != 24 {
            return Err(error("counter unavailable or read failed"));
        }
        if sample[1] == 0 || sample[2] != sample[1] {
            return Err(error("counter was not continuously scheduled"));
        }
        let result = self
            .budget
            .account(sample[0], guard.stepping, guard.target, self.fairness);
        let debug = sys::kvm_guest_debug::default();
        // SAFETY: the live guard owns the vcpu's temporary debugger state.
        check(
            unsafe { sys::ioctl(guard.vcpu, sys::KVM_SET_GUEST_DEBUG, &debug) },
            "PMU clear single step",
        )?;
        if let Some(host) = guard.host.as_mut() {
            host.restore()?;
        }
        drop(guard);
        result.map(|()| sample[0])
    }
}

/// Owns temporary vCPU debugger state, including error paths.
pub(super) struct RunGuard {
    counter: i32,
    vcpu: i32,
    pub stepping: bool,
    host: Option<HostScope>,
    target: Option<u64>,
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        let debug = sys::kvm_guest_debug::default();
        // SAFETY: descriptors outlive the guard. Disable before restoring the
        // host signal mask, so any pending signal is harmless outside KVM_RUN.
        unsafe {
            sys::ioctl(self.counter, DISABLE, 0);
            sys::ioctl(self.vcpu, sys::KVM_SET_GUEST_DEBUG, &debug);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_guard_drains_pending_overflows_without_consuming_other_signals() {
        // Keep the test's blocked signals on a dedicated thread. Its pending
        // signals disappear when it exits, including if an assertion fails.
        std::thread::spawn(|| {
            // SAFETY: valid signal sets; pthread_kill targets this same thread.
            unsafe {
                let mut blocked: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&raw mut blocked);
                libc::sigaddset(&raw mut blocked, SIGNAL);
                libc::sigaddset(&raw mut blocked, libc::SIGUSR1);
                assert_eq!(
                    libc::pthread_sigmask(
                        libc::SIG_BLOCK,
                        &raw const blocked,
                        std::ptr::null_mut()
                    ),
                    0
                );
                assert_eq!(libc::pthread_kill(libc::pthread_self(), libc::SIGUSR1), 0);
                for _ in 0..3 {
                    assert_eq!(libc::pthread_kill(libc::pthread_self(), SIGNAL), 0);
                }
                // No perf or KVM device is needed to exercise guard cleanup.
                drop(RunGuard {
                    counter: -1,
                    vcpu: -1,
                    stepping: false,
                    host: None,
                    target: None,
                });
                let mut pending: libc::sigset_t = std::mem::zeroed();
                assert_eq!(libc::sigpending(&raw mut pending), 0);
                assert_eq!(libc::sigismember(&raw const pending, SIGNAL), 0);
                assert_eq!(libc::sigismember(&raw const pending, libc::SIGUSR1), 1);
                let mut mask: libc::sigset_t = std::mem::zeroed();
                assert_eq!(
                    libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &raw mut mask),
                    0
                );
                assert_eq!(libc::sigismember(&raw const mask, SIGNAL), 1);
            }
        })
        .join()
        .unwrap();
    }

    #[test]
    fn solo_execution_counts_without_consuming_fairness_budget() {
        let mut pmu = Pmu::new(8);
        pmu.budget.account(100, false, None, false).unwrap();
        assert_eq!(pmu.total(), 100);
        assert_eq!(pmu.remaining(), None);
        pmu.set_fairness(true);
        assert_eq!(pmu.remaining(), Some(8));
        pmu.budget.account(7, false, Some(8), true).unwrap();
        pmu.budget.account(1, true, Some(1), true).unwrap();
        assert!(pmu.finished());
        pmu.set_fairness(false);
        pmu.budget.account(100, false, None, false).unwrap();
        assert!(!pmu.finished());
        assert_eq!(pmu.total(), 208);
        pmu.set_fairness(true);
        assert_eq!(pmu.remaining(), Some(8));
    }

    #[test]
    fn rejects_invalid_quantum() {
        for value in ["", "0", "-1", "1.5", "9223372036854775808", "garbage"] {
            assert!(parse_quantum(value).is_err(), "{value}");
        }
        assert_eq!(parse_quantum(" 4000 ").unwrap(), 4000);
    }

    #[test]
    fn budget_survives_exits_and_resets_only_at_dispatch() {
        let mut budget = Budget {
            quantum: 5000,
            used: 0,
            total: 0,
        };
        budget.account(2000, false, Some(5000), true).unwrap(); // syscall
        budget.account(0, false, Some(3000), true).unwrap(); // unrelated host interrupt
        budget.account(2999, false, Some(3000), true).unwrap();
        assert_eq!(budget.remaining(), 1);
        budget.account(1, true, Some(1), true).unwrap();
        assert_eq!(budget.remaining(), 0);
        budget.used = 0;
        assert_eq!(budget.remaining(), 5000);
        assert_eq!(budget.total, 5000);
    }

    #[test]
    fn rejects_late_overflow_even_at_equal_count() {
        for count in [5000, 5001] {
            let mut budget = Budget {
                quantum: 5000,
                used: 0,
                total: 0,
            };
            assert!(budget.account(count, false, Some(5000), true).is_err());
        }
        let mut budget = Budget {
            quantum: 5000,
            used: 4999,
            total: 4999,
        };
        assert!(budget.account(2, true, Some(1), true).is_err());
    }

    #[test]
    fn selects_events_for_core_generations_and_rejects_unknown_hardware() {
        for (model, core, event) in [
            (0x5e, 0, 0x1c4),
            (0x7e, 0, 0x11c4),
            (0x97, 0x40, 0x11c4),
            (0x97, 0x20, 0x7ec4),
        ] {
            assert_eq!(
                Profile::select(b"GenuineIntel", 6, model, core, core != 0)
                    .unwrap()
                    .event,
                event
            );
        }
        assert!(Profile::select(b"AuthenticAMD", 0x19, 0, 0, false).is_err());
        assert!(Profile::select(b"GenuineIntel", 6, 0xff, 0, false).is_err());
        assert!(Profile::select(b"GenuineIntel", 6, 0x97, 0, true).is_err());
    }

    #[test]
    fn homogeneous_alder_lake_does_not_require_a_hybrid_core_type() {
        let profile = Profile::select(b"GenuineIntel", 6, 0x97, 0, false).unwrap();
        assert_eq!(profile.event, 0x11c4);
    }

    #[test]
    fn event_abi_is_pinned_guest_userspace_only() {
        let attributes = EventAttr::new(Profile {
            event: 0x1c4,
            event_type: 4,
        });
        assert_eq!(std::mem::size_of::<EventAttr>(), 64);
        assert_eq!(attributes.flags, 0x8_0065);
        assert_eq!(attributes.read_format, 3);
        let hybrid = EventAttr::new(Profile {
            event: 0x7ec4,
            event_type: 17,
        });
        assert_eq!(hybrid.event_type, 17);
        assert_eq!(hybrid.config, 0x7ec4);
        assert_eq!(std::mem::offset_of!(EventAttr, flags), 40);
    }
}
