//! Execution backends: run guest code until it needs the kernel.
//!
//! nixvm never emulates devices or interrupts. Each backend runs guest
//! instructions at the lowest privilege it can (EL0/ring 3) and hands control
//! back the moment the guest makes a syscall (or faults). The kernel services
//! the request, writes the return value into guest registers, and calls
//! [`Vcpu::run`] again.
//!
//! Three backends implement one [`Vcpu`] trait:
//!
//! * **hvf** — Hypervisor.framework, macOS/arm64. (Phase 1)
//! * **kvm** — KVM, Linux/arm64 and Linux/x86-64. (Phase 10)
//! * **interp** — a software CPU, works everywhere with no acceleration. (Phase 10)
//!
//! The kernel is written against the trait and never names a concrete backend;
//! [`select`] picks the best available one for the host + guest arch.

use crate::abi::Arch;
use crate::clock::VirtualClock;
use std::sync::Arc;

pub(crate) mod cpuid;
pub(crate) mod ctrl;
pub mod mem;
pub(crate) mod pagetable;
pub(crate) mod phys;
pub(crate) mod region;
pub(crate) mod vdso;

pub use mem::{GuestMemory, MemError, Prot};

/// Measured KVM execution cannot use a host-time scheduling boundary.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(crate) fn validate_branch_watchdog() -> Result<(), VcpuError> {
    if std::env::var_os("NIXVM_QUANTUM_MS")
        .is_some_and(|value| value.to_str().map(str::trim) != Some("0"))
    {
        return Err(VcpuError::Backend("host watchdog is incompatible with branch counting; unset NIXVM_QUANTUM_MS or set it to 0".into()));
    }
    Ok(())
}

thread_local! {
    /// When this thread's embedder wants control back (monotonic ns; 0 = no
    /// deadline). Set by [`crate::kernel::Kernel::pump_for`] so a single-
    /// threaded embedder (the browser tab) gets its event loop back while the
    /// guest is still computing.
    static YIELD_AT_NS: std::cell::Cell<u128> = const { std::cell::Cell::new(0) };
}

/// Ask this thread's running vcpu to hand control back once the monotonic
/// clock passes `at` (`None` clears it).
pub(crate) fn set_yield_deadline(at: Option<std::time::Duration>) {
    YIELD_AT_NS.with(|c| c.set(at.map_or(0, |d| d.as_nanos().max(1))));
}

/// Whether this thread's yield deadline (if any) has passed. Interpreters
/// poll it every few thousand instructions and return [`Exit::Interrupted`].
pub(crate) fn yield_due() -> bool {
    let at = YIELD_AT_NS.with(std::cell::Cell::get);
    at != 0 && crate::clock::host_monotonic().as_nanos() >= at
}

/// Interpreter-side execution accounting, batched until an observable boundary.
/// The cached deadline is decremented per execution unit, so checking it in an
/// instruction loop does not require locking the shared clock on every step.
#[derive(Clone)]
pub(crate) struct ExecutionClock {
    clock: Arc<VirtualClock>,
    task: u64,
    pending: u64,
    total: u64,
    slice_used: u64,
    quantum: u64,
    preempt: bool,
    limit: Option<u64>,
    until_deadline: Option<u128>,
    syscall_pc: Option<u64>,
}

impl ExecutionClock {
    pub(crate) fn new() -> Self {
        let clock = Arc::new(VirtualClock::new());
        let task = clock.allocate_observer();
        Self {
            clock,
            task,
            pending: 0,
            total: 0,
            slice_used: 0,
            quantum: std::env::var("NIXVM_BRANCH_QUANTUM")
                .ok()
                .and_then(|value| value.trim().parse().ok())
                .filter(|&value| value > 0)
                .unwrap_or(100_000),
            preempt: true,
            limit: None,
            until_deadline: None,
            syscall_pc: None,
        }
    }

    pub(crate) fn bind(&mut self, clock: Arc<VirtualClock>, task: u64) {
        self.flush();
        self.clock = clock;
        self.task = task;
        self.refresh_deadline();
    }

    pub(crate) fn enter(&mut self) {
        self.refresh_deadline();
    }

    fn refresh_deadline(&mut self) {
        self.until_deadline = self
            .clock
            .next_deadline()
            .map(|deadline| deadline.saturating_sub(self.clock.now_monotonic().as_nanos()));
    }

    pub(crate) fn exhausted(&self) -> bool {
        self.until_deadline == Some(0)
            || self.limit == Some(0)
            || (self.preempt && self.slice_used >= self.quantum)
    }

    pub(crate) fn account(&mut self) {
        self.pending = self.pending.saturating_add(1);
        self.total = self.total.saturating_add(1);
        if self.preempt {
            self.slice_used = self.slice_used.saturating_add(1);
        }
        self.limit = self.limit.map(|remaining| remaining.saturating_sub(1));
        self.until_deadline = self
            .until_deadline
            .map(|remaining| remaining.saturating_sub(1));
    }

    pub(crate) fn flush(&mut self) {
        if self.pending != 0 {
            self.clock.advance_execution(self.pending);
            self.pending = 0;
        }
    }

    pub(crate) fn observe(&mut self) -> u64 {
        self.flush();
        let timestamp = self.clock.observe(self.task).as_nanos() as u64;
        self.refresh_deadline();
        timestamp
    }

    pub(crate) fn syscall(&mut self, pc: u64) {
        self.flush();
        if self.syscall_pc != Some(pc) {
            self.clock.advance_event();
            self.syscall_pc = Some(pc);
        }
        self.refresh_deadline();
    }

    pub(crate) fn complete_syscall(&mut self) {
        self.syscall_pc = None;
    }

    pub(crate) fn reset_observations(&self) {
        self.clock.reset_observations(self.task);
    }

    pub(crate) fn begin_slice(&mut self) {
        self.slice_used = 0;
    }

    pub(crate) fn set_preemption_required(&mut self, required: bool) {
        if required && !self.preempt {
            self.slice_used = 0;
        }
        self.preempt = required;
    }

    pub(crate) fn set_limit(&mut self, remaining: Option<u64>) {
        self.limit = remaining;
    }

    pub(crate) fn total(&self) -> u64 {
        self.total
    }

    pub(crate) fn fork(&self) -> Self {
        let mut child = self.clone();
        child.pending = 0;
        child.task = self.clock.allocate_observer();
        child.slice_used = 0;
        child.syscall_pc = None;
        child
    }
}

/// Size of the x86-64 `XSAVE` area [`Vcpu::simd_state`] uses (x87, SSE and
/// AVX components, standard format: `CPUID.(EAX=0xD,ECX=0).EBX`).
pub const X86_XSAVE_SIZE: usize = 0x340;

/// Why [`Vcpu::run`] returned control to the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// The guest executed a syscall instruction (`svc #0` / `syscall`). Read the
    /// number/args via the `syscall_*` accessors, service it, write the result
    /// with [`Vcpu::set_syscall_ret`], then run again.
    Syscall,
    /// The guest hit an unmapped/forbidden address.
    MemFault { addr: u64, write: bool },
    /// The guest executed an illegal/undefined instruction.
    IllegalInstruction { pc: u64 },
    /// The guest executed a software breakpoint: arm64 `BRK #imm` (`code` =
    /// the 16-bit immediate) or x86 `int3` (`code` = 0). Linux answers with
    /// `SIGTRAP` (`TRAP_BRKPT` on arm64, `SI_KERNEL` on x86-64) and leaves
    /// the pc on the arm64 `BRK` (after the x86 `int3`).
    Breakpoint { pc: u64, code: u64 },
    /// An alignment fault: a misaligned SP-based access or PC (arm64's SP/PC
    /// alignment checks), or an atomic/ordered access crossing its
    /// single-copy-atomicity granule. Linux answers with `SIGBUS`
    /// (`BUS_ADRALN`, `si_addr` = `addr`), not `SIGSEGV`.
    Misaligned { addr: u64, write: bool },
    /// An arithmetic exception at the instruction at `pc` — x86 `#DE`
    /// (`vector` 0), x87 `#MF` (16), SIMD `#XM` (19) — that Linux delivers as
    /// `SIGFPE` with `si_code` = `code` (`FPE_INTDIV`, `FPE_FLTDIV`, …, as the
    /// backend derived it from the unmasked status/`MXCSR` bits).
    ArithmeticFault { pc: u64, code: u64, vector: u64 },
    /// x86 `#GP` (a privileged instruction at CPL 3, a misaligned `MOVAPS`,
    /// reserved `MXCSR` bits, …) at `pc`: Linux's `SIGSEGV` with `SI_KERNEL`
    /// and no address.
    ProtectionFault { pc: u64 },
    /// The host asked the vcpu to stop (another thread wants to run, or a
    /// deadline/signal fired). The kernel decides what to do next.
    Interrupted,
    /// The guest halted the whole machine (shouldn't happen for a userspace
    /// guest; treated as a fault).
    Halt,
}

/// Backend-level failure (never a guest-visible errno — those don't surface here).
#[derive(Debug)]
pub enum VcpuError {
    /// No backend supports this host/guest combination.
    Unsupported {
        host: &'static str,
        guest: Arch,
    },
    /// The hypervisor rejected an operation.
    Backend(String),
    Mem(MemError),
}

impl core::fmt::Display for VcpuError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unsupported { host, guest } => {
                write!(
                    f,
                    "no vcpu backend for host {host} + guest {}",
                    guest.as_str()
                )
            }
            Self::Backend(m) => write!(f, "vcpu backend error: {m}"),
            Self::Mem(e) => write!(f, "guest memory error: {e:?}"),
        }
    }
}

impl std::error::Error for VcpuError {}

impl From<MemError> for VcpuError {
    fn from(e: MemError) -> Self {
        Self::Mem(e)
    }
}

/// vDSO clock calibration produced by [`Vcpu::vdso_calibration`] and written to
/// the guest's vvar page by `ctrl::write_vvar`. The guest's
/// `__vdso_clock_gettime` computes `base_*_ns + ((rdtsc() - base_tsc) * mult) >>
/// shift`.
#[derive(Clone, Copy, Debug)]
pub struct VdsoCal {
    pub mult: u64,
    pub shift: u64,
    pub base_tsc: u64,
    pub base_mono_ns: u64,
    pub base_wall_ns: u64,
}

/// A single virtual CPU executing one guest thread.
///
/// The kernel owns one `Vcpu` per running guest thread and drives it with a
/// run/serve loop. Register accessors are expressed in the guest's *syscall
/// ABI* so the kernel never needs to know which backend or arch is underneath.
pub trait Vcpu: Send {
    /// Run guest code until the next [`Exit`].
    ///
    /// `mem` is the guest address space. The software interpreter reads and
    /// writes it directly as it executes; hardware backends map it into the
    /// hypervisor (once) and the guest writes through to the same buffer.
    fn run(&mut self, mem: &mut GuestMemory) -> Result<Exit, VcpuError>;

    /// Bind this task to its VM's clock. Timestamp instructions and syscall
    /// observations use the same task identity, including after fork and exec.
    fn set_clock(&mut self, _clock: Arc<VirtualClock>, _task: u64) {}

    /// Set an additional execution-unit limit, independent of the scheduling
    /// quantum. It survives incidental exits and is cleared by passing `None`.
    /// A zero limit returns to the kernel before another instruction executes.
    fn set_execution_limit(&mut self, _remaining: Option<u64>) {}

    /// Start a scheduler slice. Precise backends keep its budget across syscalls
    /// and memory faults, resetting it only when the scheduler dispatches anew.
    fn begin_slice(&mut self) {}

    /// Whether another task needs a bounded share of execution. Backends count
    /// solo execution too; this only enables the fairness limit. The scheduler
    /// updates it before guest entry, including after syscalls and wakeups.
    /// Direct vCPU drivers supply their own runnable-task policy.
    fn set_preemption_required(&mut self, _required: bool) {}

    /// Conditional branches counted during all execution, including solo runs.
    /// The scheduler uses differences for ordering instead of host elapsed time.
    fn retired_branches(&self) -> Option<u64> {
        None
    }

    /// Execution units retired by this vCPU, excluding idle jumps, clock
    /// observation costs and syscall-entry costs. Unlike the shared clock's
    /// total, differences are safe for task CPU accounting during SMP runs.
    /// The unit is one virtual nanosecond; its execution metric is backend-specific.
    fn execution_ticks(&self) -> Option<u64> {
        self.retired_branches()
    }

    /// Whether [`Vcpu::run`] must hold the `GuestMemory` lock for its whole
    /// duration. The software interpreter reads and writes guest memory *through*
    /// the `GuestMemory` struct as it executes, so it genuinely needs the lock the
    /// entire time — `true`. Hardware backends (KVM) execute against a memory slot
    /// the hypervisor maps once; guest loads/stores go straight to the shared
    /// backing with no Rust borrow, so the SMP scheduler can [`Vcpu::reconcile`]
    /// under the lock, drop it, and then run the guest in parallel with siblings
    /// of the same address space — `false`.
    fn needs_locked_run(&self) -> bool {
        true
    }

    /// Prepare the backend's view of `mem` for a subsequent lockless
    /// [`Vcpu::run_bare`] (the SMP path). Hardware backends sync their memory
    /// slots and shadow page tables here — the one step that must see `mem` — so
    /// that `run_bare` needs no `GuestMemory` borrow. A no-op for backends whose
    /// `needs_locked_run` is `true` (the interpreter), which are never split this
    /// way.
    fn reconcile(&mut self, _mem: &mut GuestMemory) -> Result<(), VcpuError> {
        Ok(())
    }

    /// Run guest code after a prior [`Vcpu::reconcile`], without a `GuestMemory`
    /// borrow — the lockless half of the SMP split. Only called on backends whose
    /// [`Vcpu::needs_locked_run`] is `false`; the default panics so a mis-paired
    /// backend fails loudly instead of silently running unreconciled.
    fn run_bare(&mut self) -> Result<Exit, VcpuError> {
        unreachable!("run_bare on a backend that requires a locked run")
    }

    /// Whether a memory fault at `addr` is only a *stale shadow* fault: the page
    /// is mapped/accessible in `mem`, but this backend's page tables — synced at
    /// the vcpu's last dispatch — do not yet reflect a mapping change a sibling
    /// made mid-run. The SMP scheduler retries such a fault (re-dispatch
    /// reconciles the tables) rather than turning it into a signal. Always `false`
    /// for backends without lazily-synced shadow tables (the interpreter, which
    /// consults `mem` directly, and serial KVM, which reconciles before every run).
    fn shadow_stale(&self, _mem: &GuestMemory, _addr: u64) -> bool {
        false
    }

    /// The syscall number the guest requested (arm64 `x8` / x86-64 `rax`).
    fn syscall_nr(&self) -> u64;

    /// The six syscall argument registers, in ABI order.
    fn syscall_args(&self) -> [u64; 6];

    /// Write the syscall return value into the ABI return register and advance
    /// the program counter past the syscall instruction.
    fn set_syscall_ret(&mut self, value: u64);

    /// Read a general-purpose register by its architectural index.
    fn reg(&self, idx: usize) -> u64;
    /// Write a general-purpose register by its architectural index.
    fn set_reg(&mut self, idx: usize, value: u64);

    fn pc(&self) -> u64;
    fn set_pc(&mut self, pc: u64);
    fn sp(&self) -> u64;
    fn set_sp(&mut self, sp: u64);

    /// The condition/status flags register (`RFLAGS`/`PSTATE`), read and written
    /// as one word so signal delivery can save it into the guest's `ucontext`
    /// and `rt_sigreturn` can restore it. Backends that don't model the full
    /// word return a sane default; the low condition bits are what matter.
    fn rflags(&self) -> u64 {
        0
    }
    fn set_rflags(&mut self, _value: u64) {}

    /// Read/replace the SIMD/FP register file as raw bytes, so a signal frame
    /// can save and restore it: on arm64 the `fpsimd_context` payload (FPSR,
    /// FPCR, V0–V31; 520 bytes); on x86-64 the standard-format `XSAVE` area
    /// of every enabled component (legacy x87/SSE region, header, AVX upper
    /// halves; [`X86_XSAVE_SIZE`] bytes). An x86 set also accepts a bare
    /// 512-byte `FXSAVE` image (the `fxrstor`-only restore: the extended
    /// components are reset). Backends without SIMD state return an empty
    /// vector and ignore a set.
    fn simd_state(&self) -> Vec<u8> {
        Vec::new()
    }
    fn set_simd_state(&mut self, _bytes: &[u8]) {}

    /// Thread pointer (arm64 `TPIDR_EL0` / x86-64 `FS.base`), set by TLS syscalls.
    fn set_tls(&mut self, value: u64);

    /// Duplicate this vcpu's full register state (for `fork`/`clone`). The copy
    /// resumes at the same point; the kernel then sets the child's syscall
    /// return value and advances its PC.
    fn fork(&self) -> Box<dyn Vcpu>;

    /// Fallible guest clone. Resource-limited backends override this method.
    fn try_fork(&self) -> Result<Box<dyn Vcpu>, VcpuError> {
        Ok(self.fork())
    }

    /// Reset every register for `execve`: clear general/SIMD registers, flags,
    /// and TLS, then set the entry PC and initial SP for the new image.
    fn reset(&mut self, entry: u64, sp: u64);

    /// Collapse the syscall-return trampoline into the logical user state — a
    /// software `sysretq`. A KVM guest servicing a syscall is parked at CPL0 on
    /// the trampoline's `sysretq` (rip on the trampoline, the user return in
    /// `rcx` and user flags in `r11`); the host normally lets the guest execute
    /// that `sysretq` to drop back to CPL3. When the host instead redirects the
    /// guest elsewhere — into a signal handler, or back out of `rt_sigreturn` —
    /// `sysretq` never runs, so the vcpu would keep executing user code at CPL0
    /// (supervisor). This adopts the user context (rip←`rcx`, rflags←`r11`) and
    /// switches the segments to flat CPL3, exactly as `sysretq` would, so the
    /// subsequent redirect lands at user privilege. TLS (`fs.base`) is untouched.
    /// A no-op for the interpreter, which has no trampoline — its pc already sits
    /// on the post-syscall user instruction at no privilege level.
    fn settle_syscall_return(&mut self) {}

    /// Whether an [`Exit::Interrupted`] left the vcpu at a user-mode
    /// instruction boundary, where the kernel may deliver a pending
    /// asynchronous signal (build a frame from the live registers and redirect
    /// the pc) as Linux does on any return to user mode — not only at syscall
    /// returns. A compute loop that never makes a syscall (a `SIGALRM`-driven
    /// benchmark, Go's `SIGURG` goroutine preemption) depends on it. True for
    /// the interpreters, which only stop between guest instructions; the
    /// hardware backends may be interrupted inside their trampolines and
    /// answer `false`, deferring delivery to the next syscall.
    fn async_signal_boundary(&self) -> bool {
        true
    }

    /// One-time vDSO clock calibration: read the guest TSC frequency and its
    /// current value and correlate it with the host wall clock, so the guest's
    /// `vdso` can compute `clock_gettime` from `rdtsc` with no syscall. `None`
    /// when the backend uses a logical TSC (KVM and the interpreter) or calibration
    /// failed; the caller then leaves the vvar page zeroed and the vDSO falls
    /// back to the syscall. Read once, before the guest runs.
    fn vdso_calibration(&self) -> Option<VdsoCal> {
        None
    }

    /// Flush this vcpu's TLB before its next run, because the host modified the
    /// page tables of the address space it is running *without* the guest issuing
    /// an `invlpg`/`mov cr3`. The canonical case is `fork`: making the parent's
    /// pages copy-on-write read-only would otherwise be masked by stale writable
    /// TLB entries, letting the parent write straight through a shared frame.
    /// A no-op for the interpreter, which re-walks the page tables on every access
    /// and so has no TLB to invalidate.
    fn flush_tlb(&mut self) {}
}

/// Constructs [`Vcpu`]s that share one guest address space.
pub trait Backend {
    fn name(&self) -> &'static str;
    fn guest_arch(&self) -> Arch;

    /// Create a vcpu with its PC and SP set for a fresh thread. The guest
    /// address space is provided to [`Vcpu::run`], not here, so one backend can
    /// spawn several vcpus over the same memory.
    fn new_vcpu(&self, entry: u64, stack: u64) -> Result<Box<dyn Vcpu>, VcpuError>;

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn prepare_confinement(
        &self,
        _capacity: usize,
        _mem: &GuestMemory,
    ) -> Result<crate::confinement::Resources, VcpuError> {
        Ok(crate::confinement::Resources::default())
    }
}

// Behind the `hvf` feature: the backend still maps guest RAM as one flat,
// identity-mapped region, which the paged `GuestMemory` (frame pool + page
// tables) no longer provides. It needs guest stage-1 page tables before it can
// run again; until then default macOS builds use the interpreter.
#[cfg(all(feature = "hvf", target_os = "macos", target_arch = "aarch64"))]
pub mod hvf;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod kvm;

pub mod interp;
pub mod interp_x86;
pub(crate) mod softfloat;

/// Pick a backend that supplies the VM's execution clock for `guest`.
///
/// Linux/x86-64 prefers KVM when both virtualization and guest-only branch
/// counting are usable. Other hosts and unavailable hardware use the software
/// interpreter. The optional HVF backend lacks virtual execution accounting and
/// is excluded from automatic selection. `NIXVM_INTERP=1` skips hardware probes.
pub fn select(guest: Arch) -> Result<Box<dyn Backend>, VcpuError> {
    let force_interp = std::env::var_os("NIXVM_INTERP").is_some_and(|v| v == "1");
    if std::env::var_os("NIXVM_BRANCH_QUANTUM").is_some() {
        if force_interp || guest != Arch::X86_64 {
            return Err(VcpuError::Backend(
                "PMU scheduling requires the x86-64 KVM backend".into(),
            ));
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        return kvm::KvmBackend::new().map(|backend| Box::new(backend) as Box<dyn Backend>);
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        return Err(VcpuError::Backend(
            "PMU scheduling requires Linux/x86-64 KVM".into(),
        ));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        // Both virtualization and a usable guest-only counter are required.
        // Failure leaves software execution with its internal clock available.
        if !force_interp
            && guest == Arch::X86_64
            && let Ok(backend) = kvm::KvmBackend::new()
        {
            return Ok(Box::new(backend) as Box<dyn Backend>);
        }
    }
    let _ = force_interp;
    // TODO(Phase 10): KVM on Linux/arm64.
    // x86-64 guests run on the dedicated x86 software interpreter; other guest
    // arches fall back to `interp::InterpBackend`.
    if guest == Arch::X86_64 {
        return interp_x86::X86Backend::new(guest).map(|b| Box::new(b) as Box<dyn Backend>);
    }
    interp::InterpBackend::new(guest).map(|b| Box::new(b) as Box<dyn Backend>)
}

#[cfg(test)]
mod selection_tests {
    #[test]
    fn requested_pmu_never_falls_back_to_an_interpreter() {
        const CHILD: &str = "NIXVM_PMU_SELECTION_TEST";
        if std::env::var_os(CHILD).is_some() {
            assert!(super::select(crate::abi::Arch::X86_64).is_err());
            return;
        }
        for (quantum, interpreter) in [("64", "1"), ("invalid", "0")] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "vcpu::selection_tests::requested_pmu_never_falls_back_to_an_interpreter",
                ])
                .env(CHILD, "1")
                .env("NIXVM_BRANCH_QUANTUM", quantum)
                .env("NIXVM_INTERP", interpreter)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
    }
}
