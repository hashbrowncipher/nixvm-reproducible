//! Per-VM virtual time and explicitly named host clocks for embedder budgets.
//!
//! Guest time is owned by [`VirtualClock`]. Execution, observations and idle
//! jumps advance it; no host clock feeds it. One execution unit is one virtual
//! nanosecond. Backends choose their documented deterministic execution metric.
//!
//! The `host_*` functions are reserved for watchdogs, profiling and embedder
//! wall-clock budgets. They must never supply guest-visible timestamps.

use std::time::Duration;

use std::collections::BTreeMap;
use std::sync::Mutex;

/// Reproducible Unix epoch used by a newly created VM.
pub const DEFAULT_EPOCH_SECS: u64 = 1_700_000_000;
/// Maximum virtual cost of a single repeated clock observation.
pub const MAX_OBSERVATION_NS: u64 = 1_000_000;
const MAX_NS: u128 = u64::MAX as u128 * 1_000_000_000 + 999_999_999;

#[derive(Debug)]
struct State {
    monotonic_ns: u128,
    execution_ns: u128,
    deadline: Option<u128>,
    observations: BTreeMap<u64, u64>,
    next_observer: u64,
}

/// A VM's single authority for monotonic, realtime and timestamp-counter time.
///
/// All vCPUs and the kernel share an `Arc<VirtualClock>`. Clock reads are pure;
/// guest observations explicitly call [`Self::observe`]. Execution accounting
/// remains separate from idle jumps and accelerated observations so those jumps
/// do not consume guest CPU time. A mutex keeps `u128` values portable to wasm.
#[derive(Debug)]
pub struct VirtualClock {
    state: Mutex<State>,
}

impl Default for VirtualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualClock {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                monotonic_ns: 0,
                execution_ns: 0,
                deadline: None,
                observations: BTreeMap::new(),
                next_observer: 1 << 63,
            }),
        }
    }

    /// Allocate an identity for a directly driven vCPU. Kernel task identities
    /// occupy the low half of the identity space.
    pub fn allocate_observer(&self) -> u64 {
        let mut state = self.state.lock().unwrap();
        let observer = state.next_observer;
        state.next_observer = observer
            .checked_add(1)
            .expect("clock observer identity exhausted");
        observer
    }

    #[must_use]
    pub fn now_monotonic(&self) -> Duration {
        duration(self.state.lock().unwrap().monotonic_ns)
    }

    #[must_use]
    pub fn now_unix(&self) -> Duration {
        self.now_monotonic()
            .saturating_add(Duration::from_secs(DEFAULT_EPOCH_SECS))
    }

    /// Time charged to actual execution, excluding idle and observation jumps.
    #[must_use]
    pub fn execution_ns(&self) -> u128 {
        self.state.lock().unwrap().execution_ns
    }

    /// Account measured execution. It must never be clamped: a backend must
    /// stop at its execution limit rather than erase execution that happened.
    pub fn advance_execution(&self, units: u64) {
        let mut state = self.state.lock().unwrap();
        state.execution_ns = state.execution_ns.saturating_add(u128::from(units));
        state.monotonic_ns = state
            .monotonic_ns
            .saturating_add(u128::from(units))
            .min(MAX_NS);
    }

    /// Account a genuine syscall entry once, independently of blocked retries.
    pub fn advance_event(&self) {
        let mut state = self.state.lock().unwrap();
        state.monotonic_ns = state.monotonic_ns.saturating_add(1).min(MAX_NS);
    }

    /// Observe time on behalf of one task. Repeated observations cost 1, 2, 4,
    /// ... nanoseconds up to [`MAX_OBSERVATION_NS`], making polling loops finish
    /// promptly. A published timed event is always serviced before advancing
    /// past it. Ordinary execution does not reset this observation streak.
    pub fn observe(&self, task: u64) -> Duration {
        let mut state = self.state.lock().unwrap();
        let increment = *state.observations.entry(task).or_insert(1);
        state
            .observations
            .insert(task, increment.saturating_mul(2).min(MAX_OBSERVATION_NS));
        let target = state
            .monotonic_ns
            .saturating_add(u128::from(increment))
            .min(MAX_NS);
        state.monotonic_ns = state.deadline.map_or(target, |deadline| {
            target.min(deadline.max(state.monotonic_ns))
        });
        duration(state.monotonic_ns)
    }

    /// Reset after a meaningful non-clock interaction, such as blocking or a
    /// non-clock syscall. Time getters and timestamp instructions share a streak.
    pub fn reset_observations(&self, task: u64) {
        self.state.lock().unwrap().observations.remove(&task);
    }

    /// Publish the next kernel timed event as an absolute monotonic timestamp.
    pub fn set_deadline(&self, deadline: Option<u128>) {
        self.state.lock().unwrap().deadline = deadline;
    }

    #[must_use]
    pub fn next_deadline(&self) -> Option<u128> {
        self.state.lock().unwrap().deadline
    }

    #[must_use]
    pub fn deadline_due(&self) -> bool {
        let state = self.state.lock().unwrap();
        state
            .deadline
            .is_some_and(|deadline| state.monotonic_ns >= deadline)
    }

    /// Jump an idle VM to its next timed event without charging execution time.
    pub fn advance_to(&self, monotonic_ns: u128) {
        let mut state = self.state.lock().unwrap();
        state.monotonic_ns = state.monotonic_ns.max(monotonic_ns.min(MAX_NS));
    }
}

fn duration(ns: u128) -> Duration {
    let ns = ns.min(MAX_NS);
    Duration::new((ns / 1_000_000_000) as u64, (ns % 1_000_000_000) as u32)
}

/// Host time since the Unix epoch, reserved for embedder diagnostics.
/// Saturates at zero for a host clock set before 1970.
#[must_use]
pub fn host_unix() -> Duration {
    imp::now_unix()
}

/// Host monotonic time for embedder budgets and watchdogs. The epoch is
/// arbitrary and independent of every VM clock.
#[must_use]
pub fn host_monotonic() -> Duration {
    imp::now_monotonic()
}

/// Host process CPU time for profiling, independent of guest CPU accounting.
#[must_use]
pub fn host_cpu_process() -> Duration {
    imp::now_cpu_process()
}

/// Host thread CPU time for profiling, independent of guest CPU accounting.
#[must_use]
pub fn host_cpu_thread() -> Duration {
    imp::now_cpu_thread()
}

#[cfg(not(target_arch = "wasm32"))]
mod imp {
    use std::time::Duration;

    pub fn now_unix() -> Duration {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
    }

    // Linux host monotonic and CPU clocks used for embedder diagnostics only.
    #[cfg(target_os = "linux")]
    mod host {
        use std::time::Duration;
        #[repr(C)]
        struct Ts {
            sec: i64,
            nsec: i64,
        }
        unsafe extern "C" {
            fn clock_gettime(clk: i32, tp: *mut Ts) -> i32;
        }
        pub fn read(clk: i32) -> Option<Duration> {
            let mut ts = Ts { sec: 0, nsec: 0 };
            // SAFETY: `ts` is a valid, writable `timespec`; `clk` is a fixed,
            // valid POSIX clock id. `clock_gettime` writes only `ts`.
            (unsafe { clock_gettime(clk, &raw mut ts) } == 0)
                .then(|| Duration::new(ts.sec.max(0) as u64, ts.nsec.clamp(0, 999_999_999) as u32))
        }
    }

    /// Cross-platform monotonic fallback: elapsed since a fixed process origin.
    fn instant_monotonic() -> Duration {
        use std::sync::OnceLock;
        use std::time::Instant;
        static ORIGIN: OnceLock<Instant> = OnceLock::new();
        ORIGIN.get_or_init(Instant::now).elapsed()
    }

    pub fn now_monotonic() -> Duration {
        #[cfg(target_os = "linux")]
        if let Some(d) = host::read(1) {
            return d;
        }
        instant_monotonic()
    }

    pub fn now_cpu_process() -> Duration {
        #[cfg(target_os = "linux")]
        if let Some(d) = host::read(2) {
            return d;
        }
        // No portable CPU clock here: best-effort monotonic (still non-decreasing).
        instant_monotonic()
    }

    pub fn now_cpu_thread() -> Duration {
        #[cfg(target_os = "linux")]
        if let Some(d) = host::read(3) {
            return d;
        }
        instant_monotonic()
    }
}

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
mod imp {
    use std::sync::OnceLock;
    use std::time::Duration;
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    extern "C" {
        /// `Date.now()` — milliseconds since the UNIX epoch (whole ms).
        #[wasm_bindgen(js_namespace = Date, js_name = now)]
        fn date_now() -> f64;
        /// `performance.now()` — monotonic milliseconds since page load, with
        /// sub-millisecond resolution (browsers coarsen it to 5-100 µs).
        #[wasm_bindgen(js_namespace = performance, js_name = now)]
        fn perf_now() -> f64;
    }

    fn from_ms(ms: f64) -> Duration {
        Duration::from_nanos((ms.max(0.0) * 1e6) as u64)
    }

    /// `Date.now() - performance.now()`, taken once: the wall-clock time of
    /// the monotonic origin. Realtime is this plus `performance.now()`, so it
    /// keeps the monotonic clock's sub-millisecond resolution (`Date.now()`
    /// alone made every guest timing — ping's RTTs — whole milliseconds).
    fn epoch_offset_ms() -> f64 {
        static OFFSET: OnceLock<f64> = OnceLock::new();
        *OFFSET.get_or_init(|| date_now() - perf_now())
    }

    pub fn now_unix() -> Duration {
        from_ms(epoch_offset_ms() + perf_now())
    }

    pub fn now_monotonic() -> Duration {
        from_ms(perf_now())
    }
    // No per-process CPU clock in a tab; the monotonic clock is total and
    // non-panicking, which is all the demo needs.
    pub fn now_cpu_process() -> Duration {
        now_monotonic()
    }
    pub fn now_cpu_thread() -> Duration {
        now_monotonic()
    }
}

#[cfg(all(target_arch = "wasm32", not(feature = "wasm")))]
mod imp {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    /// No JS to ask and no std clock: a monotonic counter that advances 1 ms
    /// per read keeps time-dependent guest code moving instead of panicking.
    static FAKE_MS: AtomicU64 = AtomicU64::new(1_700_000_000_000);

    pub fn now_unix() -> Duration {
        Duration::from_millis(FAKE_MS.fetch_add(1, Ordering::Relaxed))
    }
    pub fn now_monotonic() -> Duration {
        now_unix()
    }
    pub fn now_cpu_process() -> Duration {
        now_unix()
    }
    pub fn now_cpu_thread() -> Duration {
        now_unix()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_clocks_have_fixed_epochs() {
        let first = VirtualClock::new();
        let second = VirtualClock::new();
        assert_eq!(first.now_monotonic(), Duration::ZERO);
        assert_eq!(first.now_unix(), Duration::from_secs(DEFAULT_EPOCH_SECS));
        first.advance_execution(17);
        assert_eq!(first.now_monotonic().as_nanos(), 17);
        assert_eq!(second.now_monotonic(), Duration::ZERO);
    }

    #[test]
    fn idle_and_observations_do_not_charge_execution() {
        let clock = VirtualClock::new();
        clock.advance_execution(9);
        clock.advance_to(100);
        assert_eq!(clock.observe(1).as_nanos(), 101);
        clock.advance_event();
        assert_eq!(clock.execution_ns(), 9);
        assert_eq!(clock.now_monotonic().as_nanos(), 102);
        clock.advance_to(0);
        assert_eq!(clock.now_monotonic().as_nanos(), 102);
    }

    #[test]
    fn observations_accelerate_per_task_and_reset() {
        let clock = VirtualClock::new();
        assert_eq!(clock.observe(1).as_nanos(), 1);
        assert_eq!(clock.observe(1).as_nanos(), 3);
        assert_eq!(clock.observe(1).as_nanos(), 7);
        assert_eq!(clock.observe(2).as_nanos(), 8);
        clock.reset_observations(1);
        assert_eq!(clock.observe(1).as_nanos(), 9);
        for _ in 0..64 {
            clock.observe(1);
        }
        let before = clock.now_monotonic();
        assert_eq!(
            clock.observe(1).checked_sub(before).unwrap(),
            Duration::from_nanos(MAX_OBSERVATION_NS)
        );
    }

    #[test]
    fn polling_stops_at_pending_event_and_never_rewinds() {
        let clock = VirtualClock::new();
        clock.set_deadline(Some(10));
        for _ in 0..100 {
            clock.observe(1);
        }
        assert_eq!(clock.now_monotonic().as_nanos(), 10);
        assert!(clock.deadline_due());
        clock.set_deadline(Some(5));
        assert_eq!(clock.observe(1).as_nanos(), 10);
        clock.set_deadline(Some(20));
        assert_eq!(clock.observe(1).as_nanos(), 20);
        clock.set_deadline(None);
        assert!(!clock.deadline_due());
        clock.observe(1);
        assert!(clock.now_monotonic().as_nanos() > 20);
    }

    #[test]
    fn execution_is_not_discarded_at_a_deadline() {
        let clock = VirtualClock::new();
        clock.set_deadline(Some(5));
        clock.advance_execution(6);
        assert_eq!(clock.now_monotonic().as_nanos(), 6);
        assert_eq!(clock.execution_ns(), 6);
        assert!(clock.deadline_due());
    }

    #[test]
    fn now_is_after_2020() {
        // A very loose sanity bound: the host clock reads as a real date.
        assert!(
            host_unix().as_secs() > 1_577_836_800,
            "clock reads as post-2020"
        );
    }
}
