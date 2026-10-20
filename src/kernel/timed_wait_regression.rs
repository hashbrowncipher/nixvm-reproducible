//! Regression cases for terminal timed-wait outcomes.
use super::futex::FutexKey;
use super::testutil::{BASE, call, e, setup};
use super::{Kernel, ProcInfo, Process, RunState};
use crate::abi::arch::Sysno;
use crate::abi::errno::Errno;

#[test]
fn expired_futex_cannot_be_rescued_by_late_wake() {
    let (k, _mem, _v, _cx) = setup();
    let key = FutexKey::Private(0, BASE);
    let mut sh = k.shared.lock().unwrap();
    sh.procs.push(Some(Process {
        vcpu: None,
        info: ProcInfo {
            pid: 2,
            tgid: 1,
            run: RunState::Running,
            parked: true,
            futex_wait: Some(key),
            futex_bitset: u32::MAX,
            wake_deadline: Some(0),
            ..ProcInfo::default()
        },
    }));
    sh.wake_expired_waiters();
    assert_eq!(
        Kernel::futex_wake_key(&mut sh, key, 1, u32::MAX),
        0,
        "expiry must remove the waiter before a wake at or after its deadline"
    );
}

#[test]
fn futex_initial_value_mismatch_precedes_expired_timeout() {
    let (k, mut mem, mut v, mut cx) = setup();
    let ts = BASE + 0x100;
    mem.write(BASE, &7u32.to_le_bytes()).unwrap();
    mem.write(ts, &[0; 16]).unwrap();
    assert_eq!(
        call(
            &k,
            &mut cx,
            &mut mem,
            &mut v,
            Sysno::Futex,
            [BASE, 128, 8, ts, 0, 0]
        ),
        e(Errno::EAGAIN),
        "the atomic compare precedes parking and timeout completion"
    );
}
