//! Virtual time crosses syscall, scheduler and filesystem boundaries.
use super::testutil::{BASE, DummyVcpu, call, e, setup};
use super::{Kernel, Process, ServiceCtx};
use crate::abi::arch::Sysno;
use crate::abi::errno::Errno;
use crate::clock::DEFAULT_EPOCH_SECS;
use crate::vcpu::{Backend, Exit};

fn timespec(mem: &mut crate::vcpu::GuestMemory, address: u64, nanoseconds: u128) {
    mem.write(
        address,
        &((nanoseconds / 1_000_000_000) as u64).to_le_bytes(),
    )
    .unwrap();
    mem.write(
        address + 8,
        &((nanoseconds % 1_000_000_000) as u64).to_le_bytes(),
    )
    .unwrap();
}

fn remember_task(k: &Kernel, cx: &ServiceCtx) {
    let mut info = cx.cur.clone();
    info.parked = true;
    k.shared
        .lock()
        .unwrap()
        .procs
        .push(Some(Process { vcpu: None, info }));
}

#[test]
fn vm_clocks_and_generated_file_times_are_isolated() {
    let (first, mut mem, mut vcpu, mut cx) = setup();
    let (second, _, _, _) = setup();
    first.clock.advance_to(3_000_000_000);
    mem.write(BASE, b"/clock-test\0").unwrap();
    assert!(
        call(
            &first,
            &mut cx,
            &mut mem,
            &mut vcpu,
            Sysno::Openat,
            [(-100i64) as u64, BASE, 0o102, 0o644, 0, 0]
        ) >= 3
    );
    assert_eq!(
        first.vfs.lock().unwrap().stat("/clock-test").unwrap().mtime,
        (DEFAULT_EPOCH_SECS + 3) as i64
    );
    assert_eq!(second.clock.now_monotonic().as_nanos(), 0);
    assert_eq!(second.clock.now_unix().as_secs(), DEFAULT_EPOCH_SECS);
    assert_eq!(cx.cur.cpu_ns, 0, "idle jumps do not consume CPU");
}

#[test]
fn relative_and_absolute_futex_domains_share_monotonic_deadlines() {
    for (operation, seconds, nanoseconds, expected) in [
        (128, 0, 40, 60),
        (128 | 9, 0, 100, 100),
        (128 | 9 | 256, DEFAULT_EPOCH_SECS, 100, 100),
    ] {
        let (k, mut mem, mut vcpu, mut cx) = setup();
        k.clock.advance_to(20);
        mem.write(BASE, &7u32.to_le_bytes()).unwrap();
        mem.write(BASE + 0x100, &seconds.to_le_bytes()).unwrap();
        mem.write(BASE + 0x108, &(nanoseconds as u64).to_le_bytes())
            .unwrap();
        assert_eq!(
            call(
                &k,
                &mut cx,
                &mut mem,
                &mut vcpu,
                Sysno::Futex,
                [BASE, operation, 7, BASE + 0x100, 0, u64::from(u32::MAX)]
            ),
            0
        );
        assert!(cx.block);
        assert_eq!(cx.cur.wake_deadline, Some(expected));
    }
}

#[test]
fn idle_jump_completes_futex_timeout_without_charging_cpu() {
    let (k, mut mem, mut vcpu, mut cx) = setup();
    mem.write(BASE, &7u32.to_le_bytes()).unwrap();
    timespec(&mut mem, BASE + 0x100, 500);
    assert_eq!(
        call(
            &k,
            &mut cx,
            &mut mem,
            &mut vcpu,
            Sysno::Futex,
            [BASE, 128, 7, BASE + 0x100, 0, 0]
        ),
        0
    );
    remember_task(&k, &cx);
    assert!(k.advance_idle_time());
    assert_eq!(k.clock.now_monotonic().as_nanos(), 500);
    cx.cur = k.shared.lock().unwrap().procs.pop().unwrap().unwrap().info;
    assert!(!cx.cur.parked);
    cx.block = false;
    assert_eq!(
        call(
            &k,
            &mut cx,
            &mut mem,
            &mut vcpu,
            Sysno::Futex,
            [BASE, 128, 7, BASE + 0x100, 0, 0]
        ),
        e(Errno::ETIMEDOUT)
    );
    assert_eq!(cx.cur.cpu_ns, 0);
    assert!(
        !k.advance_idle_time(),
        "consumed timeout must not fire twice"
    );
}

#[test]
fn explicit_futex_wake_commits_before_later_timeout() {
    let (k, mut mem, mut vcpu, mut cx) = setup();
    mem.write(BASE, &7u32.to_le_bytes()).unwrap();
    timespec(&mut mem, BASE + 0x100, 100);
    call(
        &k,
        &mut cx,
        &mut mem,
        &mut vcpu,
        Sysno::Futex,
        [BASE, 128, 7, BASE + 0x100, 0, 0],
    );
    remember_task(&k, &cx);
    {
        let mut sh = k.shared.lock().unwrap();
        assert_eq!(
            Kernel::futex_wake_key(
                &mut sh,
                super::futex::FutexKey::Private(0, BASE),
                1,
                u32::MAX
            ),
            1
        );
    }
    k.clock.advance_to(100);
    k.prepare_time(None);
    cx.cur = k.shared.lock().unwrap().procs.pop().unwrap().unwrap().info;
    cx.block = false;
    assert_eq!(
        call(
            &k,
            &mut cx,
            &mut mem,
            &mut vcpu,
            Sysno::Futex,
            [BASE, 128, 7, BASE + 0x100, 0, 0]
        ),
        0
    );
    assert!(!cx.block);
}

#[test]
fn ppoll_and_pselect_preserve_nanosecond_deadlines() {
    for syscall in [Sysno::Ppoll, Sysno::Pselect6] {
        let (k, mut mem, mut vcpu, mut cx) = setup();
        timespec(&mut mem, BASE, 3);
        let args = if matches!(syscall, Sysno::Ppoll) {
            [0, 0, BASE, 0, 0, 0]
        } else {
            [0, 0, 0, 0, BASE, 0]
        };
        assert_eq!(call(&k, &mut cx, &mut mem, &mut vcpu, syscall, args), 0);
        assert!(cx.block);
        assert_eq!(cx.cur.wake_deadline, Some(3));
        k.clock.advance_to(3);
        cx.block = false;
        assert_eq!(call(&k, &mut cx, &mut mem, &mut vcpu, syscall, args), 0);
        assert!(!cx.block);
        assert_eq!(cx.cur.wake_deadline, None);
    }
}

#[test]
fn timerfd_alone_wakes_infinite_epoll_after_idle_jump() {
    let (k, mut mem, mut vcpu, mut cx) = setup();
    let timer = call(
        &k,
        &mut cx,
        &mut mem,
        &mut vcpu,
        Sysno::TimerfdCreate,
        [1, 0, 0, 0, 0, 0],
    ) as u64;
    timespec(&mut mem, BASE, 0);
    timespec(&mut mem, BASE + 16, 11);
    assert_eq!(
        call(
            &k,
            &mut cx,
            &mut mem,
            &mut vcpu,
            Sysno::TimerfdSettime,
            [timer, 0, BASE, 0, 0, 0]
        ),
        0
    );
    let epoll = call(
        &k,
        &mut cx,
        &mut mem,
        &mut vcpu,
        Sysno::EpollCreate1,
        [0; 6],
    ) as u64;
    mem.write(BASE + 0x100, &1u32.to_le_bytes()).unwrap();
    mem.write(BASE + 0x108, &123u64.to_le_bytes()).unwrap();
    assert_eq!(
        call(
            &k,
            &mut cx,
            &mut mem,
            &mut vcpu,
            Sysno::EpollCtl,
            [epoll, 1, timer, BASE + 0x100, 0, 0]
        ),
        0
    );
    let args = [epoll, BASE + 0x200, 1, u64::MAX, 0, 0];
    assert_eq!(
        call(&k, &mut cx, &mut mem, &mut vcpu, Sysno::EpollPwait, args),
        0
    );
    assert!(cx.block);
    assert_eq!(cx.cur.wake_deadline, None);
    remember_task(&k, &cx);
    assert!(k.advance_idle_time());
    assert_eq!(k.clock.now_monotonic().as_nanos(), 11);
    cx.cur = k.shared.lock().unwrap().procs.pop().unwrap().unwrap().info;
    assert!(!cx.cur.parked);
    cx.block = false;
    assert_eq!(
        call(&k, &mut cx, &mut mem, &mut vcpu, Sysno::EpollPwait, args),
        1
    );
    assert_eq!(mem.read_u64(BASE + 0x208).unwrap(), 123);
    assert_eq!(
        call(
            &k,
            &mut cx,
            &mut mem,
            &mut vcpu,
            Sysno::Read,
            [timer, BASE + 0x300, 8, 0, 0, 0]
        ),
        8
    );
    assert_eq!(mem.read_u64(BASE + 0x300).unwrap(), 1);
    assert!(!k.advance_idle_time());
}

#[test]
fn timerfd_absolute_clock_domain_and_close_cancel_deadlines() {
    for clock in [0, 1] {
        let (k, mut mem, mut vcpu, mut cx) = setup();
        k.clock.advance_to(20);
        let timer = call(
            &k,
            &mut cx,
            &mut mem,
            &mut vcpu,
            Sysno::TimerfdCreate,
            [clock, 0, 0, 0, 0, 0],
        ) as u64;
        timespec(&mut mem, BASE, 0);
        let epoch = if clock == 0 {
            u128::from(DEFAULT_EPOCH_SECS) * 1_000_000_000
        } else {
            0
        };
        timespec(&mut mem, BASE + 16, epoch + 100);
        assert_eq!(
            call(
                &k,
                &mut cx,
                &mut mem,
                &mut vcpu,
                Sysno::TimerfdSettime,
                [timer, 1, BASE, 0, 0, 0]
            ),
            0
        );
        k.prepare_time(Some(&mut cx.cur));
        assert_eq!(k.clock.next_deadline(), Some(100));
        assert_eq!(
            call(
                &k,
                &mut cx,
                &mut mem,
                &mut vcpu,
                Sysno::Close,
                [timer, 0, 0, 0, 0, 0]
            ),
            0
        );
        k.prepare_time(Some(&mut cx.cur));
        assert_eq!(k.clock.next_deadline(), None);
        assert!(!k.advance_idle_time());
    }
}

#[test]
fn cpu_timers_ignore_idle_and_clock_observation_advances() {
    for clock in [2, 3] {
        let (k, mut mem, mut vcpu, mut cx) = setup();
        assert_eq!(
            call(
                &k,
                &mut cx,
                &mut mem,
                &mut vcpu,
                Sysno::TimerCreate,
                [clock, 0, BASE, 0, 0, 0]
            ),
            0
        );
        let timer = u64::from(mem.read_u32(BASE).unwrap());
        timespec(&mut mem, BASE + 0x100, 0);
        timespec(&mut mem, BASE + 0x110, 10);
        assert_eq!(
            call(
                &k,
                &mut cx,
                &mut mem,
                &mut vcpu,
                Sysno::TimerSettime,
                [timer, 0, BASE + 0x100, 0, 0, 0]
            ),
            0
        );
        remember_task(&k, &cx);
        assert!(
            !k.advance_idle_time(),
            "CPU timers do not supply idle events"
        );
        k.shared.lock().unwrap().procs.clear();
        k.clock.advance_to(1_000_000);
        k.clock.observe(cx.cur.pid as u64);
        k.prepare_time(Some(&mut cx.cur));
        assert_eq!(cx.cur.pending, 0);
        assert_eq!(
            k.clock.next_deadline(),
            Some(k.clock.now_monotonic().as_nanos() + 10)
        );
        cx.cur.cpu_ns = 9;
        k.prepare_time(Some(&mut cx.cur));
        assert_eq!(cx.cur.pending, 0);
        cx.cur.cpu_ns = 10;
        k.prepare_time(Some(&mut cx.cur));
        assert_ne!(cx.cur.pending & (1 << 13), 0, "CPU execution fires SIGALRM");
    }
}

#[test]
fn futex_restart_restores_original_deadline_after_handler_wait() {
    let (k, mut mem, _dummy, mut cx) = setup();
    let backend = crate::vcpu::interp::InterpBackend::new(crate::abi::Arch::Aarch64).unwrap();
    let mut cpu = backend.new_vcpu(BASE + 0x400, BASE + 0x7000).unwrap();
    mem.write(BASE, &7u32.to_le_bytes()).unwrap();
    timespec(&mut mem, BASE + 0x100, 100);
    cx.cur.handlers[10] = super::SigAction {
        handler: BASE + 0x500,
        flags: super::SA_RESTART,
        ..super::SigAction::default()
    };
    cx.cur.pending = 1 << 9;
    cpu.set_reg(8, 98); // arm64 futex
    for (register, value) in [BASE, 128, 7, BASE + 0x100, 0, 0].into_iter().enumerate() {
        cpu.set_reg(register, value);
    }
    k.service(&mut cx, Exit::Syscall, cpu.as_mut(), &mut mem);
    assert!(!cx.block);
    assert_eq!(
        cx.cur.wake_deadline, None,
        "handler owns independent wait state"
    );
    assert_eq!(cx.cur.signal_restart_deadlines.get(&cpu.sp()), Some(&100));
    k.clock.advance_to(40);
    timespec(&mut mem, BASE + 0x200, 5);
    let mut dummy = DummyVcpu;
    call(
        &k,
        &mut cx,
        &mut mem,
        &mut dummy,
        Sysno::Nanosleep,
        [BASE + 0x200, 0, 0, 0, 0, 0],
    );
    assert_eq!(cx.cur.wake_deadline, Some(45));
    k.clock.advance_to(45);
    cx.block = false;
    call(
        &k,
        &mut cx,
        &mut mem,
        &mut dummy,
        Sysno::Nanosleep,
        [BASE + 0x200, 0, 0, 0, 0, 0],
    );
    cpu.set_reg(8, 139); // arm64 rt_sigreturn, including generic service cleanup
    k.service(&mut cx, Exit::Syscall, cpu.as_mut(), &mut mem);
    assert_eq!(cx.cur.wake_deadline, Some(100));
    cx.block = false;
    k.service(&mut cx, Exit::Syscall, cpu.as_mut(), &mut mem);
    assert!(cx.block);
    assert_eq!(
        cx.cur.wake_deadline,
        Some(100),
        "restart must not add a new full duration"
    );
}

#[test]
fn infinite_poll_parks_without_registering_a_deadline() {
    let (k, mut mem, mut vcpu, mut cx) = setup();
    assert_eq!(
        call(
            &k,
            &mut cx,
            &mut mem,
            &mut vcpu,
            Sysno::Poll,
            [0, 0, u64::MAX, 0, 0, 0]
        ),
        0
    );
    assert!(cx.block);
    assert_eq!(cx.cur.wake_deadline, None);
}

#[test]
fn waitv_retry_keeps_registered_keys_when_user_vector_changes() {
    let (k, mut mem, mut vcpu, mut cx) = setup();
    let word = BASE;
    let vector = BASE + 0x100;
    mem.write(word, &7u32.to_le_bytes()).unwrap();
    mem.write(vector, &7u64.to_le_bytes()).unwrap();
    mem.write(vector + 8, &word.to_le_bytes()).unwrap();
    mem.write(vector + 16, &130u32.to_le_bytes()).unwrap(); // FUTEX_32 | PRIVATE
    mem.write(vector + 20, &0u32.to_le_bytes()).unwrap();
    let args = [vector, 1, 0, 0, 1, 0];
    assert_eq!(
        call(&k, &mut cx, &mut mem, &mut vcpu, Sysno::FutexWaitv, args),
        0
    );
    assert!(cx.block);
    let registered = cx.cur.futex_waitv.clone();
    mem.write(word, &99u32.to_le_bytes()).unwrap();
    mem.write(vector + 8, &(word + 4).to_le_bytes()).unwrap();
    cx.block = false;
    assert_eq!(
        call(&k, &mut cx, &mut mem, &mut vcpu, Sysno::FutexWaitv, args),
        0
    );
    assert!(cx.block);
    assert_eq!(cx.cur.futex_waitv, registered);
    remember_task(&k, &cx);
    {
        let mut sh = k.shared.lock().unwrap();
        assert_eq!(
            Kernel::futex_wake_key(
                &mut sh,
                super::futex::FutexKey::Private(0, word),
                1,
                u32::MAX
            ),
            1
        );
    }
    cx.cur = k.shared.lock().unwrap().procs.pop().unwrap().unwrap().info;
    cx.block = false;
    assert_eq!(
        call(&k, &mut cx, &mut mem, &mut vcpu, Sysno::FutexWaitv, args),
        0
    );
    assert!(!cx.block);
}

#[test]
fn expired_epoll_wait_does_not_consume_late_readiness() {
    let (k, mut mem, mut vcpu, mut cx) = setup();
    let event = call(&k, &mut cx, &mut mem, &mut vcpu, Sysno::Eventfd2, [0; 6]) as u64;
    let epoll = call(
        &k,
        &mut cx,
        &mut mem,
        &mut vcpu,
        Sysno::EpollCreate1,
        [0; 6],
    ) as u64;
    mem.write(BASE, &1u32.to_le_bytes()).unwrap();
    mem.write(BASE + 8, &123u64.to_le_bytes()).unwrap();
    assert_eq!(
        call(
            &k,
            &mut cx,
            &mut mem,
            &mut vcpu,
            Sysno::EpollCtl,
            [epoll, 1, event, BASE, 0, 0]
        ),
        0
    );
    let args = [epoll, BASE + 0x100, 1, 1, 0, 0];
    assert_eq!(
        call(&k, &mut cx, &mut mem, &mut vcpu, Sysno::EpollPwait, args),
        0
    );
    assert!(cx.block);
    k.clock.advance_to(1_000_000);
    mem.write(BASE + 0x200, &1u64.to_le_bytes()).unwrap();
    // A sibling posts readiness after the deadline, before this waiter runs.
    let mut sibling = ServiceCtx::for_test();
    sibling.cur.fds = cx.cur.fds.clone();
    assert_eq!(
        call(
            &k,
            &mut sibling,
            &mut mem,
            &mut vcpu,
            Sysno::Write,
            [event, BASE + 0x200, 8, 0, 0, 0]
        ),
        8
    );
    cx.block = false;
    assert_eq!(
        call(&k, &mut cx, &mut mem, &mut vcpu, Sysno::EpollPwait, args),
        0
    );
    assert!(!cx.block);
    assert_eq!(
        call(
            &k,
            &mut cx,
            &mut mem,
            &mut vcpu,
            Sysno::EpollPwait,
            [epoll, BASE + 0x100, 1, 0, 0, 0]
        ),
        1
    );
}

#[test]
fn clock_getter_fires_current_task_timer_before_guest_resumes() {
    let (k, mut mem, _dummy, mut cx) = setup();
    let backend = crate::vcpu::interp::InterpBackend::new(crate::abi::Arch::Aarch64).unwrap();
    let mut cpu = backend.new_vcpu(BASE + 0x400, BASE + 0x7000).unwrap();
    cx.cur.handlers[14] = super::SigAction {
        handler: BASE + 0x500,
        ..super::SigAction::default()
    };
    cx.cur.alarm_deadline = Some(1);
    cpu.set_reg(8, 113); // arm64 clock_gettime
    cpu.set_reg(0, 1);
    cpu.set_reg(1, BASE);
    k.prepare_time(Some(&mut cx.cur));
    k.service(&mut cx, Exit::Syscall, cpu.as_mut(), &mut mem);
    assert_eq!(cpu.pc(), BASE + 0x500);
    assert_eq!(cx.cur.alarm_deadline, None);
    assert_eq!(mem.read_u64(BASE + 8).unwrap(), 1);
}

#[test]
fn queued_scm_rights_preserves_timer_until_receiver_closes_it() {
    let (k, mut mem, mut vcpu, mut cx) = setup();
    let timer = call(
        &k,
        &mut cx,
        &mut mem,
        &mut vcpu,
        Sysno::TimerfdCreate,
        [1, 0, 0, 0, 0, 0],
    ) as u64;
    timespec(&mut mem, BASE, 0);
    timespec(&mut mem, BASE + 16, 10);
    assert_eq!(
        call(
            &k,
            &mut cx,
            &mut mem,
            &mut vcpu,
            Sysno::TimerfdSettime,
            [timer, 0, BASE, 0, 0, 0]
        ),
        0
    );
    assert_eq!(
        call(
            &k,
            &mut cx,
            &mut mem,
            &mut vcpu,
            Sysno::Socketpair,
            [1, 1, 0, BASE + 0x100, 0, 0]
        ),
        0
    );
    let sender = u64::from(mem.read_u32(BASE + 0x100).unwrap());
    let receiver = u64::from(mem.read_u32(BASE + 0x104).unwrap());
    let (header, iovec, data, control) = (BASE + 0x200, BASE + 0x240, BASE + 0x280, BASE + 0x2c0);
    mem.write(data, b"T").unwrap();
    mem.write(iovec, &data.to_le_bytes()).unwrap();
    mem.write(iovec + 8, &1u64.to_le_bytes()).unwrap();
    mem.write(control, &20u64.to_le_bytes()).unwrap();
    mem.write(control + 8, &1u32.to_le_bytes()).unwrap();
    mem.write(control + 12, &1u32.to_le_bytes()).unwrap();
    mem.write(control + 16, &(timer as u32).to_le_bytes())
        .unwrap();
    for (offset, value) in [
        (0, 0),
        (8, 0),
        (16, iovec),
        (24, 1),
        (32, control),
        (40, 24),
        (48, 0),
    ] {
        mem.write(header + offset, &value.to_le_bytes()).unwrap();
    }
    assert_eq!(
        call(
            &k,
            &mut cx,
            &mut mem,
            &mut vcpu,
            Sysno::Sendmsg,
            [sender, header, 0, 0, 0, 0]
        ),
        1
    );
    assert_eq!(
        call(
            &k,
            &mut cx,
            &mut mem,
            &mut vcpu,
            Sysno::Close,
            [timer, 0, 0, 0, 0, 0]
        ),
        0
    );
    k.prepare_time(Some(&mut cx.cur));
    assert_eq!(
        k.clock.next_deadline(),
        Some(10),
        "in-flight rights retain the armed timer"
    );
    k.clock.advance_to(10);
    k.prepare_time(Some(&mut cx.cur));
    mem.write(header + 40, &24u64.to_le_bytes()).unwrap();
    assert_eq!(
        call(
            &k,
            &mut cx,
            &mut mem,
            &mut vcpu,
            Sysno::Recvmsg,
            [receiver, header, 0, 0, 0, 0]
        ),
        1
    );
    let received_timer = u64::from(mem.read_u32(control + 16).unwrap());
    assert_eq!(
        call(
            &k,
            &mut cx,
            &mut mem,
            &mut vcpu,
            Sysno::Read,
            [received_timer, BASE + 0x300, 8, 0, 0, 0]
        ),
        8
    );
    assert_eq!(mem.read_u64(BASE + 0x300).unwrap(), 1);
    // Rearm a periodic timer to prove final close cancels a future event too.
    timespec(&mut mem, BASE, 5);
    timespec(&mut mem, BASE + 16, 5);
    assert_eq!(
        call(
            &k,
            &mut cx,
            &mut mem,
            &mut vcpu,
            Sysno::TimerfdSettime,
            [received_timer, 0, BASE, 0, 0, 0]
        ),
        0
    );
    k.prepare_time(Some(&mut cx.cur));
    assert_eq!(k.clock.next_deadline(), Some(15));
    assert_eq!(
        call(
            &k,
            &mut cx,
            &mut mem,
            &mut vcpu,
            Sysno::Close,
            [received_timer, 0, 0, 0, 0, 0]
        ),
        0
    );
    k.prepare_time(Some(&mut cx.cur));
    assert_eq!(k.clock.next_deadline(), None);
    // Rights destined for a closed reader cannot keep a timer alive.
    let discarded = call(
        &k,
        &mut cx,
        &mut mem,
        &mut vcpu,
        Sysno::TimerfdCreate,
        [1, 0, 0, 0, 0, 0],
    ) as u64;
    assert_eq!(
        call(
            &k,
            &mut cx,
            &mut mem,
            &mut vcpu,
            Sysno::TimerfdSettime,
            [discarded, 0, BASE, 0, 0, 0]
        ),
        0
    );
    mem.write(control + 16, &(discarded as u32).to_le_bytes())
        .unwrap();
    assert_eq!(
        call(
            &k,
            &mut cx,
            &mut mem,
            &mut vcpu,
            Sysno::Sendmsg,
            [sender, header, 0, 0, 0, 0]
        ),
        1
    );
    assert_eq!(
        call(
            &k,
            &mut cx,
            &mut mem,
            &mut vcpu,
            Sysno::Close,
            [discarded, 0, 0, 0, 0, 0]
        ),
        0
    );
    k.prepare_time(Some(&mut cx.cur));
    assert_eq!(k.clock.next_deadline(), Some(15));
    assert_eq!(
        call(
            &k,
            &mut cx,
            &mut mem,
            &mut vcpu,
            Sysno::Close,
            [receiver, 0, 0, 0, 0, 0]
        ),
        0
    );
    k.prepare_time(Some(&mut cx.cur));
    assert_eq!(
        k.clock.next_deadline(),
        None,
        "discarded rights cancel their timer"
    );
}

#[test]
fn stopped_task_retains_its_timerfd_reference() {
    let (k, mut mem, mut vcpu, mut cx) = setup();
    let timer = call(
        &k,
        &mut cx,
        &mut mem,
        &mut vcpu,
        Sysno::TimerfdCreate,
        [1, 0, 0, 0, 0, 0],
    ) as u64;
    timespec(&mut mem, BASE, 0);
    timespec(&mut mem, BASE + 16, 10);
    assert_eq!(
        call(
            &k,
            &mut cx,
            &mut mem,
            &mut vcpu,
            Sysno::TimerfdSettime,
            [timer, 0, BASE, 0, 0, 0]
        ),
        0
    );
    remember_task(&k, &cx);
    k.shared.lock().unwrap().procs[0].as_mut().unwrap().info.run = super::RunState::Stopped(19);
    k.prepare_time(None);
    assert_eq!(k.clock.next_deadline(), Some(10));
    k.clock.advance_to(10);
    k.prepare_time(None);
    cx.cur = k.shared.lock().unwrap().procs.pop().unwrap().unwrap().info;
    cx.cur.run = super::RunState::Running; // SIGCONT preserves descriptors.
    assert_eq!(
        call(
            &k,
            &mut cx,
            &mut mem,
            &mut vcpu,
            Sysno::Read,
            [timer, BASE + 0x100, 8, 0, 0, 0]
        ),
        8
    );
    assert_eq!(mem.read_u64(BASE + 0x100).unwrap(), 1);
}
