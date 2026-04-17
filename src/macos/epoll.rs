// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2021 Sergio Lopez. All rights reserved.
// Copyright 2026 Proofpoint, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Adapted from the libkrun project, preserving its original Apache-2.0
// license. Upstream source:
//   https://github.com/containers/libkrun/blob/a3b7ae213195c9f871a17c72f0d020e46ed90584/src/utils/src/macos/epoll.rs

//! Safe wrappers emulating the Linux
//! [`epoll`](http://man7.org/linux/man-pages/man7/epoll.7.html) API using macOS kqueue.

use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr;

use bitflags::bitflags;

/// Wrapper over `EPOLL_CTL_*` operations that can be performed on a file descriptor.
#[derive(Debug)]
#[repr(i32)]
pub enum ControlOperation {
    /// Add a file descriptor to the interest list.
    Add = 1,
    /// Change the settings associated with a file descriptor that is
    /// already in the interest list.
    Modify = 3,
    /// Remove a file descriptor from the interest list.
    Delete = 2,
}

bitflags! {
    /// The type of events we can monitor a file descriptor for.
    ///
    /// Provides the same flags as the Linux epoll API, mapped to kqueue equivalents.
    pub struct EventSet: u32 {
        /// The associated file descriptor is available for read operations.
        const IN = 0x001;
        /// The associated file descriptor is available for write operations.
        const OUT = 0x004;
        /// Error condition happened on the associated file descriptor.
        const ERROR = 0x008;
        /// This can be used to detect peer shutdown when using Edge Triggered monitoring.
        /// Note: kqueue always reports EV_EOF; this is mapped from that.
        const READ_HANG_UP = 0x2000;
        /// Sets the Edge Triggered behavior for the associated file descriptor.
        const EDGE_TRIGGERED = (1 << 31);
        /// Hang up happened on the associated file descriptor.
        const HANG_UP = 0x010;
        /// There is an exceptional condition on that file descriptor.
        const PRIORITY = 0x002;
        /// The event is considered as being "processed".
        const WAKE_UP = (1 << 29);
        /// Sets the one-shot behavior for the associated file descriptor.
        const ONE_SHOT = (1 << 30);
        /// Sets an exclusive wake up mode.
        const EXCLUSIVE = (1 << 28);
    }
}

/// Wrapper over an epoll event, backed by kqueue on macOS.
///
/// Fields are public to match the Linux `epoll_event` struct layout,
/// which is accessed directly by consumers via `Deref`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct EpollEvent {
    /// Event mask (combination of `EventSet` bits).
    pub events: u32,
    /// User data associated with this event.
    pub u64: u64,
}

impl std::fmt::Debug for EpollEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ events: {}, data: {} }}", self.events(), self.data())
    }
}

impl EpollEvent {
    /// Create a new EpollEvent instance.
    ///
    /// # Arguments
    ///
    /// `events` - contains an event mask.
    /// `data` - a user data variable.
    pub fn new(events: EventSet, data: u64) -> Self {
        EpollEvent {
            events: events.bits(),
            u64: data,
        }
    }

    /// Returns the raw events bitmask.
    pub fn events(&self) -> u32 {
        self.events
    }

    /// Returns the `EventSet` corresponding to the events.
    ///
    /// # Panics
    ///
    /// Panics if the events contain invalid bits.
    pub fn event_set(&self) -> EventSet {
        EventSet::from_bits(self.events()).unwrap()
    }

    /// Returns the user data value.
    pub fn data(&self) -> u64 {
        self.u64
    }

    /// Converts the data to a RawFd.
    ///
    /// This conversion is lossy when the data does not correspond to a RawFd.
    pub fn fd(&self) -> RawFd {
        self.u64 as i32
    }
}

/// Wrapper over epoll functionality, backed by kqueue on macOS.
#[derive(Debug)]
pub struct Epoll {
    kqueue_fd: RawFd,
}

impl Epoll {
    /// Create a new epoll-like instance backed by kqueue.
    pub fn new() -> io::Result<Self> {
        // SAFETY: kqueue() is safe and we check the return value.
        let kqueue_fd = unsafe { libc::kqueue() };
        if kqueue_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Epoll { kqueue_fd })
    }

    /// Register, modify, or remove interest in events for a file descriptor.
    ///
    /// Maps epoll_ctl semantics to kqueue kevent operations.
    ///
    /// Note: `READ_HANG_UP` (`EPOLLRDHUP`) registration is ignored since kqueue
    /// always reports `EV_EOF` on read hang-up. `wait()` will include
    /// `READ_HANG_UP` in returned events when EOF is detected on a read filter.
    pub fn ctl(&self, operation: ControlOperation, fd: RawFd, event: EpollEvent) -> io::Result<()> {
        let eset = EventSet::from_bits(event.events).unwrap_or(EventSet::empty());

        match operation {
            ControlOperation::Add | ControlOperation::Modify => {
                if matches!(operation, ControlOperation::Modify) {
                    // Linux `epoll_ctl(EPOLL_CTL_MOD)` replaces the event mask
                    // and user data for `fd`. kqueue has no equivalent single
                    // operation: `EV_ADD` on an existing filter updates its
                    // flags and udata, but leaves the unrelated filter
                    // (`EVFILT_READ` vs `EVFILT_WRITE`) registered from a
                    // prior `Add`. Clear both filters first so the subsequent
                    // `EV_ADD` calls below are the only registrations that
                    // remain for this fd.
                    let del_kevs = [
                        libc::kevent {
                            ident: fd as usize,
                            filter: libc::EVFILT_READ,
                            flags: libc::EV_DELETE,
                            fflags: 0,
                            data: 0,
                            udata: ptr::null_mut(),
                        },
                        libc::kevent {
                            ident: fd as usize,
                            filter: libc::EVFILT_WRITE,
                            flags: libc::EV_DELETE,
                            fflags: 0,
                            data: 0,
                            udata: ptr::null_mut(),
                        },
                    ];
                    // SAFETY: We provide a valid kqueue fd and a valid kevent
                    // array; errors are ignored because a filter that was
                    // never registered returns `ENOENT`, which is expected.
                    let _ = unsafe {
                        libc::kevent(
                            self.kqueue_fd,
                            del_kevs.as_ptr(),
                            del_kevs.len() as i32,
                            ptr::null_mut(),
                            0,
                            ptr::null(),
                        )
                    };
                }

                let mut kevs: Vec<libc::kevent> = Vec::new();
                let mut flags: u16 = libc::EV_ADD;
                if eset.contains(EventSet::EDGE_TRIGGERED) {
                    flags |= libc::EV_CLEAR;
                }
                if eset.contains(EventSet::ONE_SHOT) {
                    flags |= libc::EV_ONESHOT;
                }

                if eset.contains(EventSet::IN) || eset.contains(EventSet::READ_HANG_UP) {
                    kevs.push(libc::kevent {
                        ident: fd as usize,
                        filter: libc::EVFILT_READ,
                        flags,
                        fflags: 0,
                        data: 0,
                        udata: event.u64 as *mut libc::c_void,
                    });
                }
                if eset.contains(EventSet::OUT) {
                    kevs.push(libc::kevent {
                        ident: fd as usize,
                        filter: libc::EVFILT_WRITE,
                        flags,
                        fflags: 0,
                        data: 0,
                        udata: event.u64 as *mut libc::c_void,
                    });
                }

                if kevs.is_empty() {
                    return Ok(());
                }

                // SAFETY: We provide valid kqueue fd, valid kevent array, and check return.
                let ret = unsafe {
                    libc::kevent(
                        self.kqueue_fd,
                        kevs.as_ptr(),
                        kevs.len() as i32,
                        ptr::null_mut(),
                        0,
                        ptr::null(),
                    )
                };
                if ret < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            ControlOperation::Delete => {
                let eset = EventSet::from_bits(event.events).unwrap_or(EventSet::empty());
                let mut kevs: Vec<libc::kevent> = Vec::new();

                // If no specific events, remove both read and write filters.
                if eset.is_empty() {
                    kevs.push(libc::kevent {
                        ident: fd as usize,
                        filter: libc::EVFILT_READ,
                        flags: libc::EV_DELETE,
                        fflags: 0,
                        data: 0,
                        udata: ptr::null_mut(),
                    });
                    kevs.push(libc::kevent {
                        ident: fd as usize,
                        filter: libc::EVFILT_WRITE,
                        flags: libc::EV_DELETE,
                        fflags: 0,
                        data: 0,
                        udata: ptr::null_mut(),
                    });
                } else {
                    if eset.contains(EventSet::IN) {
                        kevs.push(libc::kevent {
                            ident: fd as usize,
                            filter: libc::EVFILT_READ,
                            flags: libc::EV_DELETE,
                            fflags: 0,
                            data: 0,
                            udata: ptr::null_mut(),
                        });
                    }
                    if eset.contains(EventSet::OUT) {
                        kevs.push(libc::kevent {
                            ident: fd as usize,
                            filter: libc::EVFILT_WRITE,
                            flags: libc::EV_DELETE,
                            fflags: 0,
                            data: 0,
                            udata: ptr::null_mut(),
                        });
                    }
                }

                // Ignore errors on delete - the fd may not be registered for all filters.
                // SAFETY: We provide a valid kqueue fd and a valid kevent array; the
                // return value is intentionally discarded because an `EV_DELETE` on a
                // filter that was never registered returns `ENOENT`, which is not an
                // error for our purposes.
                let _ = unsafe {
                    libc::kevent(
                        self.kqueue_fd,
                        kevs.as_ptr(),
                        kevs.len() as i32,
                        ptr::null_mut(),
                        0,
                        ptr::null(),
                    )
                };
            }
        }
        Ok(())
    }

    /// Wait for events, similar to `epoll_wait`.
    ///
    /// Returns the number of ready file descriptors.
    ///
    /// # Arguments
    ///
    /// * `timeout` - timeout in milliseconds. -1 for infinite wait.
    /// * `events` - buffer to store ready events.
    pub fn wait(&self, timeout: i32, events: &mut [EpollEvent]) -> io::Result<usize> {
        let ts = if timeout >= 0 {
            libc::timespec {
                tv_sec: (timeout / 1000) as libc::time_t,
                tv_nsec: ((timeout % 1000) as libc::c_long) * 1_000_000,
            }
        } else {
            // For infinite wait, we still need a timespec pointer.
            // Pass null below for infinite wait.
            libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }
        };

        let ts_ptr = if timeout >= 0 {
            &ts as *const libc::timespec
        } else {
            ptr::null()
        };

        let max_events = events.len();
        let mut kevs = vec![
            libc::kevent {
                ident: 0,
                filter: 0,
                flags: 0,
                fflags: 0,
                data: 0,
                udata: ptr::null_mut(),
            };
            max_events
        ];

        // SAFETY: We provide a valid kqueue fd, a valid kevent array, and check return.
        let ret = unsafe {
            libc::kevent(
                self.kqueue_fd,
                ptr::null(),
                0,
                kevs.as_mut_ptr(),
                max_events as i32,
                ts_ptr,
            )
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        let nevents = ret as usize;

        for i in 0..nevents {
            let kev = &kevs[i];
            let mut event_bits = EventSet::empty();

            match kev.filter {
                libc::EVFILT_READ => {
                    event_bits |= EventSet::IN;
                    if kev.flags & libc::EV_EOF != 0 {
                        event_bits |= EventSet::READ_HANG_UP;
                    }
                }
                libc::EVFILT_WRITE => {
                    event_bits |= EventSet::OUT;
                    if kev.flags & libc::EV_EOF != 0 {
                        event_bits |= EventSet::HANG_UP;
                    }
                }
                _ => {}
            }

            if kev.flags & libc::EV_ERROR != 0 {
                event_bits |= EventSet::ERROR;
            }

            events[i] = EpollEvent {
                events: event_bits.bits(),
                u64: kev.udata as u64,
            };
        }

        Ok(nevents)
    }
}

impl AsRawFd for Epoll {
    fn as_raw_fd(&self) -> RawFd {
        self.kqueue_fd
    }
}

impl Drop for Epoll {
    fn drop(&mut self) {
        // SAFETY: fd was opened with kqueue() and is valid.
        unsafe {
            libc::close(self.kqueue_fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::eventfd::{EventFd, EFD_NONBLOCK};

    #[test]
    fn test_event_ops() {
        let mut event = EpollEvent::default();
        assert_eq!(event.events(), 0);
        assert_eq!(event.data(), 0);

        event = EpollEvent::new(EventSet::IN, 2);
        assert_eq!(event.events(), EventSet::IN.bits());
        assert_eq!(event.event_set(), EventSet::IN);

        assert_eq!(event.data(), 2);
        assert_eq!(event.fd(), 2);
    }

    #[test]
    fn test_events_debug() {
        let events = EpollEvent::new(EventSet::IN, 42);
        assert_eq!(format!("{:?}", events), "{ events: 1, data: 42 }")
    }

    #[test]
    fn test_epoll() {
        const DEFAULT_TIMEOUT: i32 = 250;
        const EVENT_BUFFER_SIZE: usize = 128;

        let epoll = Epoll::new().unwrap();

        let event_fd_1 = EventFd::new(EFD_NONBLOCK).unwrap();
        event_fd_1.write(1).unwrap();

        let event_1 = EpollEvent::new(EventSet::IN, event_fd_1.as_raw_fd() as u64);

        assert!(epoll
            .ctl(ControlOperation::Add, event_fd_1.as_raw_fd(), event_1)
            .is_ok());

        let event_fd_2 = EventFd::new(EFD_NONBLOCK).unwrap();
        event_fd_2.write(1).unwrap();
        assert!(epoll
            .ctl(
                ControlOperation::Add,
                event_fd_2.as_raw_fd(),
                EpollEvent::new(EventSet::IN, 10)
            )
            .is_ok());

        let mut ready_events = vec![EpollEvent::default(); EVENT_BUFFER_SIZE];
        let ev_count = epoll.wait(DEFAULT_TIMEOUT, &mut ready_events[..]).unwrap();

        assert_eq!(ev_count, 2);
        assert_eq!(ready_events[0].data(), event_fd_1.as_raw_fd() as u64);
        assert_eq!(ready_events[1].data(), 10);

        assert_eq!(ready_events[0].events(), EventSet::IN.bits());
        assert_eq!(ready_events[1].events(), EventSet::IN.bits());

        // Delete a fd from the interest list.
        assert!(epoll
            .ctl(
                ControlOperation::Delete,
                event_fd_2.as_raw_fd(),
                EpollEvent::default()
            )
            .is_ok());

        let ev_count = epoll.wait(DEFAULT_TIMEOUT, &mut ready_events[..]).unwrap();
        assert_eq!(ev_count, 1);
        assert_eq!(ready_events[0].data(), event_fd_1.as_raw_fd() as u64);
        assert_eq!(ready_events[0].events(), EventSet::IN.bits());
    }

    #[test]
    fn test_epoll_modify() {
        const DEFAULT_TIMEOUT: i32 = 250;
        const EVENT_BUFFER_SIZE: usize = 8;

        let epoll = Epoll::new().unwrap();
        let event_fd = EventFd::new(EFD_NONBLOCK).unwrap();
        event_fd.write(1).unwrap();

        epoll
            .ctl(
                ControlOperation::Add,
                event_fd.as_raw_fd(),
                EpollEvent::new(EventSet::IN, 11),
            )
            .unwrap();

        let mut ready_events = vec![EpollEvent::default(); EVENT_BUFFER_SIZE];
        let ev_count = epoll.wait(DEFAULT_TIMEOUT, &mut ready_events[..]).unwrap();
        assert_eq!(ev_count, 1);
        assert_eq!(ready_events[0].data(), 11);
        assert_eq!(ready_events[0].events(), EventSet::IN.bits());

        // Modify the registration to carry a new user data value.
        epoll
            .ctl(
                ControlOperation::Modify,
                event_fd.as_raw_fd(),
                EpollEvent::new(EventSet::IN, 42),
            )
            .unwrap();

        let ev_count = epoll.wait(DEFAULT_TIMEOUT, &mut ready_events[..]).unwrap();
        assert_eq!(ev_count, 1);
        assert_eq!(ready_events[0].data(), 42);
        assert_eq!(ready_events[0].events(), EventSet::IN.bits());

        // Modify again to remove all interest; the next wait must not
        // return the previously registered read event.
        epoll
            .ctl(
                ControlOperation::Modify,
                event_fd.as_raw_fd(),
                EpollEvent::default(),
            )
            .unwrap();

        let ev_count = epoll.wait(DEFAULT_TIMEOUT, &mut ready_events[..]).unwrap();
        assert_eq!(ev_count, 0);
    }

    #[test]
    fn test_epoll_timeout() {
        const TIMEOUT_MS: i32 = 100;
        let epoll = Epoll::new().unwrap();
        let mut ready_events = vec![EpollEvent::default(); 4];
        let ev_count = epoll.wait(TIMEOUT_MS, &mut ready_events[..]).unwrap();
        assert_eq!(ev_count, 0);
    }

    // The following tests pin macOS-specific semantics that deliberately
    // diverge from the Linux `epoll_ctl` contract. The kqueue-backed
    // implementation does not track registration state itself; it relies
    // on the kernel's kqueue behavior, which is more permissive than
    // Linux's epoll. These tests exist to:
    //   1. make the divergence visible to reviewers, and
    //   2. catch any future change that silently starts rejecting these
    //      operations (which would break downstream callers that rely on
    //      the current permissive behavior).

    #[test]
    fn test_add_is_idempotent() {
        // Linux `epoll_ctl(EPOLL_CTL_ADD)` returns EEXIST when the fd is
        // already in the interest list. kqueue's `EV_ADD` is idempotent
        // and updates `udata`/flags on an existing filter, so the second
        // `Add` below succeeds and effectively re-registers the filter.
        let epoll = Epoll::new().unwrap();
        let event_fd = EventFd::new(EFD_NONBLOCK).unwrap();
        let ev = EpollEvent::new(EventSet::IN, event_fd.as_raw_fd() as u64);
        epoll
            .ctl(ControlOperation::Add, event_fd.as_raw_fd(), ev)
            .unwrap();
        epoll
            .ctl(ControlOperation::Add, event_fd.as_raw_fd(), ev)
            .unwrap();
    }

    #[test]
    fn test_modify_unregistered_succeeds() {
        // Linux `epoll_ctl(EPOLL_CTL_MOD)` returns ENOENT when the fd is
        // not in the interest list. Our `Modify` always issues a delete
        // pass (whose errors are ignored) followed by `EV_ADD`, so it
        // behaves like `Add` when the fd was never registered.
        let epoll = Epoll::new().unwrap();
        let event_fd = EventFd::new(EFD_NONBLOCK).unwrap();
        epoll
            .ctl(
                ControlOperation::Modify,
                event_fd.as_raw_fd(),
                EpollEvent::new(EventSet::IN, event_fd.as_raw_fd() as u64),
            )
            .unwrap();
    }

    #[test]
    fn test_delete_unregistered_succeeds() {
        // Linux `epoll_ctl(EPOLL_CTL_DEL)` returns ENOENT when the fd is
        // not in the interest list. Our `Delete` intentionally swallows
        // kevent errors: with two filters (`EVFILT_READ` + `EVFILT_WRITE`)
        // per fd, a partial registration would otherwise always error.
        let epoll = Epoll::new().unwrap();
        let event_fd = EventFd::new(EFD_NONBLOCK).unwrap();
        epoll
            .ctl(
                ControlOperation::Delete,
                event_fd.as_raw_fd(),
                EpollEvent::default(),
            )
            .unwrap();
    }
}
