// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2021 Sergio Lopez. All rights reserved.
// Copyright 2026 Proofpoint, Inc. All rights reserved.
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)
//
// Adapted from the libkrun project, preserving its original dual
// Apache-2.0 / BSD-3-Clause license. Upstream source:
//   https://github.com/containers/libkrun/blob/a3b7ae213195c9f871a17c72f0d020e46ed90584/src/utils/src/macos/eventfd.rs

//! Structure and wrapper functions emulating
//! [`eventfd`](http://man7.org/linux/man-pages/man2/eventfd.2.html) using a pipe pair.
//!
//! macOS does not have the `eventfd` syscall, so we emulate it with `pipe()`.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

/// Equivalent to `libc::EFD_NONBLOCK` for pipe-based emulation.
pub const EFD_NONBLOCK: i32 = 1;

/// Equivalent to `libc::EFD_CLOEXEC` for pipe-based emulation.
pub const EFD_CLOEXEC: i32 = 2;

/// Equivalent to `libc::EFD_SEMAPHORE` for pipe-based emulation.
/// Note: semaphore semantics are not fully implemented; reads do not return 1.
pub const EFD_SEMAPHORE: i32 = 4;

fn set_flags(fd: RawFd, flags: i32) -> io::Result<()> {
    if flags & EFD_NONBLOCK != 0 {
        // SAFETY: fd is a valid file descriptor.
        let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if fl < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is a valid file descriptor.
        let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    if flags & EFD_CLOEXEC != 0 {
        // SAFETY: fd is a valid file descriptor.
        let fl = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if fl < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is a valid file descriptor.
        let ret = unsafe { libc::fcntl(fd, libc::F_SETFD, fl | libc::FD_CLOEXEC) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// A pipe-backed emulation of Linux
/// [`eventfd`](http://man7.org/linux/man-pages/man2/eventfd.2.html).
#[derive(Debug)]
pub struct EventFd {
    read_fd: File,
    write_fd: File,
}

impl EventFd {
    /// Create a new EventFd with an initial value.
    ///
    /// # Arguments
    ///
    /// * `flag`: Flags for the EventFd. Supports `EFD_NONBLOCK` and `EFD_CLOEXEC`.
    pub fn new(flag: i32) -> io::Result<EventFd> {
        let mut fds: [RawFd; 2] = [-1, -1];
        // SAFETY: pipe() is safe and we check the return value.
        let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        set_flags(fds[0], flag)?;
        set_flags(fds[1], flag)?;

        Ok(EventFd {
            // SAFETY: fds are valid file descriptors from pipe().
            read_fd: unsafe { File::from_raw_fd(fds[0]) },
            write_fd: unsafe { File::from_raw_fd(fds[1]) },
        })
    }

    /// Add a value to the eventfd's counter.
    ///
    /// On pipe-based emulation, this writes the 8-byte value to the pipe.
    /// If the pipe buffer is full, this returns EAGAIN (if nonblocking) or blocks.
    pub fn write(&self, v: u64) -> io::Result<()> {
        // We silently ignore EAGAIN on writes - if the pipe is full, the reader
        // will still be notified (matching eventfd overflow behavior).
        match (&self.write_fd).write_all(&v.to_ne_bytes()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Read a value from the eventfd.
    ///
    /// If nothing has been written, this returns EAGAIN (if nonblocking) or blocks.
    pub fn read(&self) -> io::Result<u64> {
        let mut buf = [0u8; std::mem::size_of::<u64>()];
        (&self.read_fd).read_exact(&mut buf)?;
        Ok(u64::from_ne_bytes(buf))
    }

    /// Clone this EventFd, duplicating both the read and write file descriptors.
    pub fn try_clone(&self) -> io::Result<EventFd> {
        Ok(EventFd {
            read_fd: self.read_fd.try_clone()?,
            write_fd: self.write_fd.try_clone()?,
        })
    }
}

impl AsRawFd for EventFd {
    fn as_raw_fd(&self) -> RawFd {
        self.read_fd.as_raw_fd()
    }
}

impl FromRawFd for EventFd {
    /// Create an EventFd from a raw file descriptor.
    ///
    /// # Safety
    ///
    /// The fd must be the read end of a pipe pair. The write end will be duplicated
    /// from the same fd, which means write operations will not work correctly unless
    /// this fd is actually an eventfd-like descriptor (e.g., a pipe read end that has
    /// a corresponding write end managed elsewhere).
    ///
    /// This is primarily provided for API compatibility. When receiving an fd from
    /// QEMU's vhost-user protocol (which sends pipe fds on macOS), the fd is the
    /// read end for kick events or the write end for call events.
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        EventFd {
            read_fd: File::from_raw_fd(fd),
            // We dup the fd for the write side. This is not ideal but maintains
            // API compatibility. In practice, vhost-user backends receive separate
            // fds for reading (kick) and writing (call).
            write_fd: File::from_raw_fd(libc::dup(fd)),
        }
    }
}

impl IntoRawFd for EventFd {
    fn into_raw_fd(self) -> RawFd {
        self.read_fd.into_raw_fd()
        // write_fd is dropped here
    }
}

#[cfg(test)]
mod tests {
    // Note: the Linux `test_write_overflow` is intentionally not mirrored
    // here. Linux `eventfd` exposes a `u64` counter whose overflow returns
    // `EAGAIN` on non-blocking writes; our pipe-backed emulation has no
    // counter (each `write` appends 8 bytes to a pipe) and also silently
    // swallows `EAGAIN` when the pipe is full (matching libkrun's
    // behavior), so the condition that test exercises cannot occur.
    use super::*;

    #[test]
    fn test_new() {
        EventFd::new(EFD_NONBLOCK).unwrap();
        EventFd::new(0).unwrap();
    }

    #[test]
    fn test_read_write() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        evt.write(55).unwrap();
        assert_eq!(evt.read().unwrap(), 55);
    }

    #[test]
    fn test_read_nothing() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let err = evt.read().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn test_clone() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let evt_clone = evt.try_clone().unwrap();
        evt.write(923).unwrap();
        assert_eq!(evt_clone.read().unwrap(), 923);
    }

    #[test]
    fn test_cloexec() {
        let evt = EventFd::new(EFD_CLOEXEC).unwrap();
        // SAFETY: fd is valid for the lifetime of `evt`.
        let flags = unsafe { libc::fcntl(evt.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }

    #[test]
    fn test_into_raw_fd() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let read_fd = evt.as_raw_fd();
        let raw = evt.into_raw_fd();
        assert_eq!(raw, read_fd);
        // SAFETY: fd is still open (ownership was transferred out of `evt`).
        unsafe {
            libc::close(raw);
        }
    }
}
