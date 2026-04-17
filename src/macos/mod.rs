// Copyright 2024 rust-vmm Authors or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! macOS-specific modules providing compatibility shims for Linux APIs.
//!
//! - `eventfd`: Pipe-backed emulation of Linux eventfd.
//! - `epoll`: kqueue-backed emulation of Linux epoll.

pub mod epoll;
pub mod eventfd;
