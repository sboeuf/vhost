// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Virtio Vhost Backend Drivers
//!
//! Virtio devices use virtqueues to transport data efficiently. Virtqueue is a set of three
//! different single-producer, single-consumer ring structures designed to store generic
//! scatter-gather I/O.
//!
//! Vhost is a protocol for devices accessible via inter-process communication. It uses the same
//! virtqueue layout as Virtio to allow Vhost devices to be mapped directly to Virtio devices.
//! This allows a Vhost device to be accessed directly by a guest OS inside a hypervisor process
//! with an existing Virtio (PCI) driver. Only the configuration, I/O submission notification,
//! and I/O completion interruption are piped through the hypervisor.
//!
//! The initial vhost implementation is a part of the Linux kernel and uses ioctl interface to
//! communicate with userspace applications. Later Vhost-user protocol is introduced to complement
//! the ioctl interface used to control the vhost implementation in the Linux kernel. It implements
//! the control plane needed to establish virtqueue sharing with a user space process on the same
//! host. It uses communication over a Unix domain socket to share file descriptors in the
//! ancillary data of the message. The protocol defines 2 sides of the communication, master and
//! slave. Master is the application that shares its virtqueues. Slave is the consumer of the
//! virtqueues. Master and slave can be either a client (i.e. connecting) or server (listening)
//! in the socket communication.

#![deny(missing_docs)]

#[cfg_attr(
    any(feature = "vhost-user-master", feature = "vhost-user-slave"),
    macro_use
)]
extern crate bitflags;
extern crate libc;
#[cfg(feature = "vhost-kern")]
extern crate vm_memory;
#[cfg_attr(feature = "vhost-kern", macro_use)]
extern crate vmm_sys_util;

pub mod backend;
#[cfg(feature = "vhost-kern")]
pub mod vhost_kern;
#[cfg(any(feature = "vhost-user-master", feature = "vhost-user-slave"))]
pub mod vhost_user;
#[cfg(feature = "vhost-vsock")]
pub mod vsock;
