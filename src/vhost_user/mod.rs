// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The protocol for vhost-user is based on the existing implementation of
//! vhost for the Linux Kernel. The protocol defines two sides of the
//! communication, master and slave. Master is the application that shares
//! its virtqueues. Slave is the consumer of the virtqueues.
//!
//! The communication channel between the master and the slave includes two
//! sub channels. One is used to send requests from the master to the slave
//! and optional replies from the slave to the master. This sub channel is
//! created on master startup by connecting to the slave service endpoint.
//! The other is used to send requests from the slave to the master and
//! optional replies from the master to the slave. This sub channel is
//! created by the master issuing a VHOST_USER_SET_SLAVE_REQ_FD request to
//! the slave with an auxiliary file descriptor.
//!
//! Unix domain socket is used as the underlying communication channel because
//! the master needs to send file descriptors to the slave.
//!
//! Most messages that can be sent via the Unix domain socket implementing
//! vhost-user have an equivalent ioctl to the kernel implementation.

pub mod message;

mod connection;
mod sock_ctrl_msg;

use crate::backend::Error as BackendError;

#[cfg(feature = "vhost-user-master")]
mod master;
#[cfg(feature = "vhost-user-master")]
pub use self::master::{Master, VhostUserMaster};

#[cfg(feature = "vhost-user-slave")]
mod slave;
#[cfg(feature = "vhost-user-slave")]
pub use self::slave::{Slave, SlaveListener, VhostUserSlave};

/// Error codes for vhost-user protocol
#[derive(Debug)]
pub enum Error {
    /// Failure in socket read/write operations
    SocketError(std::io::Error),
    /// Failure when connecting to the slave
    ConnectFail(std::io::Error),
    /// Error conditions from the sock_ctrl_msg library
    SockCtrlMsgError(vmm_sys_util::Error),
    /// Fd array in question is too big or too small
    FdArrayCapacity,
    /// Message is too large
    OversizedMsg,
    /// Only part of a message have been sent or received successfully
    PartialMessage,
    /// Invalid message format or flags
    InvalidMessage,
    /// Invalid value in message fields
    InvalidContent,
    /// Underlying socket has been closed due to errors
    AlreadyClosed,
    /// Some parameters is invalid
    InvalidParam,
    /// Invalid operation because protocol feature is disabled
    InvalidOperation,
    /// Operation failed on slave side
    OperationFailedInSlave,
    /// Error in Slave request handler
    SlaveReqHandlerError(Box<dyn std::error::Error>),
}

impl std::convert::From<vmm_sys_util::Error> for Error {
    fn from(err: vmm_sys_util::Error) -> Self {
        Error::SockCtrlMsgError(err)
    }
}

impl std::convert::From<Error> for BackendError {
    fn from(err: Error) -> BackendError {
        BackendError::VhostUserProtocol(err)
    }
}

/// Result of vhost-user operations
pub type Result<T> = std::result::Result<T, Error>;
