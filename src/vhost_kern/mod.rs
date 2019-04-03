// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Traits and Structs to control Linux in-kernel vhost drivers.
//!
//! The initial vhost implementation is a part of the Linux kernel and uses ioctl interface to
//! communicate with userspace applications. This sub module provides ioctl based interfaces to
//! control the in-kernel net, scsi, vsock vhost drivers.

use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr::null;

use vm_memory::{Address, GuestAddress, GuestMemory, GuestUsize};
use vmm_sys_util::ioctl::{ioctl, ioctl_with_mut_ref, ioctl_with_ptr, ioctl_with_ref};
use vmm_sys_util::EventFd;

use crate::backend::{
    Error, Result, VhostBackend, VhostUserMemoryRegionInfo, VringConfigData,
    VHOST_MAX_MEMORY_REGIONS,
};

pub mod vhost_binding;
use self::vhost_binding::*;

fn ioctl_error<T>() -> Result<T> {
    Err(Error::IoctlError(std::io::Error::last_os_error()))
}

    fn guest_addr(addr: u64) -> GuestAddress {
        GuestAddress::new(addr)
    }

/// Represent an in-kernel vhost device backend.
pub trait VhostKernBackend<'a>: AsRawFd {
    /// Associated type to access the guest's memory.
    type M: GuestMemory<'a>;

    /// Get the object to access the guest's memory.
    fn mem(&self) -> &Self::M;

    /// Check whether the ring configuration is valid.
    #[allow(clippy::if_same_then_else)]
    #[allow(clippy::needless_bool)]
    fn is_valid(
        &self,
        queue_max_size: u16,
        queue_size: u16,
        desc_addr: GuestAddress,
        avail_addr: GuestAddress,
        used_addr: GuestAddress,
    ) -> bool {
        let desc_table_size = 16 * u64::from(queue_size) as GuestUsize;
        let avail_ring_size = 6 + 2 * u64::from(queue_size) as GuestUsize;
        let used_ring_size = 6 + 8 * u64::from(queue_size) as GuestUsize;
        if queue_size > queue_max_size || queue_size == 0 || (queue_size & (queue_size - 1)) != 0 {
            false
        } else if desc_addr
            .checked_add(desc_table_size)
            .map_or(true, |v| !self.mem().address_in_range(v))
        {
            false
        } else if avail_addr
            .checked_add(avail_ring_size)
            .map_or(true, |v| !self.mem().address_in_range(v))
        {
            false
        } else if used_addr
            .checked_add(used_ring_size)
            .map_or(true, |v| !self.mem().address_in_range(v))
        {
            false
        } else {
            true
        }
    }
}

impl<'a, T: VhostKernBackend<'a>> VhostBackend for T {
    /// Set the current process as the owner of this file descriptor.
    /// This must be run before any other vhost ioctls.
    fn set_owner(&mut self) -> Result<()> {
        // This ioctl is called on a valid vhost fd and has its return value checked.
        let ret = unsafe { ioctl(self, VHOST_SET_OWNER()) };
        if ret < 0 {
            return ioctl_error();
        }
        Ok(())
    }

    fn reset_owner(&mut self) -> Result<()> {
        // This ioctl is called on a valid vhost fd and has its return value checked.
        let ret = unsafe { ioctl(self, VHOST_RESET_OWNER()) };
        if ret < 0 {
            return ioctl_error();
        }
        Ok(())
    }

    /// Get a bitmask of supported virtio/vhost features.
    fn get_features(&mut self) -> Result<u64> {
        let mut avail_features: u64 = 0;
        // This ioctl is called on a valid vhost fd and has its return value checked.
        let ret = unsafe { ioctl_with_mut_ref(self, VHOST_GET_FEATURES(), &mut avail_features) };
        if ret < 0 {
            return ioctl_error();
        }
        Ok(avail_features)
    }

    /// Inform the vhost subsystem which features to enable. This should be a subset of
    /// supported features from VHOST_GET_FEATURES.
    ///
    /// # Arguments
    /// * `features` - Bitmask of features to set.
    fn set_features(&mut self, features: u64) -> Result<()> {
        // This ioctl is called on a valid vhost fd and has its return value checked.
        let ret = unsafe { ioctl_with_ref(self, VHOST_SET_FEATURES(), &features) };
        if ret < 0 {
            return ioctl_error();
        }
        Ok(())
    }

    /// Set the guest memory mappings for vhost to use.
    fn set_mem_table(&mut self, regions: &[VhostUserMemoryRegionInfo]) -> Result<()> {
        if regions.is_empty() || regions.len() > VHOST_MAX_MEMORY_REGIONS {
            return Err(Error::InvalidGuestMemory);
        }

        let num_regions = regions.len();
        // Allocate enough space to correctly align the vhost_memory struct
        let vec_size_bytes = mem::align_of::<vhost_memory>()
            + mem::size_of::<vhost_memory>()
            + (num_regions * mem::size_of::<vhost_memory_region>());
        let mut bytes: Vec<u8> = vec![0; vec_size_bytes];

        // Convert bytes pointer to a vhost_memory mut ref. The vector has been
        // sized correctly to ensure it can hold vhost_memory and N regions.
        let (_, vhost_memory, _) = unsafe { bytes.align_to_mut::<vhost_memory>() };
        vhost_memory[0].nregions = num_regions as u32;

        {
            // Safe because enough memory have been allocated for the regions.
            // regions is a zero-length array, so taking a mut slice requires that
            // we correctly specify the size to match the amount of backing memory.
            let vhost_regions =
                unsafe { vhost_memory[0].regions.as_mut_slice(num_regions as usize) };

            for (index, region) in regions.iter().enumerate() {
                vhost_regions[index] = vhost_memory_region {
                    guest_phys_addr: region.guest_phys_addr,
                    memory_size: region.memory_size,
                    userspace_addr: region.userspace_addr,
                    flags_padding: 0u64,
                };
            }
        }

        // This ioctl is called with a pointer that is valid for the lifetime
        // of this function. The kernel will make its own copy of the memory
        // tables. As always, check the return value.
        let ret = unsafe { ioctl_with_ptr(self, VHOST_SET_MEM_TABLE(), vhost_memory.as_ptr()) };
        if ret < 0 {
            return ioctl_error();
        }
        Ok(())
    }

    /// Set base address for page modification logging.
    ///
    /// # Arguments
    /// * `base` - Base address for page modification logging.
    fn set_log_base(&mut self, base: u64, fd: Option<RawFd>) -> Result<()> {
        if fd.is_some() {
            return Err(Error::LogAddress);
        }

        // This ioctl is called on a valid vhost fd and has its return value checked.
        let ret = unsafe { ioctl_with_ref(self, VHOST_SET_LOG_BASE(), &base) };
        if ret < 0 {
            return ioctl_error();
        }
        Ok(())
    }

    /// Specify an eventfd file descriptor to signal on log write.
    fn set_log_fd(&mut self, fd: RawFd) -> Result<()> {
        // This ioctl is called on a valid vhost fd and has its return value checked.
        let val: i32 = fd;
        let ret = unsafe { ioctl_with_ref(self, VHOST_SET_LOG_FD(), &val) };
        if ret < 0 {
            return ioctl_error();
        }
        Ok(())
    }

    /// Set the number of descriptors in the vring.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to set descriptor count for.
    /// * `num` - Number of descriptors in the queue.
    fn set_vring_num(&mut self, queue_index: usize, num: u16) -> Result<()> {
        let vring_state = vhost_vring_state {
            index: queue_index as u32,
            num: u32::from(num),
        };

        // This ioctl is called on a valid vhost fd and has its return value checked.
        let ret = unsafe { ioctl_with_ref(self, VHOST_SET_VRING_NUM(), &vring_state) };
        if ret < 0 {
            return ioctl_error();
        }
        Ok(())
    }

    /// Set the addresses for a given vring.
    ///
    /// # Arguments
    /// * `queue_max_size` - Maximum queue size supported by the device.
    /// * `queue_size` - Actual queue size negotiated by the driver.
    /// * `queue_index` - Index of the queue to set addresses for.
    /// * `flags` - Bitmask of vring flags.
    /// * `desc_table_addr` - Descriptor table address.
    /// * `used_ring_addr` - Used ring buffer address.
    /// * `avail_ring_addr` - Available ring buffer address.
    /// * `log_addr` - Optional address for logging.
    fn set_vring_addr(&mut self, queue_index: usize, config_data: &VringConfigData) -> Result<()> {
        if !self.is_valid(
            config_data.queue_max_size,
            config_data.queue_size,
            guest_addr(config_data.desc_table_addr),
            guest_addr(config_data.used_ring_addr),
            guest_addr(config_data.avail_ring_addr),
        ) {
            return Err(Error::InvalidQueue);
        }

        let desc_addr = self
            .mem()
            .get_host_address(guest_addr(config_data.desc_table_addr))
            .ok_or(Error::DescriptorTableAddress)?;
        let used_addr = self
            .mem()
            .get_host_address(guest_addr(config_data.used_ring_addr))
            .ok_or(Error::UsedAddress)?;
        let avail_addr = self
            .mem()
            .get_host_address(guest_addr(config_data.avail_ring_addr))
            .ok_or(Error::AvailAddress)?;
        let log_addr = match config_data.log_addr {
            None => null(),
            Some(a) => self.mem().get_host_address(guest_addr(a)).ok_or(Error::LogAddress)?,
        };

        let vring_addr = vhost_vring_addr {
            index: queue_index as u32,
            flags: config_data.flags,
            desc_user_addr: desc_addr as u64,
            used_user_addr: used_addr as u64,
            avail_user_addr: avail_addr as u64,
            log_guest_addr: log_addr as u64,
        };

        // This ioctl is called on a valid vhost fd and has its
        // return value checked.
        let ret = unsafe { ioctl_with_ref(self, VHOST_SET_VRING_ADDR(), &vring_addr) };
        if ret < 0 {
            return ioctl_error();
        }
        Ok(())
    }

    /// Set the first index to look for available descriptors.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `num` - Index where available descriptors start.
    fn set_vring_base(&mut self, queue_index: usize, base: u16) -> Result<()> {
        let vring_state = vhost_vring_state {
            index: queue_index as u32,
            num: u32::from(base),
        };

        // This ioctl is called on a valid vhost fd and has its return value checked.
        let ret = unsafe { ioctl_with_ref(self, VHOST_SET_VRING_BASE(), &vring_state) };
        if ret < 0 {
            return ioctl_error();
        }
        Ok(())
    }

    /// Get a bitmask of supported virtio/vhost features.
    fn get_vring_base(&mut self, queue_index: usize) -> Result<u32> {
        let vring_state = vhost_vring_state {
            index: queue_index as u32,
            num: 0,
        };
        // This ioctl is called on a valid vhost fd and has its return value checked.
        let ret = unsafe { ioctl_with_ref(self, VHOST_GET_VRING_BASE(), &vring_state) };
        if ret < 0 {
            return ioctl_error();
        }
        Ok(vring_state.num)
    }

    /// Set the eventfd to trigger when buffers have been used by the host.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `fd` - EventFd to trigger.
    fn set_vring_call(&mut self, queue_index: usize, fd: &EventFd) -> Result<()> {
        let vring_file = vhost_vring_file {
            index: queue_index as u32,
            fd: fd.as_raw_fd(),
        };

        // This ioctl is called on a valid vhost fd and has its return value checked.
        let ret = unsafe { ioctl_with_ref(self, VHOST_SET_VRING_CALL(), &vring_file) };
        if ret < 0 {
            return ioctl_error();
        }
        Ok(())
    }

    /// Set the eventfd that will be signaled by the guest when buffers are
    /// available for the host to process.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `fd` - EventFd that will be signaled from guest.
    fn set_vring_kick(&mut self, queue_index: usize, fd: &EventFd) -> Result<()> {
        let vring_file = vhost_vring_file {
            index: queue_index as u32,
            fd: fd.as_raw_fd(),
        };

        // This ioctl is called on a valid vhost fd and has its return value checked.
        let ret = unsafe { ioctl_with_ref(self, VHOST_SET_VRING_KICK(), &vring_file) };
        if ret < 0 {
            return ioctl_error();
        }
        Ok(())
    }

    /// Set the eventfd to signal an error from the vhost backend.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `fd` - EventFd that will be signaled from the backend.
    fn set_vring_err(&mut self, queue_index: usize, fd: &EventFd) -> Result<()> {
        let vring_file = vhost_vring_file {
            index: queue_index as u32,
            fd: fd.as_raw_fd(),
        };

        // This ioctl is called on a valid vhost fd and has its return value checked.
        let ret = unsafe { ioctl_with_ref(self, VHOST_SET_VRING_ERR(), &vring_file) };
        if ret < 0 {
            return ioctl_error();
        }
        Ok(())
    }
}
