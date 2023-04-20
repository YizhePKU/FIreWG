use core::{cell::RefCell, ptr::null_mut};

use alloc::vec;
use alloc::vec::Vec;

use crate::{getBuffer, getBufferSize, newNetBufferList, NetBufferList};

#[derive(Debug)]
pub struct KernelBuffer {
    nbl: *mut NetBufferList,
    storage: RefCell<Vec<u8>>,
}

impl KernelBuffer {
    // Allocate a new NBL with `size` bytes of memory.
    pub fn new(size: usize) -> Self {
        let nbl = unsafe { newNetBufferList(size) };
        let storage = vec![0; size];
        Self {
            nbl,
            storage: RefCell::new(storage),
        }
    }

    // Construct a KernelBuffer from an existing NBL.
    // `nbl` must points to a kernel-owned NBL.
    pub unsafe fn from_nbl(nbl: *mut NetBufferList) -> Self {
        let size = getBufferSize(nbl);
        let storage = vec![0; size];
        Self {
            nbl,
            storage: RefCell::new(storage),
        }
    }

    // Return the length of the underlying buffer.
    pub fn len(&self) -> usize {
        unsafe { getBufferSize(self.nbl) }
    }

    // Return a read-only view of the underlying buffer.
    // Will copy data into temporary local memory if the buffer is not contiguous.
    pub fn as_slice(&self) -> &[u8] {
        unsafe {
            // KernelBuffer is not Send/Sync, so we don't need to worry about thread safety.
            let ptr = getBuffer(self.nbl, self.storage.borrow_mut().as_mut_ptr());
            assert!(!ptr.is_null());
            core::slice::from_raw_parts(ptr, self.len())
        }
    }

    // Return a write-only view of the underlying buffer.
    // Will panic if the buffer is not contiguous.
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe {
            // Don't use the storage, as that won't be written into the NBL.
            let ptr = getBuffer(self.nbl, null_mut());
            assert!(!ptr.is_null()); // panic if the buffer is not contiguous
            core::slice::from_raw_parts_mut(ptr, self.len())
        }
    }

    // Convert back to NBL.
    // Consumes self to make sure no re-use after NBL is transferred to the kernel.
    pub fn into_nbl(self) -> *mut NetBufferList {
        self.nbl
    }
}
