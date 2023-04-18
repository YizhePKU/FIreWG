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
    pub fn new(size: usize) -> Self {
        let nbl = unsafe { newNetBufferList(size) };
        let storage = vec![0; size];
        Self {
            nbl,
            storage: RefCell::new(storage),
        }
    }

    pub fn from_nbl(nbl: *mut NetBufferList) -> Self {
        let size = unsafe { getBufferSize(nbl) };
        let storage = vec![0; size];
        Self {
            nbl,
            storage: RefCell::new(storage),
        }
    }

    pub fn len(&self) -> usize {
        unsafe { getBufferSize(self.nbl) }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe {
            // read data from the NBL, copying data into storage if necessary.
            // KernelBuffer is not Send/Sync, so we don't need to worry about thread safety.
            let ptr = getBuffer(self.nbl, self.storage.borrow_mut().as_mut_ptr());
            core::slice::from_raw_parts(ptr, self.len())
        }
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe {
            // write data into the NBL
            // Don't use the storage, as that won't be written into the NBL.
            let ptr = getBuffer(self.nbl, null_mut());
            assert!(!ptr.is_null());
            core::slice::from_raw_parts_mut(ptr, self.len())
        }
    }

    pub fn as_nbl(&mut self) -> *mut NetBufferList {
        self.nbl
    }
}
