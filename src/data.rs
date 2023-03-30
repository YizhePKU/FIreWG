use alloc::{borrow::ToOwned, string::String, vec::Vec};
use core::fmt::Display;
use smoltcp::wire::{IpProtocol, Ipv4Address};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Appid(Vec<u16>);

impl Appid {
    pub fn new(appid: *const u8, appid_size: u32) -> Self {
        let slice =
            unsafe { core::slice::from_raw_parts(appid as *const u16, appid_size as usize) };
        Self(slice.to_owned())
    }

    pub fn from_u16_slice(slice: &[u16]) -> Self {
        Self(slice.to_owned())
    }
}

impl Display for Appid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Remove trailing NUL when printing
        write!(
            f,
            "AppId({})",
            String::from_utf16_lossy(&self.0).trim_matches('\0')
        )
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Connection {
    pub protocol: IpProtocol,
    pub local_addr: Ipv4Address,
    pub local_port: u16,
    pub remote_addr: Ipv4Address,
    pub remote_port: u16,
}

impl Display for Connection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Remove trailing NUL when printing
        write!(
            f,
            "Connection({} {}:{} --> {}:{})",
            self.protocol, self.local_addr, self.local_port, self.remote_addr, self.remote_port
        )
    }
}
