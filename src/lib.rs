#![no_std]
#![no_main]
#![feature(extern_types)]

mod kernel_buffer;
mod utils;

extern crate alloc;

use alloc::{borrow::ToOwned, collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use boringtun::Tunn;
use core::fmt::Display;
use kernel_alloc::KernelAlloc;
use kernel_buffer::KernelBuffer;
use kernel_log::KernelLogger;
use log::LevelFilter;
use spin::{Mutex, RwLock};
use utils::make_tunn;

extern "C" {
    pub type NetBufferList;

    pub fn newNetBufferList(size: usize) -> *mut NetBufferList;
    pub fn freeNetBufferList(netBufferList: *mut NetBufferList);
    pub fn getBuffer(netBufferList: *mut NetBufferList, storage: *mut u8) -> *mut u8;
    pub fn getBufferSize(netBufferList: *mut NetBufferList) -> usize;
    pub fn sendPacket(netBufferList: *mut NetBufferList, compartmentId: u32);
    pub fn recvPacket(
        netBufferList: *mut NetBufferList,
        compartmentId: u32,
        interfaceIndex: u32,
        subInterfaceIndex: u32,
    );
}

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
    pub protocol: u8,
    pub local_addr: [u8; 4],
    pub local_port: u16,
    pub remote_addr: [u8; 4],
    pub remote_port: u16,
}

impl Display for Connection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Remove trailing NUL when printing
        write!(
            f,
            "Connection({} {:?}:{} --> {:?}:{})",
            self.protocol, self.local_addr, self.local_port, self.remote_addr, self.remote_port
        )
    }
}

#[global_allocator]
static ALLOCATOR: KernelAlloc = KernelAlloc;

#[no_mangle]
pub extern "C" fn _fltused() {}

#[panic_handler]
fn my_panic(info: &core::panic::PanicInfo) -> ! {
    log::error!("Panic info: {}", info);
    loop {}
}

// global state
#[derive(Debug)]
struct State {
    pub tunnels: BTreeMap<Appid, Arc<Mutex<Tunn>>>,
    pub connections: BTreeMap<Connection, Arc<Mutex<Tunn>>>,
}
static STATE: RwLock<State> = RwLock::new(State {
    tunnels: BTreeMap::new(),
    connections: BTreeMap::new(),
});

#[no_mangle]
pub extern "C" fn rsInit() {
    KernelLogger::init(LevelFilter::Info).expect("Failed to initialize logger");

    log::info!("rsInit entry");

    // Setup tracked processes
    // Hard-coded appid for now
    // let filename = r"\device\harddiskvolume4\program files (x86)\nmap\ncat.exe";
    let appid = Appid::from_u16_slice(&[
        92, 100, 101, 118, 105, 99, 101, 92, 104, 97, 114, 100, 100, 105, 115, 107, 118, 111, 108,
        117, 109, 101, 52, 92, 112, 114, 111, 103, 114, 97, 109, 32, 102, 105, 108, 101, 115, 32,
        40, 120, 56, 54, 41, 92, 110, 109, 97, 112, 92, 110, 99, 97, 116, 46, 101, 120, 101, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);

    // Create tunnels and associate them with appid
    let tunn = make_tunn(
        "sGayjgm8dLj0gmNcry6VeGVuKZ1jQxicvDuOpG+pO1I=",
        "dK6JxUPf0jEi3TkYJlTrQ5GkPFUvX7678ktFxylCgDg=",
        0,
    );
    STATE
        .write()
        .tunnels
        .insert(appid, Arc::new(Mutex::new(tunn)));

    log::info!("rsInit exit");
}

#[no_mangle]
pub extern "C" fn rsIsAppTracked(appid: *const u8, appid_size: u32) -> bool {
    let appid = Appid::new(appid, appid_size);
    STATE.read().tunnels.contains_key(&appid)
}

#[no_mangle]
pub extern "C" fn rsRegisterConnection(
    appid: *const u8,
    appid_size: u32,
    protocol: u8,
    local_addr: u32,
    local_port: u16,
    remote_addr: u32,
    remote_port: u16,
) {
    // Skip untracked apps
    if !rsIsAppTracked(appid, appid_size) {
        return;
    }

    let appid = Appid::new(appid, appid_size);
    let connection = Connection {
        protocol,
        local_addr: local_addr.to_be_bytes(),
        local_port,
        remote_addr: remote_addr.to_be_bytes(),
        remote_port,
    };
    // Associate the connection with a tunnel, which should exist, since `rsIsAppTracked` already checks for tracking status.
    // There is no "time-of-check to time-of-use" bug since tunnels never changes after initialization.
    let tunn = STATE.read().tunnels.get(&appid).unwrap().clone();
    STATE.write().connections.insert(connection, tunn);
    log::info!("New connection for {}: {}", appid, connection);
}

#[no_mangle]
pub extern "C" fn rsHandleInboundPacket(
    packet: *mut NetBufferList,
    compartment_id: u32,
    interface_index: u32,
    sub_interface_index: u32,
) -> bool {
    // data has same lifetime as storage
    let mut storage = [0; 2048];
    let buffer = unsafe {
        let buf = getBuffer(packet, storage.as_mut_ptr());
        let size = getBufferSize(packet);
        core::slice::from_raw_parts_mut(buf, size as usize)
    };

    true
}

#[no_mangle]
pub extern "C" fn rsHandleOutboundPacket(nbl: *mut NetBufferList, compartment_id: u32) -> bool {
    let src_buffer = KernelBuffer::from_nbl(nbl);

    let packet = src_buffer.as_slice();
    if packet[0] >> 4 != 4 {
        log::info!("Skipping non-IPv4 packet");
        return true;
    }
    let header_len = ((packet[0] & 0xf) * 4) as usize;
    let connection = Connection {
        protocol: packet[9],
        local_addr: packet[12..16].try_into().unwrap(),
        local_port: u16::from_be_bytes(packet[header_len..header_len + 2].try_into().unwrap()),
        remote_addr: packet[16..20].try_into().unwrap(),
        remote_port: u16::from_be_bytes(packet[header_len + 2..header_len + 4].try_into().unwrap()),
    };

    // Check if the connection is tracked, and if so, which tunnel it is associated with.
    let tunn = match STATE.read().connections.get(&connection) {
        Some(tunn) => tunn.clone(),
        None => {
            return true;
        }
    };

    log::info!("Trying to encrypt packet for {}", connection);

    // Encrypt the payload.
    // IP header (20 bytes) -- UDP header (8 bytes) -- payload
    let mut buffer = KernelBuffer::new(20 + 8 + core::cmp::max(packet.len() + 32, 148));
    let (header_slice, payload_slice) = buffer.as_slice_mut().split_at_mut(28);
    let (ipv4_slice, udp_slice) = header_slice.split_at_mut(20);
    let mut tunn_lock = tunn.lock();
    match tunn_lock.encapsulate(packet, payload_slice) {
        boringtun::TunnResult::WriteToNetwork(payload) => {
            log::info!("Encrypted payload: {:?}", payload);

            // TODO: Do I need to fill in checksum?
            ipv4_slice[0] = 0x45; // Version & IHL
            ipv4_slice[2..4].copy_from_slice(&u16::to_be_bytes(28 + payload.len() as u16)); // Total length
            ipv4_slice[8] = 64; // TTL
            ipv4_slice[9] = 17; // Protocol = UDP
            ipv4_slice[12..16].copy_from_slice(&connection.local_addr); // src_addr
            ipv4_slice[16..20].copy_from_slice(&[192, 168, 196, 136]); // dst_addr

            udp_slice[0..2].copy_from_slice(&u16::to_be_bytes(connection.local_port)); // src_port
            udp_slice[2..4].copy_from_slice(&u16::to_be_bytes(12345)); // dst_port
            udp_slice[4..6].copy_from_slice(&u16::to_be_bytes(8 + payload.len() as u16)); // Length

            log::info!("Sending packet...");
            log::info!("Headers: {:?}", header_slice);
            log::info!("Payload: {:?}", payload_slice);

            // Send the packet
            unsafe { sendPacket(buffer.as_nbl(), compartment_id) };
            return false;
        }
        boringtun::TunnResult::Done => {
            log::info!("Waiting for handshake");
            return false;
        }
        boringtun::TunnResult::Err(err) => {
            log::error!("Encryption error: {:?}", err);
            return false;
        }
        _ => unreachable!(),
    }
}
