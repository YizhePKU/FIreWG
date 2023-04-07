#![no_std]
#![no_main]

mod utils;

extern crate alloc;

use alloc::{borrow::ToOwned, collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use boringtun::Tunn;
use core::fmt::Display;
use kernel_alloc::KernelAlloc;
use kernel_log::KernelLogger;
use log::LevelFilter;
use smoltcp::wire::{IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket, UdpPacket};
use spin::{Mutex, RwLock};
use utils::make_tunn;

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
        protocol: if protocol == 6 {
            IpProtocol::Tcp
        } else {
            IpProtocol::Udp
        },
        local_addr: Ipv4Address::from_bytes(&local_addr.to_be_bytes()),
        local_port,
        remote_addr: Ipv4Address::from_bytes(&remote_addr.to_be_bytes()),
        remote_port,
    };
    // Associate the connection with a tunnel, which should exist, since `rsIsAppTracked` already checks for tracking status.
    // There is no "time-of-check to time-of-use" bug since tunnels never changes after initialization.
    let tunn = STATE.read().tunnels.get(&appid).unwrap().clone();
    STATE.write().connections.insert(connection, tunn);
    log::info!(
        "New connection: {}, {}:{} --> {}:{}",
        appid,
        connection.local_addr,
        connection.local_port,
        connection.remote_addr,
        connection.remote_port
    );
}

#[no_mangle]
pub extern "C" fn rsHandleInboundPacket(buf: *mut u8, size: u32) -> bool {
    let data = unsafe { core::slice::from_raw_parts_mut(buf, size as usize) };

    // log::info!("rsHandleInboundPacket entry. data: {data:?}");
    true
}

#[no_mangle]
pub extern "C" fn rsHandleOutboundPacket(buf: *mut u8, size: u32) -> bool {
    let buffer = unsafe { core::slice::from_raw_parts(buf, size as usize) };

    // Parse packet
    // TODO: Surely there's a cleaner way to handle all these match branches...
    let ipv4_packet = match Ipv4Packet::new_checked(buffer) {
        Err(_) => {
            return true;
        }
        Ok(packet) => {
            if packet.version() != 4 {
                return true;
            }
            packet
        }
    };
    let protocol = ipv4_packet.next_header();
    let (connection, payload) = match protocol {
        IpProtocol::Tcp => match TcpPacket::new_checked(ipv4_packet.payload()) {
            Err(_) => {
                return true;
            }
            Ok(tcp_packet) => {
                let connection = Connection {
                    protocol,
                    local_addr: ipv4_packet.src_addr(),
                    local_port: tcp_packet.src_port(),
                    remote_addr: ipv4_packet.dst_addr(),
                    remote_port: tcp_packet.dst_port(),
                };
                let payload = tcp_packet.payload();
                (connection, payload)
            }
        },
        IpProtocol::Udp => match UdpPacket::new_checked(ipv4_packet.payload()) {
            Err(_) => {
                return true;
            }
            Ok(udp_packet) => {
                let connection = Connection {
                    protocol,
                    local_addr: ipv4_packet.src_addr(),
                    local_port: udp_packet.src_port(),
                    remote_addr: ipv4_packet.dst_addr(),
                    remote_port: udp_packet.dst_port(),
                };
                let payload = udp_packet.payload();
                (connection, payload)
            }
        },
        _ => {
            return true;
        }
    };

    // Check if the connection is tracked, and if so, which tunnel it is associated with
    let tunn = match STATE.read().connections.get(&connection) {
        None => {
            return true;
        }
        Some(tunn) => tunn.clone(),
    };

    // TODO: Encrypt the payload and reconstruct the packet.
    log::info!("Trying to encrypt payload for {connection}");
    return true;
}
