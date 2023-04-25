#![no_std]
#![no_main]
#![feature(extern_types)]

mod checksum;
mod kernel_buffer;
mod utils;

extern crate alloc;

use alloc::{borrow::ToOwned, collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use checksum::Checksum;
use core::{cmp::max, fmt::Display};
use kernel_alloc::KernelAlloc;
use kernel_buffer::KernelBuffer;
use kernel_log::KernelLogger;
use log::LevelFilter;
use serde::{Deserialize, Serialize};
use spin::{Mutex, RwLock};
use utils::{fmt_addr, make_tunn};

#[global_allocator]
static ALLOCATOR: KernelAlloc = KernelAlloc;

#[no_mangle]
pub extern "C" fn _fltused() {}

#[panic_handler]
fn my_panic(info: &core::panic::PanicInfo) -> ! {
    log::error!("Panic info: {}", info);
    // unsafe { dbgBreak() }
    loop {}
}

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
    pub fn dbgBreak() -> !;
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Appid(Vec<u16>);

impl Appid {
    unsafe fn new(appid: *const u8, appid_size: u32) -> Self {
        let slice = core::slice::from_raw_parts(appid as *const u16, appid_size as usize);
        Self(slice.to_owned())
    }

    fn from_u16_slice(slice: &[u16]) -> Self {
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

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Session {
    protocol: u8, // TCP = 6, UDP = 17
    local_addr: [u8; 4],
    local_port: u16,
    remote_addr: [u8; 4],
    remote_port: u16,
}

impl Display for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Session({} {}:{} --> {}:{})",
            if self.protocol == 6 { "TCP" } else { "UDP" },
            fmt_addr(self.local_addr),
            self.local_port,
            fmt_addr(self.remote_addr),
            self.remote_port
        )
    }
}

#[derive(Debug, Clone)]
struct Tunnel {
    tunn: Arc<Mutex<boringtun::Tunn>>,
    interface_addr: [u8; 4],
    endpoint_addr: [u8; 4],
    endpoint_port: u16,
}

// global state
#[derive(Debug)]
struct State {
    tunnel_by_appid: BTreeMap<Appid, Tunnel>,
    tunnel_by_session: BTreeMap<Session, Tunnel>,
}
static STATE: RwLock<State> = RwLock::new(State {
    tunnel_by_appid: BTreeMap::new(),
    tunnel_by_session: BTreeMap::new(),
});

#[no_mangle]
pub extern "C" fn rsInit() {
    KernelLogger::init(LevelFilter::Debug).expect("Failed to initialize logger");

    log::info!("rsInit entry");

    // Initialize state from config.
    // Hardcoded for testing.
    // let filename = r"\device\harddiskvolume4\program files (x86)\nmap\ncat.exe";
    let appid = Appid::from_u16_slice(&[
        92, 100, 101, 118, 105, 99, 101, 92, 104, 97, 114, 100, 100, 105, 115, 107, 118, 111, 108,
        117, 109, 101, 52, 92, 112, 114, 111, 103, 114, 97, 109, 32, 102, 105, 108, 101, 115, 32,
        40, 120, 56, 54, 41, 92, 110, 109, 97, 112, 92, 110, 99, 97, 116, 46, 101, 120, 101, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    let tunn = make_tunn(
        "sGayjgm8dLj0gmNcry6VeGVuKZ1jQxicvDuOpG+pO1I=",
        "RtdFk601fL2xf4ig3bryPi1kRblUSOn2JkQGbxn/hyQ=",
        0,
    );
    let tunnel = Tunnel {
        tunn: Arc::new(Mutex::new(tunn)),
        interface_addr: [10, 0, 0, 2],
        endpoint_addr: [169, 254, 1, 3],
        endpoint_port: 12345,
    };
    STATE.write().tunnel_by_appid.insert(appid, tunnel);

    log::info!("rsInit exit");
}

#[no_mangle]
pub unsafe extern "C" fn rsIsAppTracked(appid: *const u8, appid_size: u32) -> bool {
    let appid = Appid::new(appid, appid_size);
    STATE.read().tunnel_by_appid.contains_key(&appid)
}

#[no_mangle]
pub unsafe extern "C" fn rsRegisterConnection(
    appid: *const u8,
    appid_size: u32,
    protocol: u8,
    local_addr: u32,
    local_port: u16,
    remote_addr: u32,
    remote_port: u16,
) {
    let appid = Appid::new(appid, appid_size);
    let session = Session {
        protocol,
        local_addr: local_addr.to_be_bytes(),
        local_port,
        remote_addr: remote_addr.to_be_bytes(),
        remote_port,
    };

    if STATE.read().tunnel_by_appid.contains_key(&appid) {
        // release the read lock, acquire a write lock, and re-check.
        // https://stackoverflow.com/questions/2407558/pthreads-reader-writer-locks-upgrading-read-lock-to-write-lock
        let mut state = STATE.write();
        if let Some(tunnel) = state.tunnel_by_appid.get(&appid) {
            let tunnel = tunnel.clone();
            log::info!("New session: {}", session);
            state.tunnel_by_session.insert(session, tunnel);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rsHandleInboundPacket(
    nbl: *mut NetBufferList,
    compartment_id: u32,
    interface_index: u32,
    sub_interface_index: u32,
) -> bool {
    let src_buffer = KernelBuffer::from_nbl(nbl);
    let packet = src_buffer.as_slice();
    if packet[0] >> 4 != 4 {
        return true;
    }

    let header_len = ((packet[0] & 0xf) * 4) as usize;
    // let local_addr: [u8; 4] = packet[16..20].try_into().unwrap();
    let local_port = u16::from_be_bytes(packet[header_len + 2..header_len + 4].try_into().unwrap());
    let remote_addr: [u8; 4] = packet[12..16].try_into().unwrap();
    let remote_port = u16::from_be_bytes(packet[header_len..header_len + 2].try_into().unwrap());

    // Find out which tunnel this session belongs to, if any.
    let tunnels = &STATE.read().tunnel_by_session;
    if let Some((session, tunnel)) = tunnels.iter().find(|&(session, tunnel)| {
        local_port == session.local_port
            && remote_addr == tunnel.endpoint_addr
            && remote_port == tunnel.endpoint_port
    }) {
        let tunnel = tunnel.clone();

        log::info!(
            "Decapsulating packet from {}:{}",
            fmt_addr(remote_addr),
            remote_port
        );

        // Decapsulate the packet.
        // Loop until all queued packets are sent.
        let mut datagram = &packet[header_len + 8..]; // set to &[] for repeated call
        loop {
            // Allocate a buffer for decapsulated packet.
            let buffer_size = if datagram != &[] {
                // Decapsulated packets are always smaller than the original.
                packet.len()
            } else {
                // We don't know the length of queued packets, so it's better to be safe.
                2000
            };
            let mut dst_buffer = KernelBuffer::new(buffer_size);

            let result = {
                let mut tunn = tunnel.tunn.lock();
                // Setting src_addr to None disables cookies (which causes error when tunnel is underload).
                tunn.decapsulate(None, datagram, dst_buffer.as_slice_mut())
            };
            match result {
                boringtun::TunnResult::Done => {
                    log::info!("All queued packets sent, Done.");
                    break;
                }
                boringtun::TunnResult::Err(err) => {
                    log::error!("Decapsulation error: {:?}", err);
                    break;
                }
                boringtun::TunnResult::WriteToNetwork(packet) => {
                    // Copy the queued packet to a new NBL to make space for headers.
                    // The copy could be avoided by prepending memory to the NBL.
                    let mut copy_buffer = KernelBuffer::new(28 + packet.len());
                    let (header_slice, data_slice) = copy_buffer.as_slice_mut().split_at_mut(28);
                    let (ipv4_slice, udp_slice) = header_slice.split_at_mut(20);
                    // When sending queued packets, session.local_addr/port may be different from
                    // that of the inner packet. This is fine since we perform NAT based on the inner packet.
                    ipv4_slice[0] = 0x45; // Version & IHL
                    ipv4_slice[2..4].copy_from_slice(&u16::to_be_bytes(28 + packet.len() as u16)); // Length
                    ipv4_slice[8] = 64; // TTL
                    ipv4_slice[9] = 17; // Protocol = UDP
                    ipv4_slice[12..16].copy_from_slice(&session.local_addr); // src_addr
                    ipv4_slice[16..20].copy_from_slice(&tunnel.endpoint_addr); // dst_addr
                    udp_slice[0..2].copy_from_slice(&u16::to_be_bytes(session.local_port)); // src_port
                    udp_slice[2..4].copy_from_slice(&u16::to_be_bytes(tunnel.endpoint_port)); // dst_port
                    udp_slice[4..6].copy_from_slice(&u16::to_be_bytes(8 + packet.len() as u16)); // Length
                    data_slice.copy_from_slice(packet);

                    // Free up dst_buffer since we'll not inject it to the network.
                    freeNetBufferList(dst_buffer.into_nbl());

                    log::info!(
                        "Sending queued packet, header: {:?}, data: {:?}",
                        header_slice,
                        data_slice
                    );
                    sendPacket(copy_buffer.into_nbl(), compartment_id);

                    // Repeat the call to decapsulate() with empty datagram.
                    datagram = &[];
                    continue;
                }
                boringtun::TunnResult::WriteToTunnelV4(packet, _) => {
                    // Perform reverse NAT (using the inner local port, not the outer).
                    let local_addr = {
                        if packet[0] >> 4 != 4 {
                            log::error!("Decapsulated packet is not IPv4: {packet:?}");
                            break;
                        }
                        if packet[9] != 6 && packet[9] != 17 {
                            log::error!("Decapsulated packet is not TCP or UDP: {packet:?}");
                            break;
                        }
                        let header_len = ((packet[0] & 0xf) * 4) as usize;
                        let local_port = u16::from_be_bytes(
                            packet[header_len + 2..header_len + 4].try_into().unwrap(),
                        );
                        let state = STATE.read();
                        let session = state
                            .tunnel_by_session
                            .keys()
                            .find(|&session| session.local_port == local_port)
                            .unwrap(); // FIXME: This should be fine...right?
                        session.local_addr
                    };
                    packet[16..20].copy_from_slice(&local_addr);
                    fix_checksum(packet);

                    log::info!("recvPacket {packet:?}");
                    recvPacket(
                        dst_buffer.into_nbl(),
                        compartment_id,
                        interface_index,
                        sub_interface_index,
                    );
                    break;
                }
                boringtun::TunnResult::WriteToTunnelV6(_, _) => {
                    log::error!("IPv6 encapsulation is not supported");
                    break;
                }
            }
        }
        return false;
    } else {
        return true;
    }
}

#[no_mangle]
pub unsafe extern "C" fn rsHandleOutboundPacket(
    nbl: *mut NetBufferList,
    compartment_id: u32,
) -> bool {
    let mut src_buffer = KernelBuffer::from_nbl(nbl);
    let packet = src_buffer.as_slice();
    if packet[0] >> 4 != 4 {
        return true;
    }

    let header_len = ((packet[0] & 0xf) * 4) as usize;
    let (ipv4_slice, transport_slice) = packet.split_at(header_len);
    let session = Session {
        protocol: ipv4_slice[9],
        local_addr: ipv4_slice[12..16].try_into().unwrap(),
        local_port: u16::from_be_bytes(transport_slice[..2].try_into().unwrap()),
        remote_addr: ipv4_slice[16..20].try_into().unwrap(),
        remote_port: u16::from_be_bytes(transport_slice[2..4].try_into().unwrap()),
    };

    // Check if the session is tracked.
    if let Some(tunnel) = STATE.read().tunnel_by_session.get(&session) {
        let tunnel = tunnel.clone();

        log::info!(
            "Encapsulating packet to {}:{}",
            fmt_addr(session.remote_addr),
            session.remote_port
        );

        // Perform NAT.
        let temp_packet = src_buffer.as_slice_mut_temporary();
        temp_packet[12..16].copy_from_slice(&tunnel.interface_addr);

        // Fix checksums before we encapsulate the packet.
        // IPv4 checksum is normally done by checksum offload, but it doesn't work inside encapsulated packets.
        // Also, since we modified src_addr, the original TCP/UDP checksum is now incorrect.
        fix_checksum(temp_packet);

        // Encapsulate the packet.
        let mut dst_buffer = KernelBuffer::new(28 + max(temp_packet.len() + 32, 148));
        let (header_slice, data_slice) = dst_buffer.as_slice_mut().split_at_mut(28);
        let (ipv4_slice, udp_slice) = header_slice.split_at_mut(20);
        let result = {
            let mut tunn = tunnel.tunn.lock();
            tunn.encapsulate(temp_packet, data_slice)
        };
        match result {
            boringtun::TunnResult::WriteToNetwork(data) => {
                ipv4_slice[0] = 0x45; // Version & IHL
                ipv4_slice[2..4].copy_from_slice(&u16::to_be_bytes(28 + data.len() as u16)); // Length
                ipv4_slice[8] = 64; // TTL
                ipv4_slice[9] = 17; // Protocol = UDP
                ipv4_slice[12..16].copy_from_slice(&session.local_addr); // src_addr
                ipv4_slice[16..20].copy_from_slice(&tunnel.endpoint_addr); // dst_addr
                udp_slice[0..2].copy_from_slice(&u16::to_be_bytes(session.local_port)); // src_port
                udp_slice[2..4].copy_from_slice(&u16::to_be_bytes(tunnel.endpoint_port)); // dst_port
                udp_slice[4..6].copy_from_slice(&u16::to_be_bytes(8 + data.len() as u16)); // Length

                log::info!(
                    "sendPacket with header {:?} and data {:?}",
                    header_slice,
                    data_slice
                );

                sendPacket(dst_buffer.into_nbl(), compartment_id);
            }
            boringtun::TunnResult::Done => {
                log::info!("Handshake in flight, packet queued for sending");
            }
            boringtun::TunnResult::Err(err) => {
                log::error!("Encapsulation error: {:?}", err);
            }
            _ => unreachable!(),
        }
        return false;
    } else {
        return true;
    }
}

// Fix IPv4 & TCP/UDP checksums for an IPv4 packet.
fn fix_checksum(packet: &mut [u8]) {
    let protocal = packet[9];
    let ipv4_header_len = ((packet[0] & 0xf) * 4) as usize;

    let (ip_header, transport_segment) = packet.split_at_mut(ipv4_header_len);

    // clear IPv4 checksum
    ip_header[10..12].copy_from_slice(&[0, 0]);

    if protocal == 6 {
        // clear TCP checksum
        transport_segment[16..18].copy_from_slice(&[0, 0]);
    } else if protocal == 17 {
        // clear UDP checksum
        transport_segment[6..8].copy_from_slice(&[0, 0]);
    } else {
        unreachable!()
    }

    // calculate IPv4 checksum
    let mut ipv4_checksum = Checksum::new();
    ipv4_checksum.add_bytes(ip_header);
    ip_header[10..12].copy_from_slice(&ipv4_checksum.checksum());

    if protocal == 6 {
        // calculate TCP checksum
        let mut tcp_checksum = Checksum::new();
        tcp_checksum.add_bytes(&ip_header[12..20]); // src_addr & dst_addr
        tcp_checksum.add_bytes(&[0, 6]); // protocol = 6
        tcp_checksum.add_bytes(&u16::to_be_bytes(transport_segment.len() as u16)); // TCP length
        tcp_checksum.add_bytes(transport_segment); // TCP header & data
        transport_segment[16..18].copy_from_slice(&tcp_checksum.checksum());
    } else if protocal == 17 {
        // UDP checksum is optional in IPv4, skipping
    } else {
        unreachable!()
    }
}
