use byteorder::{NativeEndian, ReadBytesExt};
use crossbeam_channel::{Receiver, Sender, unbounded};

#[cfg(target_os = "freebsd")]
use libc::RTM_IFANNOUNCE;

#[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
use libc::{LINK_STATE_DOWN, LINK_STATE_UNKNOWN, LINK_STATE_UP, RTM_IFINFO};

use libc::{
    AF_INET, AF_INET6, AF_LINK, AF_ROUTE, sockaddr, sockaddr_dl, sockaddr_in, sockaddr_in6,
};
use libc::{
    RTAX_IFA, RTAX_IFP, RTAX_MAX, RTAX_NETMASK, RTM_ADD, RTM_DELADDR, RTM_DELETE, RTM_DELMADDR,
    RTM_GET, RTM_NEWADDR, RTM_NEWMADDR, RTM_VERSION,
};

use log::{error, trace};
use mio::event::Source;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Registry, Token};
use nix::ifaddrs;
use nix::net::if_::*;
use nix::sys::socket::*;
use socket2::{Domain, Socket, Type};
use std::io;
use std::io::{Cursor, Read};
use std::mem;
use std::net::IpAddr;
use std::os::unix::io::AsRawFd;
use std::thread;
use thiserror::Error;

mod addrs;

#[derive(Debug, PartialEq)]
pub struct IfAddrEvent {
    pub ifname: String,
    pub ifindex: u32,
    pub ip: IpAddr,
    pub ipnet: IpAddr,
    pub plen: u8,
}

#[derive(Debug, PartialEq)]
pub struct IfLinkEvent {
    pub ifname: String,
    pub ifindex: u32,
}

#[derive(Debug, PartialEq)]
pub enum IfEvent {
    Deladdr(IfAddrEvent),
    Ifdown(IfLinkEvent),
    Ifup(IfLinkEvent),
    Newaddr(IfAddrEvent),
}

impl IfEvent {
    pub fn not_link_local(ifa: &IfAddrEvent) -> bool {
        match ifa.ip {
            IpAddr::V4(ip4) => !ip4.is_link_local(),
            IpAddr::V6(ip6) => !ip6.is_unicast_link_local(),
        }
    }
    pub fn from_ifaddr(ifaddr: &ifaddrs::InterfaceAddress) -> Option<IfEvent> {
        let (ip, ipnet, plen) = address_mask_to_prefix(ifaddr.address?, ifaddr.netmask?)?;
        let if_index = match if_nametoindex(&ifaddr.interface_name[..]) {
            Ok(idx) => idx,
            Err(e) => {
                error!("if_nametoindex: {}", e);
                return None;
            }
        };
        let ifae = IfAddrEvent {
            ifname: ifaddr.interface_name.clone(),
            ifindex: if_index,
            ip,
            ipnet,
            plen,
        };
        Some(IfEvent::Newaddr(ifae))
    }
}

#[derive(Debug)]
pub struct IfController {
    tx: Sender<IfEvent>,
    rx: Receiver<IfEvent>,
    raw: Socket,
    running: bool,
}

#[derive(Error, Debug)]
pub enum IfError {
    #[error("rtsock msg length error")]
    MsgLengthError,
    #[error("rtsock msg version error")]
    MsgVersionError,
    #[error("link state unknown")]
    LinkStateUnknownError,
    #[error("stdio error: {0}")]
    StdIo(#[from] std::io::Error),
}

fn u8_slice_to_sockaddr<T>(data: &[u8]) -> Option<&sockaddr> {
    // Ensure the slice is large enough
    if data.len() < mem::size_of::<T>() {
        return None;
    }

    // This is an unsafe operation and requires careful consideration
    // of memory safety and alignment.
    let sockaddr_ptr = data.as_ptr() as *const sockaddr;

    // Dereferencing a raw pointer is unsafe.
    Some(unsafe { &*sockaddr_ptr })
}

fn sockaddr_convert(sa_len: usize, raw: &[u8]) -> Option<SockaddrStorage> {
    match raw[1] as i32 {
        AF_INET => {
            if let Some(sa) = u8_slice_to_sockaddr::<sockaddr_in>(raw) {
                unsafe {
                    return SockaddrStorage::from_raw(sa, Some(sa_len as u32));
                }
            }
        }
        AF_INET6 => {
            if let Some(sa) = u8_slice_to_sockaddr::<sockaddr_in6>(raw) {
                unsafe {
                    return SockaddrStorage::from_raw(sa, Some(sa_len as u32));
                }
            }
        }
        AF_LINK => {
            if let Some(sa) = u8_slice_to_sockaddr::<sockaddr_dl>(raw) {
                unsafe {
                    return SockaddrStorage::from_raw(sa, Some(sa_len as u32));
                }
            }
        }
        _ => return None,
    }
    None
}

pub fn rtsock_parse(tx: Sender<IfEvent>, buf: &[u8], len: usize) -> Result<(), IfError> {
    let mut rdr = Cursor::new(buf);
    let rtm_msglen = rdr.read_u16::<NativeEndian>()?;
    trace!("rtm_msglen: {}", rtm_msglen);
    if len != rtm_msglen.into() {
        error!("rtsock buffer. expected {rtm_msglen}, got {len}");
        return Err(IfError::MsgLengthError);
    }
    let rtm_version = rdr.read_u8()? as i32;
    if rtm_version != RTM_VERSION {
        error!(
            "rtsock unsupported version expected {}, got {}",
            RTM_VERSION, rtm_version
        );
        return Err(IfError::MsgVersionError);
    }

    let rtm_type = rdr.read_u8()? as i32;
    match rtm_type {
        RTM_ADD => trace!("RTM_ADD"),
        RTM_DELETE => trace!("RTM_DELETE"),
        RTM_GET => trace!("RTM_GET"),

        #[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
        RTM_IFINFO => {
            // struct if_msghdr         - net/if.h
            let _ifm_addrs = rdr.read_u32::<NativeEndian>()?;
            let _ifm_flags = rdr.read_u32::<NativeEndian>()?;
            let ifm_index = rdr.read_u16::<NativeEndian>()?;
            let _ifm_spare1 = rdr.read_u16::<NativeEndian>()?;
            // struct if_data           - net/if.h
            let _ifi_type = rdr.read_u8()?;
            let _ifi_physical = rdr.read_u8()?;
            let _ifi_addrlen = rdr.read_u8()?;
            let _ifi_hdrlen = rdr.read_u8()?;
            let ifi_link_state = rdr.read_u8()?;
            let _ifi_vhid = rdr.read_u8()?;
            let _ifi_datalen = rdr.read_u16::<NativeEndian>()? as usize;

            if i32::from(ifi_link_state) == LINK_STATE_UNKNOWN {
                return Err(IfError::LinkStateUnknownError);
            }
            let ifa = IfLinkEvent {
                ifname: "".to_string(),
                ifindex: u32::from(ifm_index),
            };
            if i32::from(ifi_link_state) == LINK_STATE_DOWN {
                tx.send(IfEvent::Ifdown(ifa)).unwrap();
                return Ok(());
            }
            if i32::from(ifi_link_state) == LINK_STATE_UP {
                tx.send(IfEvent::Ifup(ifa)).unwrap();
                return Ok(());
            }
        }

        #[cfg(target_os = "freebsd")]
        RTM_IFANNOUNCE => {
            // struct if_announcemsghdr - net/if.h
            trace!("IFANNOUNCE");
        }
        RTM_NEWADDR | RTM_DELADDR => {
            let mut netmask: Option<SockaddrStorage> = None;
            let mut addr: Option<SockaddrStorage> = None;

            // struct ifa_msghdr        - net/if.h
            let ifam_addrs = rdr.read_u32::<NativeEndian>()?;
            let _ifam_flags = rdr.read_u32::<NativeEndian>()?;
            let ifam_index = rdr.read_u16::<NativeEndian>()?;
            let _ifam_spare1 = rdr.read_u16::<NativeEndian>()?; // FreeBSD but not MacOS
            let _ifam_metric = rdr.read_u32::<NativeEndian>()?;
            for i in 0..RTAX_MAX {
                if ifam_addrs & (1 << i) != 0 {
                    let sa_len = rdr.read_u8()? as usize;
                    rdr.set_position(rdr.position() - 1);
                    let mut rti_info = vec![0u8; sa_len];
                    rdr.read_exact(&mut rti_info)?;
                    if i == RTAX_NETMASK {
                        netmask = sockaddr_convert(sa_len, &rti_info);
                    } else if i == RTAX_IFA {
                        addr = sockaddr_convert(sa_len, &rti_info);
                    } else if i == RTAX_IFP {
                        if let Some(sas) = sockaddr_convert(sa_len, &rti_info) {
                            if let Some(linkaddr) = sas.as_link_addr() {
                                let idx = linkaddr.ifindex();
                                if idx != ifam_index as usize {
                                    trace!("rtsock_parse ifindex mismatch {}, {}", ifam_index, idx);
                                    continue;
                                }
                            }
                        } else {
                            trace!("rtsock_parse: ifp sockaddr_convert failed");
                        }
                    }
                }
            }
            if let Some(addr) = addr {
                if let Some(netmask) = netmask {
                    if let Some((ip, ipnet, plen)) = address_mask_to_prefix(addr, netmask) {
                        let ifae = IfAddrEvent {
                            ifname: "".to_string(),
                            ifindex: ifam_index as u32,
                            ip,
                            ipnet,
                            plen,
                        };
                        if rtm_type == RTM_NEWADDR {
                            trace!(
                                "NEWADDR: {}, {:?}, {:?}, {:?} ",
                                ifam_index, ip, ipnet, plen
                            );
                            tx.send(IfEvent::Newaddr(ifae)).unwrap();
                        } else if rtm_type == RTM_DELADDR {
                            trace!(
                                "DELADDR: {}, {:?}, {:?}, {:?} ",
                                ifam_index, ip, ipnet, plen
                            );
                            tx.send(IfEvent::Deladdr(ifae)).unwrap();
                        }
                    } else {
                        trace!("rtsock_parse: address_mask_to_prefix failed");
                    }
                } else {
                    trace!("rtsock_parse: no netmask");
                }
            } else {
                trace!("rtsock_parse: no address");
            }
        }
        RTM_NEWMADDR => trace!("RTM_NEWMADDR"),
        RTM_DELMADDR => trace!("RTM_DELMADDR"),
        _ => trace!("RTM TYPE: {rtm_type}"),
    };
    Ok(())
}

impl IfController {
    pub fn new() -> Result<Self, IfError> {
        let sock = Socket::new_raw(Domain::from(AF_ROUTE), Type::RAW, None)?;
        sock.set_nonblocking(true)?;
        let (s, r) = unbounded::<IfEvent>();
        Ok(IfController {
            tx: s,
            rx: r,
            raw: sock,
            running: false,
        })
    }

    /// subscribe to future interfaces events
    pub fn subscribe(self) -> Receiver<IfEvent> {
        let rx = self.rx.clone();
        catchup(&self.tx);
        if !self.running {
            self.run();
        }
        rx
    }

    /// unsubscribe to future interfaces events
    pub fn unsubscribe(self, r: Receiver<IfEvent>) {
        drop(r);
    }

    fn run(mut self) {
        self.running = true;
        thread::spawn(move || {
            const RT_TOKEN: Token = Token(0);
            let mut events = Events::with_capacity(1024);
            let mut poll = Poll::new().expect("Poll::new() failed");
            let mut buffer = [0u8; 4096];
            poll.registry()
                .register(&mut self, RT_TOKEN, Interest::READABLE)
                .expect("poll.register failed");
            loop {
                poll.poll(&mut events, None).expect("poll.poll failed");
                for event in events.iter() {
                    if event.token() == RT_TOKEN {
                        trace!("routing socket data available to read");
                        if event.is_readable() {
                            match self.raw.read(&mut buffer) {
                                Ok(n) => {
                                    trace!("routing socket {n} bytes available");
                                    if let Err(e) = rtsock_parse(self.tx.clone(), &buffer, n) {
                                        trace!("rtsock: {}", e);
                                        error!("rtsock: {}", e);
                                    }
                                }
                                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                                Err(e) => error!("read rtsock: {}", e),
                            }
                        }
                    }
                }
            }
        });
    }
}

impl Source for IfController {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        SourceFd(&self.raw.as_raw_fd()).register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        SourceFd(&self.raw.as_raw_fd()).reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        SourceFd(&self.raw.as_raw_fd()).deregister(registry)
    }
}

fn address_mask_to_prefix(
    address: SockaddrStorage,
    netmask: SockaddrStorage,
) -> Option<(IpAddr, IpAddr, u8)> {
    let ip = addrs::sockaddr_to_ipaddr(address)?;
    let mask = addrs::sockaddr_to_ipaddr(netmask)?;
    let net = addrs::mask_address(ip, mask)?;
    let plen = match ipnetwork::ip_mask_to_prefix(mask) {
        Ok(len) => len,
        Err(_e) => return None,
    };
    Some((ip, net, plen))
}

/// return events for current interfaces with addresses
pub fn get_current_events() -> Vec<IfEvent> {
    let addrs = ifaddrs::getifaddrs().unwrap();
    let mut events: Vec<IfEvent> = Vec::with_capacity(10);
    for ifaddr in addrs {
        if let Some(event) = IfEvent::from_ifaddr(&ifaddr) {
            events.push(event);
        }
    }
    events
}

fn catchup(tx: &Sender<IfEvent>) {
    let events = get_current_events().into_iter();
    for event in events {
        tx.send(event).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /*
        #[test]
        fn active() {
            let events = get_current_events()
                .into_iter()
                .filter(|event| IfEvent::not_link_local(event))
                .filter(|event| IfEvent::not_loopback(event));
            assert!(events.count() > 0);
        }
    */
    #[test]
    fn subscribe_test() {
        let ifc = IfController::new();
        let if_rx = ifc.subscribe();
        for event in if_rx.iter() {
            println!("event {event:?}");
        }
    }
}
