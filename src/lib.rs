use byteorder::{NativeEndian, ReadBytesExt};
use crossbeam_channel::{Receiver, Sender, unbounded};
use libc::AF_ROUTE;
use libc::RTAX_MAX;
use libc::{
    RTM_ADD, RTM_DELADDR, RTM_DELETE, RTM_DELMADDR, RTM_IFANNOUNCE, RTM_IFINFO, RTM_NEWADDR,
    RTM_NEWMADDR, RTM_VERSION,
};
use mio::event::Source;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Registry, Token};
use nix::ifaddrs;
use nix::net::if_::*;
use socket2::{Domain, Socket, Type};
use std::io;
use std::io::Cursor;
use std::io::Read;
use std::net::IpAddr;
use std::os::unix::io::AsRawFd;
use std::thread;

mod addrs;

#[derive(Debug, PartialEq)]
pub enum IfAction {
    IFINFO,
    NEWADDR,
    DELADDR,
}

#[derive(Debug, PartialEq)]
pub struct IfEvent {
    pub ifaction: IfAction,
    pub ifname: String,
    pub ifindex: u32,
    pub ifflags: InterfaceFlags,
    pub ip: IpAddr,
    pub ipnet: IpAddr,
    pub plen: u8,
}

impl IfEvent {
    pub fn new(
        action: IfAction,
        name: String,
        idx: u32,
        flags: InterfaceFlags,
        addr: IpAddr,
        net: IpAddr,
        len: u8,
    ) -> IfEvent {
        IfEvent {
            ifaction: action,
            ifname: name,
            ifindex: idx,
            ifflags: flags,
            ip: addr,
            ipnet: net,
            plen: len,
        }
    }

    pub fn not_loopback(ifev: &IfEvent) -> bool {
        !ifev.ifflags.contains(InterfaceFlags::IFF_LOOPBACK)
    }

    pub fn not_link_local(ifev: &IfEvent) -> bool {
        match ifev.ip {
            IpAddr::V4(ip4) => !ip4.is_link_local(),
            IpAddr::V6(ip6) => !ip6.is_unicast_link_local(),
        }
    }
    pub fn from_ifaddr(ifaddr: &ifaddrs::InterfaceAddress) -> Option<IfEvent> {
        let (ip, ipnet, plen) = match ifaddr_to_prefix(ifaddr.clone()) {
            Some((ip, ipnet, plen)) => (ip, ipnet, plen),
            None => return None,
        };
        let if_index = match if_nametoindex(&ifaddr.interface_name[..]) {
            Ok(idx) => idx,
            Err(e) => {
                eprintln!("if_nametoindex: {}", e);
                return None;
            }
        };
        Some(IfEvent::new(
            IfAction::NEWADDR,
            ifaddr.interface_name.clone(),
            if_index,
            ifaddr.flags,
            ip,
            ipnet,
            plen,
        ))
    }
}

#[derive(Debug)]
pub struct IfController {
    tx: Sender<IfEvent>,
    rx: Receiver<IfEvent>,
    raw: Socket,
    running: bool,
}

pub fn rtsock_parse(buf: &[u8], len: usize) {
    let mut rdr = Cursor::new(buf);
    let rtm_msglen = rdr.read_u16::<NativeEndian>().unwrap();
    if len != rtm_msglen.into() {
        eprintln!("rtsock short buffer. expected {}, got {}", rtm_msglen, len);
        return;
    }
    let rtm_version = rdr.read_u8().unwrap() as i32;
    if rtm_version != RTM_VERSION {
        eprintln!(
            "rtsock unsupported version expected {}, got {}",
            RTM_VERSION, rtm_version
        );
        return;
    }

    let rtm_type = rdr.read_u8().unwrap() as i32;
    match rtm_type {
        RTM_ADD => {
            // struct rt_msghdr         - net/route.h
            println!("RTM_ADD");
        },
        RTM_DELETE => {
            // struct rt_msghdr         - net/route.h
            println!("RTM_DELETE");
        },
        RTM_IFINFO => {
            // struct if_msghdr         - net/if.h
            let ifm_addrs = rdr.read_u32::<NativeEndian>().unwrap();
            let ifm_flags = rdr.read_u32::<NativeEndian>().unwrap();
            let ifm_index = rdr.read_u16::<NativeEndian>().unwrap();
            let _ifm_spare1 = rdr.read_u16::<NativeEndian>().unwrap();
            // struct if_data           - net/if.h
            let _ifi_type = rdr.read_u8().unwrap();
            let _ifi_physical = rdr.read_u8().unwrap();
            let _ifi_addrlen = rdr.read_u8().unwrap();
            let _ifi_hdrlen = rdr.read_u8().unwrap();
            let ifi_link_state = rdr.read_u8().unwrap();
            let _ifi_vhid = rdr.read_u8().unwrap();
            let ifi_datalen = rdr.read_u16::<NativeEndian>().unwrap() as usize;
            let mut ifdata = vec![0u8; ifi_datalen - 8];
            rdr.read_exact(&mut ifdata).unwrap();
            for i in 0..RTAX_MAX {
                if ifm_addrs & (1 << i) != 0 {
                    let sa_len = rdr.read_u8().unwrap() as usize;
                    rdr.set_position(rdr.position() - 1);
                    let mut rti_info = vec![0u8; sa_len];
                    rdr.read_exact(&mut rti_info).unwrap();
                    println!("sockaddr: {:?}", &rti_info);
                }
            }
            println!(
                "IFINFO: addrs: {:#x}, flags: {:#x}, index: {}, linkstate: {}, datalen: {}, position: {:?}",
                ifm_addrs,
                ifm_flags,
                ifm_index,
                ifi_link_state,
                ifi_datalen,
                rdr.position()
            );
        },
        RTM_IFANNOUNCE => {
            // struct if_announcemsghdr - net/if.h
            println!("IFANNOUNCE");
        },
        RTM_NEWADDR | RTM_DELADDR => {
            // struct ifa_msghdr        - net/if.h
            let ifam_addrs = rdr.read_u32::<NativeEndian>().unwrap();
            let ifam_flags = rdr.read_u32::<NativeEndian>().unwrap();
            let ifam_index = rdr.read_u16::<NativeEndian>().unwrap();
            let _ifam_spare1 = rdr.read_u16::<NativeEndian>().unwrap(); // FreeBSD but not MacOS
            let ifam_metric = rdr.read_u32::<NativeEndian>().unwrap();
            for i in 0..RTAX_MAX {
                if ifam_addrs & (1 << i) != 0 {
                    let sa_len = rdr.read_u8().unwrap() as usize;
                    rdr.set_position(rdr.position() - 1);
                    let mut rti_info = vec![0u8; sa_len];
                    rdr.read_exact(&mut rti_info).unwrap();
                    println!("sockaddr {:#x}: {:?}", 1 << i, &rti_info);
                }
            }
            println!(
                "NEWADDR/DELADDR: addrs: {:#x}, flags: {:#x}, index: {}, metric: {}, position: {:?}",
                ifam_addrs,
                ifam_flags,
                ifam_index,
                ifam_metric,
                rdr.position()
            );
        },
        RTM_NEWMADDR | RTM_DELMADDR => {
            // struct ifma_msghdr       - net/if.h
            println!("NEW MADDR/DEL MADDR");
        },
        _ => println!("RTM TYPE: {}", rtm_type),
    };
}

impl Default for IfController {
    fn default() -> Self {
        Self::new()
    }
}

impl IfController {
    pub fn new() -> Self {
        let sock =
            Socket::new_raw(Domain::from(AF_ROUTE), Type::RAW, None).expect("raw routing socket");
        sock.set_nonblocking(true).expect("nonblocking Error");
        let (s, r) = unbounded::<IfEvent>();
        IfController {
            tx: s,
            rx: r,
            raw: sock,
            running: false,
        }
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
            let mut buffer = [0u8; 1024];
            poll.registry()
                .register(&mut self, RT_TOKEN, Interest::READABLE)
                .expect("poll.register failed");
            loop {
                poll.poll(&mut events, None).expect("poll.poll failed");
                for event in events.iter() {
                    if event.token() == RT_TOKEN {
                        match self.raw.read(&mut buffer) {
                            Ok(n) => {
                                println!("received {} bytes", n);
                                rtsock_parse(&buffer, n);
                            }
                            Err(e) => eprintln!("read rtsock: {}", e),
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

fn ifaddr_to_prefix(ifaddr: ifaddrs::InterfaceAddress) -> Option<(IpAddr, IpAddr, u8)> {
    let ip = addrs::sockaddr_to_ipaddr(ifaddr.address?)?;
    let mask = addrs::sockaddr_to_ipaddr(ifaddr.netmask?)?;
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
    let events = get_current_events()
        .into_iter()
        .filter(IfEvent::not_link_local)
        .filter(IfEvent::not_loopback);
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
        for _event in if_rx.iter() {
            println!("got if event");
        }
    }
}
