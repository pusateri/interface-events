#![feature(ip)]

use std::io;
use std::io::Read;
use std::thread;
use socket2::{Domain, Socket, Type};
use std::os::unix::io::AsRawFd;
use libc::{AF_ROUTE, RTM_VERSION, RTM_ADD, RTM_DELETE, RTM_IFINFO, RTM_NEWADDR, RTM_DELADDR, RTM_NEWMADDR, RTM_DELMADDR};
use crossbeam_channel::{unbounded, Receiver, Sender};
use ipnetwork;
use nix::ifaddrs;
use nix::net::if_::*;
use std::net::IpAddr;
use mio::event::Evented;
use mio::unix::EventedFd;
use mio::{Events, Ready, Poll, PollOpt, Token};
use bytes::{IntoBuf, BytesMut, Buf};

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
    pub fn from_ifaddr(ifaddr: &ifaddrs::InterfaceAddress) -> Option<IfEvent>
    {
        let (ip, ipnet, plen) = match ifaddr_to_prefix(ifaddr.clone()) {
                Some((ip, ipnet, plen)) => (ip, ipnet, plen),
                None => return None,
        };
        let if_index = match if_nametoindex(&ifaddr.interface_name[..]) {
            Ok(idx) => idx,
            Err(e) => {
                eprintln!("if_nametoindex: {}", e);
                return None;
            },
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

pub fn rtsock_parse(bytes: &BytesMut) {
    let mut buf = bytes.into_buf();
    let rtm_msglen = buf.get_u16_le();
    let remain = buf.remaining() as u16;
    if rtm_msglen - 2 != remain {
        eprintln!("rtsock short buffer. expected {}, got {}", rtm_msglen, remain);
        return;
    }
    let rtm_version = buf.get_u8() as i32;
    if rtm_version != RTM_VERSION {
        eprintln!("rtsock unsupported version expected {}, got {}", RTM_VERSION, rtm_version);
        return;
    }
    let rtm_type = buf.get_u8() as i32;
    match rtm_type {
        RTM_ADD => (),
        RTM_DELETE => (),
        RTM_IFINFO => (),
        RTM_NEWADDR => {
                let ifam_addrs = buf.get_i32_le();
                let ifam_flags = buf.get_i32_le();
                let ifam_index = buf.get_u16_le();
                buf.advance(2);
                let _ifam_metric = buf.get_i32_le();
                println!("newaddr: addrs: {}, flags: {}, index: {}", ifam_addrs, ifam_flags, ifam_index);
            },
        RTM_DELADDR => println!("DELADDR"),
        RTM_NEWMADDR => println!("NEW MADDR"),
        RTM_DELMADDR => println!("DEL MADDR"),
        _ => println!("RTM TYPE: {}", rtm_type),
    };
}

impl IfController {
	pub fn new() -> Self {
        let sock = Socket::new(Domain::from(AF_ROUTE), Type::raw(), None).expect("raw routing socket");
        sock.set_nonblocking(true).expect("nonblocking Error");
		let (s, r) = unbounded::<IfEvent>();
		let controller = IfController {
			tx: s,
			rx: r,
            raw: sock,
            running: false,
		};
		controller
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
            let poll = Poll::new().expect("Poll::new() failed");
            //let mut buf = BytesMut::with_capacity(4096);
            let mut buffer = [0u8; 1024];
            poll.register(&self, RT_TOKEN, Ready::readable(), PollOpt::level()).expect("poll.register failed");
            loop {
                poll.poll(&mut events, None).expect("poll.poll failed");
                for event in events.iter() {
                    match event.token() {
                        RT_TOKEN => {
                            match self.raw.read(&mut buffer) {
                                Ok(n) => {
                                    let mut bytes = BytesMut::from(buffer.as_ref());
                                    bytes.truncate(n);
                                    rtsock_parse(&bytes);
                                },
                                Err(e) => eprintln!("read rtsock: {}", e),
                            }
                        },
                        _ => (),
                    }
                }
            }
        });
    }
}

impl Evented for IfController {
    fn register(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt) -> io::Result<()> {
        poll.register(&EventedFd(&self.raw.as_raw_fd()), token, interest, opts)
    }

    fn reregister(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt) -> io::Result<()> {
        poll.reregister(&EventedFd(&self.raw.as_raw_fd()), token, interest, opts)
    }

    fn deregister(&self, poll: &Poll) -> io::Result<()> {
        poll.deregister(self)
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
        .filter(|event| IfEvent::not_link_local(event))
        .filter(|event| IfEvent::not_loopback(event));
    for event in events {
        tx.send(event).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active() {
        let events = get_current_events()
        	.into_iter()
        	.filter(|event| IfEvent::not_link_local(event))
        	.filter(|event| IfEvent::not_loopback(event));
        assert!(events.count() > 0);
    }

    #[test]
    fn subscribe_test() {
        let ifc = IfController::new();
        let if_rx = ifc.subscribe();
        for event in if_rx.iter() {
            println!("got if event");
        }
    }
}
