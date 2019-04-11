#![feature(ip)]

use crossbeam_channel::{unbounded, Receiver, Sender};
use ipnetwork;
use nix::ifaddrs;
use nix::net::if_::*;
use std::net::IpAddr;

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

pub struct IfController {
	tx: Sender<IfEvent>,
	rx: Receiver<IfEvent>,
    running: bool,
}

impl IfController {
	pub fn new() -> Self {
		let (s, r) = unbounded::<IfEvent>();
		let controller = IfController {
			tx: s,
			rx: r,
            running: false,
		};
		// TODO: adding routing socket support here to listen and generate events
		controller
	}

	/// subscribe to future interfaces events
	pub fn subscribe(self) -> Receiver<IfEvent> {
        let rx = self.rx.clone();
        catchup(&self.tx);
        if !self.running {
            run(&self.tx);
        }
		rx
	}

	/// unsubscribe to future interfaces events
	pub fn unsubscribe(self, r: Receiver<IfEvent>) {
		drop(r);
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

/// return events for current interfaces with addresses that are UP
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

fn run(_tx: &Sender<IfEvent>) {
        // future rtsock events
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
}
