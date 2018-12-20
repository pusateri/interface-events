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
    pub plen: u8,
}

impl IfEvent {
    pub fn new(
        action: IfAction,
        name: String,
        idx: u32,
        flags: InterfaceFlags,
        addr: IpAddr,
        len: u8,
    ) -> IfEvent {
        IfEvent {
            ifaction: action,
            ifname: name,
            ifindex: idx,
            ifflags: flags,
            ip: addr,
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
}

pub struct IfController {
	tx: Sender<IfEvent>,
	rx: Receiver<IfEvent>,
}

impl IfController {
	pub fn new() -> Self {
		let (s, r) = unbounded::<IfEvent>();
		let controller = IfController {
			tx: s,
			rx: r,
		};
		// TODO: adding routing socket support here to listen and generate events
		controller
	}

	/// subscribe to future interfaces events
	pub fn subscribe(self) -> Receiver<IfEvent> {
		self.rx.clone()
	}

	/// unsubscribe to future interfaces events
	pub fn unsubscribe(self, r: Receiver<IfEvent>) {
		drop(r);
	}
}

fn ifaddr_to_prefix(ifaddr: ifaddrs::InterfaceAddress) -> Option<ipnetwork::IpNetwork> {
    let ip = addrs::sockaddr_to_ipaddr(ifaddr.address?)?;
    let mask = addrs::sockaddr_to_ipaddr(ifaddr.netmask?)?;
    let net = addrs::mask_address(ip, mask)?;
    let plen = match ipnetwork::ip_mask_to_prefix(mask) {
        Ok(len) => len,
        Err(_e) => return None,
    };
    match ipnetwork::IpNetwork::new(net, plen) {
        Ok(ipnet) => return Some(ipnet),
        Err(_e) => return None,
    };
}

/// return events for current interfaces with addresses that are UP
pub fn get_current_events() -> Vec<IfEvent> {
    let addrs = ifaddrs::getifaddrs().unwrap();
    let mut events: Vec<IfEvent> = Vec::with_capacity(10);
    for ifaddr in addrs {
        let (ip, plen) = match ifaddr_to_prefix(ifaddr.clone()) {
            Some(ipnet) => (ipnet.ip(), ipnet.prefix()),
            None => {
                continue;
            }
        };
        let if_index = if_nametoindex(&ifaddr.interface_name[..]).unwrap();
        if ifaddr.flags.contains(InterfaceFlags::IFF_UP) {
            events.push(IfEvent::new(
                IfAction::NEWADDR,
                ifaddr.interface_name,
                if_index,
                ifaddr.flags,
                ip,
                plen,
            ));
        }
    }
    events
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
