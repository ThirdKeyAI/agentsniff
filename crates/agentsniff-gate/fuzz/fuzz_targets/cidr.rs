#![no_main]
//! CIDR parsing and membership: no panic, and a parsed block contains its
//! own canonical network address.

use agentsniff_gate::{canonical_ip, IpCidr};
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(cidr) = IpCidr::parse(text) {
        let probe: IpAddr = if data.len() >= 16 {
            let mut b = [0u8; 16];
            b.copy_from_slice(&data[..16]);
            Ipv6Addr::from(b).into()
        } else {
            Ipv4Addr::new(data.len() as u8, 0, 0, 1).into()
        };
        let _ = cidr.contains(probe);
        let _ = cidr.contains(canonical_ip(probe));
        if let Some(net) = text
            .split('/')
            .next()
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
        {
            assert!(
                cidr.contains(net),
                "{text}: block does not contain its own address"
            );
        }
    }
});
