// Trusted-proxy address ranges.

use std::net::IpAddr;

/// An IPv4 or IPv6 network in CIDR notation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpCidr {
    network: IpAddr,
    prefix: u8,
}

/// Collapse IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to IPv4.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

impl IpCidr {
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let (addr, prefix) = match text.trim().split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (text.trim(), None),
        };
        let network = canonical_ip(
            addr.parse::<IpAddr>()
                .map_err(|_| anyhow::anyhow!("invalid trusted proxy address {text:?}"))?,
        );
        let max = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| anyhow::anyhow!("invalid prefix in {text:?}"))?,
            None => max,
        };
        Ok(Self { network, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, canonical_ip(ip)) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(self.prefix))
                };
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(self.prefix))
                };
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_matching() {
        let v4 = IpCidr::parse("10.0.0.0/8").unwrap();
        assert!(v4.contains("10.1.2.3".parse().unwrap()));
        assert!(!v4.contains("11.0.0.1".parse().unwrap()));
        assert!(v4.contains("::ffff:10.0.0.1".parse().unwrap()));
        let host = IpCidr::parse("127.0.0.1").unwrap();
        assert!(host.contains("127.0.0.1".parse().unwrap()));
        assert!(!host.contains("127.0.0.2".parse().unwrap()));
        let v6 = IpCidr::parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8:1::1".parse().unwrap()));
        assert!(!v6.contains("10.0.0.1".parse().unwrap()));
        assert!(IpCidr::parse("10.0.0.0/33").is_err());
        assert!(IpCidr::parse("nope").is_err());
        assert!(IpCidr::parse("0.0.0.0/0")
            .unwrap()
            .contains("8.8.8.8".parse().unwrap()));
    }
}
