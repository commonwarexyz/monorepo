//! Utilities for working with IP addresses.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Canonical subnet representative for an IP address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Subnet {
    addr: IpAddr,
}

impl Subnet {
    /// Access the representative [`IpAddr`] for this subnet.
    pub const fn addr(self) -> IpAddr {
        self.addr
    }
}

impl From<Subnet> for IpAddr {
    fn from(value: Subnet) -> Self {
        value.addr
    }
}

/// Extension trait providing subnet helpers for [`IpAddr`].
pub trait IpAddrExt {
    /// Return the canonical subnet representative for this IP address.
    ///
    /// IPv4 addresses are truncated to the first 24 bits, while IPv6 addresses are truncated to the
    /// upper 64 bits. This mirrors the network's default assumptions and matches common ISP subnet
    /// sizes, allowing rate-limiting to operate on broader network groupings.
    fn subnet_of(self) -> Subnet;

    /// Determine if this IP address is globally routable.
    ///
    /// This mirrors the logic in the unstable `IpAddr::is_global` method from the standard library
    /// and can be removed once that API is stabilized.
    fn is_global(self) -> bool;
}

impl IpAddrExt for IpAddr {
    fn subnet_of(self) -> Subnet {
        match self {
            IpAddr::V4(v4) => Subnet {
                addr: IpAddr::V4(Ipv4Addr::from(u32::from(v4) & 0xFFFFFF00)),
            },
            IpAddr::V6(v6) => {
                let masked = u128::from(v6) & !((1u128 << 64) - 1);
                Subnet {
                    addr: IpAddr::V6(Ipv6Addr::from(masked)),
                }
            }
        }
    }

    fn is_global(self) -> bool {
        match self {
            IpAddr::V4(ip) => is_global_v4(ip),
            IpAddr::V6(ip) => is_global_v6(ip),
        }
    }
}

#[inline]
const fn is_future_protocol_v4(ip: Ipv4Addr) -> bool {
    ip.octets()[0] == 192
        && ip.octets()[1] == 0
        && ip.octets()[2] == 0
        && ip.octets()[3] != 9
        && ip.octets()[3] != 10
}

#[inline]
const fn is_shared_v4(ip: Ipv4Addr) -> bool {
    ip.octets()[0] == 100 && (ip.octets()[1] & 0b1100_0000 == 0b0100_0000)
}

#[inline]
const fn is_benchmarking_v4(ip: Ipv4Addr) -> bool {
    ip.octets()[0] == 198 && (ip.octets()[1] & 0xfe) == 18
}

#[inline]
const fn is_reserved_v4(ip: Ipv4Addr) -> bool {
    ip.octets()[0] & 240 == 240 && !ip.is_broadcast()
}

#[inline]
const fn is_global_v4(ip: Ipv4Addr) -> bool {
    !(ip.octets()[0] == 0 // "This network"
        || ip.is_private()
        || is_shared_v4(ip)
        || ip.is_loopback()
        || ip.is_link_local()
        || is_future_protocol_v4(ip)
        || ip.is_documentation()
        || is_benchmarking_v4(ip)
        || is_reserved_v4(ip)
        || ip.is_broadcast())
}

#[inline]
const fn is_documentation_v6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] == 0x2001) && (ip.segments()[1] == 0xdb8)
}

#[inline]
const fn is_unique_local_v6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

#[inline]
const fn is_unicast_link_local_v6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

#[inline]
const fn is_global_v6(ip: Ipv6Addr) -> bool {
    !(ip.is_unspecified()
        || ip.is_loopback()
        // IPv4-mapped Address (`::ffff:0:0/96`)
        || matches!(ip.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
        // IPv4-IPv6 Translation (`64:ff9b:1::/48`)
        || matches!(ip.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
        // Discard-Only Address Block (`100::/64`)
        || matches!(ip.segments(), [0x100, 0, 0, 0, _, _, _, _])
        // IETF Protocol Assignments (`2001::/23`)
        || (matches!(ip.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
            && !(
                // Port Control Protocol Anycast (`2001:1::1`)
                u128::from_be_bytes(ip.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
                // Traversal Using Relays around NAT Anycast (`2001:1::2`)
                || u128::from_be_bytes(ip.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
                // AMT (`2001:3::/32`)
                || matches!(ip.segments(), [0x2001, 3, _, _, _, _, _, _])
                // AS112-v6 (`2001:4:112::/48`)
                || matches!(ip.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
                // ORCHIDv2 (`2001:20::/28`)
                // Drone Remote ID Protocol Entity Tags (DETs) Prefix (`2001:30::/28`)
                || matches!(ip.segments(), [0x2001, b, _, _, _, _, _, _] if b >= 0x20 && b <= 0x3F)
            ))
        // 6to4 (`2002::/16`) – it's not explicitly documented as globally reachable,
        // IANA says N/A.
        || matches!(ip.segments(), [0x2002, _, _, _, _, _, _, _])
        || is_documentation_v6(ip)
        || is_unique_local_v6(ip)
        || is_unicast_link_local_v6(ip))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn ipv4_subnet_truncates_last_octet() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 123));
        assert_eq!(
            ip.subnet_of().addr(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0))
        );
    }

    #[test]
    fn ipv6_subnet_truncates_lower_64_bits() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(
            ip.subnet_of().addr(),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0))
        );
    }

    #[test]
    fn is_global_ipv4_examples() {
        assert!(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)).is_global());
        assert!(!IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)).is_global());
        assert!(!IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)).is_global());
        assert!(!IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)).is_global());
        assert!(!IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1)).is_global());
        assert!(IpAddr::V4(Ipv4Addr::new(192, 0, 0, 9)).is_global());
    }

    #[test]
    fn is_global_ipv6_examples() {
        assert!(IpAddr::V6(Ipv6Addr::from_str("2001:4860:4860::8888").unwrap()).is_global());
        assert!(!IpAddr::V6(Ipv6Addr::UNSPECIFIED).is_global());
        assert!(!IpAddr::V6(Ipv6Addr::LOCALHOST).is_global());
        assert!(!IpAddr::V6(Ipv6Addr::from_str("64:ff9b:1::1").unwrap()).is_global());
        assert!(!IpAddr::V6(Ipv6Addr::from_str("100::1").unwrap()).is_global());
        assert!(IpAddr::V6(Ipv6Addr::from_str("2001:30::1").unwrap()).is_global());
    }

    #[test]
    fn is_global_ipaddr_helper() {
        assert!("1.2.3.4".parse::<IpAddr>().unwrap().is_global());
        assert!(!"10.0.0.1".parse::<IpAddr>().unwrap().is_global());
        assert!("2001:4860:4860::8888"
            .parse::<IpAddr>()
            .unwrap()
            .is_global());
        assert!(!"fe80::1".parse::<IpAddr>().unwrap().is_global());
    }
}
