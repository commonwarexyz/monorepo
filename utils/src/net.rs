//! Utilities for working with IP addresses.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Canonical subnet representative for an IP address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Subnet {
    addr: IpAddr,
}

/// Mask an IPv4 address to the first 24 bits.
#[inline]
fn ipv4_subnet(ip: Ipv4Addr) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(u32::from(ip) & 0xFFFFFF00))
}

/// Mask an IPv6 address to the upper 64 bits.
#[inline]
fn ipv6_subnet(ip: Ipv6Addr) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(
        u128::from(ip) & 0xFFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000,
    ))
}

/// Extension trait providing subnet helpers for [`IpAddr`].
pub trait IpAddrExt {
    /// Return the canonical subnet representative for this IP address.
    ///
    /// IPv4 addresses are truncated to the first 24 bits. Native IPv6 addresses are truncated to the
    /// upper 64 bits, while IPv4-mapped IPv6 addresses follow the IPv4 truncation rules. This mirrors
    /// the network's default assumptions and matches common ISP subnet sizes, allowing rate-limiting
    /// to operate on broader network groupings.
    fn subnet(&self) -> Subnet;

    /// Determine if this IP address is globally routable.
    ///
    /// This mirrors the logic in the unstable `IpAddr::is_global` method from the standard library
    /// and can be removed once that API is stabilized.
    fn is_global(&self) -> bool;
}

impl IpAddrExt for IpAddr {
    fn subnet(&self) -> Subnet {
        match self {
            IpAddr::V4(v4) => Subnet {
                addr: ipv4_subnet(*v4),
            },
            IpAddr::V6(v6) => {
                if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                    return Subnet {
                        addr: ipv4_subnet(mapped_v4),
                    };
                }

                Subnet {
                    addr: ipv6_subnet(*v6),
                }
            }
        }
    }

    fn is_global(&self) -> bool {
        match self {
            IpAddr::V4(ip) => is_global_v4(*ip),
            IpAddr::V6(ip) => is_global_v6(*ip),
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
        assert_eq!(ip.subnet().addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)));
    }

    #[test]
    fn ipv6_subnet_truncates_lower_64_bits() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(
            ip.subnet().addr,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0))
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_subnet_uses_ipv4_truncation() {
        let ip = IpAddr::from_str("::ffff:192.168.1.123").unwrap();
        assert_eq!(ip.subnet().addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)));
    }

    #[test]
    #[allow(unstable_name_collisions)]
    fn test_is_global_v4() {
        // Test global IPv4 addresses
        assert!(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)).is_global()); // Google DNS
        assert!(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)).is_global()); // Cloudflare DNS
        assert!(IpAddr::V4(Ipv4Addr::new(123, 45, 67, 89)).is_global()); // Random public address

        // Test private IPv4 addresses
        assert!(!IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)).is_global()); // 10.0.0.0/8
        assert!(!IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)).is_global()); // 192.168.0.0/16
        assert!(!IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)).is_global()); // 172.16.0.0/12
        assert!(!IpAddr::V4(Ipv4Addr::new(172, 31, 255, 254)).is_global());

        // Test shared address space (100.64.0.0/10)
        assert!(!IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)).is_global());
        assert!(!IpAddr::V4(Ipv4Addr::new(100, 127, 255, 254)).is_global());

        // Test loopback addresses (127.0.0.0/8)
        assert!(!IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)).is_global());
        assert!(!IpAddr::V4(Ipv4Addr::new(127, 255, 255, 254)).is_global());

        // Test link-local addresses (169.254.0.0/16)
        assert!(!IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1)).is_global());
        assert!(!IpAddr::V4(Ipv4Addr::new(169, 254, 255, 254)).is_global());

        // Test future use addresses (192.0.0.0/24 except 192.0.0.9 and 192.0.0.10)
        assert!(!IpAddr::V4(Ipv4Addr::new(192, 0, 0, 1)).is_global());
        assert!(!IpAddr::V4(Ipv4Addr::new(192, 0, 0, 254)).is_global());
        // Exception addresses (192.0.0.9 and 192.0.0.10)
        assert!(IpAddr::V4(Ipv4Addr::new(192, 0, 0, 9)).is_global());
        assert!(IpAddr::V4(Ipv4Addr::new(192, 0, 0, 10)).is_global());

        // Test documentation addresses
        assert!(!IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)).is_global()); // 192.0.2.0/24
        assert!(!IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)).is_global()); // 198.51.100.0/24
        assert!(!IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)).is_global()); // 203.0.113.0/24

        // Test benchmarking addresses (198.18.0.0/15)
        assert!(!IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)).is_global());
        assert!(!IpAddr::V4(Ipv4Addr::new(198, 19, 255, 254)).is_global());

        // Test reserved addresses (240.0.0.0/4)
        assert!(!IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1)).is_global());
        assert!(!IpAddr::V4(Ipv4Addr::new(254, 255, 255, 254)).is_global());

        // Test broadcast address
        assert!(!IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)).is_global());
    }

    #[test]
    #[allow(unstable_name_collisions)]
    fn test_is_global_v6() {
        // Test global IPv6 addresses
        assert!(IpAddr::V6(Ipv6Addr::from_str("2001:4860:4860::8888").unwrap()).is_global()); // Google DNS
        assert!(IpAddr::V6(Ipv6Addr::from_str("2606:4700:4700::1111").unwrap()).is_global()); // Cloudflare DNS
        assert!(
            IpAddr::V6(Ipv6Addr::from_str("2005:1db8:85a3:0000:0000:8a2e:0370:7334").unwrap())
                .is_global()
        ); // Random global address

        // Test unspecified address (::)
        assert!(!IpAddr::V6(Ipv6Addr::UNSPECIFIED).is_global());

        // Test loopback address (::1)
        assert!(!IpAddr::V6(Ipv6Addr::LOCALHOST).is_global());

        // Test IPv4-mapped addresses (::ffff:0:0/96)
        assert!(!IpAddr::V6(Ipv6Addr::from_str("::ffff:192.0.2.128").unwrap()).is_global());

        // Test IPv4-IPv6 translation addresses (64:ff9b:1::/48)
        assert!(!IpAddr::V6(Ipv6Addr::from_str("64:ff9b:1::1").unwrap()).is_global());

        // Test discard-only addresses (100::/64)
        assert!(!IpAddr::V6(Ipv6Addr::from_str("100::1").unwrap()).is_global());

        // Test IETF protocol assignments (2001::/23)
        assert!(!IpAddr::V6(Ipv6Addr::from_str("2001:0::1").unwrap()).is_global()); // Within 2001::/23
        assert!(IpAddr::V6(Ipv6Addr::from_str("2001:1::1").unwrap()).is_global()); // Outside 2001::/23

        // Test exceptions within 2001::/23
        assert!(IpAddr::V6(Ipv6Addr::from_str("2001:1::1").unwrap()).is_global()); // Port Control Protocol Anycast
        assert!(IpAddr::V6(Ipv6Addr::from_str("2001:1::2").unwrap()).is_global()); // Traversal Using Relays around NAT
        assert!(IpAddr::V6(Ipv6Addr::from_str("2001:3::1").unwrap()).is_global()); // AMT
        assert!(IpAddr::V6(Ipv6Addr::from_str("2001:4:112::1").unwrap()).is_global()); // AS112-v6
        assert!(IpAddr::V6(Ipv6Addr::from_str("2001:20::1").unwrap()).is_global()); // ORCHIDv2
        assert!(IpAddr::V6(Ipv6Addr::from_str("2001:30::1").unwrap()).is_global()); // Drone Remote ID

        // Test 6to4 addresses (2002::/16)
        assert!(!IpAddr::V6(Ipv6Addr::from_str("2002::1").unwrap()).is_global());

        // Test documentation addresses (2001:db8::/32)
        assert!(!IpAddr::V6(Ipv6Addr::from_str("2001:db8::1").unwrap()).is_global());

        // Test unique local addresses (fc00::/7)
        assert!(!IpAddr::V6(Ipv6Addr::from_str("fc00::1").unwrap()).is_global()); // fc00::/8
        assert!(!IpAddr::V6(
            Ipv6Addr::from_str("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").unwrap()
        )
        .is_global()); // fd00::/8

        // Test link-local unicast addresses (fe80::/10)
        assert!(!IpAddr::V6(Ipv6Addr::from_str("fe80::1").unwrap()).is_global());

        // Test multicast addresses (ff00::/8)
        assert!(IpAddr::V6(Ipv6Addr::from_str("ff00::1").unwrap()).is_global());

        // Test global address outside of special ranges
        assert!(IpAddr::V6(Ipv6Addr::from_str("2003::1").unwrap()).is_global());
    }

    #[test]
    #[allow(unstable_name_collisions)]
    fn test_is_global_ipaddr() {
        // Test with IpAddr enum
        // Global IPv4
        assert!(IpAddr::V4(Ipv4Addr::from_str("1.2.3.4").unwrap()).is_global());
        // Non-global IPv4
        assert!(!IpAddr::V4(Ipv4Addr::from_str("10.0.0.1").unwrap()).is_global());

        // Global IPv6
        assert!(IpAddr::V6(Ipv6Addr::from_str("2001:4860:4860::8888").unwrap()).is_global());
        // Non-global IPv6
        assert!(!IpAddr::V6(Ipv6Addr::from_str("fe80::1").unwrap()).is_global());
    }
}
