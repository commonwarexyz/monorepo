use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// is_global is a re-implementation of the `is_global` method from the `std::net` crate.
/// Once the method is no longer experimental, this function should be removed.
pub const fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_global_v4(ip),
        IpAddr::V6(ip) => is_global_v6(ip),
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
        // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
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
                // Drone Remote ID Protocol Entity Tags (DETs) Prefix (`2001:30::/28`)`
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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    #[test]
    fn test_is_global_v4() {
        // Test global IPv4 addresses
        assert!(is_global(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))); // Google DNS
        assert!(is_global(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))); // Cloudflare DNS
        assert!(is_global(IpAddr::V4(Ipv4Addr::new(123, 45, 67, 89)))); // Random public address

        // Test private IPv4 addresses
        assert!(!is_global(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))); // 10.0.0.0/8
        assert!(!is_global(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))); // 192.168.0.0/16
        assert!(!is_global(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)))); // 172.16.0.0/12
        assert!(!is_global(IpAddr::V4(Ipv4Addr::new(172, 31, 255, 254))));

        // Test shared address space (100.64.0.0/10)
        assert!(!is_global(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(!is_global(IpAddr::V4(Ipv4Addr::new(100, 127, 255, 254))));

        // Test loopback addresses (127.0.0.0/8)
        assert!(!is_global(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(!is_global(IpAddr::V4(Ipv4Addr::new(127, 255, 255, 254))));

        // Test link-local addresses (169.254.0.0/16)
        assert!(!is_global(IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1))));
        assert!(!is_global(IpAddr::V4(Ipv4Addr::new(169, 254, 255, 254))));

        // Test future use addresses (192.0.0.0/24 except 192.0.0.9 and 192.0.0.10)
        assert!(!is_global(IpAddr::V4(Ipv4Addr::new(192, 0, 0, 1))));
        assert!(!is_global(IpAddr::V4(Ipv4Addr::new(192, 0, 0, 254))));
        // Exception addresses (192.0.0.9 and 192.0.0.10)
        assert!(is_global(IpAddr::V4(Ipv4Addr::new(192, 0, 0, 9))));
        assert!(is_global(IpAddr::V4(Ipv4Addr::new(192, 0, 0, 10))));

        // Test documentation addresses
        assert!(!is_global(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))); // 192.0.2.0/24
        assert!(!is_global(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)))); // 198.51.100.0/24
        assert!(!is_global(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)))); // 203.0.113.0/24

        // Test benchmarking addresses (198.18.0.0/15)
        assert!(!is_global(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))));
        assert!(!is_global(IpAddr::V4(Ipv4Addr::new(198, 19, 255, 254))));

        // Test reserved addresses (240.0.0.0/4)
        assert!(!is_global(IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1))));
        assert!(!is_global(IpAddr::V4(Ipv4Addr::new(254, 255, 255, 254))));

        // Test broadcast address
        assert!(!is_global(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))));
    }

    #[test]
    fn test_is_global_v6() {
        // Test global IPv6 addresses
        assert!(is_global(IpAddr::V6(
            Ipv6Addr::from_str("2001:4860:4860::8888").unwrap()
        ))); // Google DNS
        assert!(is_global(IpAddr::V6(
            Ipv6Addr::from_str("2606:4700:4700::1111").unwrap()
        ))); // Cloudflare DNS
        assert!(is_global(IpAddr::V6(
            Ipv6Addr::from_str("2005:1db8:85a3:0000:0000:8a2e:0370:7334").unwrap()
        ))); // Random global address

        // Test unspecified address (::)
        assert!(!is_global(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));

        // Test loopback address (::1)
        assert!(!is_global(IpAddr::V6(Ipv6Addr::LOCALHOST)));

        // Test IPv4-mapped addresses (::ffff:0:0/96)
        assert!(!is_global(IpAddr::V6(
            Ipv6Addr::from_str("::ffff:192.0.2.128").unwrap()
        )));

        // Test IPv4-IPv6 translation addresses (64:ff9b:1::/48)
        assert!(!is_global(IpAddr::V6(
            Ipv6Addr::from_str("64:ff9b:1::1").unwrap()
        )));

        // Test discard-only addresses (100::/64)
        assert!(!is_global(IpAddr::V6(
            Ipv6Addr::from_str("100::1").unwrap()
        )));

        // Test IETF protocol assignments (2001::/23)
        assert!(!is_global(IpAddr::V6(
            Ipv6Addr::from_str("2001:0::1").unwrap()
        ))); // Within 2001::/23
        assert!(is_global(IpAddr::V6(
            Ipv6Addr::from_str("2001:1::1").unwrap()
        ))); // Outside 2001::/23

        // Test exceptions within 2001::/23
        assert!(is_global(IpAddr::V6(
            Ipv6Addr::from_str("2001:1::1").unwrap()
        ))); // Port Control Protocol Anycast
        assert!(is_global(IpAddr::V6(
            Ipv6Addr::from_str("2001:1::2").unwrap()
        ))); // Traversal Using Relays around NAT
        assert!(is_global(IpAddr::V6(
            Ipv6Addr::from_str("2001:3::1").unwrap()
        ))); // AMT
        assert!(is_global(IpAddr::V6(
            Ipv6Addr::from_str("2001:4:112::1").unwrap()
        ))); // AS112-v6
        assert!(is_global(IpAddr::V6(
            Ipv6Addr::from_str("2001:20::1").unwrap()
        ))); // ORCHIDv2
        assert!(is_global(IpAddr::V6(
            Ipv6Addr::from_str("2001:30::1").unwrap()
        ))); // Drone Remote ID

        // Test 6to4 addresses (2002::/16)
        assert!(!is_global(IpAddr::V6(
            Ipv6Addr::from_str("2002::1").unwrap()
        )));

        // Test documentation addresses (2001:db8::/32)
        assert!(!is_global(IpAddr::V6(
            Ipv6Addr::from_str("2001:db8::1").unwrap()
        )));

        // Test unique local addresses (fc00::/7)
        assert!(!is_global(IpAddr::V6(
            Ipv6Addr::from_str("fc00::1").unwrap()
        ))); // fc00::/8
        assert!(!is_global(IpAddr::V6(
            Ipv6Addr::from_str("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").unwrap()
        ))); // fd00::/8

        // Test link-local unicast addresses (fe80::/10)
        assert!(!is_global(IpAddr::V6(
            Ipv6Addr::from_str("fe80::1").unwrap()
        )));

        // Test multicast addresses (ff00::/8)
        assert!(is_global(IpAddr::V6(
            Ipv6Addr::from_str("ff00::1").unwrap()
        ))); // Multicast addresses are considered global

        // Test global address outside of special ranges
        assert!(is_global(IpAddr::V6(
            Ipv6Addr::from_str("2003::1").unwrap()
        )));
    }

    #[test]
    fn test_is_global_ipaddr() {
        // Test with IpAddr enum
        // Global IPv4
        assert!(is_global("1.2.3.4".parse().unwrap()));
        // Non-global IPv4
        assert!(!is_global("10.0.0.1".parse().unwrap()));

        // Global IPv6
        assert!(is_global("2001:4860:4860::8888".parse().unwrap()));
        // Non-global IPv6
        assert!(!is_global("fe80::1".parse().unwrap()));
    }
}
