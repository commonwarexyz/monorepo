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
