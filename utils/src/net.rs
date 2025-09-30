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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
