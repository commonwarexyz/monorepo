//! Owned native socket addresses for io_uring connect requests.
//!
//! A connect SQE stores a pointer, so its address must not move while the kernel
//! can access it. Requests put [`SockAddr`] in a box and retain that box through
//! the operation CQE, including when a cancellation acknowledgement arrives first.
//! Conversions preserve address bytes, network-order ports, and IPv6 metadata.

use std::net::SocketAddr;

/// A native address whose concrete layout matches its address family.
pub(crate) enum SockAddr {
    /// IPv4 address, including the network-order port and address bytes.
    V4(libc::sockaddr_in),
    /// IPv6 address, including flow information and interface scope.
    V6(libc::sockaddr_in6),
}

impl From<SocketAddr> for SockAddr {
    fn from(address: SocketAddr) -> Self {
        match address {
            SocketAddr::V4(address) => Self::V4(libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: address.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.ip().octets()),
                },
                sin_zero: [0; 8],
            }),
            SocketAddr::V6(address) => Self::V6(libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: address.port().to_be(),
                sin6_flowinfo: address.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: address.ip().octets(),
                },
                sin6_scope_id: address.scope_id(),
            }),
        }
    }
}

impl SockAddr {
    /// Borrow the native address pointer and its matching concrete size.
    ///
    /// The caller retains a boxed owner through the operation CQE. This method
    /// does not extend the pointer's validity beyond that owner's lifetime.
    pub const fn as_raw(&self) -> (*const libc::sockaddr, libc::socklen_t) {
        match self {
            Self::V4(address) => (
                std::ptr::from_ref(address).cast(),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ),
            Self::V6(address) => (
                std::ptr::from_ref(address).cast(),
                size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn test_address_roundtrip_and_stable_box() {
        let ipv4 = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 17), 0x1234);
        let ipv6 = SocketAddrV6::new("fe80::1234:5678".parse().unwrap(), 0x4321, 0x12345, 7);
        for address in [SocketAddr::V4(ipv4), SocketAddr::V6(ipv6)] {
            let native = Box::new(SockAddr::from(address));
            let (pointer, len) = native.as_raw();
            let moved = std::hint::black_box(native);
            assert_eq!(moved.as_raw(), (pointer, len));
            let recovered = match moved.as_ref() {
                SockAddr::V4(raw) => {
                    assert_eq!(raw.sin_family, libc::AF_INET as libc::sa_family_t);
                    assert_eq!(len as usize, size_of::<libc::sockaddr_in>());
                    assert_eq!(raw.sin_port.to_ne_bytes(), address.port().to_be_bytes());
                    SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::from(raw.sin_addr.s_addr.to_ne_bytes()),
                        u16::from_be(raw.sin_port),
                    ))
                }
                SockAddr::V6(raw) => {
                    assert_eq!(raw.sin6_family, libc::AF_INET6 as libc::sa_family_t);
                    assert_eq!(len as usize, size_of::<libc::sockaddr_in6>());
                    assert_eq!(raw.sin6_flowinfo, 0x12345);
                    SocketAddr::V6(SocketAddrV6::new(
                        Ipv6Addr::from(raw.sin6_addr.s6_addr),
                        u16::from_be(raw.sin6_port),
                        raw.sin6_flowinfo,
                        raw.sin6_scope_id,
                    ))
                }
            };
            assert_eq!(recovered, address);
        }
    }
}
