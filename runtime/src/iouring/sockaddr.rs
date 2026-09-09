//! Native socket addresses for io_uring connect requests.
//!
//! Connect requests box [`SockAddr`] to keep its address stable until the
//! operation completes. A cancellation acknowledgement does not release it.

use std::{net::SocketAddr, ptr};

/// An IPv4 or IPv6 socket address in native form.
pub enum SockAddr {
    /// Native IPv4 address.
    V4(libc::sockaddr_in),
    /// Native IPv6 address, including flow information and interface scope.
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
    /// Return a pointer to the native address and its size.
    ///
    /// The caller must keep this value alive, unmoved, and unchanged while
    /// using the pointer.
    pub const fn as_raw(&self) -> (*const libc::sockaddr, libc::socklen_t) {
        match self {
            Self::V4(address) => (
                ptr::from_ref(address).cast(),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ),
            Self::V6(address) => (
                ptr::from_ref(address).cast(),
                size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn test_ipv4_conversion_and_raw_parts() {
        let address = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 17), 0x1234);
        let native = SockAddr::from(SocketAddr::V4(address));
        let SockAddr::V4(raw) = &native else {
            panic!("expected an IPv4 address");
        };

        assert_eq!(raw.sin_family, libc::AF_INET as libc::sa_family_t);
        assert_eq!(raw.sin_zero, [0; 8]);

        // The address and port must have network-order bytes in memory.
        assert_eq!(raw.sin_addr.s_addr.to_ne_bytes(), [192, 0, 2, 17]);
        assert_eq!(raw.sin_port.to_ne_bytes(), [0x12, 0x34]);

        let (pointer, len) = native.as_raw();
        assert_eq!(pointer, ptr::from_ref(raw).cast());
        assert_eq!(len as usize, size_of::<libc::sockaddr_in>());
    }

    #[test]
    fn test_ipv6_conversion_and_raw_parts() {
        let address = SocketAddrV6::new("fe80::1234:5678".parse().unwrap(), 0x4321, 0x12345, 7);
        let native = SockAddr::from(SocketAddr::V6(address));
        let SockAddr::V6(raw) = &native else {
            panic!("expected an IPv6 address");
        };

        assert_eq!(raw.sin6_family, libc::AF_INET6 as libc::sa_family_t);
        assert_eq!(
            raw.sin6_addr.s6_addr,
            [
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78
            ]
        );
        assert_eq!(raw.sin6_port.to_ne_bytes(), [0x43, 0x21]);

        // Nonzero metadata must survive conversion along with the address.
        assert_eq!(raw.sin6_flowinfo, 0x12345);
        assert_eq!(raw.sin6_scope_id, 7);

        let (pointer, len) = native.as_raw();
        assert_eq!(pointer, ptr::from_ref(raw).cast());
        assert_eq!(len as usize, size_of::<libc::sockaddr_in6>());
    }
}
