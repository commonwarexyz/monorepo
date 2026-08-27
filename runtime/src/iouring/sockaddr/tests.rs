use super::*;
use std::{
    mem::size_of,
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
};

#[test]
fn test_raw_socket_addr_round_trip() {
    // Kernel-written lengths shorter than the address family must not
    // decode from truncated storage.
    let v4: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let mut raw = RawSocketAddr::from_socket_addr(&v4);
    assert_eq!(raw.to_socket_addr(), Some(v4));

    // A length one byte below sockaddr_in must be rejected, and restoring
    // the valid length must decode again.
    let valid_len = raw.len();
    *raw.len_mut() = (size_of::<libc::sockaddr_in>() - 1) as libc::socklen_t;
    assert_eq!(raw.to_socket_addr(), None);
    *raw.len_mut() = valid_len;
    assert_eq!(raw.to_socket_addr(), Some(v4));

    let v6 = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        443,
        7,
        9,
    ));
    let mut raw = RawSocketAddr::from_socket_addr(&v6);
    assert_eq!(raw.to_socket_addr(), Some(v6));

    // Same boundary for sockaddr_in6.
    let valid_len = raw.len();
    *raw.len_mut() = (size_of::<libc::sockaddr_in6>() - 1) as libc::socklen_t;
    assert_eq!(raw.to_socket_addr(), None);
    *raw.len_mut() = valid_len;
    assert_eq!(raw.to_socket_addr(), Some(v6));

    // Zeroed scratch (family AF_UNSPEC) has no decodable address.
    assert_eq!(RawSocketAddr::new_zeroed().to_socket_addr(), None);
}

#[test]
fn test_raw_socket_addr_ipv6_flowinfo_encode_uses_network_order() {
    const FLOWINFO: u32 = 0x0123_4567;
    let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, FLOWINFO, 9));

    let raw = RawSocketAddr::from_socket_addr(&addr);
    assert_eq!(raw.len() as usize, size_of::<libc::sockaddr_in6>());
    // SAFETY: the encoder stored a full sockaddr_in6 for an IPv6 address.
    let sin6 = unsafe { &*(&raw const raw.storage).cast::<libc::sockaddr_in6>() };
    assert_eq!(sin6.sin6_flowinfo.to_ne_bytes(), FLOWINFO.to_be_bytes());
}

#[test]
fn test_raw_socket_addr_ipv6_flowinfo_decode_uses_network_order() {
    const FLOWINFO: u32 = 0x0123_4567;
    let mut raw = RawSocketAddr::new_zeroed();
    let sin6 = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: 443u16.to_be(),
        sin6_flowinfo: u32::from_ne_bytes(FLOWINFO.to_be_bytes()),
        sin6_addr: libc::in6_addr {
            s6_addr: Ipv6Addr::LOCALHOST.octets(),
        },
        sin6_scope_id: 9,
    };
    assert_eq!(sin6.sin6_flowinfo.to_ne_bytes(), FLOWINFO.to_be_bytes());
    // SAFETY: sockaddr_in6 fits within sockaddr_storage and the destination
    // is valid for writes.
    unsafe {
        std::ptr::write((&raw mut raw.storage).cast::<libc::sockaddr_in6>(), sin6);
    }
    *raw.len_mut() = size_of::<libc::sockaddr_in6>() as libc::socklen_t;

    let Some(SocketAddr::V6(decoded)) = raw.to_socket_addr() else {
        panic!("kernel-form IPv6 address did not decode");
    };
    assert_eq!(decoded.flowinfo(), FLOWINFO);
}
