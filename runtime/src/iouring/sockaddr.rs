use std::{
    mem::size_of,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

/// Raw socket address storage passed to the kernel.
///
/// Requests box this so the pointers handed to the kernel stay stable for the
/// request lifetime. Serves as an output parameter for accept and getsockname,
/// and an input parameter for connect and bind.
pub(crate) struct RawSocketAddr {
    storage: libc::sockaddr_storage,
    len: libc::socklen_t,
}

impl RawSocketAddr {
    /// Return zeroed scratch for the kernel to fill.
    pub(crate) const fn new_zeroed() -> Self {
        Self {
            // SAFETY: `sockaddr_storage` is plain old data for which zeroes are
            // a valid (if empty) representation.
            storage: unsafe { std::mem::zeroed() },
            len: size_of::<libc::sockaddr_storage>() as libc::socklen_t,
        }
    }

    /// Return boxed zeroed scratch for the kernel to fill during accept.
    pub(super) fn zeroed() -> Box<Self> {
        Box::new(Self::new_zeroed())
    }

    /// Return a pointer to the underlying `sockaddr` for kernel reads.
    pub(crate) const fn as_sockaddr_ptr(&self) -> *const libc::sockaddr {
        (&raw const self.storage).cast::<libc::sockaddr>()
    }

    /// Return a pointer to the underlying `sockaddr` for kernel writes.
    pub(crate) const fn as_sockaddr_mut_ptr(&mut self) -> *mut libc::sockaddr {
        (&raw mut self.storage).cast::<libc::sockaddr>()
    }

    /// Return the encoded address length.
    pub(crate) const fn len(&self) -> libc::socklen_t {
        self.len
    }

    /// Return a mutable reference to the address length for kernel writes.
    pub(crate) const fn len_mut(&mut self) -> &mut libc::socklen_t {
        &mut self.len
    }

    /// Encode `addr` for the kernel to read during connect or bind.
    pub(crate) fn boxed_from_socket_addr(addr: &SocketAddr) -> Box<Self> {
        Box::new(Self::from_socket_addr(addr))
    }

    /// Encode `addr` for the kernel to read during connect or bind.
    pub(crate) const fn from_socket_addr(addr: &SocketAddr) -> Self {
        let mut raw = Self::new_zeroed();
        match addr {
            SocketAddr::V4(v4) => {
                let sin = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: v4.port().to_be(),
                    sin_addr: libc::in_addr {
                        // `s_addr` is stored in network byte order, which the
                        // octets already are.
                        s_addr: u32::from_ne_bytes(v4.ip().octets()),
                    },
                    sin_zero: [0; 8],
                };
                // SAFETY: `sockaddr_in` fits within `sockaddr_storage` and the
                // destination is valid for writes.
                unsafe {
                    std::ptr::write((&raw mut raw.storage).cast::<libc::sockaddr_in>(), sin);
                }
                raw.len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
            }
            SocketAddr::V6(v6) => {
                let sin6 = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: v6.port().to_be(),
                    sin6_flowinfo: v6.flowinfo().to_be(),
                    sin6_addr: libc::in6_addr {
                        s6_addr: v6.ip().octets(),
                    },
                    sin6_scope_id: v6.scope_id(),
                };
                // SAFETY: `sockaddr_in6` fits within `sockaddr_storage` and the
                // destination is valid for writes.
                unsafe {
                    std::ptr::write((&raw mut raw.storage).cast::<libc::sockaddr_in6>(), sin6);
                }
                raw.len = size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            }
        }
        raw
    }

    /// Decode the kernel-written address, if it is a valid TCP peer address.
    pub(crate) fn to_socket_addr(&self) -> Option<SocketAddr> {
        match i32::from(self.storage.ss_family) {
            libc::AF_INET => {
                if (self.len as usize) < size_of::<libc::sockaddr_in>() {
                    return None;
                }
                // SAFETY: the family and length checks above guarantee the
                // storage holds an initialized `sockaddr_in`.
                let sin = unsafe { &*(&raw const self.storage).cast::<libc::sockaddr_in>() };
                Some(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes()),
                    u16::from_be(sin.sin_port),
                )))
            }
            libc::AF_INET6 => {
                if (self.len as usize) < size_of::<libc::sockaddr_in6>() {
                    return None;
                }
                // SAFETY: the family and length checks above guarantee the
                // storage holds an initialized `sockaddr_in6`.
                let sin6 = unsafe { &*(&raw const self.storage).cast::<libc::sockaddr_in6>() };
                Some(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(sin6.sin6_addr.s6_addr),
                    u16::from_be(sin6.sin6_port),
                    u32::from_be(sin6.sin6_flowinfo),
                    sin6.sin6_scope_id,
                )))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
