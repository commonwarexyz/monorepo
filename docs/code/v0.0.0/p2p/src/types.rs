//! Shared address types for p2p networking.

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_runtime::{Error as RuntimeError, Resolver};
use commonware_utils::{Hostname, IpAddrExt};
use std::net::{IpAddr, SocketAddr};

const INGRESS_SOCKET_PREFIX: u8 = 0;
const INGRESS_DNS_PREFIX: u8 = 1;

const ADDRESS_SYMMETRIC_PREFIX: u8 = 0;
const ADDRESS_ASYMMETRIC_PREFIX: u8 = 1;

/// What we dial to connect to a peer.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ingress {
    /// IP-based ingress address.
    Socket(SocketAddr),
    /// DNS-based ingress address.
    Dns {
        /// Hostname to resolve.
        host: Hostname,
        /// Port to connect to.
        port: u16,
    },
}

impl Ingress {
    /// Returns the port number for this ingress address.
    pub const fn port(&self) -> u16 {
        match self {
            Self::Socket(addr) => addr.port(),
            Self::Dns { port, .. } => *port,
        }
    }

    /// Returns the IP address if this is a Socket variant.
    pub const fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Socket(addr) => Some(addr.ip()),
            Self::Dns { .. } => None,
        }
    }

    /// Returns whether this ingress address is allowed given the configuration.
    ///
    /// - `Socket` addresses must have a global IP (or `allow_private_ips` must be true).
    /// - `Dns` addresses are allowed only if `allow_dns` is `true`.
    ///
    /// Note: For `Dns` addresses, private IP checks are performed after resolution in
    /// [`resolve_filtered`](Self::resolve_filtered).
    pub fn is_valid(&self, allow_private_ips: bool, allow_dns: bool) -> bool {
        match self {
            Self::Socket(addr) => allow_private_ips || IpAddrExt::is_global(&addr.ip()),
            Self::Dns { .. } => allow_dns,
        }
    }

    /// Resolve this ingress address to socket addresses.
    ///
    /// For `Socket` variants, returns a single-element iterator.
    /// For `Dns` variants, performs DNS resolution and returns all resolved addresses.
    pub async fn resolve(
        &self,
        resolver: &impl Resolver,
    ) -> Result<impl Iterator<Item = SocketAddr>, RuntimeError> {
        match self {
            Self::Socket(addr) => Ok(vec![*addr].into_iter()),
            Self::Dns { host, port } => {
                let ips = resolver.resolve(host.as_str()).await?;
                if ips.is_empty() {
                    return Err(RuntimeError::ResolveFailed(host.to_string()));
                }
                Ok(ips
                    .into_iter()
                    .map(move |ip| SocketAddr::new(ip, *port))
                    .collect::<Vec<_>>()
                    .into_iter())
            }
        }
    }

    /// [`resolve`](Self::resolve) and filter by private IP policy.
    pub async fn resolve_filtered(
        &self,
        resolver: &impl Resolver,
        allow_private_ips: bool,
    ) -> Option<impl Iterator<Item = SocketAddr>> {
        let addrs = self.resolve(resolver).await.ok()?;
        Some(addrs.filter(move |addr| allow_private_ips || IpAddrExt::is_global(&addr.ip())))
    }
}

impl Write for Ingress {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Socket(addr) => {
                INGRESS_SOCKET_PREFIX.write(buf);
                addr.write(buf);
            }
            Self::Dns { host, port } => {
                INGRESS_DNS_PREFIX.write(buf);
                host.write(buf);
                port.write(buf);
            }
        }
    }
}

impl EncodeSize for Ingress {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::Socket(addr) => addr.encode_size(),
                Self::Dns { host, port } => host.encode_size() + port.encode_size(),
            }
    }
}

impl Read for Ingress {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let prefix = u8::read(buf)?;
        match prefix {
            INGRESS_SOCKET_PREFIX => {
                let addr = SocketAddr::read(buf)?;
                Ok(Self::Socket(addr))
            }
            INGRESS_DNS_PREFIX => {
                let host = Hostname::read(buf)?;
                let port = u16::read(buf)?;
                Ok(Self::Dns { host, port })
            }
            other => Err(CodecError::InvalidEnum(other)),
        }
    }
}

impl From<SocketAddr> for Ingress {
    fn from(addr: SocketAddr) -> Self {
        Self::Socket(addr)
    }
}

/// Full address specification for peer-to-peer networking.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Address {
    /// Same address for both ingress (dialing) and egress (IP filtering).
    Symmetric(SocketAddr),
    /// Different addresses for ingress and egress.
    Asymmetric {
        /// The address we dial to connect.
        ingress: Ingress,
        /// The IP we expect connections from (used for filtering).
        egress: SocketAddr,
    },
}

impl Address {
    /// Returns the ingress address for dialing.
    pub fn ingress(&self) -> Ingress {
        match self {
            Self::Symmetric(addr) => Ingress::Socket(*addr),
            Self::Asymmetric { ingress, .. } => ingress.clone(),
        }
    }

    /// Returns the egress IP address for filtering.
    pub const fn egress_ip(&self) -> IpAddr {
        match self {
            Self::Symmetric(addr) => addr.ip(),
            Self::Asymmetric { egress, .. } => egress.ip(),
        }
    }

    /// Returns the egress socket address.
    pub const fn egress(&self) -> SocketAddr {
        match self {
            Self::Symmetric(addr) => *addr,
            Self::Asymmetric { egress, .. } => *egress,
        }
    }
}

impl Write for Address {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Symmetric(addr) => {
                ADDRESS_SYMMETRIC_PREFIX.write(buf);
                addr.write(buf);
            }
            Self::Asymmetric { ingress, egress } => {
                ADDRESS_ASYMMETRIC_PREFIX.write(buf);
                ingress.write(buf);
                egress.write(buf);
            }
        }
    }
}

impl EncodeSize for Address {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::Symmetric(addr) => addr.encode_size(),
                Self::Asymmetric { ingress, egress } => {
                    ingress.encode_size() + egress.encode_size()
                }
            }
    }
}

impl Read for Address {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let prefix = u8::read(buf)?;
        match prefix {
            ADDRESS_SYMMETRIC_PREFIX => {
                let addr = SocketAddr::read(buf)?;
                Ok(Self::Symmetric(addr))
            }
            ADDRESS_ASYMMETRIC_PREFIX => {
                let ingress = Ingress::read(buf)?;
                let egress = SocketAddr::read(buf)?;
                Ok(Self::Asymmetric { ingress, egress })
            }
            other => Err(CodecError::InvalidEnum(other)),
        }
    }
}

impl From<SocketAddr> for Address {
    fn from(addr: SocketAddr) -> Self {
        Self::Symmetric(addr)
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Ingress {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        if u.ratio(1, 2)? {
            Ok(Self::Socket(u.arbitrary()?))
        } else {
            let host: Hostname = u.arbitrary()?;
            let port = u.arbitrary()?;
            Ok(Self::Dns { host, port })
        }
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Address {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        if u.ratio(1, 2)? {
            Ok(Self::Symmetric(u.arbitrary()?))
        } else {
            Ok(Self::Asymmetric {
                ingress: u.arbitrary()?,
                egress: u.arbitrary()?,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_utils::hostname;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_ingress_socket_roundtrip() {
        let addrs = [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 65535),
        ];

        for addr in addrs {
            let ingress = Ingress::Socket(addr);
            let encoded = ingress.encode();
            let decoded = Ingress::decode(encoded).unwrap();
            assert_eq!(ingress, decoded);
        }
    }

    #[test]
    fn test_ingress_dns_roundtrip() {
        let cases = [
            ("localhost", 8080),
            ("example.com", 443),
            ("a.b.c.d.e.f.g", 1234),
        ];

        for (host, port) in cases {
            let ingress = Ingress::Dns {
                host: hostname!(host),
                port,
            };
            let encoded = ingress.encode();
            let decoded = Ingress::decode(encoded).unwrap();
            assert_eq!(ingress, decoded);
        }
    }

    #[test]
    fn test_ingress_dns_max_len_exceeded() {
        // Manually encode an invalid DNS entry with a hostname that's too long
        // (Hostname::new() would reject this, so we encode manually)
        let mut buf = Vec::new();
        INGRESS_DNS_PREFIX.write(&mut buf);
        let long_hostname = "a".repeat(300);
        long_hostname.len().write(&mut buf);
        buf.extend(long_hostname.as_bytes());
        8080u16.write(&mut buf);

        let result = Ingress::decode(bytes::Bytes::from(buf));
        assert!(result.is_err());
    }

    #[test]
    fn test_ingress_port() {
        let socket = Ingress::Socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080));
        assert_eq!(socket.port(), 8080);

        let dns = Ingress::Dns {
            host: hostname!("example.com"),
            port: 443,
        };
        assert_eq!(dns.port(), 443);
    }

    #[test]
    fn test_ingress_ip() {
        let socket = Ingress::Socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080));
        assert_eq!(socket.ip(), Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));

        let dns = Ingress::Dns {
            host: hostname!("example.com"),
            port: 443,
        };
        assert_eq!(dns.ip(), None);
    }

    #[test]
    fn test_address_symmetric_roundtrip() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let address = Address::Symmetric(addr);
        let encoded = address.encode();
        let decoded = Address::decode(encoded).unwrap();
        assert_eq!(address, decoded);
    }

    #[test]
    fn test_address_asymmetric_socket_roundtrip() {
        let ingress_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
        let egress_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 9090);
        let address = Address::Asymmetric {
            ingress: Ingress::Socket(ingress_addr),
            egress: egress_addr,
        };
        let encoded = address.encode();
        let decoded = Address::decode(encoded).unwrap();
        assert_eq!(address, decoded);
    }

    #[test]
    fn test_address_asymmetric_dns_roundtrip() {
        let egress_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 9090);
        let address = Address::Asymmetric {
            ingress: Ingress::Dns {
                host: hostname!("node.example.com"),
                port: 8080,
            },
            egress: egress_addr,
        };
        let encoded = address.encode();
        let decoded = Address::decode(encoded).unwrap();
        assert_eq!(address, decoded);
    }

    #[test]
    fn test_address_helpers() {
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
        let egress_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 9090);

        let symmetric = Address::Symmetric(socket_addr);
        assert_eq!(symmetric.ingress(), Ingress::Socket(socket_addr));
        assert_eq!(
            symmetric.egress_ip(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(symmetric.egress(), socket_addr);

        let asymmetric = Address::Asymmetric {
            ingress: Ingress::Dns {
                host: hostname!("example.com"),
                port: 8080,
            },
            egress: egress_addr,
        };
        assert_eq!(
            asymmetric.ingress(),
            Ingress::Dns {
                host: hostname!("example.com"),
                port: 8080
            }
        );
        assert_eq!(
            asymmetric.egress_ip(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(asymmetric.egress(), egress_addr);
    }

    #[test]
    fn test_from_socket_addr() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);

        let ingress: Ingress = addr.into();
        assert_eq!(ingress, Ingress::Socket(addr));

        let address: Address = addr.into();
        assert_eq!(address, Address::Symmetric(addr));
    }

    #[test]
    fn test_ingress_is_allowed() {
        let public_socket =
            Ingress::Socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 8080));
        let private_socket = Ingress::Socket(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8080,
        ));
        let dns = Ingress::Dns {
            host: hostname!("example.com"),
            port: 8080,
        };

        // Public socket is allowed regardless of allow_private_ips
        assert!(public_socket.is_valid(false, false));
        assert!(public_socket.is_valid(false, true));
        assert!(public_socket.is_valid(true, false));
        assert!(public_socket.is_valid(true, true));

        // Private socket is only allowed when allow_private_ips=true
        assert!(!private_socket.is_valid(false, false));
        assert!(!private_socket.is_valid(false, true));
        assert!(private_socket.is_valid(true, false));
        assert!(private_socket.is_valid(true, true));

        // DNS is allowed only when allow_dns=true (private IP check happens after resolution)
        assert!(!dns.is_valid(false, false));
        assert!(dns.is_valid(false, true));
        assert!(!dns.is_valid(true, false));
        assert!(dns.is_valid(true, true));
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Ingress>,
            CodecConformance<Address>,
        }
    }
}
