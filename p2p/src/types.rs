//! Shared address types for p2p networking.

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write};
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
        host: String,
        /// Port to connect to.
        port: u16,
    },
}

impl Ingress {
    /// Returns the port number for this ingress address.
    pub fn port(&self) -> u16 {
        match self {
            Self::Socket(addr) => addr.port(),
            Self::Dns { port, .. } => *port,
        }
    }

    /// Returns the IP address if this is a Socket variant.
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Socket(addr) => Some(addr.ip()),
            Self::Dns { .. } => None,
        }
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
                let bytes = host.as_bytes();
                bytes.len().write(buf);
                buf.put_slice(bytes);
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
                Self::Dns { host, port } => host.len().encode_size() + host.len() + port.encode_size(),
            }
    }
}

impl Read for Ingress {
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, max_host_len: &Self::Cfg) -> Result<Self, CodecError> {
        let prefix = u8::read(buf)?;
        match prefix {
            INGRESS_SOCKET_PREFIX => {
                let addr = SocketAddr::read(buf)?;
                Ok(Self::Socket(addr))
            }
            INGRESS_DNS_PREFIX => {
                let bytes = Vec::<u8>::read_cfg(buf, &(RangeCfg::new(..=*max_host_len), ()))?;
                let host = String::from_utf8(bytes)
                    .map_err(|_| CodecError::Invalid("Ingress::Dns", "Invalid UTF-8 hostname"))?;
                let port = u16::read(buf)?;
                Ok(Self::Dns { host, port })
            }
            _ => Err(CodecError::Invalid("Ingress", "Invalid prefix")),
        }
    }
}

impl From<SocketAddr> for Ingress {
    fn from(addr: SocketAddr) -> Self {
        Self::Socket(addr)
    }
}

/// Full address specification for lookup network (needs IP filtering).
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
    pub fn egress_ip(&self) -> IpAddr {
        match self {
            Self::Symmetric(addr) => addr.ip(),
            Self::Asymmetric { egress, .. } => egress.ip(),
        }
    }

    /// Returns the egress socket address.
    pub fn egress(&self) -> SocketAddr {
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
                Self::Asymmetric { ingress, egress } => ingress.encode_size() + egress.encode_size(),
            }
    }
}

impl Read for Address {
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, max_host_len: &Self::Cfg) -> Result<Self, CodecError> {
        let prefix = u8::read(buf)?;
        match prefix {
            ADDRESS_SYMMETRIC_PREFIX => {
                let addr = SocketAddr::read(buf)?;
                Ok(Self::Symmetric(addr))
            }
            ADDRESS_ASYMMETRIC_PREFIX => {
                let ingress = Ingress::read_cfg(buf, max_host_len)?;
                let egress = SocketAddr::read(buf)?;
                Ok(Self::Asymmetric { ingress, egress })
            }
            _ => Err(CodecError::Invalid("Address", "Invalid prefix")),
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
            let len: u8 = u.int_in_range(1..=64)?;
            let host: String = (0..len)
                .map(|_| u.choose(&['a', 'b', 'c', 'd', 'e', 'f', '1', '2', '3', '.', '-']))
                .collect::<Result<_, _>>()?;
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
    use commonware_codec::{Decode, Encode};
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
            let decoded = Ingress::decode_cfg(encoded, &256).unwrap();
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
                host: host.to_string(),
                port,
            };
            let encoded = ingress.encode();
            let decoded = Ingress::decode_cfg(encoded, &256).unwrap();
            assert_eq!(ingress, decoded);
        }
    }

    #[test]
    fn test_ingress_dns_max_len_exceeded() {
        let ingress = Ingress::Dns {
            host: "a".repeat(100),
            port: 8080,
        };
        let encoded = ingress.encode();
        let result = Ingress::decode_cfg(encoded, &50);
        assert!(result.is_err());
    }

    #[test]
    fn test_ingress_port() {
        let socket = Ingress::Socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080));
        assert_eq!(socket.port(), 8080);

        let dns = Ingress::Dns {
            host: "example.com".to_string(),
            port: 443,
        };
        assert_eq!(dns.port(), 443);
    }

    #[test]
    fn test_ingress_ip() {
        let socket = Ingress::Socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080));
        assert_eq!(socket.ip(), Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));

        let dns = Ingress::Dns {
            host: "example.com".to_string(),
            port: 443,
        };
        assert_eq!(dns.ip(), None);
    }

    #[test]
    fn test_address_symmetric_roundtrip() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let address = Address::Symmetric(addr);
        let encoded = address.encode();
        let decoded = Address::decode_cfg(encoded, &256).unwrap();
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
        let decoded = Address::decode_cfg(encoded, &256).unwrap();
        assert_eq!(address, decoded);
    }

    #[test]
    fn test_address_asymmetric_dns_roundtrip() {
        let egress_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 9090);
        let address = Address::Asymmetric {
            ingress: Ingress::Dns {
                host: "node.example.com".to_string(),
                port: 8080,
            },
            egress: egress_addr,
        };
        let encoded = address.encode();
        let decoded = Address::decode_cfg(encoded, &256).unwrap();
        assert_eq!(address, decoded);
    }

    #[test]
    fn test_address_helpers() {
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
        let egress_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 9090);

        let symmetric = Address::Symmetric(socket_addr);
        assert_eq!(symmetric.ingress(), Ingress::Socket(socket_addr));
        assert_eq!(symmetric.egress_ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(symmetric.egress(), socket_addr);

        let asymmetric = Address::Asymmetric {
            ingress: Ingress::Dns {
                host: "example.com".to_string(),
                port: 8080,
            },
            egress: egress_addr,
        };
        assert_eq!(
            asymmetric.ingress(),
            Ingress::Dns {
                host: "example.com".to_string(),
                port: 8080
            }
        );
        assert_eq!(asymmetric.egress_ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
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

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Ingress> => 1024,
            CodecConformance<Address> => 1024,
        }
    }
}
