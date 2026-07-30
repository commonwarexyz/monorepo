//! Shared address types for p2p networking.

use commonware_codec::{
    Codec, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write, config::RangeCfg,
};
use commonware_runtime::{Buf, BufMut, TcpEndpoint};
use commonware_utils::{Hostname, IpAddrExt, PlatformSend, PlatformSync};
use std::{
    collections::HashSet,
    fmt::Debug,
    hash::Hash,
    net::{IpAddr, SocketAddr},
};

const INGRESS_SOCKET_PREFIX: u8 = 0;
const INGRESS_DNS_PREFIX: u8 = 1;

const ADDRESS_SYMMETRIC_PREFIX: u8 = 0;
const ADDRESS_ASYMMETRIC_PREFIX: u8 = 1;

const REACHABILITY_DIALABLE_PREFIX: u8 = 0;
const REACHABILITY_OUTBOUND_ONLY_PREFIX: u8 = 1;

/// An endpoint that can be advertised to and dialed by peers.
pub trait PeerEndpoint:
    Clone + Debug + Eq + Hash + Codec<Cfg = ()> + EncodeSize + PlatformSend + PlatformSync + 'static
{
}

/// An ordered list of endpoints where earlier entries are preferred.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Advertisement<E: PeerEndpoint> {
    endpoints: Vec<E>,
}

impl<E: PeerEndpoint> Advertisement<E> {
    /// Maximum number of endpoints in an advertisement.
    pub const MAX_ENDPOINTS: usize = 8;

    /// Maximum encoded size of one endpoint.
    pub const MAX_ENDPOINT_SIZE: usize = 2_048;

    /// Maximum encoded size of an advertisement.
    pub const MAX_SIZE: usize = 8_192;

    /// Creates an advertisement, preserving the order of `endpoints`.
    pub fn new(endpoints: Vec<E>) -> Result<Self, CodecError> {
        if endpoints.is_empty() || endpoints.len() > Self::MAX_ENDPOINTS {
            return Err(CodecError::InvalidLength(endpoints.len()));
        }

        let mut unique = HashSet::with_capacity(endpoints.len());
        for endpoint in &endpoints {
            if endpoint.encode_size() > Self::MAX_ENDPOINT_SIZE {
                return Err(CodecError::Invalid(
                    "Advertisement",
                    "endpoint exceeds maximum encoded size",
                ));
            }
            if !unique.insert(endpoint) {
                return Err(CodecError::Invalid("Advertisement", "duplicate endpoint"));
            }
        }

        if endpoints.encode_size() > Self::MAX_SIZE {
            return Err(CodecError::Invalid(
                "Advertisement",
                "advertisement exceeds maximum encoded size",
            ));
        }

        Ok(Self { endpoints })
    }

    /// Returns endpoints in dialing preference order.
    pub fn endpoints(&self) -> &[E] {
        &self.endpoints
    }

    /// Consumes the advertisement and returns endpoints in dialing preference order.
    pub fn into_endpoints(self) -> Vec<E> {
        self.endpoints
    }
}

impl<E: PeerEndpoint> Write for Advertisement<E> {
    fn write(&self, buf: &mut impl BufMut) {
        self.endpoints.write(buf);
    }
}

impl<E: PeerEndpoint> EncodeSize for Advertisement<E> {
    fn encode_size(&self) -> usize {
        self.endpoints.encode_size()
    }
}

impl<E: PeerEndpoint> Read for Advertisement<E> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let endpoints = Vec::<E>::read_cfg(buf, &(RangeCfg::new(1..=Self::MAX_ENDPOINTS), ()))?;
        Self::new(endpoints)
    }
}

/// Whether and how a peer can be reached.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Reachability<E: PeerEndpoint> {
    /// The peer can be dialed using the advertised endpoints.
    Dialable(Advertisement<E>),
    /// The peer must establish outbound connections to participate.
    OutboundOnly,
}

impl<E: PeerEndpoint> Write for Reachability<E> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Dialable(advertisement) => {
                REACHABILITY_DIALABLE_PREFIX.write(buf);
                advertisement.write(buf);
            }
            Self::OutboundOnly => REACHABILITY_OUTBOUND_ONLY_PREFIX.write(buf),
        }
    }
}

impl<E: PeerEndpoint> EncodeSize for Reachability<E> {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::Dialable(advertisement) => advertisement.encode_size(),
                Self::OutboundOnly => 0,
            }
    }
}

impl<E: PeerEndpoint> Read for Reachability<E> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            REACHABILITY_DIALABLE_PREFIX => Ok(Self::Dialable(Advertisement::<E>::read(buf)?)),
            REACHABILITY_OUTBOUND_ONLY_PREFIX => Ok(Self::OutboundOnly),
            other => Err(CodecError::InvalidEnum(other)),
        }
    }
}

/// What we dial to connect to a peer.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

impl PeerEndpoint for Ingress {}

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
    /// For `Dns` addresses, the TCP transport checks resolved addresses before connecting.
    pub fn is_valid(&self, allow_private_ips: bool, allow_dns: bool) -> bool {
        match self {
            Self::Socket(addr) => allow_private_ips || IpAddrExt::is_global(&addr.ip()),
            Self::Dns { .. } => allow_dns,
        }
    }
}

impl From<&Ingress> for TcpEndpoint {
    fn from(value: &Ingress) -> Self {
        match value {
            Ingress::Socket(address) => Self::Socket(*address),
            Ingress::Dns { host, port } => Self::Dns {
                host: host.to_string(),
                port: *port,
            },
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

#[cfg(feature = "arbitrary")]
impl<'a, E> arbitrary::Arbitrary<'a> for Advertisement<E>
where
    E: PeerEndpoint + arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let len = u.int_in_range(1..=Self::MAX_ENDPOINTS)?;
        let mut endpoints = Vec::with_capacity(len);

        while endpoints.len() < len {
            let endpoint = E::arbitrary(u)?;
            if endpoint.encode_size() > Self::MAX_ENDPOINT_SIZE || endpoints.contains(&endpoint) {
                continue;
            }
            endpoints.push(endpoint);
        }

        Self::new(endpoints).map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, E> arbitrary::Arbitrary<'a> for Reachability<E>
where
    E: PeerEndpoint + arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        if u.arbitrary::<bool>()? {
            return Ok(Self::OutboundOnly);
        }

        Ok(Self::Dialable(u.arbitrary::<Advertisement<E>>()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_runtime::IoBuf;
    use commonware_utils::hostname;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct TestEndpoint(Vec<u8>);

    impl Write for TestEndpoint {
        fn write(&self, buf: &mut impl BufMut) {
            self.0.write(buf);
        }
    }

    impl EncodeSize for TestEndpoint {
        fn encode_size(&self) -> usize {
            self.0.encode_size()
        }
    }

    impl Read for TestEndpoint {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
            Vec::<u8>::read_cfg(buf, &(RangeCfg::new(..), ())).map(Self)
        }
    }

    impl PeerEndpoint for TestEndpoint {}

    fn assert_invalid_advertisement(endpoints: Vec<TestEndpoint>) {
        assert!(Advertisement::new(endpoints.clone()).is_err());
        assert!(Advertisement::<TestEndpoint>::decode(endpoints.encode()).is_err());
    }

    #[test]
    fn test_advertisement_roundtrip_preserves_preference() {
        let preferred = Ingress::Socket(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 8080));
        let fallback = Ingress::Dns {
            host: hostname!("fallback.example.com"),
            port: 443,
        };
        let advertisement = Advertisement::new(vec![preferred.clone(), fallback.clone()]).unwrap();

        let decoded = Advertisement::<Ingress>::decode(advertisement.encode()).unwrap();
        assert_eq!(decoded.endpoints(), &[preferred, fallback]);
        assert_eq!(decoded, advertisement);
    }

    #[test]
    fn test_advertisement_rejects_invalid_endpoints() {
        assert_invalid_advertisement(Vec::new());
        assert_invalid_advertisement(vec![TestEndpoint(vec![0]); 2]);
        assert_invalid_advertisement(
            (0..=Advertisement::<TestEndpoint>::MAX_ENDPOINTS)
                .map(|value| TestEndpoint(vec![value as u8]))
                .collect(),
        );

        let oversized_endpoint = vec![0; Advertisement::<TestEndpoint>::MAX_ENDPOINT_SIZE];
        assert!(
            TestEndpoint(oversized_endpoint.clone()).encode_size()
                > Advertisement::<TestEndpoint>::MAX_ENDPOINT_SIZE
        );
        assert_invalid_advertisement(vec![TestEndpoint(oversized_endpoint)]);

        let endpoints = (0..5)
            .map(|value| {
                let mut bytes = vec![0; 2_045];
                bytes[0] = value;
                TestEndpoint(bytes)
            })
            .collect::<Vec<_>>();
        assert!(
            endpoints.iter().all(|endpoint| endpoint.encode_size()
                <= Advertisement::<TestEndpoint>::MAX_ENDPOINT_SIZE)
        );
        assert!(endpoints.encode_size() > Advertisement::<TestEndpoint>::MAX_SIZE);
        assert_invalid_advertisement(endpoints);
    }

    #[test]
    fn test_reachability_roundtrip() {
        let endpoint = Ingress::Socket(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 8080));
        let cases = [
            Reachability::Dialable(Advertisement::new(vec![endpoint]).unwrap()),
            Reachability::OutboundOnly,
        ];

        for reachability in cases {
            let decoded = Reachability::<Ingress>::decode(reachability.encode()).unwrap();
            assert_eq!(decoded, reachability);
        }
    }

    #[test]
    fn test_reachability_rejects_invalid_prefix() {
        assert!(matches!(
            Reachability::<Ingress>::decode([2].as_slice()),
            Err(CodecError::InvalidEnum(2))
        ));
    }

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

        let result = Ingress::decode(IoBuf::from(buf));
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
            CodecConformance<Advertisement<Ingress>>,
            CodecConformance<Reachability<Ingress>>,
        }
    }
}
