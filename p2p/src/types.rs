//! Shared address types for p2p networking.

#[stability(ALPHA)]
pub use crate::reachability::{Advertisement, PeerEndpoint, Reachability};
use commonware_codec::{EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_macros::stability;
use commonware_runtime::{Buf, BufMut, Error as RuntimeError, Resolver, TcpEndpoint};
use commonware_utils::{Hostname, IpAddrExt};
use std::net::{IpAddr, SocketAddr};

const INGRESS_SOCKET_PREFIX: u8 = 0;
const INGRESS_DNS_PREFIX: u8 = 1;

const ADDRESS_SYMMETRIC_PREFIX: u8 = 0;
const ADDRESS_ASYMMETRIC_PREFIX: u8 = 1;

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

impl crate::reachability::PeerEndpoint for Ingress {}

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

impl Ingress {
    /// Resolves this ingress address to socket addresses.
    pub async fn resolve(
        &self,
        resolver: &impl Resolver,
    ) -> Result<impl Iterator<Item = SocketAddr>, RuntimeError> {
        match self {
            Self::Socket(address) => Ok(vec![*address].into_iter()),
            Self::Dns { host, port } => {
                let addresses = resolver.resolve(host.as_str()).await?;
                if addresses.is_empty() {
                    return Err(RuntimeError::ResolveFailed(host.to_string()));
                }
                Ok(addresses
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, *port))
                    .collect::<Vec<_>>()
                    .into_iter())
            }
        }
    }

    /// Resolves this ingress and filters addresses according to the private-IP policy.
    pub async fn resolve_filtered(
        &self,
        resolver: &impl Resolver,
        allow_private_ips: bool,
    ) -> Option<impl Iterator<Item = SocketAddr>> {
        let addresses = self.resolve(resolver).await.ok()?;
        Some(
            addresses
                .filter(move |address| allow_private_ips || IpAddrExt::is_global(&address.ip())),
        )
    }

    /// Converts this advertised ingress into a TCP dial attempt.
    pub(crate) fn tcp_endpoint(&self, allow_private_ips: bool) -> TcpEndpoint {
        match self {
            Self::Socket(address) => TcpEndpoint::Socket(*address),
            Self::Dns { host, port } => TcpEndpoint::Dns {
                host: host.to_string(),
                port: *port,
                allow_private_ips,
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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode, config::RangeCfg};
    use commonware_runtime::{IoBuf, Runner as _, deterministic};
    use commonware_utils::hostname;
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        sync::atomic::{AtomicUsize, Ordering},
    };

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct TestEndpoint(Vec<u8>);

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct IdentityOnlyEndpoint(u8);

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct RemainingEndpoint;

    #[cfg(feature = "arbitrary")]
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct SingletonEndpoint;

    static ENDPOINT_REMAINING: AtomicUsize = AtomicUsize::new(usize::MAX);

    #[cfg(feature = "arbitrary")]
    static SINGLETON_ENDPOINT_CALLS: AtomicUsize = AtomicUsize::new(0);

    #[cfg(feature = "arbitrary")]
    const SINGLETON_ENDPOINT_CALL_LIMIT: usize = 32;

    impl PeerEndpoint for IdentityOnlyEndpoint {}

    impl PeerEndpoint for RemainingEndpoint {}

    impl Read for RemainingEndpoint {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
            ENDPOINT_REMAINING.store(buf.remaining(), Ordering::Relaxed);
            Ok(Self)
        }
    }

    #[cfg(feature = "arbitrary")]
    impl PeerEndpoint for SingletonEndpoint {}

    #[cfg(feature = "arbitrary")]
    impl arbitrary::Arbitrary<'_> for SingletonEndpoint {
        fn arbitrary(_u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
            let calls = SINGLETON_ENDPOINT_CALLS.fetch_add(1, Ordering::Relaxed);
            if calls >= SINGLETON_ENDPOINT_CALL_LIMIT {
                return Err(arbitrary::Error::NotEnoughData);
            }

            Ok(Self)
        }
    }

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

    fn assert_invalid_encoded_advertisement(endpoints: Vec<TestEndpoint>) {
        let advertisement = Advertisement::new(endpoints.clone()).unwrap();
        assert!(advertisement.validate_encoded().is_err());
        assert!(Advertisement::new_encoded(endpoints.clone()).is_err());
        assert!(Advertisement::<TestEndpoint>::decode(endpoints.encode()).is_err());
    }

    #[test]
    fn test_advertisement_does_not_require_endpoint_codec() {
        let advertisement =
            Advertisement::new(vec![IdentityOnlyEndpoint(1), IdentityOnlyEndpoint(2)]).unwrap();

        assert_eq!(
            advertisement.endpoints(),
            &[IdentityOnlyEndpoint(1), IdentityOnlyEndpoint(2)]
        );
    }

    #[cfg(feature = "arbitrary")]
    #[test]
    fn test_advertisement_arbitrary_rejects_insufficient_unique_endpoints() {
        use arbitrary::Arbitrary;

        SINGLETON_ENDPOINT_CALLS.store(0, Ordering::Relaxed);
        // Select two endpoints, leaving no input for the endpoint generator to consume.
        let mut input = arbitrary::Unstructured::new(&[1]);

        let result = Advertisement::<SingletonEndpoint>::arbitrary(&mut input);

        assert_eq!(result, Err(arbitrary::Error::IncorrectFormat));
        assert!(SINGLETON_ENDPOINT_CALLS.load(Ordering::Relaxed) < SINGLETON_ENDPOINT_CALL_LIMIT);
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
    }

    #[test]
    fn test_advertisement_rejects_oversized_encoded_endpoint() {
        let endpoint = TestEndpoint(vec![0; Advertisement::<TestEndpoint>::MAX_ENDPOINT_SIZE]);
        assert!(endpoint.encode_size() > Advertisement::<TestEndpoint>::MAX_ENDPOINT_SIZE);

        assert_invalid_encoded_advertisement(vec![endpoint]);
    }

    #[test]
    fn test_advertisement_limits_endpoint_decoder_input() {
        let mut payload = 1usize.encode().to_vec();
        payload.resize(
            payload.len() + Advertisement::<RemainingEndpoint>::MAX_ENDPOINT_SIZE + 1,
            0,
        );

        let _ = Advertisement::<RemainingEndpoint>::decode(payload.as_slice());

        let remaining = ENDPOINT_REMAINING.load(Ordering::Relaxed);
        assert!(
            remaining <= Advertisement::<RemainingEndpoint>::MAX_ENDPOINT_SIZE,
            "endpoint decoder saw {remaining} bytes, maximum is {}",
            Advertisement::<RemainingEndpoint>::MAX_ENDPOINT_SIZE,
        );
    }

    #[test]
    fn test_advertisement_rejects_oversized_encoded_payload() {
        let endpoints = (0..5)
            .map(|value| {
                let mut bytes = vec![0; 2_045];
                bytes[0] = value;
                TestEndpoint(bytes)
            })
            .collect::<Vec<_>>();
        assert!(endpoints.iter().all(|endpoint| {
            endpoint.encode_size() <= Advertisement::<TestEndpoint>::MAX_ENDPOINT_SIZE
        }));
        assert!(endpoints.encode_size() > Advertisement::<TestEndpoint>::MAX_SIZE);

        assert_invalid_encoded_advertisement(endpoints);
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

    #[test]
    fn test_ingress_resolve_compatibility() {
        deterministic::Runner::default().start(|context| async move {
            let public = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
            let private = IpAddr::V4(Ipv4Addr::LOCALHOST);
            context.resolver_register("example.com", Some(vec![public, private]));
            let ingress = Ingress::Dns {
                host: hostname!("example.com"),
                port: 443,
            };

            let resolved = ingress.resolve(&context).await.unwrap().collect::<Vec<_>>();
            assert_eq!(
                resolved,
                vec![SocketAddr::new(public, 443), SocketAddr::new(private, 443)]
            );

            let filtered = ingress
                .resolve_filtered(&context, false)
                .await
                .unwrap()
                .collect::<Vec<_>>();
            assert_eq!(filtered, vec![SocketAddr::new(public, 443)]);
        });
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
