//! Codec implementations for network-related types

use crate::{EncodeSize, Error, FixedSize, RangeCfg, Read, ReadExt, Write};
use bytes::{Buf, BufMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

/// Maximum length of a hostname (253 characters per RFC 1035).
///
/// While the DNS wire format allows 255 bytes total, the text representation
/// is limited to 253 characters (255 minus 2 bytes for length encoding overhead).
pub const MAX_HOSTNAME_LEN: usize = 253;

/// Maximum length of a single hostname label (63 characters per RFC 1035).
pub const MAX_HOSTNAME_LABEL_LEN: usize = 63;

/// A validated hostname.
///
/// This type ensures the hostname conforms to RFC 1035 and RFC 1123:
/// - Total length is at most 253 characters
/// - Each label (part between dots) is at most 63 characters
/// - Labels contain only ASCII letters, digits, and hyphens
/// - Labels do not start or end with a hyphen
/// - No empty labels (no consecutive dots, leading dots, or trailing dots)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hostname(String);

impl Hostname {
    /// Create a new hostname, validating it according to RFC 1035/1123.
    pub fn new(hostname: impl Into<String>) -> Result<Self, Error> {
        let hostname = hostname.into();
        Self::validate(&hostname)?;
        Ok(Self(hostname))
    }

    /// Validate a hostname string according to RFC 1035/1123.
    fn validate(hostname: &str) -> Result<(), Error> {
        if hostname.is_empty() {
            return Err(Error::Invalid("Hostname", "empty"));
        }

        if hostname.len() > MAX_HOSTNAME_LEN {
            return Err(Error::Invalid("Hostname", "too long"));
        }

        for label in hostname.split('.') {
            Self::validate_label(label)?;
        }

        Ok(())
    }

    /// Validate a single hostname label.
    fn validate_label(label: &str) -> Result<(), Error> {
        if label.is_empty() {
            return Err(Error::Invalid("Hostname", "empty label"));
        }

        if label.len() > MAX_HOSTNAME_LABEL_LEN {
            return Err(Error::Invalid("Hostname", "label too long"));
        }

        for c in label.chars() {
            if !c.is_ascii_alphanumeric() && c != '-' {
                return Err(Error::Invalid("Hostname", "invalid character"));
            }
        }

        if label.starts_with('-') {
            return Err(Error::Invalid("Hostname", "label starts with hyphen"));
        }
        if label.ends_with('-') {
            return Err(Error::Invalid("Hostname", "label ends with hyphen"));
        }

        Ok(())
    }

    /// Returns the hostname as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the hostname and returns the underlying String.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for Hostname {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Hostname {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<String> for Hostname {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for Hostname {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Creates a [`Hostname`] from a string literal or expression.
///
/// This macro panics if the hostname is invalid, making it suitable for
/// use with known-valid hostnames in tests or configuration.
///
/// # Examples
///
/// ```
/// use commonware_codec::hostname;
///
/// let h1 = hostname!("example.com");
/// let h2 = hostname!("sub.domain.example.com");
/// ```
///
/// # Panics
///
/// Panics if the provided string is not a valid hostname according to RFC 1035/1123.
#[macro_export]
macro_rules! hostname {
    ($s:expr) => {
        $crate::Hostname::new($s).expect("invalid hostname")
    };
}

impl Write for Hostname {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        self.0.as_bytes().to_vec().write(buf);
    }
}

impl EncodeSize for Hostname {
    #[inline]
    fn encode_size(&self) -> usize {
        self.0.as_bytes().to_vec().encode_size()
    }
}

impl Read for Hostname {
    type Cfg = ();

    #[inline]
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let bytes = Vec::<u8>::read_cfg(buf, &(RangeCfg::new(..=MAX_HOSTNAME_LEN), ()))?;
        let hostname =
            String::from_utf8(bytes).map_err(|_| Error::Invalid("Hostname", "invalid UTF-8"))?;
        Self::new(hostname)
    }
}

impl Write for Ipv4Addr {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        self.to_bits().write(buf);
    }
}

impl Read for Ipv4Addr {
    type Cfg = ();

    #[inline]
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        Ok(Self::from_bits(u32::read(buf)?))
    }
}

impl FixedSize for Ipv4Addr {
    const SIZE: usize = u32::SIZE;
}

impl Write for Ipv6Addr {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        self.to_bits().write(buf);
    }
}

impl Read for Ipv6Addr {
    type Cfg = ();

    #[inline]
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        Ok(Self::from_bits(u128::read(buf)?))
    }
}

impl FixedSize for Ipv6Addr {
    const SIZE: usize = u128::SIZE;
}

impl Write for SocketAddrV4 {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        self.ip().write(buf);
        self.port().write(buf);
    }
}

impl Read for SocketAddrV4 {
    type Cfg = ();

    #[inline]
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let ip = Ipv4Addr::read(buf)?;
        let port = u16::read(buf)?;
        Ok(Self::new(ip, port))
    }
}

impl FixedSize for SocketAddrV4 {
    const SIZE: usize = Ipv4Addr::SIZE + u16::SIZE;
}

impl Write for SocketAddrV6 {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        self.ip().write(buf);
        self.port().write(buf);
    }
}

impl Read for SocketAddrV6 {
    type Cfg = ();

    #[inline]
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let address = Ipv6Addr::read(buf)?;
        let port = u16::read(buf)?;
        Ok(Self::new(address, port, 0, 0))
    }
}

impl FixedSize for SocketAddrV6 {
    const SIZE: usize = Ipv6Addr::SIZE + u16::SIZE;
}

impl Write for IpAddr {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::V4(v4) => {
                4u8.write(buf);
                v4.write(buf);
            }
            Self::V6(v6) => {
                6u8.write(buf);
                v6.write(buf);
            }
        }
    }
}

impl EncodeSize for IpAddr {
    #[inline]
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::V4(_) => Ipv4Addr::SIZE,
                Self::V6(_) => Ipv6Addr::SIZE,
            }
    }
}

impl Read for IpAddr {
    type Cfg = ();

    #[inline]
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let version = u8::read(buf)?;
        match version {
            4 => Ok(Self::V4(Ipv4Addr::read(buf)?)),
            6 => Ok(Self::V6(Ipv6Addr::read(buf)?)),
            _ => Err(Error::Invalid("IpAddr", "Invalid version")),
        }
    }
}

// SocketAddr implementation
impl Write for SocketAddr {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        self.ip().write(buf);
        self.port().write(buf);
    }
}

impl EncodeSize for SocketAddr {
    #[inline]
    fn encode_size(&self) -> usize {
        self.ip().encode_size() + u16::SIZE
    }
}

impl Read for SocketAddr {
    type Cfg = ();

    #[inline]
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let ip = IpAddr::read(buf)?;
        let port = u16::read(buf)?;
        Ok(Self::new(ip, port))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Hostname {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let num_labels: u8 = u.int_in_range(1..=4)?;
        let mut labels = Vec::with_capacity(num_labels as usize);

        for _ in 0..num_labels {
            let label_len: u8 = u.int_in_range(1..=10)?;
            let label: String = (0..label_len)
                .map(|i| {
                    if i == 0 || i == label_len - 1 {
                        u.choose(&['a', 'b', 'c', 'd', 'e', '1', '2', '3'])
                    } else {
                        u.choose(&['a', 'b', 'c', 'd', 'e', '1', '2', '3', '-'])
                    }
                })
                .collect::<Result<_, _>>()?;
            labels.push(label);
        }

        let hostname = labels.join(".");
        Ok(Self(hostname))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{DecodeExt, Encode};
    use bytes::Bytes;

    #[test]
    fn test_ipv4_addr() {
        // Test various IPv4 addresses
        let ips = [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        ];

        for ip in ips.iter() {
            let encoded = ip.encode();
            assert_eq!(encoded.len(), 4);
            let decoded = Ipv4Addr::decode(encoded).unwrap();
            assert_eq!(*ip, decoded);
        }

        // Test insufficient data
        let insufficient = vec![0, 0, 0]; // 3 bytes instead of 4
        assert!(Ipv4Addr::decode(Bytes::from(insufficient)).is_err());
    }

    #[test]
    fn test_ipv6_addr() {
        // Test various IPv6 addresses
        let ips = [
            Ipv6Addr::UNSPECIFIED,
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            ),
        ];

        for ip in ips.iter() {
            let encoded = ip.encode();
            assert_eq!(encoded.len(), 16);
            let decoded = Ipv6Addr::decode(encoded).unwrap();
            assert_eq!(*ip, decoded);
        }

        // Test insufficient data
        let insufficient = Bytes::from(vec![0u8; 15]); // 15 bytes instead of 16
        assert!(Ipv6Addr::decode(insufficient).is_err());
    }

    #[test]
    fn test_socket_addr_v4() {
        // Test various SocketAddrV4 instances
        let addrs = [
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080),
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 65535),
        ];

        for addr in addrs.iter() {
            let encoded = addr.encode();
            assert_eq!(encoded.len(), 6);
            let decoded = SocketAddrV4::decode(encoded).unwrap();
            assert_eq!(*addr, decoded);
        }

        // Test insufficient data
        let insufficient = Bytes::from(vec![0u8; 5]); // 5 bytes instead of 6
        assert!(SocketAddrV4::decode(insufficient).is_err());
    }

    #[test]
    fn test_socket_addr_v6() {
        // Test various SocketAddrV6 instances
        let addrs = [
            SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0),
            SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8080, 0, 0),
            SocketAddrV6::new(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1), 65535, 0, 0),
        ];

        for addr in addrs.iter() {
            let encoded = addr.encode();
            assert_eq!(encoded.len(), 18);
            let decoded = SocketAddrV6::decode(encoded).unwrap();
            assert_eq!(*addr, decoded);
        }

        // Test insufficient data
        let insufficient = Bytes::from(vec![0u8; 17]); // 17 bytes instead of 18
        assert!(SocketAddrV6::decode(insufficient).is_err());
    }

    #[test]
    fn test_ip_addr() {
        // Test IpAddr::V4
        let addr_v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let encoded_v4 = addr_v4.encode();
        assert_eq!(encoded_v4.len(), 5);
        assert_eq!(addr_v4.encode_size(), 5);
        let decoded_v4 = IpAddr::decode(encoded_v4).unwrap();
        assert_eq!(addr_v4, decoded_v4);

        // Test IpAddr::V6
        let addr_v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
        let encoded_v6 = addr_v6.encode();
        assert_eq!(encoded_v6.len(), 17);
        assert_eq!(addr_v6.encode_size(), 17);
        let decoded_v6 = IpAddr::decode(encoded_v6).unwrap();
        assert_eq!(addr_v6, decoded_v6);

        // Test invalid version
        let invalid_version = [5];
        assert!(matches!(
            IpAddr::decode(&invalid_version[..]),
            Err(Error::Invalid(_, _))
        ));

        // Test insufficient data for V4
        let insufficient_v4 = [4, 127, 0, 0]; // Version + 3 bytes instead of 4
        assert!(IpAddr::decode(&insufficient_v4[..]).is_err());

        // Test insufficient data for V6
        let mut insufficient_v6 = vec![6];
        insufficient_v6.extend_from_slice(&[0; 15]); // 15 bytes instead of 16
        assert!(IpAddr::decode(&insufficient_v6[..]).is_err());
    }

    #[test]
    fn test_socket_addr() {
        // Test SocketAddr V4
        let addr_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(196, 168, 0, 1)), 8080);
        let encoded_v4 = addr_v4.encode();
        assert_eq!(encoded_v4.len(), 7);
        assert_eq!(addr_v4.encode_size(), 7);
        let decoded_v4 = SocketAddr::decode(encoded_v4).unwrap();
        assert_eq!(addr_v4, decoded_v4);

        // Test SocketAddr V6
        let addr_v6 = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(
                0x2001, 0x0db8, 0xffff, 0x1234, 0x5678, 0x9abc, 0xdeff, 1,
            )),
            8080,
        );
        let encoded_v6 = addr_v6.encode();
        assert_eq!(encoded_v6.len(), 19);
        assert_eq!(addr_v6.encode_size(), 19);
        let decoded_v6 = SocketAddr::decode(encoded_v6).unwrap();
        assert_eq!(addr_v6, decoded_v6);

        // Test invalid version
        let invalid_version = [5]; // Neither 4 nor 6
        assert!(matches!(
            SocketAddr::decode(&invalid_version[..]),
            Err(Error::Invalid(_, _))
        ));

        // Test insufficient data for V4
        let mut insufficient_v4 = vec![4]; // Version byte
        insufficient_v4.extend_from_slice(&[127, 0, 0, 1, 0x1f]); // IP + 1 byte of port (5 bytes total)
        assert!(SocketAddr::decode(&insufficient_v4[..]).is_err());

        // Test insufficient data for V6
        let mut insufficient_v6 = vec![6]; // Version byte
        insufficient_v6.extend_from_slice(&[0; 17]); // 17 bytes instead of 18
        assert!(SocketAddr::decode(&insufficient_v6[..]).is_err());
    }

    #[test]
    fn test_conformity() {
        assert_eq!(Ipv4Addr::new(0, 0, 0, 0).encode(), &[0, 0, 0, 0][..]);
        assert_eq!(Ipv4Addr::new(127, 0, 0, 1).encode(), &[127, 0, 0, 1][..]);
        assert_eq!(
            Ipv4Addr::new(192, 168, 1, 100).encode(),
            &[192, 168, 1, 100][..]
        );
        assert_eq!(
            Ipv4Addr::new(255, 255, 255, 255).encode(),
            &[255, 255, 255, 255][..]
        );

        assert_eq!(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0).encode(), &[0; 16][..]);
        assert_eq!(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).encode(),
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1][..]
        );
        let ipv6_test: Ipv6Addr = "2001:db8::ff00:42:8329".parse().unwrap();
        assert_eq!(
            ipv6_test.encode(),
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0xff, 0x00, 0, 0x42, 0x83, 0x29][..]
        );
        assert_eq!(
            Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff).encode(),
            &[0xff; 16][..]
        );

        let sock_v4_1 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 80);
        assert_eq!(sock_v4_1.encode(), &[10, 0, 0, 1, 0x00, 0x50][..]);
        let sock_v4_2 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 20, 30), 65535);
        assert_eq!(sock_v4_2.encode(), &[192, 168, 20, 30, 0xFF, 0xFF][..]);

        let sock_v6_1 =
            SocketAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 8080, 0, 0);
        assert_eq!(
            sock_v6_1.encode(),
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x1F, 0x90][..]
        );

        let sa_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        assert_eq!(sa_v4.encode(), &[0x04, 127, 0, 0, 1, 0x1F, 0x90][..]);
        let sa_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 443);
        assert_eq!(
            sa_v6.encode(),
            &[0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0xBB][..]
        );
    }

    #[test]
    fn test_hostname_valid() {
        // Simple hostnames
        assert!(Hostname::new("localhost").is_ok());
        assert!(Hostname::new("example").is_ok());
        assert!(Hostname::new("a").is_ok());

        // Multi-label hostnames
        assert!(Hostname::new("example.com").is_ok());
        assert!(Hostname::new("sub.example.com").is_ok());
        assert!(Hostname::new("deep.sub.example.com").is_ok());

        // Hostnames with hyphens
        assert!(Hostname::new("my-host").is_ok());
        assert!(Hostname::new("my-example-host.com").is_ok());
        assert!(Hostname::new("a-b-c.d-e-f.com").is_ok());

        // Hostnames with numbers (RFC 1123 allows labels to start with digits)
        assert!(Hostname::new("123").is_ok());
        assert!(Hostname::new("123.456").is_ok());
        assert!(Hostname::new("host1.example2.com").is_ok());
        assert!(Hostname::new("1host.2example.3com").is_ok());

        // Mixed case (valid but should be treated case-insensitively by DNS)
        assert!(Hostname::new("Example.COM").is_ok());
        assert!(Hostname::new("MyHost.Example.Com").is_ok());
    }

    #[test]
    fn test_hostname_invalid_empty() {
        assert!(matches!(
            Hostname::new("").unwrap_err(),
            Error::Invalid("Hostname", "empty")
        ));
    }

    #[test]
    fn test_hostname_invalid_too_long() {
        // Create a hostname that's exactly 255 characters (over the 253 limit)
        // Use 63-char labels separated by dots: 63 + 1 + 63 + 1 + 63 + 1 + 63 = 255
        let long_label = "a".repeat(63);
        let long_hostname = format!("{long_label}.{long_label}.{long_label}.{long_label}");
        assert_eq!(long_hostname.len(), 255);
        assert!(matches!(
            Hostname::new(&long_hostname).unwrap_err(),
            Error::Invalid("Hostname", "too long")
        ));

        // Hostname at exactly 253 characters should be valid
        // Use 63-char labels: 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253
        let short_label = "a".repeat(61);
        let valid_long = format!("{long_label}.{long_label}.{long_label}.{short_label}");
        assert_eq!(valid_long.len(), 253);
        assert!(Hostname::new(&valid_long).is_ok());
    }

    #[test]
    fn test_hostname_invalid_label_too_long() {
        // Label longer than 63 characters
        let long_label = "a".repeat(64);
        assert!(matches!(
            Hostname::new(&long_label).unwrap_err(),
            Error::Invalid("Hostname", "label too long")
        ));

        // Label with exactly 63 characters should be valid
        let valid_label = "a".repeat(63);
        assert!(Hostname::new(&valid_label).is_ok());
    }

    #[test]
    fn test_hostname_invalid_empty_label() {
        // Leading dot
        assert!(matches!(
            Hostname::new(".example.com").unwrap_err(),
            Error::Invalid("Hostname", "empty label")
        ));

        // Trailing dot
        assert!(matches!(
            Hostname::new("example.com.").unwrap_err(),
            Error::Invalid("Hostname", "empty label")
        ));

        // Consecutive dots
        assert!(matches!(
            Hostname::new("example..com").unwrap_err(),
            Error::Invalid("Hostname", "empty label")
        ));
    }

    #[test]
    fn test_hostname_invalid_characters() {
        // Underscore (common mistake)
        assert!(matches!(
            Hostname::new("my_host.com").unwrap_err(),
            Error::Invalid("Hostname", "invalid character")
        ));

        // Space
        assert!(matches!(
            Hostname::new("my host.com").unwrap_err(),
            Error::Invalid("Hostname", "invalid character")
        ));

        // Special characters
        assert!(matches!(
            Hostname::new("host@example.com").unwrap_err(),
            Error::Invalid("Hostname", "invalid character")
        ));
        assert!(matches!(
            Hostname::new("host!.com").unwrap_err(),
            Error::Invalid("Hostname", "invalid character")
        ));

        // Unicode characters
        assert!(matches!(
            Hostname::new("hôst.com").unwrap_err(),
            Error::Invalid("Hostname", "invalid character")
        ));
    }

    #[test]
    fn test_hostname_invalid_hyphen_position() {
        // Label starting with hyphen
        assert!(matches!(
            Hostname::new("-example.com").unwrap_err(),
            Error::Invalid("Hostname", "label starts with hyphen")
        ));
        assert!(matches!(
            Hostname::new("example.-sub.com").unwrap_err(),
            Error::Invalid("Hostname", "label starts with hyphen")
        ));

        // Label ending with hyphen
        assert!(matches!(
            Hostname::new("example-.com").unwrap_err(),
            Error::Invalid("Hostname", "label ends with hyphen")
        ));
        assert!(matches!(
            Hostname::new("example.sub-.com").unwrap_err(),
            Error::Invalid("Hostname", "label ends with hyphen")
        ));

        // Single hyphen label
        assert!(matches!(
            Hostname::new("-").unwrap_err(),
            Error::Invalid("Hostname", "label starts with hyphen")
        ));
    }

    #[test]
    fn test_hostname_codec_roundtrip() {
        let hostnames = [
            "localhost",
            "example.com",
            "sub.example.com",
            "my-host.example.com",
            "host123.test",
        ];

        for hostname_str in hostnames {
            let hostname = Hostname::new(hostname_str).unwrap();
            let encoded = hostname.encode();
            let decoded = Hostname::decode(encoded).unwrap();
            assert_eq!(hostname, decoded);
            assert_eq!(hostname.as_str(), hostname_str);
        }
    }

    #[test]
    fn test_hostname_encode_size() {
        let hostname = Hostname::new("example.com").unwrap();
        let encoded = hostname.encode();
        assert_eq!(encoded.len(), hostname.encode_size());

        // Size should be: varint length prefix + actual bytes
        // "example.com" is 11 bytes, varint for 11 is 1 byte
        assert_eq!(hostname.encode_size(), 1 + 11);
    }

    #[test]
    fn test_hostname_decode_invalid_utf8() {
        // Create invalid UTF-8 bytes
        let invalid_utf8: Vec<u8> = vec![
            3, // length prefix (varint)
            0xff, 0xfe, 0xfd, // invalid UTF-8 sequence
        ];
        assert!(Hostname::decode(&invalid_utf8[..]).is_err());
    }

    #[test]
    fn test_hostname_decode_invalid_format() {
        // Valid UTF-8 but invalid hostname format (has underscore)
        let invalid_hostname = "invalid_host";
        let mut encoded = Vec::new();
        encoded.push(invalid_hostname.len() as u8); // length prefix
        encoded.extend_from_slice(invalid_hostname.as_bytes());
        assert!(Hostname::decode(&encoded[..]).is_err());
    }

    #[test]
    fn test_hostname_try_from() {
        // From String
        let hostname: Result<Hostname, _> = "example.com".to_string().try_into();
        assert!(hostname.is_ok());

        // From &str
        let hostname: Result<Hostname, _> = "example.com".try_into();
        assert!(hostname.is_ok());

        // Invalid
        let hostname: Result<Hostname, _> = "invalid..host".try_into();
        assert!(hostname.is_err());
    }

    #[test]
    fn test_hostname_display_and_as_ref() {
        let hostname = Hostname::new("example.com").unwrap();
        assert_eq!(format!("{hostname}"), "example.com");
        assert_eq!(hostname.as_ref(), "example.com");
        assert_eq!(hostname.as_str(), "example.com");
    }

    #[test]
    fn test_hostname_into_string() {
        let hostname = Hostname::new("example.com").unwrap();
        let s: String = hostname.into_string();
        assert_eq!(s, "example.com");
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use crate::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Ipv4Addr>,
            CodecConformance<Ipv6Addr>,
            CodecConformance<SocketAddrV4>,
            CodecConformance<SocketAddrV6>,
            CodecConformance<IpAddr>,
            CodecConformance<SocketAddr>,
            CodecConformance<Hostname>,
        }
    }
}
