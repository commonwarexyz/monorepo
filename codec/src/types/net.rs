//! Codec implementations for network-related types

use crate::{EncodeSize, Error, FixedSize, Read, ReadExt, Write};
use bytes::{Buf, BufMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

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

        let sa_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        assert_eq!(sa_v4.encode(), &[0x04, 127, 0, 0, 1, 0x1F, 0x90][..]);
        let sa_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 443);
        assert_eq!(
            sa_v6.encode(),
            &[0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0xBB][..]
        );
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use crate::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Ipv4Addr>,
            CodecConformance<Ipv6Addr>,
            CodecConformance<IpAddr>,
            CodecConformance<SocketAddr>,
        }
    }
}
