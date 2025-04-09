use crate::{Encode, Error, FixedSize, Read, ReadExt, Write};
use bytes::{Buf, BufMut};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

impl Write for Ipv4Addr {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        self.to_bits().write(buf);
    }
}

impl Read for Ipv4Addr {
    #[inline]
    fn read_cfg(buf: &mut impl Buf, _: ()) -> Result<Self, Error> {
        let bits = <u32>::read(buf)?;
        Ok(Ipv4Addr::from_bits(bits))
    }
}

impl FixedSize for Ipv4Addr {
    const LEN_ENCODED: usize = u32::LEN_ENCODED;
}

impl Write for Ipv6Addr {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        self.to_bits().write(buf);
    }
}

impl Read for Ipv6Addr {
    #[inline]
    fn read_cfg(buf: &mut impl Buf, _: ()) -> Result<Self, Error> {
        let bits = <u128>::read(buf)?;
        Ok(Ipv6Addr::from_bits(bits))
    }
}

impl FixedSize for Ipv6Addr {
    const LEN_ENCODED: usize = u128::LEN_ENCODED;
}

impl Write for SocketAddrV4 {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        self.ip().write(buf);
        self.port().write(buf);
    }
}

impl Read for SocketAddrV4 {
    #[inline]
    fn read_cfg(buf: &mut impl Buf, _: ()) -> Result<Self, Error> {
        let ip = Ipv4Addr::read(buf)?;
        let port = u16::read(buf)?;
        Ok(Self::new(ip, port))
    }
}

impl FixedSize for SocketAddrV4 {
    const LEN_ENCODED: usize = Ipv4Addr::LEN_ENCODED + u16::LEN_ENCODED;
}

impl Write for SocketAddrV6 {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        self.ip().write(buf);
        self.port().write(buf);
    }
}

impl Read for SocketAddrV6 {
    #[inline]
    fn read_cfg(buf: &mut impl Buf, _: ()) -> Result<Self, Error> {
        let address = Ipv6Addr::read(buf)?;
        let port = u16::read(buf)?;
        Ok(SocketAddrV6::new(address, port, 0, 0))
    }
}

impl FixedSize for SocketAddrV6 {
    const LEN_ENCODED: usize = Ipv6Addr::LEN_ENCODED + u16::LEN_ENCODED;
}

// SocketAddr implementation
impl Write for SocketAddr {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            SocketAddr::V4(v4) => {
                u8::write(&4, buf);
                v4.write(buf);
            }
            SocketAddr::V6(v6) => {
                u8::write(&6, buf);
                v6.write(buf);
            }
        }
    }
}

impl Encode for SocketAddr {
    #[inline]
    fn len_encoded(&self) -> usize {
        (match self {
            SocketAddr::V4(_) => SocketAddrV4::LEN_ENCODED,
            SocketAddr::V6(_) => SocketAddrV6::LEN_ENCODED,
        }) + u8::LEN_ENCODED
    }
}

impl Read for SocketAddr {
    #[inline]
    fn read_cfg(buf: &mut impl Buf, _: ()) -> Result<Self, Error> {
        let version = u8::read(buf)?;
        match version {
            4 => Ok(SocketAddr::V4(SocketAddrV4::read(buf)?)),
            6 => Ok(SocketAddr::V6(SocketAddrV6::read(buf)?)),
            _ => Err(Error::Invalid("SocketAddr", "Invalid version")),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::DecodeExt;
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
    fn test_socket_addr() {
        // Test SocketAddr::V4
        let addr_v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(196, 168, 0, 1), 8080));
        let encoded_v4 = addr_v4.encode();
        assert_eq!(encoded_v4.len(), 7);
        assert_eq!(addr_v4.len_encoded(), 7);
        let decoded_v4 = SocketAddr::decode(encoded_v4).unwrap();
        assert_eq!(addr_v4, decoded_v4);

        // Test SocketAddr::V6
        let addr_v6 = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0x0db8, 0xffff, 0x1234, 0x5678, 0x9abc, 0xdeff, 1),
            8080,
            0,
            0,
        ));
        let encoded_v6 = addr_v6.encode();
        assert_eq!(encoded_v6.len(), 19);
        assert_eq!(addr_v6.len_encoded(), 19);
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
}
