//! PROXY protocol support.
//!
//! The PROXY protocol allows TCP proxies (HAProxy, nginx, AWS NLB) to
//! transmit the original client connection information to backend servers.
//! This module uses the `proxy-header` crate for parsing v1/v2 headers.

use crate::Error;
use ipnet::IpNet;
use proxy_header::{ParseConfig, ProxyHeader};
use std::net::{IpAddr, SocketAddr};
use tokio::io::AsyncBufReadExt;

/// Configuration for PROXY protocol support.
#[derive(Clone, Debug, Default)]
pub struct ProxyConfig {
    /// Trusted proxy CIDR ranges. Connections from these IPs will have PROXY
    /// headers parsed. If empty, proxy support is disabled.
    trusted_proxies: Vec<IpNet>,
}

impl ProxyConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_trusted_proxy(mut self, cidr: IpNet) -> Self {
        self.trusted_proxies.push(cidr);
        self
    }

    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        self.trusted_proxies.iter().any(|net| net.contains(&ip))
    }
}

/// Parse PROXY header from a buffered reader, returning the real client address.
/// Consumes the header bytes from the reader.
pub async fn parse<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> Result<SocketAddr, Error> {
    let buf = reader.fill_buf().await.map_err(|_| Error::ReadFailed)?;

    let (header, consumed) =
        ProxyHeader::parse(buf, ParseConfig::default()).map_err(|_| Error::ReadFailed)?;

    let addr = header
        .proxied_address()
        .map(|p| p.source)
        .ok_or(Error::ReadFailed)?;

    reader.consume(consumed);
    Ok(addr)
}

/// Parse PROXY header from raw bytes, returning the real client address and bytes consumed.
/// Used by io_uring implementation which doesn't use tokio's BufReader.
pub fn parse_from_bytes(data: &[u8]) -> Result<(SocketAddr, usize), Error> {
    let (header, consumed) =
        ProxyHeader::parse(data, ParseConfig::default()).map_err(|_| Error::ReadFailed)?;

    let addr = header
        .proxied_address()
        .map(|p| p.source)
        .ok_or(Error::ReadFailed)?;

    Ok((addr, consumed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::io::BufReader;

    fn make_reader(data: &[u8]) -> BufReader<Cursor<Vec<u8>>> {
        BufReader::new(Cursor::new(data.to_vec()))
    }

    #[tokio::test]
    async fn test_v1_tcp4() {
        let header = b"PROXY TCP4 192.168.1.100 10.0.0.1 56789 443\r\n";
        let mut reader = make_reader(header);
        let addr = parse(&mut reader).await.unwrap();
        assert_eq!(addr.ip(), "192.168.1.100".parse::<IpAddr>().unwrap());
        assert_eq!(addr.port(), 56789);
    }

    #[tokio::test]
    async fn test_v1_tcp6() {
        let header = b"PROXY TCP6 2001:db8::1 2001:db8::2 12345 80\r\n";
        let mut reader = make_reader(header);
        let addr = parse(&mut reader).await.unwrap();
        assert_eq!(addr.ip(), "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(addr.port(), 12345);
    }

    #[tokio::test]
    async fn test_v1_unknown() {
        let header = b"PROXY UNKNOWN\r\n";
        let mut reader = make_reader(header);
        assert!(parse(&mut reader).await.is_err());
    }

    #[tokio::test]
    async fn test_invalid_signature() {
        let header = b"GET / HTTP/1.1\r\n";
        let mut reader = make_reader(header);
        assert!(parse(&mut reader).await.is_err());
    }

    #[test]
    fn test_parse_from_bytes_v1() {
        let header = b"PROXY TCP4 192.168.1.100 10.0.0.1 56789 443\r\nactual data";
        let (addr, consumed) = parse_from_bytes(header).unwrap();
        assert_eq!(addr.ip(), "192.168.1.100".parse::<IpAddr>().unwrap());
        assert_eq!(addr.port(), 56789);
        assert_eq!(&header[consumed..], b"actual data");
    }

    #[test]
    fn test_parse_from_bytes_invalid() {
        let header = b"GET / HTTP/1.1\r\n";
        assert!(parse_from_bytes(header).is_err());
    }

    #[test]
    fn test_proxy_config_trusted() {
        let config = ProxyConfig::new()
            .with_trusted_proxy("10.0.0.0/8".parse().unwrap())
            .with_trusted_proxy("192.168.0.0/16".parse().unwrap());

        assert!(config.is_trusted("10.1.2.3".parse().unwrap()));
        assert!(config.is_trusted("192.168.1.1".parse().unwrap()));
        assert!(!config.is_trusted("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_proxy_config_empty() {
        let config = ProxyConfig::new();
        assert!(!config.is_trusted("10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn test_proxy_config_ipv6() {
        let config = ProxyConfig::new().with_trusted_proxy("2001:db8::/32".parse().unwrap());

        assert!(config.is_trusted("2001:db8::1".parse().unwrap()));
        assert!(!config.is_trusted("2001:db9::1".parse().unwrap()));
    }
}
