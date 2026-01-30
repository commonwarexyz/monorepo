//! PROXY protocol support.
//!
//! The [PROXY protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt)
//! allows TCP proxies (HAProxy, nginx, AWS NLB) to transmit the original client
//! connection information to backend servers. This module provides configuration
//! and parsing for both v1 (text) and v2 (binary) formats.
//!
//! # Example
//!
//! ```ignore
//! use commonware_runtime::{tokio, ProxyConfig};
//!
//! // Trust connections from 10.0.0.0/8 (private network where proxy runs)
//! let proxy_config = ProxyConfig::new()
//!     .with_trusted_proxy_cidr("10.0.0.0/8")
//!     .unwrap();
//!
//! let network_config = tokio::Config::default()
//!     .with_proxy(proxy_config);
//!
//! // Now accept() returns the real client IP for proxied connections
//! ```
//!
//! # Security
//!
//! Only parse PROXY headers from explicitly trusted proxy IPs. Connections from
//! untrusted sources return the TCP-level address unchanged. Invalid PROXY headers
//! from trusted proxies cause the connection to be rejected.

use crate::Error;
use proxy_header::{ParseConfig, ProxyHeader};
use std::net::{IpAddr, SocketAddr};
use tokio::io::AsyncBufReadExt;

/// Re-export for convenience so users don't need to add ipnet as a dependency.
pub use ipnet::IpNet;

/// Configuration for PROXY protocol support.
///
/// When attached to a network configuration, connections from trusted proxy IPs
/// will have their PROXY headers parsed to extract the real client address.
/// Connections from untrusted IPs are passed through unchanged.
#[derive(Clone, Debug, Default)]
pub struct ProxyConfig {
    trusted_proxies: Vec<IpNet>,
}

impl ProxyConfig {
    /// Create a new empty configuration. No proxies are trusted by default.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a trusted proxy by CIDR notation string (e.g., "10.0.0.0/8").
    ///
    /// Returns an error if the CIDR string is invalid.
    pub fn with_trusted_proxy_cidr(mut self, cidr: &str) -> Result<Self, Error> {
        let net: IpNet = cidr.parse().map_err(|_| Error::ReadFailed)?;
        self.trusted_proxies.push(net);
        Ok(self)
    }

    /// Add a trusted proxy by [`IpNet`].
    pub fn with_trusted_proxy(mut self, net: IpNet) -> Self {
        self.trusted_proxies.push(net);
        self
    }

    /// Check if an IP address belongs to a trusted proxy.
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

/// Result of attempting to parse a PROXY header from bytes.
#[cfg_attr(not(feature = "iouring-network"), allow(dead_code))]
pub enum ParseResult {
    /// Successfully parsed. Contains client address and bytes consumed.
    Complete(SocketAddr, usize),
    /// Need more data to complete parsing.
    Incomplete,
}

/// Parse PROXY header from raw bytes.
///
/// Returns `ParseResult::Incomplete` if more data is needed, or
/// `ParseResult::Complete` with the client address and bytes consumed.
/// Returns an error if the data is definitively invalid.
#[cfg_attr(not(feature = "iouring-network"), allow(dead_code))]
pub fn parse_from_bytes(data: &[u8]) -> Result<ParseResult, Error> {
    match ProxyHeader::parse(data, ParseConfig::default()) {
        Ok((header, consumed)) => {
            let addr = header
                .proxied_address()
                .map(|p| p.source)
                .ok_or(Error::ReadFailed)?;
            Ok(ParseResult::Complete(addr, consumed))
        }
        Err(proxy_header::Error::BufferTooShort) => Ok(ParseResult::Incomplete),
        Err(_) => Err(Error::ReadFailed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::Ipv6Addr;
    use tokio::io::BufReader;

    fn make_reader(data: &[u8]) -> BufReader<Cursor<Vec<u8>>> {
        BufReader::new(Cursor::new(data.to_vec()))
    }

    // V1 (text) tests

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
    async fn test_v1_unknown_rejected() {
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

    // V2 (binary) tests

    const V2_SIG: [u8; 12] = [
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ];

    fn make_v2_header(command: u8, family: u8, addr_data: &[u8]) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&V2_SIG);
        header.push(0x20 | command); // version 2
        header.push((family << 4) | 1); // TCP
        header.extend_from_slice(&(addr_data.len() as u16).to_be_bytes());
        header.extend_from_slice(addr_data);
        header
    }

    #[tokio::test]
    async fn test_v2_ipv4() {
        let mut addr_data = Vec::new();
        addr_data.extend_from_slice(&[192, 168, 1, 100]); // src ip
        addr_data.extend_from_slice(&[10, 0, 0, 1]); // dst ip
        addr_data.extend_from_slice(&56789u16.to_be_bytes()); // src port
        addr_data.extend_from_slice(&443u16.to_be_bytes()); // dst port

        let header = make_v2_header(1, 1, &addr_data);
        let mut reader = make_reader(&header);
        let addr = parse(&mut reader).await.unwrap();
        assert_eq!(addr.ip(), "192.168.1.100".parse::<IpAddr>().unwrap());
        assert_eq!(addr.port(), 56789);
    }

    #[tokio::test]
    async fn test_v2_ipv6() {
        let mut addr_data = Vec::new();
        let src_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst_ip: Ipv6Addr = "2001:db8::2".parse().unwrap();
        addr_data.extend_from_slice(&src_ip.octets());
        addr_data.extend_from_slice(&dst_ip.octets());
        addr_data.extend_from_slice(&12345u16.to_be_bytes());
        addr_data.extend_from_slice(&80u16.to_be_bytes());

        let header = make_v2_header(1, 2, &addr_data);
        let mut reader = make_reader(&header);
        let addr = parse(&mut reader).await.unwrap();
        assert_eq!(addr.ip(), src_ip);
        assert_eq!(addr.port(), 12345);
    }

    #[tokio::test]
    async fn test_v2_local_command_rejected() {
        // LOCAL command (health check) has no client address
        let addr_data = [0u8; 12];
        let header = make_v2_header(0, 1, &addr_data);
        let mut reader = make_reader(&header);
        assert!(parse(&mut reader).await.is_err());
    }

    // parse_from_bytes tests

    #[test]
    fn test_parse_from_bytes_v1() {
        let header = b"PROXY TCP4 192.168.1.100 10.0.0.1 56789 443\r\nactual data";
        let ParseResult::Complete(addr, consumed) = parse_from_bytes(header).unwrap() else {
            panic!("expected Complete");
        };
        assert_eq!(addr.ip(), "192.168.1.100".parse::<IpAddr>().unwrap());
        assert_eq!(addr.port(), 56789);
        assert_eq!(&header[consumed..], b"actual data");
    }

    #[test]
    fn test_parse_from_bytes_v2() {
        let mut addr_data = Vec::new();
        addr_data.extend_from_slice(&[192, 168, 1, 100]);
        addr_data.extend_from_slice(&[10, 0, 0, 1]);
        addr_data.extend_from_slice(&56789u16.to_be_bytes());
        addr_data.extend_from_slice(&443u16.to_be_bytes());

        let mut header = make_v2_header(1, 1, &addr_data);
        header.extend_from_slice(b"actual data");

        let ParseResult::Complete(addr, consumed) = parse_from_bytes(&header).unwrap() else {
            panic!("expected Complete");
        };
        assert_eq!(addr.ip(), "192.168.1.100".parse::<IpAddr>().unwrap());
        assert_eq!(addr.port(), 56789);
        assert_eq!(&header[consumed..], b"actual data");
    }

    #[test]
    fn test_parse_from_bytes_incomplete() {
        // Just the v2 signature, not enough for full header
        let header = &V2_SIG[..];
        let result = parse_from_bytes(header).unwrap();
        assert!(matches!(result, ParseResult::Incomplete));
    }

    #[test]
    fn test_parse_from_bytes_invalid() {
        let header = b"GET / HTTP/1.1\r\n";
        assert!(parse_from_bytes(header).is_err());
    }

    // ProxyConfig tests

    #[test]
    fn test_proxy_config_cidr_string() {
        let config = ProxyConfig::new()
            .with_trusted_proxy_cidr("10.0.0.0/8")
            .unwrap()
            .with_trusted_proxy_cidr("192.168.0.0/16")
            .unwrap();

        assert!(config.is_trusted("10.1.2.3".parse().unwrap()));
        assert!(config.is_trusted("192.168.1.1".parse().unwrap()));
        assert!(!config.is_trusted("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_proxy_config_invalid_cidr() {
        let result = ProxyConfig::new().with_trusted_proxy_cidr("not-a-cidr");
        assert!(result.is_err());
    }

    #[test]
    fn test_proxy_config_empty() {
        let config = ProxyConfig::new();
        assert!(!config.is_trusted("10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn test_proxy_config_ipv6() {
        let config = ProxyConfig::new()
            .with_trusted_proxy_cidr("2001:db8::/32")
            .unwrap();

        assert!(config.is_trusted("2001:db8::1".parse().unwrap()));
        assert!(!config.is_trusted("2001:db9::1".parse().unwrap()));
    }
}
