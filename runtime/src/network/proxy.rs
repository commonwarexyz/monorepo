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
use bytes::Buf;
/// Re-export for convenience so users don't need to add ipnet as a dependency.
pub use ipnet::IpNet;
use proxy_header::{ParseConfig, ProxyHeader};
use std::net::{IpAddr, SocketAddr};
use tokio::io::AsyncBufReadExt;

/// PROXY v2 absolute maximum header size (spec section 2.2):
/// fixed preamble (16) + payload length field (u16::MAX).
///
/// PROXY v1 is much smaller and capped at 107 bytes including CRLF
/// (spec section 2.1); `proxy-header` enforces that separately.
const MAX_PROXY_HEADER_BYTES: usize = 12 + 4 + u16::MAX as usize;

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
    let mut parser = IncrementalParser::new();
    loop {
        let (consumed, parsed) = {
            let buf = reader.fill_buf().await.map_err(|_| Error::ReadFailed)?;
            if buf.is_empty() {
                return Err(Error::ReadFailed);
            }

            let mut remaining = buf;
            let parsed = parser.push_buf(&mut remaining)?;
            let consumed = buf
                .len()
                .checked_sub(remaining.len())
                .ok_or(Error::ReadFailed)?;
            (consumed, parsed)
        };

        reader.consume(consumed);
        if let Some(addr) = parsed {
            return Ok(addr);
        }
    }
}

/// Incremental PROXY header parser shared by tokio and io_uring network paths.
pub(crate) struct IncrementalParser {
    parsed: Vec<u8>,
}

impl IncrementalParser {
    /// Create a parser with a small initial buffer for realistic header sizes.
    pub(crate) fn new() -> Self {
        Self {
            parsed: Vec::with_capacity(256),
        }
    }

    /// Push bytes from any [`Buf`] and attempt to parse a header.
    ///
    /// On success, returns the parsed address and leaves any payload bytes
    /// (after the header) in `buf` for the caller to process.
    /// If more bytes are needed, this consumes all bytes currently in `buf`
    /// into parser state and returns `Ok(None)`.
    pub(crate) fn push_buf<B: Buf>(&mut self, buf: &mut B) -> Result<Option<SocketAddr>, Error> {
        while buf.has_remaining() {
            if self.parsed.len() == MAX_PROXY_HEADER_BYTES {
                return Err(Error::ReadFailed);
            }

            let chunk_len = buf.chunk().len();
            if chunk_len == 0 {
                return Err(Error::ReadFailed);
            }
            let take = std::cmp::min(chunk_len, MAX_PROXY_HEADER_BYTES - self.parsed.len());
            let previous_len = self.parsed.len();
            self.parsed.extend_from_slice(&buf.chunk()[..take]);

            match ProxyHeader::parse(&self.parsed, ParseConfig::default()) {
                Ok((header, consumed_total)) => {
                    let addr = header
                        .proxied_address()
                        .map(|p| p.source)
                        .ok_or(Error::ReadFailed)?;
                    let consumed = consumed_total.saturating_sub(previous_len);
                    if consumed > take {
                        return Err(Error::ReadFailed);
                    }
                    buf.advance(consumed);
                    return Ok(Some(addr));
                }
                Err(proxy_header::Error::BufferTooShort) => {
                    buf.advance(take);
                    if take < chunk_len {
                        return Err(Error::ReadFailed);
                    }
                }
                Err(_) => return Err(Error::ReadFailed),
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::{IncrementalParser, MAX_PROXY_HEADER_BYTES};
    use crate::Error;

    fn build_v2_max_tcp4_header() -> Vec<u8> {
        let mut header = Vec::with_capacity(MAX_PROXY_HEADER_BYTES);
        header.extend_from_slice(b"\r\n\r\n\0\r\nQUIT\n");
        header.push(0x21); // version 2, PROXY command
        header.push(0x11); // AF_INET + STREAM
        header.extend_from_slice(&u16::MAX.to_be_bytes()); // payload length

        // IPv4 address block (12 bytes)
        header.extend_from_slice(&[192, 168, 1, 100]);
        header.extend_from_slice(&[10, 0, 0, 1]);
        header.extend_from_slice(&56789u16.to_be_bytes());
        header.extend_from_slice(&443u16.to_be_bytes());

        // Fill remaining payload as opaque TLV bytes.
        let trailing = (u16::MAX as usize) - 12;
        header.extend(std::iter::repeat_n(0u8, trailing));
        assert_eq!(header.len(), MAX_PROXY_HEADER_BYTES);
        header
    }

    #[test]
    fn test_incremental_parser_v1_length_limit_106_then_107() {
        // Keep a syntactically plausible v1 prefix but omit all delimiters after src addr.
        // At 106 bytes this remains "incomplete"; adding one byte (107) crosses v1 max line
        // length and must be rejected.
        let mut first = b"PROXY TCP4 ".to_vec();
        first.extend(std::iter::repeat_n(b'1', 95));
        assert_eq!(first.len(), 106);

        let mut parser = IncrementalParser::new();
        let mut first = first.as_slice();
        assert!(
            parser
                .push_buf(&mut first)
                .expect("106-byte malformed v1 prefix should be treated as incomplete")
                .is_none()
        );
        assert!(first.is_empty());

        let mut one_more = b"1".as_slice();
        let result = parser.push_buf(&mut one_more);
        assert!(matches!(result, Err(Error::ReadFailed)));
    }

    #[test]
    fn test_incremental_parser_v1_max_tcp6_header_preserves_payload() {
        let src = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
        let dst = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
        let header = format!("PROXY TCP6 {src} {dst} 65535 65535\r\n");
        assert_eq!(header.len(), 104);

        let mut full = header.into_bytes();
        full.extend_from_slice(b"payload");

        let mut parser = IncrementalParser::new();
        let mut buf = full.as_slice();
        let addr = parser
            .push_buf(&mut buf)
            .expect("max v1 tcp6 header should parse")
            .expect("header should be complete");
        assert_eq!(addr.ip().to_string(), src);
        assert_eq!(addr.port(), 65535);
        assert_eq!(buf, b"payload");
    }

    #[test]
    fn test_incremental_parser_split_header_preserves_payload() {
        let full = b"PROXY TCP4 192.168.1.100 10.0.0.1 56789 443\r\nhello";
        let header_len = full
            .windows(2)
            .position(|w| w == b"\r\n")
            .expect("missing header terminator")
            + 2;

        let chunk1 = &full[..10];
        let chunk2 = &full[10..30];
        let chunk3 = &full[30..];
        let expected_payload = &full[header_len..];

        let mut parser = IncrementalParser::new();
        let mut chunk1 = chunk1;
        let mut chunk2 = chunk2;
        let mut chunk3 = chunk3;

        assert!(
            parser
                .push_buf(&mut chunk1)
                .expect("chunk1 parse failed")
                .is_none(),
            "header should be incomplete"
        );
        assert!(chunk1.is_empty());

        assert!(
            parser
                .push_buf(&mut chunk2)
                .expect("chunk2 parse failed")
                .is_none(),
            "header should be incomplete"
        );
        assert!(chunk2.is_empty());

        let addr = parser
            .push_buf(&mut chunk3)
            .expect("chunk3 parse failed")
            .expect("header should be complete");
        assert_eq!(addr.ip().to_string(), "192.168.1.100");
        assert_eq!(addr.port(), 56789);
        assert_eq!(chunk3, expected_payload);
    }

    #[test]
    fn test_incremental_parser_v2_absolute_max_header_preserves_payload() {
        let header = build_v2_max_tcp4_header();
        let split = header.len() - 1;

        let mut parser = IncrementalParser::new();
        let mut first = &header[..split];
        assert!(
            parser
                .push_buf(&mut first)
                .expect("incomplete max v2 header chunk should not fail")
                .is_none()
        );
        assert!(first.is_empty());

        let mut second = Vec::from(&header[split..]);
        second.extend_from_slice(b"tail");
        let mut second = second.as_slice();
        let addr = parser
            .push_buf(&mut second)
            .expect("complete max v2 header should parse")
            .expect("header should be complete");
        assert_eq!(addr.ip().to_string(), "192.168.1.100");
        assert_eq!(addr.port(), 56789);
        assert_eq!(second, b"tail");
    }
}
