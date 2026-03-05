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
/// Re-export for convenience so users don't need to add ipnet as a dependency.
pub use ipnet::IpNet;
use proxy_header::{ParseConfig, ProxyHeader};
use std::net::{IpAddr, SocketAddr};
use tokio::io::AsyncBufReadExt;

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
#[cfg_attr(feature = "iouring-network", allow(dead_code))]
pub async fn parse<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> Result<SocketAddr, Error> {
    let mut parser = IncrementalParser::new();
    loop {
        let buf = reader.fill_buf().await.map_err(|_| Error::ReadFailed)?;
        if buf.is_empty() {
            return Err(Error::ReadFailed);
        }

        match parser.push(buf)? {
            ParseChunkResult::Complete { addr, consume, .. } => {
                reader.consume(consume);
                return Ok(addr);
            }
            ParseChunkResult::Incomplete { consume } => {
                reader.consume(consume);
            }
        }
    }
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

/// Result of parsing an incremental input chunk.
#[cfg_attr(not(feature = "iouring-network"), allow(dead_code))]
pub enum ParseChunkResult<'a> {
    /// Header complete. `consume` bytes from the current chunk were part of
    /// the header, and `remaining` are payload bytes after the header.
    Complete {
        addr: SocketAddr,
        consume: usize,
        remaining: &'a [u8],
    },
    /// Need more bytes. `consume` bytes from the current chunk are now part of
    /// parser state.
    Incomplete { consume: usize },
}

/// Incremental PROXY header parser shared by tokio and io_uring network paths.
#[cfg_attr(not(feature = "iouring-network"), allow(dead_code))]
pub struct IncrementalParser {
    parsed: Vec<u8>,
}

#[cfg_attr(not(feature = "iouring-network"), allow(dead_code))]
impl IncrementalParser {
    /// Create a parser with a small initial buffer for realistic header sizes.
    pub fn new() -> Self {
        Self {
            parsed: Vec::with_capacity(256),
        }
    }

    /// Push one input chunk and attempt to parse a header.
    pub fn push<'a>(&mut self, chunk: &'a [u8]) -> Result<ParseChunkResult<'a>, Error> {
        let previous_len = self.parsed.len();
        self.parsed.extend_from_slice(chunk);

        match parse_from_bytes(&self.parsed)? {
            ParseResult::Complete(addr, consumed_total) => {
                if consumed_total < previous_len {
                    return Ok(ParseChunkResult::Complete {
                        addr,
                        consume: 0,
                        remaining: chunk,
                    });
                }

                let consume = consumed_total
                    .checked_sub(previous_len)
                    .ok_or(Error::ReadFailed)?;
                let remaining = chunk.get(consume..).ok_or(Error::ReadFailed)?;
                Ok(ParseChunkResult::Complete {
                    addr,
                    consume,
                    remaining,
                })
            }
            ParseResult::Incomplete => Ok(ParseChunkResult::Incomplete {
                consume: chunk.len(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{IncrementalParser, ParseChunkResult};

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

        let mut parser = IncrementalParser::new();

        match parser.push(chunk1).expect("chunk1 parse failed") {
            ParseChunkResult::Incomplete { consume } => assert_eq!(consume, chunk1.len()),
            ParseChunkResult::Complete { .. } => panic!("header should be incomplete"),
        }

        match parser.push(chunk2).expect("chunk2 parse failed") {
            ParseChunkResult::Incomplete { consume } => assert_eq!(consume, chunk2.len()),
            ParseChunkResult::Complete { .. } => panic!("header should be incomplete"),
        }

        match parser.push(chunk3).expect("chunk3 parse failed") {
            ParseChunkResult::Complete {
                addr,
                consume,
                remaining,
            } => {
                assert_eq!(addr.ip().to_string(), "192.168.1.100");
                assert_eq!(addr.port(), 56789);
                assert_eq!(consume, header_len - (chunk1.len() + chunk2.len()));
                assert_eq!(remaining, b"hello");
            }
            ParseChunkResult::Incomplete { .. } => panic!("header should be complete"),
        }
    }
}
