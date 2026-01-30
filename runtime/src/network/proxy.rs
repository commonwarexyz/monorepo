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
#[cfg_attr(feature = "iouring-network", allow(dead_code))]
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

