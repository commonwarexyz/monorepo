//! Addresses of endpoints.

use commonware_formatting::{Hex, from_hex};
use std::{
    fmt::{self, Write as _},
    net::{IpAddr, SocketAddr},
    ops::RangeInclusive,
    str::FromStr,
};
use thiserror::Error;

/// Number of characters a username may have.
const USERNAME_SIZE: RangeInclusive<usize> = 4..=256;

/// Number of characters a password may have.
const PASSWORD_SIZE: RangeInclusive<usize> = 22..=256;

/// Most sockets an [Address] lists.
const MAX_SOCKETS: usize = 16;

/// Longest name a browser announces on the local network, without its `.local` suffix.
const MAX_NAME_SIZE: usize = 63;

/// Suffix of the names browsers announce on the local network.
const LOCAL: &str = ".local";

/// Longest socket as written: the longest name, its suffix, a colon, and a port.
const MAX_SOCKET_SIZE: usize = MAX_NAME_SIZE + LOCAL.len() + 1 + 5;

/// Priority a browser gives the first socket of an address it dials. Each later socket ranks
/// one below the socket before it.
const PRIORITY: u32 = 2_130_706_431;

/// A string that is not an [Address].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("invalid address")]
pub struct InvalidAddress;

/// Somewhere an endpoint can be reached.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Socket {
    /// A port at an address of the device or of the NAT in front of it.
    Ip(SocketAddr),
    /// A port at a name the browser announces on the local network in place of the device's
    /// address.
    Name(String, u16),
}

impl Socket {
    /// Returns the socket at `port` of `host`, which is an IP address or a name announced on the
    /// local network.
    fn new(host: &str, port: u16) -> Option<Self> {
        if port == 0 {
            return None;
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Some(Self::Ip(SocketAddr::new(ip, port)));
        }
        let name = host.strip_suffix(LOCAL)?;
        let named = (1..=MAX_NAME_SIZE).contains(&name.len())
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
        named.then(|| Self::Name(host.to_string(), port))
    }
}

impl fmt::Display for Socket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(socket) => socket.fmt(f),
            Self::Name(name, port) => write!(f, "{name}:{port}"),
        }
    }
}

impl FromStr for Socket {
    type Err = InvalidAddress;

    fn from_str(socket: &str) -> Result<Self, Self::Err> {
        // Brackets set an IPv6 address apart from the port that follows it.
        let (host, port) = socket.rsplit_once(':').ok_or(InvalidAddress)?;
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        let port = port.parse().map_err(|_| InvalidAddress)?;
        Self::new(host, port).ok_or(InvalidAddress)
    }
}

/// Where an [Endpoint](super::Endpoint) can be reached and what a page needs to connect to it.
///
/// An address holds the fingerprint of the certificate its endpoint proves, the username and
/// password that authenticate checks sent to the endpoint, and up to sixteen sockets the
/// endpoint can be reached at. It is written as
///
/// ```text
/// <fingerprint>:<username>:<password>,<socket>,<socket>,...
/// ```
///
/// The fingerprint is 64 lowercase hexadecimal characters. A socket is a port at an IP address
/// or at a name the browser announces on the local network, such as `203.0.113.7:51413`,
/// `[2001:db8::7]:51413`, or `4f1c0a8e-6a52-4b1e-9d0c-3c5a1b2e7f90.local:51413`. An address
/// has one spelling, and only that spelling parses.
///
/// An address reveals the sockets it lists. Holding one does not let a page connect to its
/// endpoint, which connects only to the address it dials.
///
/// Addresses are ordered, and the two ends of a connection order their addresses the same way.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address {
    fingerprint: [u8; 32],
    username: String,
    password: String,
    sockets: Vec<Socket>,
}

impl Address {
    /// Length of the longest address as written, in bytes. It holds a fingerprint, the longest
    /// username and password, and the most sockets an address lists, each of the greatest
    /// length, with the character that separates each part from the one before it.
    pub const MAX_SIZE: usize = 64
        + 1
        + *USERNAME_SIZE.end()
        + 1
        + *PASSWORD_SIZE.end()
        + MAX_SOCKETS * (1 + MAX_SOCKET_SIZE);

    /// Returns the address with these parts. Returns `None` if the username or the password
    /// is not one a browser uses, or if an address cannot list this number of sockets.
    fn new(
        fingerprint: [u8; 32],
        username: &str,
        password: &str,
        sockets: Vec<Socket>,
    ) -> Option<Self> {
        // A username or password holds only letters, digits, plus signs, and slashes.
        let credential = |value: &str, size: RangeInclusive<usize>| {
            size.contains(&value.len())
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
        };
        let valid = credential(username, USERNAME_SIZE)
            && credential(password, PASSWORD_SIZE)
            && (1..=MAX_SOCKETS).contains(&sockets.len());
        valid.then(|| Self {
            fingerprint,
            username: username.to_string(),
            password: password.to_string(),
            sockets,
        })
    }

    /// Reads the address of the endpoint a browser described, along with the name the
    /// description gives its only section. Returns `None` unless the description holds every
    /// part of an address.
    pub(super) fn read(description: &str) -> Option<(Self, String)> {
        let attribute = |name: &str| description.lines().find_map(|line| line.strip_prefix(name));
        let section = attribute("a=mid:")?;
        let username = attribute("a=ice-ufrag:")?;
        let password = attribute("a=ice-pwd:")?;
        let (algorithm, digest) = attribute("a=fingerprint:")?.split_once(' ')?;
        if !algorithm.eq_ignore_ascii_case("sha-256") {
            return None;
        }
        let fingerprint = from_hex(&digest.replace(':', ""))?.try_into().ok()?;

        // A candidate lists its foundation, component, transport, priority, host, and port. A
        // data channel has only the first component, and a browser listens only on UDP.
        let sockets = description
            .lines()
            .filter_map(|line| line.strip_prefix("a=candidate:"))
            .filter_map(|candidate| {
                let mut fields = candidate.split(' ');
                let (component, transport) = (fields.nth(1)?, fields.next()?);
                let (host, port) = (fields.nth(1)?, fields.next()?);
                if component != "1" || !transport.eq_ignore_ascii_case("udp") {
                    return None;
                }
                Socket::new(host, port.parse().ok()?)
            })
            .take(MAX_SOCKETS)
            .collect();
        let address = Self::new(fingerprint, username, password, sockets)?;
        Some((address, section.to_string()))
    }

    /// Describes the endpoint at this address as its browser would in answer to an offer whose
    /// only section is named `section`. An `active` endpoint begins the handshake that secures
    /// the connection.
    pub(super) fn answer(&self, section: &str, active: bool) -> String {
        let fingerprint = self
            .fingerprint
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":");
        let setup = if active { "active" } else { "passive" };
        let mut description = format!(
            "v=0\r\n\
             o=- 0 0 IN IP4 0.0.0.0\r\n\
             s=-\r\n\
             t=0 0\r\n\
             a=group:BUNDLE {section}\r\n\
             m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
             c=IN IP4 0.0.0.0\r\n\
             a=mid:{section}\r\n\
             a=ice-ufrag:{}\r\n\
             a=ice-pwd:{}\r\n\
             a=ice-options:trickle\r\n\
             a=fingerprint:sha-256 {fingerprint}\r\n\
             a=setup:{setup}\r\n\
             a=sctp-port:5000\r\n",
            self.username, self.password,
        );
        for (socket, priority) in self.sockets.iter().zip((0..=PRIORITY).rev()) {
            let (host, port) = match socket {
                Socket::Ip(socket) => (socket.ip().to_string(), socket.port()),
                Socket::Name(name, port) => (name.clone(), *port),
            };
            let _ = write!(
                description,
                "a=candidate:{priority} 1 udp {priority} {host} {port} typ host\r\n"
            );
        }
        description
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            Hex(&self.fingerprint),
            self.username,
            self.password
        )?;
        for socket in &self.sockets {
            write!(f, ",{socket}")?;
        }
        Ok(())
    }
}

impl FromStr for Address {
    type Err = InvalidAddress;

    fn from_str(address: &str) -> Result<Self, Self::Err> {
        // Refuse text longer than any address before reading it.
        if address.len() > Self::MAX_SIZE {
            return Err(InvalidAddress);
        }
        let (endpoint, sockets) = address.split_once(',').ok_or(InvalidAddress)?;
        let mut parts = endpoint.split(':');
        let (Some(fingerprint), Some(username), Some(password), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(InvalidAddress);
        };
        let fingerprint = from_hex(fingerprint)
            .and_then(|fingerprint| fingerprint.try_into().ok())
            .ok_or(InvalidAddress)?;
        let sockets = sockets
            .split(',')
            .map(str::parse)
            .collect::<Result<_, _>>()?;
        let parsed = Self::new(fingerprint, username, password, sockets).ok_or(InvalidAddress)?;

        // The parts above accept other spellings of a value, such as a port with leading zeros.
        (parsed.to_string() == address)
            .then_some(parsed)
            .ok_or(InvalidAddress)
    }
}
