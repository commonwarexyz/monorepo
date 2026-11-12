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

/// Length of the longest socket as written, which is the longest name, its suffix, a colon,
/// and a port.
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
/// An address holds up to sixteen sockets its endpoint can be reached at. An endpoint with
/// more leaves out sockets of the device's own before any that a STUN server reported.
///
/// ```text
///  as the browser lists them   o o o o o o o o o o o o o o o o o o o o r r
///  as the address lists them   o o o o o o o o o o o o o o . . . . . . r r
///
///  o  the device's own     r  reported by a STUN server     .  left out
/// ```
///
/// An address also holds the fingerprint of a certificate, a username, and a password. The
/// endpoint's browser makes those three for this one connection, and a browser connects only
/// to an endpoint whose three it was given. They say nothing about who runs the page. A page
/// that must know who it reached authenticates it over the connection.
///
/// An address is written as its parts in order, joined by the characters shown under them.
///
/// ```text
///  made by its browser for this one connection
///                   |                                  where it can be reached
///                   |                                             |
///   .---------------^---------------. .---------------------------^----------------------------.
///  +-------------+------+------------+------------------+--------------------+------------------+
///  | fingerprint | user |  password  |      socket      |       socket       |      socket      |
///  +-------------+------+------------+------------------+--------------------+------------------+
///    a346..9e41  : 1qYx : kV9h..t8Zs , 203.0.113.7:5001 , [2001:db8::7]:5002 , d77f..local:5001
/// ```
///
/// The fingerprint is 64 lowercase hexadecimal characters. A socket is a port at an IP address
/// or at a name the browser announces on the local network. The figure shortens the
/// fingerprint, the password, and the name. An address has one spelling, and only that
/// spelling parses.
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

        // A candidate lists its foundation, component, transport, priority, host, port, and
        // type. A data channel has only the first component, and a browser listens only on UDP.
        let candidates = description
            .lines()
            .filter_map(|line| line.strip_prefix("a=candidate:"))
            .filter_map(|candidate| {
                let mut fields = candidate.split(' ');
                let (component, transport) = (fields.nth(1)?, fields.next()?);
                let (host, port) = (fields.nth(1)?, fields.next()?);
                let own = fields.nth(1).is_none_or(|kind| kind == "host");
                if component != "1" || !transport.eq_ignore_ascii_case("udp") {
                    return None;
                }
                Some((own, Socket::new(host, port.parse().ok()?)?))
            })
            .collect::<Vec<_>>();

        // A browser lists the sockets of the device's own interfaces before the ones a server
        // reported, and the reported ones are the only sockets that reach a device behind a
        // NAT. A device with many interfaces has more sockets than an address lists, so its
        // own are the ones left out.
        let reported = candidates.iter().filter(|(own, _)| !own).count();
        let mut spare = MAX_SOCKETS.saturating_sub(reported);
        let sockets = candidates
            .into_iter()
            .filter_map(|(own, socket)| {
                if own {
                    spare = spare.checked_sub(1)?;
                }
                Some(socket)
            })
            .take(MAX_SOCKETS)
            .collect();
        let address = Self::new(fingerprint, username, password, sockets)?;
        Some((address, section.to_string()))
    }

    /// Describes the endpoint at this address to a browser whose own end has one section,
    /// named `section`. The description has the form of an answer, the only form in which a
    /// browser accepts the other end. An `active` endpoint begins the handshake that secures
    /// the connection.
    pub(super) fn describe(&self, section: &str, active: bool) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    const FINGERPRINT: &str = "a346bc7d1f08e25c9b4d6a7e3f1c0d2b5a8e9f7061c2d3e4f5a6b7c8d9e09e41";
    const USERNAME: &str = "1qYx";
    const PASSWORD: &str = "kV9hQ2mX7pL4sT8wB3nZ6cRf";

    /// Returns the description a browser gives of an endpoint with these candidates.
    fn description(candidates: &[String]) -> String {
        let digest = FINGERPRINT
            .as_bytes()
            .chunks(2)
            .map(|pair| String::from_utf8_lossy(pair).to_uppercase())
            .collect::<Vec<_>>()
            .join(":");
        let mut description = String::from(
            "v=0\r\n\
             o=- 4611731400430051336 2 IN IP4 127.0.0.1\r\n\
             s=-\r\n\
             t=0 0\r\n\
             a=group:BUNDLE 0\r\n\
             m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
             c=IN IP4 0.0.0.0\r\n",
        );
        for candidate in candidates {
            let _ = write!(description, "a=candidate:{candidate}\r\n");
        }
        let _ = write!(
            description,
            "a=ice-ufrag:{USERNAME}\r\n\
             a=ice-pwd:{PASSWORD}\r\n\
             a=ice-options:trickle\r\n\
             a=fingerprint:sha-256 {digest}\r\n\
             a=setup:actpass\r\n\
             a=mid:0\r\n\
             a=sctp-port:5000\r\n"
        );
        description
    }

    #[test]
    fn test_read_lists_udp_sockets_of_first_component() {
        let candidates = [
            "1 1 udp 2113937151 192.0.2.4 50000 typ host generation 0".to_string(),
            "2 1 tcp 1518280447 192.0.2.4 9 typ host tcptype active generation 0".to_string(),
            "3 2 udp 2113937150 192.0.2.4 50001 typ host generation 0".to_string(),
            "4 1 UDP 1677729535 203.0.113.7 51413 typ srflx raddr 192.0.2.4 rport 50000"
                .to_string(),
        ];
        let (address, section) = Address::read(&description(&candidates)).unwrap();
        assert_eq!(section, "0");
        assert_eq!(
            address.to_string(),
            format!("{FINGERPRINT}:{USERNAME}:{PASSWORD},192.0.2.4:50000,203.0.113.7:51413")
        );
    }

    #[test]
    fn test_read_keeps_sockets_a_server_reported() {
        // A device with twenty network interfaces lists their sockets before the two a STUN
        // server reported.
        let mut candidates = (0..20)
            .map(|i| {
                format!(
                    "{i} 1 udp 2113937151 10.0.0.{} {} typ host",
                    i + 1,
                    50_000 + i
                )
            })
            .collect::<Vec<_>>();
        candidates
            .push("20 1 udp 1677729535 203.0.113.7 51413 typ srflx raddr 0.0.0.0 rport 0".into());
        candidates.push("21 1 udp 1677729535 2001:db8::7 51414 typ srflx raddr :: rport 0".into());
        let (address, _) = Address::read(&description(&candidates)).unwrap();

        // The address lists both of those and as many of the device's own as still fit, in the
        // order the browser gave them.
        let mut expected = (0..14)
            .map(|i| format!("10.0.0.{}:{}", i + 1, 50_000 + i))
            .collect::<Vec<_>>();
        expected.push("203.0.113.7:51413".into());
        expected.push("[2001:db8::7]:51414".into());
        assert_eq!(
            address.to_string(),
            format!("{FINGERPRINT}:{USERNAME}:{PASSWORD},{}", expected.join(","))
        );
    }

    #[test]
    fn test_read_recovers_described_address() {
        let address = format!(
            "{FINGERPRINT}:{USERNAME}:{PASSWORD},203.0.113.7:51413,[2001:db8::7]:51414,a.local:9"
        )
        .parse::<Address>()
        .unwrap();
        for (active, setup) in [(true, "a=setup:active\r\n"), (false, "a=setup:passive\r\n")] {
            let description = address.describe("data", active);
            assert!(description.contains(setup));
            assert_eq!(
                Address::read(&description),
                Some((address.clone(), "data".to_string()))
            );
        }
    }
}
