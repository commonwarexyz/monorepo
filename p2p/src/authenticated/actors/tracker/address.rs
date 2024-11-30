use super::Error;
use crate::authenticated::wire::Peer;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Clone)]
pub enum Address {
    Config(SocketAddr), // Provided during initialization
    Network(Signature), // Learned from other peers
}

const IPV4_LEN: usize = 6;
const IPV6_LEN: usize = 18;

#[derive(Clone)]
pub struct Signature {
    pub addr: SocketAddr,
    pub peer: Peer,
}

pub fn wire_peer_payload(peer: &Peer) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&peer.socket);
    payload.extend_from_slice(&peer.timestamp_ms.to_be_bytes());
    payload
}

pub fn socket_peer_payload(socket: &SocketAddr, timestamp: u64) -> (Vec<u8>, Vec<u8>) {
    let socket = bytes(socket);
    let mut payload = Vec::new();
    payload.extend_from_slice(&socket);
    payload.extend_from_slice(&timestamp.to_be_bytes());
    (socket, payload)
}

pub fn socket_from_payload(peer: &Peer) -> Result<SocketAddr, Error> {
    let bytes = &peer.socket;
    if bytes.len() == IPV4_LEN {
        // IPv4: 4 bytes for IP + 2 bytes for port
        let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
        let port = u16::from_be_bytes([bytes[4], bytes[5]]);
        Ok(SocketAddr::new(ip.into(), port))
    } else if bytes.len() == IPV6_LEN {
        // IPv6: 16 bytes for IP + 2 bytes for port
        let ip = Ipv6Addr::new(
            u16::from_be_bytes([bytes[0], bytes[1]]),
            u16::from_be_bytes([bytes[2], bytes[3]]),
            u16::from_be_bytes([bytes[4], bytes[5]]),
            u16::from_be_bytes([bytes[6], bytes[7]]),
            u16::from_be_bytes([bytes[8], bytes[9]]),
            u16::from_be_bytes([bytes[10], bytes[11]]),
            u16::from_be_bytes([bytes[12], bytes[13]]),
            u16::from_be_bytes([bytes[14], bytes[15]]),
        );
        let port = u16::from_be_bytes([bytes[16], bytes[17]]);
        Ok(SocketAddr::new(ip.into(), port))
    } else {
        Err(Error::InvalidIPLength(bytes.len()))
    }
}

pub fn bytes(socket: &SocketAddr) -> Vec<u8> {
    match socket {
        SocketAddr::V4(v4) => {
            let mut bytes = Vec::with_capacity(IPV4_LEN);
            bytes.extend_from_slice(&v4.ip().octets());
            bytes.extend_from_slice(&v4.port().to_be_bytes());
            bytes
        }
        SocketAddr::V6(v6) => {
            let mut bytes = Vec::with_capacity(IPV6_LEN);
            bytes.extend_from_slice(&v6.ip().octets());
            bytes.extend_from_slice(&v6.port().to_be_bytes());
            bytes
        }
    }
}
