use std::{collections::BTreeMap, net::SocketAddr};

use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, Encode as _, EncodeSize, Error, Read, ReadExt as _, Write};
use commonware_cryptography::{PublicKey, Signer};

struct Tracker<P: PublicKey> {
    /// The current known information about each peer.
    peers: BTreeMap<P, PeerInfo<P>>,
}

impl<P: PublicKey> Tracker<P> {
    /// Create a new tracker.
    pub fn new() -> Self {
        Self {
            peers: BTreeMap::new(),
        }
    }
}

/// A signed message from a peer attesting to its own socket address and public key at a given time.
///
/// This is used to share the peer's socket address and public key with other peers in a verified
/// manner.
#[derive(Clone, Debug)]
pub struct PeerInfo<P: PublicKey> {
    /// The socket address of the peer.
    pub socket: SocketAddr,

    /// The timestamp (epoch milliseconds) at which the socket was signed over.
    pub timestamp: u64,

    /// The public key of the peer.
    pub public_key: P,

    /// The peer's signature over the socket and timestamp.
    pub signature: P::Signature,
}

impl<C: PublicKey> PeerInfo<C> {
    /// Verify the signature of the peer info.
    pub fn verify(&self, namespace: &[u8]) -> bool {
        self.public_key.verify(
            Some(namespace),
            &(self.socket, self.timestamp).encode(),
            &self.signature,
        )
    }

    pub fn sign<Sk: Signer<PublicKey = C, Signature = C::Signature>>(
        signer: &Sk,
        namespace: &[u8],
        socket: SocketAddr,
        timestamp: u64,
    ) -> Self {
        let signature = signer.sign(Some(namespace), &(socket, timestamp).encode());
        PeerInfo {
            socket,
            timestamp,
            public_key: signer.public_key(),
            signature,
        }
    }
}

impl<C: PublicKey> EncodeSize for PeerInfo<C> {
    fn encode_size(&self) -> usize {
        self.socket.encode_size()
            + UInt(self.timestamp).encode_size()
            + self.public_key.encode_size()
            + self.signature.encode_size()
    }
}

impl<C: PublicKey> Write for PeerInfo<C> {
    fn write(&self, buf: &mut impl BufMut) {
        self.socket.write(buf);
        UInt(self.timestamp).write(buf);
        self.public_key.write(buf);
        self.signature.write(buf);
    }
}

impl<C: PublicKey> Read for PeerInfo<C> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let socket = SocketAddr::read(buf)?;
        let timestamp = UInt::read(buf)?.into();
        let public_key = C::read(buf)?;
        let signature = C::Signature::read(buf)?;
        Ok(PeerInfo {
            socket,
            timestamp,
            public_key,
            signature,
        })
    }
}
