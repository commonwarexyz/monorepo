use std::net::SocketAddr;

use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, Encode as _, EncodeSize, Error, Read, ReadExt as _, Write};
use commonware_cryptography::{PublicKey, Signer};

/// A signed message from a peer attesting to its own socket address and public key at a given time.
///
/// This is used to share the peer's socket address and public key with other peers in a verified
/// manner.
#[derive(Clone, Debug)]
pub struct PeerInfo<C: PublicKey> {
    /// The socket address of the peer.
    pub socket: SocketAddr,

    /// The timestamp (epoch milliseconds) at which the socket was signed over.
    pub timestamp: u64,

    /// The public key of the peer.
    pub public_key: C,

    /// The peer's signature over the socket and timestamp.
    pub signature: C::Signature,
}

impl<C: PublicKey> PeerInfo<C> {
    /// Verify the signature of the peer info.
    // TODO danlaine: use or remove
    #[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::DecodeRangeExt as _;
    use commonware_cryptography::{secp256r1, PrivateKeyExt as _};

    fn signed_peer_info() -> PeerInfo<secp256r1::PublicKey> {
        let mut rng = rand::thread_rng();
        let c = secp256r1::PrivateKey::from_rng(&mut rng);
        PeerInfo {
            socket: SocketAddr::from(([127, 0, 0, 1], 8080)),
            timestamp: 1234567890,
            public_key: c.public_key(),
            signature: c.sign(None, &[1, 2, 3, 4, 5]),
        }
    }

    #[test]
    fn test_signed_peer_info_codec() {
        let original = vec![signed_peer_info(), signed_peer_info(), signed_peer_info()];
        let encoded = original.encode();
        let decoded = Vec::<PeerInfo<secp256r1::PublicKey>>::decode_range(encoded, 3..=3).unwrap();
        for (original, decoded) in original.iter().zip(decoded.iter()) {
            assert_eq!(original.socket, decoded.socket);
            assert_eq!(original.timestamp, decoded.timestamp);
            assert_eq!(original.public_key, decoded.public_key);
            assert_eq!(original.signature, decoded.signature);
        }

        let too_short = Vec::<PeerInfo<secp256r1::PublicKey>>::decode_range(original.encode(), ..3);
        assert!(matches!(too_short, Err(Error::InvalidLength(3))));

        let too_long = Vec::<PeerInfo<secp256r1::PublicKey>>::decode_range(original.encode(), 4..);
        assert!(matches!(too_long, Err(Error::InvalidLength(3))));
    }
}
