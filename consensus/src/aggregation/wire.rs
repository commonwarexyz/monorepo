//! Types sent over the wire.

use super::types::{Ack, Index};
use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_cryptography::{bls12381::primitives::variant::Variant, Digest};
use std::hash::Hash;

/// Message exchanged between peers.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PeerAck<V: Variant, D: Digest> {
    /// The peer's acknowledgement (partial signature) for an item.
    pub ack: Ack<V, D>,

    /// The peer's local view of the tip (the lowest index that is not yet confirmed).
    pub tip: Index,
}

impl<V: Variant, D: Digest> Write for PeerAck<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.ack.write(writer);
        UInt(self.tip).write(writer);
    }
}

impl<V: Variant, D: Digest> Read for PeerAck<V, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let ack = Ack::<V, D>::read(reader)?;
        let tip = UInt::read(reader)?.into();
        Ok(Self { ack, tip })
    }
}

impl<V: Variant, D: Digest> EncodeSize for PeerAck<V, D> {
    fn encode_size(&self) -> usize {
        self.ack.encode_size() + UInt(self.tip).encode_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_cryptography::{
        bls12381::primitives::{
            group,
            poly::{self},
            variant::MinSig,
        },
        sha256,
    };

    use crate::aggregation::types::Item;

    fn generate_keys(n: u32, t: u32) -> (poly::Public<MinSig>, Vec<group::Share>) {
        let private = poly::new_from(t - 1, &mut rand::thread_rng());
        let public = poly::Public::<MinSig>::commit(private.clone());
        let shares = (0..n)
            .map(|i| {
                let eval = private.evaluate(i);
                group::Share {
                    index: eval.index,
                    private: eval.value,
                }
            })
            .collect();
        (public, shares)
    }

    #[test]
    fn test_peer_ack_codec() {
        let namespace = b"test";
        let (_, shares) = generate_keys(4, 3);
        let item = Item {
            index: 100,
            digest: sha256::hash(b"test_item"),
        };
        let ack = Ack::sign(namespace, 1, &shares[0], item.clone());
        let peer_ack = PeerAck { ack, tip: 42 };

        let restored: PeerAck<MinSig, sha256::Digest> = PeerAck::decode(peer_ack.encode()).unwrap();
        assert_eq!(peer_ack, restored);
    }
}
