//! Size limits for the payloads DKG sends.

use commonware_codec::{EncodeSize, FixedSize, varint::MAX_U64_VARINT_SIZE};
use commonware_cryptography::{
    Signer,
    bls12381::primitives::{group::Scalar, variant::Variant},
    transcript::Summary,
};
use commonware_p2p::{Footprint, utils::mux::Prefixed};
use commonware_utils::Widen;
use std::num::NonZeroU32;

/// Largest payloads DKG sends.
///
/// The reshare [`Actor`](crate::dkg::reshare::Actor) sends each dealing and acknowledgement as a
/// [`Message`](crate::dkg::types::Message) on an epoch subchannel of its DKG channel. Dealer logs
/// and epoch artifacts travel in application blocks as a [`Payload`](crate::dkg::types::Payload),
/// so the application block bound must admit [`Limits::payload`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    dealer: usize,
    ack: usize,
    log: usize,
    info: usize,
}

impl Limits {
    /// Returns the limits for participant sets of at most `max_participants` entries, dealing
    /// under `V` and signing with `C`.
    ///
    /// # Panics
    ///
    /// Panics if a bound overflows `usize`.
    pub fn new<V: Variant, C: Signer>(max_participants: NonZeroU32) -> Self {
        // Every list holds at most `max_participants` items behind a length prefix
        let count: usize = Widen::widen(max_participants.get());
        let list = |item: usize| {
            count
                .checked_mul(item)
                .and_then(|items| items.checked_add(count.encode_size()))
                .expect("dkg size overflow")
        };
        let set = list(C::PublicKey::SIZE);
        let commitment = list(V::Public::SIZE);

        // A dealing is a tag, a commitment, and a share. An acknowledgement is a tag and a
        // signature.
        let dealer = sum(&[u8::SIZE, commitment, Scalar::SIZE]);
        let ack = sum(&[u8::SIZE, C::Signature::SIZE]);

        // A signed dealer log is a dealer, a commitment, a tagged map from each player to a
        // tagged acknowledgement or revealed share, and a signature
        let results = sum(&[
            u8::SIZE,
            set,
            list(u8::SIZE + C::Signature::SIZE.max(Scalar::SIZE)),
        ]);
        let log = sum(&[C::PublicKey::SIZE, commitment, results, C::Signature::SIZE]);

        // An epoch artifact, excluding its directory, is an outcome, an epoch, an output (a
        // summary, a sharing, and dealer, player, and revealed sets), and player and next player
        // sets. A sharing is a mode, a participant count, and a commitment.
        let sharing = sum(&[u8::SIZE, u32::SIZE, commitment]);
        let output = sum(&[Summary::SIZE, sharing, set, set, set]);
        let info = sum(&[u8::SIZE, MAX_U64_VARINT_SIZE, output, set, set]);

        Self {
            dealer,
            ack,
            log,
            info,
        }
    }

    /// Returns the largest encoded [`Payload`](crate::dkg::types::Payload) whose epoch artifact
    /// carries a [`Directory`](crate::dkg::network::Directory) of at most `directory` encoded
    /// bytes.
    ///
    /// # Panics
    ///
    /// Panics if the bound overflows `usize`.
    pub fn payload(&self, directory: usize) -> usize {
        let info = sum(&[self.info, directory]);
        sum(&[u8::SIZE, self.log.max(info)])
    }
}

impl Footprint for Limits {
    fn footprint(&self) -> usize {
        // Messages travel on an epoch subchannel
        Prefixed(self.dealer.max(self.ack)).footprint()
    }
}

/// Returns the sum of `parts`.
///
/// # Panics
///
/// Panics if the sum overflows `usize`.
fn sum(parts: &[usize]) -> usize {
    parts
        .iter()
        .try_fold(0usize, |total, &part| total.checked_add(part))
        .expect("dkg size overflow")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::{
        network::Addresses,
        types::{Message, Payload},
    };
    use bytes::{BufMut, Bytes};
    use commonware_codec::{Decode, Encode, Write};
    use commonware_consensus::types::Epoch;
    use commonware_cryptography::{
        bls12381::primitives::{
            sharing::ModeVersion,
            variant::{MinPk, MinSig},
        },
        ed25519,
        transcript::{Transcript, Version},
    };
    use commonware_math::{algebra::Random, poly::Poly};
    use commonware_p2p::Address;
    use commonware_utils::{NZU32, ordered::Set, sequence::Unit, test_rng};
    use std::net::SocketAddr;

    const NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_DKG_LIMITS";

    type PublicKey = ed25519::PublicKey;
    type Signature = ed25519::Signature;

    /// Returns `count` sorted participants.
    fn participants(count: u32) -> Set<PublicKey> {
        Set::from_iter_dedup(
            (0..u64::from(count)).map(|seed| ed25519::PrivateKey::from_seed(seed).public_key()),
        )
    }

    /// Returns an encoded commitment with `count` coefficients.
    fn commitment<V: Variant>(count: u32) -> Vec<u8> {
        let scalars = Poly::<Scalar>::new(test_rng(), count - 1);
        Poly::<V::Public>::commit(scalars).encode().to_vec()
    }

    /// Returns an encoded signature.
    fn signature() -> Vec<u8> {
        ed25519::PrivateKey::from_seed(0)
            .sign(NAMESPACE, b"message")
            .encode()
            .to_vec()
    }

    /// Returns the widest dealing for `count` participants.
    fn dealer<V: Variant>(count: u32) -> Vec<u8> {
        let mut message = vec![0u8];
        message.extend(commitment::<V>(count));
        Scalar::random(test_rng()).write(&mut message);
        message
    }

    /// Returns the widest acknowledgement.
    fn ack() -> Vec<u8> {
        let mut message = vec![1u8];
        message.extend(signature());
        message
    }

    /// Returns the widest dealer log payload for `count` participants.
    fn log<V: Variant>(count: u32) -> Vec<u8> {
        // Acknowledgements carry signatures, which are wider than revealed shares
        const { assert!(Signature::SIZE > Scalar::SIZE) };

        let mut payload = vec![0u8];
        ed25519::PrivateKey::from_seed(0)
            .public_key()
            .write(&mut payload);
        payload.extend(commitment::<V>(count));
        payload.put_u8(0);
        participants(count).write(&mut payload);
        Widen::<usize>::widen(count).write(&mut payload);
        for _ in 0..count {
            payload.put_u8(0);
            payload.extend(signature());
        }
        payload.extend(signature());
        payload
    }

    /// Returns the widest epoch artifact payload for `count` participants, ending with
    /// `directory`.
    fn info<V: Variant>(count: u32, directory: &[u8]) -> Vec<u8> {
        let set = participants(count).encode();
        let mut payload = vec![1u8, 1u8];
        Epoch::new(u64::MAX).write(&mut payload);
        Transcript::new(NAMESPACE, Version::V1)
            .summarize()
            .write(&mut payload);
        payload.put_u8(0);
        count.write(&mut payload);
        payload.extend(commitment::<V>(count));
        for _ in 0..5 {
            payload.extend_from_slice(&set);
        }
        payload.extend_from_slice(directory);
        payload
    }

    /// Asserts that the widest messages and payloads decode and encode to exactly their limits.
    fn check<V: Variant>(count: u32) {
        let max_participants = NonZeroU32::new(count).unwrap();
        let limits = Limits::new::<V, ed25519::PrivateKey>(max_participants);

        // Dealings and acknowledgements travel behind the widest subchannel prefix
        for (encoded, limit) in [(dealer::<V>(count), limits.dealer), (ack(), limits.ack)] {
            let message =
                Message::<V, PublicKey>::decode_cfg(Bytes::from(encoded), &max_participants)
                    .unwrap();
            assert_eq!(message.encode().len(), limit);
        }
        assert_eq!(
            limits.footprint(),
            limits.dealer.max(limits.ack) + MAX_U64_VARINT_SIZE
        );

        // Dealer logs and epoch artifacts with a key-only directory
        let cfg = (max_participants, ModeVersion::v0());
        let sizes = [log::<V>(count), info::<V>(count, &[])].map(|encoded| {
            Payload::<V, ed25519::PrivateKey>::decode_cfg(Bytes::from(encoded), &cfg)
                .unwrap()
                .encode()
                .len()
        });
        assert_eq!(sizes, [limits.log + u8::SIZE, limits.info + u8::SIZE]);
        assert_eq!(sizes.into_iter().max(), Some(limits.payload(0)));

        // Epoch artifacts with an address directory
        let directory = participants(count)
            .into_iter()
            .map(|participant| {
                let address = Address::Symmetric(SocketAddr::from(([127, 0, 0, 1], 3000)));
                (participant, address)
            })
            .collect::<Addresses<PublicKey>>()
            .encode();
        let encoded = info::<V>(count, &directory);
        let payload = Payload::<V, ed25519::PrivateKey, Addresses<PublicKey>>::decode_cfg(
            Bytes::from(encoded),
            &cfg,
        )
        .unwrap();
        assert_eq!(payload.encode().len(), limits.payload(directory.len()));

        // One more coefficient or participant than configured fails to decode
        let encoded = dealer::<V>(count + 1);
        assert!(
            Message::<V, PublicKey>::decode_cfg(Bytes::from(encoded), &max_participants).is_err()
        );
        for encoded in [log::<V>(count + 1), info::<V>(count + 1, &[])] {
            assert!(
                Payload::<V, ed25519::PrivateKey, Unit>::decode_cfg(Bytes::from(encoded), &cfg)
                    .is_err()
            );
        }
    }

    #[test]
    fn widest_encodings() {
        for count in [1, 4, 127, 128] {
            check::<MinPk>(count);
            check::<MinSig>(count);
        }
    }

    #[test]
    #[should_panic(expected = "dkg size overflow")]
    fn payload_overflow() {
        Limits::new::<MinSig, ed25519::PrivateKey>(NZU32!(1)).payload(usize::MAX);
    }
}
