//! Size limits for the payloads DKG sends.

use crate::dkg::types::{Message, max_participants};
use commonware_codec::Footprint;
use commonware_cryptography::{PublicKey, bls12381::primitives::variant::Variant};
use commonware_p2p::utils::mux::Prefixed;

/// Largest payloads DKG sends, as [message sizes](crate::dkg#message-sizes) draws them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Largest dealing or acknowledgement, with room for its epoch subchannel prefix.
    message: usize,
}

impl Limits {
    /// Returns the limits for committees of at most `participants` members, dealing under `V`
    /// among participants identified by `P`.
    ///
    /// A dealing's commitment holds at most one coefficient per member of an
    /// [`N3f1`](commonware_utils::N3f1) quorum of `participants`, the most the [`Message`]
    /// codec decodes.
    ///
    /// # Panics
    ///
    /// Panics if `participants` is zero or exceeds `u32::MAX`, or if a bound overflows `usize`.
    pub fn new<V: Variant, P: PublicKey>(participants: usize) -> Self {
        // Dealings and acknowledgements travel on an epoch subchannel.
        let message = Message::<V, P>::max_encode_size(max_participants(participants))
            .expect("dkg size must fit in usize");
        Self {
            message: Prefixed(message).footprint(),
        }
    }
}

impl Footprint for Limits {
    fn footprint(&self) -> usize {
        self.message
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::{
        network::Addresses,
        types::{EpochInfo, Message, Payload},
    };
    use bytes::{BufMut, Bytes};
    use commonware_codec::{Decode, Encode, Error as CodecError, FixedSize, Write};
    use commonware_consensus::types::Epoch;
    use commonware_cryptography::{
        Signer,
        bls12381::{
            dkg::feldman_desmedt::SignedDealerLog,
            primitives::{
                group::Scalar,
                sharing::ModeVersion,
                variant::{MinPk, MinSig},
            },
        },
        ed25519,
        transcript::{Transcript, Version},
    };
    use commonware_math::{algebra::Random, poly::Poly};
    use commonware_p2p::Address;
    use commonware_utils::{Faults, N3f1, NZU32, Widen, ordered::Set, sequence::Unit, test_rng};
    use std::{net::SocketAddr, num::NonZeroU32};

    /// Namespace for the signatures and transcripts these tests build.
    const NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_DKG_LIMITS";

    type PublicKey = ed25519::PublicKey;
    type Signature = ed25519::Signature;

    /// Returns `count` sorted participants.
    fn participants(count: u32) -> Set<PublicKey> {
        Set::from_iter_dedup(
            (0..u64::from(count)).map(|seed| ed25519::PrivateKey::from_seed(seed).public_key()),
        )
    }

    /// Returns an encoded commitment with `coefficients` coefficients.
    fn commitment<V: Variant>(coefficients: u32) -> Vec<u8> {
        let scalars = Poly::<Scalar>::new(test_rng(), coefficients - 1);
        Poly::<V::Public>::commit(scalars).encode().to_vec()
    }

    /// Returns an encoded signature.
    fn signature() -> Vec<u8> {
        ed25519::PrivateKey::from_seed(0)
            .sign(NAMESPACE, b"message")
            .encode()
            .to_vec()
    }

    /// Returns a dealing whose commitment has `coefficients` coefficients.
    fn dealer<V: Variant>(coefficients: u32) -> Vec<u8> {
        let mut message = vec![0u8];
        message.extend(commitment::<V>(coefficients));
        Scalar::random(test_rng()).write(&mut message);
        message
    }

    /// Returns the widest acknowledgement.
    fn ack() -> Vec<u8> {
        let mut message = vec![1u8];
        message.extend(signature());
        message
    }

    /// Returns the widest dealer log payload for `count` players whose commitment has
    /// `coefficients` coefficients.
    fn log<V: Variant>(count: u32, coefficients: u32) -> Vec<u8> {
        // Every player is acknowledged, since a signature is wider than a revealed share.
        const { assert!(Signature::SIZE > Scalar::SIZE) };

        let mut payload = vec![0u8];
        ed25519::PrivateKey::from_seed(0)
            .public_key()
            .write(&mut payload);
        payload.extend(commitment::<V>(coefficients));
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

    /// Returns the widest epoch artifact payload for `count` participants whose public
    /// polynomial has `coefficients` coefficients, ending with `directory`.
    fn info<V: Variant>(count: u32, coefficients: u32, directory: &[u8]) -> Vec<u8> {
        let set = participants(count).encode();
        let mut payload = vec![1u8, 1u8];
        Epoch::new(u64::MAX).write(&mut payload);
        Transcript::new(NAMESPACE, Version::V1)
            .summarize()
            .write(&mut payload);
        payload.put_u8(0);
        count.write(&mut payload);
        payload.extend(commitment::<V>(coefficients));
        for _ in 0..5 {
            payload.extend_from_slice(&set);
        }
        payload.extend_from_slice(directory);
        payload
    }

    /// Asserts that the widest messages and payloads, whose commitments hold one coefficient per
    /// member of a quorum of `count`, decode and encode to exactly the sizes their types report,
    /// and that the limits fold the widest message.
    fn check<V: Variant>(count: u32) {
        let max_participants = NonZeroU32::new(count).unwrap();
        let quorum = N3f1::quorum(count);
        let limits = Limits::new::<V, PublicKey>(Widen::widen(count));

        // The wider of the widest dealing and acknowledgement is the message size, and the
        // footprint adds the widest subchannel prefix.
        let sizes = [dealer::<V>(quorum), ack()].map(|encoded| {
            Message::<V, PublicKey>::decode_cfg(Bytes::from(encoded), &max_participants)
                .unwrap()
                .encode()
                .len()
        });
        let message = Message::<V, PublicKey>::max_encode_size(max_participants).unwrap();
        assert_eq!(sizes.into_iter().max(), Some(message));
        assert_eq!(limits.footprint(), Prefixed(message).footprint());

        // The widest dealer log and the widest epoch artifact with a key-only directory encode to
        // the sizes their types report, and the wider one is the payload size.
        let cfg = (max_participants, ModeVersion::v0());
        let sizes = [log::<V>(count, quorum), info::<V>(count, quorum, &[])].map(|encoded| {
            Payload::<V, PublicKey>::decode_cfg(Bytes::from(encoded), &cfg)
                .unwrap()
                .encode()
                .len()
        });
        let log_size =
            SignedDealerLog::<V, PublicKey>::max_encode_size(max_participants, NZU32!(quorum))
                .unwrap();
        let info_size = EpochInfo::<V, PublicKey>::max_encode_size(max_participants, 0).unwrap();
        assert_eq!(sizes, [log_size + u8::SIZE, info_size + u8::SIZE]);
        assert_eq!(
            sizes.into_iter().max(),
            Payload::<V, PublicKey>::max_encode_size(max_participants, 0)
        );

        // An epoch artifact with an address directory encodes to the payload size for that
        // directory.
        let directory = participants(count)
            .into_iter()
            .map(|participant| {
                let address = Address::Symmetric(SocketAddr::from(([127, 0, 0, 1], 3000)));
                (participant, address)
            })
            .collect::<Addresses<PublicKey>>()
            .encode();
        let encoded = info::<V>(count, quorum, &directory);
        let payload =
            Payload::<V, PublicKey, Addresses<PublicKey>>::decode_cfg(Bytes::from(encoded), &cfg)
                .unwrap();
        assert_eq!(
            Some(payload.encode().len()),
            Payload::<V, PublicKey, Addresses<PublicKey>>::max_encode_size(
                max_participants,
                directory.len()
            )
        );

        // One more coefficient than a quorum of the participants fails to decode.
        let errors = [
            Message::<V, PublicKey>::decode_cfg(
                Bytes::from(dealer::<V>(quorum + 1)),
                &max_participants,
            )
            .err(),
            Payload::<V, PublicKey>::decode_cfg(Bytes::from(log::<V>(count, quorum + 1)), &cfg)
                .err(),
            Payload::<V, PublicKey>::decode_cfg(
                Bytes::from(info::<V>(count, quorum + 1, &[])),
                &cfg,
            )
            .err(),
        ];
        let expected = Widen::<usize>::widen(quorum + 1);
        for error in errors {
            assert!(matches!(error, Some(CodecError::InvalidLength(len)) if len == expected));
        }

        // One more participant than configured fails to decode.
        for encoded in [
            log::<V>(count + 1, quorum),
            info::<V>(count + 1, quorum, &[]),
        ] {
            assert!(Payload::<V, PublicKey, Unit>::decode_cfg(Bytes::from(encoded), &cfg).is_err());
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
    fn payload_overflow() {
        assert_eq!(
            Payload::<MinSig, PublicKey>::max_encode_size(NZU32!(1), usize::MAX),
            None
        );
    }
}
