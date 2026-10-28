//! Size limits for the payloads DKG sends.

use crate::dkg::types::{Message, max_participants};
use commonware_cryptography::{PublicKey, bls12381::primitives::variant::Variant};
use commonware_p2p::utils::mux::prefixed;

/// Returns the largest payload DKG sends for committees of at most `participants` members.
///
/// # Panics
///
/// Panics if `participants` is zero or exceeds `u32::MAX`.
pub fn max_payload_size<V: Variant, P: PublicKey>(participants: usize) -> usize {
    // DKG sends only dealings and acknowledgements, each on the subchannel of its epoch.
    prefixed(Message::<V, P>::max_encode_size(max_participants(
        participants,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::{
        network::Addresses,
        tests::mocks::widest_addresses,
        types::{EpochInfo, Message, Payload},
    };
    use bytes::{BufMut, Bytes};
    use commonware_codec::{Decode, Encode, FixedSize, Write};
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
    use commonware_utils::{Widen, ordered::Set, sequence::Unit, test_rng};
    use std::num::NonZeroU32;

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
        // Every player is acknowledged, since a signature is wider than a revealed share.
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

    /// Returns the widest epoch artifact payload for `count` participants, ending with `directory`.
    /// Its output names `sets[0]`, its players are `sets[1]`, and its next players are `sets[2]`.
    fn info<V: Variant>(count: u32, sets: [&Set<PublicKey>; 3], directory: &[u8]) -> Vec<u8> {
        let mut payload = vec![1u8, 1u8];
        Epoch::new(u64::MAX).write(&mut payload);
        Transcript::new(NAMESPACE, Version::V1)
            .summarize()
            .write(&mut payload);
        payload.put_u8(0);
        count.write(&mut payload);
        payload.extend(commitment::<V>(count));
        for set in [sets[0], sets[0], sets[0], sets[1], sets[2]] {
            set.write(&mut payload);
        }
        payload.extend_from_slice(directory);
        payload
    }

    /// Asserts that the widest messages and payloads for `count` participants encode to exactly the
    /// sizes their types report, that [`max_payload_size`] is the widest message plus its
    /// subchannel prefix, and that encodings for one more participant fail to decode.
    fn check<V: Variant>(count: u32) {
        let max_participants = NonZeroU32::new(count).unwrap();
        let bound = max_payload_size::<V, PublicKey>(Widen::widen(count));

        // The wider of the widest dealing and acknowledgement is the message size, and the largest
        // payload adds the widest subchannel prefix.
        let sizes = [dealer::<V>(count), ack()].map(|encoded| {
            Message::<V, PublicKey>::decode_cfg(Bytes::from(encoded), &max_participants)
                .unwrap()
                .encode()
                .len()
        });
        let message = Message::<V, PublicKey>::max_encode_size(max_participants);
        assert_eq!(sizes.into_iter().max(), Some(message));
        assert_eq!(bound, prefixed(message));

        // The widest dealer log and the widest epoch artifact with a key-only directory encode to
        // the sizes their types report, and the wider one is the payload size.
        let cfg = (max_participants, ModeVersion::v0());
        let set = participants(count);
        let sizes = [log::<V>(count), info::<V>(count, [&set; 3], &[])].map(|encoded| {
            Payload::<V, PublicKey>::decode_cfg(Bytes::from(encoded), &cfg)
                .unwrap()
                .encode()
                .len()
        });
        let log_size = SignedDealerLog::<V, PublicKey>::max_encode_size(max_participants);
        let info_size = EpochInfo::<V, PublicKey>::max_encode_size(max_participants);
        assert_eq!(sizes, [log_size + u8::SIZE, info_size + u8::SIZE]);
        assert_eq!(
            sizes.into_iter().max(),
            Some(Payload::<V, PublicKey>::max_encode_size(max_participants))
        );

        // The widest epoch artifact with an address directory names disjoint output players,
        // players, and next players, so its directory holds three times `count` peers, each
        // behind the widest address, and encodes to the payload size for that directory type.
        let size: usize = Widen::widen(count);
        let peers = participants(3 * count);
        let sets: Vec<Set<PublicKey>> = (0..3)
            .map(|i| Set::from_iter_dedup(peers.iter().skip(i * size).take(size).cloned()))
            .collect();
        let directory = widest_addresses(&peers).encode();
        let encoded = info::<V>(count, [&sets[0], &sets[1], &sets[2]], &directory);
        let payload =
            Payload::<V, PublicKey, Addresses<PublicKey>>::decode_cfg(Bytes::from(encoded), &cfg)
                .unwrap();
        assert_eq!(
            payload.encode().len(),
            Payload::<V, PublicKey, Addresses<PublicKey>>::max_encode_size(max_participants)
        );

        // One more coefficient or participant than configured fails to decode.
        let encoded = dealer::<V>(count + 1);
        assert!(
            Message::<V, PublicKey>::decode_cfg(Bytes::from(encoded), &max_participants).is_err()
        );
        let set = participants(count + 1);
        for encoded in [log::<V>(count + 1), info::<V>(count + 1, [&set; 3], &[])] {
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
}
