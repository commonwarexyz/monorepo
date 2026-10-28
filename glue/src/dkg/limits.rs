//! Size limits for the payloads DKG sends.

use crate::dkg::types::Message;
use commonware_cryptography::{PublicKey, bls12381::primitives::variant::Variant};
use commonware_p2p::utils::mux::prefixed;
use std::num::NonZeroU32;

/// Returns an upper bound on the payloads DKG sends for committees of at most `max_participants`
/// members.
pub fn max_payload_size<V: Variant, P: PublicKey>(max_participants: NonZeroU32) -> usize {
    // DKG sends only dealings and acknowledgements, each on the subchannel of its epoch.
    prefixed(Message::<V, P>::max_encode_size(max_participants))
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
    use commonware_codec::{
        Decode, Encode, EncodeSize, FixedSize, MaxEncodeSize, Write, varint::MAX_U32_VARINT_SIZE,
    };
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
    use commonware_utils::{Widen, ordered::Set, sequence::Unit, test_rng};

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

    /// Checks message and payload bounds against encoded fields and rejects excess participants.
    fn check<V: Variant>(count: u32) {
        let max_participants = NonZeroU32::new(count).unwrap();
        let bound = max_payload_size::<V, PublicKey>(max_participants);
        let size: usize = Widen::widen(count);
        let prefix_slack = MAX_U32_VARINT_SIZE - size.encode_size();

        // The dealing is wider than the acknowledgement, and the message bound adds the unused
        // width of its commitment's count prefix. The payload bound adds the subchannel prefix.
        let sizes = [dealer::<V>(count), ack()].map(|encoded| {
            Message::<V, PublicKey>::decode_cfg(Bytes::from(encoded), &max_participants)
                .unwrap()
                .encode()
                .len()
        });
        let message = Message::<V, PublicKey>::max_encode_size(max_participants);
        let [dealing, ack] = sizes;
        assert!(ack < dealing);
        assert_eq!(dealing + prefix_slack, message);
        assert_eq!(bound, prefixed(message));

        // The payload bounds add the unused width of each count prefix: three in a dealer log
        // (commitment, players, and acknowledgements) and six in an epoch artifact (commitment and
        // five participant sets).
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
        let payload_bounds = [sizes[0] + 3 * prefix_slack, sizes[1] + 6 * prefix_slack];
        assert_eq!(payload_bounds, [log_size + u8::SIZE, info_size + u8::SIZE]);
        assert_eq!(
            payload_bounds.into_iter().max(),
            Some(Payload::<V, PublicKey>::max_encode_size(max_participants))
        );

        // The widest epoch artifact with an address directory names disjoint output players,
        // players, and next players, so its directory holds three times `count` peers, each
        // behind the widest address.
        let peers = participants(3 * count);
        let sets: Vec<Set<PublicKey>> = (0..3)
            .map(|i| Set::from_iter_dedup(peers.iter().skip(i * size).take(size).cloned()))
            .collect();
        let addresses = widest_addresses(&peers);
        let entries = 3 * size;

        // The bound also adds the unused width of the directory's key-set and address-list
        // prefixes and of each address's hostname prefix.
        let address_slack =
            Address::MAX_ENCODE_SIZE - addresses.get(&peers[0]).unwrap().encode_size();
        let directory_slack =
            2 * (MAX_U32_VARINT_SIZE - entries.encode_size()) + entries * address_slack;
        let directory = addresses.encode();
        let encoded = info::<V>(count, [&sets[0], &sets[1], &sets[2]], &directory);
        let payload =
            Payload::<V, PublicKey, Addresses<PublicKey>>::decode_cfg(Bytes::from(encoded), &cfg)
                .unwrap();
        assert_eq!(
            payload.encode().len() + 6 * prefix_slack + directory_slack,
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
