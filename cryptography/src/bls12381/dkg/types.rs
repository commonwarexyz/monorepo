//! Standard types sent over the wire for [Dealer] shares and [Player] acknowledgements.
//!
//! [Dealer]: crate::bls12381::dkg::Dealer
//! [Player]: crate::bls12381::dkg::Player

use crate::{
    bls12381::primitives::{group, poly::Public, variant::Variant},
    PublicKey, Signature, Signer,
};
use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, EncodeSize, FixedSize, Read, ReadExt, Write};
use commonware_utils::quorum;

/// A [Share] sent by a [Dealer] node to a [Player] node.
///
/// Contains the [Dealer]'s public commitment to their polynomial and the specific
/// share calculated for the receiving [Player].
///
/// [Share]: group::Share
/// [Dealer]: crate::bls12381::dkg::Dealer
/// [Player]: crate::bls12381::dkg::Player
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share<V: Variant> {
    /// The [Dealer]'s public commitment (coefficients of the polynomial).
    ///
    /// [Dealer]: crate::bls12381::dkg::Dealer
    pub commitment: Public<V>,
    /// The secret share evaluated for the recipient [Player].
    ///
    /// [Player]: crate::bls12381::dkg::Player
    pub share: group::Share,
}

impl<V: Variant> Share<V> {
    /// Create a new [Share] message.
    pub fn new(commitment: Public<V>, share: group::Share) -> Self {
        Self { commitment, share }
    }
}

impl<V: Variant> Write for Share<V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.commitment.write(buf);
        self.share.write(buf);
    }
}

impl<V: Variant> EncodeSize for Share<V> {
    fn encode_size(&self) -> usize {
        self.commitment.encode_size() + self.share.encode_size()
    }
}

impl<V: Variant> Read for Share<V> {
    type Cfg = u32;

    fn read_cfg(buf: &mut impl Buf, t: &u32) -> Result<Self, commonware_codec::Error> {
        let q = quorum(*t);
        Ok(Self {
            commitment: Public::<V>::read_cfg(buf, &(q as usize))?,
            share: group::Share::read(buf)?,
        })
    }
}

/// Acknowledgement message sent by a [Player] node back to the [Dealer] node.
///
/// Acknowledges the receipt and verification of a [Share] message.
/// Includes a signature to authenticate the acknowledgment.
///
/// [Dealer]: crate::bls12381::dkg::Dealer
/// [Player]: crate::bls12381::dkg::Player
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ack<S: Signature> {
    /// The public key identifier of the [Player] sending the acknowledgment.
    ///
    /// [Player]: crate::bls12381::dkg::Player
    pub player: u32,
    /// A signature covering the DKG round, dealer ID, and the [Dealer]'s commitment.
    /// This confirms the player received and validated the correct share.
    ///
    /// [Dealer]: crate::bls12381::dkg::Dealer
    pub signature: S,
}

impl<S: Signature> Ack<S> {
    /// Create a new [Ack] message, constructing and signing the payload with the provided [Signer].
    pub fn new<C, V>(
        namespace: &[u8],
        signer: &C,
        player: u32,
        round: u64,
        dealer: &C::PublicKey,
        commitment: &Public<V>,
    ) -> Self
    where
        C: Signer<Signature = S>,
        V: Variant,
    {
        let payload = Self::signature_payload::<V, C::PublicKey>(round, dealer, commitment);
        let signature = signer.sign(Some(namespace), &payload);
        Self { player, signature }
    }

    /// Verifies the signature in the [Ack] message.
    pub fn verify<V: Variant, P: PublicKey<Signature = S>>(
        &self,
        namespace: &[u8],
        public_key: &P,
        round: u64,
        dealer: &P,
        commitment: &Public<V>,
    ) -> bool {
        let payload = Self::signature_payload::<V, P>(round, dealer, commitment);
        public_key.verify(Some(namespace), &payload, &self.signature)
    }

    /// Create a signature payload for acking a secret.
    ///
    /// This payload consists of the round number, [Dealer]'s public key, and the [Dealer]'s commitment,
    /// and the signature over this payload is included in the [Ack] message.
    ///
    /// [Dealer]: crate::bls12381::dkg::Dealer
    fn signature_payload<V: Variant, P: PublicKey>(
        round: u64,
        dealer: &P,
        commitment: &Public<V>,
    ) -> Vec<u8> {
        let mut payload = Vec::with_capacity(u64::SIZE + P::SIZE + commitment.encode_size());
        round.write(&mut payload);
        dealer.write(&mut payload);
        commitment.write(&mut payload);
        payload
    }
}

impl<S: Signature> Write for Ack<S> {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.player).write(buf);
        self.signature.write(buf);
    }
}

impl<S: Signature> EncodeSize for Ack<S> {
    fn encode_size(&self) -> usize {
        UInt(self.player).encode_size() + self.signature.encode_size()
    }
}

impl<S: Signature> Read for Ack<S> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            player: UInt::read(buf)?.into(),
            signature: S::read(buf)?,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        bls12381::{
            dkg::ops,
            primitives::{group, poly::Public, variant::MinSig},
        },
        ed25519::PrivateKey,
        PrivateKeyExt, Signer,
    };
    use commonware_utils::quorum;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    const ACK_NAMESPACE: &[u8] = b"DKG_ACK";

    fn generate_identities(num_peers: u32) -> (Public<MinSig>, Vec<(PrivateKey, group::Share)>) {
        let mut rng = ChaCha8Rng::seed_from_u64(num_peers as u64);

        // Generate consensus key
        let threshold = quorum(num_peers);
        let (polynomial, shares) =
            ops::generate_shares::<_, MinSig>(&mut rng, None, num_peers, threshold);

        // Generate p2p private keys
        let mut peer_signers = (0..num_peers)
            .map(|_| PrivateKey::from_rng(&mut rng))
            .collect::<Vec<_>>();
        peer_signers.sort_by_key(|signer| signer.public_key());

        let identities = peer_signers.into_iter().zip(shares).collect::<Vec<_>>();

        (polynomial, identities)
    }

    #[test]
    fn test_share_roundtrip() {
        const NUM_PARTICIPANTS: u32 = 4;

        let (commitment, identities) = generate_identities(NUM_PARTICIPANTS);
        let (_, share) = &identities[0];

        let share = Share::<MinSig>::new(commitment.clone(), share.clone());

        let mut buf = Vec::with_capacity(share.encode_size());
        share.write(&mut buf);

        let decoded = Share::<MinSig>::read_cfg(&mut buf.as_slice(), &NUM_PARTICIPANTS).unwrap();
        assert_eq!(decoded, share);
    }

    #[test]
    fn test_ack_roundtrip() {
        const NUM_PARTICIPANTS: u32 = 4;

        let (commitment, identities) = generate_identities(NUM_PARTICIPANTS);
        let (signer, _) = &identities[0];

        let ack = Ack::new::<PrivateKey, MinSig>(
            ACK_NAMESPACE,
            signer,
            1337,
            42,
            &signer.public_key(),
            &commitment,
        );

        let mut buf = Vec::with_capacity(ack.encode_size());
        ack.write(&mut buf);

        let decoded =
            Ack::<<PrivateKey as Signer>::Signature>::read_cfg(&mut buf.as_slice(), &()).unwrap();
        assert_eq!(decoded, ack);
    }
}
