//! Committee key material created by one trusted dealer.

use super::{Error, Roster, Scheme, SignerKeys};
use crate::multimmit::config::Parameters;
use bytes::BytesMut;
use commonware_codec::{Read as _, Write as _};
use commonware_cryptography::{
    PublicKey,
    bls12381::primitives::{
        group::{Private, Scalar, Share},
        ops,
        sharing::{Mode, ModeVersion, Sharing},
        variant::Variant,
    },
};
use commonware_math::poly::Poly;
use commonware_parallel::Sequential;
use commonware_utils::{Participant, ordered::Set};
use core::num::NonZeroU32;
use rand_core::CryptoRng;
use std::sync::Arc;

/// A threshold sharing and each participant's private share, in participant order.
pub struct DealtSharing<V: Variant> {
    /// The public sharing.
    pub sharing: Sharing<V>,
    /// One private share per participant.
    pub shares: Vec<Share>,
}

/// The key material one trusted dealer created for a committee.
pub struct Dealt<P: PublicKey, V: Variant> {
    /// The proof-of-possession checked ordinary-key roster.
    pub roster: Roster<P, V>,
    /// The public `n - 2f` data-availability sharing.
    pub da: Sharing<V>,
    /// The public `2f + 1` nullification sharing.
    pub nullification: Sharing<V>,
    /// One signing scheme per participant, in participant order.
    pub signers: Vec<Scheme<P, V>>,
    /// A keyless verification scheme for observers.
    pub verifier: Scheme<P, V>,
}

/// Deals every participant's ordinary key and threshold shares for the epoch `parameters`.
///
/// `identities` are the participants' network keys; participant `i` owns the `i`-th identity. The
/// dealer sees every secret it creates, so the committee must trust it with all of them. That
/// suits tests, benchmarks, and deployments run by one operator; a committee without such a party
/// should run a distributed key generation instead.
///
/// Randomness is drawn for the ordinary keys in participant order, then for the data-availability
/// sharing, then for the nullification sharing.
///
/// # Errors
///
/// Returns an error when `identities` does not hold exactly the epoch's participants.
pub fn deal<P, V>(
    rng: &mut impl CryptoRng,
    parameters: &Arc<Parameters>,
    identities: &Set<P>,
) -> Result<Dealt<P, V>, Error>
where
    P: PublicKey,
    V: Variant,
{
    let codec = parameters.codec_config();
    let participants = u32::try_from(codec.participants()).map_err(|_| Error::Participants)?;
    let mut ordinary = Vec::with_capacity(identities.len());
    let roster_input = identities
        .iter()
        .map(|identity| {
            let (private, public) = ops::keypair::<_, V>(&mut *rng);
            let proof = Roster::<P, V>::proof_of_possession(parameters.namespace(), &private);
            ordinary.push(private);
            (identity.clone(), public, proof)
        })
        .collect();
    let roster = Roster::verify(
        parameters.namespace(),
        codec.participants(),
        roster_input,
        &Sequential,
    )?;
    let da = deal_sharing::<V>(
        rng,
        participants,
        u32::try_from(codec.da_quorum()).map_err(|_| Error::Participants)?,
    );
    let nullification = deal_sharing::<V>(
        rng,
        participants,
        u32::try_from(codec.nullification_quorum()).map_err(|_| Error::Participants)?,
    );
    let signers = ordinary
        .into_iter()
        .zip(da.shares)
        .zip(nullification.shares)
        .map(|((ordinary, da_share), nullification_share)| {
            Scheme::signer(
                parameters,
                roster.clone(),
                SignerKeys {
                    ordinary,
                    da: da_share,
                    nullification: nullification_share,
                },
                da.sharing.clone(),
                nullification.sharing.clone(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let verifier = Scheme::verifier(
        parameters,
        roster.clone(),
        da.sharing.clone(),
        nullification.sharing.clone(),
    )?;
    Ok(Dealt {
        roster,
        da: da.sharing,
        nullification: nullification.sharing,
        signers,
        verifier,
    })
}

/// Deals a `required`-of-`total` threshold sharing from `rng`.
///
/// # Panics
///
/// Panics when `total` or `required` is zero.
pub(crate) fn deal_sharing<V: Variant>(
    rng: &mut impl CryptoRng,
    total: u32,
    required: u32,
) -> DealtSharing<V> {
    let private = Poly::<Scalar>::new(rng, required - 1);
    let shares = (0..total)
        .map(|index| {
            let point = Scalar::from_u64(u64::from(index) + 1);
            Share::new(Participant::new(index), Private::new(private.eval(&point)))
        })
        .collect();
    let public = Poly::<V::Public>::commit(private);
    // A sharing has no public constructor from its polynomial; its canonical encoding is the
    // supported way to build one.
    let mut encoded = BytesMut::new();
    Mode::NonZeroCounter.write(&mut encoded);
    total.write(&mut encoded);
    public.write(&mut encoded);
    let mut encoded = encoded.freeze();
    let total = NonZeroU32::new(total).expect("a sharing has at least one participant");
    let sharing = Sharing::read_cfg(&mut encoded, &(total, ModeVersion::v0()))
        .expect("a freshly committed sharing decodes");
    DealtSharing { sharing, shares }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Epochable as _,
        multimmit::{
            mocks::{Committee, keys::test_config},
            types::{ChainId, PathLimits, TransactionBlockHeader},
        },
        types::Height,
    };
    use commonware_cryptography::{
        Hasher as _, Sha256, Signer as _, bls12381::primitives::variant::MinPk, ed25519,
    };
    use commonware_utils::test_rng;

    #[test]
    fn dealt_signers_sign_what_the_verifier_accepts() {
        let committee = Committee::<MinPk>::builder(93, 6).build();
        let config = test_config(
            94,
            b"_COMMONWARE_CONSENSUS_MULTIMMIT_DEALER_TEST",
            6,
            (0..6).map(Participant::new).collect(),
            PathLimits::new(2, 1).unwrap(),
        );
        let identities = Set::try_from(committee.identities).unwrap();
        let dealt = deal::<_, MinPk>(&mut test_rng(), config.parameters(), &identities).unwrap();
        assert_eq!(dealt.signers.len(), 6);
        for (index, signer) in dealt.signers.iter().enumerate() {
            assert_eq!(signer.me(), Some(Participant::from_usize(index)));
        }

        let parent = config.genesis().tips()[0].digest();
        let header = TransactionBlockHeader::new(
            config.epoch(),
            ChainId::new(0),
            Height::new(1),
            parent,
            Sha256::hash(&[b"body"]),
        )
        .unwrap();
        let votes = (0..config.codec_config().da_quorum())
            .map(|signer| dealt.signers[signer].sign_da_vote(header.clone()).unwrap())
            .collect::<Vec<_>>();
        assert!(
            dealt
                .verifier
                .assemble_da_certificate(&votes, &Sequential)
                .is_ok()
        );
    }

    #[test]
    fn dealing_rejects_a_mismatched_identity_count() {
        let config = test_config(
            95,
            b"_COMMONWARE_CONSENSUS_MULTIMMIT_DEALER_COUNT_TEST",
            6,
            (0..6).map(Participant::new).collect(),
            PathLimits::new(2, 1).unwrap(),
        );
        let identities =
            Set::try_from([ed25519::PrivateKey::from_seed(1).public_key()].to_vec()).unwrap();
        assert!(matches!(
            deal::<_, MinPk>(&mut test_rng(), config.parameters(), &identities),
            Err(Error::Participants)
        ));
    }
}
