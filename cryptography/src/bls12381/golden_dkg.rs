#[allow(dead_code)]
mod evrf;

use crate::{
    bls12381::{
        golden_dkg::evrf::VrfCommitments,
        primitives::{
            group::{Scalar, Share},
            sharing::{Mode, Sharing},
            variant::Variant,
        },
    },
    transcript::Summary,
};
use commonware_math::{algebra::Random as _, poly::Poly};
use commonware_utils::{
    ordered::{Map, Quorum as _, Set},
    Faults, Participant, NZU32,
};
pub use evrf::{PrivateKey, PublicKey};
use rand_core::CryptoRngCore;
use std::{collections::BTreeMap, marker::PhantomData, num::NonZeroU32};

pub enum Error {
    DkgFailed,
    MissingDealerShare,
    UnknownDealer(String),
    UnknownPlayer,
}

/// The output of a successful DKG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output<V: Variant, P> {
    summary: Summary,
    public: Sharing<V>,
    dealers: Set<P>,
    players: Set<P>,
    revealed: Set<P>,
}

impl<V: Variant, P: Ord> Output<V, P> {
    /// Return the quorum, i.e. the number of players needed to reconstruct the key.
    pub fn quorum<M: Faults>(&self) -> u32 {
        self.players.quorum::<M>()
    }

    /// Get the public polynomial associated with this output.
    ///
    /// This is useful for verifying partial signatures, with [`crate::bls12381::primitives::ops::threshold::verify_message`].
    pub const fn public(&self) -> &Sharing<V> {
        &self.public
    }

    /// Return the dealers who were selected in this round of the DKG.
    pub const fn dealers(&self) -> &Set<P> {
        &self.dealers
    }

    /// Return the players who participated in this round of the DKG, and should have shares.
    pub const fn players(&self) -> &Set<P> {
        &self.players
    }
}

#[allow(dead_code)]
pub struct Info<V: Variant> {
    summary: Summary,
    round: u64,
    previous: Option<Output<V, PublicKey>>,
    mode: Mode,
    dealers: Set<PublicKey>,
    players: Set<PublicKey>,
}

#[allow(dead_code)]
impl<V: Variant> Info<V> {
    fn player_index(&self, player: &PublicKey) -> Result<Participant, Error> {
        self.players.index(player).ok_or(Error::UnknownPlayer)
    }

    fn dealer_index(&self, dealer: &PublicKey) -> Result<Participant, Error> {
        self.dealers
            .index(dealer)
            .ok_or(Error::UnknownDealer(format!("{dealer:?}")))
    }

    /// Figure out what the dealer share should be.
    ///
    /// If there's no previous round, we need a random value, hence `rng`.
    ///
    /// However, if there is a previous round, we expect a share, hence `Result`.
    fn unwrap_or_random_share(
        &self,
        mut rng: impl CryptoRngCore,
        share: Option<Scalar>,
    ) -> Result<Scalar, Error> {
        let out = match (self.previous.as_ref(), share) {
            (None, None) => Scalar::random(&mut rng),
            (_, Some(x)) => x,
            (Some(_), None) => return Err(Error::MissingDealerShare),
        };
        Ok(out)
    }

    const fn num_players(&self) -> NonZeroU32 {
        // Will not panic because we check that the number of players is non-empty in `new`
        NZU32!(self.players.len() as u32)
    }

    fn degree<M: Faults>(&self) -> u32 {
        self.players.quorum::<M>().saturating_sub(1)
    }

    fn required_commitments<M: Faults>(&self) -> u32 {
        let dealer_quorum = self.dealers.quorum::<M>();
        let prev_quorum = self
            .previous
            .as_ref()
            .map(Output::quorum::<M>)
            .unwrap_or(u32::MIN);
        dealer_quorum.max(prev_quorum)
    }

    fn player_scalar(&self, player: &PublicKey) -> Result<Scalar, Error> {
        Ok(self
            .mode
            .scalar(self.num_players(), self.player_index(player)?)
            .expect("player index should be < num_players"))
    }
}

pub fn deal<V: Variant, M: Faults>(
    rng: &mut impl CryptoRngCore,
    info: &Info<V>,
    me: &PrivateKey,
    share: Option<Share>,
) -> Result<SignedDealerLog<V>, Error> {
    let me_pub = me.public();

    // Error early if this dealer shouldn't be a part of the DKG.
    info.dealer_index(&me_pub)?;

    let share = info.unwrap_or_random_share(
        &mut *rng,
        // We are extracting the private scalar from `Secret` protection because
        // `Poly::new_with_constant` requires an owned value. The extracted scalar is
        // scoped to this function and will be zeroized on drop (i.e. the secret is
        // only exposed for the duration of this function).
        share.map(|x| x.private.expose_unwrap()),
    )?;
    let poly = Poly::new_with_constant(&mut *rng, info.degree::<M>(), share);

    let nonce = Summary::random(&mut *rng);
    let receivers = info.players.iter().filter(|p| *p != &me_pub).cloned();
    let (masks, commitments) = me.vrf_batch_checked(&nonce, receivers);

    Ok(DealerLog {
        nonce,
        // Evaluate this first, borrowing poly...
        masked_shares: MaskedShares::reckon(info, &poly, masks)?,
        // which gets move here.
        poly: Poly::commit(poly),
        commitments,
    }
    .sign(me))
}

pub fn observe<V: Variant>(_logs: BTreeMap<PublicKey, DealerLog<V>>) -> Result<Sharing<V>, Error> {
    todo!()
}

pub fn play<V: Variant>(
    _logs: BTreeMap<PublicKey, DealerLog<V>>,
    _me: &PrivateKey,
) -> (Sharing<V>, Share) {
    todo!()
}

pub struct SignedDealerLog<V: Variant> {
    p: PhantomData<V>,
}

impl<V: Variant> SignedDealerLog<V> {
    pub fn identify(self) -> Option<(PublicKey, DealerLog<V>)> {
        todo!()
    }
}

#[allow(dead_code)]
pub struct DealerLog<V: Variant> {
    nonce: Summary,
    poly: Poly<V::Public>,
    commitments: VrfCommitments,
    masked_shares: MaskedShares,
}

#[allow(dead_code)]
impl<V: Variant> DealerLog<V> {
    #[allow(dead_code)]
    fn batch_check(
        _batch: impl IntoIterator<Item = (PublicKey, Self)>,
    ) -> Map<PublicKey, MaskedShares> {
        todo!()
    }

    fn sign(self, _priv: &PrivateKey) -> SignedDealerLog<V> {
        todo!()
    }
}

struct MaskedShares {
    #[allow(dead_code)]
    inner: Map<PublicKey, Scalar>,
}

impl MaskedShares {
    fn reckon<V: Variant>(
        info: &Info<V>,
        poly: &Poly<Scalar>,
        masks: Map<PublicKey, Scalar>,
    ) -> Result<Self, Error> {
        let mut inner = masks;
        for (player, mask) in inner.iter_pairs_mut() {
            *mask += &poly.eval(&info.player_scalar(player)?);
        }
        Ok(Self { inner })
    }
}
