#[allow(dead_code)]
mod evrf;

use crate::{
    bls12381::{
        golden_dkg::evrf::VrfCommitments,
        primitives::{
            group::{Private, Scalar, Share, SmallScalar, G1},
            sharing::{Mode, Sharing},
            variant::MinPk,
        },
    },
    ed25519,
    transcript::Summary,
    Signer as _, Verifier as _,
};
use bytes::Bytes;
use commonware_codec::{Encode, EncodeSize, Write};
use commonware_math::{
    algebra::{Additive, CryptoGroup, Random, Space},
    poly::{Interpolator, Poly},
};
use commonware_parallel::Strategy;
use commonware_utils::{
    ordered::{Map, Quorum as _, Set},
    Faults, Participant, TryCollect as _, NZU32,
};
pub use evrf::{PrivateKey, PublicKey};
use rand_core::CryptoRngCore;
use std::{borrow::Cow, collections::BTreeMap, num::NonZeroU32};

const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_GOLDEN_DKG";

#[derive(Debug)]
pub enum Error {
    DkgFailed,
    MissingDealerShare,
    UnknownDealer(String),
    UnknownPlayer,
}

/// The output of a successful DKG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output<P> {
    summary: Summary,
    public: Sharing<MinPk>,
    dealers: Set<P>,
    players: Set<P>,
    revealed: Set<P>,
}

impl<P: Ord> Output<P> {
    /// Return the quorum, i.e. the number of players needed to reconstruct the key.
    pub fn quorum<M: Faults>(&self) -> u32 {
        self.players.quorum::<M>()
    }

    /// Get the public polynomial associated with this output.
    ///
    /// This is useful for verifying partial signatures, with [`crate::bls12381::primitives::ops::threshold::verify_message`].
    pub const fn public(&self) -> &Sharing<MinPk> {
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
pub struct Info {
    summary: Summary,
    round: u64,
    previous: Option<Output<PublicKey>>,
    mode: Mode,
    dealers: Set<PublicKey>,
    players: Set<PublicKey>,
}

#[allow(dead_code)]
impl Info {
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

pub fn deal<M: Faults>(
    rng: &mut impl CryptoRngCore,
    info: &Info,
    me: &PrivateKey,
    share: Option<Share>,
) -> Result<SignedDealerLog, Error> {
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
    let (masks, commitments) = me.vrf_batch_checked(&nonce, info.players.iter().cloned());

    Ok(DealerLog {
        dealing: Dealing::reckon(info, nonce, poly, masks)?,
        commitments,
    }
    .sign(me))
}

struct Selection {
    weights: Option<Interpolator<PublicKey, Scalar>>,
    dealings: BTreeMap<PublicKey, Dealing>,
}

#[allow(dead_code)]
impl Selection {
    /// Recover the public polynomial from the selected dealings.
    ///
    /// With weights (reshare), this interpolates the commitment polynomials.
    /// Without weights (fresh DKG), this sums them.
    fn public_poly(&self, strategy: &impl Strategy) -> Poly<G1> {
        self.weights.as_ref().map_or_else(
            || {
                let mut public = Poly::zero();
                for dealing in self.dealings.values() {
                    public += &dealing.poly;
                }
                public
            },
            |weights| {
                let commitments: Map<PublicKey, Poly<G1>> = self
                    .dealings
                    .iter()
                    .map(|(dealer, dealing)| (dealer.clone(), dealing.poly.clone()))
                    .try_collect()
                    .expect("Map should have unique keys");
                weights
                    .interpolate(&commitments, strategy)
                    .expect("select checks that enough points have been provided")
            },
        )
    }
}

fn select<M: Faults>(
    rng: &mut impl CryptoRngCore,
    info: &Info,
    logs: BTreeMap<PublicKey, DealerLog>,
    strategy: &impl Strategy,
) -> Result<Selection, Error> {
    // We need at most a certain number of valid dealings, so we will only produce
    // that number. Our strategy is to first check a batch of that size, and then,
    // if any of those are invalid, to check all the remaining dealings, and use
    // some of those to assemble the result. We don't just take the minimum number,
    // to avoid pathological behavior where we check the remaining dealings one
    // by one, because of strategically placed invalid dealings.
    let required = info.required_commitments::<M>() as usize;
    let (first_required, rest) = {
        let mut head = logs.into_iter().collect::<Vec<_>>();
        if head.len() < required {
            return Err(Error::DkgFailed);
        }
        let tail = head.split_off(required);
        (head, tail)
    };
    let mut checked = DealerLog::batch_check(rng, info, first_required, strategy);
    let missing = required.saturating_sub(checked.len());
    if missing > 0 {
        let rest = DealerLog::batch_check(rng, info, rest, strategy);
        if rest.len() < missing {
            return Err(Error::DkgFailed);
        }
        checked.extend(rest.into_iter().take(missing));
    }
    // As a sanity check, make sure that we're emitting exactly what's needed.
    assert_eq!(checked.len(), required);

    let weights = info.previous.as_ref().map(|previous| {
        let dealers: Set<PublicKey> = checked
            .keys()
            .cloned()
            .try_collect()
            .expect("selected dealers are unique");
        previous
            .public()
            .mode()
            .subset_interpolator(previous.players(), &dealers)
            .expect("the result of select should produce a valid subset")
    });
    Ok(Selection {
        weights,
        dealings: checked,
    })
}

pub fn observe<M: Faults>(
    rng: &mut impl CryptoRngCore,
    info: &Info,
    logs: BTreeMap<PublicKey, DealerLog>,
    strategy: &impl Strategy,
) -> Result<Sharing<MinPk>, Error> {
    let selection = select::<M>(rng, info, logs, strategy)?;
    let public = selection.public_poly(strategy);
    let n = info.players.len() as u32;
    Ok(Sharing::new(info.mode, NZU32!(n), public))
}

pub fn play<M: Faults>(
    rng: &mut impl CryptoRngCore,
    info: &Info,
    logs: BTreeMap<PublicKey, DealerLog>,
    me: &PrivateKey,
    strategy: &impl Strategy,
) -> Result<(Sharing<MinPk>, Share), Error> {
    let me_pub = me.public();
    let my_index = info.player_index(&me_pub)?;

    let selection = select::<M>(rng, info, logs, strategy)?;

    // For each dealing, recover our share by unmasking.
    let dealings: Map<PublicKey, Scalar> = selection
        .dealings
        .iter()
        .map(|(dealer, dealing)| {
            let mask = me.vrf(&dealing.nonce, dealer);
            let masked_share = dealing
                .masked_shares
                .get_value(&me_pub)
                .expect("select checks that all players have shares");
            (dealer.clone(), masked_share.clone() - &mask)
        })
        .try_collect()
        .expect("selected dealers are unique");

    // Recover the public polynomial.
    let public = selection.public_poly(strategy);

    // Interpolate (reshare) or sum (fresh) the per-dealer shares.
    let private = selection.weights.map_or_else(
        || {
            let mut out = Scalar::zero();
            for s in dealings.values() {
                out += s;
            }
            out
        },
        |weights| {
            weights
                .interpolate(&dealings, strategy)
                .expect("select ensures that we can recover")
        },
    );

    let n = info.players.len() as u32;
    let sharing = Sharing::new(info.mode, NZU32!(n), public);
    let share = Share::new(my_index, Private::new(private));
    Ok((sharing, share))
}

pub struct SignedDealerLog {
    dealer: PublicKey,
    signature: ed25519::Signature,
    log: DealerLog,
}

impl SignedDealerLog {
    /// Verify the signature and extract the dealer's public key and log.
    ///
    /// Returns `None` if the signature is invalid.
    pub fn identify(self) -> Option<(PublicKey, DealerLog)> {
        let msg = self.log.encode();
        if !self.dealer.verify(NAMESPACE, &msg, &self.signature) {
            return None;
        }
        Some((self.dealer, self.log))
    }
}

#[allow(dead_code)]
pub struct DealerLog {
    commitments: VrfCommitments,
    dealing: Dealing,
}

impl Write for DealerLog {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.dealing.write(buf);
        self.commitments.write(buf);
    }
}

impl EncodeSize for DealerLog {
    fn encode_size(&self) -> usize {
        self.dealing.encode_size() + self.commitments.encode_size()
    }
}

#[allow(dead_code)]
impl DealerLog {
    #[allow(dead_code)]
    fn batch_check(
        rng: &mut impl CryptoRngCore,
        info: &Info,
        batch: impl IntoIterator<Item = (PublicKey, Self)>,
        strategy: &impl Strategy,
    ) -> BTreeMap<PublicKey, Dealing> {
        let (commitments, dealings) = batch
            .into_iter()
            .map(|(d, log)| {
                (
                    (
                        d.clone(),
                        Bytes::copy_from_slice(log.dealing.nonce.as_ref()),
                        log.commitments,
                    ),
                    (d, log.dealing),
                )
            })
            .collect::<(Vec<_>, Vec<_>)>();
        let mask_commitments = VrfCommitments::check_batch(rng, commitments);
        dealings
            .into_iter()
            .filter_map(|(d, dealing)| {
                let mask_commitments = mask_commitments.get_value(&d)?;
                if !dealing.check(rng, info, &d, mask_commitments, strategy) {
                    return None;
                }
                Some((d, dealing))
            })
            .collect()
    }

    fn sign(self, signer: &PrivateKey) -> SignedDealerLog {
        let dealer = signer.public();
        let msg = self.encode();
        let signature = signer.sign(NAMESPACE, &msg);
        SignedDealerLog {
            dealer,
            signature,
            log: self,
        }
    }
}

struct Dealing {
    nonce: Summary,
    poly: Poly<G1>,
    masked_shares: Map<PublicKey, Scalar>,
}

impl Write for Dealing {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.nonce.write(buf);
        self.poly.write(buf);
        self.masked_shares.write(buf);
    }
}

impl EncodeSize for Dealing {
    fn encode_size(&self) -> usize {
        self.nonce.encode_size() + self.poly.encode_size() + self.masked_shares.encode_size()
    }
}

impl Dealing {
    fn reckon(
        info: &Info,
        nonce: Summary,
        poly: Poly<Scalar>,
        masks: Map<PublicKey, Scalar>,
    ) -> Result<Self, Error> {
        let mut inner = masks;
        for (player, mask) in inner.iter_pairs_mut() {
            *mask += &poly.eval(&info.player_scalar(player)?);
        }
        let poly = Poly::commit(poly);
        Ok(Self {
            nonce,
            poly,
            masked_shares: inner,
        })
    }

    #[must_use]
    fn check(
        &self,
        rng: &mut impl CryptoRngCore,
        info: &Info,
        dealer: &PublicKey,
        mask_commitments: &Map<PublicKey, G1>,
        strategy: &impl Strategy,
    ) -> bool {
        // If this is a reshare, the constant of the dealing polynomial must match
        // the dealer's share commitment from the previous round.
        if let Some(previous) = info.previous.as_ref() {
            let Some(expected) = previous
                .players()
                .index(dealer)
                .and_then(|idx| previous.public().partial_public(idx).ok())
            else {
                return false;
            };
            if *self.poly.constant() != expected {
                return false;
            }
        }

        // An honest dealer will set, for each player i, the masked share to be:
        //
        //   z_i := m_i + f(x_i)
        //
        // we have M_i assumed to equal m_i * G, and F := f * G, so we can check:
        //
        //   z_i * G - M_i =? F(x_i)
        //
        // to batch this efficiently over multiple players, we can do:
        //
        //   <r_i, z_i * G - M_i> =? <r_i, F(x_i)>
        //   <r_i, z_i> * G - <r_i, M_i> =? <r_i, F(x_i)>
        //
        // [`Poly`] has an efficient method for evaluating the right hand side,
        // we can do an MSM for the M_i portion of the left hand side, and then
        // just do one scalar multiplication for the z_i part.
        //
        // We'll also want to do some other boilerplate checks, like making sure
        // all commitments are present, all shares are present, etc.
        let len = info.players.len() - 1;
        let (r, z, m, x) = {
            let mut r = Vec::with_capacity(len);
            let mut z = Vec::with_capacity(len);
            let mut m = Vec::with_capacity(len);
            let mut x = Vec::with_capacity(len);
            for p in &info.players {
                if p == dealer {
                    continue;
                }
                r.push(SmallScalar::random(&mut *rng));
                let Some(z_i) = self.masked_shares.get_value(p) else {
                    return false;
                };
                z.push(z_i.clone());
                let Some(m_i) = mask_commitments.get_value(p) else {
                    return false;
                };
                m.push(*m_i);
                x.push(info.player_scalar(p).expect("player scalar must exist"));
            }
            (r, z, m, x)
        };
        let lhs: G1 = {
            let r_z = r.iter().zip(z).fold(Scalar::zero(), |mut acc, (r_i, z_i)| {
                acc += &(Scalar::from(r_i.clone()) * &z_i);
                acc
            });
            let r_m = G1::msm(&m, &r, strategy);
            G1::generator() * &r_z - &r_m
        };
        let rhs: G1 = self.poly.lin_comb_eval(
            r.into_iter()
                .zip(x)
                .map(|(r_i, x_i)| (Scalar::from(r_i), Cow::Owned(x_i))),
            strategy,
        );
        lhs == rhs
    }
}

#[cfg(any(feature = "arbitrary", test))]
mod test_plan {
    use super::*;
    use crate::transcript::Transcript;
    use commonware_codec::Encode;
    use commonware_math::algebra::Random;
    use commonware_parallel::Sequential;
    use commonware_utils::N3f1;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::collections::BTreeMap;

    /// A golden DKG test plan.
    ///
    /// Generates a fresh DKG with the given number of dealers and players,
    /// then verifies that a particular "star" player ends up with a valid share.
    #[derive(Debug)]
    pub struct Plan {
        num_dealers: u32,
        num_players: u32,
        star: u32,
    }

    impl Plan {
        pub const fn new(num_dealers: u32, num_players: u32, star: u32) -> Self {
            Self {
                num_dealers,
                num_players,
                star,
            }
        }

        fn validate(&self) -> anyhow::Result<()> {
            anyhow::ensure!(self.num_dealers >= 1, "need at least 1 dealer");
            anyhow::ensure!(self.num_players >= 1, "need at least 1 player");
            anyhow::ensure!(
                self.star < self.num_players,
                "star must be a valid player index"
            );
            Ok(())
        }

        pub fn run(self, seed: u64) -> anyhow::Result<()> {
            self.validate()?;

            let mut rng = StdRng::seed_from_u64(seed);

            // Generate separate keys for dealers and players.
            let dealer_keys: Vec<PrivateKey> = (0..self.num_dealers)
                .map(|_| PrivateKey::random(&mut rng))
                .collect();
            let player_keys: Vec<PrivateKey> = (0..self.num_players)
                .map(|_| PrivateKey::random(&mut rng))
                .collect();

            let dealer_set: Set<PublicKey> = dealer_keys
                .iter()
                .map(|k| k.public())
                .try_collect()
                .unwrap();
            let player_set: Set<PublicKey> = player_keys
                .iter()
                .map(|k| k.public())
                .try_collect()
                .unwrap();

            // Build Info for a fresh DKG (no previous round).
            let round = 0u64;
            let mode = Mode::default();
            let summary = {
                let mut transcript = Transcript::new(NAMESPACE);
                transcript
                    .commit(round.encode())
                    .commit(dealer_set.encode())
                    .commit(player_set.encode());
                transcript.summarize()
            };
            let info = Info {
                summary,
                round,
                previous: None,
                mode,
                dealers: dealer_set,
                players: player_set,
            };

            // Each dealer deals.
            let mut logs = BTreeMap::new();
            for dk in &dealer_keys {
                let signed =
                    deal::<N3f1>(&mut rng, &info, dk, None).map_err(|e| anyhow::anyhow!("{e:?}"))?;
                let (pk, log) = signed
                    .identify()
                    .ok_or_else(|| anyhow::anyhow!("dealer signature verification failed"))?;
                logs.insert(pk, log);
            }

            // Star player plays.
            let star_key = &player_keys[self.star as usize];
            let (sharing, share) = play::<N3f1>(&mut rng, &info, logs, star_key, &Sequential)
                .map_err(|e| anyhow::anyhow!("{e:?}"))?;

            // Verify share matches public polynomial.
            let expected = sharing
                .partial_public(share.index)
                .map_err(|e| anyhow::anyhow!("{e:?}"))?;
            let actual = share.public::<MinPk>();
            assert_eq!(expected, actual, "share should match public polynomial");

            Ok(())
        }
    }

    #[cfg(feature = "arbitrary")]
    impl<'a> arbitrary::Arbitrary<'a> for Plan {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            const MAX: u32 = 10;
            let num_dealers = u.int_in_range(1..=MAX)?;
            let num_players = u.int_in_range(1..=MAX)?;
            let star = u.int_in_range(0..=num_players - 1)?;
            let plan = Self {
                num_dealers,
                num_players,
                star,
            };
            plan.validate()
                .map_err(|_| arbitrary::Error::IncorrectFormat)?;
            Ok(plan)
        }
    }
}

#[cfg(feature = "arbitrary")]
pub use test_plan::Plan as FuzzPlan;

#[cfg(test)]
mod tests {
    use super::test_plan::Plan;
    use commonware_invariants::minifuzz;

    #[test]
    fn single_dealer_single_player() {
        Plan::new(1, 1, 0).run(42).expect("plan should succeed");
    }

    #[test]
    fn multiple_dealers_multiple_players() {
        Plan::new(4, 7, 3).run(42).expect("plan should succeed");
    }

    #[test]
    fn many_dealers() {
        Plan::new(10, 5, 0).run(42).expect("plan should succeed");
    }

    #[test]
    fn fuzz_plan() {
        minifuzz::test(|u| {
            let num_dealers = u.int_in_range(1..=10u32)?;
            let num_players = u.int_in_range(1..=10u32)?;
            let star = u.int_in_range(0..=num_players - 1)?;
            let seed: u64 = u.arbitrary()?;
            Plan::new(num_dealers, num_players, star)
                .run(seed)
                .expect("plan should succeed");
            Ok(())
        });
    }
}
