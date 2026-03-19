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
    let mut checked = DealerLog::batch_check::<M>(rng, info, first_required, strategy);
    let missing = required.saturating_sub(checked.len());
    if missing > 0 {
        let rest = DealerLog::batch_check::<M>(rng, info, rest, strategy);
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

#[derive(Clone)]
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
    fn batch_check<M: Faults>(
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
                if !dealing.check::<M>(rng, info, &d, mask_commitments, strategy) {
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

#[derive(Clone)]
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
    fn check<M: Faults>(
        &self,
        rng: &mut impl CryptoRngCore,
        info: &Info,
        dealer: &PublicKey,
        mask_commitments: &Map<PublicKey, G1>,
        strategy: &impl Strategy,
    ) -> bool {
        if self.poly.degree_exact() != info.degree::<M>() {
            return false;
        }

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
    use commonware_math::{algebra::Random, poly::Poly};
    use commonware_parallel::Sequential;
    use commonware_utils::N3f1;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::collections::{BTreeMap, BTreeSet};

    /// A golden DKG test plan.
    ///
    /// Generates a fresh DKG with the given number of dealers and players,
    /// then verifies that a particular "star" player ends up with a valid share.
    /// Supports perturbations to test adversarial/failure paths.
    #[derive(Debug)]
    pub struct Plan {
        num_dealers: u32,
        num_players: u32,
        star: u32,
        bad_signatures: BTreeSet<u32>,
        bad_shares: BTreeSet<(u32, u32)>,
        bad_commitments: BTreeSet<u32>,
        missing_shares: BTreeSet<(u32, u32)>,
        shift_degrees: BTreeMap<u32, i32>,
        drop_dealers: BTreeSet<u32>,
        reshare: bool,
        replace_shares: BTreeSet<u32>,
    }

    impl Plan {
        pub const fn new(num_dealers: u32, num_players: u32, star: u32) -> Self {
            Self {
                num_dealers,
                num_players,
                star,
                bad_signatures: BTreeSet::new(),
                bad_shares: BTreeSet::new(),
                bad_commitments: BTreeSet::new(),
                missing_shares: BTreeSet::new(),
                shift_degrees: BTreeMap::new(),
                drop_dealers: BTreeSet::new(),
                reshare: false,
                replace_shares: BTreeSet::new(),
            }
        }

        pub fn bad_signature(mut self, dealer: u32) -> Self {
            self.bad_signatures.insert(dealer);
            self
        }

        pub fn bad_share(mut self, dealer: u32, player: u32) -> Self {
            self.bad_shares.insert((dealer, player));
            self
        }

        pub fn bad_commitment(mut self, dealer: u32) -> Self {
            self.bad_commitments.insert(dealer);
            self
        }

        pub fn missing_share(mut self, dealer: u32, player: u32) -> Self {
            self.missing_shares.insert((dealer, player));
            self
        }

        pub fn shift_degree(mut self, dealer: u32, shift: i32) -> Self {
            self.shift_degrees.insert(dealer, shift);
            self
        }

        pub fn drop_dealer(mut self, dealer: u32) -> Self {
            self.drop_dealers.insert(dealer);
            self
        }

        pub const fn reshare(mut self) -> Self {
            self.reshare = true;
            self
        }

        pub fn replace_share(mut self, dealer: u32) -> Self {
            self.replace_shares.insert(dealer);
            self
        }

        pub fn validate(&self) -> anyhow::Result<()> {
            anyhow::ensure!(self.num_dealers >= 1, "need at least 1 dealer");
            anyhow::ensure!(self.num_players >= 1, "need at least 1 player");
            anyhow::ensure!(
                self.star < self.num_players,
                "star must be a valid player index"
            );
            for &d in &self.bad_signatures {
                anyhow::ensure!(d < self.num_dealers, "bad_signature dealer out of range");
            }
            for &(d, p) in &self.bad_shares {
                anyhow::ensure!(d < self.num_dealers, "bad_share dealer out of range");
                anyhow::ensure!(p < self.num_players, "bad_share player out of range");
            }
            for &d in &self.bad_commitments {
                anyhow::ensure!(d < self.num_dealers, "bad_commitment dealer out of range");
            }
            for &(d, p) in &self.missing_shares {
                anyhow::ensure!(d < self.num_dealers, "missing_share dealer out of range");
                anyhow::ensure!(p < self.num_players, "missing_share player out of range");
            }
            for &d in self.shift_degrees.keys() {
                anyhow::ensure!(d < self.num_dealers, "shift_degree dealer out of range");
            }
            for &d in &self.drop_dealers {
                anyhow::ensure!(d < self.num_dealers, "drop_dealer dealer out of range");
            }
            for &d in &self.replace_shares {
                anyhow::ensure!(d < self.num_dealers, "replace_share dealer out of range");
                anyhow::ensure!(self.reshare, "replace_share requires reshare");
            }
            Ok(())
        }

        /// Is this dealer "bad" (will be filtered by check)?
        fn is_bad_dealer(&self, dealer: u32) -> bool {
            self.bad_commitments.contains(&dealer)
                || self.shift_degree_effective(dealer)
                || self.replace_shares.contains(&dealer)
                || self.bad_shares.iter().any(|&(d, _)| d == dealer)
                || self.missing_shares.iter().any(|&(d, _)| d == dealer)
        }

        /// Does the shift_degree perturbation actually change the polynomial degree?
        fn shift_degree_effective(&self, dealer: u32) -> bool {
            let Some(&shift) = self.shift_degrees.get(&dealer) else {
                return false;
            };
            let degree = N3f1::quorum(self.num_players).saturating_sub(1);
            let new_degree = (degree as i32 + shift).max(0) as u32;
            new_degree != degree
        }

        /// Count how many honest (non-dropped, non-bad-sig, non-bad) dealers remain.
        fn honest_dealer_count(&self) -> u32 {
            (0..self.num_dealers)
                .filter(|d| {
                    !self.drop_dealers.contains(d)
                        && !self.bad_signatures.contains(d)
                        && !self.is_bad_dealer(*d)
                })
                .count() as u32
        }

        fn expect_failure(&self) -> bool {
            let required = N3f1::quorum(self.num_dealers);
            let previous_quorum = if self.reshare {
                // In reshare, dealers == players from previous round.
                N3f1::quorum(self.num_dealers)
            } else {
                0
            };
            let required = required.max(previous_quorum);
            self.honest_dealer_count() < required
        }

        fn make_info(
            round: u64,
            previous: Option<Output<PublicKey>>,
            dealer_keys: &[PrivateKey],
            player_keys: &[PrivateKey],
        ) -> Info {
            let mode = Mode::default();
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
            let summary = {
                let mut transcript = Transcript::new(NAMESPACE);
                transcript
                    .commit(round.encode())
                    .commit(dealer_set.encode())
                    .commit(player_set.encode());
                transcript.summarize()
            };
            Info {
                summary,
                round,
                previous,
                mode,
                dealers: dealer_set,
                players: player_set,
            }
        }

        /// Run a fresh (honest) DKG round and return the output and per-player shares.
        pub fn run_fresh(
            rng: &mut StdRng,
            dealer_keys: &[PrivateKey],
            player_keys: &[PrivateKey],
        ) -> anyhow::Result<(Output<PublicKey>, Vec<Share>)> {
            let info = Self::make_info(0, None, dealer_keys, player_keys);

            let mut logs = BTreeMap::new();
            for dk in dealer_keys {
                let signed =
                    deal::<N3f1>(rng, &info, dk, None).map_err(|e| anyhow::anyhow!("{e:?}"))?;
                let (pk, log) = signed
                    .identify()
                    .ok_or_else(|| anyhow::anyhow!("identify failed"))?;
                logs.insert(pk, log);
            }

            // Observe to get the public polynomial.
            let sharing = observe::<N3f1>(rng, &info, logs.clone(), &Sequential)
                .map_err(|e| anyhow::anyhow!("{e:?}"))?;

            // Each player plays to get their share.
            let mut shares = Vec::new();
            for pk in player_keys {
                let (_, share) = play::<N3f1>(rng, &info, logs.clone(), pk, &Sequential)
                    .map_err(|e| anyhow::anyhow!("{e:?}"))?;
                shares.push(share);
            }

            let dealers: Set<PublicKey> = dealer_keys
                .iter()
                .map(|k| k.public())
                .try_collect()
                .unwrap();
            let players: Set<PublicKey> = player_keys
                .iter()
                .map(|k| k.public())
                .try_collect()
                .unwrap();
            let output = Output {
                summary: info.summary,
                public: sharing,
                dealers,
                players: players.clone(),
                revealed: players,
            };
            Ok((output, shares))
        }

        pub fn run(self, seed: u64) -> anyhow::Result<()> {
            self.validate()?;
            let expect_failure = self.expect_failure();

            let mut rng = StdRng::seed_from_u64(seed);

            let dealer_keys: Vec<PrivateKey> = (0..self.num_dealers)
                .map(|_| PrivateKey::random(&mut rng))
                .collect();
            let player_keys: Vec<PrivateKey> = (0..self.num_players)
                .map(|_| PrivateKey::random(&mut rng))
                .collect();

            // If reshare, run an honest fresh round first where dealers == players.
            let (previous, previous_shares) = if self.reshare {
                let (output, shares) = Self::run_fresh(&mut rng, &dealer_keys, &dealer_keys)?;
                (Some(output), Some(shares))
            } else {
                (None, None)
            };

            let info = Self::make_info(
                if self.reshare { 1 } else { 0 },
                previous,
                &dealer_keys,
                &player_keys,
            );

            // Each dealer deals (with perturbations).
            let mut signed_logs: Vec<(u32, SignedDealerLog)> = Vec::new();
            for (i, dk) in dealer_keys.iter().enumerate() {
                let i = i as u32;
                if self.drop_dealers.contains(&i) {
                    continue;
                }

                let share = if self.reshare {
                    let shares = previous_shares.as_ref().unwrap();
                    if self.replace_shares.contains(&i) {
                        Some(Share::new(
                            shares[i as usize].index,
                            Private::new(Scalar::random(&mut rng)),
                        ))
                    } else {
                        Some(shares[i as usize].clone())
                    }
                } else {
                    None
                };

                // P5: shift polynomial degree
                //
                // Manually construct a dealing with a wrong-degree poly
                // evaluated at the correct player scalars. Because
                // golden_dkg has no explicit degree check, this dealing
                // passes Dealing::check() and gets selected -- the test
                // verifies this by NOT considering shift_degree dealers
                // as "bad".
                let mut signed = if let Some(&shift) = self.shift_degrees.get(&i) {
                    let current_degree = info.degree::<N3f1>();
                    let new_degree = (current_degree as i32 + shift).max(0) as u32;
                    if new_degree != current_degree {
                        let constant = info
                            .unwrap_or_random_share(
                                &mut rng,
                                share.as_ref().map(|s| s.private.clone().expose_unwrap()),
                            )
                            .expect("share should be available");
                        let poly = Poly::new_with_constant(&mut rng, new_degree, constant);
                        let nonce = Summary::random(&mut rng);
                        let (masks, commitments) =
                            dk.vrf_batch_checked(&nonce, info.players.iter().cloned());
                        let dealing = Dealing::reckon(&info, nonce, poly, masks)
                            .expect("reckon should succeed");
                        DealerLog {
                            dealing,
                            commitments,
                        }
                        .sign(dk)
                    } else {
                        deal::<N3f1>(&mut rng, &info, dk, share)
                            .map_err(|e| anyhow::anyhow!("{e:?}"))?
                    }
                } else {
                    deal::<N3f1>(&mut rng, &info, dk, share)
                        .map_err(|e| anyhow::anyhow!("{e:?}"))?
                };

                // P1: corrupt signature
                if self.bad_signatures.contains(&i) {
                    let mut sig_bytes = signed.signature.encode_mut();
                    sig_bytes[0] ^= 0xFF;
                    signed.signature = commonware_codec::ReadExt::read(&mut sig_bytes)
                        .expect("signature should decode");
                }

                signed_logs.push((i, signed));
            }

            // Identify (filter bad signatures) and collect logs.
            let mut logs = BTreeMap::new();
            for (i, signed) in signed_logs {
                if let Some((pk, mut log)) = signed.identify() {
                    // P2: corrupt masked shares
                    for &(d, p) in &self.bad_shares {
                        if d == i {
                            let player_pk = &player_keys[p as usize].public();
                            if let Some(share_val) =
                                log.dealing.masked_shares.get_value_mut(player_pk)
                            {
                                *share_val += &Scalar::random(&mut rng);
                            }
                        }
                    }

                    // P3: corrupt polynomial commitment
                    if self.bad_commitments.contains(&i) {
                        let corruption: Poly<Scalar> =
                            Poly::new(&mut rng, log.dealing.poly.degree());
                        log.dealing.poly += &Poly::commit(corruption);
                    }

                    // P4: remove player's share
                    for &(d, p) in &self.missing_shares {
                        if d == i {
                            let player_pk = player_keys[p as usize].public();
                            let new_shares: Map<PublicKey, Scalar> = log
                                .dealing
                                .masked_shares
                                .iter_pairs()
                                .filter(|(pk, _)| **pk != player_pk)
                                .map(|(pk, v)| (pk.clone(), v.clone()))
                                .try_collect()
                                .unwrap();
                            log.dealing.masked_shares = new_shares;
                        }
                    }

                    logs.insert(pk, log);
                }
                // If identify() returned None (bad sig), log is silently dropped.
            }

            // Run observe and play.
            let observe_result = observe::<N3f1>(&mut rng, &info, logs.clone(), &Sequential);
            let star_key = &player_keys[self.star as usize];
            let play_result = play::<N3f1>(&mut rng, &info, logs, star_key, &Sequential);

            if expect_failure {
                assert!(
                    observe_result.is_err() || play_result.is_err(),
                    "expected DkgFailed but both succeeded"
                );
                return Ok(());
            }

            let observe_sharing = observe_result.map_err(|e| anyhow::anyhow!("{e:?}"))?;
            let (play_sharing, share) = play_result.map_err(|e| anyhow::anyhow!("{e:?}"))?;

            // Verify observe and play produce the same public polynomial.
            assert_eq!(
                observe_sharing, play_sharing,
                "observe and play should produce the same public polynomial"
            );

            // Verify share matches public polynomial.
            let expected = play_sharing
                .partial_public(share.index)
                .map_err(|e| anyhow::anyhow!("{e:?}"))?;
            let actual = share.public::<MinPk>();
            assert_eq!(expected, actual, "share should match public polynomial");

            // In reshare, verify group public key is preserved.
            if self.reshare {
                let prev_public = info.previous.as_ref().unwrap().public().public();
                let new_public = play_sharing.public();
                assert_eq!(
                    prev_public, new_public,
                    "reshare should preserve group public key"
                );
            }

            Ok(())
        }
    }

    #[cfg(any(feature = "arbitrary", test))]
    impl<'a> arbitrary::Arbitrary<'a> for Plan {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            const MAX: u32 = 10;
            let num_dealers = u.int_in_range(1..=MAX)?;
            let num_players = u.int_in_range(1..=MAX)?;
            let star = u.int_in_range(0..=num_players - 1)?;
            let mut plan = Self::new(num_dealers, num_players, star);

            // Randomly apply perturbations.
            for d in 0..num_dealers {
                if u.ratio(1, 8)? {
                    plan.bad_signatures.insert(d);
                }
                if u.ratio(1, 8)? {
                    plan.bad_commitments.insert(d);
                }
                if u.ratio(1, 8)? {
                    plan.drop_dealers.insert(d);
                }
                if u.ratio(1, 10)? {
                    let shift = u.int_in_range(-2..=2i32)?;
                    if shift != 0 {
                        plan.shift_degrees.insert(d, shift);
                    }
                }
                for p in 0..num_players {
                    if u.ratio(1, 12)? {
                        plan.bad_shares.insert((d, p));
                    }
                    if u.ratio(1, 12)? {
                        plan.missing_shares.insert((d, p));
                    }
                }
            }

            // Optionally enable reshare.
            if u.ratio(1, 4)? {
                plan = plan.reshare();
                for d in 0..num_dealers {
                    if u.ratio(1, 6)? {
                        plan.replace_shares.insert(d);
                    }
                }
            }

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
    use super::{test_plan::Plan, *};
    use crate::bls12381::primitives::sharing::Mode;
    use commonware_codec::Encode;
    use commonware_invariants::minifuzz;
    use commonware_math::algebra::Random;
    use commonware_utils::N3f1;

    // Happy path tests

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

    // Perturbation tests

    #[test]
    fn bad_signature_filtered() {
        // 1 bad sig out of 4 dealers, DKG succeeds
        Plan::new(4, 7, 3)
            .bad_signature(0)
            .run(42)
            .expect("plan should succeed with 1 bad sig");
    }

    #[test]
    fn bad_signature_too_many() {
        // 3 bad sigs out of 4 dealers. quorum(4) = 3, so only 1 honest < 3.
        Plan::new(4, 7, 3)
            .bad_signature(0)
            .bad_signature(1)
            .bad_signature(2)
            .run(42)
            .expect("plan should handle expected failure");
    }

    #[test]
    fn bad_share_filtered() {
        // 1 dealer sends bad share, DKG succeeds
        Plan::new(4, 7, 3)
            .bad_share(0, 1)
            .run(42)
            .expect("plan should succeed with 1 bad share");
    }

    #[test]
    fn bad_share_too_many() {
        // 3 out of 4 dealers send bad shares. quorum(4) = 3, so only 1 honest < 3.
        Plan::new(4, 7, 3)
            .bad_share(0, 1)
            .bad_share(1, 2)
            .bad_share(2, 3)
            .run(42)
            .expect("plan should handle expected failure");
    }

    #[test]
    fn bad_commitment_filtered() {
        Plan::new(4, 7, 3)
            .bad_commitment(0)
            .run(42)
            .expect("plan should succeed with 1 bad commitment");
    }

    #[test]
    fn missing_share_filtered() {
        Plan::new(4, 7, 3)
            .missing_share(0, 1)
            .run(42)
            .expect("plan should succeed with 1 missing share");
    }

    #[test]
    fn shift_degree_filtered() {
        Plan::new(4, 7, 3)
            .shift_degree(0, 1)
            .run(42)
            .expect("plan should succeed with 1 wrong degree dealer filtered");
    }

    #[test]
    fn insufficient_dealers() {
        // Drop 3 out of 4 dealers. quorum(4) = 3, so only 1 < 3.
        Plan::new(4, 7, 3)
            .drop_dealer(0)
            .drop_dealer(1)
            .drop_dealer(2)
            .run(42)
            .expect("plan should handle expected failure");
    }

    // Reshare tests

    #[test]
    fn reshare_happy_path() {
        Plan::new(4, 7, 3)
            .reshare()
            .run(42)
            .expect("reshare should succeed");
    }

    #[test]
    fn reshare_replace_share_filtered() {
        Plan::new(4, 7, 3)
            .reshare()
            .replace_share(0)
            .run(42)
            .expect("reshare should succeed with 1 replaced share");
    }

    #[test]
    fn reshare_replace_share_fails() {
        // 3 out of 4 dealers use wrong previous share. quorum(4) = 3, only 1 honest.
        Plan::new(4, 7, 3)
            .reshare()
            .replace_share(0)
            .replace_share(1)
            .replace_share(2)
            .run(42)
            .expect("plan should handle expected failure");
    }

    // Error tests (standalone, outside Plan)

    #[test]
    fn unknown_dealer() {
        let mut rng = commonware_utils::test_rng();
        let dealer_keys: Vec<PrivateKey> = (0..4).map(|_| PrivateKey::random(&mut rng)).collect();
        let player_keys: Vec<PrivateKey> = (0..4).map(|_| PrivateKey::random(&mut rng)).collect();
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

        let info = Info {
            summary: crate::transcript::Summary::random(&mut rng),
            round: 0,
            previous: None,
            mode: Mode::default(),
            dealers: dealer_set,
            players: player_set,
        };

        let outsider = PrivateKey::random(&mut rng);
        let result = deal::<N3f1>(&mut rng, &info, &outsider, None);
        assert!(matches!(result, Err(Error::UnknownDealer(_))));
    }

    #[test]
    fn unknown_player() {
        let mut rng = commonware_utils::test_rng();
        let dealer_keys: Vec<PrivateKey> = (0..4).map(|_| PrivateKey::random(&mut rng)).collect();
        let player_keys: Vec<PrivateKey> = (0..4).map(|_| PrivateKey::random(&mut rng)).collect();
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

        let info = Info {
            summary: crate::transcript::Summary::random(&mut rng),
            round: 0,
            previous: None,
            mode: Mode::default(),
            dealers: dealer_set,
            players: player_set,
        };

        // Deal honestly, then try to play as an outsider.
        let mut logs = std::collections::BTreeMap::new();
        for dk in &dealer_keys {
            let signed = deal::<N3f1>(&mut rng, &info, dk, None).unwrap();
            let (pk, log) = signed.identify().unwrap();
            logs.insert(pk, log);
        }

        let outsider = PrivateKey::random(&mut rng);
        let result = play::<N3f1>(
            &mut rng,
            &info,
            logs,
            &outsider,
            &commonware_parallel::Sequential,
        );
        assert!(matches!(result, Err(Error::UnknownPlayer)));
    }

    #[test]
    fn missing_dealer_share_in_reshare() {
        let mut rng = commonware_utils::test_rng();
        let dealer_keys: Vec<PrivateKey> = (0..4).map(|_| PrivateKey::random(&mut rng)).collect();
        let player_keys: Vec<PrivateKey> = (0..4).map(|_| PrivateKey::random(&mut rng)).collect();

        // Run a fresh round to get an output.
        let (output, _shares) = Plan::run_fresh(&mut rng, &dealer_keys, &dealer_keys).unwrap();

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

        let summary = {
            let mut transcript = crate::transcript::Transcript::new(NAMESPACE);
            transcript
                .commit(1u64.encode())
                .commit(dealer_set.encode())
                .commit(player_set.encode());
            transcript.summarize()
        };

        let info = Info {
            summary,
            round: 1,
            previous: Some(output),
            mode: Mode::default(),
            dealers: dealer_set,
            players: player_set,
        };

        // Call deal with share: None in reshare mode -> MissingDealerShare
        let result = deal::<N3f1>(&mut rng, &info, &dealer_keys[0], None);
        assert!(matches!(result, Err(Error::MissingDealerShare)));
    }

    #[test]
    fn fuzz_plan() {
        minifuzz::test(|u| {
            let plan: Plan = u.arbitrary()?;
            let seed: u64 = u.arbitrary()?;
            plan.run(seed).expect("plan should not panic");
            Ok(())
        });
    }
}
