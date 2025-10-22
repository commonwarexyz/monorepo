use crate::{
    bls12381::{
        dkg::ops::recover_public_with_weights,
        primitives::{
            group::{Element, Scalar},
            poly::{self, new_with_constant, Eval, Poly, Public, Weight},
            variant::Variant,
        },
    },
    transcript::Transcript,
    PrivateKey, PublicKey,
};
use commonware_codec::{Encode, EncodeSize, Write};
use commonware_utils::{max_faults, quorum, set::Set};
use rand_core::CryptoRngCore;
use std::collections::BTreeMap;
use thiserror::Error;

use super::primitives::group::Share;

const NAMESPACE: &[u8] = b"commonware-bls12381-dkg";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output<V: Variant, P> {
    round: u32,
    players: Set<P>,
    public: Public<V>,
}

impl<V: Variant, P: PublicKey> Output<V, P> {
    fn share_commitment(&self, player: &P) -> Option<V::Public> {
        let index = self.players.position(player)?;
        Some(self.public.evaluate(index as u32).value)
    }

    pub fn quorum(&self) -> u32 {
        quorum(self.players.len() as u32)
    }

    /// Get the public polynomial associated with this output.
    ///
    /// This is useful to verify partial signatures, with [crate::bls12381::primitives::ops::partial_verify_message].
    pub fn public(&self) -> &Public<V> {
        &self.public
    }
}

impl<V: Variant, P: PublicKey> EncodeSize for Output<V, P> {
    fn encode_size(&self) -> usize {
        self.round.encode_size() + self.players.encode_size() + self.public.encode_size()
    }
}

impl<V: Variant, P: PublicKey> Write for Output<V, P> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.round.write(buf);
        self.players.write(buf);
        self.public.write(buf);
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("missing dealer's share from the previous round")]
    MissingDealerShare,
    #[error("player is not present in the list of players")]
    UnknownPlayer,
    #[error("dealer is not present in the previous list of players")]
    UnknownDealer,
    #[error("dkg failed for some reason")]
    DkgFailed,
    #[error("not enough dealers: {0}")]
    InsufficientDealers(usize),
}

#[derive(Clone)]
pub struct RoundInfo<V: Variant, P: PublicKey> {
    round: u32,
    previous: Option<Output<V, P>>,
    dealers: Set<P>,
    players: Set<P>,
}

impl<V: Variant, P: PublicKey> RoundInfo<V, P> {
    /// Figure out what the dealer share should be.
    ///
    /// If there's no previous round, we need a random value, hence `rng`.
    ///
    /// However, if there is a previous round, we expect a share, hence `Result`.
    fn dealer_share(
        &self,
        mut rng: impl CryptoRngCore,
        share: Option<Scalar>,
    ) -> Result<Scalar, Error> {
        let out = match (self.previous.as_ref(), share) {
            (None, None) => Scalar::from_rand(&mut rng),
            (_, Some(x)) => x,
            (Some(_), None) => return Err(Error::MissingDealerShare),
        };
        Ok(out)
    }

    fn degree(&self) -> u32 {
        quorum(self.players.len() as u32).saturating_sub(1)
    }

    fn required_commitments(&self) -> u32 {
        let dealer_quorum = quorum(self.dealers.len() as u32);
        let prev_quorum = self
            .previous
            .as_ref()
            .map(Output::quorum)
            .unwrap_or(u32::MIN);
        dealer_quorum.max(prev_quorum)
    }

    fn max_reveals(&self) -> u32 {
        max_faults(self.players.len() as u32)
    }

    fn player_index(&self, player: &P) -> Result<u32, Error> {
        self.players
            .position(player)
            .map(|x| x as u32)
            .ok_or(Error::UnknownPlayer)
    }

    fn dealer_index(&self, dealer: &P) -> Result<u32, Error> {
        self.dealers
            .position(dealer)
            .map(|x| x as u32)
            .ok_or(Error::UnknownPlayer)
    }

    #[must_use]
    fn check_dealer_commitment(&self, dealer: &P, commitment: &Public<V>) -> bool {
        if self.degree() != commitment.degree() {
            return false;
        }
        if let Some(previous) = self.previous.as_ref() {
            let Some(share_commitment) = previous.share_commitment(dealer) else {
                return false;
            };
            if *commitment.constant() != share_commitment {
                return false;
            }
        }
        true
    }
}

impl<V: Variant, P: PublicKey> RoundInfo<V, P> {
    pub fn new(
        previous: Option<Output<V, P>>,
        dealers: Set<P>,
        players: Set<P>,
    ) -> Result<Self, Error> {
        assert!(dealers.len() <= u32::MAX as usize);
        assert!(players.len() <= u32::MAX as usize);
        let round = if let Some(previous) = previous.as_ref() {
            previous.round + 1
        } else {
            0
        };
        if let Some(previous) = previous.as_ref() {
            if dealers
                .iter()
                .any(|d| previous.players.position(d).is_none())
            {
                return Err(Error::UnknownDealer);
            }
            if dealers.len() < previous.quorum() as usize {
                return Err(Error::InsufficientDealers(dealers.len()));
            }
        }
        Ok(Self {
            round,
            previous,
            dealers,
            players,
        })
    }
}

impl<V: Variant, P: PublicKey> EncodeSize for RoundInfo<V, P> {
    fn encode_size(&self) -> usize {
        self.round.encode_size()
            + self.previous.encode_size()
            + self.dealers.encode_size()
            + self.players.encode_size()
    }
}

impl<V: Variant, P: PublicKey> Write for RoundInfo<V, P> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.round.write(buf);
        self.previous.write(buf);
        self.dealers.write(buf);
        self.players.write(buf);
    }
}

#[derive(Clone)]
enum AckOrReveal<P: PublicKey> {
    Ack(PlayerAck<P>),
    Reveal(Scalar),
}

#[derive(Clone)]
pub struct DealerLog<V: Variant, P: PublicKey> {
    pub_msg: DealerPubMsg<V>,
    results: Vec<AckOrReveal<P>>,
}

impl<V: Variant, P: PublicKey> DealerLog<V, P> {
    fn zip_players<'a, 'b>(
        &'a self,
        players: &'b Set<P>,
    ) -> Option<impl Iterator<Item = (&'b P, &'a AckOrReveal<P>)>> {
        if self.results.len() != players.len() {
            return None;
        }
        Some(players.iter().zip(self.results.iter()))
    }
}

fn select<V: Variant, P: PublicKey>(
    round_info: &RoundInfo<V, P>,
    logs: BTreeMap<P, DealerLog<V, P>>,
) -> Result<Vec<(P, DealerLog<V, P>)>, Error> {
    let required_commitments = round_info.required_commitments() as usize;
    let transcript = transcript_for_round(round_info);
    let out = logs
        .into_iter()
        .filter_map(|(dealer, log)| {
            let results_iter = log.zip_players(&round_info.players)?;
            let transcript = transcript_for_dealer(&transcript, &dealer, &log.pub_msg);
            let (acks_good, reveal_count) = results_iter.fold(
                (true, 0u32),
                |(acks_good, reveal_count), (player, result)| match result {
                    AckOrReveal::Ack(ack) => (
                        acks_good && transcript.verify(player, &ack.sig),
                        reveal_count,
                    ),
                    AckOrReveal::Reveal(_) => (acks_good, reveal_count + 1),
                },
            );
            if !acks_good || reveal_count > round_info.max_reveals() {
                return None;
            }
            Some((dealer, log))
        })
        .take(required_commitments)
        .collect::<Vec<_>>();
    if out.len() < required_commitments {
        return Err(Error::DkgFailed);
    }
    Ok(out)
}

struct ObserveInner<V: Variant, P: PublicKey> {
    output: Output<V, P>,
    weights: Option<BTreeMap<u32, Weight>>,
}

impl<V: Variant, P: PublicKey> ObserveInner<V, P> {
    fn reckon(
        round_info: RoundInfo<V, P>,
        selected: Vec<(P, DealerLog<V, P>)>,
    ) -> Result<Self, Error> {
        let commitments = selected
            .iter()
            .filter_map(|(dealer, log)| {
                let index = round_info.dealer_index(dealer).ok()?;
                Some((index, log.pub_msg.commitment.clone()))
            })
            .collect::<BTreeMap<_, _>>();
        let indices = selected
            .into_iter()
            .map(|(dealer, _log)| {
                round_info
                    .dealer_index(&dealer)
                    .expect("select checks that dealer exists, via our signature")
            })
            .collect::<Vec<_>>();
        let (public, weights) = if let Some(previous) = round_info.previous {
            let weights =
                poly::compute_weights(indices).expect("should be able to compute weights");
            let public = recover_public_with_weights::<V>(
                &previous.public,
                &commitments,
                &weights,
                quorum(previous.players.len() as u32),
                1,
            )
            .expect("should be able to recover group");
            (public, Some(weights))
        } else {
            let mut public = Poly::zero();
            for c in commitments.values() {
                public.add(c);
            }
            (public, None)
        };
        let output = Output {
            round: round_info.round + 1,
            players: round_info.players,
            public,
        };
        Ok(Self { output, weights })
    }
}

pub fn observe<V: Variant, P: PublicKey>(
    round_info: RoundInfo<V, P>,
    logs: BTreeMap<P, DealerLog<V, P>>,
) -> Result<Output<V, P>, Error> {
    let selected = select(&round_info, logs)?;
    ObserveInner::<V, P>::reckon(round_info, selected).map(|x| x.output)
}

#[derive(Clone)]
pub struct DealerPubMsg<V: Variant> {
    commitment: Public<V>,
}

impl<V: Variant> EncodeSize for DealerPubMsg<V> {
    fn encode_size(&self) -> usize {
        self.commitment.encode_size()
    }
}

impl<V: Variant> Write for DealerPubMsg<V> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.commitment.write(buf);
    }
}

#[derive(Clone)]
pub struct DealerPrivMsg {
    share: Scalar,
}

impl DealerPrivMsg {
    fn expected_element<E: Element>(&self) -> E {
        let mut out = E::one();
        out.mul(&self.share);
        out
    }
}

impl EncodeSize for DealerPrivMsg {
    fn encode_size(&self) -> usize {
        self.share.encode_size()
    }
}

impl Write for DealerPrivMsg {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.share.write(buf);
    }
}

#[derive(Clone)]
pub struct PlayerAck<P: PublicKey> {
    sig: P::Signature,
}

fn transcript_for_round<V: Variant, P: PublicKey>(round_info: &RoundInfo<V, P>) -> Transcript {
    let mut transcript = Transcript::new(NAMESPACE);
    transcript.commit(round_info.encode());
    transcript
}

fn transcript_for_dealer<V: Variant, P: PublicKey>(
    transcript: &Transcript,
    dealer: &P,
    pub_msg: &DealerPubMsg<V>,
) -> Transcript {
    let mut out = transcript.fork(b"dealer");
    out.commit(dealer.encode());
    out.commit(pub_msg.encode());
    out
}

pub struct Player<V: Variant, S: PrivateKey> {
    me: S,
    round_info: RoundInfo<V, S::PublicKey>,
    index: u32,
    transcript: Transcript,
    view: BTreeMap<S::PublicKey, (DealerPubMsg<V>, DealerPrivMsg)>,
}

impl<V: Variant, S: PrivateKey> Player<V, S> {
    pub fn new(round_info: RoundInfo<V, S::PublicKey>, me: S) -> Result<Self, Error> {
        Ok(Self {
            index: round_info.player_index(&me.public_key())?,
            me,
            transcript: transcript_for_round(&round_info),
            round_info,
            view: BTreeMap::new(),
        })
    }

    pub fn dealer_message(
        &mut self,
        dealer: S::PublicKey,
        pub_msg: DealerPubMsg<V>,
        priv_msg: DealerPrivMsg,
    ) -> Option<PlayerAck<S::PublicKey>> {
        self.round_info.dealer_index(&dealer).ok()?;
        if pub_msg.commitment.degree() != self.round_info.degree() {
            return None;
        }
        if pub_msg.commitment.evaluate(self.index).value != priv_msg.expected_element() {
            return None;
        }
        if !self
            .round_info
            .check_dealer_commitment(&dealer, &pub_msg.commitment)
        {
            return None;
        }
        let sig = transcript_for_dealer(&self.transcript, &dealer, &pub_msg).sign(&self.me);
        self.view.insert(dealer, (pub_msg, priv_msg));
        Some(PlayerAck { sig })
    }

    pub fn finalize(
        self,
        logs: BTreeMap<S::PublicKey, DealerLog<V, S::PublicKey>>,
    ) -> Result<(Output<V, S::PublicKey>, Share), Error> {
        let selected = select(&self.round_info, logs)?;
        let dealings = selected
            .iter()
            .map(|(dealer, log)| {
                let index = self
                    .round_info
                    .dealer_index(&dealer)
                    .expect("select checks that dealer exists, via our signature");
                let share = self
                    .view
                    .get(&dealer)
                    .map(|(_, priv_msg)| priv_msg.share.clone())
                    .unwrap_or_else(|| match log.results.get(self.index as usize) {
                        Some(AckOrReveal::Reveal(share)) => share.clone(),
                        _ => {
                            panic!("select didn't check dealer reveal, or we're not a player?")
                        }
                    });
                Eval {
                    index,
                    value: share,
                }
            })
            .collect::<Vec<_>>();
        let ObserveInner { output, weights } =
            ObserveInner::<V, S::PublicKey>::reckon(self.round_info, selected)?;
        let private = if let Some(weights) = weights {
            poly::Private::recover_with_weights(&weights, dealings.iter())
                .expect("should be able to recover share")
        } else {
            let mut out = Scalar::zero();
            for s in dealings {
                out.add(&s.value);
            }
            out
        };
        let share = Share {
            index: self.index,
            private,
        };
        Ok((output, share))
    }
}

pub struct Dealer<V: Variant, P: PublicKey> {
    round_info: RoundInfo<V, P>,
    pub_msg: DealerPubMsg<V>,
    results: Vec<AckOrReveal<P>>,
    transcript: Transcript,
}

impl<V: Variant, P: PublicKey> Dealer<V, P> {
    pub fn start(
        mut rng: impl CryptoRngCore,
        round_info: RoundInfo<V, P>,
        me: P,
        share: Option<Share>,
    ) -> Result<(Self, DealerPubMsg<V>, Vec<(P, DealerPrivMsg)>), Error> {
        let share = round_info.dealer_share(&mut rng, share.map(|x| x.private))?;
        let my_poly = new_with_constant(round_info.degree(), &mut rng, share.clone());
        let reveals = round_info
            .players
            .iter()
            .enumerate()
            .map(|(i, pk)| (pk.clone(), my_poly.evaluate(i as u32).value))
            .collect::<BTreeMap<_, _>>();
        let results = reveals
            .values()
            .cloned()
            .map(AckOrReveal::Reveal)
            .collect::<Vec<_>>();
        let priv_msgs = reveals
            .iter()
            .map(|(pk, share)| {
                (
                    pk.clone(),
                    DealerPrivMsg {
                        share: share.clone(),
                    },
                )
            })
            .collect::<Vec<_>>();
        let commitment = Poly::commit(my_poly);
        let pub_msg = DealerPubMsg { commitment };
        let transcript = {
            let t = transcript_for_round(&round_info);
            transcript_for_dealer(&t, &me, &pub_msg)
        };
        let this = Self {
            round_info,
            pub_msg: pub_msg.clone(),
            results,
            transcript,
        };
        Ok((this, pub_msg, priv_msgs))
    }

    pub fn receive_player_ack(&mut self, player: P, ack: PlayerAck<P>) -> Result<(), Error> {
        let index = self.round_info.player_index(&player)?;
        if self.transcript.verify(&player, &ack.sig) {
            self.results[index as usize] = AckOrReveal::Ack(ack);
        }
        Ok(())
    }

    pub fn finalize(self) -> DealerLog<V, P> {
        DealerLog {
            pub_msg: self.pub_msg,
            results: self.results,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ed25519;
    use crate::{
        bls12381::primitives::{
            ops::{partial_sign_message, partial_verify_message, threshold_signature_recover},
            variant::MinSig,
        },
        Signer as _,
    };
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    const MAX_IDENTITIES: u32 = 1000;

    struct Round {
        dealers: Vec<u32>,
        players: Vec<u32>,
    }

    impl From<(Vec<u32>, Vec<u32>)> for Round {
        fn from((dealers, players): (Vec<u32>, Vec<u32>)) -> Self {
            Self { dealers, players }
        }
    }

    struct Plan {
        rounds: Vec<Round>,
    }

    impl Plan {
        fn run_with_seed(self, seed: u64) {
            // Create a single RNG from the seed
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            // 1. Figure out the maximum index between dealers and players across all rounds.
            // Also, check that the dealers in round N + 1 are players in round N.
            let max_index = self
                .rounds
                .iter()
                .map(|round| {
                    round
                        .dealers
                        .iter()
                        .copied()
                        .chain(round.players.iter().copied())
                        .max()
                        .unwrap_or_default()
                })
                .max()
                .unwrap_or_default();
            // 2. Make sure this is a reasonable value (<= MAX_IDENTITIES).
            assert!(max_index <= MAX_IDENTITIES, "too many players for test",);
            let mut previous_output: Option<Output<MinSig, ed25519::PublicKey>> = None;
            let mut shares: BTreeMap<ed25519::PublicKey, Share> = BTreeMap::new();

            // 3. Generate the Ed25519 keys for each index, using the RNG.
            let mut keys = BTreeMap::new();
            for i in 0..=max_index {
                let signing_key = ed25519_consensus::SigningKey::new(&mut rng);
                let private_key = ed25519::PrivateKey::from(signing_key);
                keys.insert(i, private_key);
            }

            // 4. For each round, run the DKG, using, if necessary the previous output.
            for (round_idx, round) in self.rounds.into_iter().enumerate() {
                // 4.1 Create round info.
                let dealer_set = round
                    .dealers
                    .iter()
                    .map(|&idx| keys[&idx].public_key())
                    .collect::<Set<_>>();
                let player_set = round
                    .players
                    .iter()
                    .map(|&idx| keys[&idx].public_key())
                    .collect::<Set<_>>();

                let round_info = RoundInfo::<MinSig, ed25519::PublicKey>::new(
                    std::mem::take(&mut previous_output),
                    dealer_set,
                    player_set,
                )
                .expect("Failed to create round info");

                // 4.2 Initialize players
                let mut players = BTreeMap::new();
                for &player_idx in &round.players {
                    let player = Player::<MinSig, ed25519::PrivateKey>::new(
                        round_info.clone(),
                        keys[&player_idx].clone(),
                    )
                    .expect("Failed to create player");
                    players.insert(keys[&player_idx].public_key(), player);
                }

                // 4.3 For each dealer:
                let mut log = BTreeMap::new();

                for dealer_idx in &round.dealers {
                    // 4.3.1 Generate the messages intended for the other players
                    let dealer_pub = keys[&dealer_idx].public_key();
                    // Get share from previous round if this dealer was a player
                    let share = shares.get(&dealer_pub).cloned();
                    let (mut dealer, pub_msg, priv_msgs) =
                        Dealer::<MinSig, ed25519::PublicKey>::start(
                            &mut rng,
                            round_info.clone(),
                            dealer_pub.clone(),
                            share,
                        )
                        .expect("Failed to start dealer");

                    // 4.3.2 Have each player process the message, and the dealer process the ack.
                    for (player_id, priv_msg) in priv_msgs {
                        let player = players.get_mut(&player_id).expect("player should exist");
                        let ack = player
                            .dealer_message(dealer_pub.clone(), pub_msg.clone(), priv_msg)
                            .expect("player should ack valid dealer message");
                        dealer
                            .receive_player_ack(player_id, ack)
                            .expect("should be able to accept ack");
                    }

                    log.insert(dealer_pub, dealer.finalize());
                }

                // 4.5 Run the observer to get an output.
                let observer_output =
                    observe::<MinSig, ed25519::PublicKey>(round_info.clone(), log.clone())
                        .expect("Observer failed");

                // 4.6 Finalize each player, checking that its output is the same as the observer,
                // and remember its shares.
                let mut player_ids = Vec::with_capacity(players.len());
                for (player_id, player) in players {
                    let (player_output, share) = player
                        .finalize(log.clone())
                        .expect("Player finalize failed");

                    // Check that player output matches observer output
                    assert_eq!(player_output, observer_output);

                    shares.insert(player_id.clone(), share);
                    player_ids.push(player_id)
                }

                // 4.7 Generate a signature, by using each player's share, and then recover a group signature.
                //
                let test_message = format!("test message {}", round_idx).into_bytes();
                let namespace = Some(&b"test"[..]);

                // Create partial signatures from each player's share
                let mut partial_sigs = Vec::new();
                for player_id in player_ids {
                    let share = &shares[&player_id];
                    let partial_sig =
                        partial_sign_message::<MinSig>(share, namespace, &test_message);

                    // Verify partial signature
                    partial_verify_message::<MinSig>(
                        &observer_output.public,
                        namespace,
                        &test_message,
                        &partial_sig,
                    )
                    .expect("Partial signature verification failed");

                    partial_sigs.push(partial_sig);
                }

                // Recover threshold signature
                let threshold = observer_output.quorum();
                let threshold_sig = threshold_signature_recover::<MinSig, _>(
                    threshold,
                    &partial_sigs[0..threshold as usize],
                )
                .expect("Failed to recover threshold signature");

                // 4.8 Check this signature
                let threshold_public = poly::public::<MinSig>(&observer_output.public());
                crate::bls12381::primitives::ops::verify_message::<MinSig>(
                    &threshold_public,
                    namespace,
                    &test_message,
                    &threshold_sig,
                )
                .expect("Threshold signature verification failed");

                // Update state for next round
                previous_output = Some(observer_output);
            }
        }
    }

    #[test]
    fn test_dkg2_single_round() {
        let plan = Plan {
            rounds: vec![Round::from((vec![0, 1, 2], vec![0, 1, 2, 3, 4]))],
        };
        plan.run_with_seed(42);
    }

    #[test]
    fn test_dkg2_multiple_rounds() {
        let plan = Plan {
            rounds: vec![
                Round::from((vec![0, 1], vec![0, 1, 2])),
                Round::from((vec![0, 1, 2], vec![0, 1, 2, 3])),
            ],
        };
        plan.run_with_seed(42);
    }
}
