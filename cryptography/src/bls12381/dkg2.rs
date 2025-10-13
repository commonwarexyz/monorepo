use crate::{
    bls12381::{
        dkg::ops::recover_public_with_weights,
        primitives::{
            group::{Element, Scalar},
            poly::{self, new_with_constant, Eval, Poly},
            variant::Variant,
        },
    },
    transcript::Transcript,
    PrivateKey, PublicKey,
};
use commonware_codec::{Encode, EncodeSize, Write};
use rand_core::CryptoRngCore;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const NAMESPACE: &[u8] = b"commonware-bls12381-dkg";

/// Assign indices to the unique elements of a collection, in order.
fn assign_indices<T: Ord>(data: impl Iterator<Item = T>) -> BTreeMap<T, u32> {
    let set = data.collect::<BTreeSet<_>>();
    set.into_iter()
        .enumerate()
        .map(|(i, x)| (x, u32::try_from(i).expect("failed to convert index to u32")))
        .collect()
}

pub struct Output<E, P> {
    round: u32,
    players: BTreeMap<P, u32>,
    group_commitment: Poly<E>,
    faults: u32,
}

impl<E: Element, P: PublicKey> Output<E, P> {
    fn share_commitment(&self, player: &P) -> Option<E> {
        let &index = self.players.get(player)?;
        Some(self.group_commitment.evaluate(index).value)
    }
}

impl<E: Element, P: PublicKey> EncodeSize for Output<E, P> {
    fn encode_size(&self) -> usize {
        self.round.encode_size()
            + self.players.encode_size()
            + self.group_commitment.encode_size()
            + self.faults.encode_size()
    }
}

impl<E: Element, P: PublicKey> Write for Output<E, P> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.round.write(buf);
        self.players.write(buf);
        self.group_commitment.write(buf);
        self.faults.write(buf);
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
    #[error("not enough players: {0}")]
    InsufficientPlayers(usize),
    #[error("not enough dealers: {0}")]
    InsufficientDealers(usize),
}

pub struct RoundInfo<E, P: PublicKey> {
    round: u32,
    previous: Option<Output<E, P>>,
    dealers: BTreeMap<P, u32>,
    players: BTreeMap<P, u32>,
    faults: u32,
}

impl<E: Element, P: PublicKey> RoundInfo<E, P> {
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
        2 * self.faults
    }

    fn required_commitments(&self) -> u32 {
        2 * self.faults + 1
    }

    fn max_reveals(&self) -> u32 {
        self.faults
    }

    fn player_index(&self, player: &P) -> Result<u32, Error> {
        self.players
            .get(player)
            .copied()
            .ok_or(Error::UnknownPlayer)
    }

    fn dealer_index(&self, dealer: &P) -> Result<u32, Error> {
        self.dealers
            .get(dealer)
            .copied()
            .ok_or(Error::UnknownPlayer)
    }

    #[must_use]
    fn check_dealer_commitment(&self, dealer: &P, commitment: &Poly<E>) -> bool {
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

impl<E, P: PublicKey> RoundInfo<E, P> {
    pub fn new(
        previous: Option<Output<E, P>>,
        dealers: &[P],
        players: &[P],
        faults: u32,
    ) -> Result<Self, Error> {
        let round = if let Some(previous) = previous.as_ref() {
            previous.round + 1
        } else {
            0
        };
        if let Some(previous) = previous.as_ref() {
            if dealers.iter().any(|d| !previous.players.contains_key(d)) {
                return Err(Error::UnknownDealer);
            }
            if dealers.len() < (2 * faults + 1) as usize {
                return Err(Error::InsufficientDealers(dealers.len()));
            }
        }
        if players.len() < (3 * faults + 1) as usize {
            return Err(Error::InsufficientPlayers(players.len()));
        }
        Ok(Self {
            round,
            previous,
            dealers: assign_indices(dealers.iter().cloned()),
            players: assign_indices(players.iter().cloned()),
            faults,
        })
    }
}

impl<E: Element, P: PublicKey> EncodeSize for RoundInfo<E, P> {
    fn encode_size(&self) -> usize {
        self.round.encode_size()
            + self.previous.encode_size()
            + self.dealers.encode_size()
            + self.players.encode_size()
            + self.faults.encode_size()
    }
}

impl<E: Element, P: PublicKey> Write for RoundInfo<E, P> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.round.write(buf);
        self.previous.write(buf);
        self.dealers.write(buf);
        self.players.write(buf);
        self.faults.write(buf);
    }
}

pub struct DealerLog<E, P: PublicKey> {
    pub_msg: DealerPubMsg<E>,
    acks: BTreeMap<P, PlayerAck<P>>,
    reveals: BTreeMap<P, Scalar>,
}

fn select<E: Element, P: PublicKey>(
    logs: &BTreeMap<P, DealerLog<E, P>>,
    round_info: &RoundInfo<E, P>,
) -> Option<Vec<P>> {
    let required_commitments = round_info.required_commitments() as usize;
    let mut out = Vec::with_capacity(required_commitments);
    let transcript = transcript_for_round(round_info);
    'outer: for (dealer, log) in logs {
        if out.len() >= required_commitments {
            break;
        }
        if !round_info.dealers.contains_key(dealer) {
            continue;
        }
        if log.reveals.len() > round_info.max_reveals() as usize {
            continue 'outer;
        }
        for player in round_info.players.keys() {
            // Each player must either have acked, or been revealed.
            //
            // Not present in either: bad news.
            // Present in both: bad news.
            if log.acks.contains_key(player) == log.reveals.contains_key(player) {
                continue 'outer;
            }
        }
        let transcript = transcript_for_dealer(&transcript, dealer, &log.pub_msg);
        for (player, ack) in &log.acks {
            if !transcript.verify(player, &ack.sig) {
                continue 'outer;
            }
        }
        out.push(dealer.clone());
    }
    if out.len() >= required_commitments {
        out.truncate(required_commitments);
        Some(out)
    } else {
        None
    }
}

#[derive(Clone)]
pub struct DealerPubMsg<E> {
    commitment: Poly<E>,
}

impl<E: Element> EncodeSize for DealerPubMsg<E> {
    fn encode_size(&self) -> usize {
        self.commitment.encode_size()
    }
}

impl<E: Element> Write for DealerPubMsg<E> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.commitment.write(buf);
    }
}

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

pub struct PlayerAck<P: PublicKey> {
    sig: P::Signature,
}

fn transcript_for_round<E: Element, P: PublicKey>(round_info: &RoundInfo<E, P>) -> Transcript {
    let mut transcript = Transcript::new(NAMESPACE);
    transcript.commit(round_info.encode());
    transcript
}

fn transcript_for_dealer<P: PublicKey, E: Element>(
    transcript: &Transcript,
    dealer: &P,
    pub_msg: &DealerPubMsg<E>,
) -> Transcript {
    let mut out = transcript.fork(b"dealer");
    out.commit(dealer.encode());
    out.commit(pub_msg.encode());
    out
}

pub struct Player<V: Variant, S: PrivateKey> {
    me: S,
    round_info: RoundInfo<V::Public, S::PublicKey>,
    index: u32,
    transcript: Transcript,
    view: BTreeMap<S::PublicKey, (DealerPubMsg<V::Public>, DealerPrivMsg)>,
}

impl<V: Variant, S: PrivateKey> Player<V, S> {
    pub fn new(round_info: RoundInfo<V::Public, S::PublicKey>, me: S) -> Result<Self, Error> {
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
        pub_msg: DealerPubMsg<V::Public>,
        priv_msg: DealerPrivMsg,
    ) -> Option<PlayerAck<S::PublicKey>> {
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
        logs: BTreeMap<S::PublicKey, DealerLog<V::Public, S::PublicKey>>,
    ) -> Result<(Scalar, Output<V::Public, S::PublicKey>), Error> {
        let dealers = select(&logs, &self.round_info).ok_or(Error::DkgFailed)?;
        let commitments = dealers
            .iter()
            .filter_map(|dealer| {
                let index = self.round_info.dealer_index(&dealer).ok()?;
                let log = logs.get(dealer)?;
                Some((index, log.pub_msg.commitment.clone()))
            })
            .collect::<BTreeMap<_, _>>();
        let (indices, dealings) = dealers
            .into_iter()
            .map(|dealer| {
                let index = self
                    .round_info
                    .dealer_index(&dealer)
                    .expect("select checks that dealer exists");
                let share = self
                    .view
                    .get(&dealer)
                    .map(|(_, priv_msg)| priv_msg.share.clone())
                    .unwrap_or_else(|| {
                        logs.get(&dealer)
                            .expect("select takes dealer from log")
                            .reveals
                            .get(&self.me.public_key())
                            .expect("select checks that dealer revealed")
                            .clone()
                    });
                (
                    index,
                    Eval {
                        index,
                        value: share,
                    },
                )
            })
            .collect::<(Vec<_>, Vec<_>)>();
        let (public, share) = if let Some(previous) = self.round_info.previous {
            let weights =
                poly::compute_weights(indices).expect("should be able to compute weights");
            let public = recover_public_with_weights::<V>(
                &previous.group_commitment,
                &commitments,
                &weights,
                2 * previous.faults + 1,
                1,
            )
            .expect("should be able to recover group");
            let share = poly::Private::recover_with_weights(&weights, dealings.iter())
                .expect("should be able to recover share");
            (public, share)
        } else {
            let mut public = Poly::zero();
            let mut share = Scalar::zero();
            for c in commitments.values() {
                public.add(c);
            }
            for s in dealings {
                share.add(&s.value);
            }
            (public, share)
        };

        let output = Output {
            round: self.round_info.round + 1,
            players: self.round_info.players,
            group_commitment: public,
            faults: self.round_info.faults,
        };
        Ok((share, output))
    }
}

pub struct Dealer<E, P: PublicKey> {
    share: Scalar,
    round_info: RoundInfo<E, P>,
    pub_msg: DealerPubMsg<E>,
    reveals: BTreeMap<P, Scalar>,
    acks: BTreeMap<P, PlayerAck<P>>,
    transcript: Transcript,
}

impl<E: Element, P: PublicKey> Dealer<E, P> {
    pub fn start(
        mut rng: impl CryptoRngCore,
        round_info: RoundInfo<E, P>,
        me: P,
        share: Option<Scalar>,
    ) -> Result<(Self, DealerPubMsg<E>, Vec<(P, DealerPrivMsg)>), Error> {
        let share = round_info.dealer_share(&mut rng, share)?;
        let my_poly = new_with_constant(round_info.degree(), &mut rng, share.clone());
        let reveals = round_info
            .players
            .iter()
            .map(|(pk, &i)| (pk.clone(), my_poly.evaluate(i).value))
            .collect::<BTreeMap<_, _>>();
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
            share,
            round_info,
            pub_msg: pub_msg.clone(),
            reveals,
            acks: BTreeMap::new(),
            transcript,
        };
        Ok((this, pub_msg, priv_msgs))
    }

    pub fn receive_player_ack(&mut self, player: P, ack: PlayerAck<P>) {
        if self.transcript.verify(&player, &ack.sig) {
            self.reveals.remove(&player);
            self.acks.insert(player, ack);
        }
    }

    pub fn finalize(self) -> DealerLog<E, P> {
        DealerLog {
            pub_msg: self.pub_msg,
            acks: self.acks,
            reveals: self.reveals,
        }
    }
}
