use super::primitives::group::Share;
use crate::{
    bls12381::primitives::{
        group::{Element, Scalar},
        ops::msm_interpolate,
        poly::{self, new_with_constant, Eval, Poly, Public, Weight},
        variant::Variant,
    },
    transcript::{Summary, Transcript},
    Digest, PrivateKey, PublicKey,
};
use commonware_codec::{Encode, EncodeSize, RangeCfg, Read, ReadExt, Write};
use commonware_utils::{
    max_faults, quorum,
    set::{Ordered, OrderedAssociated},
};
use rand_core::CryptoRngCore;
use std::collections::BTreeMap;
use thiserror::Error;

/// Recover public polynomial by interpolating coefficient-wise all
/// polynomials using precomputed Barycentric Weights.
///
/// It is assumed that the required number of commitments are provided.
pub fn recover_public_with_weights<V: Variant>(
    commitments: &BTreeMap<u32, poly::Public<V>>,
    weights: &BTreeMap<u32, poly::Weight>,
    threshold: u32,
) -> poly::Public<V> {
    // Perform interpolation over each coefficient using the precomputed weights
    (0..threshold)
        .into_iter()
        .map(|coeff| {
            // Extract evaluations for this coefficient from all commitments
            let evals = commitments
                .iter()
                .map(|(dealer, commitment)| poly::Eval {
                    index: *dealer,
                    value: commitment.get(coeff),
                })
                .collect::<Vec<_>>();

            // Use precomputed weights for interpolation
            msm_interpolate(weights, &evals).expect("interpolation should not fail")
        })
        .collect()
}

const NAMESPACE: &[u8] = b"commonware-bls12381-dkg";

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output<V: Variant, P> {
    hash: Summary,
    players: Ordered<P>,
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

    /// Return the players who participated in this round of the DKG, and should have shares.
    pub fn players(&self) -> &Ordered<P> {
        &self.players
    }
}

impl<V: Variant, P: PublicKey> EncodeSize for Output<V, P> {
    fn encode_size(&self) -> usize {
        self.hash.encode_size() + self.players.encode_size() + self.public.encode_size()
    }
}

impl<V: Variant, P: PublicKey> Write for Output<V, P> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.hash.write(buf);
        self.players.write(buf);
        self.public.write(buf);
    }
}

impl<V: Variant, P: PublicKey> Read for Output<V, P> {
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        &max_players: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            hash: ReadExt::read(buf)?,
            players: Read::read_cfg(buf, &(RangeCfg::new(0..=max_players), ()))?,
            public: Read::read_cfg(buf, &max_players)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RoundInfo<V: Variant, P: PublicKey> {
    round: u64,
    previous: Option<Output<V, P>>,
    dealers: Ordered<P>,
    players: Ordered<P>,
    /// Never written when encoded, always computed from the previous fields.
    hash: Summary,
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

    fn threshold(&self) -> u32 {
        self.degree() + 1
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
        round: u64,
        previous: Option<Output<V, P>>,
        dealers: Ordered<P>,
        players: Ordered<P>,
    ) -> Result<Self, Error> {
        assert!(dealers.len() <= u32::MAX as usize);
        assert!(players.len() <= u32::MAX as usize);
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
        let hash = Transcript::new(NAMESPACE)
            .commit(round.encode())
            .commit(previous.encode())
            .commit(dealers.encode())
            .commit(players.encode())
            .summarize();
        Ok(Self {
            round,
            previous,
            dealers,
            players,
            hash,
        })
    }

    /// Return the `usize` governing the size of reads.
    ///
    /// This will need to be passed to various structs when reading them from
    /// bytes, to avoid allocating buffers that are too large for the round.
    pub fn max_read_size(&self) -> usize {
        // This isn't as tight as it could be, but provides a nice upper bound
        // for various things, like polynomial sizes, messages, etc.
        self.players.len() + self.dealers.len()
    }

    /// Return the round number for this round.
    ///
    /// Round numbers should increase sequentially.
    pub fn round(&self) -> u64 {
        self.round
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

impl<V: Variant, P: PublicKey> Read for RoundInfo<V, P> {
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        &max_players: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self::new(
            ReadExt::read(buf)?,
            Read::read_cfg(buf, &max_players)?,
            Read::read_cfg(buf, &(RangeCfg::new(0..=max_players), ()))?,
            Read::read_cfg(buf, &(RangeCfg::new(0..=max_players), ()))?,
        )
        .map_err(|_| commonware_codec::Error::Invalid("RoundInfo", "validation"))?)
    }
}

#[derive(Clone, Debug)]
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

impl<V: Variant> Read for DealerPubMsg<V> {
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            commitment: Read::read_cfg(buf, cfg)?,
        })
    }
}

#[derive(Clone)]
pub struct DealerPrivMsg {
    share: Scalar,
}

impl std::fmt::Debug for DealerPrivMsg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DealerPrivMsg(REDACTED)")
    }
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

impl Read for DealerPrivMsg {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            share: Read::read_cfg(buf, cfg)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct PlayerAck<P: PublicKey> {
    sig: P::Signature,
}

impl<P: PublicKey> EncodeSize for PlayerAck<P> {
    fn encode_size(&self) -> usize {
        self.sig.encode_size()
    }
}

impl<P: PublicKey> Write for PlayerAck<P> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.sig.write(buf);
    }
}

impl<P: PublicKey> Read for PlayerAck<P> {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            sig: ReadExt::read(buf)?,
        })
    }
}

#[derive(Clone)]
enum AckOrReveal<P: PublicKey> {
    Ack(PlayerAck<P>),
    Reveal(Scalar),
}

impl<P: PublicKey> std::fmt::Debug for AckOrReveal<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AckOrReveal::Ack(x) => write!(f, "Ack({:?})", x),
            AckOrReveal::Reveal(_) => write!(f, "Reveal(REDACTED)"),
        }
    }
}

impl<P: PublicKey> EncodeSize for AckOrReveal<P> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Ack(x) => x.encode_size(),
            Self::Reveal(x) => x.encode_size(),
        }
    }
}

impl<P: PublicKey> Write for AckOrReveal<P> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Ack(x) => {
                1u8.write(buf);
                x.write(buf);
            }
            Self::Reveal(x) => {
                2u8.write(buf);
                x.write(buf);
            }
        }
    }
}

impl<P: PublicKey> Read for AckOrReveal<P> {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let tag = u8::read(buf)?;
        match tag {
            1 => Ok(Self::Ack(ReadExt::read(buf)?)),
            2 => Ok(Self::Reveal(ReadExt::read(buf)?)),
            x => Err(commonware_codec::Error::InvalidEnum(x)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DealerLog<V: Variant, P: PublicKey> {
    pub_msg: DealerPubMsg<V>,
    results: Vec<AckOrReveal<P>>,
}

impl<V: Variant, P: PublicKey> EncodeSize for DealerLog<V, P> {
    fn encode_size(&self) -> usize {
        self.pub_msg.encode_size() + self.results.encode_size()
    }
}

impl<V: Variant, P: PublicKey> Write for DealerLog<V, P> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.pub_msg.write(buf);
        self.results.write(buf);
    }
}

impl<V: Variant, P: PublicKey> Read for DealerLog<V, P> {
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        &max_players: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            pub_msg: Read::read_cfg(buf, &max_players)?,
            results: Read::read_cfg(buf, &(RangeCfg::from(0..=max_players), ()))?,
        })
    }
}

impl<V: Variant, P: PublicKey> DealerLog<V, P> {
    fn zip_players<'a, 'b>(
        &'a self,
        players: &'b Ordered<P>,
    ) -> Option<impl Iterator<Item = (&'b P, &'a AckOrReveal<P>)>> {
        if self.results.len() != players.len() {
            return None;
        }
        Some(players.iter().zip(self.results.iter()))
    }
}

#[derive(Clone, Debug)]
pub struct SignedDealerLog<V: Variant, S: PrivateKey> {
    dealer: S::PublicKey,
    log: DealerLog<V, S::PublicKey>,
    sig: S::Signature,
}

impl<V: Variant, S: PrivateKey> SignedDealerLog<V, S> {
    fn sign(
        sk: &S,
        round_info: &RoundInfo<V, S::PublicKey>,
        log: DealerLog<V, S::PublicKey>,
    ) -> Self {
        let sig = transcript_for_round(round_info).sign(sk);
        Self {
            dealer: sk.public_key(),
            log,
            sig,
        }
    }

    pub fn check(
        self,
        round_info: &RoundInfo<V, S::PublicKey>,
    ) -> Option<(S::PublicKey, DealerLog<V, S::PublicKey>)> {
        if !transcript_for_round(round_info).verify(&self.dealer, &self.sig) {
            return None;
        }
        Some((self.dealer, self.log))
    }
}

impl<V: Variant, S: PrivateKey> EncodeSize for SignedDealerLog<V, S> {
    fn encode_size(&self) -> usize {
        self.dealer.encode_size() + self.log.encode_size() + self.sig.encode_size()
    }
}
impl<V: Variant, S: PrivateKey> Write for SignedDealerLog<V, S> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.dealer.write(buf);
        self.log.write(buf);
        self.sig.write(buf);
    }
}

impl<V: Variant, S: PrivateKey> Read for SignedDealerLog<V, S> {
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            dealer: ReadExt::read(buf)?,
            log: Read::read_cfg(buf, cfg)?,
            sig: ReadExt::read(buf)?,
        })
    }
}

fn transcript_for_round<V: Variant, P: PublicKey>(round_info: &RoundInfo<V, P>) -> Transcript {
    Transcript::resume(round_info.hash)
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

pub struct Dealer<V: Variant, S: PrivateKey> {
    me: S,
    round_info: RoundInfo<V, S::PublicKey>,
    pub_msg: DealerPubMsg<V>,
    results: Vec<AckOrReveal<S::PublicKey>>,
    transcript: Transcript,
}

impl<V: Variant, S: PrivateKey> Dealer<V, S> {
    pub fn start(
        mut rng: impl CryptoRngCore,
        round_info: RoundInfo<V, S::PublicKey>,
        me: S,
        share: Option<Share>,
    ) -> Result<(Self, DealerPubMsg<V>, Vec<(S::PublicKey, DealerPrivMsg)>), Error> {
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
            transcript_for_dealer(&t, &me.public_key(), &pub_msg)
        };
        let this = Self {
            me,
            round_info,
            pub_msg: pub_msg.clone(),
            results,
            transcript,
        };
        Ok((this, pub_msg, priv_msgs))
    }

    pub fn receive_player_ack(
        &mut self,
        player: S::PublicKey,
        ack: PlayerAck<S::PublicKey>,
    ) -> Result<(), Error> {
        let index = self.round_info.player_index(&player)?;
        if self.transcript.verify(&player, &ack.sig) {
            self.results[index as usize] = AckOrReveal::Ack(ack);
        }
        Ok(())
    }

    pub fn finalize(self) -> SignedDealerLog<V, S> {
        let log = DealerLog {
            pub_msg: self.pub_msg,
            results: self.results,
        };
        SignedDealerLog::sign(&self.me, &self.round_info, log)
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
            if !round_info.check_dealer_commitment(&dealer, &log.pub_msg.commitment) {
                return None;
            }
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
        let (public, weights) = if let Some(previous) = round_info.previous.as_ref() {
            let weights =
                poly::compute_weights(indices).expect("should be able to compute weights");
            let public =
                recover_public_with_weights::<V>(&commitments, &weights, round_info.threshold());
            if previous.public().constant() != public.constant() {
                return Err(Error::DkgFailed);
            }
            (public, Some(weights))
        } else {
            let mut public = Poly::zero();
            for c in commitments.values() {
                public.add(c);
            }
            (public, None)
        };
        let output = Output {
            hash: round_info.hash,
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
        if self.view.contains_key(&dealer) {
            return None;
        }
        self.round_info.dealer_index(&dealer).ok()?;
        if pub_msg.commitment.degree() != self.round_info.degree() {
            return None;
        }
        if pub_msg.commitment.evaluate(self.index).value != priv_msg.expected_element() {
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

/// Simply distribute shares at random, instead of performing a distributed protocol.
pub fn deal<V: Variant, P: PublicKey>(
    mut rng: impl CryptoRngCore,
    players: impl IntoIterator<Item = P>,
) -> (Output<V, P>, OrderedAssociated<P, Share>) {
    let players = Ordered::from_iter(players.into_iter());
    let t = quorum(players.len() as u32);
    let private = poly::new_from(t - 1, &mut rng);
    let shares: OrderedAssociated<_, _> = players
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let eval = private.evaluate(i as u32);
            let share = Share {
                index: eval.index,
                private: eval.value,
            };
            (p.clone(), share)
        })
        .collect();
    let output = Output {
        hash: Summary::random(&mut rng),
        players,
        public: Poly::commit(private),
    };
    (output, shares)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        bls12381::primitives::{
            ops::{partial_sign_message, partial_verify_message, threshold_signature_recover},
            variant::MinSig,
        },
        ed25519, Signer as _,
    };
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    const MAX_IDENTITIES: u32 = 1000;

    #[derive(Clone)]
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

    impl From<Vec<Round>> for Plan {
        fn from(rounds: Vec<Round>) -> Self {
            Self { rounds }
        }
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
                    .collect::<Ordered<_>>();
                let player_set = round
                    .players
                    .iter()
                    .map(|&idx| keys[&idx].public_key())
                    .collect::<Ordered<_>>();

                let round_info = RoundInfo::<MinSig, ed25519::PublicKey>::new(
                    round_idx as u64,
                    std::mem::take(&mut previous_output),
                    dealer_set.clone(),
                    player_set.clone(),
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
                    let dealer_priv = keys[&dealer_idx].clone();
                    let dealer_pub = dealer_priv.public_key();
                    // Get share from previous round if this dealer was a player
                    let share = shares.get(&dealer_pub).cloned();
                    let (mut dealer, pub_msg, priv_msgs) =
                        Dealer::<MinSig, ed25519::PrivateKey>::start(
                            &mut rng,
                            round_info.clone(),
                            dealer_priv.clone(),
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

                    let (dealer_pub, checked_log) = dealer
                        .finalize()
                        .check(&round_info)
                        .expect("check should succeed");
                    log.insert(dealer_pub, checked_log);
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

                    // Verify the share matches the public polynomial
                    let expected_public = observer_output.public.evaluate(share.index);
                    let actual_public = {
                        let mut g = <MinSig as Variant>::Public::one();
                        g.mul(&share.private);
                        g
                    };
                    assert_eq!(expected_public.value, actual_public);

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
        Plan::from(vec![Round::from((vec![0, 1, 2, 3], vec![0, 1, 2, 3]))]).run_with_seed(0);
    }

    #[test]
    fn test_dkg2_multiple_rounds() {
        Plan::from(vec![Round::from((vec![0, 1, 2, 3], vec![0, 1, 2, 3])); 4]).run_with_seed(0);
    }

    #[test]
    fn test_dkg2_changing_committee() {
        Plan::from(vec![
            Round::from((vec![0, 1, 2], vec![1, 2, 3])),
            Round::from((vec![1, 2, 3], vec![2, 3, 4])),
            Round::from((vec![2, 3, 4], vec![0, 1, 2])),
            Round::from((vec![0, 1, 2], vec![0, 1, 2])),
        ])
        .run_with_seed(0);
    }

    #[test]
    fn test_dkg2_increasing_committee() {
        Plan::from(vec![
            Round::from((vec![0, 1], vec![0, 1, 2])),
            Round::from((vec![0, 1, 2], vec![0, 1, 2, 3])),
            Round::from((vec![0, 1, 2, 3], vec![0, 1, 2, 3, 4])),
        ])
        .run_with_seed(0);
    }
}
