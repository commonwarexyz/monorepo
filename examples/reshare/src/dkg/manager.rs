//! A manager for a DKG/reshare round.

use crate::{
    application::Block,
    dkg::{DealOutcome, Dkg, Payload, OUTCOME_NAMESPACE},
};
use commonware_codec::{Decode, Encode};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    bls12381::{
        dkg::{
            player::Output,
            types::{Ack, Share},
            Arbiter, Dealer, Player,
        },
        primitives::{group, poly::Public, variant::Variant},
    },
    Hasher, Signer, Verifier,
};
use commonware_p2p::{
    utils::mux::{MuxHandle, SubReceiver, SubSender},
    Receiver, Recipients, Sender,
};
use futures::FutureExt;
use rand_core::CryptoRngCore;
use std::{collections::BTreeMap, ops::Deref};
use tracing::{debug, error, info, warn};

/// The signature namespace for DKG acknowledgment messages.
const ACK_NAMESPACE: &[u8] = b"COMMONWARE_DKG_ACK";

/// The concurrency level for DKG/reshare operations.
const CONCURRENCY: usize = 1;

/// A manager for a DKG/reshare round.
///
/// Exposes functionality:
/// - Distribute a [Dealer]'s shares
/// - Process incoming shares and acknowledgements from other [Dealer]s and [Player]s.
/// - Create a [DealOutcome] from the current state, for inclusion in a [Block].
/// - Process [Block]s that may contain a [DealOutcome].
/// - Finalize the DKG/reshare round, returning the resulting [Output].
pub struct DkgManager<'ctx, V, P, S, R>
where
    V: Variant,
    P: Signer,
    S: Sender<PublicKey = P::PublicKey>,
    R: Receiver<PublicKey = P::PublicKey>,
{
    /// The local signer.
    signer: &'ctx mut P,

    /// The previous group polynomial and (if dealing) share.
    previous: RoundResult<V>,

    /// The players in the round.
    players: Vec<P::PublicKey>,

    /// The outbound communication channel for peers.
    sender: SubSender<S>,

    /// The inbound communication channel for peers.
    receiver: SubReceiver<R>,

    /// [Dealer] metadata, if this manager is also dealing.
    dealer_meta: Option<DealerMetadata<P, V>>,

    /// The local [Player] for this round, if the manager is playing.
    player: Option<(u32, Player<P::PublicKey, V>)>,

    /// The local [Arbiter] for this round.
    arbiter: Arbiter<P::PublicKey, V>,
}

/// Metadata associated with a [Dealer].
struct DealerMetadata<P: Signer, V: Variant> {
    /// The [Dealer] object.
    dealer: Dealer<P::PublicKey, V>,
    /// The [Dealer]'s commitment.
    commitment: Public<V>,
    /// The [Dealer]'s shares for all players.
    shares: Vec<group::Share>,
    /// Signed acknowledgements from contributors.
    acks: BTreeMap<u32, Ack<P::Signature>>,
    /// The constructed dealing for inclusion in a block, if any.
    outcome: Option<DealOutcome<P, V>>,
}

/// A result of a DKG/reshare round.
pub enum RoundResult<V: Variant> {
    /// The new group polynomial, if the manager is not a [Player].
    Polynomial(Public<V>),
    /// The new group polynomial and the local share, if the manager is a [Player].
    Output(Output<V>),
}

impl<'ctx, V, P, S, R> DkgManager<'ctx, V, P, S, R>
where
    V: Variant,
    P: Signer,
    S: Sender<PublicKey = P::PublicKey>,
    R: Receiver<PublicKey = P::PublicKey>,
{
    /// Create a new DKG/reshare manager.
    ///
    /// # Panics
    ///
    /// Panics if the signer is not in the list of contributors or if the sub-channel for the current
    /// epoch could not be registered.
    #[allow(clippy::too_many_arguments)]
    pub async fn init<E: CryptoRngCore>(
        context: &mut E,
        epoch: Epoch,
        public: Public<V>,
        share: Option<group::Share>,
        signer: &'ctx mut P,
        dealers: Vec<P::PublicKey>,
        players: Vec<P::PublicKey>,
        mux: &'ctx mut MuxHandle<S, R>,
    ) -> Self {
        let dealer_meta = share.as_ref().map(|share| {
            let (dealer, commitment, shares) =
                Dealer::new(context, Some(share.clone()), players.to_vec());
            DealerMetadata {
                dealer,
                commitment,
                shares,
                acks: BTreeMap::new(),
                outcome: None,
            }
        });
        let player = players
            .iter()
            .position(|p| p == &signer.public_key())
            .map(|signer_index| {
                let player = Player::new(
                    signer.public_key(),
                    Some(public.clone()),
                    dealers.to_vec(),
                    players.to_vec(),
                    CONCURRENCY,
                );

                (signer_index as u32, player)
            });
        let arbiter = Arbiter::new(
            Some(public.clone()),
            dealers.to_vec(),
            players.to_vec(),
            CONCURRENCY,
        );

        let (s, r) = mux.register(epoch as u32).await.unwrap();

        Self {
            signer,
            previous: share.map_or(RoundResult::Polynomial(public.clone()), |share| {
                RoundResult::Output(Output { public, share })
            }),
            players,
            sender: s,
            receiver: r,
            dealer_meta,
            player,
            arbiter,
        }
    }

    /// Distribute the [Dealer]'s 'shares to all contributors that have not yet acknowledged receipt of their share.
    pub async fn distribute(&mut self, round: u64) {
        // Only attempt distribution if the manager is also a dealer.
        let Some(DealerMetadata {
            dealer,
            commitment,
            shares,
            acks,
            ..
        }) = &mut self.dealer_meta
        else {
            return;
        };

        // Find all contributors that need to be sent a share by filtering out those that have
        // not yet acknowledged receipt of their share.
        let needs_broadcast = self
            .players
            .iter()
            .enumerate()
            .filter(|(i, _)| !acks.contains_key(&(*i as u32)))
            .collect::<Vec<_>>();

        for (idx, contributor) in needs_broadcast {
            let share = shares.get(idx).cloned().unwrap();

            if let Some((signer_index, ref mut player)) = self.player {
                if idx == signer_index as usize {
                    player
                        .share(self.signer.public_key(), commitment.deref().clone(), share)
                        .unwrap();
                    dealer.ack(self.signer.public_key()).unwrap();

                    let ack = Ack::new::<_, V>(
                        ACK_NAMESPACE,
                        self.signer,
                        signer_index,
                        round,
                        &self.signer.public_key(),
                        commitment,
                    );
                    acks.insert(signer_index, ack);
                    continue;
                }
            }

            let payload =
                Payload::<V, P::Signature>::Share(Share::new(commitment.deref().clone(), share))
                    .into_message(round);
            let success = self
                .sender
                .send(
                    Recipients::One(contributor.clone()),
                    payload.encode().freeze(),
                    true,
                )
                .await
                .expect("could not send share");

            if success.is_empty() {
                warn!(round, player = ?contributor, "failed to send share");
            } else {
                info!(round, player = ?contributor, "sent share");
            }
        }
    }

    /// Processes all available messages from the [Receiver], handling both incoming shares and
    /// acknowledgements. Once the [Receiver] needs to wait for more messages, this function
    /// yields back to the caller.
    pub async fn process_messages(&mut self, round: u64) {
        while let Some(msg) = self.receiver.recv().now_or_never() {
            let (peer, msg) = msg.expect("receiver closed");

            let msg =
                Dkg::<V, P::Signature>::decode_cfg(&mut msg.as_ref(), &(self.players.len() as u32))
                    .unwrap();
            if msg.round != round {
                warn!(
                    round,
                    msg_round = msg.round,
                    "ignoring message for different round"
                );
                return;
            }

            match msg.payload {
                Payload::Ack(ack) => {
                    let Some(DealerMetadata {
                        acks,
                        dealer,
                        commitment,
                        ..
                    }) = &mut self.dealer_meta
                    else {
                        warn!(round, "ignoring ack; not a dealer");
                        return;
                    };

                    // Verify index matches
                    let Some(player) = self.players.get(ack.player as usize) else {
                        warn!(round, index = ack.player, "invalid ack index");
                        return;
                    };

                    if player != &peer {
                        warn!(round, index = ack.player, "mismatched ack index");
                        return;
                    }

                    // Verify signature on incoming ack
                    if !ack.verify::<V, _>(
                        ACK_NAMESPACE,
                        &peer,
                        round,
                        &self.signer.public_key(),
                        commitment,
                    ) {
                        warn!(round, index = ack.player, "invalid ack signature");
                        return;
                    }

                    // Store ack
                    if let Err(e) = dealer.ack(peer) {
                        debug!(round, index = ack.player, error = ?e, "failed to store ack");
                        return;
                    }
                    info!(round, index = ack.player, "stored ack");

                    acks.insert(ack.player, ack);
                }
                Payload::Share(Share { commitment, share }) => {
                    let Some((signer_index, ref mut player)) = self.player else {
                        warn!(round, "ignoring share; not a player");
                        return;
                    };

                    // Store share
                    if let Err(e) = player.share(peer.clone(), commitment.clone(), share) {
                        debug!(round, error = ?e, "failed to store share");
                        return;
                    }

                    // Send ack
                    let payload = Payload::<V, P::Signature>::Ack(Ack::new::<_, V>(
                        ACK_NAMESPACE,
                        self.signer,
                        signer_index,
                        round,
                        &peer,
                        &commitment,
                    ))
                    .into_message(round);
                    self.sender
                        .send(
                            Recipients::One(peer.clone()),
                            payload.encode().freeze(),
                            true,
                        )
                        .await
                        .expect("could not send ack");

                    info!(round, player = ?peer, "sent ack");
                }
            }
        }
    }

    /// Processes a [Block] that may contain a [DealOutcome], tracking it with the [Arbiter] if
    /// all acknowledgement signatures are valid.
    pub async fn process_block(&mut self, round: u64, block: Block<impl Hasher, P, V>) {
        let Some(outcome) = block.reshare_outcome else {
            debug!(height = block.height, "saw block with no deal outcome");
            return;
        };

        // Ensure the outcome is for the current round.
        if outcome.round != round {
            warn!(
                outcome_round = outcome.round,
                round, "outcome round does not match current round"
            );
            return;
        }

        // Verify the dealer's signature before considering processing the outcome.
        let outcome_payload = outcome.signature_payload();
        if !outcome.dealer.verify(
            Some(OUTCOME_NAMESPACE),
            &outcome_payload,
            &outcome.dealer_signature,
        ) {
            warn!(round, "invalid dealer signature; ignoring deal outcome");
        }

        // Verify all ack signatures
        if !outcome.acks.iter().all(|ack| {
            self.players
                .get(ack.player as usize)
                .map(|public_key| {
                    ack.verify::<V, _>(
                        ACK_NAMESPACE,
                        public_key,
                        round,
                        &outcome.dealer,
                        &outcome.commitment,
                    )
                })
                .unwrap_or(false)
        }) {
            warn!(round, "invalid ack signatures; disqualifying dealer");
            self.arbiter.disqualify(outcome.dealer.clone());
            return;
        }

        // Check dealer commitment
        let ack_indices = outcome
            .acks
            .iter()
            .map(|ack| ack.player)
            .collect::<Vec<_>>();
        if let Err(e) = self.arbiter.commitment(
            outcome.dealer,
            outcome.commitment,
            ack_indices,
            outcome.reveals,
        ) {
            warn!(round, error = ?e, "failed to track dealer outcome in arbiter");
        }

        info!(
            round,
            height = block.height,
            "processed deal outcome from block"
        );
    }

    /// Finalize the DKG/reshare round, returning the [Output].
    pub async fn finalize(self, round: u64) -> (Vec<P::PublicKey>, RoundResult<V>) {
        let (result, disqualified) = self.arbiter.finalize();
        let result = match result {
            Ok(output) => output,
            Err(e) => {
                error!(error = ?e, "failed to finalize arbiter; aborting round");
                return (self.players, self.previous);
            }
        };

        match self.player {
            Some((signer_index, player)) => {
                let commitments = result.commitments.into_iter().collect::<BTreeMap<_, _>>();
                let reveals = result
                    .reveals
                    .into_iter()
                    .filter_map(|(dealer_idx, shares)| {
                        shares
                            .iter()
                            .find(|s| s.index == signer_index)
                            .cloned()
                            .map(|share| (dealer_idx, share))
                    })
                    .collect::<BTreeMap<_, _>>();

                let n_commitments = commitments.len();
                let n_reveals = reveals.len();

                let output = match player.finalize(commitments, reveals) {
                    Ok(output) => output,
                    Err(e) => {
                        error!(error = ?e, "failed to finalize player; aborting round");
                        return (self.players, self.previous);
                    }
                };

                info!(
                    round,
                    ?disqualified,
                    n_commitments,
                    n_reveals,
                    "finalized DKG/reshare round"
                );

                (self.players, RoundResult::Output(output))
            }
            None => (self.players, RoundResult::Polynomial(result.public)),
        }
    }

    /// Instantiate the [DealOutcome] from the current state of the manager.
    pub fn construct_deal_outcome(&mut self, round: u64) {
        // Only attempt to construct a deal outcome if the manager is also a dealer.
        let Some(DealerMetadata {
            commitment,
            shares,
            acks,
            outcome,
            ..
        }) = &mut self.dealer_meta
        else {
            return;
        };

        let reveals = (0..self.players.len() as u32)
            .filter_map(|i| {
                (!acks.contains_key(&i))
                    .then(|| shares.get(i as usize).cloned())
                    .flatten()
            })
            .collect::<Vec<_>>();

        *outcome = Some(DealOutcome::new(
            self.signer,
            round,
            commitment.deref().clone(),
            acks.values().cloned().collect(),
            reveals,
        ));
    }

    /// Returns the [DealOutcome] for inclusion in a block, if one has been processed.
    pub fn take_deal_outcome(&mut self) -> Option<DealOutcome<P, V>> {
        self.dealer_meta
            .as_mut()
            .and_then(|meta| meta.outcome.take())
    }
}
