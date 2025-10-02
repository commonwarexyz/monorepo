//! A manager for a DKG/reshare round.

use crate::{
    application::Block,
    dkg::{DealOutcome, Dkg, Payload, OUTCOME_NAMESPACE},
};
use commonware_codec::{Decode, Encode, EncodeSize, FixedSize, Write};
use commonware_cryptography::{
    bls12381::{
        dkg::{player::Output, Arbiter, Dealer, Player},
        primitives::{group::Share, poly::Public, variant::Variant},
    },
    Hasher, PrivateKey, PublicKey, Verifier,
};
use commonware_p2p::{Receiver, Recipients, Sender};
use futures::FutureExt;
use rand_core::CryptoRngCore;
use std::collections::HashMap;
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
    P: PrivateKey,
    S: Sender<PublicKey = P::PublicKey>,
    R: Receiver<PublicKey = P::PublicKey>,
{
    /// The local signer.
    signer: &'ctx mut P,

    /// The index of the local signer in the contributors list.
    signer_index: usize,

    /// The previous group polynomial and share.
    previous: Output<V>,

    /// The contributors to the round.
    contributors: &'ctx [P::PublicKey],

    /// The outbound communication channel for peers.
    sender: &'ctx mut S,

    /// The inbound communication channel for peers.
    receiver: &'ctx mut R,

    /// The local dealer for this round.
    dealer: Dealer<P::PublicKey, V>,

    /// The dealer's commitment.
    commitment: Public<V>,

    /// The dealer's shares for all players.
    shares: Vec<Share>,

    /// The local player for this round.
    player: Player<P::PublicKey, V>,

    /// The local arbiter for this round.
    arbiter: Arbiter<P::PublicKey, V>,

    /// Signed acknowledgements from contributors.
    acks: HashMap<u32, P::Signature>,

    /// The deal outcome constructed from this manager's state, if any.
    deal_outcome: Option<DealOutcome<P, V>>,
}

impl<'ctx, V, P, S, R> DkgManager<'ctx, V, P, S, R>
where
    V: Variant,
    P: PrivateKey,
    S: Sender<PublicKey = P::PublicKey>,
    R: Receiver<PublicKey = P::PublicKey>,
{
    /// Create a new DKG/reshare manager.
    ///
    /// # Panics
    ///
    /// Panics if the signer is not in the list of contributors.
    pub fn new<E: CryptoRngCore>(
        context: &mut E,
        public: Public<V>,
        share: Share,
        signer: &'ctx mut P,
        contributors: &'ctx [P::PublicKey],
        sender: &'ctx mut S,
        receiver: &'ctx mut R,
    ) -> Self {
        let signer_index = contributors
            .iter()
            .position(|pk| pk == &signer.public_key())
            .expect("signer must be in contributors");

        let (dealer, commitment, shares) =
            Dealer::new(context, Some(share.clone()), contributors.to_vec());
        let player = Player::new(
            signer.public_key(),
            Some(public.clone()),
            contributors.to_vec(),
            contributors.to_vec(),
            CONCURRENCY,
        );
        let arbiter = Arbiter::new(
            Some(public.clone()),
            contributors.to_vec(),
            contributors.to_vec(),
            CONCURRENCY,
        );

        Self {
            signer,
            signer_index,
            previous: Output { public, share },
            contributors,
            sender,
            receiver,
            dealer,
            commitment,
            shares,
            player,
            arbiter,
            acks: HashMap::new(),
            deal_outcome: None,
        }
    }

    /// Distribute the [Dealer]'s 'shares to all contributors that have not yet acknowledged receipt of their share.
    pub async fn distribute(&mut self, round: u64) {
        // Find all contributors that need to be sent a share by filtering out those that have
        // not yet acknowledged receipt of their share.
        let needs_broadcast = self
            .contributors
            .iter()
            .enumerate()
            .filter(|(i, _)| !self.acks.contains_key(&(*i as u32)))
            .collect::<Vec<_>>();

        for (idx, contributor) in needs_broadcast {
            let share = self.shares.get(idx).cloned().unwrap();

            if idx == self.signer_index {
                self.player
                    .share(self.signer.public_key(), self.commitment.clone(), share)
                    .unwrap();
                self.dealer.ack(self.signer.public_key()).unwrap();

                let payload = ack_payload::<V, P::PublicKey>(
                    round,
                    &self.signer.public_key(),
                    &self.commitment,
                );
                let signature = self.signer.sign(Some(ACK_NAMESPACE), &payload);
                self.acks.insert(self.signer_index as u32, signature);
                continue;
            }

            let payload: Dkg<V, P::Signature> = Dkg {
                round,
                payload: Payload::Share {
                    commitment: self.commitment.clone(),
                    share,
                },
            };
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
                Dkg::<V, P::Signature>::decode_cfg(&mut msg.as_ref(), &self.contributors.len())
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
                Payload::Ack {
                    public_key,
                    signature,
                } => {
                    // Verify index matches
                    let Some(player) = self.contributors.get(public_key as usize) else {
                        warn!(round, index = public_key, "invalid ack index");
                        return;
                    };

                    if player != &peer {
                        warn!(round, index = public_key, "mismatched ack index");
                        return;
                    }

                    // Verify signature on incoming ack
                    let payload = ack_payload::<V, P::PublicKey>(
                        round,
                        &self.signer.public_key(),
                        &self.commitment,
                    );
                    if !peer.verify(Some(ACK_NAMESPACE), &payload, &signature) {
                        warn!(round, index = public_key, "invalid ack signature");
                        return;
                    }

                    // Store ack
                    if let Err(e) = self.dealer.ack(peer) {
                        debug!(round, index = public_key, error = ?e, "failed to store ack");
                        return;
                    }
                    self.acks.insert(public_key, signature);

                    info!(round, index = public_key, "stored ack");
                }
                Payload::Share { commitment, share } => {
                    // Store share
                    if let Err(e) = self.player.share(peer.clone(), commitment.clone(), share) {
                        debug!(round, error = ?e, "failed to store share");
                        return;
                    }

                    // Send ack
                    let payload = ack_payload::<V, P::PublicKey>(round, &peer, &commitment);
                    let signature = self.signer.sign(Some(ACK_NAMESPACE), &payload);
                    let ack: Dkg<V, P::Signature> = Dkg {
                        round,
                        payload: Payload::Ack {
                            public_key: self.signer_index as u32,
                            signature,
                        },
                    };

                    self.sender
                        .send(Recipients::One(peer.clone()), ack.encode().freeze(), true)
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
        let payload = ack_payload::<V, P::PublicKey>(round, &outcome.dealer, &outcome.commitment);
        if !outcome.acks.iter().all(|(i, sig)| {
            self.contributors
                .get(*i as usize)
                .map(|public_key| public_key.verify(Some(ACK_NAMESPACE), &payload, sig))
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
            .map(|(i, _)| i)
            .copied()
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
    pub async fn finalize(self, round: u64) -> Output<V> {
        let (result, disqualified) = self.arbiter.finalize();
        let result = match result {
            Ok(output) => output,
            Err(e) => {
                error!(error = ?e, "failed to finalize arbiter; aborting round");
                return self.previous;
            }
        };

        let commitments = result.commitments.into_iter().collect::<HashMap<_, _>>();
        let reveals = result
            .reveals
            .into_iter()
            .filter_map(|(dealer_idx, shares)| {
                shares
                    .iter()
                    .find(|s| s.index == self.signer_index as u32)
                    .cloned()
                    .map(|share| (dealer_idx, share))
            })
            .collect::<HashMap<_, _>>();

        let n_commitments = commitments.len();
        let n_reveals = reveals.len();

        let output = match self.player.finalize(commitments, reveals) {
            Ok(output) => output,
            Err(e) => {
                error!(error = ?e, "failed to finalize player; aborting round");
                return self.previous;
            }
        };

        info!(
            round,
            ?disqualified,
            n_commitments,
            n_reveals,
            "finalized DKG/reshare round"
        );

        output
    }

    /// Instantiate the [DealOutcome] from the current state of the manager.
    pub fn construct_deal_outcome(&mut self, round: u64) {
        let reveals = (0..self.contributors.len() as u32)
            .filter_map(|i| {
                (!self.acks.contains_key(&i))
                    .then(|| self.shares.get(i as usize).cloned())
                    .flatten()
            })
            .collect::<Vec<_>>();

        self.deal_outcome = Some(DealOutcome::new(
            self.signer,
            round,
            self.commitment.clone(),
            self.acks.clone().into_iter().collect::<Vec<_>>(),
            reveals,
        ));
    }

    /// Returns the [DealOutcome] for inclusion in a block, if one has been processed.
    pub fn take_deal_outcome(&mut self) -> Option<DealOutcome<P, V>> {
        self.deal_outcome.take()
    }
}

/// Create a payload for acking a secret.
fn ack_payload<V: Variant, P: PublicKey>(
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
