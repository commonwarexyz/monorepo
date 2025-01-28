use super::{Config, Mailbox, Message};
use crate::{
    linked::{encoder, prover::Prover, wire, Context, Epoch},
    Application, Collector, Error, ThresholdCoordinator,
};
use bytes::Bytes;
use commonware_cryptography::{
    bls12381::primitives::{
        group::{self, Element},
        ops,
        poly::{self, PartialSignature},
    },
    Digest, Hasher, PublicKey, Scheme,
};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Blob, Clock, Spawner, Storage};
use commonware_storage::journal::Journal;
use futures::channel::{mpsc, oneshot};
use futures::StreamExt;
use prost::Message as _;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    time::{Duration, SystemTime},
};
use tracing::{debug, error};

pub struct Actor<
    B: Blob,
    E: Clock + Spawner + Storage<B>,
    C: Scheme,
    H: Hasher,
    A: Application<Context = Context>,
    Z: Collector<Context = Context>,
    S: ThresholdCoordinator<Index = Epoch, Share = group::Share, Identity = poly::Public>,
> {
    ////////////////////////////////////////
    // Constants
    ////////////////////////////////////////
    runtime: E,
    crypto: C,
    hasher: H,

    ////////////////////////////////////////
    // Storage
    ////////////////////////////////////////
    journal: Option<Journal<B, E>>,

    ////////////////////////////////////////
    // Threshold
    ////////////////////////////////////////
    coordinator: S,

    ////////////////////////////////////////
    // Application Mailboxes
    ////////////////////////////////////////
    application: A,
    collector: Z,

    ////////////////////////////////////////
    // Namespace Constants
    ////////////////////////////////////////
    chunk_namespace: Vec<u8>,
    ack_namespace: Vec<u8>,

    ////////////////////////////////////////
    // Timeouts
    ////////////////////////////////////////

    // The configured timeout for rebroadcasting a chunk to all signers
    rebroadcast_timeout: Option<Duration>,

    // The system time at which the rebroadcast deadline is reached
    rebroadcast_deadline: Option<SystemTime>,

    ////////////////////////////////////////
    // Pruning
    ////////////////////////////////////////

    // A tuple representing the epochs to keep in memory.
    // The first element is the number of old epochs to keep.
    // The second element is the number of future epochs to accept.
    // For example, if the current epoch is 10, and the bounds are (1, 2), then
    // epochs 9, 10, 11, and 12 are kept (and accepted);
    // all others are pruned or rejected.
    epoch_bounds: (u64, u64),

    ////////////////////////////////////////
    // Messaging
    ////////////////////////////////////////
    mailbox_receiver: mpsc::Receiver<Message>,

    ////////////////////////////////////////
    // State
    ////////////////////////////////////////

    // The highest-height chunk for each sequencer.
    // The chunk must have the threshold signature of its parent.
    // Existence of the chunk implies:
    // - The existence of the sequencer's entire chunk chain (from height zero)
    // - That the chunk has been acked by this signer.
    tips: HashMap<PublicKey, wire::Chunk>,

    ackman: AckManager,
}

impl<
        B: Blob,
        E: Clock + Spawner + Storage<B>,
        C: Scheme,
        H: Hasher,
        A: Application<Context = Context>,
        Z: Collector<Context = Context>,
        S: ThresholdCoordinator<Index = Epoch, Share = group::Share, Identity = poly::Public>,
    > Actor<B, E, C, H, A, Z, S>
{
    pub fn new(runtime: E, journal: Journal<B, E>, cfg: Config<C, H, A, Z, S>) -> (Self, Mailbox) {
        let (mailbox_sender, mailbox_receiver) = mpsc::channel(cfg.mailbox_size);
        let mailbox = Mailbox::new(mailbox_sender);
        let result = Self {
            runtime,
            crypto: cfg.crypto,
            hasher: cfg.hasher,
            coordinator: cfg.coordinator,
            application: cfg.application,
            collector: cfg.collector,
            journal: Some(journal),
            chunk_namespace: encoder::chunk_namespace(&cfg.namespace),
            ack_namespace: encoder::ack_namespace(&cfg.namespace),
            rebroadcast_timeout: cfg.rebroadcast_timeout,
            rebroadcast_deadline: None,
            epoch_bounds: cfg.epoch_bounds,
            mailbox_receiver,
            tips: HashMap::new(),
            ackman: AckManager::new(),
        };

        (result, mailbox)
    }

    pub async fn run(
        mut self,
        chunk_network: (impl Sender, impl Receiver),
        ack_network: (impl Sender, impl Receiver),
    ) {
        let (mut link_sender, mut link_receiver) = chunk_network;
        let (mut ack_sender, mut ack_receiver) = ack_network;
        let mut shutdown = self.runtime.stopped();
        let runtime = self.runtime.clone();

        loop {
            let rebroadcast_deadline = self.rebroadcast_deadline.clone();
            select! {
                // Handle shutdown signal
                _ = &mut shutdown => {
                    debug!("Signer shutting down");
                    self.journal
                        .take()
                        .unwrap()
                        .close()
                        .await
                        .expect("unable to close journal");
                    return;
                },

                // Handle rebroadcast deadline (if it exists)
                _ = async {
                    if let Some(deadline) = rebroadcast_deadline {
                        runtime.sleep_until(deadline).await;
                    } else {
                        futures::future::pending::<()>().await;
                    }
                } => {
                    debug!("Rebroadcasting");
                    self.rebroadcast(&mut link_sender).await;
                },

                // Handle incoming links
                msg = link_receiver.recv() => {
                    debug!("Received link");
                    // Error handling
                    let Ok((sender, msg)) = msg else {
                        error!("link_receiver failed");
                        break;
                    };
                    let Ok(link) = wire::Link::decode(msg) else {
                        error!("Failed to decode link");
                        continue;
                    };
                    let Ok((chunk, parent)) = self.validate_link(link, &sender) else {
                        error!("Failed to validate link");
                        continue;
                    };

                    if let Some(parent) = parent {
                        debug!("Received parent");
                        let parent_chunk = wire::Chunk {
                            sequencer: sender.clone(),
                            height: chunk.height.checked_sub(1).unwrap(),
                            payload_digest: parent.payload_digest.clone(),
                        };
                        let threshold = group::Signature::deserialize(&parent.threshold).unwrap();
                        self.handle_threshold(&parent_chunk, parent.epoch, threshold).await;
                    }
                    self.handle_chunk(&chunk, &mut ack_sender).await;
                },

                // Handle incoming acks
                msg = ack_receiver.recv() => {
                    debug!("Received ack");
                    // Error handling
                    let Ok((sender, msg)) = msg else {
                        error!("ack_receiver failed");
                        break;
                    };
                    let Ok(ack) = wire::Ack::decode(msg) else {
                        error!("Failed to decode ack");
                        continue;
                    };
                    let Ok((chunk, epoch, partial)) = self.validate_ack(ack, &sender) else {
                        error!("Failed to verify ack");
                        continue;
                    };
                    self.handle_ack(&chunk, epoch, partial).await;
                },

                // Handle mailbox messages
                mail = self.mailbox_receiver.next() => {
                    debug!("Received mailbox message");
                    let msg = match mail {
                        Some(msg) => msg,
                        None => break,
                    };
                    match msg {
                        Message::Broadcast{ payload, result } => {
                            self.broadcast_new(payload, result, &mut link_sender, &mut ack_sender).await;
                        }
                    }
                }
            }
        }
    }

    /// Handles a threshold, either received from a link from the network or generated locally.
    ///
    /// Returns an error if the threshold already exists.
    async fn handle_threshold(
        &mut self,
        chunk: &wire::Chunk,
        epoch: Epoch,
        threshold: group::Signature,
    ) -> Result<(), Error> {
        // Check if the threshold signature is already known
        let evidence = self.ackman.get_or_init(epoch, &chunk);
        if let Evidence::Threshold(_) = evidence {
            return Err(Error::ThresholdAlreadyExists);
        }

        // The threshold signature is new, so store it
        *evidence = Evidence::Threshold(threshold);

        // Emit the proof
        let context = Context {
            sequencer: chunk.sequencer.clone(),
            height: chunk.height,
        };
        let proof =
            Prover::<C, H>::serialize_threshold(&context, &chunk.payload_digest, &threshold);
        self.collector
            .acknowledged(context, chunk.payload_digest.clone(), proof)
            .await;

        Ok(())
    }

    /// Handles an ack
    ///
    /// Returns an error if the ack is invalid, or can be ignored
    /// (e.g. already exists, threshold already exists, is outside the epoch bounds, etc.).
    async fn handle_ack(
        &mut self,
        chunk: &wire::Chunk,
        ack_epoch: Epoch,
        partial: Bytes,
    ) -> Result<(), Error> {
        // If the ack is for an epoch that is too old or too new, ignore.
        let (bound_lo, bound_hi) = {
            let epoch = self.coordinator.index();
            let (eb_lo, eb_hi) = self.epoch_bounds;
            (epoch.saturating_sub(eb_lo), epoch.saturating_add(eb_hi))
        };
        if ack_epoch < bound_lo || ack_epoch > bound_hi {
            return Err(Error::AckEpochOutsideBounds(ack_epoch, bound_lo, bound_hi));
        }

        // Get the number of required partials
        let Some(identity) = self.coordinator.identity(ack_epoch) else {
            return Err(Error::UnknownIdentity(ack_epoch));
        };
        let quorum = identity.required();

        // Get the partial signatures, returning early if we already have a threshold
        let evidence = self.ackman.get_or_init(ack_epoch, &chunk);
        let Evidence::Partials(partials) = evidence else {
            return Err(Error::ThresholdAlreadyExists);
        };

        // Return early if we already have this partial
        if partials.contains(&partial) {
            debug!("Ignoring ack. Already have this partial.");
            return Err(Error::PartialAlreadyExists);
        }

        // Store the ack
        partials.insert(partial.clone());

        // Return early if we don't have enough partials
        if partials.len() < quorum as usize {
            return Ok(());
        }

        // Construct the threshold signature
        let partials: Vec<PartialSignature> = partials
            .iter()
            .map(|p| PartialSignature::deserialize(p).unwrap())
            .collect();
        let threshold = ops::threshold_signature_recover(quorum, partials).unwrap();

        // Handle the threshold
        self.handle_threshold(chunk, ack_epoch, threshold).await?;

        Ok(())
    }

    /// Handles a chunk
    ///
    /// Returns an error if the chunk is invalid, or can be ignored
    /// (e.g. height is below the tip, etc.).
    async fn handle_chunk(&mut self, chunk: &wire::Chunk, ack_sender: &mut impl Sender) {
        let epoch = self.coordinator.index();

        // Validate the chunk with the application
        // TODO

        // Store the tip
        self.tips.insert(chunk.sequencer.clone(), chunk.clone());

        // Prune old evidence
        self.ackman
            .prune_height(epoch, &chunk.sequencer, chunk.height);

        // Construct partial signature
        let ack_digest = self.hash_ack(&chunk, epoch);
        let Some(share) = self.coordinator.share(epoch) else {
            error!("Failed to get share for epoch {:?}", epoch);
            return;
        };
        let partial: Bytes =
            ops::partial_sign_message(share, Some(&self.ack_namespace), &ack_digest)
                .serialize()
                .into();

        // Deal with the ack as if it were received over the network
        self.handle_ack(chunk, epoch, partial.clone()).await;

        // Send the ack to the network
        let ack = wire::Ack {
            chunk: Some(chunk.clone()),
            epoch,
            partial,
        };
        if let Err(e) = ack_sender
            .send(Recipients::All, ack.encode_to_vec().into(), false)
            .await
        {
            error!("Failed to send ack: {:?}", e);
        }
    }

    /// Broadcast a message to the network.
    ///
    /// The result is returned to the caller via the provided channel.
    /// The broadcast is only successful if the parent Chunk and threshold signature are known.
    async fn broadcast_new(
        &mut self,
        payload_digest: Bytes,
        result: oneshot::Sender<bool>,
        link_sender: &mut impl Sender,
        ack_sender: &mut impl Sender,
    ) {
        let epoch = self.coordinator.index();
        let me = self.crypto.public_key();

        // Get parent Chunk and threshold signature
        let mut height = 0;
        let mut parent = None;
        if let Some(tip) = self.tips.get(&me) {
            // Get threshold or return early
            let Evidence::Threshold(threshold) = self.ackman.get_or_init(epoch, tip) else {
                error!("Failed to get threshold for tip");
                let _ = result.send(false);
                return;
            };

            // Update height and parent
            height = tip.height + 1;
            parent = Some(wire::Parent {
                payload_digest: tip.payload_digest.clone(),
                threshold: threshold.serialize().into(),
                epoch: self.coordinator.index(),
            });
        }

        // Construct new chunk
        let chunk = wire::Chunk {
            sequencer: me.clone(),
            height,
            payload_digest: payload_digest.clone(),
        };

        // Deal with the chunk as if it were received over the network
        self.handle_chunk(&chunk, ack_sender).await;

        // Construct new link
        let signature = {
            let chunk_digest = self.hash_chunk(&chunk);
            self.crypto.sign(Some(&self.chunk_namespace), &chunk_digest)
        };
        let link = wire::Link {
            chunk: Some(chunk),
            signature,
            parent,
        };

        // Broadcast to network
        if let Err(_) = self.broadcast(&link, link_sender, epoch).await {
            error!("Failed to broadcast link");
            let _ = result.send(false);
            return;
        };

        // Return success
        let _ = result.send(true);
    }

    /// Attempt to rebroadcast the highest-height chunk of this sequencer to all signers.
    ///
    /// This is only done if:
    /// - this instance is the sequencer for the current epoch.
    /// - this instance has a chunk to rebroadcast.
    /// - this instance has not yet collected the threshold signature for the chunk.
    async fn rebroadcast(&mut self, link_sender: &mut impl Sender) -> Result<(), Error> {
        // Return if not a sequencer in the current epoch
        let epoch = self.coordinator.index();
        let me = self.crypto.public_key();
        if self.coordinator.is_sequencer(epoch, &me).is_none() {
            return Err(Error::IAmNotASequencer(epoch));
        }

        // Return if no chunk to rebroadcast
        let Some(tip) = self.tips.get(&me) else {
            return Err(Error::NothingToRebroadcast);
        };
        let tip = tip.clone();

        // Return if threshold already collected
        if let Evidence::Threshold(_) = self.ackman.get_or_init(epoch, &tip) {
            return Err(Error::ThresholdAlreadyExists);
        }

        // Broadcast the message
        let chunk_digest = self.hash_chunk(&tip);
        let link = wire::Link {
            chunk: Some(tip),
            signature: self.crypto.sign(Some(&self.chunk_namespace), &chunk_digest),
            parent: None, // TODO: bug
        };
        self.broadcast(&link, link_sender, epoch).await?;

        Ok(())
    }

    /// Send a link message to all signers in the given epoch.
    async fn broadcast(
        &mut self,
        link: &wire::Link,
        sender: &mut impl Sender,
        epoch: Epoch,
    ) -> Result<(), Error> {
        // Send the link to all signers
        let Some(signers) = self.coordinator.signers(epoch) else {
            return Err(Error::UnknownSigners(epoch));
        };
        sender
            .send(
                Recipients::Some(signers.clone()),
                link.encode_to_vec().into(),
                false,
            )
            .await
            .map_err(|_| Error::BroadcastFailed)?;

        // Set the rebroadcast deadline
        // TODO

        Ok(())
    }

    /// Takes a raw link (from sender) from the p2p network and validates it.
    ///
    /// Returns the chunk if the link is valid.
    /// Returns an error if the link is invalid.
    fn validate_link(
        &mut self,
        link: wire::Link,
        sender: &PublicKey,
    ) -> Result<(wire::Chunk, Option<wire::Parent>), Error> {
        // Validate chunk
        let epoch = self.coordinator.index();
        let chunk = self.validate_chunk(link.chunk, epoch)?;

        // Verify the sender
        if chunk.sequencer != sender {
            return Err(Error::PeerMismatch);
        }

        // Verify the signature
        let chunk_digest = self.hash_chunk(&chunk);
        if !C::verify(
            Some(&self.chunk_namespace),
            &chunk_digest,
            sender,
            &link.signature.into(),
        ) {
            return Err(Error::InvalidLinkSignature);
        }

        // Verify no parent
        if chunk.height == 0 {
            if link.parent.is_some() {
                return Err(Error::GenesisChunkMustNotHaveParent);
            }
            return Ok((chunk, None));
        }

        // Verify parent
        let Some(parent) = &link.parent else {
            return Err(Error::LinkMissingParent);
        };
        let parent_chunk = wire::Chunk {
            sequencer: sender.clone(),
            height: chunk.height.checked_sub(1).unwrap(),
            payload_digest: parent.payload_digest.clone(),
        };
        let Some(identity) = self.coordinator.identity(epoch) else {
            return Err(Error::UnknownIdentity(epoch));
        };
        let public_key = poly::public(identity);
        let Some(threshold) = group::Signature::deserialize(&parent.threshold) else {
            return Err(Error::UnableToDeserializeThresholdSignature);
        };
        let ack_digest = self.hash_ack(&parent_chunk, parent.epoch);
        ops::verify_message(
            &public_key,
            Some(&self.ack_namespace),
            &ack_digest,
            &threshold,
        )
        .map_err(|_| Error::InvalidThresholdSignature)?;

        Ok((chunk, Some(parent.clone())))
    }

    /// Takes a raw ack (from sender) from the p2p network and validates it.
    ///
    /// Returns the chunk, epoch, and partial signature if the ack is valid.
    /// Returns an error if the ack is invalid.
    fn validate_ack(
        &mut self,
        ack: wire::Ack,
        sender: &PublicKey,
    ) -> Result<(wire::Chunk, Epoch, Bytes), Error> {
        // Validate chunk
        let chunk = self.validate_chunk(ack.chunk, ack.epoch)?;

        let Some(partial) = PartialSignature::deserialize(&ack.partial) else {
            return Err(Error::UnableToDeserializePartialSignature);
        };

        // Validate sender
        let Some(signer_index) = self.coordinator.is_signer(ack.epoch, sender) else {
            return Err(Error::UnknownSigner);
        };
        if signer_index != partial.index {
            return Err(Error::PeerMismatch);
        }

        // Validate partial signature
        let ack_digest = self.hash_ack(&chunk, ack.epoch);
        let Some(identity) = self.coordinator.identity(ack.epoch) else {
            return Err(Error::UnknownIdentity(ack.epoch));
        };
        ops::partial_verify_message(identity, Some(&self.ack_namespace), &ack_digest, &partial)
            .map_err(|_| Error::InvalidPartialSignature)?;

        Ok((chunk, ack.epoch, ack.partial.clone()))
    }

    /// Takes a raw chunk from the p2p network and validates it against the epoch.
    ///
    /// Returns the chunk if the chunk is valid.
    /// Returns an error if the chunk is invalid.
    fn validate_chunk(
        &self,
        chunk: Option<wire::Chunk>,
        epoch: Epoch,
    ) -> Result<wire::Chunk, Error> {
        let Some(chunk) = chunk else {
            return Err(Error::MissingChunk);
        };

        // Verify sequencer
        if self
            .coordinator
            .is_sequencer(epoch, &chunk.sequencer)
            .is_none()
        {
            return Err(Error::UnknownSequencer(epoch, chunk.sequencer.clone()));
        }

        // Verify height
        if let Some(tip) = self.tips.get(&chunk.sequencer) {
            // Height must be at least the tip height
            if tip.height < chunk.height {
                return Err(Error::HeightTooLow(chunk.height, tip.height));
            } else if tip.height == chunk.height {
                // Ensure this matches the tip if the height is the same
                if tip.payload_digest != chunk.payload_digest {
                    return Err(Error::ChunkMismatch(chunk.sequencer.clone(), chunk.height));
                }
            }
        }

        // Verify digest
        if chunk.payload_digest.len() != H::len() {
            return Err(Error::InvalidDigest);
        }

        Ok(chunk)
    }

    /// Returns the digest of the given chunk
    fn hash_chunk(&mut self, chunk: &wire::Chunk) -> Digest {
        self.hasher.reset();
        self.hasher.update(&chunk.sequencer);
        self.hasher.update(&chunk.height.to_be_bytes());
        self.hasher.update(&chunk.payload_digest);
        self.hasher.finalize()
    }

    /// Returns the digest of the given ack
    fn hash_ack(&mut self, chunk: &wire::Chunk, epoch: Epoch) -> Digest {
        self.hasher.reset();
        self.hasher.update(&chunk.sequencer);
        self.hasher.update(&chunk.height.to_be_bytes());
        self.hasher.update(&chunk.payload_digest);
        self.hasher.update(&epoch.to_be_bytes());
        self.hasher.finalize()
    }
}

enum Evidence {
    Partials(HashSet<Bytes>),
    Threshold(group::Signature),
}

/// Manages acknowledgements for chunks.
struct AckManager {
    // Acknowledgements for digests.
    //
    // Map from Epoch => Sequencer => Height => PayloadDigest => Evidence
    //
    // Evidence may be partial signatures or threshold signatures.
    //
    // The BTreeMaps are sorted by key, so we can prune old entries. In particular, we can prune
    // entries where the height is less than the height of the highest chunk for the sequencer.
    // We can often prune entries for old epochs as well.
    acks: BTreeMap<Epoch, HashMap<PublicKey, BTreeMap<u64, HashMap<Digest, Evidence>>>>,
}

impl AckManager {
    /// Returns a new AckManager.
    pub fn new() -> Self {
        AckManager {
            acks: BTreeMap::new(),
        }
    }

    /// Returns the evidence for the given epoch, sequencer, height, and chunk.
    /// If the evidence did not exist, it is initialized as an empty set of partials.
    fn get_or_init(&mut self, epoch: Epoch, chunk: &wire::Chunk) -> &mut Evidence {
        self.acks
            .entry(epoch)
            .or_insert_with(HashMap::new)
            .entry(chunk.sequencer.clone())
            .or_insert_with(BTreeMap::new)
            .entry(chunk.height)
            .or_insert_with(HashMap::new)
            .entry(chunk.payload_digest.clone())
            .or_insert_with(|| Evidence::Partials(HashSet::new()))
    }

    /// Prunes all entries (at the given epoch and sequencer) below the height (exclusive).
    fn prune_height(&mut self, epoch: Epoch, sequencer: &PublicKey, height: u64) {
        self.acks
            .get_mut(&epoch)
            .and_then(|m| m.get_mut(sequencer))
            .map(|m| m.retain(|h, _| *h >= height));
    }

    /// Prunes all entries below the given epoch (exclusive).
    fn prune_epoch(&mut self, epoch: Epoch) {
        self.acks.retain(|e, _| *e >= epoch);
    }
}
