use super::{AckManager, Config, Mailbox, Message, TipManager};
use crate::{
    linked::{encoder, prover::Prover, serializer, wire, Context, Epoch},
    Application, Collector, ThresholdCoordinator,
};
use bytes::Bytes;
use commonware_cryptography::{
    bls12381::primitives::{
        group::{self, Element},
        ops,
        poly::{self, PartialSignature},
    },
    Digest, PublicKey, Scheme,
};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Blob, Clock, Spawner, Storage};
use commonware_storage::journal::{self, Journal};
use commonware_utils::hex;
use futures::{
    channel::{mpsc, oneshot},
    future::Either,
    pin_mut, StreamExt,
};
use prometheus_client::registry::Registry;
use prost::Message as _;
use std::{
    collections::HashMap,
    marker::PhantomData,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use thiserror::Error;
use tracing::{debug, error, info};

pub struct Actor<
    B: Blob,
    E: Clock + Spawner + Storage<B>,
    C: Scheme,
    D: Digest,
    J: Fn(&PublicKey) -> String,
    A: Application<Context = Context, Digest = D>,
    Z: Collector<Context = Context, Digest = D>,
    S: ThresholdCoordinator<Index = Epoch, Share = group::Share, Identity = poly::Public>,
> {
    ////////////////////////////////////////
    // Constants
    ////////////////////////////////////////
    runtime: E,
    crypto: C,
    _digest: PhantomData<D>,

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

    // The configured timeout for refreshing the epoch
    refresh_epoch_timeout: Duration,
    refresh_epoch_deadline: Option<SystemTime>,

    // The configured timeout for rebroadcasting a chunk to all signers
    rebroadcast_timeout: Duration,
    rebroadcast_deadline: Option<SystemTime>,

    ////////////////////////////////////////
    // Pruning
    ////////////////////////////////////////

    // A tuple representing the epochs to keep in memory.
    // The first element is the number of old epochs to keep.
    // The second element is the number of future epochs to accept.
    //
    // For example, if the current epoch is 10, and the bounds are (1, 2), then
    // epochs 9, 10, 11, and 12 are kept (and accepted);
    // all others are pruned or rejected.
    epoch_bounds: (u64, u64),

    // The number of future heights to accept acks for.
    // This is used to prevent spam of acks for arbitrary heights.
    //
    // For example, if the current tip for a sequencer is at height 100,
    // and the height_bound is 10, then acks for heights 100-110 are accepted.
    height_bound: u64,

    ////////////////////////////////////////
    // Messaging
    ////////////////////////////////////////
    mailbox_receiver: mpsc::Receiver<Message<D>>,

    ////////////////////////////////////////
    // Storage
    ////////////////////////////////////////
    journal_entries_per_section: u64,
    journal_replay_concurrency: usize,
    journal_naming_fn: J,
    journals: HashMap<PublicKey, Journal<B, E>>,

    ////////////////////////////////////////
    // State
    ////////////////////////////////////////
    tip_manager: TipManager,

    // Handles acknowledgements for chunks.
    ack_manager: AckManager<D>,

    // The current epoch.
    epoch: Epoch,
}

impl<
        B: Blob,
        E: Clock + Spawner + Storage<B>,
        C: Scheme,
        D: Digest,
        J: Fn(&PublicKey) -> String,
        A: Application<Context = Context, Digest = D>,
        Z: Collector<Context = Context, Digest = D>,
        S: ThresholdCoordinator<Index = Epoch, Share = group::Share, Identity = poly::Public>,
    > Actor<B, E, C, D, J, A, Z, S>
{
    pub fn new(runtime: E, cfg: Config<C, D, J, A, Z, S>) -> (Self, Mailbox<D>) {
        let (mailbox_sender, mailbox_receiver) = mpsc::channel(cfg.mailbox_size);
        let mailbox = Mailbox::new(mailbox_sender);
        let result = Self {
            runtime,
            crypto: cfg.crypto,
            _digest: PhantomData,
            coordinator: cfg.coordinator,
            application: cfg.application,
            collector: cfg.collector,
            chunk_namespace: encoder::chunk_namespace(&cfg.namespace),
            ack_namespace: encoder::ack_namespace(&cfg.namespace),
            refresh_epoch_timeout: cfg.refresh_epoch_timeout,
            refresh_epoch_deadline: None,
            rebroadcast_timeout: cfg.rebroadcast_timeout,
            rebroadcast_deadline: None,
            epoch_bounds: cfg.epoch_bounds,
            height_bound: cfg.height_bound,
            mailbox_receiver,
            journal_entries_per_section: cfg.journal_entries_per_section,
            journal_replay_concurrency: cfg.journal_replay_concurrency,
            journal_naming_fn: cfg.journal_naming_fn,
            journals: HashMap::new(),
            tip_manager: TipManager::default(),
            ack_manager: AckManager::default(),
            epoch: 0,
        };

        (result, mailbox)
    }

    /// Runs the actor until the runtime is stopped.
    ///
    /// The actor will handle:
    /// - Timeouts
    ///   - Refreshing the Epoch
    ///   - Rebroadcasting Links
    /// - Mailbox messages from the application:
    ///   - Broadcast requests
    ///   - Ack requests
    /// - Messages from the network:
    ///   - Links
    ///   - Acks
    pub async fn run(
        mut self,
        chunk_network: (impl Sender, impl Receiver),
        ack_network: (impl Sender, impl Receiver),
    ) {
        let (mut link_sender, mut link_receiver) = chunk_network;
        let (mut ack_sender, mut ack_receiver) = ack_network;
        let mut shutdown = self.runtime.stopped();

        // Before starting on the main runtime loop, initialize my own sequencer journal
        // and attempt to rebroadcast if necessary.
        self.refresh_epoch();
        self.journal_prepare(&self.crypto.public_key()).await;
        if let Err(e) = self.rebroadcast(&mut link_sender).await {
            // Rebroadcasting my return a non-critical error, so log the error and continue.
            info!("Failed initial rebroadcast: {:?}", e);
        }

        loop {
            // Enter the epoch
            self.refresh_epoch();

            // Create deadline futures.
            // If the deadline is None, the future will never resolve.
            let refresh_epoch = match self.refresh_epoch_deadline {
                Some(deadline) => Either::Left(self.runtime.sleep_until(deadline)),
                None => Either::Right(futures::future::pending()),
            };
            let rebroadcast = match self.rebroadcast_deadline {
                Some(deadline) => Either::Left(self.runtime.sleep_until(deadline)),
                None => Either::Right(futures::future::pending()),
            };

            select! {
                // Handle shutdown signal
                _ = &mut shutdown => {
                    debug!("Shutdown");
                    for (_, journal) in self.journals.drain() {
                        journal.close().await.expect("unable to close journal");
                    }
                    return;
                },

                // Handle refresh epoch deadline
                _ = refresh_epoch => {
                    debug!("Timeout: Refresh Epoch");
                    // Simply continue; the epoch will be refreshed on the next iteration.
                    continue;
                },

                // Handle rebroadcast deadline
                _ = rebroadcast => {
                    debug!("Timeout: Rebroadcast");
                    if let Err(e) = self.rebroadcast(&mut link_sender).await {
                        error!("Failed to rebroadcast: {:?}", e);
                        continue;
                    }
                },

                // Handle incoming links
                msg = link_receiver.recv() => {
                    debug!("Network: Link");
                    // Error handling
                    let Ok((sender, msg)) = msg else {
                        error!("link_receiver failed");
                        break;
                    };
                    let Ok(link) = wire::Link::decode(msg) else {
                        error!("Failed to decode link");
                        continue;
                    };
                    let parent_proof = match self.validate_link(&link, &sender) {
                        Ok(result) => result,
                        Err(e) => {
                            error!("Failed to validate link: {:?}", e);
                            continue;
                        }
                    };

                    // Initialize journal for sequencer if it does not exist
                    self.journal_prepare(&sender).await;

                    // Handle the parent threshold signature
                    if let Some((chunk, epoch, threshold)) = parent_proof {
                        self.handle_threshold(&chunk, epoch, threshold).await;
                    }

                    // Process the new link
                    self.handle_link(&link).await;
                },

                // Handle incoming acks
                msg = ack_receiver.recv() => {
                    debug!("Network: Ack");
                    // Error handling
                    let Ok((sender, msg)) = msg else {
                        error!("ack_receiver failed");
                        break;
                    };
                    let Ok(ack) = wire::Ack::decode(msg) else {
                        error!("Failed to decode ack");
                        continue;
                    };
                    let (chunk, epoch, partial) = match self.validate_ack(ack, &sender) {
                        Ok(result) => result,
                        Err(e) => {
                            error!("Failed to validate ack: {:?}", e);
                            continue;
                        }
                    };
                    if let Err(e) = self.handle_ack(&chunk, epoch, &partial).await {
                        error!("Failed to handle ack: {:?}", e);
                        continue;
                    }
                },

                // Handle mailbox messages
                mail = self.mailbox_receiver.next() => {
                    let msg = match mail {
                        Some(msg) => msg,
                        None => {
                            error!("Mailbox receiver failed");
                            break;
                        }
                    };
                    match msg {
                        Message::Broadcast{ payload_digest, result } => {
                            debug!("Mailbox: Broadcast");
                            if self.coordinator.is_sequencer(self.epoch, &self.crypto.public_key()).is_none() {
                                error!("Not a sequencer in the current epoch");
                                continue;
                            }

                            // Broadcast the message
                            if let Err(e) = self.broadcast_new(payload_digest, result, &mut link_sender).await {
                                error!("Failed to broadcast new: {:?}", e);
                                continue;
                            }
                        }
                        Message::Verified{ context, payload_digest } => {
                            debug!("Mailbox: Verified");
                            if let Err(e) = self.handle_app_verified(&context, &payload_digest, &mut ack_sender).await {
                                error!("Failed to handle app-verified: {:?}", e);
                                continue;
                            }
                        }
                    }
                }
            }
        }
    }

    ////////////////////////////////////////
    // Handling
    ////////////////////////////////////////

    /// Handles a verified message from the application.
    ///
    /// This is called when the application has verified a payload.
    /// The chunk will be signed if it matches the current tip.
    async fn handle_app_verified(
        &mut self,
        context: &Context,
        payload_digest: &D,
        ack_sender: &mut impl Sender,
    ) -> Result<(), Error> {
        // Get the tip
        let Some(chunk) = self.tip_manager.get_chunk(&context.sequencer) else {
            return Err(Error::AppVerifiedNoTip);
        };

        // Return early if the height does not match
        if chunk.height != context.height {
            return Err(Error::AppVerifiedHeightMismatch);
        }

        // Return early if the payload digest does not match
        let chunk_digest = D::read_from(&mut chunk.payload_digest.clone()).unwrap();
        if chunk_digest != *payload_digest {
            return Err(Error::AppVerifiedPayloadMismatch);
        }

        // Construct partial signature
        let Some(share) = self.coordinator.share(self.epoch) else {
            return Err(Error::UnknownShare(self.epoch));
        };
        let partial = ops::partial_sign_message(
            share,
            Some(&self.ack_namespace),
            &serializer::ack(&chunk, self.epoch),
        );

        // Sync the journal to prevent ever acking two conflicting chunks at
        // the same height, even if the node crashes and restarts.
        self.journal_sync(&context.sequencer, context.height).await;

        // The recipients are all the signers in the epoch and the sequencer.
        // The sequencer may or may not be a signer.
        let recipients = {
            let Some(signers) = self.coordinator.signers(self.epoch) else {
                return Err(Error::UnknownSigners(self.epoch));
            };
            let mut recipients = signers.clone();
            if self
                .coordinator
                .is_signer(self.epoch, &chunk.sequencer)
                .is_none()
            {
                recipients.push(chunk.sequencer.clone());
            }
            recipients
        };

        // Send the ack to the network
        let ack = wire::Ack {
            chunk: Some(chunk.clone()),
            epoch: self.epoch,
            partial: partial.serialize().into(),
        };
        ack_sender
            .send(
                Recipients::Some(recipients),
                ack.encode_to_vec().into(),
                false,
            )
            .await
            .map_err(|_| Error::UnableToSendMessage)?;

        // Handle the ack internally
        self.handle_ack(&chunk, self.epoch, &partial).await?;

        Ok(())
    }

    /// Handles a threshold, either received from a link from the network or generated locally.
    ///
    /// The threshold must already be verified.
    /// If the threshold is new, it is stored and the proof is emitted to the collector.
    /// If the threshold is already known, it is ignored.
    async fn handle_threshold(
        &mut self,
        chunk: &wire::Chunk,
        epoch: Epoch,
        threshold: group::Signature,
    ) {
        // Set the threshold signature, returning early if it already exists
        if !self
            .ack_manager
            .add_threshold(&chunk.sequencer, chunk.height, epoch, threshold)
        {
            return;
        }

        // Emit the proof
        let context = Context {
            sequencer: chunk.sequencer.clone(),
            height: chunk.height,
        };
        let digest = D::read_from(&mut chunk.payload_digest.clone()).unwrap();
        let proof = Prover::<C, D>::serialize_threshold(&context, &digest, epoch, &threshold);
        self.collector.acknowledged(context, digest, proof).await;
    }

    /// Handles an ack
    ///
    /// Returns an error if the ack is invalid, or can be ignored
    /// (e.g. already exists, threshold already exists, is outside the epoch bounds, etc.).
    async fn handle_ack(
        &mut self,
        chunk: &wire::Chunk,
        epoch: Epoch,
        partial: &PartialSignature,
    ) -> Result<(), Error> {
        // Get the quorum
        let Some(identity) = self.coordinator.identity(epoch) else {
            return Err(Error::UnknownIdentity(epoch));
        };
        let quorum = identity.required();

        // Add the partial signature. If a new threshold is formed, handle it.
        let digest = D::read_from(&mut chunk.payload_digest.clone()).unwrap();
        if let Some(threshold) = self.ack_manager.add_partial(
            &chunk.sequencer,
            chunk.height,
            epoch,
            &digest,
            partial,
            quorum,
        ) {
            // Handle the threshold signature
            self.handle_threshold(chunk, epoch, threshold).await;
        }

        Ok(())
    }

    /// Handles a valid link message, storing it as the tip.
    /// Alerts the application of the new link.
    /// Also appends the link to the journal if it's new.
    async fn handle_link(&mut self, link: &wire::Link) {
        // Store the tip
        let is_new = self.tip_manager.put(link);
        let chunk = link.chunk.as_ref().unwrap();

        // Take actions if the link is new
        if is_new {
            // Append to journal
            self.journal_append(link).await;
            self.journal_sync(&chunk.sequencer, chunk.height).await;
        }

        // Verify the chunk with the application
        let context = Context {
            sequencer: chunk.sequencer.clone(),
            height: chunk.height,
        };
        let digest = D::read_from(&mut chunk.payload_digest.clone()).unwrap();
        self.application.verify(context, digest).await;
    }

    ////////////////////////////////////////
    // Broadcasting
    ////////////////////////////////////////

    /// Broadcast a message to the network.
    ///
    /// The result is returned to the caller via the provided channel.
    /// The broadcast is only successful if the parent Chunk and threshold signature are known.
    async fn broadcast_new(
        &mut self,
        payload_digest: D,
        result: oneshot::Sender<bool>,
        link_sender: &mut impl Sender,
    ) -> Result<(), Error> {
        let me = self.crypto.public_key();

        // Get parent Chunk and threshold signature
        let mut height = 0;
        let mut parent = None;
        if let Some(chunk_tip) = self.tip_manager.get_chunk(&me) {
            // Get threshold, or, if it doesn't exist, return an error
            let Some((epoch, threshold)) = self.ack_manager.get_threshold(&me, chunk_tip.height)
            else {
                let _ = result.send(false);
                return Err(Error::NoThresholdForTip(chunk_tip.height));
            };

            // Update height and parent
            height = chunk_tip.height + 1;
            parent = Some(wire::Parent {
                payload_digest: chunk_tip.payload_digest,
                threshold: threshold.serialize().into(),
                epoch,
            });
        }

        // Construct new link
        let chunk = wire::Chunk {
            sequencer: me.clone(),
            height,
            payload_digest: payload_digest.to_vec().into(),
        };
        let signature = self
            .crypto
            .sign(Some(&self.chunk_namespace), &serializer::chunk(&chunk));
        let link = wire::Link {
            chunk: Some(chunk),
            signature,
            parent,
        };

        // Deal with the chunk as if it were received over the network
        self.handle_link(&link).await;

        // Sync the journal to prevent ever broadcasting two conflicting chunks
        // at the same height, even if the node crashes and restarts
        self.journal_sync(&me, height).await;

        // Broadcast to network
        if let Err(e) = self.broadcast(&link, link_sender, self.epoch).await {
            error!("Failed to broadcast link: {:?}", e);
            let _ = result.send(false);
            return Err(e);
        };

        // Return success
        debug!("Broadcast successful");
        let _ = result.send(true);
        Ok(())
    }

    /// Attempt to rebroadcast the highest-height chunk of this sequencer to all signers.
    ///
    /// This is only done if:
    /// - this instance is the sequencer for the current epoch.
    /// - this instance has a chunk to rebroadcast.
    /// - this instance has not yet collected the threshold signature for the chunk.
    async fn rebroadcast(&mut self, link_sender: &mut impl Sender) -> Result<(), Error> {
        // Unset the rebroadcast deadline
        self.rebroadcast_deadline = None;

        // Return if not a sequencer in the current epoch
        let me = self.crypto.public_key();
        if self.coordinator.is_sequencer(self.epoch, &me).is_none() {
            return Err(Error::IAmNotASequencer(self.epoch));
        }

        // Return if no chunk to rebroadcast
        let Some(link_tip) = self.tip_manager.get(&me) else {
            return Err(Error::NothingToRebroadcast);
        };

        // Return if threshold already collected
        if self
            .ack_manager
            .get_threshold(&me, link_tip.chunk.as_ref().unwrap().height)
            .is_some()
        {
            return Err(Error::AlreadyBroadcast);
        }

        // Broadcast the message, which resets the rebroadcast deadline
        self.broadcast(&link_tip, link_sender, self.epoch).await?;

        Ok(())
    }

    /// Send a link message to all signers in the given epoch.
    async fn broadcast(
        &mut self,
        link: &wire::Link,
        link_sender: &mut impl Sender,
        epoch: Epoch,
    ) -> Result<(), Error> {
        // Send the link to all signers
        let Some(signers) = self.coordinator.signers(epoch) else {
            return Err(Error::UnknownSigners(epoch));
        };
        link_sender
            .send(
                Recipients::Some(signers.clone()),
                link.encode_to_vec().into(),
                false,
            )
            .await
            .map_err(|_| Error::BroadcastFailed)?;

        // Set the rebroadcast deadline
        self.rebroadcast_deadline = Some(self.runtime.current() + self.rebroadcast_timeout);

        Ok(())
    }

    ////////////////////////////////////////
    // Validation
    ////////////////////////////////////////

    /// Takes a raw link (from sender) from the p2p network and validates it.
    ///
    /// If valid, returns the implied parent chunk and its threshold signature.
    /// Else returns an error if the link is invalid.
    fn validate_link(
        &mut self,
        link: &wire::Link,
        sender: &PublicKey,
    ) -> Result<Option<(wire::Chunk, Epoch, group::Signature)>, Error> {
        // Validate chunk
        let chunk = self.validate_chunk(link.chunk.clone(), self.epoch)?;

        // Verify the sender
        if chunk.sequencer != sender {
            return Err(Error::PeerMismatch);
        }

        // Verify the signature
        // TODO (Optimization): If the link is equal to the tip, don't verify
        if !C::verify(
            Some(&self.chunk_namespace),
            &serializer::chunk(&chunk),
            sender,
            &link.signature.clone(),
        ) {
            return Err(Error::InvalidLinkSignature);
        }

        // Verify no parent
        if chunk.height == 0 {
            if link.parent.is_some() {
                return Err(Error::GenesisChunkMustNotHaveParent);
            }
            return Ok(None);
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
        let Some(threshold) = group::Signature::deserialize(&parent.threshold) else {
            return Err(Error::UnableToDeserializeThresholdSignature);
        };

        // Verify parent threshold signature
        // TODO (Optimization): If the link is exactly equal to the tip, don't verify
        let Some(identity) = self.coordinator.identity(parent.epoch) else {
            return Err(Error::UnknownIdentity(parent.epoch));
        };
        let public_key = poly::public(identity);
        ops::verify_message(
            &public_key,
            Some(&self.ack_namespace),
            &serializer::ack(&parent_chunk, parent.epoch),
            &threshold,
        )
        .map_err(|_| Error::InvalidThresholdSignature)?;

        Ok(Some((parent_chunk, parent.epoch, threshold)))
    }

    /// Takes a raw ack (from sender) from the p2p network and validates it.
    ///
    /// Returns the chunk, epoch, and partial signature if the ack is valid.
    /// Returns an error if the ack is invalid.
    fn validate_ack(
        &mut self,
        ack: wire::Ack,
        sender: &PublicKey,
    ) -> Result<(wire::Chunk, Epoch, PartialSignature), Error> {
        // Validate chunk
        let chunk = self.validate_chunk(ack.chunk, ack.epoch)?;

        // Validate sender
        let Some(signer_index) = self.coordinator.is_signer(ack.epoch, sender) else {
            return Err(Error::UnknownSigner(ack.epoch, sender.clone()));
        };
        let Some(partial) = PartialSignature::deserialize(&ack.partial) else {
            return Err(Error::UnableToDeserializePartialSignature);
        };
        if signer_index != partial.index {
            return Err(Error::PeerMismatch);
        }

        // Spam prevention: If the ack is for an epoch that is too old or too new, ignore.
        {
            let (eb_lo, eb_hi) = self.epoch_bounds;
            let bound_lo = self.epoch.saturating_sub(eb_lo);
            let bound_hi = self.epoch.saturating_add(eb_hi);
            if ack.epoch < bound_lo || ack.epoch > bound_hi {
                return Err(Error::AckEpochOutsideBounds(ack.epoch, bound_lo, bound_hi));
            }
        }

        // Spam prevention: If the ack is for a height that is too old or too new, ignore.
        {
            let bound_lo = self.tip_manager.get_height(sender).unwrap_or(0);
            let bound_hi = bound_lo + self.height_bound;
            if chunk.height < bound_lo || chunk.height > bound_hi {
                return Err(Error::AckHeightOutsideBounds(
                    chunk.height,
                    bound_lo,
                    bound_hi,
                ));
            }
        }

        // Validate partial signature
        // TODO (Optimization): If the ack already exists, don't verify
        let Some(identity) = self.coordinator.identity(ack.epoch) else {
            return Err(Error::UnknownIdentity(ack.epoch));
        };
        ops::partial_verify_message(
            identity,
            Some(&self.ack_namespace),
            &serializer::ack(&chunk, ack.epoch),
            &partial,
        )
        .map_err(|_| Error::InvalidPartialSignature)?;

        Ok((chunk, ack.epoch, partial))
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
        if let Some(chunk_tip) = self.tip_manager.get_chunk(&chunk.sequencer) {
            // Height must be at least the tip height
            match chunk.height.cmp(&chunk_tip.height) {
                std::cmp::Ordering::Less => {
                    return Err(Error::ChunkHeightTooLow(chunk.height, chunk_tip.height));
                }
                std::cmp::Ordering::Equal => {
                    // Ensure this matches the tip if the height is the same
                    if chunk_tip.payload_digest != chunk.payload_digest {
                        return Err(Error::ChunkMismatch(chunk.sequencer, chunk.height));
                    }
                }
                std::cmp::Ordering::Greater => {}
            }
        }

        // Verify digest
        if D::read_from(&mut chunk.payload_digest.clone()).is_err() {
            return Err(Error::InvalidDigest);
        }

        Ok(chunk)
    }

    ////////////////////////////////////////
    // Journal
    ////////////////////////////////////////

    /// Returns the section of the journal for the given height.
    fn get_journal_section(&self, height: u64) -> u64 {
        height / self.journal_entries_per_section
    }

    /// Ensures the journal exists and is initialized for the given sequencer.
    /// If the journal does not exist, it is created and replayed.
    /// Else, no action is taken.
    async fn journal_prepare(&mut self, sequencer: &PublicKey) {
        // Return early if the journal already exists
        if self.journals.contains_key(sequencer) {
            return;
        }

        // Initialize journal
        let cfg = journal::Config {
            registry: Arc::new(Mutex::new(Registry::default())),
            partition: (self.journal_naming_fn)(sequencer),
        };
        let mut journal = Journal::init(self.runtime.clone(), cfg)
            .await
            .expect("unable to init journal");

        // Replay journal
        {
            debug!(sequencer = hex(sequencer), "Replaying journal");

            // Prepare the stream
            let stream = journal
                .replay(self.journal_replay_concurrency, None)
                .await
                .expect("unable to replay journal");
            pin_mut!(stream);

            // Read from the stream, which may be in arbitrary order.
            // Remember the highest link height
            let mut tip: Option<wire::Link> = None;
            let mut num_items = 0;
            while let Some(msg) = stream.next().await {
                num_items += 1;
                let (_, _, _, msg) = msg.expect("unable to decode journal message");
                let link = wire::Link::decode(msg).expect("journal message is unexpected format");
                let height = link.chunk.as_ref().unwrap().height;
                match tip {
                    None => {
                        tip = Some(link);
                    }
                    Some(ref t) => {
                        if height > t.chunk.as_ref().unwrap().height {
                            tip = Some(link);
                        }
                    }
                }
            }

            // Set the tip
            if let Some(link) = tip.take() {
                let is_new = self.tip_manager.put(&link);
                assert!(is_new);
            }

            debug!(
                sequencer = hex(sequencer),
                n = num_items,
                "Journal replay complete"
            );
        }

        // Store journal
        self.journals.insert(sequencer.clone(), journal);
    }

    /// Write a link to the appropriate journal.
    ///
    /// The journal must already be open and replayed.
    async fn journal_append(&mut self, link: &wire::Link) {
        let chunk = link.chunk.as_ref().unwrap();
        let section = self.get_journal_section(chunk.height);
        self.journals
            .get_mut(&chunk.sequencer)
            .expect("journal does not exist")
            .append(section, link.encode_to_vec().into())
            .await
            .expect("unable to append to journal");
    }

    /// Syncs (ensures all data is written to disk) and prunes the journal for the given sequencer and height.
    async fn journal_sync(&mut self, sequencer: &PublicKey, height: u64) {
        let section = self.get_journal_section(height);

        // Get journal
        let journal = self
            .journals
            .get_mut(sequencer)
            .expect("journal does not exist");

        // Sync journal
        journal.sync(section).await.expect("unable to sync journal");

        // Prune journal, ignoring errors
        let _ = journal.prune(section).await;
    }

    ////////////////////////////////////////
    // Epoch
    ////////////////////////////////////////

    /// Updates the epoch to the value of the coordinator, and sets the refresh epoch deadline.
    fn refresh_epoch(&mut self) {
        // Set the refresh epoch deadline
        self.refresh_epoch_deadline = Some(self.runtime.current() + self.refresh_epoch_timeout);

        // Ensure epoch is not before the current epoch
        let epoch = self.coordinator.index();
        if epoch < self.epoch {
            panic!("epoch must be greater than or equal to the current epoch");
        }

        // Update the epoch
        self.epoch = epoch;
    }
}

/// Errors that can occur when running the actor.
#[derive(Error, Debug)]
enum Error {
    // Application Verified Errors
    #[error("Application verified no tip")]
    AppVerifiedNoTip,
    #[error("Application verified height mismatch")]
    AppVerifiedHeightMismatch,
    #[error("Application verified payload mismatch")]
    AppVerifiedPayloadMismatch,

    // P2P Errors
    #[error("Unable to send message")]
    UnableToSendMessage,

    // Broadcast errors
    #[error("Already broadcast")]
    AlreadyBroadcast,
    #[error("I am not a sequencer in epoch {0}")]
    IAmNotASequencer(u64),
    #[error("Nothing to rebroadcast")]
    NothingToRebroadcast,
    #[error("Broadcast failed")]
    BroadcastFailed,
    #[error("No threshold for tip")]
    NoThresholdForTip(u64),

    // Proto Malformed Errors
    #[error("Missing chunk")]
    MissingChunk,
    #[error("Genesis chunk must not have a parent")]
    GenesisChunkMustNotHaveParent,
    #[error("Link missing parent")]
    LinkMissingParent,
    #[error("Invalid digest")]
    InvalidDigest,

    // Epoch Errors
    #[error("Unknown identity at epoch {0}")]
    UnknownIdentity(u64),
    #[error("Unknown signers at epoch {0}")]
    UnknownSigners(u64),
    #[error("Epoch {0} has no sequencer {1:?}")]
    UnknownSequencer(u64, Bytes),
    #[error("Epoch {0} has no signer {1:?}")]
    UnknownSigner(u64, Bytes),
    #[error("Unknown share at epoch {0}")]
    UnknownShare(u64),

    // Peer Errors
    #[error("Peer mismatch")]
    PeerMismatch,

    // Signature Errors
    #[error("Unable to deserialize threshold signature")]
    UnableToDeserializeThresholdSignature,
    #[error("Unable to deserialize partial signature")]
    UnableToDeserializePartialSignature,
    #[error("Invalid threshold signature")]
    InvalidThresholdSignature,
    #[error("Invalid partial signature")]
    InvalidPartialSignature,
    #[error("Invalid link signature")]
    InvalidLinkSignature,

    // Ignorable Message Errors
    #[error("Invalid ack epoch {0} outside bounds {1} - {2}")]
    AckEpochOutsideBounds(u64, u64, u64),
    #[error("Invalid ack height {0} outside bounds {1} - {2}")]
    AckHeightOutsideBounds(u64, u64, u64),
    #[error("Chunk height {0} lower than tip height {1}")]
    ChunkHeightTooLow(u64, u64),

    // Slashable Errors
    #[error("Chunk mismatch from sender {0:?} with height {1}")]
    ChunkMismatch(Bytes, u64),
}
