use super::{AckManager, Config, Evidence, Mailbox, Message, TipManager};
use crate::{
    linked::{encoder, prover::Prover, wire, Context, Epoch},
    Application, Collector, Digest, Error, ThresholdCoordinator,
};
use bytes::Bytes;
use commonware_cryptography::{
    bls12381::primitives::{
        group::{self, Element},
        ops,
        poly::{self, PartialSignature},
    },
    Hasher, PublicKey, Scheme,
};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Blob, Clock, Spawner, Storage};
use commonware_storage::journal::{self, Journal};
use futures::{
    channel::{mpsc, oneshot},
    future::Either,
    pin_mut, StreamExt,
};
use prometheus_client::registry::Registry;
use prost::Message as _;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
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
    rebroadcast_timeout: Option<Duration>,
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
    // Storage
    ////////////////////////////////////////
    journal_entries_per_section: u64,
    journal_replay_concurrency: usize,
    journal_naming_fn: fn(&PublicKey) -> String,
    journals: HashMap<PublicKey, Journal<B, E>>,

    ////////////////////////////////////////
    // State
    ////////////////////////////////////////
    tip_man: TipManager,

    // Handles acknowledgements for chunks.
    ack_man: AckManager,

    // The current epoch.
    epoch: Epoch,
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
    pub fn new(runtime: E, cfg: Config<C, H, A, Z, S>) -> (Self, Mailbox) {
        let (mailbox_sender, mailbox_receiver) = mpsc::channel(cfg.mailbox_size);
        let mailbox = Mailbox::new(mailbox_sender);
        let result = Self {
            runtime,
            crypto: cfg.crypto,
            hasher: cfg.hasher,
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
            mailbox_receiver,
            journal_entries_per_section: cfg.journal_entries_per_section,
            journal_replay_concurrency: cfg.journal_replay_concurrency,
            journal_naming_fn: cfg.journal_naming_fn,
            journals: HashMap::new(),
            tip_man: TipManager::default(),
            ack_man: AckManager::default(),
            epoch: 0,
        };

        (result, mailbox)
    }

    /// Runs the actor until the runtime is stopped.
    ///
    /// The actor will handle:
    /// - Timeouts
    ///   - Rebroadcasting Links
    ///   - Pruning old evidence
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

        loop {
            // Enter the epoch
            self.refresh_epoch();

            // Create deadline futures.
            // If the deadline is None, the future will never resolve.
            let rebroadcast = match self.rebroadcast_deadline {
                Some(deadline) => Either::Left(self.runtime.sleep_until(deadline)),
                None => Either::Right(futures::future::pending()),
            };
            let refresh_epoch = match self.refresh_epoch_deadline {
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

                // Handle rebroadcast deadline
                _ = rebroadcast => {
                    debug!("Timeout: Rebroadcast");
                    if let Err(e) = self.rebroadcast(&mut link_sender).await {
                        error!("Failed to rebroadcast: {:?}", e);
                        continue;
                    }
                },

                // Handle prune deadline
                _ = refresh_epoch => {
                    debug!("Timeout: Refresh Epoch");
                    // Simply continue; the epoch will be refreshed on the next iteration.
                    continue;
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
                    if let Err(e) = self.handle_ack(&chunk, epoch, partial).await {
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
                        Message::Broadcast{ payload, result } => {
                            debug!("Mailbox: Broadcast");
                            // Initialize my journal if it does not exist
                            self.journal_prepare(&self.crypto.public_key()).await;

                            // Broadcast the message
                            if let Err(e) = self.broadcast_new(payload, result, &mut link_sender).await {
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
        payload_digest: &Digest,
        ack_sender: &mut impl Sender,
    ) -> Result<(), Error> {
        // Get the tip
        let Some(chunk) = self.tip_man.get_chunk(&context.sequencer) else {
            return Err(Error::AppVerifiedNoTip);
        };

        // Return early if the height does not match
        if chunk.height != context.height {
            error!("App-verified payload height does not match tip");
            return Err(Error::AppVerifiedHeightMismatch);
        }

        // Return early if the payload digest does not match
        if chunk.payload_digest != payload_digest {
            error!("App-verified payload does not match tip");
            return Err(Error::AppVerifiedPayloadMismatch);
        }

        // Construct partial signature
        let ack_digest = self.hash_ack(&chunk, self.epoch);
        let Some(share) = self.coordinator.share(self.epoch) else {
            return Err(Error::UnknownShare(self.epoch));
        };
        let partial: Bytes =
            ops::partial_sign_message(share, Some(&self.ack_namespace), &ack_digest)
                .serialize()
                .into();

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
            partial: partial.clone(),
        };
        ack_sender
            .send(
                Recipients::Some(recipients),
                ack.encode_to_vec().into(),
                false,
            )
            .await
            .map_err(|_| Error::UnableToSendMessage)?;

        // Deal with the ack as if it were received over the network
        self.handle_ack(&chunk, self.epoch, partial).await?;

        Ok(())
    }

    /// Handles a threshold, either received from a link from the network or generated locally.
    ///
    /// Returns an error if the threshold already exists.
    async fn handle_threshold(
        &mut self,
        chunk: &wire::Chunk,
        epoch: Epoch,
        threshold: group::Signature,
    ) {
        // Check if the threshold signature is already known
        let evidence = self.ack_man.get_or_init(epoch, chunk);
        if let Evidence::Threshold(_) = evidence {
            return;
        }

        // The threshold signature is new, so store it
        *evidence = Evidence::Threshold(Box::new(threshold));

        // Emit the proof
        let context = Context {
            sequencer: chunk.sequencer.clone(),
            height: chunk.height,
        };
        let proof =
            Prover::<C, H>::serialize_threshold(&context, &chunk.payload_digest, epoch, &threshold);
        self.collector
            .acknowledged(context, chunk.payload_digest.clone(), proof)
            .await;
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
        let evidence = self.ack_man.get_or_init(ack_epoch, chunk);
        let partials = match evidence {
            Evidence::Threshold(_) => return Ok(()),
            Evidence::Partials(partials) => partials,
        };

        // Return early if we already have this partial
        if partials.contains(&partial) {
            debug!("Ignoring ack. Already have this partial.");
            return Ok(());
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
        self.handle_threshold(chunk, ack_epoch, threshold).await;

        Ok(())
    }

    /// Handles a valid link message, storing it as the tip.
    /// Alerts the application of the new link.
    /// Also appends the link to the journal if it's new.
    async fn handle_link(&mut self, link: &wire::Link) {
        // Store the tip
        let is_new = self.tip_man.put(link);
        let chunk = link.chunk.as_ref().unwrap();

        // Take actions if the link is new
        if is_new {
            // Append to journal
            self.journal_append(link).await;
            self.journal_sync(&chunk.sequencer, chunk.height).await;

            // Prune old evidence
            self.ack_man
                .prune_height(self.epoch, &chunk.sequencer, chunk.height);
        }

        // Verify the chunk with the application
        let context = Context {
            sequencer: chunk.sequencer.clone(),
            height: chunk.height,
        };
        self.application
            .verify(context, chunk.payload_digest.clone())
            .await;
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
        payload_digest: Bytes,
        result: oneshot::Sender<bool>,
        link_sender: &mut impl Sender,
    ) -> Result<(), Error> {
        let me = self.crypto.public_key();

        // Get parent Chunk and threshold signature
        let mut height = 0;
        let mut parent = None;
        if let Some(chunk_tip) = self.tip_man.get_chunk(&me) {
            // Get threshold or return early
            let Evidence::Threshold(threshold) = self.ack_man.get_or_init(self.epoch, &chunk_tip)
            else {
                let _ = result.send(false);
                return Err(Error::NoThresholdForTip(chunk_tip.height));
            };

            // Update height and parent
            height = chunk_tip.height + 1;
            parent = Some(wire::Parent {
                payload_digest: chunk_tip.payload_digest,
                threshold: threshold.serialize().into(),
                epoch: self.epoch,
            });
        }

        // Construct new link
        let chunk = wire::Chunk {
            sequencer: me.clone(),
            height,
            payload_digest: payload_digest.clone(),
        };
        let signature = {
            let chunk_digest = self.hash_chunk(&chunk);
            self.crypto.sign(Some(&self.chunk_namespace), &chunk_digest)
        };
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
        let Some(link_tip) = self.tip_man.get(&me) else {
            return Err(Error::NothingToRebroadcast);
        };

        // Return if threshold already collected
        if let Evidence::Threshold(_) = self
            .ack_man
            .get_or_init(self.epoch, link_tip.chunk.as_ref().unwrap())
        {
            return Err(Error::ThresholdAlreadyExists);
        }

        // Broadcast the message
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
        if let Some(timeout) = self.rebroadcast_timeout {
            self.rebroadcast_deadline = Some(self.runtime.current() + timeout);
        }

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
        let chunk_digest = self.hash_chunk(&chunk);
        if !C::verify(
            Some(&self.chunk_namespace),
            &chunk_digest,
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
        let Some(identity) = self.coordinator.identity(parent.epoch) else {
            return Err(Error::UnknownIdentity(parent.epoch));
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
        if let Some(chunk_tip) = self.tip_man.get_chunk(&chunk.sequencer) {
            // Height must be at least the tip height
            match chunk.height.cmp(&chunk_tip.height) {
                std::cmp::Ordering::Less => {
                    return Err(Error::HeightTooLow(chunk.height, chunk_tip.height));
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
        if chunk.payload_digest.len() != size_of::<H::Digest>() {
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
            // Prepare the stream
            let stream = journal
                .replay(self.journal_replay_concurrency, None)
                .await
                .expect("unable to replay journal");
            pin_mut!(stream);

            // Read from the stream, which may be in arbitrary order.
            // Remember the highest link height
            let mut tip: Option<wire::Link> = None;
            while let Some(msg) = stream.next().await {
                let (_, _, _, msg) = msg.expect("unable to decode journal message");
                let link = wire::Link::decode(msg).expect("journal message is unexpected format");
                let height = link.chunk.as_ref().unwrap().height;
                if tip.is_none() || height > tip.as_ref().unwrap().chunk.as_ref().unwrap().height {
                    tip = Some(link);
                }
            }

            // Set the tip
            if let Some(link) = tip.take() {
                let is_new = self.tip_man.put(&link);
                assert!(is_new);
            }
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
    /// Prunes old evidence if moving to a new epoch.
    fn refresh_epoch(&mut self) {
        // Set the refresh epoch deadline
        self.refresh_epoch_deadline = Some(self.runtime.current() + self.refresh_epoch_timeout);

        // Ensure epoch is not before the current epoch
        let epoch = self.coordinator.index();
        if epoch < self.epoch {
            panic!("epoch must be greater than or equal to the current epoch");
        }

        // Take no action if the epoch is the same
        if epoch == self.epoch {
            return;
        }

        // Update the epoch
        self.epoch = epoch;

        // Prune old evidence
        let epoch_to_prune = {
            let (eb_lo, _) = self.epoch_bounds;
            epoch.saturating_sub(eb_lo)
        };
        self.ack_man.prune_epoch(epoch_to_prune);
    }

    ////////////////////////////////////////
    // Hashing
    ////////////////////////////////////////

    /// Returns the digest of the given chunk
    fn hash_chunk(&mut self, chunk: &wire::Chunk) -> Digest {
        self.hasher.reset();
        self.hasher.update(&chunk.sequencer);
        self.hasher.update(&chunk.height.to_be_bytes());
        self.hasher.update(&chunk.payload_digest);
        self.hasher.finalize().into()
    }

    /// Returns the digest of the given ack
    fn hash_ack(&mut self, chunk: &wire::Chunk, epoch: Epoch) -> Digest {
        self.hasher.reset();
        self.hasher.update(&chunk.sequencer);
        self.hasher.update(&chunk.height.to_be_bytes());
        self.hasher.update(&chunk.payload_digest);
        self.hasher.update(&epoch.to_be_bytes());
        self.hasher.finalize().into()
    }
}
