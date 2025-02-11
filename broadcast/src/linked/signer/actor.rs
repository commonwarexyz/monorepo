use super::{AckManager, Config, Mailbox, Message, TipManager};
use crate::{
    linked::{namespace, prover::Prover, safe, serializer, Context, Epoch},
    Application, Collector, ThresholdCoordinator,
};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{self},
        ops,
        poly::{self},
    },
    Array, Scheme,
};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Blob, Clock, Spawner, Storage};
use commonware_storage::journal::{self, variable::Journal};
use futures::{
    channel::{mpsc, oneshot},
    future::{self, Either},
    pin_mut,
    stream::FuturesUnordered,
    StreamExt,
};
use prometheus_client::registry::Registry;
use std::{
    collections::BTreeMap,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use thiserror::Error;
use tracing::{debug, error, info, warn};

/// A future representing a request to the application to verify a payload.
type VerifyFuture<D, P> =
    Pin<Box<dyn Future<Output = (Context<P>, D, Result<bool, Error>)> + Send>>;

/// The actor that implements the Broadcaster trait.
pub struct Actor<
    B: Blob,
    E: Clock + Spawner + Storage<B>,
    C: Scheme,
    D: Array,
    J: Fn(&C::PublicKey) -> String,
    A: Application<Context = Context<C::PublicKey>, Digest = D> + Clone,
    Z: Collector<Context = Context<C::PublicKey>, Digest = D>,
    S: ThresholdCoordinator<
        Index = Epoch,
        Share = group::Share,
        Identity = poly::Public,
        PublicKey = C::PublicKey,
    >,
> {
    ////////////////////////////////////////
    // Interfaces
    ////////////////////////////////////////
    runtime: E,
    crypto: C,
    coordinator: S,
    application: A,
    collector: Z,
    _digest: PhantomData<D>,

    ////////////////////////////////////////
    // Namespace Constants
    ////////////////////////////////////////

    // The namespace for chunk signatures.
    chunk_namespace: Vec<u8>,

    // The namespace for ack signatures.
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

    // A stream of futures.
    // Each future represents a verification request to the application
    // that will either timeout or resolve with a boolean.
    pending_verifies: FuturesUnordered<VerifyFuture<D, C::PublicKey>>,

    // The maximum number of items in `pending_verifies`.
    pending_verify_size: usize,

    // The mailbox for receiving messages (primarily from the application).
    mailbox_receiver: mpsc::Receiver<Message<D>>,

    ////////////////////////////////////////
    // Storage
    ////////////////////////////////////////

    // The number of heights per each journal section.
    journal_heights_per_section: u64,

    // The number of concurrent operations when replaying journals.
    journal_replay_concurrency: usize,

    // A function that returns the partition name for a sequencer.
    journal_naming_fn: J,

    // A map of sequencer public keys to their journals.
    journals: BTreeMap<C::PublicKey, Journal<B, E>>,

    ////////////////////////////////////////
    // State
    ////////////////////////////////////////

    // Tracks the current tip for each sequencer.
    // The tip is a `Link` which is comprised of a `Chunk` and,
    // if not the genesis chunk for that sequencer,
    // a threshold signature over the parent chunk.
    tip_manager: TipManager<C, D>,

    // Tracks the acknowledgements for chunks.
    // This is comprised of partial signatures or threshold signatures.
    ack_manager: AckManager<D, C::PublicKey>,

    // The current epoch.
    epoch: Epoch,
}

impl<
        B: Blob,
        E: Clock + Spawner + Storage<B>,
        C: Scheme,
        D: Array,
        J: Fn(&C::PublicKey) -> String,
        A: Application<Context = Context<C::PublicKey>, Digest = D> + Clone,
        Z: Collector<Context = Context<C::PublicKey>, Digest = D>,
        S: ThresholdCoordinator<
            Index = Epoch,
            Share = group::Share,
            Identity = poly::Public,
            PublicKey = C::PublicKey,
        >,
    > Actor<B, E, C, D, J, A, Z, S>
{
    /// Creates a new actor with the given runtime and configuration.
    /// Returns the actor and a mailbox for sending messages to the actor.
    pub fn new(runtime: E, cfg: Config<C, D, J, A, Z, S>) -> (Self, Mailbox<D>) {
        let (mailbox_sender, mailbox_receiver) = mpsc::channel(cfg.mailbox_size);
        let mailbox = Mailbox::new(mailbox_sender);

        // Initialize the pending verification futures.
        let pending_verifies = FuturesUnordered::new();
        {
            // Inserts a dummy future (that never resolves) to prevent the stream from being empty.
            // If the stream were empty, the `select_next_some()` function would return `None`
            // instantly, front-running all other branches in the `select!` macro.
            let dummy: VerifyFuture<D, C::PublicKey> = Box::pin(async {
                future::pending::<(Context<C::PublicKey>, D, Result<bool, Error>)>().await
            });
            pending_verifies.push(dummy);
        }

        let result = Self {
            runtime,
            crypto: cfg.crypto,
            _digest: PhantomData,
            coordinator: cfg.coordinator,
            application: cfg.application,
            collector: cfg.collector,
            chunk_namespace: namespace::chunk(&cfg.namespace),
            ack_namespace: namespace::ack(&cfg.namespace),
            refresh_epoch_timeout: cfg.refresh_epoch_timeout,
            refresh_epoch_deadline: None,
            rebroadcast_timeout: cfg.rebroadcast_timeout,
            rebroadcast_deadline: None,
            epoch_bounds: cfg.epoch_bounds,
            height_bound: cfg.height_bound,
            pending_verifies,
            pending_verify_size: cfg.pending_verify_size,
            mailbox_receiver,
            journal_heights_per_section: cfg.journal_heights_per_section,
            journal_replay_concurrency: cfg.journal_replay_concurrency,
            journal_naming_fn: cfg.journal_naming_fn,
            journals: BTreeMap::new(),
            tip_manager: TipManager::<C, D>::new(),
            ack_manager: AckManager::<D, C::PublicKey>::new(),
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
        chunk_network: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        ack_network: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
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
            info!(err=?e, "Failed initial rebroadcast");
        }

        loop {
            // Enter the epoch
            self.refresh_epoch();

            // Create deadline futures.
            // If the deadline is None, the future will never resolve.
            let refresh_epoch = match self.refresh_epoch_deadline {
                Some(deadline) => Either::Left(self.runtime.sleep_until(deadline)),
                None => Either::Right(future::pending()),
            };
            let rebroadcast = match self.rebroadcast_deadline {
                Some(deadline) => Either::Left(self.runtime.sleep_until(deadline)),
                None => Either::Right(future::pending()),
            };

            select! {
                // Handle shutdown signal
                _ = &mut shutdown => {
                    debug!("Shutdown");
                    while let Some((_, journal)) = self.journals.pop_first() {
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
                        error!(err=?e, "Failed to rebroadcast");
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
                    let Ok(link) = safe::Link::<C, D>::decode(&msg) else {
                        error!("Failed to decode link");
                        continue;
                    };
                    if let Err(e) = self.validate_link(&link, &sender) {
                        error!(err=?e, "Failed to validate link");
                        continue;
                    };

                    // Initialize journal for sequencer if it does not exist
                    self.journal_prepare(&sender).await;

                    // Handle the parent threshold signature
                    if let Some(parent) = link.parent.as_ref() {
                        self.handle_threshold(&link.chunk, parent.epoch, parent.threshold).await;
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
                    let ack = match safe::Ack::decode(&msg) {
                        Ok(ack) => ack,
                        Err(e) => {
                            error!(err=?e, "Failed to decode ack");
                            continue;
                        }
                    };
                    if let Err(e) = self.validate_ack(&ack, &sender) {
                        error!(err=?e, "Failed to validate ack");
                        continue;
                    };
                    if let Err(e) = self.handle_ack(ack).await {
                        error!(err=?e, "Failed to handle ack");
                        continue;
                    }
                },

                // Handle completed verification futures.
                maybe_verified = self.pending_verifies.select_next_some() => {
                    let (context, digest, verify_result) = maybe_verified;
                    match verify_result {
                        Ok(true) => {
                            debug!("Verification successful for context: {:?}, digest: {:?}", context, digest);
                            if let Err(e) = self.handle_app_verified(&context, &digest, &mut ack_sender).await {
                                error!(err=?e, "Failed to handle app verified");
                            }
                        },
                        Ok(false) => {
                            warn!("Application returned false for verify request");
                        },
                        Err(e) => {
                            warn!(err=?e, "Verification error or timeout");
                        },
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
                            if self.coordinator.is_sequencer(self.epoch, &self.crypto.public_key()).is_none() {
                                error!("Not a sequencer in the current epoch");
                                continue;
                            }

                            // Broadcast the message
                            if let Err(e) = self.broadcast_new(payload, result, &mut link_sender).await {
                                error!(err=?e, "Failed to broadcast new");
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
        context: &Context<C::PublicKey>,
        payload: &D,
        ack_sender: &mut impl Sender<PublicKey = C::PublicKey>,
    ) -> Result<(), Error> {
        // Get the tip
        let Some(tip) = self.tip_manager.get(&context.sequencer) else {
            return Err(Error::AppVerifiedNoTip);
        };

        // Return early if the height does not match
        if tip.chunk.height != context.height {
            return Err(Error::AppVerifiedHeightMismatch);
        }

        // Return early if the payload digest does not match
        if tip.chunk.payload != *payload {
            return Err(Error::AppVerifiedPayloadMismatch);
        }

        // Construct partial signature
        let Some(share) = self.coordinator.share(self.epoch) else {
            return Err(Error::UnknownShare(self.epoch));
        };
        let partial = ops::partial_sign_message(
            share,
            Some(&self.ack_namespace),
            &serializer::ack(&tip.chunk, self.epoch),
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
                .is_signer(self.epoch, &tip.chunk.sequencer)
                .is_none()
            {
                recipients.push(tip.chunk.sequencer.clone());
            }
            recipients
        };

        // Send the ack to the network
        let ack = safe::Ack::<D, C::PublicKey> {
            chunk: tip.chunk,
            epoch: self.epoch,
            partial,
        };
        ack_sender
            .send(
                Recipients::Some(recipients),
                ack.encode().map_err(Error::CannotEncode)?,
                false,
            )
            .await
            .map_err(|_| Error::UnableToSendMessage)?;

        // Handle the ack internally
        self.handle_ack(ack).await?;

        Ok(())
    }

    /// Handles a threshold, either received from a link from the network or generated locally.
    ///
    /// The threshold must already be verified.
    /// If the threshold is new, it is stored and the proof is emitted to the collector.
    /// If the threshold is already known, it is ignored.
    async fn handle_threshold(
        &mut self,
        chunk: &safe::Chunk<D, C::PublicKey>,
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
        let proof =
            Prover::<C, D>::serialize_threshold(&context, &chunk.payload, epoch, &threshold);
        self.collector
            .acknowledged(context, chunk.payload.clone(), proof)
            .await;
    }

    /// Handles an ack
    ///
    /// Returns an error if the ack is invalid, or can be ignored
    /// (e.g. already exists, threshold already exists, is outside the epoch bounds, etc.).
    async fn handle_ack(&mut self, ack: safe::Ack<D, C::PublicKey>) -> Result<(), Error> {
        // Get the quorum
        let Some(identity) = self.coordinator.identity(ack.epoch) else {
            return Err(Error::UnknownIdentity(ack.epoch));
        };
        let quorum = identity.required();

        // Add the partial signature. If a new threshold is formed, handle it.
        if let Some(threshold) = self.ack_manager.add_ack(&ack, quorum) {
            // Handle the threshold signature
            self.handle_threshold(&ack.chunk, ack.epoch, threshold)
                .await;
        }

        Ok(())
    }

    /// Handles a valid link message, storing it as the tip.
    /// Alerts the application of the new link.
    /// Also appends the link to the journal if it's new.
    async fn handle_link(&mut self, link: &safe::Link<C, D>) {
        // Store the tip
        let is_new = self.tip_manager.put(link);

        // Append to journal if the link is new, making sure to sync the journal
        // to prevent sending two conflicting chunks to the application, even if
        // the node crashes and restarts.
        if is_new {
            self.journal_append(link).await;
            self.journal_sync(&link.chunk.sequencer, link.chunk.height)
                .await;
        }

        // Ignore sending the verification request to the application
        // if the number of pending requests is too high.
        // We use > instead of >= because the stream always has one dummy future.
        if self.pending_verifies.len() > self.pending_verify_size {
            warn!("Too many concurrent requests to application");
            return;
        }

        // Verify the chunk with the application
        let context = Context {
            sequencer: link.chunk.sequencer.clone(),
            height: link.chunk.height,
        };
        let payload = link.chunk.payload.clone();
        let mut app_clone = self.application.clone();
        let verify_future = Box::pin(async move {
            let receiver = app_clone.verify(context.clone(), payload.clone()).await;
            let result = receiver.await.map_err(Error::AppVerifyCanceled);
            (context, payload, result)
        });

        // Save the verification future
        self.pending_verifies.push(verify_future);
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
        payload: D,
        result: oneshot::Sender<bool>,
        link_sender: &mut impl Sender<PublicKey = C::PublicKey>,
    ) -> Result<(), Error> {
        let me = self.crypto.public_key();

        // Get parent Chunk and threshold signature
        let mut height = 0;
        let mut parent = None;
        if let Some(tip) = self.tip_manager.get(&me) {
            // Get threshold, or, if it doesn't exist, return an error
            let Some((epoch, threshold)) = self.ack_manager.get_threshold(&me, tip.chunk.height)
            else {
                let _ = result.send(false);
                return Err(Error::NoThresholdForTip(tip.chunk.height));
            };

            // Update height and parent
            height = tip.chunk.height + 1;
            parent = Some(safe::Parent::<D> {
                payload: tip.chunk.payload,
                threshold,
                epoch,
            });
        }

        // Construct new link
        let chunk = safe::Chunk::<D, C::PublicKey> {
            sequencer: me.clone(),
            height,
            payload,
        };
        let signature = self
            .crypto
            .sign(Some(&self.chunk_namespace), &serializer::chunk(&chunk));
        let link = safe::Link::<C, D> {
            chunk,
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
            error!(err=?e, "Failed to broadcast link");
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
    async fn rebroadcast(
        &mut self,
        link_sender: &mut impl Sender<PublicKey = C::PublicKey>,
    ) -> Result<(), Error> {
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
            .get_threshold(&me, link_tip.chunk.height)
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
        link: &safe::Link<C, D>,
        link_sender: &mut impl Sender<PublicKey = C::PublicKey>,
        epoch: Epoch,
    ) -> Result<(), Error> {
        // Send the link to all signers
        let Some(signers) = self.coordinator.signers(epoch) else {
            return Err(Error::UnknownSigners(epoch));
        };
        link_sender
            .send(
                Recipients::Some(signers.clone()),
                link.encode().map_err(Error::CannotEncode)?,
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
        link: &safe::Link<C, D>,
        sender: &C::PublicKey,
    ) -> Result<(), Error> {
        // Validate chunk
        self.validate_chunk(&link.chunk, self.epoch)?;

        // Verify the sender
        if link.chunk.sequencer != *sender {
            return Err(Error::PeerMismatch);
        }

        // Verify the signature
        // TODO (Optimization): If the link is equal to the tip, don't verify
        if !C::verify(
            Some(&self.chunk_namespace),
            &serializer::chunk(&link.chunk),
            sender,
            &link.signature.clone(),
        ) {
            return Err(Error::InvalidLinkSignature);
        }

        // Verify no parent
        if link.chunk.height == 0 {
            if link.parent.is_some() {
                return Err(Error::GenesisChunkMustNotHaveParent);
            }
            return Ok(());
        }

        // Verify parent
        let Some(parent) = &link.parent else {
            return Err(Error::LinkMissingParent);
        };
        let parent_chunk = safe::Chunk::<D, C::PublicKey> {
            sequencer: sender.clone(),
            height: link.chunk.height.checked_sub(1).unwrap(),
            payload: parent.payload.clone(),
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
            &parent.threshold,
        )
        .map_err(|_| Error::InvalidThresholdSignature)?;

        Ok(())
    }

    /// Takes a raw ack (from sender) from the p2p network and validates it.
    ///
    /// Returns the chunk, epoch, and partial signature if the ack is valid.
    /// Returns an error if the ack is invalid.
    fn validate_ack(
        &self,
        ack: &safe::Ack<D, C::PublicKey>,
        sender: &C::PublicKey,
    ) -> Result<(), Error> {
        // Validate chunk
        self.validate_chunk(&ack.chunk, ack.epoch)?;

        // Validate sender
        let Some(signer_index) = self.coordinator.is_signer(ack.epoch, sender) else {
            return Err(Error::UnknownSigner(ack.epoch, sender.to_string()));
        };
        if signer_index != ack.partial.index {
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
            let bound_lo = self
                .tip_manager
                .get(&ack.chunk.sequencer)
                .map(|t| t.chunk.height)
                .unwrap_or(0);
            let bound_hi = bound_lo + self.height_bound;
            if ack.chunk.height < bound_lo || ack.chunk.height > bound_hi {
                return Err(Error::AckHeightOutsideBounds(
                    ack.chunk.height,
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
            &serializer::ack(&ack.chunk, ack.epoch),
            &ack.partial,
        )
        .map_err(|_| Error::InvalidPartialSignature)?;

        Ok(())
    }

    /// Takes a raw chunk from the p2p network and validates it against the epoch.
    ///
    /// Returns the chunk if the chunk is valid.
    /// Returns an error if the chunk is invalid.
    fn validate_chunk(
        &self,
        chunk: &safe::Chunk<D, C::PublicKey>,
        epoch: Epoch,
    ) -> Result<(), Error> {
        // Verify sequencer
        if self
            .coordinator
            .is_sequencer(epoch, &chunk.sequencer)
            .is_none()
        {
            return Err(Error::UnknownSequencer(epoch, chunk.sequencer.to_string()));
        }

        // Verify height
        if let Some(tip) = self.tip_manager.get(&chunk.sequencer) {
            // Height must be at least the tip height
            match chunk.height.cmp(&tip.chunk.height) {
                std::cmp::Ordering::Less => {
                    return Err(Error::ChunkHeightTooLow(chunk.height, tip.chunk.height));
                }
                std::cmp::Ordering::Equal => {
                    // Ensure this matches the tip if the height is the same
                    if tip.chunk.payload != chunk.payload {
                        return Err(Error::ChunkMismatch(
                            chunk.sequencer.to_string(),
                            chunk.height,
                        ));
                    }
                }
                std::cmp::Ordering::Greater => {}
            }
        }

        Ok(())
    }

    ////////////////////////////////////////
    // Journal
    ////////////////////////////////////////

    /// Returns the section of the journal for the given height.
    fn get_journal_section(&self, height: u64) -> u64 {
        height / self.journal_heights_per_section
    }

    /// Ensures the journal exists and is initialized for the given sequencer.
    /// If the journal does not exist, it is created and replayed.
    /// Else, no action is taken.
    async fn journal_prepare(&mut self, sequencer: &C::PublicKey) {
        // Return early if the journal already exists
        if self.journals.contains_key(sequencer) {
            return;
        }

        // Initialize journal
        let cfg = journal::variable::Config {
            registry: Arc::new(Mutex::new(Registry::default())),
            partition: (self.journal_naming_fn)(sequencer),
        };
        let mut journal = Journal::init(self.runtime.clone(), cfg)
            .await
            .expect("unable to init journal");

        // Replay journal
        {
            debug!(?sequencer, "Replaying journal");

            // Prepare the stream
            let stream = journal
                .replay(self.journal_replay_concurrency, None)
                .await
                .expect("unable to replay journal");
            pin_mut!(stream);

            // Read from the stream, which may be in arbitrary order.
            // Remember the highest link height
            let mut tip: Option<safe::Link<C, D>> = None;
            let mut num_items = 0;
            while let Some(msg) = stream.next().await {
                num_items += 1;
                let (_, _, _, msg) = msg.expect("unable to decode journal message");
                let link =
                    safe::Link::<C, D>::decode(&msg).expect("journal message is unexpected format");
                let height = link.chunk.height;
                match tip {
                    None => {
                        tip = Some(link);
                    }
                    Some(ref t) => {
                        if height > t.chunk.height {
                            tip = Some(link);
                        }
                    }
                }
            }

            // Set the tip only once. The items from the journal may be in arbitrary order,
            // and the tip manager will panic if inserting tips out-of-order.
            if let Some(link) = tip.take() {
                let is_new = self.tip_manager.put(&link);
                assert!(is_new);
            }

            debug!(?sequencer, ?num_items, "Journal replay complete");
        }

        // Store journal
        self.journals.insert(sequencer.clone(), journal);
    }

    /// Write a link to the appropriate journal.
    ///
    /// The journal must already be open and replayed.
    async fn journal_append(&mut self, link: &safe::Link<C, D>) {
        let section = self.get_journal_section(link.chunk.height);
        let data = link
            .encode()
            .map_err(Error::CannotEncode)
            .expect("unable to encode link");
        self.journals
            .get_mut(&link.chunk.sequencer)
            .expect("journal does not exist")
            .append(section, data)
            .await
            .expect("unable to append to journal");
    }

    /// Syncs (ensures all data is written to disk) and prunes the journal for the given sequencer and height.
    async fn journal_sync(&mut self, sequencer: &C::PublicKey, height: u64) {
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
        assert!(epoch >= self.epoch);

        // Update the epoch
        self.epoch = epoch;
    }
}

/// Errors that can occur when running the actor.
#[derive(Error, Debug)]
enum Error {
    // Application Verification Errors
    #[error("Application verify error: {0}")]
    AppVerifyCanceled(oneshot::Canceled),
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
    #[error("Genesis chunk must not have a parent")]
    GenesisChunkMustNotHaveParent,
    #[error("Link missing parent")]
    LinkMissingParent,
    #[error("Cannot encode")]
    CannotEncode(#[from] safe::Error),

    // Epoch Errors
    #[error("Unknown identity at epoch {0}")]
    UnknownIdentity(u64),
    #[error("Unknown signers at epoch {0}")]
    UnknownSigners(u64),
    #[error("Epoch {0} has no sequencer {1}")]
    UnknownSequencer(u64, String),
    #[error("Epoch {0} has no signer {1}")]
    UnknownSigner(u64, String),
    #[error("Unknown share at epoch {0}")]
    UnknownShare(u64),

    // Peer Errors
    #[error("Peer mismatch")]
    PeerMismatch,

    // Signature Errors
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
    #[error("Chunk mismatch from sender {0} with height {1}")]
    ChunkMismatch(String, u64),
}
