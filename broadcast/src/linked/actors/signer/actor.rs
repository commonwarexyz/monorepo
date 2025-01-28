use super::{Config, Mailbox, Message};
use crate::{
    linked::{encoder, wire, Context, Epoch},
    Application, Collector, ThresholdCoordinator,
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
use std::{collections::{BTreeMap, HashMap, HashSet}, time::{Duration, SystemTime}};
use tracing::{debug, error};

enum Evidence {
    Partials(HashSet<Bytes>),
    Threshold(group::Signature),
}

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
    ack_namespace: Vec<u8>,
    chunk_namespace: Vec<u8>,

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

    // Acknowledgements for digests.
    //
    // Map from Epoch => Sequencer => Height => Digest => Evidence
    //
    // Evidence may be partial signatures or threshold signatures.
    // 
    // The BTreeMaps are sorted by key, so we can prune old entries. In particular, we can prune
    // entries where the height is less than the height of the highest chunk for the sequencer.
    // We can often prune entries for old epochs as well.
    acks: BTreeMap<Epoch, HashMap<PublicKey, BTreeMap<u64, HashMap<Digest, Evidence>>>>,
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
            ack_namespace: encoder::ack_namespace(&cfg.namespace),
            chunk_namespace: encoder::chunk_namespace(&cfg.namespace),
            mailbox_receiver,
            tips: HashMap::new(),
        };

        (result, mailbox)
    }

    pub async fn run(
        mut self,
        chunk_network: (impl Sender, impl Receiver),
        ack_network: (impl Sender, impl Receiver),
    ) {
        let (mut chunk_sender, mut chunk_receiver) = chunk_network;
        let (mut ack_sender, mut ack_receiver) = ack_network;
        let mut shutdown = self.runtime.stopped();
        let mut rebroadcast_deadline = 

        loop {
            let rebroadcast_deadline = self.rebroadcast_deadline;
            select! {
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
                _ = self.runtime.sleep_until(self.rebroadcast_deadline) => {
                    debug!("Rebroadcasting");
                    self.rebroadcast(&mut chunk_sender).await;
                },
                msg = chunk_receiver.recv() => {
                    debug!("Received chunk");
                    // Error handling
                    let Ok((sender, msg)) = msg else {
                        error!("chunk_receiver failed");
                        break;
                    };
                    let Ok(chunk) = wire::Chunk::decode(msg) else {
                        error!("Failed to decode chunk");
                        continue;
                    };
                    if sender != chunk.sequencer {
                        error!("Received chunk from wrong sender");
                        continue;
                    };
                    self.handle_chunk(&chunk, &mut ack_sender).await;
                },
                msg = ack_receiver.recv() => {
                    debug!("Received ack");
                    // Error handling
                    let Ok((_sender, msg)) = msg else {
                        error!("ack_receiver failed");
                        break;
                    };
                    let Ok(ack) = wire::Ack::decode(msg) else {
                        error!("Failed to decode ack");
                        continue;
                    };
                    let Some(public_key) = self.verify_ack(&ack) else {
                        error!("Failed to verify ack");
                        continue;
                    };
                    self.handle_ack(&public_key.clone(), &ack).await;
                },
                mail = self.mailbox_receiver.next() => {
                    debug!("Received mailbox message");
                    let msg = match mail {
                        Some(msg) => msg,
                        None => break,
                    };
                    match msg {
                        Message::Broadcast{ payload, result } => {
                            self.broadcast(payload, result, &mut chunk_sender, &mut ack_sender).await;
                        }
                    }
                }
            }
        };
    }

    async fn handle_ack(&mut self, signer: &PublicKey, ack: &wire::Ack) {
        // Signature should already be verified

        // If the ack is for a non-relevant height, epoch, etc., ignore.
        if let Some(tip) = self.tips.get(&ack.sequencer) {
            if ack.height < tip.height {
                debug!("Ignoring ack. Chunk height {:?} < tip height {:?}", ack.height, tip.height);
                return;
            }
        }

        // If the ack is for an epoch that is too old or too new, ignore.
        let epoch = self.coordinator.index();
        let (eb_lo, eb_hi) = self.epoch_bounds;
        let (epoch_bound_lo, epoch_bound_hi) = (epoch.saturating_sub(eb_lo), epoch.saturating_add(eb_hi));
        if ack.epoch < epoch_bound_lo || ack.epoch > epoch_bound_hi {
            debug!("Ignoring ack. Epoch {:?} outside bounds [{:?}-{:?}]", ack.epoch, epoch_bound_lo, epoch_bound_hi);
            return;
        }

        // Check that the sequencer is valid
        // (The signer should already have been checked for validity)
        if self.coordinator.is_sequencer(epoch, &ack.sequencer).is_none() {
            debug!("Ignoring ack. Epoch {:?} has no sequencer {:?}", ack.epoch, ack.sequencer);
            return;
        }
        if self.coordinator.is_signer(ack.epoch, signer).is_none() {
            debug!("Ignoring ack. Epoch {:?} has no signer {:?}", ack.epoch, signer);
            return;
        }

        // Get the partial signatures, returning early if we already have a threshold
        let evidence = self.acks.entry(epoch).or_insert_with(HashMap::new)
            .entry(ack.sequencer.clone()).or_insert_with(BTreeMap::new)
            .entry(ack.height).or_insert_with(HashMap::new)
            .entry(ack.chunk_digest.clone()).or_insert_with(|| Evidence::Partials(HashSet::new()));
        let Evidence::Partials(partials) = evidence else {
            debug!("Ignoring ack. Threshold already exists.");
            return;
        };

        // Return early if we already have this partial
        if partials.contains(&ack.partial) {
            debug!("Ignoring ack. Already have this partial.");
            return;
        }

        // Store the ack
        partials.insert(ack.partial.clone());

        // Return early if we don't have enough partials
        let Some(identity) = self.coordinator.identity(ack.epoch) else {
            error!("Failed to get identity for epoch {:?}", ack.epoch);
            return;
        };
        let quorum = identity.required();
        if partials.len() < quorum as usize {
            return;
        }

        // Construct the threshold signature
        let partials: Vec<PartialSignature> = partials
            .iter()
            .map(|p| PartialSignature::deserialize(p).unwrap())
            .collect();
        let threshold = ops::threshold_signature_recover(quorum, partials).unwrap();
        let threshold_bytes = threshold.serialize().into();

        // Store the threshold by replacing the partials
        *evidence = Evidence::Threshold(threshold);

        // Emit the proof to the application
        let Some(tip) = self.tips.get(&sequencer) else {
            error!("Failed to get tip");
            return;
        };
        if !self.ack_matches_chunk(ack, chunk) {
            error!("Ack does not match chunk");
            return;
        }
        let context = Context { sequencer: ack.sequencer, height: ack.height };
        self.collector
            .acknowledged(context, tip.payload_digest, threshold_bytes)
            .await;
    }

    async fn handle_chunk(&mut self, chunk: &wire::Chunk, ack_sender: &mut impl Sender) {
        // If Chunk is at or behind the tip, ignore.
        // This check is fast, so we do it before full validation.
        if let Some(tip) = self.tips.get(&chunk.sequencer) {
            if tip.height >= chunk.height {
                return;
            }
        }

        // Validate that the chunk is well-formed
        if !self.verify_chunk(chunk) {
            return;
        }

        // Validate the chunk with the application
        let context = Context {
            sequencer: chunk.sequencer.clone(),
            height: chunk.height,
        };
        match self
        .application
        .verify(context, chunk.payload_digest.clone())
        .await {
            Ok(true) => {}
            Ok(false) => {
                error!("Application rejected chunk");
                return;
            }
            Err(e) => {
                error!("Failed to verify chunk with application: {:?}", e);
                return;
            }
        }

        // Emit evidence of parent to the application if the height is greater than 0
        if let Some(parent) = &chunk.parent {
            let context = Context {
                sequencer: chunk.sequencer.clone(),
                height: chunk.height.checked_sub(1).unwrap(),
            };
            self.collector
                .acknowledged(
                    context,
                    parent.chunk_digest.clone(),
                    parent.threshold.clone(),
                )
                .await;
        }

        // Compute the digest before inserting to avoid borrow conflicts
        let chunk_digest = self.hash_chunk(chunk);
        self.tips.insert(
            chunk.sequencer.clone(),
            chunk.clone(),
        );

        // Construct new ack.
        let epoch = self.coordinator.index();
        let mut ack = wire::Ack {
            sequencer: chunk.sequencer.clone(),
            height: chunk.height,
            chunk_digest,
            epoch,
            partial: Bytes::new(), // Unsigned
        };

        // Construct partial signature
        let ack_digest = self.hash_ack(&ack);
        let Some(share) = self.coordinator.share(epoch) else {
            error!("Failed to get share for epoch {:?}", epoch);
            return;
        };
        ack.partial = ops::partial_sign_message(share, Some(&self.ack_namespace), &ack_digest)
            .serialize()
            .into();

        // Deal with the ack as if it were received over the network
        self.handle_ack(&self.crypto.public_key(), &ack).await;

        // Send the ack to the network
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
    async fn broadcast(
        &mut self,
        payload_digest: Bytes,
        result: oneshot::Sender<bool>,
        chunk_sender: &mut impl Sender,
        ack_sender: &mut impl Sender,
    ) {
        let public_key = self.crypto.public_key();

        // Get parent Chunk and threshold signature
        let mut height = 0;
        let mut parent = None;
        if let Some(tip) = self.tips.get(&public_key) {
            let tip_digest = self.hash_chunk(tip.clone());
            let tholdself.acks.get(&self.coordinator.index())
                .unwrap().get(&public_key)
                .unwrap().get(&chunk.height)
                .unwrap().get(&tip_digest)
                .unwrap();
            height = chunk.height.checked_add(1).unwrap();
            parent = Some(wire::chunk::Parent {
                threshold: threshold.clone(),
                chunk_digest: self.hash_chunk(&chunk.clone()),
            });
        }

        // Construct new chunk
        let mut chunk = wire::Chunk {
            sequencer: public_key,
            height,
            payload_digest,
            parent,
            signature: Bytes::new(), // Unsigned
        };

        // Construct signature
        let digest = self.hash_chunk(&chunk);
        chunk.signature = self.crypto.sign(Some(&self.chunk_namespace), &digest);

        // Deal with the chunk as if it were received over the network
        self.handle_chunk(&chunk, ack_sender).await;

        // Broadcast to network
        if let Err(e) = chunk_sender
            .send(Recipients::All, chunk.encode_to_vec().into(), false)
            .await
        {
            error!("Failed to send chunk: {:?}", e);
            let _ = result.send(false);
            return;
        }

        // Return success
        let _ = result.send(true);
    }

    /// Attempt to rebroadcast the highest-height chunk of this sequencer to all signers.
    /// 
    /// This is only done if:
    /// - this instance is the sequencer for the current epoch.
    /// - this instance has a chunk to rebroadcast.
    /// - this instance has not yet collected the threshold signature for the chunk.
    pub async fn rebroadcast(&mut self, chunk_sender: &mut impl Sender) {
        // Return if not a sequencer in the current epoch
        let epoch = self.coordinator.index();
        if !self.coordinator.is_sequencer(epoch, &self.crypto.public_key()) {
            return;
        }

        // Return if no chunk to rebroadcast
        let Some(tip) = self.tips.get(&self.crypto.public_key()) else {
            error!("Nothing to rebroadcast");
            continue;
        };

        // Return if threshold already collected
        // TODO

        // Rebroadcast to all signers
        if let Err(e) = chunk_sender
            .send(Recipients::Some(self.coordinator.signers(epoch)), chunk.encode_to_vec().into(), false)
            .await {
            error!("Failed to rebroadcast: {:?}", e);
        }
    }

    /// Returns the digest of the given chunk
    fn hash_chunk(&mut self, chunk: &wire::Chunk) -> Digest {
        self.hasher.reset();
        self.hasher.update(&encoder::serialize_chunk(chunk, false));
        self.hasher.finalize()
    }

    /// Returns the digest of the given ack
    fn hash_ack(&mut self, ack: &wire::Ack) -> Digest {
        self.hasher.reset();
        self.hasher.update(&encoder::serialize_ack(ack, false));
        self.hasher.finalize()
    }

    fn verify_ack(&mut self, ack: &wire::Ack) -> Option<PublicKey> {
        let ack_digest = self.hash_ack(ack);
        let Some(identity) = self.coordinator.identity(ack.epoch) else {
            error!("Failed to get identity for epoch {:?}", ack.epoch);
            return None;
        };
        let Some(signers) = self.coordinator.signers(ack.epoch) else {
            error!("Failed to get signers for epoch {:?}", ack.epoch);
            return None;
        };
        let Some(partial): Option<PartialSignature> = PartialSignature::deserialize(&ack.partial) else {
            error!("Failed to deserialize partial signature");
            return None;
        };
        let Some(public_key) = signers.get(partial.index as usize) else {
            error!("Failed to get public key");
            return None;
        };
        if let Err(e) =
            ops::partial_verify_message(identity, Some(&self.ack_namespace), &ack_digest, &partial)
        {
            error!("Failed to verify partial signature: {:?}", e);
            return None;
        }
        Some(public_key.clone())
    }

    /// Returns true if the chunk is valid.
    fn verify_chunk(&mut self, chunk: &wire::Chunk) -> bool {
        // Verify the signature
        let digest = self.hash_chunk(chunk);
        if !C::verify(
            Some(&self.chunk_namespace),
            &digest,
            &chunk.sequencer,
            &chunk.signature,
        ) {
            error!("Failed to verify signature");
            return false;
        }

        // Verify the parent threshold signature
        if chunk.height == 0 {
            if chunk.parent.is_none() {
                return true;
            } else {
                error!("Genesis chunk must not have a parent");
                return false;
            }
        }
        let Some(parent) = &chunk.parent else {
            error!("Chunk must have a parent");
            return false;
        };
        let epoch = self.coordinator.index();
        let Some(identity) = self.coordinator.identity(epoch) else {
            error!("Failed to get identity for epoch {:?}", epoch);
            return false;
        };
        let signature = match group::Signature::deserialize(&parent.threshold) {
            Some(s) => s,
            None => {
                error!("Failed to deserialize signature");
                return false;
            }
        };
        match ops::verify_message(
            &poly::public(identity),
            Some(&self.ack_namespace),
            &parent.chunk_digest,
            &signature,
        ) {
            Ok(()) => true,
            Err(_) => {
                error!("Failed to verify threshold signature");
                false
            }
        }
    }

    /// Returns true if the ack matches (is for) the chunk.
    fn ack_matches_chunk(&self, ack: &wire::Ack, chunk: &wire::Chunk) -> bool {
        ack.sequencer == chunk.sequencer
            && ack.height == chunk.height
            && ack.chunk_digest == self.hash_chunk(chunk)
    }
}
