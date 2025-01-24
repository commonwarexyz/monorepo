use super::{Config, Mailbox, Message};
use crate::{
    linked::{encoder, wire, Context, View},
    Application, Collector, ThresholdCoordinator,
};
use bytes::Bytes;
use commonware_cryptography::{
    bls12381::primitives::{
        group::{self, Element, Share, G2},
        ops::{self},
        poly::{self, Eval, PartialSignature, Public},
    },
    Digest, Hasher, PublicKey, Scheme,
};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Blob, Spawner, Storage};
use commonware_storage::journal::Journal;
use futures::channel::{mpsc, oneshot};
use futures::StreamExt;
use prost::Message as _;
use std::collections::HashMap;
use tracing::{debug, error};

enum Evidence {
    Partials(HashMap<PublicKey, Bytes>),
    Threshold(Bytes),
}

pub struct Actor<
    B: Blob,
    E: Spawner + Storage<B>,
    C: Scheme,
    H: Hasher,
    A: Application<Context = Context>,
    Z: Collector<Context = Context, Proof = Bytes>,
    S: ThresholdCoordinator<Index = View, Share = Share, Identity = Public>,
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
    tips: HashMap<PublicKey, (wire::Chunk, Evidence)>,
}

impl<
        B: Blob,
        E: Spawner + Storage<B>,
        C: Scheme,
        H: Hasher,
        A: Application<Context = Context>,
        Z: Collector<Context = Context, Proof = Bytes>,
        S: ThresholdCoordinator<Index = View, Share = Share, Identity = Public>,
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

        loop {
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
        }
    }

    async fn handle_ack(&mut self, signer: &PublicKey, ack: &wire::Ack) {
        // Get the current Chunk and evidence
        let sequencer: Bytes = ack.sequencer.clone().into();
        let Some((_tip, evidence)) = self.tips.get_mut(&sequencer) else {
            // Return early if the ack doesn't match the tip
            return;
        };

        // Get the partial signatures, returning early if we already have a threshold
        let partials = match evidence {
            Evidence::Partials(partials) => partials,
            Evidence::Threshold(_) => return,
        };

        // Return early if we already have this partial
        if partials.contains_key(signer) {
            return;
        }

        // Store the ack
        partials.insert(signer.clone(), ack.partial.clone());

        // Return early if we don't have enough partials
        let quorum = self.coordinator.identity(ack.view).unwrap().required();
        if partials.len() < quorum as usize {
            return;
        }

        // Construct the threshold signature
        let partials: Vec<PartialSignature> = partials
            .values()
            .map(|p| PartialSignature::deserialize(p).unwrap())
            .collect();
        let threshold: Bytes = ops::threshold_signature_recover(quorum, partials)
            .expect("Failed to recover threshold signature")
            .serialize()
            .into();

        // Store the threshold
        let (tip, _) = self.tips.remove(&sequencer).unwrap();
        let digest = self.hash(&tip);
        let height = tip.height;
        self.tips.insert(
            sequencer.clone(),
            (tip, Evidence::Threshold(threshold.clone())),
        );

        // Emit the proof to the application
        let context = Context { sequencer, height };
        self.collector
            .acknowledged(context, digest, threshold)
            .await;
    }

    async fn handle_chunk(&mut self, chunk: &wire::Chunk, ack_sender: &mut impl Sender) {
        // If Chunk is at or behind the tip, ignore.
        // This check is fast, so we do it before full validation.
        if let Some((tip, _evidence)) = self.tips.get(&chunk.sequencer) {
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
        let result = self
            .application
            .verify(context, chunk.payload.clone())
            .await;
        match result.await {
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
                .acknowledged(context, parent.digest.clone(), parent.threshold.clone())
                .await;
        }

        // Compute the digest before inserting to avoid borrow conflicts
        let digest = self.hash(chunk);
        self.tips.insert(
            chunk.sequencer.clone(),
            (chunk.clone(), Evidence::Partials(HashMap::new())),
        );

        // Create an ack for the chunk
        let share = self.coordinator.share(chunk.view).unwrap();
        let partial: Bytes = ops::partial_sign_message(share, Some(&self.ack_namespace), &digest)
            .serialize()
            .into();
        let ack = wire::Ack {
            sequencer: chunk.sequencer.clone().to_vec(),
            height: chunk.height,
            view: self.coordinator.index(),
            digest: digest.to_vec().into(),
            partial,
        };

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
        payload: Bytes,
        result: oneshot::Sender<bool>,
        chunk_sender: &mut impl Sender,
        ack_sender: &mut impl Sender,
    ) {
        let public_key = self.crypto.public_key();

        // Get parent Chunk and threshold signature
        let mut height = 0;
        let mut parent = None;
        if let Some((chunk, Evidence::Threshold(threshold))) = self.tips.get(&public_key) {
            height = chunk.height.checked_add(1).unwrap();
            parent = Some(wire::chunk::Parent {
                threshold: threshold.clone(),
                digest: self.hash(&chunk.clone()),
            });
        }

        // Construct new chunk
        let mut chunk = wire::Chunk {
            sequencer: public_key,
            height,
            view: self.coordinator.index(),
            payload,
            parent,
            signature: Bytes::new(), // Unsigned
        };

        // Construct full signature
        let digest = self.hash(&chunk);
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

    /// Returns the digest of the given chunk
    fn hash(&mut self, chunk: &wire::Chunk) -> Digest {
        self.hasher.reset();
        self.hasher.update(&chunk.sequencer);
        self.hasher.update(&chunk.height.to_be_bytes());
        self.hasher.update(&chunk.view.to_be_bytes());
        self.hasher.update(&chunk.payload);
        if let Some(parent) = &chunk.parent {
            self.hasher.update(&parent.digest);
            self.hasher.update(&parent.threshold);
        }
        self.hasher.finalize()
    }

    fn verify_ack(&mut self, ack: &wire::Ack) -> Option<PublicKey> {
        let Some(identity) = self.coordinator.identity(ack.view) else {
            error!("Failed to get identity for view {:?}", ack.view);
            return None;
        };
        let Some(signers) = self.coordinator.signers(ack.view) else {
            error!("Failed to get signers for view {:?}", ack.view);
            return None;
        };
        let Some(partial): Option<Eval<group::Signature>> = Eval::deserialize(&ack.partial) else {
            error!("Failed to deserialize partial signature");
            return None;
        };
        let Some(public_key) = signers.get(partial.index as usize) else {
            error!("Failed to get public key");
            return None;
        };
        if let Err(e) =
            ops::partial_verify_message(identity, Some(&self.ack_namespace), &ack.digest, &partial)
        {
            error!("Failed to verify partial signature: {:?}", e);
            return None;
        }
        Some(public_key.clone())
    }

    /// Returns true if the chunk is valid.
    fn verify_chunk(&mut self, chunk: &wire::Chunk) -> bool {
        // Verify the signature
        let digest = self.hash(chunk);
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
        let public_key = match self.coordinator.identity(chunk.view) {
            Some(p) => poly::public(p),
            None => {
                error!("Failed to get public key");
                return false;
            }
        };
        let signature = match G2::deserialize(&parent.threshold) {
            Some(s) => s,
            None => {
                error!("Failed to deserialize signature");
                return false;
            }
        };
        match ops::verify_message(
            &public_key,
            Some(&self.ack_namespace),
            &parent.digest,
            &signature,
        ) {
            Ok(()) => true,
            Err(_) => {
                error!("Failed to verify threshold signature");
                false
            }
        }
    }
}
