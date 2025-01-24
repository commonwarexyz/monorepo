use super::{Config, Mailbox, Message};
use crate::{
    linked::{encoder, wire, Context, Index},
    Acknowledgement, Application, ThresholdCoordinator,
};
use bytes::Bytes;
use commonware_cryptography::{
    bls12381::primitives::{
        group::{Element, Share, G2},
        ops::{self},
        poly::{self, PartialSignature, Public},
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
    Z: Acknowledgement<Context = Context, Proof = Bytes>,
    S: ThresholdCoordinator<Index = Index, Share = Share, Identity = Public>,
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
    app: A,
    acknowledgement: Z,

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

    // The highest-index chunk for each sequencer.
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
        Z: Acknowledgement<Context = Context, Proof = Bytes>,
        S: ThresholdCoordinator<Index = Index, Share = Share, Identity = Public>,
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
            app: cfg.app,
            acknowledgement: cfg.acknowledgement,
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
                    // Error handling
                    let Ok((sender, msg)) = msg else {
                        error!("ack_receiver failed");
                        break;
                    };
                    let Ok(ack) = wire::Ack::decode(msg) else {
                        error!("Failed to decode ack");
                        continue;
                    };
                    if sender != ack.public_key {
                        error!("Received ack from wrong sender");
                        continue;
                    }
                    self.handle_ack(&ack).await;
                },
                mail = self.mailbox_receiver.next() => {
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

    async fn handle_ack(&mut self, ack: &wire::Ack) {
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
        if partials.contains_key(&ack.public_key) {
            return;
        }

        // Store the ack
        partials.insert(ack.public_key.clone(), ack.signature.clone());

        // Return early if we don't have enough partials
        let quorum = self.coordinator.identity(111).unwrap().required();
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
        let index = tip.index;
        self.tips.insert(
            sequencer.clone(),
            (tip, Evidence::Threshold(threshold.clone())),
        );

        // Emit the proof to the application
        let context = Context { sequencer, index };
        self.acknowledgement
            .acknowledged(context, digest, threshold)
            .await;
    }

    async fn handle_chunk(&mut self, chunk: &wire::Chunk, ack_sender: &mut impl Sender) {
        // If Chunk is at or behind the tip, ignore.
        // This check is fast, so we do it before full validation.
        if let Some((tip, _evidence)) = self.tips.get(&chunk.sequencer) {
            if tip.index >= chunk.index {
                return;
            }
        }

        // Validate that the chunk is well-formed
        if !self.verify(chunk) {
            return;
        }

        // Validate the chunk with the application
        let context = Context {
            sequencer: chunk.sequencer.clone(),
            index: chunk.index,
        };
        let result = self.app.verify(context, chunk.payload.clone()).await;
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

        // Emit evidence of parent to the application if the index is greater than 0
        if chunk.index > 0 {
            let context = Context {
                sequencer: chunk.sequencer.clone(),
                index: chunk.index.checked_sub(1).unwrap(),
            };
            self.acknowledgement
                .acknowledged(
                    context,
                    chunk.parent_digest.clone(),
                    chunk.parent_threshold.clone(),
                )
                .await;
        }

        // Insert the chunk at the tip
        let digest = self.hash(chunk);
        self.tips.insert(
            chunk.sequencer.clone(),
            (chunk.clone(), Evidence::Partials(HashMap::new())),
        );

        // Create an ack for the chunk
        let share = self.coordinator.share(111).unwrap();
        let partial_signature: Bytes =
            ops::partial_sign_message(share, Some(&self.ack_namespace), &digest)
                .serialize()
                .into();
        let ack = wire::Ack {
            sequencer: chunk.sequencer.clone().to_vec(),
            index: chunk.index,
            digest: digest.to_vec().into(),
            public_key: self.crypto.public_key(),
            signature: partial_signature,
        };

        // Deal with the ack as if it were received over the network
        self.handle_ack(&ack).await;

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

        // Get parent Chunk and threshold signature, otherwise return.
        let (parent, parent_threshold) = match self.tips.get(&public_key) {
            Some((chunk, Evidence::Threshold(threshold))) => (chunk.clone(), threshold.clone()),
            None | Some((_, Evidence::Partials(_))) => {
                let _ = result.send(false);
                return;
            }
        };

        // Construct new chunk
        let parent_digest = self.hash(&parent);
        let mut chunk = wire::Chunk {
            sequencer: public_key,
            index: parent.index.checked_add(1).unwrap(),
            payload,
            parent_digest,
            parent_threshold,
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
        self.hasher.update(&chunk.sequencer);
        self.hasher.update(&chunk.index.to_be_bytes());
        self.hasher.update(&chunk.payload);
        self.hasher.update(&chunk.parent_digest);
        self.hasher.update(&chunk.parent_threshold);
        self.hasher.finalize()
    }

    /// Returns true if the chunk is valid.
    fn verify(&mut self, chunk: &wire::Chunk) -> bool {
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
        let public_key = match self.coordinator.identity(111) {
            Some(p) => poly::public(p),
            None => {
                error!("Failed to get public key");
                return false;
            }
        };
        let signature = match G2::deserialize(&chunk.parent_threshold) {
            Some(s) => s,
            None => {
                error!("Failed to deserialize signature");
                return false;
            }
        };
        match ops::verify_message(
            &public_key,
            Some(&self.ack_namespace),
            &chunk.parent_digest,
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
