use super::{Config, Mailbox, Message};
use crate::{
    linked::{encoder, wire, Context},
    Application,
};
use bytes::Bytes;
use commonware_consensus::{threshold_simplex::View, ThresholdSupervisor};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{Element, Share, Signature, G2},
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
    A: Application<Context = Context, Proof = Bytes>,
    S: ThresholdSupervisor<Seed = Signature, Index = View, Share = Share, Identity = Public>,
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
    supervisor: S,

    ////////////////////////////////////////
    // Application Mailboxes
    ////////////////////////////////////////
    app: A,

    ////////////////////////////////////////
    // Namespace Constants
    ////////////////////////////////////////
    ack_namespace: Vec<u8>,
    car_namespace: Vec<u8>,

    ////////////////////////////////////////
    // Messaging
    ////////////////////////////////////////
    mailbox_receiver: mpsc::Receiver<Message>,

    ////////////////////////////////////////
    // State
    ////////////////////////////////////////

    // The most recently seen car for each lane.
    // The car must have the threshold signature of its parent.
    // Existence of the car implies:
    // - The existence of the entire lane.
    // - That the car has been signed by this actor.
    tips: HashMap<PublicKey, (wire::Car, Evidence)>,
}

impl<
        B: Blob,
        E: Spawner + Storage<B>,
        C: Scheme,
        H: Hasher,
        A: Application<Context = Context, Proof = Bytes>,
        S: ThresholdSupervisor<Seed = Signature, Index = View, Share = Share, Identity = Public>,
    > Actor<B, E, C, H, A, S>
{
    pub fn new(runtime: E, journal: Journal<B, E>, cfg: Config<C, H, A, S>) -> (Self, Mailbox) {
        let (mailbox_sender, mailbox_receiver) = mpsc::channel(cfg.mailbox_size);
        let mailbox = Mailbox::new(mailbox_sender);
        let result = Self {
            runtime,
            crypto: cfg.crypto,
            hasher: cfg.hasher,
            supervisor: cfg.supervisor,
            journal: Some(journal),
            app: cfg.app,
            ack_namespace: encoder::ack_namespace(&cfg.namespace),
            car_namespace: encoder::car_namespace(&cfg.namespace),
            mailbox_receiver,
            tips: HashMap::new(),
        };

        (result, mailbox)
    }

    pub async fn run(
        mut self,
        car_network: (impl Sender, impl Receiver),
        ack_network: (impl Sender, impl Receiver),
    ) {
        let (mut car_sender, mut car_receiver) = car_network;
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
                msg = car_receiver.recv() => {
                    // Error handling
                    let Ok((sender, msg)) = msg else {
                        error!("car_receiver failed");
                        break;
                    };
                    let Ok(car) = wire::Car::decode(msg) else {
                        error!("Failed to decode car");
                        continue;
                    };
                    if sender != car.sequencer {
                        error!("Received car from wrong sender");
                        continue;
                    };
                    self.handle_car(&car, &mut ack_sender).await;
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
                            self.broadcast(payload, result, &mut car_sender, &mut ack_sender).await;
                        }
                    }
                }
            }
        }
    }

    async fn handle_ack(&mut self, ack: &wire::Ack) {
        // Get the current car and evidence
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
        let quorum = self.supervisor.identity(111).unwrap().required();
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
        self.app.broadcasted(context, digest, threshold).await;
    }

    async fn handle_car(&mut self, car: &wire::Car, ack_sender: &mut impl Sender) {
        // If car is at or behind the tip, ignore.
        // This check is fast, so we do it before full validation.
        if let Some((tip, _evidence)) = self.tips.get(&car.sequencer) {
            if tip.index >= car.index {
                return;
            }
        }

        // Validate that the car is well-formed
        if !self.verify(car) {
            return;
        }

        // Validate the car with the application
        let context = Context {
            sequencer: car.sequencer.clone(),
            index: car.index,
        };
        let result = self.app.verify(context, car.payload.clone()).await;
        match result.await {
            Ok(true) => {}
            Ok(false) => {
                error!("Application rejected car");
                return;
            }
            Err(e) => {
                error!("Failed to verify car with application: {:?}", e);
                return;
            }
        }

        // Emit evidence of parent to the application if the index is greater than 0
        if car.index > 0 {
            let context = Context {
                sequencer: car.sequencer.clone(),
                index: car.index.checked_sub(1).unwrap(),
            };
            self.app
                .broadcasted(
                    context,
                    car.parent_digest.clone(),
                    car.parent_threshold.clone(),
                )
                .await;
        }

        // Insert the car at the tip
        let digest = self.hash(car);
        self.tips.insert(
            car.sequencer.clone(),
            (car.clone(), Evidence::Partials(HashMap::new())),
        );

        // Create an ack for the car
        let share = self.supervisor.share(111).unwrap();
        let partial_signature: Bytes =
            ops::partial_sign_message(share, Some(&self.ack_namespace), &digest)
                .serialize()
                .into();
        let ack = wire::Ack {
            sequencer: car.sequencer.clone().to_vec(),
            index: car.index,
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
    /// The broadcast is only successful if the parent car and threshold signature are known.
    async fn broadcast(
        &mut self,
        payload: Bytes,
        result: oneshot::Sender<bool>,
        car_sender: &mut impl Sender,
        ack_sender: &mut impl Sender,
    ) {
        let public_key = self.crypto.public_key();

        // Get parent car and threshold signature, otherwise return.
        let (parent, parent_threshold) = match self.tips.get(&public_key) {
            Some((car, Evidence::Threshold(threshold))) => (car.clone(), threshold.clone()),
            None | Some((_, Evidence::Partials(_))) => {
                let _ = result.send(false);
                return;
            }
        };

        // Construct new car.
        let parent_digest = self.hash(&parent);
        let mut car = wire::Car {
            sequencer: public_key,
            index: parent.index.checked_add(1).unwrap(),
            payload,
            parent_digest,
            parent_threshold,
            signature: Bytes::new(), // Unsigned
        };

        // Construct full signature
        let plate = self.hash(&car);
        car.signature = self.crypto.sign(Some(&self.car_namespace), &plate);

        // Deal with the car as if it were received over the network
        self.handle_car(&car, ack_sender).await;

        // Broadcast to network
        if let Err(e) = car_sender
            .send(Recipients::All, car.encode_to_vec().into(), false)
            .await
        {
            error!("Failed to send car: {:?}", e);
            let _ = result.send(false);
            return;
        }

        // Return success
        let _ = result.send(true);
    }

    /// Returns the digest of the given car.
    fn hash(&mut self, car: &wire::Car) -> Digest {
        self.hasher.update(&car.sequencer);
        self.hasher.update(&car.index.to_be_bytes());
        self.hasher.update(&car.payload);
        self.hasher.update(&car.parent_digest);
        self.hasher.update(&car.parent_threshold);
        self.hasher.finalize()
    }

    /// Returns true if the car is valid.
    fn verify(&mut self, car: &wire::Car) -> bool {
        // Verify the signature
        let digest = self.hash(car);
        if !C::verify(
            Some(&self.car_namespace),
            &digest,
            &car.sequencer,
            &car.signature,
        ) {
            error!("Failed to verify signature");
            return false;
        }

        // Verify the parent threshold signature
        let public_key = match self.supervisor.identity(111) {
            Some(p) => poly::public(p),
            None => {
                error!("Failed to get public key");
                return false;
            }
        };
        let signature = match G2::deserialize(&car.parent_threshold) {
            Some(s) => s,
            None => {
                error!("Failed to deserialize signature");
                return false;
            }
        };
        match ops::verify_message(
            &public_key,
            Some(&self.ack_namespace),
            &car.parent_digest,
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
