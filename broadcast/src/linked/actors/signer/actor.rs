use super::{Config, Mailbox, Message};
use crate::{
    linked::{encoder, wire, Context},
    Application,
};
use bytes::Bytes;
use commonware_consensus::{threshold_simplex::View, ThresholdSupervisor};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{Element, Share, Signature},
        ops::{self},
        poly::Public,
    },
    Digest, Hasher, PublicKey, Scheme,
};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::Spawner;
use futures::channel::{mpsc, oneshot};
use futures::StreamExt;
use prost::Message as _;
use std::collections::HashMap;
use tracing::{debug, error};

pub struct Actor<
    E: Spawner,
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

enum Evidence {
    Partials(HashMap<PublicKey, Bytes>),
    Threshold(Bytes),
}

impl<
        E: Spawner,
        C: Scheme,
        H: Hasher,
        A: Application<Context = Context, Proof = Bytes>,
        S: ThresholdSupervisor<Seed = Signature, Index = View, Share = Share, Identity = Public>,
    > Actor<E, C, H, A, S>
{
    pub fn new(runtime: E, cfg: Config<C, H, A, S>) -> (Self, Mailbox) {
        let (mailbox_sender, mailbox_receiver) = mpsc::channel(cfg.mailbox_size);
        let mailbox = Mailbox::new(mailbox_sender);
        let result = Self {
            runtime,
            crypto: cfg.crypto,
            hasher: cfg.hasher,
            supervisor: cfg.supervisor,
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
                    return;
                },
                msg = car_receiver.recv() => {
                    // Error handling
                    let Ok((_sender, msg)) = msg else {
                        break;
                    };
                    let Ok(car) = wire::Car::decode(msg) else {
                        continue;
                    };
                    if car.car.is_none() {
                        continue;
                    }

                    // Logic
                    self.handle_car(&car, &mut ack_sender).await;
                },
                msg = ack_receiver.recv() => {
                    // Error handling
                    let Ok((_sender, msg)) = msg else {
                        break;
                    };
                    let Ok(ack) = wire::Ack::decode(msg) else {
                        continue;
                    };

                    // Logic
                    self.handle_ack(ack).await;
                },
                mail = self.mailbox_receiver.next() => {
                    let msg = match mail {
                        Some(msg) => msg,
                        None => break,
                    };
                    match msg {
                        Message::Broadcast{ payload, result } => {
                            // TODO
                            self.handle_broadcast(payload, result, &mut car_sender).await;
                        }
                    }
                }
            }
        }
    }

    async fn handle_ack(&mut self, ack: &wire::Ack) {
        let entry = self.acks.entry(ack.plate.clone()).or_default();

        // If the ack already exists, ignore it.
        if entry.contains_key(&ack.public_key) {
            return;
        }

        // Store the ack
        entry.insert(ack.public_key.clone(), ack.signature.clone());

        // If quorum is not reached, or if the threshold already exists, return.
        let quorum = self.supervisor.threshold(111);
        if entry.len() < quorum {
            return;
        }
        if self.proofs.contains_key(&ack.plate) {
            return;
        }

        // Construct the threshold signature
        let sigs = entry.values().collect();
        let threshold = ops::threshold_signature_recover(quorum, sigs)
            .expect("Failed to recover threshold signature");
        self.proofs
            .insert(ack.plate.clone(), threshold.serialize().into());

        // TODO: emit the proof to the application
        self.app.broadcasted(context, payload, proof).await;
    }

    async fn handle_car(&mut self, car: &wire::Car, ack_sender: &mut impl Sender) {
        // If car is at or behind the tip, ignore.
        // This check is fast, so we do it before full validation.
        if let Some((prev, evidence)) = self.tips.get(&car.sequencer) {
            if prev.index >= car.index {
                return;
            }
        }

        // Validate that the car is well-formed
        if !self.verify(car) {
            return;
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
                    car.parent_plate.clone(),
                    car.parent_threshold.clone(),
                )
                .await;
        }

        // Insert the car at the tip
        let plate = self.hash(&car);
        self.tips.insert(
            car.sequencer.clone(),
            (car.clone(), Evidence::Partials(HashMap::new())),
        );

        // Create an ack for the car
        let share = self.supervisor.share(111).unwrap();
        let partial_signature: Bytes =
            ops::partial_sign_message(&share, Some(&self.car_namespace), &plate)
                .serialize()
                .into();
        let ack = wire::Ack {
            plate: plate.to_vec().into(),
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

    async fn handle_broadcast(
        &mut self,
        payload: Bytes,
        result: oneshot::Sender<bool>,
        car_sender: &mut impl Sender,
    ) {
        let public_key = self.crypto.public_key();

        // Get parent car and threshold signature, otherwise return.
        let (parent, parent_threshold) = match self.tips.get(&public_key) {
            Some((car, Evidence::Threshold(threshold))) => (car, threshold),
            None | Some((_, Evidence::Partials(_))) => {
                let _ = result.send(false);
                return;
            }
        };
        let parent_threshold = parent_threshold.clone();

        // Construct new car.
        let parent_plate = self.hash(parent);
        let mut car = wire::Car {
            sequencer: public_key,
            index: parent.index + 1,
            payload,
            parent_plate,
            parent_threshold,
            signature: Bytes::new(), // Unsigned
        };

        // Construct full signature
        let plate = self.hash(&car);
        car.signature = self.crypto.sign(Some(&self.car_namespace), &plate);

        // Broadcast to network
        if let Err(e) = car_sender
            .send(Recipients::All, car.encode_to_vec().into(), false)
            .await
        {
            error!("Failed to send car: {:?}", e);
        }

        // Return success
        let _ = result.send(true);
    }

    // Helper Functions

    fn hash(&mut self, car: &wire::Car) -> Digest {
        self.hasher.update(&car.sequencer);
        self.hasher.update(&car.index.to_be_bytes());
        self.hasher.update(&car.payload);
        self.hasher.update(&car.parent_plate);
        self.hasher.update(&car.parent_threshold);
        self.hasher.finalize()
    }

    fn verify(&self, car: &wire::Car) -> bool {
        let plate = self.hash(car);
        let partials = self.tips.get(&car.sequencer).unwrap().1.clone();
        let partials = match partials {
            Evidence::Partials(partials) => partials,
            _ => panic!("Expected partials"),
        };
        let threshold = ops::threshold_signature_recover(111, partials.values())
            .expect("Failed to recover threshold signature");
        let threshold = threshold.serialize().into();

        // Verify the signature
        if !ops::verify_message(
            &car.sequencer,
            Some(&self.car_namespace),
            &plate,
            &threshold,
        ) {
            return false;
        }

        // Store the threshold
        self.tips.insert(
            car.sequencer.clone(),
            (car.clone(), Evidence::Threshold(threshold)),
        );

        true
    }
}
