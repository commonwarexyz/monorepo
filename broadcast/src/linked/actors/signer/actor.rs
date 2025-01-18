use super::{Config, Mailbox, Message};
use crate::linked::{encoder, wire};
use bytes::Bytes;
use commonware_cryptography::{
    bls12381::primitives::{
        group::{Element, Share},
        ops::{self},
    },
    Digest, Hasher, PublicKey,
};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::Spawner;
use futures::channel::mpsc;
use futures::StreamExt;
use prost::Message as _;
use std::collections::HashMap;
use tracing::{debug, error};

pub struct Signer<E: Spawner, H: Hasher> {
    runtime: E,

    hasher: H,
    share: Share,

    ack_namespace: Vec<u8>,
    mailbox_receiver: mpsc::Receiver<Message>,

    ////////////////////////////////////////
    // State
    ////////////////////////////////////////

    // Map from sequencer to (map from car index to plate).
    lanes: HashMap<PublicKey, HashMap<u64, Digest>>,

    // Map from plate to car
    cars: HashMap<Digest, wire::Car>,

    // Map from car hash to map from signer to partial signature.
    acks: HashMap<Digest, HashMap<PublicKey, Bytes>>,

    // Map from car hash to threshold signature.
    proofs: HashMap<Digest, Bytes>,
}

impl<E: Spawner, H: Hasher> Signer<E, H> {
    pub fn new(runtime: E, cfg: Config<H>) -> (Self, Mailbox) {
        let (mailbox_sender, mailbox_receiver) = mpsc::channel(cfg.mailbox_size);
        let mailbox = Mailbox::new(mailbox_sender);
        (
            Self {
                runtime,
                hasher: cfg.hasher,
                share: cfg.share,
                ack_namespace: encoder::ack_namespace(&cfg.namespace),
                mailbox_receiver,
                lanes: HashMap::new(),
                cars: HashMap::new(),
                acks: HashMap::new(),
                proofs: HashMap::new(),
            },
            mailbox,
        )
    }

    pub async fn run(
        mut self,
        car_network: (impl Sender, impl Receiver),
        ack_network: (impl Sender, impl Receiver),
        proof_network: (impl Sender, impl Receiver),
        backfill_network: (impl Sender, impl Receiver),
    ) {
        let (mut car_sender, mut car_receiver) = car_network;
        let (mut ack_sender, mut ack_receiver) = ack_network;
        let (mut proof_sender, mut proof_receiver) = proof_network;
        let (mut backfill_sender, mut backfill_receiver) = backfill_network;
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

                    // Logic
                    self.handle_car(car, &mut ack_sender).await;
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
                msg = proof_receiver.recv() => {
                    // Error handling
                    let Ok((_sender, msg)) = msg else {
                        break;
                    };
                    let Ok(proof) = wire::Proof::decode(msg) else {
                        continue;
                    };

                    // Logic
                    self.handle_proof(proof).await;
                },
                msg = backfill_receiver.recv() => {
                    // Error handling
                    let Ok((sender, msg)) = msg else {
                        break;
                    };
                    let Ok(backfill) = wire::Backfill::decode(msg) else {
                        continue;
                    };

                    // Logic
                    self.handle_backfill(sender, backfill, &mut proof_sender).await;
                },
                mail = self.mailbox_receiver.next() => {
                    let msg = match mail {
                        Some(msg) => msg,
                        None => break,
                    };
                    match msg {
                        Message::BroadcastCar { car } => {
                            if let Err(error) =
                                car_sender.send(Recipients::All, car.encode_to_vec().into(), false).await
                                {
                                    error!("Failed to send car: {:?}", error);
                                }
                        }
                        Message::RequestProvenCar { request } => {
                            if let Err(error) = backfill_sender.send(Recipients::All, request.encode_to_vec().into(), false).await {
                                error!("Failed to send backfill request: {:?}", error);
                            }
                        }
                    }
                }
            }
        }
    }

    fn hash_car(&mut self, car: &wire::Car) -> Digest {
        self.hasher.update(&car.sequencer);
        self.hasher.update(&car.index.to_be_bytes());
        self.hasher.update(&car.view.to_be_bytes());
        self.hasher.update(&car.payload);
        self.hasher.update(&car.parent_plate);
        self.hasher.update(&car.parent_threshold);
        self.hasher.finalize()
    }

    /// Handle a backfill request.
    async fn handle_backfill(
        &mut self,
        _requester: PublicKey,
        _backfill: wire::Backfill,
        _sender: &mut impl Sender,
    ) {
        // TODO
    }

    async fn handle_proof(&mut self, _proof: wire::Proof) {
        // TODO
    }

    async fn handle_ack(&self, _ack: wire::Ack) {
        // TODO
    }

    async fn handle_car(&mut self, car: wire::Car, ack_sender: &mut impl Sender) {
        let plate = self.hash_car(&car);

        // If the car is already in the highway, ignore it.
        if self.cars.contains_key(&plate) {
            return;
        }

        // Validate that the car is well-formed
        // TODO

        // Verify the car against the application
        // TODO

        // Update

        // Remember the car, return if it already exists.
        if None == self.cars.insert(plate.clone(), car.clone()) {
            return;
        }

        // Return if my signature already exists
        // TODO

        // Sign the plate
        let partial_signature: Bytes =
            ops::partial_sign_message(&self.share, Some(&self.ack_namespace), &plate)
                .serialize()
                .into();

        // Store the ack
        let public_key: Bytes = self.share.public().serialize().into();
        self.acks
            .entry(plate.clone())
            .or_default()
            .insert(public_key.clone(), partial_signature.clone());

        // Send the ack
        let ack = wire::Ack {
            plate: plate.to_vec().into(),
            public_key,
            signature: partial_signature,
        };
        if let Err(e) = ack_sender
            .send(Recipients::All, ack.encode_to_vec().into(), false)
            .await
        {
            error!("Failed to send ack: {:?}", e);
        }

        // If the threshold is reached, send the proof
        // TODO
    }
}

// =============================================================================

/*
    /// Adds an ack to the manager.
    ///
    /// Returns an error if:
    /// - the threshold already exists
    /// - the ack already exists (whether or not it conflicts)
    /// Returns the threshold signature if the threshold is reached for the first time.
    fn update(&self, ack: Ack) -> Result<Option<(Digest, G2)>, Error> {
        // Check if the threshold already exists.
        let threshold = self.thresholds.get(&ack.digest);
        if let Some(threshold) = threshold {
            return Err(Error::ThresholdExists);
        }

        // Attempt to insert the ack
        let sigs = self.acks.entry(ack.digest).or_default();
        let existing = sigs.get(&ack.signer);
        if let Some(existing) = existing {
            if existing == ack.signature {
                return Err(Error::DuplicateAck);
            } else {
                return Err(Error::ConflictingAck);
            }
        }
        sigs.insert(ack.signer, ack.signature);

        // If the threshold is not reached, return None
        if sigs.len() < self.quorum {
            return Ok(None);
        }

        // Otherwise, compute the threshold signature
        let signatures = Vec::new();
        for (_, s) in sigs {
            signatures.push(s);
        }
        let threshold = ops::threshold_signature_recover(self.quorum as u32, signatures)
            .map_err(|_| Error::ThresholdSignature)?;

        // Remove the acks and insert the threshold signature.
        self.thresholds.insert(ack.digest, threshold);
        self.acks.entry(ack.digest).remove();

        return Ok(Some((ack.digest, threshold)));
    }
*/
