use super::wire::{self};
use crate::Error;
use commonware_cryptography::{
    bls12381::primitives::{
        group::{Share, G1, G2},
        ops,
    },
    Digest, Hasher, PublicKey,
};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::Spawner;
use futures::channel::{mpsc, oneshot};
use futures::StreamExt;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{debug, error};

pub enum ToAppMsg {
    VerifyChunk(Car, oneshot::Sender<bool>),
    Threshold(Digest, G2),
}

pub enum FromAppMsg {
    GetCar(Digest),
}

pub struct Signer<E: Spawner, H: Hasher> {
    runtime: E,

    hasher: H,
    share: Share,

    ack_namespace: Vec<u8>,

    ack_mgr: Arc<Mutex<AckManager>>,
    highway: Arc<Mutex<Highway>>,
}

impl<E: Spawner, H: Hasher> Signer<E, H> {
    pub fn new(runtime: E, hasher: H, quorum: usize, share: Share) -> Self {
        Self {
            runtime,
            hasher,
            share,
            ack_namespace: b"ack".to_vec(),
            ack_mgr: Arc::new(Mutex::new(AckManager::new(quorum))),
            highway: Arc::new(Mutex::new(Highway::new())),
        }
    }

    pub async fn run(
        &self,
        car_network: (impl Sender, impl Receiver),
        ack_network: (impl Sender, impl Receiver),
        app_interface: (mpsc::Sender<ToAppMsg>, mpsc::Receiver<FromAppMsg>),
    ) {
        let (car_sender, mut car_receiver) = car_network;
        let (ack_sender, mut ack_receiver) = ack_network;
        let (app_sender, mut app_receiver) = app_interface;

        // Listens for incoming cars
        self.runtime.spawn("car_listener", {
            let ack_sender = ack_sender.clone();
            async move {
                while let Ok((sender, msg)) = car_receiver.recv().await {
                    if let Ok(car) = Car::from_bytes(&msg) {
                        self.handle_car(car, ack_sender.clone()).await;
                    } else {
                        // TODO log error
                    }
                }
            }
        });

        // Listens for incoming acks
        self.runtime.spawn("ack_listener", {
            let app_sender = app_sender.clone();
            async move {
                while let Ok((_sender, msg)) = ack_receiver.recv().await {
                    if let Ok(ack) = Ack::from_bytes(&msg) {
                        self.handle_ack(ack, app_sender.clone()).await;
                    } else {
                        // TODO log error
                    }
                }
            }
        });

        // Listens for incoming app messages
        self.runtime.spawn("app_listener", {
            async move {
                while let Some(msg) = app_receiver.next().await {
                    match msg {
                        FromAppMsg::GetCar(_digest) => {
                            // TODO
                        }
                    }
                }
            }
        });
    }

    fn hash_car(&mut self, car: &Car) -> Digest {
        self.hasher.update(&car.index.to_be_bytes());
        self.hasher.update(&car.payload);
        self.hasher.update(&car.parent);
        self.hasher.finalize()
    }

    async fn handle_ack(&self, ack: Ack, app_sender: mpsc::Sender<ToAppMsg>) {
        match self.ack_mgr.lock().unwrap().update(ack) {
            Ok(Some((digest, threshold))) => {
                debug!(digest, "Threshold reached");
                app_sender
                    .send(ToAppMsg::Threshold(digest, threshold))
                    .await;
            }
            Ok(None) => {
                debug!(digest = ack.digest, "Ack received");
            }
            Err(_) => {
                error!("Unable to update ack");
            }
        }
    }

    async fn handle_car(&mut self, car: Car, ack_sender: impl Sender) {
        // If the car is already in the highway, ignore it.
        if self.highway.lock().unwrap().contains(&car) {
            return;
        }

        // Validate that the car is well-formed
        // TODO

        // Verify the car against the application
        // TODO

        // Update the highway.
        match self.highway.lock().unwrap().update(car) {
            Ok(()) => {
                let digest = self.hash_car(&car);
                let partial_signature =
                    ops::partial_sign_message(&self.share, Some(&self.ack_namespace), &digest);
                let ack = Ack {
                    digest: digest,
                    signer: self.share.public(),
                    signature: partial_signature.value,
                };
                ack_sender
                    .send(Recipients::All, &ack.to_bytes(), false)
                    .await;
            }
            Err(error) => {
                error!("Unable to update highway: {:?}", error);
            }
        };
    }
}

// =============================

struct Sequencer {}

impl Sequencer {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn run() {}
}

// =============================

/// A signed acknowledgment of a car.
struct Ack {
    digest: Digest,
    signer: G1,
    signature: G2,
}

impl Ack {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let ack = wire::Ack::decode(bytes).map_err(Error::UnableToDecode)?;
        Ok(Self {
            digest: ack.digest,
            signature: ack.signature,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let ack = wire::Ack {
            digest: self.digest,
            signature: Some(self.signature),
        };
        ack.encode_to_vec().unwrap()
    }
}

/// Manages partial and threshold signatures for a set of cars.
struct AckManager {
    // Number of partial signatures required to reach a threshold signature.
    quorum: usize,

    // Map from car hash to map from signer to partial signature.
    acks: HashMap<Digest, HashMap<PublicKey, G2>>,

    // Map from car hash to threshold signature.
    thresholds: HashMap<Digest, G2>,
}

impl AckManager {
    fn new(quorum: usize) -> Self {
        Self {
            quorum,
            acks: HashMap::new(),
            thresholds: HashMap::new(),
        }
    }

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
}

// =============================

struct Car {
    // Sequencer-specific sequential index
    index: u64,

    payload: Digest,

    // Hash of previous `Car` that has `index` of `this.index-1`
    parent: Digest,

    // Sequencer public key
    signer: G1,

    // Signature of sequencer over the hash of the car
    signature: G2,
}

impl Car {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let car = wire::Car::decode(bytes).map_err(Error::UnableToDecode)?;
        Ok(Self {
            signature: car.signature,
            index: car.index,
            payload: car.payload,
            parent: car.parent,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let car = wire::Car {
            signature: Some(self.signature),
            index: self.index,
            payload: self.payload,
            parent: self.parent,
        };
        let mut buf = Vec::new();
        car.encode(&mut buf).unwrap();
        buf
    }
}

struct Lane {
    // The index of the last contiguous car.
    // That is, the highest index such that all cars with index <= `tail` are present.
    tail: u64,

    // Map from car index to car.
    cars: HashMap<u64, Car>,
}

struct Highway {
    lanes: HashMap<PublicKey, Lane>,
}

impl Highway {
    fn new() -> Self {
        Self {
            lanes: HashMap::new(),
        }
    }

    fn contains(&self, car: &Car) -> bool {
        self.lanes
            .get(&car.signer)
            .map_or(false, |lane| lane.cars.contains_key(&car.index))
    }

    fn update(&self, car: Car) -> Result<(), Error> {
        let signer = match self.lanes.get(&car.signer) {
            Some(signer) => signer,
            None => return Err(Error::UnknownSigner),
        };
        self.lanes
            .entry(car.signer)
            .or_default()
            .cars
            .insert(car.index, car);
        Ok(())
    }
}
