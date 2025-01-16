use crate::Error;
use super::wire;
use commonware_cryptography::{Digest, Hash, Hasher, PublicKey, Scheme, Signature};
use commonware_p2p::{Sender, Receiver};
use commonware_runtime::{Runtime, mpsc};

pub enum ToAppMsg {
    VerifyChunk(Chunk),
    CertifyAvailability(Chunk)
}

pub enum FromAppMsg {
    VerifyChunkResponse(Chunk, bool),
}

pub struct <E: Runtime, Hasher, Scheme> Signer {
    runtime: E,
    avail_mgr: Arc<Mutex<AckManager>>,
    highway: Arc<Mutex<Highway>>,
}

impl <E: Runtime, Hasher, Scheme> Signer {
    pub fn new(
        runtime: E,
        quorum: usize,
    ) -> Self {
        let 
        Self {
            runtime,
            avail_mgr: Arc::new(Mutex::new(AckManager::new(quorum))),
            highway: Arc::new(Mutex::new(Highway::new())),
        }
    }

    pub async fn run(
        &self,
        car_network: (impl Sender, impl Receiver),
        partial_network: (impl Sender, impl Receiver),
        app_interface: (mpsc::Sender<ToAppMsg>, mpsc::Receiver<FromAppMsg>),
    ) {
        let (car_sender, car_receiver) = car_network;
        let (partial_sender, partial_receiver) = partial_network;
        // Listens for incoming cars.
        runtime.spawn("car_listener", {
            let partial_sender = self.partial_sender.clone();
            async move {
                while let Some(car) = self.car_receiver.recv().await {
                    // Signs the car.
                    let signature = self.sign(car);
                    let partial = AckPart {
                        car_hash: car.hash::<Hasher>(),
                        signer: self.runtime.public_key(),
                        partial_signature: signature,
                    };
                    self.partial_sender.send(partial).await;
                }
            }
        });

        // Listens for incoming partial signatures.
        runtime.spawn("partial_listener", async {
            while let Some(part) = self.partial_receiver.recv().await {
            }
        });
    }
}

// =============================

struct AckPart {
    car_hash: Digest,
    signature: wire::Signature,
}

impl AckPart {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let part = wire::AckPart::decode(msg).map_err(Error::UnableToDecode)?;
        Ok(Self {
            car_hash: part.car_hash,
            signature: part.signature,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let part = wire::AckPart {
            car_hash: self.car_hash,
            signature: self.signature,
        };
        let mut buf = Vec::new();
        part.encode(&mut buf).unwrap();
        buf
    }
}

struct AckFull {
    car_hash: Digest,
    threshold_signature: Signature,
}

type Sigs = HashMap<PublicKey, Signature>;

/// Manages partial and threshold signatures for a set of cars.
#[derive(Error, Debug)]
struct AckManager {
    // Number of partial signatures required to reach a threshold signature.
    quorum: usize,

    // Map from car hash to map from signer to partial signature.
    partials: HashMap<Digest, Sigs>,

    // Map from car hash to threshold signature.
    thresholds: HashMap<Digest, Signature>,
}

impl AckManager {
    fn new(quorum: usize) -> Self {
        Self {
            quorum,
            partials: HashMap::new(),
            thresholds: HashMap::new(),
        }
    }

    /// Adds a partial signature to the manager.
    ///
    /// Returns an error if:
    /// - the threshold already exists
    /// - the part already exists (whether or not it conflicts)
    /// Returns the threshold signature if the threshold is reached for the first time.
    fn update(&self, part: AckPart) Result<Option<AckFull>, Error> {
        // Check if the threshold already exists.
        let threshold = self.thresholds.get(&part.car_hash);
        if let Some(threshold) = threshold {
            return Err(Error::ThresholdExists);
        }

        // Attempt to insert the partial signature.
        let sigs: Sigs = self.partials.entry(part.car_hash).or_default();
        let existing = sigs.get(&part.signer);
        if let Some(existing) = existing {
            if existing == part.partial_signature {
                return Err(Error::DuplicatePartial);
            } else {
                return Err(Error::ConflictingPartial);
            }
        }
        sigs.insert(part.signer, part.partial_signature);
        
        // If the threshold is not reached, return None.
        if false { // TODO [crypto]
            return Ok(None);
        }

        // If the threshold is reached, remove the partial signatures and store/return the threshold signature.
        // TODO [crypto]
        let threshold = Signature::new();
        return Ok(Some(threshold));
    }
}

// =============================

struct Car {
    index: uint64, // sequencer-specific sequential index
    payload: Digest,
    parent: Digest, // hash of previous `Car` that has `index` of `this.index-1`
    signature: wire::Signature, // signature of sequencer over the hash of the car
}

impl Car {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let car = wire::Car::decode(msg).map_err(Error::UnableToDecode)?;
        Ok(Self {
            signature: car.signature,
            index: car.index,
            payload: car.payload,
            parent: car.parent,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let car = wire::Chunk {
            signature: self.signature,
            index: self.index,
            payload: self.payload,
            parent: self.parent,
        };
        let mut buf = Vec::new();
        car.encode(&mut buf).unwrap();
        buf
    }

    fn hash<H: Hasher>(&self) Digest {
        let hasher = H::new();
        hasher.update(self.index.to_be_bytes());
        hasher.update(self.payload.as_bytes());
        hasher.update(self.parent.as_bytes());
        hasher.finalize()
    }
}

struct Lane {
    // The index of the last contiguous car.
    // That is, the highest index such that all cars with index <= `tail` are present.
    tail: uint64,

    // Map from car index to car.
    cars: HashMap<uint64, Car>,
}

struct Highway {
    lanes: HashMap<PublicKey, Lane>,
}

impl Highway {
    fn new() -> Self {
        Self {}
    }

    fn update(&self, car: Car) {
        // TODO
    }
}