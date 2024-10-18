use commonware_consensus::{
    Activity, Context, Finalizer, Hash, Hasher, Payload, Proof, Supervisor, View,
};
use commonware_cryptography::PublicKey;
use commonware_runtime::Clock;
use std::time::UNIX_EPOCH;
use tracing::debug;

#[derive(Clone)]
pub struct Application<E: Clock, H: Hasher> {
    runtime: E,
    hasher: H,

    validators: Vec<PublicKey>,
    validators_set: HashSet<PublicKey>,

    last: u128,
}

impl<E: Clock, H: Hasher> Application<E, H> {
    pub fn new(runtime: E, hasher: H, validators: Vec<PublicKey>) -> Self {
        let validators_set = validators.iter().cloned().collect();
        Self {
            runtime,
            hasher,

            validators,
            validators_set,

            last: 0,
        }
    }
}

impl<E: Clock, H: Hasher> commonware_consensus::Application for Application<E, H> {
    fn genesis(&mut self) -> (Hash, Payload) {
        let now: u128 = 0;
        let payload = now.to_be_bytes().to_vec();
        self.hasher.update(&payload);
        let hash = self.hasher.finalize();
        (hash, payload.into())
    }

    async fn propose(&mut self, _: Context) -> Option<Payload> {
        // Get current time
        let current_time = self
            .runtime
            .current()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();

        // Ensure equal or greater than last
        let current_time = if current_time >= self.last {
            current_time
        } else {
            self.last
        };
        Some(current_time.to_be_bytes().to_vec().into())
    }

    async fn parse(&mut self, payload: Payload) -> Option<Hash> {
        // Check that right size
        if payload.len() != 16 {
            return None;
        }

        // Generate hash
        self.hasher.update(&payload);
        Some(self.hasher.finalize())
    }

    async fn verify(&mut self, _context: Context, _payload: Payload, _block: Hash) -> bool {
        unimplemented!()
    }
}

impl<E: Clock, H: Hasher> Supervisor for Application<E, H> {
    fn participants(&self, _view: View) -> Option<&Vec<PublicKey>> {
        Some(&self.validators)
    }

    fn is_participant(&self, _view: View, candidate: &PublicKey) -> Option<bool> {
        Some(self.validators_set.contains(candidate))
    }

    async fn report(&mut self, activity: Activity, _proof: Proof) {
        debug!(activity, "observed activity");
    }
}

impl<E: Clock, H: Hasher> Finalizer for Application<E, H> {
    async fn notarized(&mut self, _block: Hash) {
        unimplemented!()
    }

    async fn finalized(&mut self, _block: Hash) {
        unimplemented!()
    }
}
