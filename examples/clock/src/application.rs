use bytes::Bytes;
use commonware_consensus::{
    authority::{Prover, FINALIZE, PROPOSAL, VOTE},
    Activity, Context, Finalizer, Hash, Hasher, Payload, Proof, Supervisor, View,
};
use commonware_cryptography::{PublicKey, Scheme};
use commonware_runtime::Clock;
use commonware_utils::hex;
use std::collections::HashSet;
use std::time::UNIX_EPOCH;
use tracing::debug;
use tracing_subscriber::field::debug;

#[derive(Clone)]
pub struct Application<E: Clock, C: Scheme, H: Hasher> {
    runtime: E,
    hasher: H,

    validators: Vec<PublicKey>,
    validators_set: HashSet<PublicKey>,
    prover: Prover<C, H>,

    last: u128,
}

impl<E: Clock, C: Scheme, H: Hasher> Application<E, C, H> {
    pub fn new(runtime: E, hasher: H, namespace: Bytes, validators: Vec<PublicKey>) -> Self {
        let validators_set = validators.iter().cloned().collect();
        Self {
            runtime,
            hasher: hasher.clone(),

            validators,
            validators_set,
            prover: Prover::new(hasher, namespace),

            last: 0,
        }
    }
}

impl<E: Clock, C: Scheme, H: Hasher> commonware_consensus::Application for Application<E, C, H> {
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

impl<E: Clock, C: Scheme, H: Hasher> Supervisor for Application<E, C, H> {
    fn participants(&self, _view: View) -> Option<&Vec<PublicKey>> {
        Some(&self.validators)
    }

    fn is_participant(&self, _view: View, candidate: &PublicKey) -> Option<bool> {
        Some(self.validators_set.contains(candidate))
    }

    async fn report(&mut self, activity: Activity, proof: Proof) {
        match activity {
            PROPOSAL => {
                let (public_key, view, height, hash) =
                    self.prover.deserialize_proposal(proof, false).unwrap();
                debug!(
                    public_key = hex(&public_key),
                    view,
                    height,
                    hash = hex(&hash),
                    "received proposal"
                );
            }
            VOTE => {
                let (public_key, view, height, hash) =
                    self.prover.deserialize_vote(proof, false).unwrap();
                debug!(
                    public_key = hex(&public_key),
                    view,
                    height,
                    hash = hex(&hash),
                    "received vote"
                );
            }
            FINALIZE => {
                let (public_key, view, height, hash) =
                    self.prover.deserialize_finalize(proof, false).unwrap();
                debug!(
                    public_key = hex(&public_key),
                    view,
                    height,
                    hash = hex(&hash),
                    "received finalize"
                )
            }
            _ => {}
        }
    }
}

impl<E: Clock, C: Scheme, H: Hasher> Finalizer for Application<E, C, H> {
    async fn notarized(&mut self, _block: Hash) {
        unimplemented!()
    }

    async fn finalized(&mut self, _block: Hash) {
        unimplemented!()
    }
}
