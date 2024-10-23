use bytes::Bytes;
use commonware_consensus::{
    authority::{Prover, FINALIZE, PROPOSAL, VOTE},
    Activity, Context, Finalizer, Hash, Hasher, Payload, Proof, Supervisor, View,
};
use commonware_cryptography::{PublicKey, Scheme};
use commonware_runtime::Clock;
use commonware_utils::hex;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::UNIX_EPOCH;
use tracing::{debug, info};

const SYNCHRONY_BOUND: u128 = 250;

#[derive(Clone)]
pub struct Application<E: Clock, C: Scheme, H: Hasher> {
    runtime: E,
    hasher: H,

    validators: Vec<PublicKey>,
    validators_set: HashSet<PublicKey>,
    prover: Prover<C, H>,

    best: Option<(View, Hash)>,
    tracking: HashMap<Hash, u128>,
    tracking_index: BTreeMap<View, Hash>,
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

            best: None,
            tracking: HashMap::new(),
            tracking_index: BTreeMap::new(),
        }
    }
}

impl<E: Clock, C: Scheme, H: Hasher> commonware_consensus::Application for Application<E, C, H> {
    fn genesis(&mut self) -> (Hash, Payload) {
        // Generate genesis value
        //
        // TODO: in production this would be balances
        let now: u128 = 0;
        let payload = now.to_be_bytes().to_vec();
        self.hasher.update(&payload);
        let hash = self.hasher.finalize();

        // Store genesis value so we can build off of it
        self.tracking.insert(hash.clone(), now);
        self.tracking_index.insert(0, hash.clone());
        self.best = Some((0, hash.clone()));
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
        let last = match &self.best {
            Some((_, hash)) => *self.tracking.get(hash).unwrap(),
            None => 0,
        };
        let current_time = if current_time >= last {
            current_time
        } else {
            last
        };
        info!(time = current_time, "proposed");
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

    async fn verify(&mut self, context: Context, payload: Payload, block: Hash) -> bool {
        // Check validity
        let payload = payload.to_vec().try_into();
        let candidate = match payload {
            Ok(time) => u128::from_be_bytes(time),
            Err(_) => return false,
        };
        let parent = match self.tracking.get(&context.parent) {
            Some(parent) => *parent,
            None => return false,
        };
        let current_time = self
            .runtime
            .current()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let valid = candidate >= parent && candidate <= current_time + SYNCHRONY_BOUND;
        if !valid {
            return false;
        }

        // Store result
        self.tracking.insert(block.clone(), candidate);
        self.tracking_index.insert(context.view, block);
        true
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
    async fn notarized(&mut self, view: View, block: Hash) {
        let (best_view, _) = self.best.as_ref().unwrap();
        if view <= *best_view {
            return;
        }
        self.best = Some((view, block));
    }

    async fn finalized(&mut self, view: View, block: Hash) {
        // Discover minimum pruneable payload
        let required_view = {
            let (best_view, _) = self.best.as_ref().unwrap();
            if view <= *best_view {
                *best_view
            } else {
                self.best = Some((view, block));
                view
            }
        };

        // Prune old payloads
        self.tracking_index.retain(|&old_view, old_block| {
            if old_view < required_view {
                self.tracking.remove(old_block);
                debug!(view, "pruned payload");
                false
            } else {
                true
            }
        });
    }
}
