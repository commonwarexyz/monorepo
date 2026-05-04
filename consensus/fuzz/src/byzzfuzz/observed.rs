//! Observed-value pool. Forwarders/extractors populate it from successfully
//! decoded vote/cert/resolver bytes (both outgoing forwarder paths and
//! inbound `RoundTrackingReceiver`s); the mutator draws from it for
//! semantic mutations (replay valid certs, reuse seen payloads, swap
//! resolver request views).
//!
//! BTree containers are used everywhere so iteration order is deterministic
//! across process runs -- selection by RNG-driven index from the same fuzz
//! input must yield the same observed value every time.

use commonware_consensus::{
    simplex::types::{Certificate, Proposal, Vote},
    Viewable,
};
use commonware_cryptography::{sha256::Digest as Sha256Digest, PublicKey};
use commonware_utils::sync::Mutex;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[derive(Default)]
pub struct ObservedState {
    pub proposals: Mutex<BTreeMap<u64, Vec<Proposal<Sha256Digest>>>>,
    pub payloads: Mutex<BTreeSet<Sha256Digest>>,
    pub notarized_views: Mutex<BTreeSet<u64>>,
    pub finalized_views: Mutex<BTreeSet<u64>>,
    pub nullified_views: Mutex<BTreeSet<u64>>,
    pub notarization_bytes: Mutex<BTreeMap<u64, Vec<Vec<u8>>>>,
    pub nullification_bytes: Mutex<BTreeMap<u64, Vec<Vec<u8>>>>,
    pub finalization_bytes: Mutex<BTreeMap<u64, Vec<Vec<u8>>>>,
    pub resolver_request_views: Mutex<BTreeSet<u64>>,
}

impl ObservedState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn observe_vote<S, P>(&self, v: &Vote<S, Sha256Digest>)
    where
        S: commonware_consensus::simplex::scheme::Scheme<Sha256Digest, PublicKey = P>,
        P: PublicKey,
    {
        match v {
            Vote::Notarize(n) => {
                self.observe_proposal(&n.proposal);
            }
            Vote::Finalize(f) => {
                self.observe_proposal(&f.proposal);
            }
            Vote::Nullify(n) => {
                self.nullified_views.lock().insert(n.view().get());
            }
        }
    }

    pub fn observe_proposal(&self, p: &Proposal<Sha256Digest>) {
        let view = p.view().get();
        let mut proposals = self.proposals.lock();
        let bucket = proposals.entry(view).or_default();
        if !bucket
            .iter()
            .any(|q| q.payload == p.payload && q.parent == p.parent)
        {
            bucket.push(p.clone());
        }
        self.payloads.lock().insert(p.payload);
    }

    pub fn observe_certificate<S, P>(&self, c: &Certificate<S, Sha256Digest>, bytes: &[u8])
    where
        S: commonware_consensus::simplex::scheme::Scheme<Sha256Digest, PublicKey = P>,
        P: PublicKey,
    {
        let view = c.view().get();
        match c {
            Certificate::Notarization(n) => {
                self.notarized_views.lock().insert(view);
                self.observe_proposal(&n.proposal);
                self.notarization_bytes
                    .lock()
                    .entry(view)
                    .or_default()
                    .push(bytes.to_vec());
            }
            Certificate::Nullification(_) => {
                self.nullified_views.lock().insert(view);
                self.nullification_bytes
                    .lock()
                    .entry(view)
                    .or_default()
                    .push(bytes.to_vec());
            }
            Certificate::Finalization(f) => {
                self.finalized_views.lock().insert(view);
                self.observe_proposal(&f.proposal);
                self.finalization_bytes
                    .lock()
                    .entry(view)
                    .or_default()
                    .push(bytes.to_vec());
            }
        }
    }

    pub fn observe_resolver_request(&self, view: u64) {
        self.resolver_request_views.lock().insert(view);
    }

    pub fn random_payload(&self, rng: &mut impl rand::Rng) -> Option<Sha256Digest> {
        let payloads = self.payloads.lock();
        if payloads.is_empty() {
            return None;
        }
        let idx = rng.gen_range(0..payloads.len());
        payloads.iter().nth(idx).copied()
    }

    pub fn random_proposal_at(
        &self,
        rng: &mut impl rand::Rng,
        view: u64,
    ) -> Option<Proposal<Sha256Digest>> {
        let proposals = self.proposals.lock();
        let bucket = proposals.get(&view)?;
        if bucket.is_empty() {
            return None;
        }
        Some(bucket[rng.gen_range(0..bucket.len())].clone())
    }

    pub fn random_proposal_any(&self, rng: &mut impl rand::Rng) -> Option<Proposal<Sha256Digest>> {
        let proposals = self.proposals.lock();
        let total: usize = proposals.values().map(|v| v.len()).sum();
        if total == 0 {
            return None;
        }
        let mut pick = rng.gen_range(0..total);
        for bucket in proposals.values() {
            if pick < bucket.len() {
                return Some(bucket[pick].clone());
            }
            pick -= bucket.len();
        }
        None
    }

    pub fn random_known_view(
        &self,
        rng: &mut impl rand::Rng,
        kinds: KnownViewKinds,
    ) -> Option<u64> {
        let mut union: Vec<u64> = Vec::new();
        if kinds.notarized {
            union.extend(self.notarized_views.lock().iter().copied());
        }
        if kinds.finalized {
            union.extend(self.finalized_views.lock().iter().copied());
        }
        if kinds.nullified {
            union.extend(self.nullified_views.lock().iter().copied());
        }
        if union.is_empty() {
            return None;
        }
        Some(union[rng.gen_range(0..union.len())])
    }

    pub fn random_resolver_request_view(&self, rng: &mut impl rand::Rng) -> Option<u64> {
        let v = self.resolver_request_views.lock();
        if v.is_empty() {
            return None;
        }
        v.iter().nth(rng.gen_range(0..v.len())).copied()
    }

    pub fn random_cert_bytes(&self, rng: &mut impl rand::Rng, kinds: CertKinds) -> Option<Vec<u8>> {
        let mut all: Vec<Vec<u8>> = Vec::new();
        if kinds.notarization {
            for v in self.notarization_bytes.lock().values() {
                all.extend_from_slice(v);
            }
        }
        if kinds.nullification {
            for v in self.nullification_bytes.lock().values() {
                all.extend_from_slice(v);
            }
        }
        if kinds.finalization {
            for v in self.finalization_bytes.lock().values() {
                all.extend_from_slice(v);
            }
        }
        if all.is_empty() {
            return None;
        }
        Some(all.swap_remove(rng.gen_range(0..all.len())))
    }
}

#[derive(Clone, Copy)]
pub struct KnownViewKinds {
    pub notarized: bool,
    pub finalized: bool,
    pub nullified: bool,
}

#[derive(Clone, Copy)]
pub struct CertKinds {
    pub notarization: bool,
    pub nullification: bool,
    pub finalization: bool,
}

impl CertKinds {
    pub const ALL: Self = Self {
        notarization: true,
        nullification: true,
        finalization: true,
    };
}
