//! Observed-value pool used by ByzzFuzz vote mutation. Forwarders /
//! extractors populate it from successfully decoded outgoing and inbound
//! vote and certificate traffic. Notarize/finalize vote mutations replay
//! observed proposals, payloads, and parent views; nullify vote mutations use
//! observed notarized/finalized certificate views and observed nullify views as
//! semantically interesting targets. The pool is seeded with the mock genesis
//! payload and genesis parent view.
//! Certificate and resolver process faults are omit-only so this pool
//! deliberately does not retain raw cert bytes or resolver request views.

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
    pub parent_views: Mutex<BTreeSet<u64>>,
    pub notarized_views: Mutex<BTreeSet<u64>>,
    pub finalized_views: Mutex<BTreeSet<u64>>,
    pub nullified_views: Mutex<BTreeSet<u64>>,
}

impl ObservedState {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn new_with_genesis(genesis_payload: Sha256Digest) -> Arc<Self> {
        let state = Self::new();
        state.observe_payload(genesis_payload);
        state.observe_parent_view(0);
        state
    }

    pub fn observe_payload(&self, payload: Sha256Digest) {
        self.payloads.lock().insert(payload);
    }

    pub fn observe_parent_view(&self, view: u64) {
        self.parent_views.lock().insert(view);
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
        {
            let mut proposals = self.proposals.lock();
            let bucket = proposals.entry(view).or_default();
            if !bucket
                .iter()
                .any(|q| q.payload == p.payload && q.parent == p.parent)
            {
                bucket.push(p.clone());
            }
        }
        self.observe_payload(p.payload);
        self.observe_parent_view(p.parent.get());
    }

    pub fn observe_certificate<S, P>(&self, c: &Certificate<S, Sha256Digest>)
    where
        S: commonware_consensus::simplex::scheme::Scheme<Sha256Digest, PublicKey = P>,
        P: PublicKey,
    {
        let view = c.view().get();
        match c {
            Certificate::Notarization(n) => {
                self.notarized_views.lock().insert(view);
                self.observe_proposal(&n.proposal);
            }
            Certificate::Nullification(_) => {
                self.nullified_views.lock().insert(view);
            }
            Certificate::Finalization(f) => {
                self.finalized_views.lock().insert(view);
                self.observe_proposal(&f.proposal);
            }
        }
    }

    pub fn random_payload(&self, rng: &mut impl rand::Rng) -> Option<Sha256Digest> {
        let payloads = self.payloads.lock();
        if payloads.is_empty() {
            return None;
        }
        let idx = rng.gen_range(0..payloads.len());
        payloads.iter().nth(idx).copied()
    }

    pub fn random_parent_view(&self, rng: &mut impl rand::Rng) -> Option<u64> {
        let parent_views = self.parent_views.lock();
        if parent_views.is_empty() {
            return None;
        }
        let idx = rng.gen_range(0..parent_views.len());
        parent_views.iter().nth(idx).copied()
    }

    pub fn latest_notarized_view(&self) -> Option<u64> {
        self.notarized_views.lock().iter().next_back().copied()
    }

    pub fn latest_finalized_view(&self) -> Option<u64> {
        self.finalized_views.lock().iter().next_back().copied()
    }

    pub fn latest_nullified_view(&self) -> Option<u64> {
        self.nullified_views.lock().iter().next_back().copied()
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

    pub fn random_proposal(&self, rng: &mut impl rand::Rng) -> Option<Proposal<Sha256Digest>> {
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

    pub fn random_nullify_target_view(&self, rng: &mut impl rand::Rng) -> Option<u64> {
        let mut views = BTreeSet::new();
        views.extend(self.notarized_views.lock().iter().copied());
        views.extend(self.finalized_views.lock().iter().copied());
        views.extend(self.nullified_views.lock().iter().copied());
        if views.is_empty() {
            return None;
        }
        let idx = rng.gen_range(0..views.len());
        views.iter().nth(idx).copied()
    }
}
