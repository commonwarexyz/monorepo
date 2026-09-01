//! A bounded cache of verified votes for certificate transcript discharge.

use crate::{
    multimmit::{
        machine::{VerificationCompletion, VerifyJob},
        types::Artifact,
    },
    types::{Round, View},
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use commonware_runtime::telemetry::metrics::Histogram;
use std::{collections::BTreeMap, sync::Arc};

/// Votes and novotes this verifier verified, by view, for certificate transcript discharge.
///
/// The machine attaches the votes it has already accepted when it admits a certificate, but at
/// scale the view's votes are usually still queued for verification at that moment. Jobs consult
/// this cache as they start, when the same verifier has typically just verified those votes.
pub(super) struct VerifiedVotes<V: Variant, D: Digest> {
    views: BTreeMap<View, Vec<Arc<Artifact<V, D>>>>,
    per_view: usize,
}

impl<V: Variant, D: Digest> VerifiedVotes<V, D> {
    /// Views kept behind the newest verified vote.
    ///
    /// A certificate job for a view usually starts within a few views of that view's votes, and
    /// each retained view holds at most two messages per participant.
    const RETAINED_VIEWS: u64 = 16;

    pub(super) const fn new(participants: usize) -> Self {
        Self {
            views: BTreeMap::new(),
            // One vote and one novote per participant bound a view's distinct messages.
            per_view: participants.saturating_mul(2),
        }
    }

    /// Caches one verified vote or novote of `view`.
    pub(super) fn record(&mut self, view: View, artifact: &Arc<Artifact<V, D>>) {
        let messages = self.views.entry(view).or_default();
        if messages.len() < self.per_view {
            messages.push(Arc::clone(artifact));
        }
        // Splitting only when a view falls out keeps the common case to one key comparison.
        let cutoff = View::new(view.get().saturating_sub(Self::RETAINED_VIEWS));
        if self
            .views
            .first_key_value()
            .is_some_and(|(&first, _)| first < cutoff)
        {
            self.views = self.views.split_off(&cutoff);
        }
    }

    /// Caches every valid vote and novote of a completed job and observes in `lag` how many views
    /// each trails the job's round.
    pub(super) fn record_job(
        &mut self,
        job: &VerifyJob<V, D>,
        completion: &VerificationCompletion<V, D>,
        round: Round,
        lag: &Histogram,
    ) {
        for (item, verdict) in job.items().iter().zip(completion.verdicts()) {
            let artifact = item.artifact();
            if !verdict.valid() || !matches!(artifact, Artifact::Vote(_) | Artifact::NoVote(_)) {
                continue;
            }
            let Some(view) = artifact.view() else {
                continue;
            };
            self.record(view, item.shared_artifact());
            lag.observe(round.view().get().saturating_sub(view.get()) as f64);
        }
    }

    /// Returns the cached messages of `view`.
    pub(super) fn known(&self, view: View) -> Vec<Arc<Artifact<V, D>>> {
        self.views.get(&view).cloned().unwrap_or_default()
    }
}
