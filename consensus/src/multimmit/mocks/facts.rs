//! A record of the agreement facts one cluster slot's consensus reported, across restarts.

use crate::{
    Reporter, Viewable as _,
    multimmit::types::{Activity, Resolution},
    types::View,
};
use commonware_actor::Feedback;
use commonware_cryptography::{bls12381::primitives::variant::Variant, sha256::Digest};
use commonware_utils::sync::Mutex;
use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
    sync::Arc,
};

/// What one slot's consensus reported.
#[derive(Clone, Debug, Default)]
pub struct FactLog {
    /// Each resolved view's tips-history commitment and how it resolved.
    pub resolved: BTreeMap<View, (Digest, Resolution<Digest>)>,
    /// Views of finalized leader blocks.
    pub finalized: BTreeSet<View>,
    /// Open-view sweeps reported.
    pub sweeps: u64,
    /// Headers accepted with a local body verdict.
    pub verified: u64,
    /// Headers adopted from `alpha` endorsers.
    pub adopted: u64,
}

/// Records reported facts and checks the reporting contract: a view resolves once, in view order
/// within a process, and a re-reported resolution (after a restart) carries the same commitment.
///
/// A node that anchors on a peer's floor of view `v` jumps: it reports the floor finalized and
/// resolves views from `v` on, never the views it skipped.
pub struct Facts<V> {
    log: Arc<Mutex<FactLog>>,
    /// The last view this process reported as resolved.
    last: Option<View>,
    _variant: PhantomData<fn() -> V>,
}

impl<V> Facts<V> {
    /// Returns a recorder for a new process appending to `log`.
    pub(super) const fn new(log: Arc<Mutex<FactLog>>) -> Self {
        Self {
            log,
            last: None,
            _variant: PhantomData,
        }
    }
}

impl<V> Clone for Facts<V> {
    fn clone(&self) -> Self {
        Self {
            log: Arc::clone(&self.log),
            last: self.last,
            _variant: PhantomData,
        }
    }
}

impl<V: Variant> Reporter for Facts<V> {
    type Activity = Activity<V, Digest>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let mut log = self.log.lock();
        match activity {
            Activity::ViewResolved {
                view,
                commitment,
                by,
                ..
            } => {
                assert!(
                    self.last.is_none_or(|last| view == last.next()),
                    "view {view} resolved after view {:?}",
                    self.last
                );
                self.last = Some(view);
                if let Some((previous, _)) = log.resolved.get(&view) {
                    assert_eq!(
                        *previous, commitment,
                        "view {view} resolved twice differently"
                    );
                } else {
                    log.resolved.insert(view, (commitment, by));
                }
            }
            Activity::LeaderFinalized { lqc, .. } => {
                let view = lqc.leader().view();
                if let Some(anchor) = view.previous()
                    && self.last.is_some_and(|last| last < anchor)
                {
                    self.last = Some(anchor);
                }
                log.finalized.insert(view);
            }
            Activity::ViewSweep { .. } => log.sweeps += 1,
            Activity::HeaderAccepted {
                adopted: Some(_), ..
            } => log.adopted += 1,
            Activity::HeaderAccepted { adopted: None, .. } => log.verified += 1,
            Activity::TransactionProposed { .. } => {}
        }
        Feedback::Ok
    }
}
