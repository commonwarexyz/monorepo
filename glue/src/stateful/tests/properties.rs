use super::common::MockValidatorState;
use crate::simulate::{processed::ProcessedHeight, property::Property, tracker::ProgressTracker};
use commonware_consensus::marshal::core::Variant;
use commonware_cryptography::{ed25519, sha256, Digestible};
use std::{future::Future, pin::Pin};

/// Post-run property: all validators agree on the finalized block at `height`.
#[derive(Clone, Copy)]
pub(crate) struct BlockAgreementAtHeight {
    height: u64,
}

impl BlockAgreementAtHeight {
    pub fn new(height: u64) -> Self {
        Self { height }
    }
}

impl<V> Property<ed25519::PublicKey, MockValidatorState<V>> for BlockAgreementAtHeight
where
    V: Variant,
    V::ApplicationBlock: Digestible<Digest = sha256::Digest>,
    MockValidatorState<V>: Send + Sync,
{
    fn name(&self) -> &str {
        "block_agreement_at_height"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        states: &'a [&'a MockValidatorState<V>],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let mut expected = None;
            for state in states {
                let Some(digest) = state.digest_at_height(self.height).await else {
                    return Err(format!(
                        "missing finalized digest at height {} on at least one validator",
                        self.height
                    ));
                };
                if let Some(previous) = expected {
                    if digest != previous {
                        return Err(format!(
                            "digest disagreement at finalized height {}",
                            self.height
                        ));
                    }
                } else {
                    expected = Some(digest);
                }
            }

            Ok(())
        })
    }
}

/// Post-run property: marshal pruned its finalized block history.
///
/// Asserts that every active validator no longer serves the block at
/// `pruned_height` (pruned out of marshal) while still serving the more recent
/// block at `retained_height`. This proves marshal pruning actually ran through
/// the live actor, not merely that it was configured.
#[derive(Clone, Copy)]
pub(crate) struct MarshalPrunedBelow {
    pruned_height: u64,
    retained_height: u64,
}

impl MarshalPrunedBelow {
    pub fn new(pruned_height: u64, retained_height: u64) -> Self {
        Self {
            pruned_height,
            retained_height,
        }
    }
}

impl<V> Property<ed25519::PublicKey, MockValidatorState<V>> for MarshalPrunedBelow
where
    V: Variant,
    V::ApplicationBlock: Digestible<Digest = sha256::Digest>,
    MockValidatorState<V>: Send + Sync,
{
    fn name(&self) -> &str {
        "marshal_pruned_below"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        states: &'a [&'a MockValidatorState<V>],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            for (index, state) in states.iter().enumerate() {
                if state.digest_at_height(self.retained_height).await.is_none() {
                    return Err(format!(
                        "validator {index} pruned the retained block at height {}",
                        self.retained_height
                    ));
                }
                if state.digest_at_height(self.pruned_height).await.is_some() {
                    return Err(format!(
                        "validator {index} still serves the block at height {}; marshal did not prune",
                        self.pruned_height
                    ));
                }
            }

            Ok(())
        })
    }
}

/// Post-run property: every active validator pruned QMDB operation history.
///
/// Asserts that each validator's database set no longer retains operations from
/// the start of the log (its oldest retained location advanced past
/// `min_oldest_retained`). This proves pruning actually ran through the live
/// actor (the deferred `Step::Prune` path discards durable operations), not
/// merely that it was configured.
#[derive(Clone, Copy)]
pub(crate) struct QmdbPruned {
    min_oldest_retained: u64,
}

impl QmdbPruned {
    pub fn new(min_oldest_retained: u64) -> Self {
        Self {
            min_oldest_retained,
        }
    }
}

impl<V> Property<ed25519::PublicKey, MockValidatorState<V>> for QmdbPruned
where
    V: Variant,
    V::ApplicationBlock: Digestible<Digest = sha256::Digest>,
    MockValidatorState<V>: Send + Sync,
{
    fn name(&self) -> &str {
        "qmdb_pruned"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        states: &'a [&'a MockValidatorState<V>],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            for (index, state) in states.iter().enumerate() {
                let oldest_retained = state.oldest_retained().await;
                if oldest_retained < self.min_oldest_retained {
                    return Err(format!(
                        "validator {index} retains operations from location {oldest_retained}; \
                         expected pruning past {}",
                        self.min_oldest_retained
                    ));
                }
            }

            Ok(())
        })
    }
}

/// Post-run property: at least one node used state sync and then advanced further.
#[derive(Clone, Copy)]
pub(crate) struct LateJoinerStateSyncHandoff;

impl<V> Property<ed25519::PublicKey, MockValidatorState<V>> for LateJoinerStateSyncHandoff
where
    V: Variant,
    V::ApplicationBlock: Digestible<Digest = sha256::Digest>,
    MockValidatorState<V>: Send + Sync,
{
    fn name(&self) -> &str {
        "late_joiner_state_sync_handoff"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        states: &'a [&'a MockValidatorState<V>],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            for state in states {
                let Some(sync_height) = state.state_sync_height() else {
                    continue;
                };
                let processed_height = state.processed_height().await;
                if processed_height > sync_height {
                    return Ok(());
                }
            }

            Err(
                "no validator both used state sync and advanced beyond the synced height"
                    .to_string(),
            )
        })
    }
}

/// Post-run property: a validator started state sync, crashed before it
/// completed, restarted, re-entered state sync, then advanced beyond the
/// synced height.
#[derive(Clone, Copy)]
pub(crate) struct CrashDuringStateSyncRecovery;

impl<V> Property<ed25519::PublicKey, MockValidatorState<V>> for CrashDuringStateSyncRecovery
where
    V: Variant,
    V::ApplicationBlock: Digestible<Digest = sha256::Digest>,
    MockValidatorState<V>: Send + Sync,
{
    fn name(&self) -> &str {
        "crash_during_state_sync_recovery"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        states: &'a [&'a MockValidatorState<V>],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let mut observed = Vec::new();
            for state in states {
                let processed_height = state.processed_height().await;
                observed.push(format!(
                    "entries={} sync_height={:?} processed_height={processed_height}",
                    state.state_sync_entries(),
                    state.state_sync_height(),
                ));

                let Some(sync_height) = state.state_sync_height() else {
                    continue;
                };
                if state.state_sync_entries() < 2 {
                    continue;
                }
                if processed_height > sync_height {
                    return Ok(());
                }
            }

            Err(
                format!(
                    "no validator re-entered state sync after a crash and then advanced beyond the synced height; observed [{}]",
                    observed.join(", "),
                ),
            )
        })
    }
}
