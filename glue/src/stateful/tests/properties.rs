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

/// Post-run property: at least one node used startup state sync and then advanced further.
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
                let Some(sync_height) = state.startup_sync_height() else {
                    continue;
                };
                let processed_height = state.processed_height().await;
                if processed_height > sync_height {
                    return Ok(());
                }
            }

            Err(
                "no validator both used startup state sync and advanced beyond the synced height"
                    .to_string(),
            )
        })
    }
}
