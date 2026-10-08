use super::Variant;
use crate::simplex::{scheme::Scheme, types::Finalization};
use commonware_cryptography::certificate::Scoped;
use commonware_utils::channel::oneshot;

/// A finalized delivery admitted under the requested height's epoch scope.
///
/// The retained scope owns verification even if the provider retires that epoch.
pub(super) struct PendingVerification<S, V: Variant>
where
    S: Scheme<V::Commitment>,
{
    pub(super) scoped: Scoped<S>,
    pub(super) finalization: Finalization<S, V::Commitment>,
    pub(super) block: V::ApplicationBlock,
    pub(super) response: oneshot::Sender<bool>,
}
