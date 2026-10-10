use commonware_runtime::telemetry::metrics::histogram::Timer;
use std::sync::Arc;

/// The outcome of the marshal's proposal checks for a parent.
///
/// The handle reports the same outcome to the marshal with a unit ancestry.
pub(crate) enum Resolved<D, S, A, M = ()> {
    /// The marshal re-proposes the epoch boundary block, identified by the first field.
    Reuse(D, Arc<S>),
    /// The marshal cannot build on this parent.
    Skip,
    /// The parent is fetched and the application may build on its ancestry. The timer
    /// measures the application's build from this point; the metadata (the coding
    /// configuration, or unit for standard blocks) is passed to the sealing callback with
    /// the built block.
    Build(A, Timer, M),
}

/// The staging log name of a re-proposed epoch boundary block.
pub(crate) const BOUNDARY_BLOCK: &str = "re-proposed boundary block";
