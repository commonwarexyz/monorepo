//! ByzzFuzz fault data types. Sampling lives in [`super::sampling`].

use crate::{byzzfuzz::scope::FaultScope, utils::SetPartition};
use commonware_consensus::types::View;
use commonware_cryptography::PublicKey;

/// A single ByzzFuzz process fault. At view `view` the byzantine process's
/// deliveries to anyone in `receivers` whose channel/kind matches `scope`
/// are replaced by `mutate(_, seed)`. When `omit` is true the mutation is
/// the empty message set and the injector emits nothing.
#[derive(Clone, Debug)]
pub struct ProcessFault<P: PublicKey> {
    pub view: u64,
    pub receivers: Vec<P>,
    pub seed: u64,
    pub omit: bool,
    pub scope: FaultScope,
}

/// A single ByzzFuzz network fault. At view `view`, all messages whose
/// channel/kind match `scope` are dropped between blocks of `partition`.
#[derive(Clone, Copy, Debug)]
pub struct NetworkFault {
    pub view: View,
    pub partition: SetPartition,
    pub scope: FaultScope,
}
