//! ByzzFuzz fault data types. Sampling lives in [`super::sampling`].

use crate::{byzzfuzz::scope::FaultScope, utils::SetPartition};
use commonware_consensus::types::View;
use commonware_cryptography::PublicKey;

/// A single ByzzFuzz process fault. When the byzantine sender's `rnd(m)`
/// equals `view`, its deliveries to anyone in `receivers` whose
/// channel/kind matches `scope` are intercepted. The forwarder drops the
/// original to those receivers; the injector then either replaces it
/// (Vote: semantic mutation drawn from the runtime RNG -- which is fed
/// by the libfuzzer input -- and re-signed under the byzantine keys) or
/// emits nothing (Cert / Resolver: omit-only; or Vote when `omit` is true).
#[derive(Clone, Debug)]
pub struct ProcessFault<P: PublicKey> {
    pub view: u64,
    pub receivers: Vec<P>,
    pub omit: bool,
    pub scope: FaultScope,
}

/// A single ByzzFuzz network fault. When the message sender's `rnd(m)`
/// equals `view`, all messages on every channel are dropped between blocks
/// of `partition` -- network partitions are total at their round; no
/// per-channel/kind targeting.
#[derive(Clone, Copy, Debug)]
pub struct NetworkFault {
    pub view: View,
    pub partition: SetPartition,
}
