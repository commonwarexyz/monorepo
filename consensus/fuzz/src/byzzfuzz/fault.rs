//! ByzzFuzz process-fault data type. Sampling lives in [`super::sampling`].

use commonware_cryptography::PublicKey;

/// A single ByzzFuzz process fault. At view `view` the byzantine process's
/// deliveries to anyone in `receivers` are replaced by `mutate(_, seed)`.
/// When `omit` is true the mutation is the empty message set and the
/// injector emits nothing -- the forwarder's drop is the entire fault.
#[derive(Clone, Debug)]
pub struct ProcessFault<P: PublicKey> {
    pub view: u64,
    pub receivers: Vec<P>,
    pub seed: u64,
    pub omit: bool,
}
