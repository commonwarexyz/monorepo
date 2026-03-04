//! Decorator for a cryptographic hasher that implements the MMB-specific hashing logic.

use super::{Location, Mmb};
use crate::merkle;
use commonware_cryptography::Hasher as CHasher;
pub use merkle::hasher::Hasher;

/// The standard hasher to use with an MMB for computing leaf, node and root digests. Leverages no
/// external data.
pub type Standard<H> = merkle::hasher::Standard<Mmb, H>;

impl<H: CHasher> Hasher<Mmb> for Standard<H> {
    type Digest = H::Digest;
    type Inner = H;

    fn inner(&mut self) -> &mut H {
        self.inner_mut()
    }

    fn fork(&self) -> impl Hasher<Mmb, Digest = H::Digest> {
        Self::new()
    }

    fn root<'a>(
        &mut self,
        leaves: Location,
        peak_digests: impl Iterator<Item = &'a H::Digest>,
    ) -> H::Digest {
        let mut acc = self.digest(&leaves.as_u64().to_be_bytes());
        for digest in peak_digests {
            acc = self.fold_peak(&acc, digest);
        }
        acc
    }
}
