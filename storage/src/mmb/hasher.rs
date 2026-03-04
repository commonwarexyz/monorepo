//! Decorator for a cryptographic hasher that implements the MMB-specific hashing logic.

use super::Mmb;
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

    // root() uses the default fold-based implementation from the trait.
}
