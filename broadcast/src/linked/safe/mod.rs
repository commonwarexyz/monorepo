//! Provides a wrapped version of the `wire` module.
//! This allows for more robust error handling and type checking.

use commonware_cryptography::Scheme;

// Exports certain types from the private module.
mod private;
pub use private::{Ack, Chunk, Parent};

/// Safe version of a `Link`.
///
/// This type is exported publicly for simplicity, while allowing the sealed representation to use
/// automatic-derivations like `Debug` and `PartialEq`.
pub type Link<C, D> = private::Link<<C as Scheme>::PublicKey, <C as Scheme>::Signature, D>;
