//! `commonware-storage-core` is **ALPHA** software and is not yet recommended for production use.
//! Developers should expect breaking changes and occasional instability.

#![cfg_attr(not(any(test, feature = "std")), no_std)]

extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;

pub mod mmr;
