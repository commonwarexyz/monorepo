//! Persist and retrieve data from an abstract store.
//!
//! # Status
//!
//! Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

commonware_macros::stability_scope!(ALPHA {
    extern crate alloc;

    pub mod mmr;
});
commonware_macros::stability_scope!(ALPHA, cfg(feature = "std") {
    mod bitmap;
    pub mod qmdb;
    pub use crate::bitmap::{BitMap as AuthenticatedBitMap, MerkleizedBitMap, UnmerkleizedBitMap};
    pub mod bmt;
    pub mod cache;
});
commonware_macros::stability_scope!(BETA, cfg(feature = "std") {
    pub mod archive;
    pub mod freezer;
    pub mod index;
    pub mod journal;
    pub mod kv;
    pub mod metadata;
    pub mod ordinal;
    pub mod rmap;
    pub mod translator;

    /// A storage structure with capabilities to persist and recover state across restarts.
    pub trait Persistable {
        /// The error type returned when there is a failure from the underlying storage system.
        type Error;

        /// Durably persist the structure, guaranteeing the current state will survive a crash.
        ///
        /// For a stronger guarantee that eliminates potential recovery, use [Self::sync] instead.
        fn commit(&mut self) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
            self.sync()
        }

        /// Durably persist the structure, guaranteeing the current state will survive a crash, and that
        /// no recovery will be needed on startup.
        ///
        /// This provides a stronger guarantee than [Self::commit] but may be slower.
        fn sync(&mut self) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

        /// Destroy the structure, removing all associated storage.
        ///
        /// This method consumes the structure and deletes all persisted data, leaving behind no storage
        /// artifacts. This can be used to clean up disk resources in tests.
        fn destroy(self) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;
    }
});
