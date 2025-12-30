//! Persist and retrieve data from an abstract store.
//!
//! # Status
//!
//! `commonware-storage` is **ALPHA** software and is not yet recommended for production use. Developers should
//! expect breaking changes and occasional instability.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
pub mod mmr;

cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        pub mod qmdb;
        pub mod archive;
        mod bitmap;
        pub use bitmap::{BitMap as AuthenticatedBitMap, CleanBitMap as CleanAuthenticatedBitMap, DirtyBitMap as DirtyAuthenticatedBitMap};
        pub mod bmt;
        pub mod cache;
        pub mod freezer;
        pub mod index;
        pub mod journal;
        pub mod kv;
        pub mod metadata;
        pub mod ordinal;
        pub mod rmap;
        pub mod translator;
    }
}

/// A storage structure with capabilities to persist and recover state across restarts.
#[cfg(feature = "std")]
pub trait Persistable {
    /// The error type returned when there is a failure from the underlying storage system.
    type Error;

    /// Durably persist the structure, guaranteeing the current state will survive a crash.
    ///
    /// For a stronger guarantee that eliminates potential recovery, use [Self::sync] instead.
    fn commit(&mut self) -> impl std::future::Future<Output = Result<(), Self::Error>> {
        self.sync()
    }

    /// Durably persist the structure, guaranteeing the current state will survive a crash, and that
    /// no recovery will be needed on startup.
    ///
    /// This provides a stronger guarantee than [Self::commit] but may be slower.
    fn sync(&mut self) -> impl std::future::Future<Output = Result<(), Self::Error>>;

    /// Close the structure, syncing all pending writes and releasing resources.
    fn close(self) -> impl std::future::Future<Output = Result<(), Self::Error>>;

    /// Destroy the structure, removing all associated storage.
    ///
    /// This method consumes the structure and deletes all persisted data, leaving behind no storage
    /// artifacts. This can be used to clean up disk resources in tests.
    fn destroy(self) -> impl std::future::Future<Output = Result<(), Self::Error>>;
}
