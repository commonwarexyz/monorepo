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

    pub mod bmt;
    pub mod merkle;
    pub use merkle::{mmb, mmr};
});
commonware_macros::stability_scope!(ALPHA, cfg(feature = "std") {
    mod bitmap;
    pub mod qmdb;
    pub use crate::bitmap::{BitMap as AuthenticatedBitMap, MerkleizedBitMap, UnmerkleizedBitMap};
    pub mod cache;
    pub mod queue;
    #[cfg(any(test, feature = "test-utils"))]
    pub mod utils;
});
commonware_macros::stability_scope!(BETA, cfg(feature = "std") {
    /// A shared in-flight sync result. Detached observers of the same completion: dropping one
    /// neither cancels the sync nor consumes its result.
    pub(crate) type SyncCompletion = futures::future::Shared<
        futures::future::BoxFuture<'static, Result<(), commonware_runtime::Error>>,
    >;

    pub mod archive;
    pub mod freezer;
    pub mod index;
    pub mod journal;
    pub mod metadata;
    pub mod ordinal;
    pub mod rmap;

    /// Section selector for storage operations that act on one or more sections.
    pub trait Sections {
        /// Iterator over selected sections.
        type Iter: Iterator<Item = u64>;

        /// Convert into selected section indices.
        ///
        /// This trait does not impose ordering or uniqueness; each storage operation decides how
        /// to handle duplicates and missing sections.
        fn sections(self) -> Self::Iter;
    }

    impl Sections for u64 {
        type Iter = core::iter::Once<Self>;

        fn sections(self) -> Self::Iter {
            core::iter::once(self)
        }
    }

    impl<const N: usize> Sections for [u64; N] {
        type Iter = core::array::IntoIter<u64, N>;

        fn sections(self) -> Self::Iter {
            self.into_iter()
        }
    }

    impl<'a, const N: usize> Sections for &'a [u64; N] {
        type Iter = core::iter::Copied<core::slice::Iter<'a, u64>>;

        fn sections(self) -> Self::Iter {
            self.iter().copied()
        }
    }

    impl<'a> Sections for &'a [u64] {
        type Iter = core::iter::Copied<core::slice::Iter<'a, u64>>;

        fn sections(self) -> Self::Iter {
            self.iter().copied()
        }
    }

    impl Sections for Vec<u64> {
        type Iter = std::vec::IntoIter<u64>;

        fn sections(self) -> Self::Iter {
            self.into_iter()
        }
    }

    impl<'a> Sections for &'a Vec<u64> {
        type Iter = core::iter::Copied<core::slice::Iter<'a, u64>>;

        fn sections(self) -> Self::Iter {
            self.iter().copied()
        }
    }

    impl Sections for std::collections::BTreeSet<u64> {
        type Iter = std::collections::btree_set::IntoIter<u64>;

        fn sections(self) -> Self::Iter {
            self.into_iter()
        }
    }

    impl<'a> Sections for &'a std::collections::BTreeSet<u64> {
        type Iter = core::iter::Copied<std::collections::btree_set::Iter<'a, u64>>;

        fn sections(self) -> Self::Iter {
            self.iter().copied()
        }
    }

    /// A runtime context providing storage, timing, and metrics capabilities.
    ///
    /// This is a convenience alias for the trait bound `BufferPooler + Storage + Clock + Metrics`
    /// that appears on nearly every type in this crate.
    pub trait Context:
        commonware_runtime::BufferPooler
        + commonware_runtime::Storage
        + commonware_runtime::Clock
        + commonware_runtime::Metrics
    {
    }
    impl<
        T: commonware_runtime::BufferPooler
            + commonware_runtime::Storage
            + commonware_runtime::Clock
            + commonware_runtime::Metrics,
    > Context for T
    {
    }

    /// The physical namespace entries owned by one logical storage object.
    ///
    /// Every target in a plan belongs to the same runtime storage namespace. Composite objects
    /// merge child plans and execute the union as one crash-recoverable removal.
    pub(crate) struct DestroyPlan<E: commonware_runtime::Storage> {
        context: E,
        targets: Vec<commonware_runtime::RemoveTarget>,
    }

    impl<E: commonware_runtime::Storage> DestroyPlan<E> {
        pub(crate) fn new(
            context: E,
            targets: impl IntoIterator<Item = commonware_runtime::RemoveTarget>,
        ) -> Self {
            Self {
                context,
                targets: targets.into_iter().collect(),
            }
        }

        pub(crate) fn merge(&mut self, mut other: Self) {
            self.targets.append(&mut other.targets);
        }

        #[commonware_macros::stability(ALPHA)]
        pub(crate) fn extend(
            &mut self,
            targets: impl IntoIterator<Item = commonware_runtime::RemoveTarget>,
        ) {
            self.targets.extend(targets);
        }

        pub(crate) async fn destroy(self) -> Result<(), commonware_runtime::Error> {
            self.context.remove_batch(self.targets).await
        }
    }
});
commonware_macros::stability_scope!(BETA {
    pub mod translator;
});
