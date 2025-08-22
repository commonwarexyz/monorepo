//! Persist and retrieve data from an abstract store.
//!
//! # Status
//!
//! `commonware-storage` is **ALPHA** software and is not yet recommended for production use. Developers should
//! expect breaking changes and occasional instability.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/commonwarexyz/monorepo/main/docs/rustdoc_logo.png",
    html_favicon_url = "https://raw.githubusercontent.com/commonwarexyz/monorepo/main/docs/favicon.ico"
)]

pub mod adb;
pub mod archive;
pub mod bmt;
pub mod freezer;
pub mod index;
pub mod journal;
pub mod metadata;
pub mod mmr;
pub mod ordinal;
pub mod rmap;
pub mod store;
pub mod translator;
