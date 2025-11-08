//! Unified marshal core implementation.
//!
//! # Overview
//!
//! This module provides the core marshal actor and mailbox that work with both
//! the [`crate::marshal::standard`] and [`crate::marshal::coding`] variants through
//! the [`Variant`] and [`Buffer`] trait abstractions.
//!
//! # Components
//!
//! - [`Actor`]: The main marshal actor that orders finalized blocks, manages caching,
//!   handles backfill requests, and reports blocks to the application.
//! - [`Mailbox`]: A clonable handle for interacting with the actor from other subsystems.
//! - [`Variant`]: A marker trait describing the types used by different marshal variants
//!   (block types, commitment types, etc.).
//! - [`Buffer`]: An abstraction over block dissemination strategies (whole blocks
//!   vs erasure-coded shards).
//!
//! # Usage
//!
//! The actor is initialized with storage archives and started with a buffer implementation:
//!
//! ```rust,ignore
//! // Initialize with storage
//! let (actor, mailbox, last_height) = Actor::<S, Standard<B>>::init(
//!     context,
//!     finalizations_archive,
//!     blocks_archive,
//!     config,
//! ).await;
//!
//! // Start with application and buffer
//! actor.start(application, buffer, resolver);
//! ```
//!
//! For standard mode, use [`crate::marshal::standard::Standard`] as the variant and
//! `buffered::Mailbox` as the buffer. For coding mode, use
//! [`crate::marshal::coding::Coding`] as the variant and `shards::Mailbox` as the buffer.

mod actor;
pub use actor::Actor;

pub(crate) mod cache;

mod mailbox;
pub use mailbox::Mailbox;

mod variant;
pub use variant::{Buffer, IntoBlock, Variant};
