//! Segmented journals with section-based storage.
//!
//! This module provides journal implementations that organize data into sections,
//! where each section is stored in a separate blob.

mod blob_manager;

pub mod fixed;
pub mod variable;

pub use blob_manager::{BlobManager, Config as BlobManagerConfig};
