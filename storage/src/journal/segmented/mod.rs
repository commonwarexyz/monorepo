//! Segmented journals with section-based storage.
//!
//! This module provides journal implementations that organize data into sections,
//! where each section is stored in a separate blob.
//!
//! Sections are never truncated. The storage backend syncs each blob atomically,
//! so a torn tail is [Corruption](super::Error::Corruption) rather than crash
//! state to repair, and a truncation API would only invite masking it.

pub mod fixed;
pub mod glob;
mod manager;
pub mod oversized;
pub mod variable;
