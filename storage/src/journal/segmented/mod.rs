//! Segmented journals with section-based storage.
//!
//! This module provides journal implementations that organize data into sections,
//! where each section is stored in a separate blob.

pub mod fixed;
pub mod glob;
mod manager;
pub(crate) use manager::SectionSync;
pub mod oversized;
pub mod variable;
