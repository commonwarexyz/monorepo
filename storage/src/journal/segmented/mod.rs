//! Segmented journals with section-based storage.
//!
//! This module provides journal implementations that organize data into sections,
//! where each section is stored in a separate blob.

mod manager;

pub mod fixed;
pub mod glob;
pub mod variable;
