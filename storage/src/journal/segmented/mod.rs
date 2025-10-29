//! Segmented journals with section-based storage.
//!
//! This module provides journal implementations that organize data into sections,
//! where each section is stored in a separate blob. This allows for efficient
//! pruning and targeted access patterns.

pub mod variable;
