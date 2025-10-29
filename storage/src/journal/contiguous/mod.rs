//! Contiguous journals with position-based access.
//!
//! This module provides position-based journal implementations where items are stored
//! contiguously and can be accessed by their position (0-indexed). Both fixed-size and
//! variable-size item journals are provided.

pub mod fixed;
pub mod variable;
