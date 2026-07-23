//! Segmented journals with section-based storage.
//!
//! This module provides journal implementations that organize data into sections,
//! where each section is stored in a separate blob.
//!
//! # Recovery
//!
//! The [fixed] and [variable] journals perform journal-level recovery during replay, not
//! initialization. After reopening either journal, callers must replay it from the beginning
//! (or from a separately validated durable checkpoint), drain the replay completely, and call
//! its `finish` method before reading or mutating the recovered journal. See each implementation's
//! recovery documentation for details.

pub mod fixed;
pub mod glob;
mod manager;
pub mod oversized;
pub mod variable;
