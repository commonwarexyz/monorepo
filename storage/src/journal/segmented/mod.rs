//! Segmented journals with section-based storage.
//!
//! This module provides journal implementations that organize data into sections,
//! where each section is stored in a separate blob.
//!
//! # Recovery
//!
//! The [fixed] and [variable] journal constructors return replay readers rather than usable
//! journals. Drain the replay completely and call its `finish` method to obtain a journal that can
//! be read or mutated. Composite journals may instead expose an explicit constructor that restores
//! a separately validated durable checkpoint. See each implementation's recovery documentation
//! for details.

pub mod fixed;
pub mod glob;
mod manager;
pub mod oversized;
pub mod variable;
