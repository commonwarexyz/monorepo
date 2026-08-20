//! Clear many-to-many payments with compact, challengeable settlement.
//!
//! This module implements the runtime-agnostic protocol objects, verification rules, and bounded
//! in-memory settlement transitions described by [Bajillion](https://commonware.xyz/blogs/clearing).
//! Operators, persistence, networking, clocks, and atomic asset-adapter integration are
//! deliberately left to applications.

pub mod admission;
pub mod boundary;
pub mod challenge;
pub mod commitment;
pub mod credit;
pub mod payment;
pub mod settlement;
pub mod state;
pub mod transition;

mod wire;
