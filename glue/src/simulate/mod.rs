//! Simulation harness for testing commonware primitive compositions.
//!
//! Provides a configurable test framework that composes the core consensus
//! stack (e.g. p2p, simplex, marshal, broadcast, application) with fault injection,
//! progress tracking, and property checking.
//!
//! # Components
//!
//! - [`EngineDefinition`]: Trait for defining how to wire up a validator's
//!   service stack.
//! - [`Plan`]: Declarative test configuration with fault injection.
//! - [`Team`]: Manages running validators (start, crash, restart).
//! - [`ProgressTracker`]: Monitors finalization progress and agreement.

pub mod engine;
pub mod exit;
pub mod fault;
pub mod plan;
pub mod processed;
pub mod property;
pub mod reporter;
pub mod team;
pub mod tracker;
