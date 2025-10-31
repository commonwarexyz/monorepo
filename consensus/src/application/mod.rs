//! Adapters and wrappers for [Application] implementations.
//!
//! This module provides composable adapters that enhance [Application] implementations with
//! additional functionality while maintaining the same trait interfaces. These adapters can be
//! layered to add features like epoch management, erasure coding, etc.
//!
//! [Application]: crate::Application

pub mod epoched;
