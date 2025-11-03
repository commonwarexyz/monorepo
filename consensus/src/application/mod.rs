//! Adapters and wrappers for [crate::Application] implementations.
//!
//! This module provides composable adapters that enhance [crate::Application] implementations with
//! additional functionality while maintaining the same trait interfaces. These adapters can be
//! layered to add features like epoch management, erasure coding, etc.

pub mod marshaled;
