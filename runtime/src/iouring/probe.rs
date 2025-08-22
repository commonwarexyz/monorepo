//! Probe io_uring capabilities at runtime to determine which operations are supported
//! by the current kernel.
//!
//! This module provides a mechanism to detect supported io_uring operations at startup,
//! allowing the runtime to automatically use optimized paths when available and fallback
//! to alternative implementations when operations are not supported.

use io_uring::{opcode, IoUring, Probe};
use std::sync::LazyLock;

/// Capabilities detected from the kernel's io_uring implementation.
#[derive(Default, Debug, Clone)]
pub struct Capabilities {
    /// Whether IORING_OP_FTRUNCATE is supported (requires kernel 6.9+).
    pub ftruncate: bool,
}

/// Global capabilities, initialized on first access.
pub static CAPABILITIES: LazyLock<Capabilities> =
    LazyLock::new(|| probe_capabilities().unwrap_or_default());

/// Probe the kernel for supported io_uring operations.
///
/// Creates a temporary io_uring instance solely for probing capabilities,
/// then immediately drops it. This is a one-time synchronous operation
/// performed at startup.
fn probe_capabilities() -> Result<Capabilities, std::io::Error> {
    let ring = IoUring::new(2)?;
    let mut probe = Probe::new();

    ring.submitter().register_probe(&mut probe)?;

    Ok(Capabilities {
        ftruncate: probe.is_supported(opcode::Ftruncate::CODE),
    })
}

/// Initialize capabilities probing.
///
/// This function can be called explicitly to trigger capability detection
/// at a controlled point during startup, rather than on first use.
pub fn init() {
    // Just access the lazy static to trigger initialization
    let _ = &*CAPABILITIES;
}
