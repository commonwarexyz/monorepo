//! Pure ring-size arithmetic for the storage benchmark's io_uring runtime.
//!
//! This file compiles into two targets: the harness-free `storage` bench
//! binary (as `ring_size`) and the library unit-test build (as
//! `bench_ring_size` through a `#[path]` inclusion in
//! `runtime/src/storage/mod.rs`), so its tests run under the crate's normal
//! test harness. Keep it dependency-free (core and alloc only).

/// Compute the io_uring ring size for `inflight` concurrent operations.
///
/// Accepted inputs reproduce the benchmark's historical sizing exactly:
/// double the requested concurrency (so in-flight operations never contend
/// for waiter slots) with a minimum of 1024, returned unrounded. The ring
/// constructor rounds the size up to the next power of two and rejects
/// rounded sizes above `max_ring_size`, so this function performs the same
/// rounding up front and converts every failure (conversion or
/// multiplication overflow, rounding overflow, or a rounded size above the
/// limit) into a clean CLI error instead of a truncated ring or a
/// construction panic.
pub fn iouring_ring_size(inflight: usize, max_ring_size: u32) -> Result<u32, String> {
    let size = u32::try_from(inflight)
        .ok()
        .and_then(|inflight| inflight.checked_mul(2))
        .ok_or_else(|| "--inflight is too large to size the io_uring ring".to_string())?
        .max(1024);
    let rounded = size.checked_next_power_of_two().ok_or_else(|| {
        "--inflight requires an io_uring ring larger than MAX_RING_SIZE".to_string()
    })?;
    if rounded > max_ring_size {
        return Err("--inflight requires an io_uring ring larger than MAX_RING_SIZE".to_string());
    }
    Ok(size)
}

/// Mirror of the runtime's `MAX_RING_SIZE` (2^27) for the boundary tests
/// below. A literal is required because this file compiles both into the
/// bench binary and into the library, whose paths to the runtime crate
/// differ. The drift test beside the inclusion in `runtime/src/storage/mod.rs`
/// asserts the mirror stays equal to the real constant.
///
/// The dead-code allowance is for the bench binary, where cargo sets
/// cfg(test) without a test harness: the `#[test]` functions referencing
/// this constant are stripped there.
#[cfg(test)]
#[allow(dead_code)]
pub const MIRRORED_MAX_RING_SIZE: u32 = 1 << 27;

#[cfg(test)]
mod tests {
    // The unused-imports allowance is for the bench binary, where cargo sets
    // cfg(test) without a test harness: the `#[test]` functions using these
    // imports are stripped there.
    #![allow(unused_imports)]

    use super::{MIRRORED_MAX_RING_SIZE as MAX_RING_SIZE, iouring_ring_size};

    /// Property: small inputs keep the historical floor. Setup: minimal and
    /// mid-range concurrency values. Action: size the ring. Expected: doubled
    /// concurrency with a minimum of 1024, unrounded.
    #[test]
    fn test_ring_size_minimum_behavior() {
        assert_eq!(iouring_ring_size(1, MAX_RING_SIZE), Ok(1024));
        assert_eq!(iouring_ring_size(512, MAX_RING_SIZE), Ok(1024));
        assert_eq!(iouring_ring_size(513, MAX_RING_SIZE), Ok(1026));
        assert_eq!(iouring_ring_size(3000, MAX_RING_SIZE), Ok(6000));
    }

    /// Property: the largest accepted concurrency is exactly half the ring
    /// limit. Setup: MAX_RING_SIZE / 2 in-flight operations. Action: size the
    /// ring. Expected: the doubled size equals MAX_RING_SIZE and is accepted.
    #[test]
    fn test_ring_size_accepts_half_limit() {
        let inflight = (MAX_RING_SIZE / 2) as usize;
        assert_eq!(
            iouring_ring_size(inflight, MAX_RING_SIZE),
            Ok(MAX_RING_SIZE)
        );
    }

    /// Property: one past the largest accepted concurrency is rejected.
    /// Setup: MAX_RING_SIZE / 2 + 1 in-flight operations, whose doubled size
    /// rounds above the limit. Action: size the ring. Expected: the exact
    /// MAX_RING_SIZE error string.
    #[test]
    fn test_ring_size_rejects_half_limit_plus_one() {
        let inflight = (MAX_RING_SIZE / 2) as usize + 1;
        assert_eq!(
            iouring_ring_size(inflight, MAX_RING_SIZE),
            Err("--inflight requires an io_uring ring larger than MAX_RING_SIZE".to_string())
        );
    }

    /// Property: a doubled size with no u32 power-of-two ceiling is the same
    /// clean MAX_RING_SIZE rejection, never the ring constructor's panic.
    /// Setup: 1_073_741_825 converts and doubles within u32 on every target,
    /// but its doubled size exceeds 2^31 so rounding overflows. Action: size
    /// the ring. Expected: the exact MAX_RING_SIZE error string.
    #[test]
    fn test_ring_size_rejects_rounding_overflow() {
        assert_eq!(
            iouring_ring_size(1_073_741_825, MAX_RING_SIZE),
            Err("--inflight requires an io_uring ring larger than MAX_RING_SIZE".to_string())
        );
    }

    /// Property: a concurrency whose doubling overflows u32 is rejected as
    /// too large. Setup: a value that converts to u32 but cannot be doubled.
    /// Action: size the ring. Expected: the exact too-large error string.
    #[test]
    fn test_ring_size_rejects_multiplication_overflow() {
        assert_eq!(
            iouring_ring_size(u32::MAX as usize, MAX_RING_SIZE),
            Err("--inflight is too large to size the io_uring ring".to_string())
        );
    }

    /// Property: a concurrency that does not fit in u32 is rejected instead
    /// of truncating. Setup: u32::MAX + 1, expressible only on 64-bit
    /// targets. Action: size the ring. Expected: the exact too-large error
    /// string.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn test_ring_size_rejects_conversion_overflow() {
        assert_eq!(
            iouring_ring_size(u32::MAX as usize + 1, MAX_RING_SIZE),
            Err("--inflight is too large to size the io_uring ring".to_string())
        );
    }
}
