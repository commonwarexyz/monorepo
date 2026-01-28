//! Commonware fuzzing infrastructure
//!
//! Provides message corruption testing for Commonware consensus protocols.
//! Requires `fuzzing` feature enabled in commonware-runtime.

use std::collections::HashMap;
use std::panic;
use std::sync::OnceLock;

pub mod fuzzer;

#[cfg(feature = "test-registry")]
pub mod test_registry;

#[cfg(test)]
mod fuzzer_test;

pub use fuzzer::{
    clear_deferred_fork_range, clear_fuzzer_input, clear_task_order_bytes, corrupt_bytes,
    disable_stats, enable_stats, get_deferred_fork_range, get_fuzz_input, get_stats,
    get_task_order_bytes, permute_tasks, reset_iteration_state, reset_stats,
    set_deferred_fork_range, set_deferred_mode, set_expected_messages, set_fuzzer_input,
    set_task_order_bytes, DeferredMode, Stats,
};

// =============================================================================
// FFI Exports
// =============================================================================

#[no_mangle]
pub extern "C" fn commonware_fuzz_corrupt_bytes(ptr: *mut u8, len: usize) -> bool {
    let slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
    corrupt_bytes(slice)
}

#[no_mangle]
pub extern "C" fn commonware_fuzz_get_task_order_bytes(
    buffer: *mut u8,
    buffer_len: usize,
) -> usize {
    let bytes = get_task_order_bytes();
    if buffer.is_null() {
        return bytes.len();
    }
    let copy_len = bytes.len().min(buffer_len);
    if copy_len > 0 {
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, copy_len) };
    }
    copy_len
}

#[no_mangle]
pub extern "C" fn commonware_fuzz_permute_tasks(ids: *mut u128, len: usize) -> bool {
    if ids.is_null() || len <= 1 {
        return false;
    }
    let slice = unsafe { std::slice::from_raw_parts_mut(ids, len) };
    permute_tasks(slice)
}

// =============================================================================
// Test Oracle (built at compile time via build.rs)
// =============================================================================

/// Maps file paths to line ranges that are test code: (start_line, end_line)
static ORACLE: OnceLock<HashMap<String, Vec<(u32, u32)>>> = OnceLock::new();

fn load_oracle() -> HashMap<String, Vec<(u32, u32)>> {
    let mut map: HashMap<String, Vec<(u32, u32)>> = HashMap::new();
    // Read from project root (relative to src/lib.rs)
    for line in include_str!("../test_oracle.txt").lines() {
        let parts: Vec<_> = line.rsplitn(3, ':').collect();
        if parts.len() == 3 {
            let path = parts[2].to_string();
            let start: u32 = parts[1].parse().unwrap_or(0);
            let end: u32 = parts[0].parse().unwrap_or(0);
            map.entry(path).or_default().push((start, end));
        }
    }
    map
}

/// Files that are test infrastructure - always filter panics from these
const TEST_INFRA_FILES: &[&str] = &[
    "p2p/src/simulated/network.rs",
    "runtime/src/deterministic.rs",
    "broadcast/src/buffered/engine.rs",
];

fn is_test_location(file: &str, line: u32) -> bool {
    // Always filter test infrastructure files
    if TEST_INFRA_FILES
        .iter()
        .any(|pattern| file.ends_with(pattern))
    {
        return true;
    }

    let oracle = ORACLE.get_or_init(load_oracle);

    // Try direct match first as file is usually full path.
    if let Some(ranges) = oracle.get(file) {
        return ranges.iter().any(|(s, e)| line >= *s && line <= *e);
    }

    // Fallback: suffix match for different path formats
    oracle.iter().any(|(path, ranges)| {
        let matches = path.ends_with(file) || file.ends_with(path);
        matches && ranges.iter().any(|(s, e)| line >= *s && line <= *e)
    })
}

// =============================================================================
// Panic Hooks
// =============================================================================

/// Setup panic hook that aborts on any panic (simple mode).
pub fn setup_abort_on_panic() {
    panic::set_hook(Box::new(|info| {
        eprintln!("{info}");
        std::process::abort();
    }));
}

/// Setup panic hook that filters test infrastructure panics.
///
/// Panics originating from test code (detected via compile-time oracle) exit cleanly.
/// Panics from production code abort to signal a real bug to the fuzzer.
pub fn setup_panic_hook() {
    ORACLE.get_or_init(load_oracle);

    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        if std::env::var("FUZZ_SHOW_ALL_PANICS").is_ok() {
            default_hook(info);
            std::process::abort();
        }

        let in_test = info.location().map_or(false, |loc| {
            let result = is_test_location(loc.file(), loc.line());
            result
        });

        if in_test {
            // For AFL builds, exit cleanly (afl crate aborts after hook returns).
            // For other builds, just return and let the harness continue.
            #[cfg(feature = "afl-fuzz")]
            std::process::exit(0);
            return;
        }

        default_hook(info);
        std::process::abort();
    }));
}

// =============================================================================
// Fuzz Iteration Helpers
// =============================================================================

#[macro_export]
macro_rules! init_fuzzer {
    ($init:ident) => {
        static $init: std::sync::Once = std::sync::Once::new();
        $init.call_once(helper::setup_panic_hook);
    };
}

#[inline]
pub fn run_fuzz_iteration<F>(data: &[u8], expected_messages: usize, test_fn: F)
where
    F: FnOnce() + panic::UnwindSafe,
{
    if get_deferred_fork_range().is_some() {
        panic!("run_fuzz_iteration is not compatible with deferred fork mode");
    }
    reset_iteration_state();
    set_expected_messages(expected_messages);
    if !set_fuzzer_input(data) {
        return;
    }
    let _ = panic::catch_unwind(test_fn);
}
