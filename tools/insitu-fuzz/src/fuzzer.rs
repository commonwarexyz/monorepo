//! Fuzzing control for P2P message corruption
//!
//! This module provides the fuzzer input control mechanism for
//! deterministic message corruption with direct message selection and XOR-based mutation.
//!
//! # Environment Variables
//!
//! ## MSG_IDX
//! Target specific message(s) for corruption. Maps fuzzer entropy to this range.
//! - Single message: `MSG_IDX=5` targets message 5
//! - Message range: `MSG_IDX=5..10` targets messages 5-10 (AFL exits after 10)
//!
//! # AFL Deferred Fork Server
//! When TEST_IDX and MSG_IDX are both set, AFL forks right before the target
//! message range, avoiding O(N²) complexity for late messages.
//! Example: `TEST_IDX=5 MSG_IDX=2 ./afl.sh run`

use once_cell::sync::Lazy;
#[cfg(feature = "afl-fuzz")]
use std::io::Read;
use std::sync::{atomic::AtomicUsize, Mutex};

static FUZZER_INPUT: Lazy<Mutex<Vec<u8>>> = Lazy::new(|| Mutex::new(Vec::new()));

// Task order bytes for controlling task scheduling in deterministic runtime
static TASK_ORDER_BYTES: Lazy<Mutex<Vec<u8>>> = Lazy::new(|| Mutex::new(Vec::new()));

// Position in task order bytes (consumed by permute_tasks)
static TASK_ORDER_POS: AtomicUsize = AtomicUsize::new(0);

/// Controls where deferred fork routes stdin input
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum DeferredMode {
    /// Route input to message corruption (default)
    MessageCorruption = 0,
    /// Route input to task order control
    TaskOrder = 1,
}

// Deferred mode: 0 = MessageCorruption, 1 = TaskOrder
static DEFERRED_MODE: AtomicUsize = AtomicUsize::new(0);

// Local message index counter (for corruption targeting, not for reporting)
static MESSAGE_INDEX: AtomicUsize = AtomicUsize::new(0);

// Expected message count (set once, used for validation)
static EXPECTED_MESSAGES: AtomicUsize = AtomicUsize::new(0);

// Target range for deferred fork server (set by harness via API)
static DEFERRED_FORK_RANGE: Lazy<Mutex<Option<(usize, Option<usize>)>>> =
    Lazy::new(|| Mutex::new(None));

/// MSG_IDX override from environment variable (for targeted fuzzing campaigns)
/// Supports single index (e.g., "50") or range (e.g., "50..60")
static MSG_IDX_OVERRIDE: Lazy<Option<(usize, Option<usize>)>> = Lazy::new(|| {
    std::env::var("MSG_IDX").ok().and_then(|s| {
        if let Some((start, end)) = s.split_once("..") {
            // Range format: "50..60"
            let start = start.parse::<usize>().ok()?;
            let end = end.parse::<usize>().ok()?;
            Some((start, Some(end)))
        } else {
            // Single index: "50"
            let idx = s.parse::<usize>().ok()?;
            Some((idx, None))
        }
    })
});

/// Optional statistics tracking for debugging and analysis
#[derive(Debug, Default, Clone)]
pub struct Stats {
    /// Messages that were actually corrupted
    pub corrupted_messages: usize,
}

static STATS_ENABLED: AtomicUsize = AtomicUsize::new(0); // 0 = disabled, 1 = enabled
static STATS: Lazy<Mutex<Stats>> = Lazy::new(|| Mutex::new(Stats::default()));

/// Set the expected message count for validation.
///
/// Must be called before `set_fuzzer_input` to enable validation.
pub fn set_expected_messages(count: usize) {
    EXPECTED_MESSAGES.store(count, std::sync::atomic::Ordering::SeqCst);
}

/// Set the deferred fork mode.
///
/// Controls where stdin input is routed after the deferred fork:
/// - `MessageCorruption`: route to message corruption (default)
/// - `TaskOrder`: route to task order control
pub fn set_deferred_mode(mode: DeferredMode) {
    DEFERRED_MODE.store(mode as usize, std::sync::atomic::Ordering::SeqCst);
}

/// Set the target message range for deferred fork server.
///
/// Called by the harness before running the test. The fork server will
/// initialize right before `start` and exit cleanly after `end` (if Some).
///
/// # Arguments
/// * `start` - First message index to target (fork happens at start-1)
/// * `end` - Optional last message index (exit after this)
///
/// # Example
/// ```ignore
/// // Target message 50 only
/// set_deferred_fork_range(50, None);
///
/// // Target messages 50-60, exit after 60
/// set_deferred_fork_range(50, Some(60));
/// ```
pub fn set_deferred_fork_range(start: usize, end: Option<usize>) {
    let mut range = DEFERRED_FORK_RANGE.lock().unwrap();
    *range = Some((start, end));
}

/// Clear the deferred fork range (disables deferred fork)
pub fn clear_deferred_fork_range() {
    let mut range = DEFERRED_FORK_RANGE.lock().unwrap();
    *range = None;
}

/// Get the current deferred fork range
pub fn get_deferred_fork_range() -> Option<(usize, Option<usize>)> {
    DEFERRED_FORK_RANGE.lock().unwrap().clone()
}

/// Set fuzzer input bytes for controlling corruption behavior.
///
/// Validates against the expected message count (set via `set_expected_messages`).
///
/// Format: [msg_idx(2), raw_key_bytes...]
/// - Bytes 0-1: Target message index (u16 little-endian)
/// - Bytes 2+: XOR key for corruption
///
/// Returns `true` if input was valid and set, `false` if invalid.
pub fn set_fuzzer_input(data: &[u8]) -> bool {
    // Need at least 2 bytes for message index
    if data.len() < 2 {
        return false;
    }

    let target_message = u16::from_le_bytes([data[0], data[1]]) as usize;

    // Reject out-of-range indices
    if target_message >= EXPECTED_MESSAGES.load(std::sync::atomic::Ordering::SeqCst) {
        return false;
    }

    // MSG_IDX mode: check if target is in the allowed range
    match *MSG_IDX_OVERRIDE {
        Some((start, Some(end))) if target_message < start || target_message > end => return false,
        Some((idx, None)) if target_message != idx => return false,
        _ => {}
    }

    // Valid - set input
    let mut input = FUZZER_INPUT.lock().unwrap();
    input.clear();
    input.extend_from_slice(data);

    // Reset MESSAGE_INDEX for each iteration, except when AFL deferred fork is active.
    // Deferred fork mode preserves MESSAGE_INDEX from the fork point (set via set_deferred_fork_range).
    let deferred_fork_active = cfg!(feature = "afl-fuzz") && get_deferred_fork_range().is_some();
    if !deferred_fork_active {
        MESSAGE_INDEX.store(0, std::sync::atomic::Ordering::SeqCst);
        // Also reset task order position for consistency (not strictly needed for message corruption)
        TASK_ORDER_POS.store(0, std::sync::atomic::Ordering::SeqCst);
    }

    true
}

/// Clear fuzzer input to disable corruption
pub fn clear_fuzzer_input() {
    let mut input = FUZZER_INPUT.lock().unwrap();
    input.clear();
    MESSAGE_INDEX.store(0, std::sync::atomic::Ordering::SeqCst);
}

/// Reset all iteration-specific state for persistent mode fuzzing.
///
/// Call this at the start of each fuzz iteration to ensure deterministic behavior.
/// This resets MESSAGE_INDEX and TASK_ORDER_POS to their initial values.
pub fn reset_iteration_state() {
    MESSAGE_INDEX.store(0, std::sync::atomic::Ordering::SeqCst);
    TASK_ORDER_POS.store(0, std::sync::atomic::Ordering::Release);
    // Note: We don't clear FUZZER_INPUT or TASK_ORDER_BYTES here because
    // the harness may want to set them before calling the test function.
}

/// Enable statistics tracking (disabled by default for performance)
pub fn enable_stats() {
    STATS_ENABLED.store(1, std::sync::atomic::Ordering::SeqCst);
}

/// Disable statistics tracking
pub fn disable_stats() {
    STATS_ENABLED.store(0, std::sync::atomic::Ordering::SeqCst);
}

/// Reset statistics counters
pub fn reset_stats() {
    let mut stats = STATS.lock().unwrap();
    *stats = Stats::default();
}

/// Get a snapshot of current statistics
pub fn get_stats() -> Stats {
    let stats = STATS.lock().unwrap();
    stats.clone()
}

/// Check if statistics tracking is enabled
fn stats_enabled() -> bool {
    STATS_ENABLED.load(std::sync::atomic::Ordering::SeqCst) == 1
}

/// Get the fuzzer input data for message corruption.
/// Returns the raw bytes starting from index 2 (after the message index).
/// This data can be used for deterministic mutation of message fields.
pub fn get_fuzz_input() -> Vec<u8> {
    let input = FUZZER_INPUT.lock().unwrap();
    if input.len() > 2 {
        input[2..].to_vec()
    } else {
        Vec::new()
    }
}

/// Set task order bytes for controlling task scheduling.
///
/// These bytes are used by the deterministic runtime to control task permutation
/// order in each event loop iteration. The runtime calls `permute_tasks()` FFI
/// which consumes these bytes.
pub fn set_task_order_bytes(data: &[u8]) {
    let mut bytes = TASK_ORDER_BYTES.lock().unwrap();
    bytes.clear();
    bytes.extend_from_slice(data);
    // Reset position so new bytes are consumed from the start
    TASK_ORDER_POS.store(0, std::sync::atomic::Ordering::Release);
}

/// Get task order bytes.
pub fn get_task_order_bytes() -> Vec<u8> {
    TASK_ORDER_BYTES.lock().unwrap().clone()
}

/// Clear task order bytes.
pub fn clear_task_order_bytes() {
    TASK_ORDER_BYTES.lock().unwrap().clear();
    TASK_ORDER_POS.store(0, std::sync::atomic::Ordering::Release);
}

/// Debug logging for task order fuzzing (enabled by TASK_ORDER_DEBUG env var)
fn log_permute(msg: &str) {
    use std::io::Write;
    static DEBUG: Lazy<bool> = Lazy::new(|| std::env::var("TASK_ORDER_DEBUG").is_ok());
    if *DEBUG {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/task_order.log")
        {
            let _ = writeln!(f, "{}", msg);
        }
    }
}

/// Permute a slice of task IDs using fuzzer-provided bytes.
///
/// Uses Fisher-Yates shuffle where each byte selects the next element.
/// Consumes bytes from TASK_ORDER_BYTES starting at TASK_ORDER_POS.
///
/// Returns true if permutation was applied (enough bytes available), false otherwise.
/// Requires enough bytes for a complete shuffle to avoid partial/hybrid states.
pub fn permute_tasks(ids: &mut [u128]) -> bool {
    if ids.len() <= 1 {
        return false;
    }

    let bytes = TASK_ORDER_BYTES.lock().unwrap();
    if bytes.is_empty() {
        log_permute(&format!("permute: no bytes, n={}", ids.len()));
        return false;
    }

    let n = ids.len();
    let bytes_needed = n.saturating_sub(1);
    let start_pos = TASK_ORDER_POS.load(std::sync::atomic::Ordering::Relaxed);

    // Require enough bytes for complete shuffle - no partial/hybrid states
    if start_pos + bytes_needed > bytes.len() {
        log_permute(&format!(
            "permute: not enough bytes, n={} need={} have={} pos={}",
            n,
            bytes_needed,
            bytes.len(),
            start_pos
        ));
        return false;
    }

    // Commit to consuming bytes
    TASK_ORDER_POS.store(
        start_pos + bytes_needed,
        std::sync::atomic::Ordering::Relaxed,
    );

    // Permute using bytes (Fisher-Yates)
    let mut swaps = Vec::new();
    for i in 0..bytes_needed {
        let pos = start_pos + i;
        let remaining = n - i;
        let pick = i + (bytes[pos] as usize % remaining);
        ids.swap(i, pick);
        if swaps.len() < 5 {
            swaps.push(format!("{}↔{}", i, pick));
        }
    }

    log_permute(&format!(
        "permute: OK n={} used={} pos={}->{} swaps=[{}]",
        n,
        bytes_needed,
        start_pos,
        start_pos + bytes_needed,
        swaps.join(",")
    ));
    true
}

/// Corrupt a message by XORing its bytes with fuzzer input.
///
/// Uses direct message selection: bytes 0-1 specify which message index to corrupt.
/// The raw XOR key (bytes 2+) is applied with truncate-or-pad:
/// - If the key is longer than the message: only the first N bytes of the key are used (truncate)
/// - If the key is shorter than the message: only the first K bytes of the message are XORed (zero-pad)
///
/// This approach gives the fuzzer granular control over corruption size:
/// - 1-byte key corrupts only the first byte
/// - 100-byte key corrupts the first 100 bytes
/// - etc.
///
/// Returns true if the message was corrupted, false otherwise.
///.
pub fn corrupt_bytes(encoded: &mut [u8]) -> bool {
    // Get the current message index and increment for the next call
    let msg_idx = MESSAGE_INDEX.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    let input = FUZZER_INPUT.lock().unwrap();
    if input.is_empty() || input.len() < 2 || encoded.is_empty() {
        return false;
    }

    // Extract the target message index from bytes 0-1
    let target_message = u16::from_le_bytes([input[0], input[1]]) as usize;

    // Only corrupt the target message
    // Out-of-range indices naturally don't match, training the fuzzer to use valid indices
    if msg_idx != target_message {
        return false;
    }

    // Get a raw XOR key from bytes 2+
    let raw_key = &input[2..];
    if raw_key.is_empty() {
        // No key provided - skip corruption to encourage fuzzer to provide key data
        return false;
    }

    // This is the target message - corrupt it with XOR!
    if stats_enabled() {
        let mut stats = STATS.lock().unwrap();
        stats.corrupted_messages += 1;
    }

    // Apply truncate-or-pad XOR:
    // - If the key is longer than the message: use only first N bytes (truncate)
    // - If the key is shorter than the message: XOR only first K bytes, rest unchanged (zero-pad)
    let xor_len = raw_key.len().min(encoded.len());
    for i in 0..xor_len {
        encoded[i] ^= raw_key[i];
    }

    true
}

/// Fuzzer checkpoint called at runtime quiescent points
///
/// This function is called by the runtime at each event loop iteration (quiescent point).
/// When AFL++ is detected AND a deferred fork range is set (via `set_deferred_fork_range`),
/// it initializes the AFL fork server right before the target message range to avoid
/// O(N²) complexity.
///
/// Also handles clean exit when the range upper bound is exceeded (AFL only).
///
/// Enabled only when built with the afl-fuzz feature.
#[cfg(feature = "fuzzing")]
#[no_mangle]
pub extern "C" fn insitu_fuzz_checkpoint() {
    #[cfg(feature = "afl-fuzz")]
    {
        // Get target range from harness (not env var)
        let (target_msg, end_bound) = match get_deferred_fork_range() {
            Some((start, end)) => (start, end),
            None => return, // No range set by harness, skip deferred fork
        };

        // Check if we've exceeded the upper bound of the range
        if let Some(end) = end_bound {
            let current_msg = MESSAGE_INDEX.load(std::sync::atomic::Ordering::Relaxed);
            if current_msg > end {
                // Exit cleanly at quiescent point - we've processed the range
                std::process::exit(0);
            }
        }

        // Fork right before the target message
        let fork_at = target_msg.saturating_sub(1);

        // Only initialize once when we reach the fork point
        static INIT_DONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if INIT_DONE.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }

        let current_msg = MESSAGE_INDEX.load(std::sync::atomic::Ordering::Relaxed);
        if current_msg < fork_at {
            return;
        }

        INIT_DONE.store(true, std::sync::atomic::Ordering::Relaxed);

        log_permute(&format!("=== FORK at msg {} ===", current_msg));

        // Fork here - parent pauses, child continues below
        unsafe {
            extern "C" {
                fn __afl_manual_init();
            }
            __afl_manual_init();
        }

        // Child wakes up here - read fresh input from AFL's stdin pipe
        let mut new_input = Vec::new();
        if std::io::stdin().read_to_end(&mut new_input).is_ok() {
            // Log first 8 bytes as hex to verify inputs differ
            let preview: String = new_input
                .iter()
                .take(8)
                .map(|b| format!("{:02x}", b))
                .collect();
            log_permute(&format!(
                "=== CHILD got {} bytes, first8={} ===",
                new_input.len(),
                preview
            ));
            match DEFERRED_MODE.load(std::sync::atomic::Ordering::Relaxed) {
                0 => {
                    // MessageCorruption mode
                    if !set_fuzzer_input(&new_input) {
                        std::process::exit(0);
                    }
                }
                1 => {
                    // TaskOrder mode
                    set_task_order_bytes(&new_input);
                }
                _ => unreachable!(),
            }
        }
    }
}

#[cfg(not(feature = "fuzzing"))]
#[no_mangle]
pub extern "C" fn insitu_fuzz_checkpoint() {
    // No-op when fuzzing is disabled
}
