//! On-panic decision log for ByzzFuzz runs.
//!
//! ByzzFuzz forwarders and the injector push one line per
//! drop / intercept / replace / omit decision. The buffer is bounded and
//! quiet by default -- entries are only surfaced by [`take`], which `fuzz()`
//! calls in its panic-catching path. Successful runs flush the buffer so the
//! next run starts clean.
//!
//! The buffer is process-wide. ByzzFuzz fuzz targets are run by libfuzzer one
//! input at a time on a single thread, so the global state is appropriate.
//! For test-suite usage, runs share the buffer; the FIFO cap keeps memory
//! bounded.

use commonware_utils::sync::Mutex;
use std::{collections::VecDeque, sync::OnceLock};

/// Maximum retained log lines. Older entries are dropped FIFO once the cap is
/// reached; the dump on panic is the trail of the *most recent* decisions
/// leading to the failure.
const LOG_CAP: usize = 8192;

static LOG: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();

fn buf() -> &'static Mutex<VecDeque<String>> {
    LOG.get_or_init(|| Mutex::new(VecDeque::new()))
}

/// Append a line. Bounded -- oldest entries are dropped beyond an internal cap.
pub fn push(line: String) {
    let mut b = buf().lock();
    if b.len() >= LOG_CAP {
        b.pop_front();
    }
    b.push_back(line);
}

/// Reset the buffer. Called by `runner::run` at the start of each run so that
/// a panic dump only contains entries from the failing run.
pub fn clear() {
    buf().lock().clear();
}

/// Drain and return the current contents. Called by `fuzz()` when a
/// `Mode::Byzzfuzz` run panics.
pub fn take() -> Vec<String> {
    buf().lock().drain(..).collect()
}
