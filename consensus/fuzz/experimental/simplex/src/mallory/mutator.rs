//! The Mallory custom libFuzzer mutator: the campaign's learned policy steers which
//! schedules the fuzzer tries next, without touching how an input executes.
//!
//! Execution reads its whole schedule from the input ([`super::schedule`]), so the
//! campaign-persistent Q-table and role bandit can act only here, when libFuzzer
//! asks for a mutation of a parent input. Each executed episode records a trace,
//! per step the Q-state the runner learned in and the legal mask it decoded that
//! step's action byte against, keyed by the hash of the parent's raw input bytes (the fuzz target announces them via
//! [`set_current_input`] before running). A mutation of that parent then either
//! replays the policy over the recorded states, rewriting the action bytes by
//! masked softmax over the campaign Q-rows (an off-policy form of Mallory's
//! Algorithm 1 selection: once a changed action diverges the child's run, later
//! choices still follow the parent's recorded states), or re-draws the role byte from the bandit,
//! or defers to libFuzzer's own mutator, which is also what a parent without a
//! trace gets and what explores the config prefix and the entropy tail byte-wise.

use super::{adversary, fault::N_FAULTS, policy, schedule};
use arbitrary::{Arbitrary as _, Unstructured};
use commonware_consensus_fuzz_core::{FuzzInput, MAX_RAW_BYTES};
use commonware_utils::{FuzzRng, sync::Mutex};
use rand::{Rng, RngExt as _};
use std::{
    collections::{HashMap, VecDeque},
    hash::{DefaultHasher, Hash as _, Hasher as _},
    sync::OnceLock,
};

/// Bound on cached traces; the oldest is evicted past it.
const TRACE_CACHE_CAP: usize = 4096;

/// One executed step: the Q-state the runner learned in and the legal mask it
/// decoded the step's action byte against. The mutator selects over these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TraceStep {
    pub(crate) state: u64,
    pub(crate) legal: [bool; N_FAULTS],
}

/// How a mutation rewrites the parent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Rewrite every traced step's action byte by the campaign policy; keep the role.
    PolicyRollout,
    /// Redraw the role byte from the role bandit; keep the action bytes.
    RoleRedraw,
    /// Defer to libFuzzer's default mutator.
    Default,
}

struct TraceCache {
    traces: HashMap<u64, Vec<TraceStep>>,
    order: VecDeque<u64>,
}

static CURRENT: OnceLock<Mutex<Option<u64>>> = OnceLock::new();
static TRACES: OnceLock<Mutex<TraceCache>> = OnceLock::new();

fn current() -> &'static Mutex<Option<u64>> {
    CURRENT.get_or_init(|| Mutex::new(None))
}

fn traces() -> &'static Mutex<TraceCache> {
    TRACES.get_or_init(|| {
        Mutex::new(TraceCache {
            traces: HashMap::new(),
            order: VecDeque::new(),
        })
    })
}

/// The trace key of a raw input: a process-local hash of its bytes.
fn key_of(data: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    hasher.finish()
}

/// Announce the raw bytes of the input about to run, so the episode's trace is
/// recorded under the key a later mutation of those bytes looks up.
pub(crate) fn set_current_input(data: &[u8]) {
    *current().lock() = Some(key_of(data));
}

/// The trace key announced for the running input, if any (none under unit tests).
pub(crate) fn current_key() -> Option<u64> {
    *current().lock()
}

/// Record the executed steps of the input keyed by `key`, evicting the oldest trace
/// past the cache bound.
pub(crate) fn record_trace(key: u64, steps: Vec<TraceStep>) {
    let mut cache = traces().lock();
    if cache.traces.insert(key, steps).is_none() {
        cache.order.push_back(key);
    }
    while cache.order.len() > TRACE_CACHE_CAP {
        if let Some(old) = cache.order.pop_front() {
            cache.traces.remove(&old);
        }
    }
}

fn trace_of(key: u64) -> Option<Vec<TraceStep>> {
    traces().lock().traces.get(&key).cloned()
}

/// The custom mutator body: mutate `data[..size]` in place into at most `max_size`
/// bytes and return the new size. See the module docs for the strategy.
pub(crate) fn mutate(data: &mut [u8], size: usize, max_size: usize, seed: u32) -> usize {
    let mut rng = FuzzRng::new(seed.to_le_bytes().to_vec());
    let mode = match rng.random_range(0..5u8) {
        0 | 1 => Mode::PolicyRollout,
        2 => Mode::RoleRedraw,
        _ => Mode::Default,
    };
    let rewritten = match mode {
        Mode::Default => None,
        Mode::PolicyRollout | Mode::RoleRedraw => trace_of(key_of(&data[..size.min(data.len())]))
            .and_then(|trace| rewrite(data, size, max_size, &trace, mode, &mut rng)),
    };
    rewritten.unwrap_or_else(|| libfuzzer_sys::fuzzer_mutate(data, size, max_size))
}

/// Rewrite the schedule prefix of `data[..size]` under `mode`, extending the input
/// (up to `max_size`) so the prefix fits. Returns the new size, or `None` when the
/// input cannot be decoded or has no room for a schedule, in which case the caller
/// falls back to the default mutator.
fn rewrite(
    data: &mut [u8],
    size: usize,
    max_size: usize,
    trace: &[TraceStep],
    mode: Mode,
    rng: &mut impl Rng,
) -> Option<usize> {
    let max_size = max_size.min(data.len());
    // Define every byte the decode below may read: the structured prefix consumes
    // more bytes as more become available, so locate the schedule on the longest
    // candidate rather than on the (possibly exhausted) parent.
    if size < max_size {
        data[size..max_size].fill(0);
    }
    let input = FuzzInput::arbitrary_take_rest(Unstructured::new(&data[..max_size])).ok()?;
    if input.raw_bytes.len() >= MAX_RAW_BYTES {
        return None;
    }
    let offset = max_size - input.raw_bytes.len();
    let schedule_end = offset + schedule::SCHEDULE_LEN;
    let new_size = if size >= schedule_end {
        size.min(max_size)
    } else {
        schedule_end.min(max_size)
    };
    // No room for even the role byte.
    if new_size <= offset {
        return None;
    }
    match mode {
        Mode::RoleRedraw => {
            data[offset] = schedule::encode_role(adversary::role_bandit().lock().select(rng));
        }
        Mode::PolicyRollout => {
            let campaign = policy::campaign(N_FAULTS).lock();
            let writable = (new_size - offset - 1).min(schedule::SCHEDULE_STEPS);
            for (step, observed) in trace.iter().enumerate().take(writable) {
                let action = campaign.policy.select(observed.state, &observed.legal, rng);
                data[offset + 1 + step] = schedule::encode_action(action, &observed.legal);
            }
        }
        Mode::Default => unreachable!("the default mode never rewrites"),
    }
    Some(new_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mallory::{adversary::AdversaryRole, fault};

    /// A parent input whose structured prefix decodes fully, followed by a schedule
    /// and some entropy, plus the structured-prefix length.
    fn parent() -> (Vec<u8>, usize) {
        // Enough bytes for every structured field, then a full schedule and entropy.
        let mut data = vec![0x11u8; 24];
        data.extend(std::iter::repeat_n(0x33u8, schedule::SCHEDULE_LEN + 8));
        let input = FuzzInput::arbitrary_take_rest(Unstructured::new(&data)).unwrap();
        let offset = data.len() - input.raw_bytes.len();
        (data, offset)
    }

    fn honest_trace(steps: usize) -> Vec<TraceStep> {
        (0..steps)
            .map(|step| TraceStep {
                state: 0x1000 + step as u64,
                legal: fault::legal_mask(false, false, false, false),
            })
            .collect()
    }

    #[test]
    fn rollout_rewrites_only_traced_action_bytes_and_keeps_everything_else() {
        let (mut data, offset) = parent();
        let original = data.clone();
        let size = data.len();
        let trace = honest_trace(5);
        let mut rng = FuzzRng::new(vec![7, 7, 7, 7]);
        let new_size = rewrite(&mut data, size, size, &trace, Mode::PolicyRollout, &mut rng)
            .expect("a decodable parent with room is rewritten");
        assert_eq!(new_size, size);
        assert_eq!(
            &data[..=offset],
            &original[..=offset],
            "prefix and role byte kept"
        );
        for step in 0..5 {
            let byte = data[offset + 1 + step];
            assert!(
                usize::from(byte) < schedule::legal_ids(&trace[step].legal).len(),
                "a rewritten byte is a legal-id position"
            );
        }
        assert_eq!(
            &data[offset + 6..],
            &original[offset + 6..],
            "untraced steps and the entropy tail are untouched"
        );
    }

    #[test]
    fn rollout_extends_a_short_parent_to_hold_the_schedule() {
        // A parent shorter than its structured prefix plus the schedule grows (within
        // `max_size`) so the schedule fits; the grown region is fully defined.
        let (data, _) = parent();
        let short = 3usize;
        let mut buffer = vec![0xEEu8; 96];
        buffer[..short].copy_from_slice(&data[..short]);
        let trace = honest_trace(schedule::SCHEDULE_STEPS);
        let mut rng = FuzzRng::new(vec![1, 2, 3]);
        let new_size = rewrite(
            &mut buffer,
            short,
            96,
            &trace,
            Mode::PolicyRollout,
            &mut rng,
        )
        .expect("room to extend");
        let decoded =
            FuzzInput::arbitrary_take_rest(Unstructured::new(&buffer[..new_size])).unwrap();
        let offset = new_size - decoded.raw_bytes.len();
        assert_eq!(new_size, offset + schedule::SCHEDULE_LEN);
        assert!(
            buffer[short..offset].iter().all(|&b| b == 0),
            "padding is zeroed"
        );
    }

    #[test]
    fn role_redraw_writes_a_valid_role_byte_only() {
        let (mut data, offset) = parent();
        let original = data.clone();
        let size = data.len();
        let mut rng = FuzzRng::new(vec![9, 9]);
        let new_size = rewrite(
            &mut data,
            size,
            size,
            &honest_trace(1),
            Mode::RoleRedraw,
            &mut rng,
        )
        .unwrap();
        assert_eq!(new_size, size);
        assert!(usize::from(data[offset]) < AdversaryRole::COUNT);
        assert_eq!(&data[..offset], &original[..offset]);
        assert_eq!(&data[offset + 1..], &original[offset + 1..]);
    }

    #[test]
    fn no_room_or_undecodable_input_defers_to_the_default_mutator() {
        // Shrinking below the structured prefix leaves no room for a role byte.
        let (mut data, offset) = parent();
        let size = data.len();
        let mut rng = FuzzRng::new(vec![5]);
        assert!(
            rewrite(
                &mut data,
                size,
                offset,
                &honest_trace(1),
                Mode::PolicyRollout,
                &mut rng
            )
            .is_none()
        );
    }

    #[test]
    fn trace_cache_is_keyed_by_input_bytes_and_bounded() {
        let a = b"input-a".to_vec();
        set_current_input(&a);
        let key = current_key().expect("announced");
        record_trace(key, honest_trace(2));
        assert_eq!(trace_of(key_of(&a)).map(|t| t.len()), Some(2));
        assert!(trace_of(key_of(b"input-b")).is_none());
        for i in 0..(TRACE_CACHE_CAP as u64 + 8) {
            record_trace(u64::MAX - i, honest_trace(1));
        }
        assert!(
            traces().lock().traces.len() <= TRACE_CACHE_CAP,
            "cache stays bounded"
        );
    }
}
