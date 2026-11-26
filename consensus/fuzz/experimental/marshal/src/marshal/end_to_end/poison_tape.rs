//! Tape-first input for the end-to-end poison bases, and the certificate
//! poison's bounded retry check.
//!
//! [`MarshalDisrupterInput`] decodes its runtime tape last, after its
//! configuration fields, so libFuzzer's first short inputs all run with an
//! empty tape and differ only in the few fields a poison base does not force.
//! [`FuzzInput`] copies the whole input into the tape before any field is
//! decoded, then decodes the configuration from the same bytes: a one-byte
//! input already gets a one-byte tape. Every scheduling and poison decision of
//! a run is drawn from that tape.

use super::MarshalDisrupterInput;
use arbitrary::{Arbitrary, Unstructured};
use commonware_consensus::types::View;
use commonware_consensus_fuzz_core::{
    MAX_RAW_BYTES,
    network::{ActivityKind, CertificatePoison, LedgerRecord},
};
use commonware_cryptography::PublicKey;
use std::time::Duration;

/// Input of the tape-first poison targets.
#[derive(Debug, Clone)]
pub struct FuzzInput {
    /// The runtime tape: the first `MAX_RAW_BYTES` bytes of the whole input.
    pub raw_bytes: Vec<u8>,
    /// The configuration, decoded from the same bytes as the old poison
    /// targets decode it. Its own `raw_bytes` is never used.
    pub base: MarshalDisrupterInput,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let raw_bytes = u
            .peek_bytes(u.len().min(MAX_RAW_BYTES))
            .ok_or(arbitrary::Error::NotEnoughData)?
            .to_vec();
        let base = MarshalDisrupterInput::arbitrary(u)?;
        Ok(Self { raw_bytes, base })
    }
}

/// The coding block-poison cluster of
/// [`fuzz_marshal_coding_block_poison`](crate::marshal::fuzz_marshal_coding_block_poison)
/// on the certificate mock scheme, with the tape-first input.
pub mod coding {
    use super::{
        super::runner::{force_poison, run_coding_disrupter},
        FuzzInput, MarshalDisrupterInput,
    };
    use commonware_consensus_fuzz_core::SimplexCertificateMock;
    use std::time::Duration;

    /// Runs one case; returns the runtime's auditor state and the simulated
    /// time at its end.
    pub fn run(input: FuzzInput) -> (String, Duration) {
        let mut input = MarshalDisrupterInput {
            raw_bytes: input.raw_bytes,
            ..input.base
        };
        force_poison(&mut input);
        run_coding_disrupter::<SimplexCertificateMock>(input, true, None)
    }

    /// Runs one case for the fuzz target.
    pub fn fuzz(input: FuzzInput) {
        let _ = run(input);
    }
}

/// How long the poisoned node has, in simulated time, to retry the poisoned
/// view or settle it: ten times the standard engines' fetch retry delay.
pub const RETRY_BOUND: Duration = Duration::from_secs(1);

/// Start of the panic text of a retry-check violation.
pub const RETRY_VIOLATION: &str = "backfill retry:";

/// Whether the retry check measured a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryCheck {
    /// The poison did not fire.
    NotFired,
    /// The poison fired, but the run ended before the bound expired.
    NotMeasured,
    /// The poison fired and the check held.
    Held,
}

/// The poisoned view and the time of the rewritten answer.
fn poisoned(ledger: &[LedgerRecord]) -> Option<(usize, View, Duration)> {
    ledger
        .iter()
        .enumerate()
        .find_map(|(index, record)| match *record {
            LedgerRecord::Poisoned { view, at } => Some((index, view, at)),
            _ => None,
        })
}

/// The time of the first request for `view` recorded after `index`.
fn first_request(ledger: &[LedgerRecord], index: usize, view: View) -> Option<Duration> {
    ledger[index + 1..].iter().find_map(|record| match *record {
        LedgerRecord::Request { view: v, at } if v == view => Some(at),
        _ => None,
    })
}

/// The first activity in the ledger that settles a nullification ask at
/// `view` under a one-view term: its nullification, a finalization at or
/// above it, or a certification above it.
fn first_settling(ledger: &[LedgerRecord], view: View) -> Option<(ActivityKind, View, Duration)> {
    ledger.iter().find_map(|record| match *record {
        LedgerRecord::Activity { kind, view: v, at }
            if match kind {
                ActivityKind::Nullification => v == view,
                ActivityKind::Finalization => v >= view,
                ActivityKind::Certification => v > view,
            } =>
        {
            Some((kind, v, at))
        }
        _ => None,
    })
}

/// Checks that a poisoned answer was followed, within [RETRY_BOUND], by a
/// request for the poisoned view from the poisoned node or by an activity of
/// its engine that settles that view. `now` is the simulated time of the
/// evaluation; before the bound expires the run is not measured.
///
/// # Panics
///
/// Panics, with text starting [RETRY_VIOLATION], when the check fails.
pub(super) fn check_retry(ledger: &[LedgerRecord], now: Duration) -> RetryCheck {
    let Some((index, view, t0)) = poisoned(ledger) else {
        return RetryCheck::NotFired;
    };
    let deadline = t0 + RETRY_BOUND;
    if now < deadline {
        return RetryCheck::NotMeasured;
    }
    let request = first_request(ledger, index, view);
    let settling = first_settling(ledger, view);
    let held = request.is_some_and(|at| at <= deadline)
        || settling.is_some_and(|(_, _, at)| at <= deadline);
    assert!(
        held,
        "{RETRY_VIOLATION} the poisoned node neither re-requested view {view} nor settled it \
         within {RETRY_BOUND:?} of the poisoned answer at {t0:?}; first later request: {}; first \
         settling activity: {}",
        request.map_or_else(|| "none".to_string(), |at| format!("{at:?}")),
        settling.map_or_else(
            || "none".to_string(),
            |(kind, view, at)| format!("{kind:?} at view {view}, {at:?}")
        ),
    );
    RetryCheck::Held
}

/// What one run of [standard::run] observed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The runtime's auditor state at the end of the run.
    pub state: String,
    /// The simulated time at the end of the run, which is also the time of
    /// the retry check after the liveness phases.
    pub end: Duration,
    /// The poisoned view and the time of the rewritten answer.
    pub poisoned: Option<(View, Duration)>,
    /// The time of the first request for the poisoned view recorded after the
    /// poisoned answer.
    pub first_request: Option<Duration>,
    /// The first activity in the ledger that settles the poisoned view.
    pub first_settling: Option<(ActivityKind, View, Duration)>,
    /// Answers to a re-fetch of the poisoned view.
    pub retries_answered: usize,
    /// Whether the retry check measured the run.
    pub retry_check: RetryCheck,
    /// The whole ledger, in the order its records were made.
    pub ledger: Vec<LedgerRecord>,
}

impl Report {
    fn new<P: PublicKey>(state: String, end: Duration, poison: &CertificatePoison<P>) -> Self {
        let ledger = poison.ledger();
        let found = poisoned(&ledger);
        let retry_check = match found {
            None => RetryCheck::NotFired,
            Some((_, _, t0)) if end < t0 + RETRY_BOUND => RetryCheck::NotMeasured,
            Some(_) => RetryCheck::Held,
        };
        Self {
            state,
            end,
            poisoned: found.map(|(_, view, at)| (view, at)),
            first_request: found.and_then(|(index, view, _)| first_request(&ledger, index, view)),
            first_settling: found.and_then(|(_, view, _)| first_settling(&ledger, view)),
            retries_answered: poison.retries_answered(),
            retry_check,
            ledger,
        }
    }
}

/// The certificate-poison cluster of
/// [`fuzz_marshal_standard_certificate_poison`](crate::marshal::fuzz_marshal_standard_certificate_poison)
/// on the certificate mock scheme, with the tape-first input and the retry
/// check of `check_retry` evaluated in every run.
pub mod standard {
    use super::{
        super::{
            runner::{force_poison, run_standard_disrupter},
            twins::PublicKeyOf,
        },
        FuzzInput, MarshalDisrupterInput, Report,
    };
    use commonware_consensus_fuzz_core::{SimplexCertificateMock, network::CertificatePoison};

    /// Runs one case and returns its report.
    pub fn run(input: FuzzInput) -> Report {
        run_with(input, CertificatePoison::with_ledger())
    }

    /// [run] with a poison whose ledger keeps no evidence of a retry or of a
    /// settling activity, so the retry check must fail whenever the poison
    /// fires and the run is measured.
    #[cfg(test)]
    #[allow(dead_code, reason = "read by tests")]
    pub(crate) fn run_suppressed(input: FuzzInput) -> Report {
        let poison = CertificatePoison::with_ledger();
        poison.suppress_evidence();
        run_with(input, poison)
    }

    fn run_with(
        input: FuzzInput,
        poison: CertificatePoison<PublicKeyOf<SimplexCertificateMock>>,
    ) -> Report {
        let mut forced = MarshalDisrupterInput {
            raw_bytes: input.raw_bytes,
            ..input.base
        };
        force_poison(&mut forced);
        let (state, end, _) = run_standard_disrupter::<SimplexCertificateMock>(
            forced,
            Some(poison.clone()),
            None,
            None,
        );
        Report::new(state, end, &poison)
    }

    /// Runs one case for the fuzz target.
    pub fn fuzz(input: FuzzInput) {
        let _ = run(input);
    }
}

#[cfg(test)]
mod acceptance;
