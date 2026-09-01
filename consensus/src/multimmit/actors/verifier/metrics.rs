//! Metrics registered by the verifier.

use crate::multimmit::{
    actors::metrics::{COUNT_POW2_FROM_ONE, COUNT_POW2_FROM_ZERO},
    machine::VerifyJob,
    types::Artifact,
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use commonware_runtime::{
    Metrics as MetricsTrait,
    telemetry::metrics::{Histogram, MetricsExt as _, histogram},
};
use std::ops::Index;

/// Buckets for the transcript messages behind one certificate.
const TRANSCRIPT_MESSAGES: [f64; 11] = [
    0.0, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 48.0, 64.0, 128.0, 256.0,
];

/// The artifacts one verification job carries, used as a metric label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum VerificationKind {
    /// Only view-critical proposals and view messages.
    ViewMessage,
    /// Only V-QCs.
    Vqc,
    /// Only L-QCs.
    Lqc,
    /// Only artifacts the round does not wait on.
    Bulk,
    /// More than one of the above.
    Mixed,
}

impl VerificationKind {
    const ALL: [Self; 5] = [
        Self::ViewMessage,
        Self::Vqc,
        Self::Lqc,
        Self::Bulk,
        Self::Mixed,
    ];

    /// Classifies `job` by the kinds of its items.
    pub(super) fn of<V: Variant, D: Digest>(job: &VerifyJob<V, D>) -> Self {
        job.items()
            .iter()
            .map(|item| match item.artifact() {
                Artifact::Vqc(_) => Self::Vqc,
                Artifact::Lqc(_) => Self::Lqc,
                artifact if artifact.view_critical() => Self::ViewMessage,
                _ => Self::Bulk,
            })
            .reduce(|left, right| if left == right { left } else { Self::Mixed })
            .unwrap_or(Self::Mixed)
    }

    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::ViewMessage => "view_message",
            Self::Vqc => "vqc",
            Self::Lqc => "lqc",
            Self::Bulk => "bulk",
            Self::Mixed => "mixed",
        }
    }
}

/// One value per [`VerificationKind`], indexed by kind.
pub(super) struct PerKind<T>([T; VerificationKind::ALL.len()]);

impl<T> Index<VerificationKind> for PerKind<T> {
    type Output = T;

    fn index(&self, kind: VerificationKind) -> &T {
        // `VerificationKind::ALL` lists the kinds in discriminant order.
        &self.0[kind as usize]
    }
}

/// Timing of the verification jobs of one kind.
pub(super) struct KindMetrics {
    /// Worker execution time of one job.
    pub(crate) latency: histogram::Timed,
    /// Time from executor submission to worker entry.
    pub(crate) queue: Histogram,
}

/// Verifier actor metrics.
pub(super) struct Metrics {
    /// Views a verified vote trails the job that carried it.
    ///
    /// Peers that fall behind show up as a growing upper tail.
    pub(crate) verified_vote_lag: Histogram,
    /// Artifacts in one verification job.
    pub(crate) batch_size: Histogram,
    /// Per-kind job timing.
    pub(crate) kinds: PerKind<KindMetrics>,
    /// Time from the voter reserving a job's permit to its executor submission.
    pub(crate) verification_dispatch_wait: Histogram,
    /// Transcript messages of one verified certificate.
    pub(crate) certificate_transcript_messages: Histogram,
    /// Cached verified votes supplied to one certificate verification, before transcript matching.
    pub(crate) certificate_known_messages: Histogram,
}

impl Metrics {
    pub(crate) fn new<E: MetricsTrait>(context: &E) -> Self {
        Self {
            verified_vote_lag: context.histogram(
                "verified_vote_lag",
                "views a cryptographically verified vote trails the job that carried it",
                COUNT_POW2_FROM_ZERO,
            ),
            batch_size: context.histogram(
                "batch_size",
                "artifacts in one verification job",
                COUNT_POW2_FROM_ONE,
            ),
            kinds: PerKind(VerificationKind::ALL.map(|kind| {
                let verify = context.child("verify").with_attribute("kind", kind.label());
                KindMetrics {
                    latency: histogram::Timed::new(verify.histogram(
                        "latency",
                        "worker execution time of one verification job",
                        histogram::Buckets::CRYPTOGRAPHY,
                    )),
                    queue: verify.histogram(
                        "queue",
                        "time from executor submission to verification worker entry",
                        histogram::Buckets::CRYPTOGRAPHY,
                    ),
                }
            })),
            verification_dispatch_wait: context.histogram(
                "verification_dispatch_wait",
                "time from voter permit reservation to verification executor submission",
                histogram::Buckets::LOCAL,
            ),
            certificate_transcript_messages: context.histogram(
                "certificate_transcript_messages",
                "transcript messages of one verified certificate",
                TRANSCRIPT_MESSAGES,
            ),
            certificate_known_messages: context.histogram(
                "certificate_known_messages",
                "cached verified votes supplied to one certificate verification before transcript matching",
                TRANSCRIPT_MESSAGES,
            ),
        }
    }
}
