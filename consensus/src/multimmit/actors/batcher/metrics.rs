use crate::{LATENCY, multimmit::actors::metrics::Traffic};
use commonware_runtime::{
    Metrics as MetricsTrait,
    telemetry::metrics::{Counter, CounterFamily, Histogram, MetricsExt as _, histogram},
};

/// View-distance buckets for the lag of a verified vote behind the job that carried it.
///
/// The zero bucket separates current-view votes, which is the healthy case, from any lag at all.
const VIEW_LAG: [f64; 10] = [0.0, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0];

pub(super) struct Metrics {
    pub decoded: CounterFamily<Traffic>,
    /// Views a verified vote trails the job that carried it.
    ///
    /// One histogram replaces a per-participant gauge family, which scaled as the validator
    /// count per node. Peers that fall behind show up as a growing upper tail.
    pub verified_vote_lag: Histogram,
    pub forwarded: Counter,
    pub dropped_lane: Counter,
    pub dropped_peer: Counter,
    pub dropped_voter_cohorts: Counter,
    pub blocked: Counter,
    pub batch_size: Histogram,
    /// Network receipt to voter hand-off of one artifact. The ingress queue on the round's
    /// critical path.
    pub ingress_dwell: Histogram,
    pub verify_latency: histogram::Timed,
    /// Transcript messages of one verified certificate.
    pub certificate_transcript_messages: Histogram,
    /// Transcript messages of one verified certificate that a locally verified vote discharged.
    pub certificate_known_messages: Histogram,
}

impl Metrics {
    pub fn new<E: MetricsTrait>(context: &E) -> Self {
        let decoded = context.family(
            "decoded",
            "decoded canonical ingress messages by network plane",
        );
        for plane in Traffic::VOTER {
            let _ = decoded.get_or_create(&plane);
        }

        let verified_vote_lag = context.histogram(
            "verified_vote_lag",
            "views a cryptographically verified vote trails the job that carried it",
            VIEW_LAG,
        );

        let forwarded = context.counter("forwarded", "artifacts forwarded in observation cohorts");
        let dropped_lane = context.counter("dropped_lane", "artifacts dropped by a full lane");
        let dropped_peer = context.counter(
            "dropped_peer",
            "artifacts dropped by a per-lane peer budget",
        );
        let dropped_voter_cohorts = context.counter(
            "dropped_voter_cohorts",
            "observation cohorts rejected by the voter mailbox",
        );
        let blocked = context.counter("blocked", "peers blocked for invalid traffic");
        let batch_size = context.histogram(
            "batch_size",
            "artifacts in one verification job",
            [1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0],
        );
        let certificate_transcript_messages = context.histogram(
            "certificate_transcript_messages",
            "transcript messages of one verified certificate",
            [0.0, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 48.0, 64.0, 128.0, 256.0],
        );
        let certificate_known_messages = context.histogram(
            "certificate_known_messages",
            "transcript messages of one verified certificate discharged by known votes",
            [0.0, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 48.0, 64.0, 128.0, 256.0],
        );
        let ingress_dwell = context.histogram(
            "ingress_dwell",
            "network receipt to voter hand-off of one artifact",
            LATENCY,
        );
        let verify_latency = context.histogram(
            "verify_latency",
            "latency of one verification job",
            histogram::Buckets::CRYPTOGRAPHY,
        );

        Self {
            decoded,
            verified_vote_lag,
            forwarded,
            dropped_lane,
            dropped_peer,
            dropped_voter_cohorts,
            blocked,
            batch_size,
            ingress_dwell,
            certificate_transcript_messages,
            certificate_known_messages,
            verify_latency: histogram::Timed::new(verify_latency),
        }
    }
}
