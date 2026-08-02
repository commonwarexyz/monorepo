use crate::multimmit::actors::metrics::{Peer, Traffic};
use commonware_cryptography::PublicKey;
use commonware_runtime::{
    Metrics as MetricsTrait,
    telemetry::metrics::{
        Counter, CounterFamily, GaugeFamily, Histogram, MetricsExt as _, histogram,
    },
};
use commonware_utils::ordered::Set;

pub(super) struct Metrics<P: PublicKey> {
    pub decoded: CounterFamily<Traffic>,
    pub latest_verified_vote: GaugeFamily<Peer<P>>,
    pub forwarded: Counter,
    pub dropped_lane: Counter,
    pub dropped_peer: Counter,
    pub dropped_voter_cohorts: Counter,
    pub blocked: Counter,
    pub batch_size: Histogram,
    pub verify_latency: histogram::Timed,
}

impl<P: PublicKey> Metrics<P> {
    pub fn new<E: MetricsTrait>(context: &E, participants: &Set<P>) -> Self {
        let decoded = context.family(
            "decoded",
            "decoded canonical ingress messages by network plane",
        );
        for plane in Traffic::VOTER {
            let _ = decoded.get_or_create(&plane);
        }

        let latest_verified_vote: GaugeFamily<Peer<P>> = context.family(
            "latest_verified_vote",
            "latest cryptographically verified vote view by participant",
        );
        for participant in participants {
            latest_verified_vote.get_or_create_by(participant).set(0);
        }

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
        let verify_latency = context.histogram(
            "verify_latency",
            "latency of one verification job",
            histogram::Buckets::CRYPTOGRAPHY,
        );

        Self {
            decoded,
            latest_verified_vote,
            forwarded,
            dropped_lane,
            dropped_peer,
            dropped_voter_cohorts,
            blocked,
            batch_size,
            verify_latency: histogram::Timed::new(verify_latency),
        }
    }
}
