//! Benchmark tooling: synthetic input and proposal latency measurement.
//!
//! None of this is needed to run Multimmit. It paces producers with synthetic input and measures
//! how long local blocks take to finalize, to be placed in the total order, and to be delivered in
//! it.
//!
//! # Input
//!
//! `--offered-bytes-per-second` paces each producer at a constant rate. A benchmark [`Config`]
//! instead replays a finite [`Schedule`]. Either way, the generator submits a whole block's
//! payload at each arrival deadline, and a delayed build keeps that submission time.
//!
//! # Latency
//!
//! `application_proposal_signing_latency` measures batch submission to the moment the producer
//! signs the block's header, right before the block is disseminated.
//! `application_proposal_certification_latency` measures batch submission to the first durable
//! local DA certificate covering the block, at its producer. With benchmark events, every node
//! also logs when its durable certificate first covers every eighth height of every chain, so
//! certification at each validator can be measured against the producer's submission time.
//! With payment chains, `application_proposal_receipt_latency` measures submission to the moment
//! the producer forms the block's `n - f` receipt.
//!
//! `application_proposal_finalization_latency` measures batch submission to the first local
//! consensus finality covering the block, including queueing, body construction, custody, and
//! signing. Without offered load, submission happens right before body construction. Finality
//! resolves retained local ancestry, so a block finalized through a descendant tip still counts
//! once. `application_proposal_placement_latency` measures submission to the moment consensus
//! reports that local finality fixed the block's position in the total order
//! ([`Activity::Placed`](commonware_consensus::multimmit::types::Activity::Placed)): a finalized
//! block above the point where its leader's final sweep halts is placed only once later evidence
//! carries the order past it. Placement does not wait for marshal. `application_proposal_ordering_latency` measures submission to delivery in
//! the total order, which also waits for marshal to collect ordering proofs and read the block.
//! Finality, placement, and delivery are timestamped when consensus and marshal report the
//! activity that completes them, before the report waits in the application's mailbox, so the
//! application's own queueing is not part of any sample.
//!
//! The start boundary matches BlueBottle's `latency_s`, which timestamps transactions in its
//! generator before they enter consensus. Every transaction in a fixed-size batch shares the
//! batch's submission time.
//!
//! # Benchmark Events
//!
//! With a benchmark configured, every tracked block logs INFO events with
//! `latency_start="batch_submission"` and raw microsecond timestamps; `started_at_us` identifies
//! the submission cohort. Samples are per block. A block can go unobserved after a restart, an
//! eviction, or missing local ancestry, so report pending and evicted samples (the
//! `application_proposal_*` counters) when computing completion rates and percentiles, and
//! compare log counts against those counters to detect lost log lines.
//!
//! # Faults
//!
//! A benchmark [`Config`] can inject [`Faults`]: random loss of received messages, and leaders
//! that censor chosen producer chains. Crash faults need no configuration: the driver simply does
//! not start the crashed nodes.

mod latency;
mod workload;

pub use latency::ProposalLatency;
use serde::{Deserialize, Serialize};
pub use workload::{EmptyBody, Schedule, ScheduleError, Workload};

/// One benchmark repetition: a finite input schedule and a fresh committee.
///
/// No command in this crate writes it. A benchmark driver adds it under the `benchmark` key of
/// each generated `node-<key>.yaml` before starting a repetition. Benchmarks run headless and
/// cannot be combined with `--offered-bytes-per-second`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Seed for the committee's key material, so each repetition signs with fresh keys.
    pub committee_seed: u64,
    /// Input arrivals shared by every producer.
    pub schedule: Schedule,
    /// Faults injected into the repetition. None by default.
    #[serde(default)]
    pub faults: Faults,
}

/// Faults a benchmark injects.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Faults {
    /// Probability that a node drops each message it receives on any protocol channel.
    ///
    /// Each node samples drops independently, after transport delivery, so the transport never
    /// repairs a loss. Messages the network exchanges internally are unaffected.
    #[serde(default)]
    pub loss: f64,
    /// Participants that censor the [`Self::victims`] whenever they lead: each victim chain is
    /// proposed at the parent tip, with no newer certificate and no blocks. Censors otherwise
    /// follow the protocol, and vote normally.
    #[serde(default)]
    pub censors: Vec<u64>,
    /// Producers whose chains the [`Self::censors`] censor.
    #[serde(default)]
    pub victims: Vec<u64>,
}
