//! Benchmark tooling: synthetic input and proposal latency measurement.
//!
//! None of this is needed to run Multimmit. It paces producers with synthetic input and measures
//! how long local blocks take to finalize and to reach the total order.
//!
//! # Input
//!
//! `--offered-bytes-per-second` feeds each producer at a constant rate. A benchmark [`Config`]
//! instead replays a finite [`Schedule`]. Either way, input is cut into batches of exactly one
//! block body, and a batch is submitted when its last byte arrives (with 512-byte transactions
//! and 256 KiB bodies, 512 transactions per batch). Consensus asks for a block as soon as the
//! producer's window admits one; the block carries the oldest submitted batch, or is empty when
//! none is queued. Empty blocks are not tracked, so every latency sample stands for one full
//! batch and per-block statistics are also per-transaction statistics. Their parent links are
//! kept, so a final position on an empty block still covers the batches below it.
//!
//! # Latency
//!
//! `application_proposal_finalization_latency` measures batch submission to the first local
//! consensus finality covering the block (a resolved view's tip or the swept view's per-chain
//! final at or above it), including queueing, body construction, custody, and signing. Without
//! offered load, submission happens right before body construction. Finality resolves retained
//! local ancestry, so a block finalized through a descendant tip still counts once.
//! `application_proposal_ordering_latency` measures submission to delivery in the total order,
//! which also waits for marshal to collect ordering proofs and read the block. Finality and
//! delivery are timestamped when consensus and marshal report them, before the report waits in
//! the application's mailbox, so the application's own queueing is not part of either sample.
//!
//! `application_proposal_signed_finalization_latency` and
//! `application_proposal_signed_ordering_latency` measure the same blocks from their header
//! signature instead. When a block is signed, it captures the finality goal `2 * delta_hat + eta`
//! from the latest engine inspection; `application_proposal_goal_met` over
//! `application_proposal_goal_finalized` is the share of blocks final within that goal.
//!
//! The start boundary matches BlueBottle's `latency_s`, which timestamps transactions in its
//! generator before they enter consensus. Every transaction in a fixed-size batch shares the
//! batch's submission time.
//!
//! # Benchmark Events
//!
//! With a benchmark configured, every tracked block logs INFO events with
//! `latency_start="batch_submission"` and raw microsecond timestamps; `started_at_us` identifies
//! the submission cohort, and `signed_at_us` and `goal_us` give the header signature time and
//! captured goal once known. Samples are per block. A block can go unobserved after a restart, an
//! eviction, or missing local ancestry, so report pending and evicted samples (the
//! `application_proposal_*` counters) when computing completion rates and percentiles, and
//! compare log counts against those counters to detect lost log lines.

mod latency;
mod workload;

pub use latency::{Finality, FinalityGoal, ProposalLatency};
use serde::{Deserialize, Serialize};
pub use workload::{Batch, EmptyBody, Schedule, ScheduleError, Workload};

/// One benchmark repetition: a finite input schedule and a fresh committee.
///
/// No command in this crate writes it. A benchmark driver adds it under the `benchmark` key of
/// each generated `node-<key>.yaml` before starting a repetition. Benchmarks run headless and
/// cannot be combined with `--offered-bytes-per-second`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// Seed for the committee's key material, so each repetition signs with fresh keys.
    pub committee_seed: u64,
    /// Input arrivals shared by every producer.
    pub schedule: Schedule,
}
