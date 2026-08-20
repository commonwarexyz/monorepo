//! Chaos mode: an all-honest committee under a fuzzer-driven crash/network
//! fault schedule, adapted from the zksync-os-server chaos rig
//! (`tools/chaos`) for the in-process libfuzzer harness.
//!
//! Where byzzfuzz owns bounded protocol-round Byzantine faults and mallory owns
//! the adaptive Byzantine adversary, chaos owns the CRASH-FAULT axis. It checks
//! SAFETY only. Its firsts relative to every existing mode:
//!
//! - lifecycle faults on ANY node (mallory pins lifecycle to node 0);
//! - multiple concurrently broken nodes (a killed node beside a disconnected
//!   one), composed by the schedule's per-node conditions;
//! - the `crate::invariants` suite asserted at EVERY step boundary (not just
//!   at episode end): the audit-history invariants over the recording
//!   reporters' lossless, generation-stamped event logs (each restart stamps a
//!   new incarnation), plus a step-level finalized-payload-uniqueness oracle
//!   over the reporters' append-only finalize-vote maps (loss-free across
//!   polls).
//!
//! The `SimplexCertificateMock` targets run the finalized-payload-uniqueness
//! check. The harness reports individual finalize votes to the reporter directly
//! (no `AttributableReporter` wrapper), so the append-only `finalizes` map is
//! populated regardless of scheme attributability, and a conflicting
//! finalization landing between two polls is never lost (unlike the
//! overwrite-only certificate map).
//!
//! Vocabulary, mapped onto the mechanisms it reuses:
//!
//! | chaos action | mechanism |
//! |---|---|
//! | `Kill` | `mallory::lifecycle::crash_stop` (abort both task handles) |
//! | `Start` | durable restart: re-register + rebuild on the same partition |
//! | `Reload` | abort, fixed downtime, then the same durable rebuild |
//! | `Disconnect` / `Reconnect` | surgical per-edge oracle link changes |
//!
//! The reference rig's doctrine "a seed replays the experiment, not the
//! execution" INVERTS here: the deterministic runtime is seeded from
//! `FuzzRng::new(input.raw_bytes)` and chaos keeps no cross-input state, so a
//! saved input replays the execution exactly; findings panic (libfuzzer keeps
//! the input) and the decision log is dumped when `CONSENSUS_FUZZ_LOG` is set.
//!
//! Out of scope, deliberately: liveness (a sound liveness oracle would need a
//! journal-replay / catch-up completion signal the harness does not expose, and
//! the finalization monitors are lossy, so chaos asserts none, at any point);
//! a graceful per-node stop (the engine only honors a runtime-wide stop signal,
//! so "stop" would be kill with extra steps); degraded-but-live network weather
//! (the netem analog; mallory's packet-fault pump is the natural future home);
//! indefinite-run bug classes such as slow leaks (an episode is bounded by its
//! finalization budget); and the reference's unexpected-death check (the
//! deterministic runtime already propagates any engine task panic into the
//! run).

pub(crate) mod log;
pub(crate) mod runner;
pub(crate) mod schedule;
pub(crate) mod twins;
pub(crate) mod watch;
