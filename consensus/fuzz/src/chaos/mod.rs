//! Chaos mode: an all-honest committee under a fuzzer-driven crash/network
//! fault schedule, adapted from the zksync-os-server chaos rig
//! (`tools/chaos`) for the in-process libfuzzer harness.
//!
//! Where byzzfuzz owns bounded protocol-round Byzantine faults and mallory owns
//! the adaptive Byzantine adversary, chaos owns the CRASH-FAULT axis. Its four
//! firsts relative to every existing mode:
//!
//! - lifecycle faults on ANY node (mallory pins lifecycle to node 0);
//! - multiple concurrently broken nodes (a killed node beside a disconnected
//!   one), composed by the schedule's per-node conditions;
//! - deliberate below-quorum windows with an ONLINE tip-freeze oracle
//!   (progress without quorum is a safety finding, not a silent counter);
//! - mid-run liveness-stall detection with laggard naming (every other mode
//!   asserts liveness only at episode end).
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
//! Out of scope, deliberately: a graceful per-node stop (the engine only
//! honors a runtime-wide stop signal, so "stop" would be kill with extra
//! steps); degraded-but-live network weather (the netem analog; mallory's
//! packet-fault pump is the natural future home); indefinite-run bug classes
//! such as slow leaks (an episode is bounded by its finalization budget); and
//! the reference's unexpected-death check (the deterministic runtime already
//! propagates any engine task panic into the run).

pub(crate) mod log;
pub(crate) mod runner;
pub(crate) mod schedule;
pub(crate) mod watch;
