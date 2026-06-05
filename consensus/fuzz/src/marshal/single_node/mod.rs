//! Single-actor fuzz driver for the marshal actor.
//!
//! Drives a single marshal actor under test by synthesizing every input
//! marshal would normally receive from the consensus engine and from peers
//! (blocks, notarizations, finalizations) and feeding them through the
//! mailbox directly. Generic over `H: TestHarness` so the standard and
//! coding variants share the same driver and corpora-per-binary discipline.
//!
//! # Invariants checked
//!
//! - **In-order delivery, no gaps within a marshal instance.** Within each
//!   actor lifetime (segment between restarts), the first validated delivery
//!   is `setup.height + 1` and subsequent deliveries advance strictly by one;
//!   the height-0 genesis floor block surfaced on a fresh start is filtered
//!   out. Marshal documents this guarantee on `Update::Block`.
//! - **Ready-prefix delivery (anchor-based, chain-aware repair).**
//!   When a `ReportFinalization` at height `h` arrives while block
//!   `h` is locally available (durable or variant), marshal stores a
//!   finalized anchor at `h` in its finalized archive. The driver mirrors this
//!   with a persistent `finalized_available` set that also includes repaired
//!   ancestors written into the finalized archive.
//!
//!   A `ReportFinalization` only triggers a repair wake when its
//!   height is strictly above marshal's `processed_height` AND the
//!   block is locally available. At-or-below-floor finalizations
//!   are dropped by marshal's `store_finalization` (see
//!   actor.rs:1732) and `try_repair_gaps` is gated on store success
//!   (actor.rs:648). The driver mirrors this with a shadow
//!   `processed_height`: initialized to `setup.height.get()`,
//!   advanced on non-stale `AckNext`, and reset to
//!   `setup.height.get()` after `Restart`.
//!
//!   On each repair wake (every above-floor `ReportFinalization`
//!   that found its block, and every `Restart` after the variant
//!   cache is cleared, since marshal's startup path runs
//!   `try_repair_gaps` unconditionally) the driver mirrors marshal's
//!   backward gap repair. Repair can write ancestors above a lower missing gap
//!   into the finalized archive. Those ancestors survive future restarts even
//!   if they were originally sourced from the variant cache. The driver advances
//!   `ready_prefix` when `finalized_available` is contiguous from height 1.
//!
//!   Availability state:
//!     - `durable_available`: heights set by Propose / Verify /
//!       Certify (marshal persists them), anchor blocks persisted by
//!       `ReportFinalization` when the block was locally available
//!       at that moment (marshal writes the block to
//!       `finalized_blocks` alongside the finalization), plus ancestors
//!       repaired into `finalized_blocks`. Survives restart.
//!     - `variant_available`: heights set by `PublishViaVariant`
//!       after confirmed local availability. Lives only in the
//!       in-memory buffered / shards cache; cleared on `Restart`.
//!     - `finalized_available`: heights stored in `finalized_blocks` by
//!       finalization or repair. Survives restart.
//! - **At-least-once across restart.** Heights pending ack at the moment
//!   of restart are tracked. A later actor instance must redeliver each
//!   of them at least once before the run ends.
//! - **Digest fidelity.** Every finalized block surfaced in the append-only
//!   application delivery log must match the canonical chain digest at its
//!   height. The height-0 genesis floor block (surfaced on a fresh start) is
//!   skipped: it is not part of the canonical chain, which starts at height 1.
//! - **Durability acks.** `H::propose`/`H::verify`/`H::certify` return
//!   `true` on durable persist; `false` surfaces an actor-died panic.
//!
//! # Variant buffer coverage
//!
//! `PublishViaVariant` exercises marshal's interaction with the local
//! variant cache (buffered broadcast engine for Standard, shards engine
//! for Coding). After publishing, the driver verifies the block actually
//! landed in the local cache before counting it as `provided`; a publish
//! that silently drops does not register.
//!
//! The marshal-mailbox path (`H::propose`/`H::verify`/`H::certify`) does
//! NOT route through the shards mailbox for the coding harness: those
//! wrappers call `handle.mailbox.proposed/verified/certified` directly.
//! Shards-mailbox coverage is therefore exclusively via
//! `PublishViaVariant`.
//!
//! # Auxiliary query coverage
//!
//! `GetBlock`, `Subscribe`, `SetFloor`, and `Prune` issue read, floor, or
//! prune-below-floor mailbox traffic. Reads are pure. Subscriptions keep their
//! receiver parked so the actor observes them. `SetFloor` is constrained to the
//! next processable height while the current delivery segment has no real block
//! deliveries, which lets the shadow model represent both local and pending
//! floor-anchor application without accepting delivery gaps. `Prune` is clamped
//! to the processed floor so it only removes already-delivered data.
//!
//! # Known scope limitations
//!
//! - Single-validator only: peer-to-peer shard *dissemination* and
//!   *reconstruction-from-peer-shards* are not exercised. Multi-validator
//!   coding is covered by the [`super::multi_node`] model.
//! - Floor jumps that skip undispatched heights are intentionally not modeled
//!   in this single-node harness. They require a richer delivery shadow that
//!   tracks sync-start changes independently from restart segments.
//!
//! # Layout
//!
//! - `input` defines the libFuzzer-facing scenario type.
//! - `variant` adapts the standard / coding variant mailboxes to a
//!   single publish trait the driver can call generically.
//! - [`invariant`] holds the end-of-run assertions, one per property.
//! - `runner` holds the deterministic-runtime driver and delegates
//!   to [`invariant::check_all`] at the end.

mod input;
pub mod invariant;
mod runner;
mod variant;

pub use input::{MarshalEvent, MarshalFuzzInput};
pub use runner::fuzz_marshal;
pub use variant::VariantPublish;

/// Number of blocks in the canonical single-node fuzz chain.
const NUM_BLOCKS: u64 = 16;
