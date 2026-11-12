//! Fuzzing for the glue [`commonware_glue::dkg`] module: the one-shot DKG of
//! [`bootstrap`](commonware_glue::dkg::bootstrap), resharing, the probe, and
//! state sync. `SPEC.md` in this directory is the specification; this file
//! summarises what is built.
//!
//! Every target runs the real DKG module under the deterministic runtime over
//! the mock group: a BLS variant whose group is the scalar field, so no curve
//! arithmetic or pairing runs while every check of the ceremony keeps the
//! verdict it has on the real curve.
//!
//! The targets check safety only. Whenever a ceremony completes, the correct
//! nodes must agree on its result, every share they hold must match the
//! public output, and any `required()` of those shares must reconstruct the
//! key behind the group public key. No liveness is asserted: a stalled run, a
//! failed ceremony, and a run that reaches its timeout are healthy.
//!
//! # Targets
//!
//! - `dkg_bootstrap`: five [`bootstrap::Engine`](commonware_glue::dkg::bootstrap::Engine)s
//!   over four identities. One identity is compromised and runs two engines
//!   that share its key and have separate secret stores, so it deals twice
//!   under one identity. Its Simplex channels are split per view by a twins
//!   scenario for the first views, and its DKG channel is split by a mask the
//!   input chooses.
//! - `dkg_bootstrap_restarts`: four correct identities with one
//!   [`bootstrap::Engine`](commonware_glue::dkg::bootstrap::Engine) each. The
//!   engines are crashed and restarted on a schedule drawn from the tape, on
//!   the storage and the secret stores they retain, while the links among
//!   them delay, lose, and temporarily cut off what they carry. Writes an
//!   engine makes shortly before one of its crashes may be held, so that the
//!   crash falls between two of them.
//! - `dkg_reshare`: six reshare stacks over five identities, each the real
//!   marshal, [`reshare::Actor`](commonware_glue::dkg::reshare::Actor),
//!   [`reshare::Application`](commonware_glue::dkg::reshare::Application),
//!   [`orchestrator::Actor`](commonware_glue::dkg::orchestrator::Actor), and
//!   [`probe::Actor`](commonware_glue::dkg::probe::Actor), signing consensus
//!   with the threshold scheme over the mock group. The first output comes
//!   from a trusted deal, and the run reshares it for up to three epochs
//!   among committees of four that the input rotates. The compromised
//!   identity's channels are split per view for the first views of every
//!   epoch and its DKG channel by one mask per epoch, and its secondary half
//!   runs an application that proposes misplaced and wrong reshare payloads.
//! - `dkg_reshare_restarts`: five correct identities with one reshare stack
//!   each, resharing the first output for up to three epochs among the
//!   committees the input rotates. The engines are crashed and restarted on a
//!   schedule drawn from the tape, on the storage and the secret stores they
//!   retain, while the links among them delay, lose, and temporarily cut off
//!   what they carry. Writes are held around the crashes as in
//!   `dkg_bootstrap_restarts`.
//! - `dkg_probe`: one discovering
//!   [`probe::Actor`](commonware_glue::dkg::probe::Actor) and three serving
//!   ones over real marshal actors seeded with a fabricated chain, with no
//!   consensus and no ceremony. The sources' responses are captured as opaque
//!   bytes and a bounded event program releases, replays, and damages them.
//!   Whenever the discovering probe emits an artifact it is compared with what
//!   the sources were seeded with, and every block the probe places is judged
//!   against what was delivered to it.
//! - `dkg_state_sync`: five correct identities with one reshare stack each,
//!   four of which start at genesis. The fifth joins once the others have
//!   applied a height the input selects: its probe discovers a floor and the
//!   description of the floor's epoch, and its marshal, its reshare actor,
//!   and its orchestrator start from that pair through
//!   [`state_sync::Plan`](commonware_glue::dkg::state_sync::Plan). The joiner
//!   may be crashed on its own clock, in the middle of its sync or after it,
//!   and a schedule drawn from the tape crashes and restarts any of the
//!   five, from the joiner's start on. Writes are held around the crashes as
//!   in `dkg_bootstrap_restarts`, the joiner's included. The links are fixed.
//!
//! # Layout
//!
//! - `context` is the runtime context each engine is given, which attributes
//!   the engine's panics to it.
//! - `runner` is what every driver shares around a run: the entry point a
//!   fuzz target calls, the runtime the run executes on, and the reason a run
//!   stopped.
//! - `environment` is what the restart drivers share: the crash and restart
//!   schedule, the link conditions, the late start of an identity, the
//!   supervision of every engine instance across its restarts, and where a
//!   crash found its engine.
//! - `input` and `reshare_input` are the libFuzzer-facing inputs and their
//!   `Arbitrary`.
//! - `mock` is the mock group.
//! - `store` is the secret store each engine is given.
//! - `network` classifies the bootstrap chain's messages for the twins split
//!   and realises the DKG mask.
//! - `pacing` holds some of the durable writes an engine makes shortly before
//!   a scheduled crash, in its secret store and in its storage, so that the
//!   crash falls between two of them, for one identity at a time.
//! - `restarts` is the bootstrap restart driver.
//! - `stack` builds one bootstrap engine.
//! - `twins` is the bootstrap Twins driver.
//! - `app` is the block of the reshare chain and the correct application.
//! - `scheme` is the consensus scheme of the reshare chain, its epoch-keyed
//!   provider, and the registrar that fills it.
//! - `schedule` is the committee schedule and the participants provider.
//! - `reshare_stack` builds one reshare engine, and the marshal of the
//!   reshare chain for the probe driver as well.
//! - `faulty` is the application the secondary half runs in `dkg_reshare`.
//! - `reshare_network` classifies the reshare chain's messages for the twins
//!   split, realises the per-epoch DKG mask, and scripts the leaders.
//! - `reshare_twins` is the reshare Twins driver.
//! - `probe_input` is the probe target's input and event program.
//! - `probe` is the probe driver.
//! - `reshare_restarts_input` is the input of the reshare restart target and
//!   the session controls every driver over correct reshare engines draws.
//! - `reshare_cluster` is the correct reshare engines of a run, kept across
//!   their restarts, and what the oracle reads of them.
//! - `reshare_restarts` is the reshare restart driver.
//! - `joiner` is the caller's side of DKG state sync: the durable record of
//!   an engine's floor and what the engine starts from at each start.
//! - `state_sync_input` is the input of the state-sync target.
//! - `state_sync` is the state-sync driver.
//! - `invariants` holds the observation records and every check.
//! - `fixtures` is what the tests of these modules share.

mod app;
mod context;
mod environment;
mod faulty;
#[cfg(test)]
mod fixtures;
mod input;
mod invariants;
mod joiner;
mod mock;
mod network;
mod pacing;
mod probe;
mod probe_input;
mod reshare_cluster;
mod reshare_input;
mod reshare_network;
mod reshare_restarts;
mod reshare_restarts_input;
mod reshare_stack;
mod reshare_twins;
mod restarts;
mod runner;
mod schedule;
mod scheme;
mod stack;
mod state_sync;
mod state_sync_input;
mod store;
mod twins;

pub(crate) use crate::stateful::PublicKey;
use commonware_cryptography::{Signer as _, ed25519, sha256};
use commonware_glue::dkg::types::EpochInfo;
use commonware_utils::{NZU32, NZU64, NZUsize};
pub use input::{
    Cut, CutScope, DkgBootstrapFuzzInput, DkgBootstrapRestartsFuzzInput, DkgMask,
    EnvironmentControls, LinkControls, Side,
};
pub use invariants::{Counts, ProbeCounts, ReshareCounts, SyncCounts};
pub use mock::{MockGroup, MockPoint};
pub use pacing::PacedCounts;
pub use probe::{ProbeOutcome, ProbeReport, fuzz_dkg_probe, run_dkg_probe};
pub use probe_input::DkgProbeFuzzInput;
pub use reshare_cluster::ReshareRestartCounts;
pub use reshare_input::{DkgReshareFuzzInput, Rotation};
pub use reshare_restarts::{
    ReshareRestartsReport, fuzz_dkg_reshare_restarts, run_dkg_reshare_restarts,
};
pub use reshare_restarts_input::{DkgReshareRestartsFuzzInput, SessionControls};
pub use reshare_twins::{ReshareReport, fuzz_dkg_reshare, run_dkg_reshare};
pub use restarts::{
    BootstrapRestartsReport, RestartCounts, fuzz_dkg_bootstrap_restarts, run_dkg_bootstrap_restarts,
};
pub use runner::Outcome;
pub use state_sync::{StateSyncReport, fuzz_dkg_state_sync, run_dkg_state_sync};
pub use state_sync_input::{DkgStateSyncFuzzInput, FirstOutage, JoinerRestart};
use std::{
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    time::Duration,
};
pub use twins::{BootstrapReport, fuzz_dkg_bootstrap, run_dkg_bootstrap};

/// Block digest type of the bootstrap chain.
pub(crate) type Digest = sha256::Digest;

/// The public description of an epoch over the mock group.
pub(crate) type Info = EpochInfo<MockGroup, PublicKey>;

/// Namespace of the bootstrap ceremony's transcripts.
pub(crate) const BOOTSTRAP_NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_FUZZ_DKG_BOOTSTRAP";

/// Members of the committee. Three of them reconstruct the key.
pub(crate) const COMMITTEE: NonZeroU32 = NZU32!(4);

/// Blocks in an epoch. The first half is the dealing window and the second
/// the inclusion window.
pub(crate) const EPOCH_LENGTH: NonZeroU64 = NZU64!(32);

/// The committee's identity keys, in identity order.
pub(crate) fn identities() -> Vec<ed25519::PrivateKey> {
    signers(COMMITTEE.get())
}

/// The identity keys of a run among `count` identities, in identity order.
pub(crate) fn signers(count: u32) -> Vec<ed25519::PrivateKey> {
    let mut identities: Vec<_> = (0..u64::from(count))
        .map(ed25519::PrivateKey::from_seed)
        .collect();
    identities.sort_by_key(|identity| identity.public_key());
    identities
}

/// The identities `signers` sign as, in the same order.
pub(crate) fn public_keys<C: FromIterator<PublicKey>>(signers: &[ed25519::PrivateKey]) -> C {
    signers.iter().map(|signer| signer.public_key()).collect()
}

/// Bound on the simulated duration of a bootstrap run, with or without
/// restarts. Each driver ends its run earlier when it has nothing left to
/// observe; a run that reaches this bound is healthy.
pub(crate) const BOOTSTRAP_RUN_TIMEOUT: Duration = Duration::from_secs(120);

/// Namespace of the reshare chain: its ceremony transcripts and its consensus
/// signatures.
pub(crate) const RESHARE_NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_FUZZ_DKG_RESHARE";

/// Identities in a reshare run. Every committee is [`COMMITTEE`] of them, so
/// one identity is always outside it.
pub(crate) const RESHARE_IDENTITIES: u32 = COMMITTEE.get() + 1;

/// Most epochs a reshare run may be asked to complete.
pub(crate) const MAX_EPOCHS: u8 = 3;

/// Peer sets the network of a reshare run keeps. Every engine tracks one set
/// per epoch on top of the initial set of every identity, and that initial
/// set must stay tracked for every identity to remain connected whatever
/// committee it is in: the links of a run are fixed or the input's to cut,
/// never the committee's. A run that completes tracks at most five sets. The
/// network sizes each channel by this number, so it is kept small.
pub(crate) const TRACKED_PEER_SETS: NonZeroUsize = NZUsize!(8);

/// Bound on the simulated duration of a reshare run. The run normally ends
/// when every correct engine has processed the last boundary block of the
/// epochs it was asked to complete; a run that reaches this bound is healthy.
pub(crate) const RESHARE_RUN_TIMEOUT: Duration = Duration::from_secs(120);
