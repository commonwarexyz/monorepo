//! The adversary multiplexer for a byzantine Mallory episode.
//!
//! In a byzantine episode node 0 ([`crate::BYZANTINE_IDX`]) is an unmanaged
//! Byzantine actor for the whole run. The [`RoleMultiplexer`] is the SINGLE owner
//! of node 0's three raw consensus channels: it spawns the current Byzantine
//! profile's actor and, on a per-step [`SetRole`](super::fault::Fault::SetRole),
//! swaps to a different profile so the learner can compose faults across views
//! (e.g. conflict at one view, equivocate at a later one).
//!
//! # Single live actor
//!
//! Only ONE actor is ever live at a time (abort-then-respawn, never
//! pre-spawn-and-gate), so the single-consumer channel mailboxes always have
//! exactly one owner. [`set_role`](RoleMultiplexer::set_role) aborts and awaits the
//! live actor's [`Handle`] FIRST, driving it to termination and cascading to its
//! sub-tasks, before re-registering and spawning the replacement, so no second
//! incarnation ever coexists with the first.
//!
//! # Re-registration preserves connectivity
//!
//! Re-registration through the owned [`Oracle`] clone overwrites node 0's three
//! mailboxes, disconnecting the aborted actor's receivers, while leaving the
//! honest<->node0 links intact, so the honest quorum keeps delivering to (and
//! hearing from) node 0's fresh actor. This mirrors the durable-restart
//! re-registration in [`crate::mallory::runner`].
//!
//! # Scope
//!
//! The multiplexer only ever hosts the six Byzantine profiles; node 0 stays
//! Byzantine throughout the episode, so the oracle treatment is unchanged
//! (`ambiguous = [0]`, safety excludes node 0). An Honest<->Byzantine mid-episode
//! transition is out of scope (it would need an amnesia-style oracle flip).

use super::adversary::{spawn_adversary, AdversaryRole};
use crate::{simplex::Simplex, NetworkChannels, PublicKeyOf};
use commonware_consensus::simplex::mocks::relay;
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_p2p::simulated::Oracle;
use commonware_runtime::{deterministic, Handle, Supervisor as _};
use std::sync::Arc;

/// Owns node 0's Byzantine identity for a byzantine Mallory episode and swaps its
/// active [`AdversaryRole`] on demand.
///
/// Holds everything a role switch needs: node 0's public key and signing `scheme`,
/// an [`Oracle`] clone for re-registration, the shared `relay` and `required_containers`
/// the profiles need, the current active role, the live actor's task handle, and a
/// switch counter. Exactly one actor is live between calls, so `handle` is always
/// `Some` outside [`set_role`](Self::set_role).
pub(crate) struct RoleMultiplexer<P: Simplex> {
    /// Node 0's public key, re-registered on every role switch.
    node0: PublicKeyOf<P>,
    /// Node 0's signing scheme, cloned into each spawned actor.
    scheme: P::Scheme,
    /// Oracle clone used to re-register node 0's channels on a switch.
    oracle: Oracle<PublicKeyOf<P>, deterministic::Context>,
    /// Shared relay the [`AdversaryRole::Equivocator`] broadcasts through.
    relay: Arc<relay::Relay<Sha256Digest, PublicKeyOf<P>>>,
    /// The disrupter's finalization target (ignored by the other profiles).
    required_containers: u64,
    /// The currently active Byzantine profile.
    role: AdversaryRole,
    /// The live actor's task handle; aborted and awaited before each switch.
    handle: Option<Handle<()>>,
    /// Number of role switches enacted this episode (for the switch cap and log).
    switches: u32,
}

impl<P: Simplex> RoleMultiplexer<P> {
    /// Spawn the INITIAL Byzantine `role`'s actor on node 0's raw registered
    /// `channels` and take ownership of node 0's identity for the episode.
    ///
    /// `role` must be Byzantine; the multiplexer never hosts
    /// [`Honest`](AdversaryRole::Honest).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        context: &deterministic::Context,
        node0: PublicKeyOf<P>,
        scheme: P::Scheme,
        oracle: Oracle<PublicKeyOf<P>, deterministic::Context>,
        relay: Arc<relay::Relay<Sha256Digest, PublicKeyOf<P>>>,
        required_containers: u64,
        role: AdversaryRole,
        channels: NetworkChannels<PublicKeyOf<P>>,
    ) -> Self {
        debug_assert!(
            role.is_byzantine(),
            "the multiplexer only hosts byzantine roles"
        );
        let ctx = context
            .child("validator")
            .with_attribute("public_key", &node0);
        let handle = spawn_adversary::<P>(
            role,
            ctx,
            scheme.clone(),
            required_containers,
            relay.clone(),
            P::Elector::default(),
            channels,
        );
        Self {
            node0,
            scheme,
            oracle,
            relay,
            required_containers,
            role,
            handle: Some(handle),
            switches: 0,
        }
    }

    /// Swap node 0's active Byzantine profile to `new_role`.
    ///
    /// Aborts and awaits the live actor FIRST (no double incarnation), re-registers
    /// node 0's three channels through the owned oracle (disconnecting the aborted
    /// actor's receivers while keeping the honest<->node0 links), then spawns the
    /// `new_role` actor on the fresh channels. Any parameters the new actor draws
    /// come from the runtime `context` RNG, so a replay reproduces the switch.
    ///
    /// `new_role` must be Byzantine.
    pub(crate) async fn set_role(
        &mut self,
        new_role: AdversaryRole,
        context: &mut deterministic::Context,
    ) {
        debug_assert!(
            new_role.is_byzantine(),
            "the multiplexer only hosts byzantine roles"
        );
        // (1) Abort+await the live actor so no second incarnation coexists; aborting
        //     cascades to its sub-tasks and awaiting drives it to termination.
        if let Some(handle) = self.handle.take() {
            handle.abort();
            let _ = handle.await;
        }
        // (2) Re-register node 0's three channels: overwrites its mailboxes (which
        //     disconnects the aborted actor's receivers) and hands back fresh raw
        //     channels, while the honest<->node0 links stay intact.
        let mut fresh =
            crate::utils::register(&mut self.oracle, std::slice::from_ref(&self.node0)).await;
        let channels = fresh
            .remove(&self.node0)
            .expect("node 0 must re-register its own channels");
        // (3) Spawn the replacement on the fresh channels and adopt it.
        let ctx = context
            .child("validator")
            .with_attribute("public_key", &self.node0);
        self.handle = Some(spawn_adversary::<P>(
            new_role,
            ctx,
            self.scheme.clone(),
            self.required_containers,
            self.relay.clone(),
            P::Elector::default(),
            channels,
        ));
        self.role = new_role;
        self.switches += 1;
    }

    /// The currently active Byzantine profile.
    pub(crate) fn current_role(&self) -> AdversaryRole {
        self.role
    }

    /// The number of role switches enacted this episode. The runner reads this to
    /// enforce the switch cap in the legal mask.
    pub(crate) fn switches(&self) -> u32 {
        self.switches
    }
}
