//! Retention: the floor at or below which views are no longer retained.
//!
//! The floor trails the newest view whose L-QC was reported finalized (`v_lqc`) by the retention
//! window `W` ([`Tuning::view_retention`](crate::multimmit::config::Tuning::view_retention)), and
//! stays at least two views below the current one, so the V-QC the current view was entered on is
//! never retired. Every view at or below the floor is resolved: its successor's emission state is
//! defined.
//!
//! Raising the floor ([`Change::RetentionAdvanced`](super::durability::Change::RetentionAdvanced))
//! durably drops the retired views' signing slots, emissions, forwarding records, exits,
//! entry-chain ancestors, and local artifacts, and per chain the accepted and own headers below the
//! lowest height retention keeps (the base of the view after the floor, or the accepted tip when
//! that is lower, so each chain keeps its tip). It records the floor's root: the V-QC of the floor
//! view on the chain the current view was entered on, with its history record, on which a restart
//! holds the retained V-QCs again.
//!
//! The volatile state of the components follows the durable floor: held headers at or below the
//! retained heights, V-QCs and L-QCs of retired views, the signatures of votes for retired leader
//! blocks, and, once their tags also left the window the pool reads, the votes of retired tags.

use crate::{
    multimmit::machine::{
        capability::{Capabilities, Capability, ResolverCommand},
        reducer::{
            components::{WorkResult, WorkStatus},
            machine::Machine,
        },
    },
    types::View,
};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Runs one quantum of retention: raises the durable floor when the finalized view allows it
    /// and the floor's root is held, then prunes volatile state to the durable floor.
    pub(in crate::multimmit::machine) fn drive_retention(&mut self) -> WorkResult<V, H::Digest> {
        let mut capabilities = Capabilities::new();
        let state = &self.durable.state;
        let window = self.profile.tuning().view_retention.get();
        let floor = View::new(
            self.components
                .emitter
                .finalized
                .get()
                .saturating_sub(window)
                .min(state.view.get().saturating_sub(2)),
        );
        if floor > state.retired_view
            && let Some(root) = self.retention_root(floor)
            && !self.stage(self.retention_advance(floor, root), &mut capabilities)?
        {
            return Ok((WorkStatus::Blocked, capabilities));
        }
        capabilities.extend(self.prune_retired());
        Ok((WorkStatus::Complete, capabilities))
    }

    /// Prunes the components' volatile state to the durable floor, and tells the resolver to stop
    /// serving the headers of every chain whose header floor rose.
    pub(in crate::multimmit::machine) fn prune_retired(&mut self) -> Capabilities<V, H::Digest> {
        let mut capabilities = Capabilities::new();
        let state = &self.durable.state;
        let retired = state.retired_view;
        let genesis = self.profile.protocol().genesis().tips();
        for (tip, height) in genesis.iter().zip(state.retained_heights(genesis)) {
            let chain = tip.chain();
            let floor = height.previous().unwrap_or(height);
            let Some(dropped) = self.components.chain.headers.retain_above(chain, floor) else {
                continue;
            };
            for id in dropped {
                self.store.remove(&id);
            }
            capabilities.push(Capability::Resolver(ResolverCommand::SettleHeaders {
                chain,
                height: floor,
            }));
        }
        self.retire_vqcs_through(retired);
        self.retire_leader_votes_through(retired);
        let (low, _) = self.vote_tags();
        self.retire_votes_through(retired.min(low.previous().unwrap_or(View::zero())));
        capabilities
    }
}
