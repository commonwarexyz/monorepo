//! View-level counts over the pool, the facts the view and emission layers decide on.
//!
//! Endorsements "in view `v`" count every read vote tagged `v` or earlier, through the per-header
//! endorser partitions by tag that the header store keeps (see
//! [`headers`](crate::multimmit::machine::chain::headers)); a vote counts once, as it was
//! interpreted at its first read. Settledness counts only votes tagged `v`, through each sender's
//! first binding vote per chain. Every count reads held headers only: a tip the pool could not
//! resolve endorses nothing toward `b*` and counts as reaching beyond it for settledness.
//!
//! - [`Machine::final_tip`]: `b*_i`, the highest window block extending the base that `n - f`
//!   validators endorse in the view.
//! - Settledness, `phi_i`, `gamma_i`, and whether `gamma_i + (n - phi_i) <= n - 4f - 1`, is
//!   tallied by the emission sweep from [`Machine::first_binding`].
//! - [`Machine::leader_votes`]: votes for one leader block.
//! - [`Machine::finals`] and [`Machine::first_binding`]: the read votes themselves, for V-QC
//!   assembly, determination, and declaration rule (v).
//!
//! The height quorum `h*` and adoption belong to the chain layer, fed by the same reads.

#[cfg(test)]
use crate::multimmit::algebra::{Settledness, settled};
use crate::{
    multimmit::{
        machine::reducer::machine::Machine,
        types::{BlockRef, ChainId, VoteContent},
    },
    types::{Participant, View},
};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use std::sync::Arc;

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Returns `b*` on `base`'s chain in `view`: the highest block of the window above `base`
    /// extending it that `n - f` validators endorse through votes tagged `view` or earlier, or
    /// `base` when there is none, given `from`: `base` or a block of the window on the path
    /// to `b*`.
    ///
    /// Endorsers of a block endorse its ancestors, so qualifying blocks form one path up from the
    /// base (two blocks of one height cannot both reach `n - f`); the walk follows it. Endorsements
    /// only accumulate, so a `b*` found before is a valid `from`, and the walk resumes there.
    pub(in crate::multimmit::machine) fn final_tip(
        &self,
        view: View,
        base: &BlockRef<H::Digest>,
        from: BlockRef<H::Digest>,
    ) -> BlockRef<H::Digest> {
        let codec = self.profile.codec();
        let quorum = codec.view_quorum();
        let end = base.height().get() + u64::from(codec.window().cap());
        let headers = &self.components.chain.headers;
        let mut tip = from;
        while tip.height().get() < end {
            let next = headers
                .at(tip.chain(), tip.height().next())
                .iter()
                .find(|entry| {
                    entry.header.parent() == tip.digest()
                        && entry.endorsements_through(view) >= quorum
                });
            match next {
                Some(entry) => tip = entry.block(),
                None => break,
            }
        }
        tip
    }

    /// Returns the settledness counts of `base`'s chain in `view` given its `b*`, `final_tip`,
    /// evaluated from every first binding vote at once.
    #[cfg(test)]
    pub(in crate::multimmit::machine) fn settledness(
        &self,
        view: View,
        base: &BlockRef<H::Digest>,
        final_tip: &BlockRef<H::Digest>,
    ) -> Settledness {
        settled(
            base,
            final_tip,
            self.profile.codec(),
            self.first_binding(view, base.chain()).iter().copied(),
            &self.components.chain.headers,
        )
    }

    /// Returns, for every sender with a vote tagged `view` binding it on `chain`, the tip of the
    /// first such vote read, in read order. Later reads only append.
    ///
    /// A vote binds its sender on a chain when it is final, declares the chain, or its tip there is
    /// capped against the view's resolved base `beta_v`, the base settledness is measured against.
    /// A vote read before `beta_v` is resolved binds only by being final or declaring the chain: a
    /// tip capped against any other base may still be below the window end of `beta_v`, and its
    /// sender free to extend it.
    pub(in crate::multimmit::machine) fn first_binding(
        &self,
        view: View,
        chain: ChainId,
    ) -> &[(Participant, BlockRef<H::Digest>)] {
        self.components
            .pool
            .tags
            .get(&view)
            .and_then(|tag| tag.bindings.get(chain.index()))
            .map_or(&[], Vec::as_slice)
    }

    /// Returns how many validators voted for the leader block `leader` in `view`, counting any
    /// read vote for it.
    pub(in crate::multimmit::machine) fn leader_votes(
        &self,
        view: View,
        leader: &H::Digest,
    ) -> usize {
        self.components
            .pool
            .tags
            .get(&view)
            .and_then(|tag| tag.leaders.get(leader))
            .map_or(0, |voters| voters.count_ones() as usize)
    }

    /// Returns the final votes read for `view`, in read order.
    pub(in crate::multimmit::machine) fn finals(
        &self,
        view: View,
    ) -> impl Iterator<Item = (Participant, &Arc<VoteContent<H::Digest>>)> + '_ {
        let pool = &self.components.pool;
        pool.tags
            .get(&view)
            .into_iter()
            .flat_map(|tag| tag.finals.iter())
            .filter_map(move |sender| {
                let content = pool.reader(view, *sender)?.last.latest()?;
                Some((*sender, content))
            })
    }

    /// Returns the latest vote read from `sender` tagged `view`.
    #[cfg(test)]
    pub(in crate::multimmit::machine) fn latest_vote(
        &self,
        sender: Participant,
        view: View,
    ) -> Option<&Arc<VoteContent<H::Digest>>> {
        self.components.pool.reader(view, sender)?.last.latest()
    }
}
