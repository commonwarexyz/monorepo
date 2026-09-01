//! Planning which committed outputs reach delivery with their bodies.
//!
//! A committed batch hands delivery one descriptor per output it can afford, and upgrades some
//! descriptors to hot bodies so delivery need not read them back. Descriptors and bodies share
//! one hot-byte budget with every commit not yet handed to delivery.

use super::{cache::BlockCache, mailbox::Error};
use crate::multimmit::{
    marshal::{
        actors::delivery::{self, DeliveryOutput, DurableBatch, HotOutput},
        storage::{catalog::StoredRef, commit::OutputRow},
    },
    types::Body,
};
use commonware_cryptography::Hasher;
use std::collections::BTreeSet;

/// Where a hot body came from, in priority order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Source {
    /// Retained by the committing caller.
    Handoff,
    /// Admitted recently and held by the live cache.
    LiveCache,
    /// Read back from storage and held by the materialized cache.
    MaterializedCache,
}

/// A slot's priority for keeping a hot body; a slot without a body ranks last.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Rank {
    Body(Source),
    Descriptor,
}

/// One output's place in the plan.
struct Slot<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    /// Whether delivery receives the output.
    retained: bool,
    /// Whether delivery receives the output's body.
    hot: bool,
    /// A body available for the output.
    body: Option<(Source, HotOutput<H, B>)>,
}

impl<H, B> Slot<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    fn rank(&self) -> Rank {
        self.body
            .as_ref()
            .map_or(Rank::Descriptor, |(source, _)| Rank::Body(*source))
    }
}

/// The hot-byte budget a plan draws from.
pub(super) struct Budget {
    /// Hot bytes delivery may hold across every pending commit.
    pub(super) max_bytes: u64,
    /// Hot bytes already charged to commits not yet handed to delivery.
    pub(super) pending: u64,
}

/// What one commit hands delivery.
pub(super) struct HandoffPlan<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    /// Outputs handed to delivery, or `None` when the commit has no output.
    pub(super) batch: Option<DurableBatch<H, B>>,
    /// Hot bytes `batch` charges.
    pub(super) bytes: u64,
    /// Hot bytes charged to pending commits once this commit is accepted.
    pub(super) pending_bytes: u64,
}

/// Plans the outputs and hot bodies one commit hands delivery.
///
/// The plan first keeps a descriptor for as many leading outputs as the budget allows. It then
/// upgrades outputs to bodies in source priority (caller handoff, live cache, materialized
/// cache), in output order within a source. An upgrade of a retained output costs its body bytes
/// less its descriptor. An output past the descriptor prefix may take the slot of a retained
/// descriptor whose body has lower priority (or none), preferring the lowest-priority, latest
/// such slot, so coverage never narrows.
///
/// `handoff` must carry bodies ordered like `rows`, each naming its row.
pub(super) fn plan<H, B>(
    rows: &[OutputRow<H::Digest>],
    floor_generation: u64,
    handoff: Vec<HotOutput<H, B>>,
    caches: [&BlockCache<H, B>; 2],
    budget: Budget,
) -> Result<HandoffPlan<H, B>, Error>
where
    H: Hasher,
    B: Body<H>,
{
    let Some(committed) = rows.last().map(|row| row.index) else {
        if !handoff.is_empty() {
            return Err(Error::Invalid("delivery handoff has no output row"));
        }
        return Ok(HandoffPlan {
            batch: None,
            bytes: 0,
            pending_bytes: budget.pending,
        });
    };
    let stored = rows
        .iter()
        .map(|row| StoredRef::new(row, floor_generation))
        .collect::<Vec<_>>();
    let available = budget.max_bytes.saturating_sub(budget.pending);
    let descriptor_bytes = delivery::descriptor_bytes::<H::Digest>();
    let descriptors = rows
        .len()
        .min(usize::try_from(available / descriptor_bytes).unwrap_or(usize::MAX));
    let mut bytes = descriptor_bytes.saturating_mul(u64::try_from(descriptors).unwrap_or(u64::MAX));
    let mut slots = (0..rows.len())
        .map(|position| Slot {
            retained: position < descriptors,
            hot: false,
            body: None,
        })
        .collect::<Vec<Slot<H, B>>>();

    let mut handoff = handoff.into_iter().peekable();
    for (slot, row) in slots.iter_mut().zip(&stored) {
        let Some(retained) = handoff.next_if(|retained| retained.stored.index <= row.index) else {
            continue;
        };
        if retained.stored.index != row.index {
            return Err(Error::Invalid(
                "delivery handoff is not ordered with its output rows",
            ));
        }
        if retained.stored != *row || !row.matches(&retained.block) {
            return Err(Error::Invalid(
                "delivery handoff does not match its output row",
            ));
        }
        slot.body = Some((Source::Handoff, retained));
    }
    if handoff.next().is_some() {
        return Err(Error::Invalid(
            "delivery handoff contains an unknown output row",
        ));
    }
    for (source, cache) in [Source::LiveCache, Source::MaterializedCache]
        .into_iter()
        .zip(caches)
    {
        for (slot, row) in slots.iter_mut().zip(&stored) {
            if slot.body.is_some() {
                continue;
            }
            let Some(block) = cache.get(&row.reference) else {
                continue;
            };
            if !row.matches(&block) {
                continue;
            }
            slot.body = Some((
                source,
                HotOutput {
                    stored: *row,
                    block,
                },
            ));
        }
    }

    // Retained descriptors that a higher-priority body may replace, ordered by rank then
    // position so the last entry is the replacement.
    let mut replaceable = slots
        .iter()
        .enumerate()
        .filter(|(_, slot)| slot.retained)
        .map(|(position, slot)| (slot.rank(), position))
        .collect::<BTreeSet<_>>();
    let mut candidates = slots
        .iter()
        .enumerate()
        .filter_map(|(position, slot)| slot.body.as_ref().map(|(source, _)| (*source, position)))
        .collect::<Vec<_>>();
    candidates.sort_unstable();
    for (source, position) in candidates {
        let body_bytes = delivery::body_bytes::<H::Digest>(stored[position].encoded_len);
        let additional = body_bytes.saturating_sub(descriptor_bytes);
        if slots[position].retained {
            if bytes
                .checked_add(additional)
                .is_some_and(|total| total <= available)
            {
                bytes += additional;
                slots[position].hot = true;
                replaceable.remove(&(slots[position].rank(), position));
            }
            continue;
        }
        if additional > available.saturating_sub(bytes) {
            continue;
        }
        let Some(&(rank, replacement)) = replaceable.last() else {
            continue;
        };
        if rank <= Rank::Body(source) {
            continue;
        }
        replaceable.remove(&(rank, replacement));
        bytes += additional;
        slots[replacement].retained = false;
        slots[position].retained = true;
        slots[position].hot = true;
    }
    let pending_bytes = budget
        .pending
        .checked_add(bytes)
        .ok_or(Error::Invalid("pending delivery-cache bytes overflow"))?;
    let mut batch = DurableBatch::builder(floor_generation, committed, budget.max_bytes);
    for (slot, stored) in slots.into_iter().zip(stored) {
        if !slot.retained {
            continue;
        }
        let output = match slot.body.filter(|_| slot.hot) {
            Some((_, output)) => DeliveryOutput::Hot(output),
            None => DeliveryOutput::Descriptor(stored),
        };
        batch
            .push(output)
            .map_err(|_| Error::Invalid("delivery handoff exceeds the hot-byte budget"))?;
    }
    debug_assert_eq!(batch.bytes(), bytes);
    Ok(HandoffPlan {
        batch: Some(batch.build()),
        bytes,
        pending_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{
            marshal::{storage::commit::CustodyRef, types::OutputIndex},
            testing::TestBody,
            types::{ChainId, TransactionBlock, TransactionBlockHeader},
        },
        types::{Epoch, Height},
    };
    use commonware_cryptography::{Digestible as _, Sha256};
    use std::{num::NonZeroUsize, sync::Arc};
    type Block = Arc<TransactionBlock<Sha256, TestBody>>;

    fn block(height: u64) -> Block {
        let body = TestBody::new(Sha256::hash(&[b"parent"]), Height::new(height), height);
        let header = TransactionBlockHeader::new(
            Epoch::new(0),
            ChainId::new(0),
            Height::new(height),
            Sha256::hash(&[&height.to_be_bytes()]),
            body.digest(),
        )
        .unwrap();
        Arc::new(TransactionBlock::new(header, body).unwrap())
    }

    fn rows(blocks: &[Block]) -> Vec<OutputRow<<Sha256 as Hasher>::Digest>> {
        blocks
            .iter()
            .zip(0..)
            .map(|(block, index)| {
                OutputRow::new(OutputIndex::new(index), CustodyRef::for_test(block))
            })
            .collect()
    }

    /// Hands off the bodies of `indexes`, as committed by floor generation 1.
    fn handoff(blocks: &[Block], indexes: &[u64]) -> Vec<HotOutput<Sha256, TestBody>> {
        indexes
            .iter()
            .map(|&index| {
                let block = Arc::clone(&blocks[index as usize]);
                let row = OutputRow::new(OutputIndex::new(index), CustodyRef::for_test(&block));
                HotOutput {
                    stored: StoredRef::new(&row, 1),
                    block,
                }
            })
            .collect()
    }

    fn cache(blocks: &[&Block]) -> BlockCache<Sha256, TestBody> {
        let mut cache = BlockCache::new(NonZeroUsize::new(1 << 20).unwrap());
        for block in blocks {
            cache.insert(block.reference(), Arc::clone(block));
        }
        cache
    }

    /// Returns each delivered output's index and whether it carries a body.
    fn shape(plan: &HandoffPlan<Sha256, TestBody>) -> Vec<(u64, bool)> {
        plan.batch
            .as_ref()
            .unwrap()
            .outputs
            .iter()
            .map(|output| {
                (
                    output.stored().index.get(),
                    matches!(output, DeliveryOutput::Hot(_)),
                )
            })
            .collect()
    }

    fn body_cost(block: &Block) -> u64 {
        let encoded_len = CustodyRef::for_test(block).meta().encoded_len();
        delivery::body_bytes::<<Sha256 as Hasher>::Digest>(encoded_len)
            - delivery::descriptor_bytes::<<Sha256 as Hasher>::Digest>()
    }

    #[test]
    fn empty_commit_charges_nothing_and_rejects_handoff() {
        let empty = cache(&[]);
        let nothing = plan::<Sha256, TestBody>(
            &[],
            1,
            Vec::new(),
            [&empty, &empty],
            Budget {
                max_bytes: 100,
                pending: 7,
            },
        )
        .unwrap();
        assert!(nothing.batch.is_none());
        assert_eq!((nothing.bytes, nothing.pending_bytes), (0, 7));

        let blocks = [block(1)];
        assert_eq!(
            plan(
                &[],
                1,
                handoff(&blocks, &[0]),
                [&empty, &empty],
                Budget {
                    max_bytes: 100,
                    pending: 0,
                }
            )
            .err(),
            Some(Error::Invalid("delivery handoff has no output row"))
        );
    }

    #[test]
    fn handoff_must_follow_rows_exactly() {
        let blocks = [block(1), block(2)];
        let rows = rows(&blocks);
        let empty = cache(&[]);
        let budget = || Budget {
            max_bytes: u64::MAX,
            pending: 0,
        };
        assert_eq!(
            plan(
                &rows,
                1,
                handoff(&blocks, &[1, 0]),
                [&empty, &empty],
                budget()
            )
            .err(),
            Some(Error::Invalid(
                "delivery handoff contains an unknown output row"
            ))
        );
        let mut mismatched = handoff(&blocks, &[0]);
        mismatched[0].block = Arc::clone(&blocks[1]);
        assert_eq!(
            plan(&rows, 1, mismatched, [&empty, &empty], budget()).err(),
            Some(Error::Invalid(
                "delivery handoff does not match its output row"
            ))
        );
        let mut unknown = handoff(&blocks, &[1]);
        unknown[0].stored.index = OutputIndex::new(5);
        assert_eq!(
            plan(&rows, 1, unknown, [&empty, &empty], budget()).err(),
            Some(Error::Invalid(
                "delivery handoff contains an unknown output row"
            ))
        );
    }

    #[test]
    fn unbounded_budget_retains_every_available_body() {
        let blocks = [block(1), block(2), block(3)];
        let rows = rows(&blocks);
        let live = cache(&[&blocks[1]]);
        let materialized = cache(&[&blocks[2]]);
        let plan = plan(
            &rows,
            1,
            handoff(&blocks, &[0]),
            [&live, &materialized],
            Budget {
                max_bytes: u64::MAX / 2,
                pending: 5,
            },
        )
        .unwrap();
        assert_eq!(shape(&plan), [(0, true), (1, true), (2, true)]);
        assert_eq!(plan.pending_bytes, 5 + plan.bytes);
    }

    #[test]
    fn bodies_upgrade_by_source_priority_within_the_budget() {
        let blocks = [block(1), block(2), block(3)];
        let rows = rows(&blocks);
        let descriptor = delivery::descriptor_bytes::<<Sha256 as Hasher>::Digest>();
        let live = cache(&[&blocks[0]]);
        let materialized = cache(&[&blocks[1]]);
        // Room for three descriptors and one body upgrade: the handoff body wins.
        let max_bytes = 3 * descriptor + body_cost(&blocks[2]);
        let plan = plan(
            &rows,
            1,
            handoff(&blocks, &[2]),
            [&live, &materialized],
            Budget {
                max_bytes,
                pending: 0,
            },
        )
        .unwrap();
        assert_eq!(shape(&plan), [(0, false), (1, false), (2, true)]);
        assert_eq!(plan.bytes, max_bytes);
    }

    #[test]
    fn a_higher_priority_body_replaces_the_latest_lowest_priority_descriptor() {
        let blocks = [block(1), block(2), block(3)];
        let rows = rows(&blocks);
        let descriptor = delivery::descriptor_bytes::<<Sha256 as Hasher>::Digest>();
        let empty = cache(&[]);
        // Room for two descriptors plus one upgrade: output 2's handoff body displaces the last
        // retained descriptor without a body.
        let max_bytes = 2 * descriptor + body_cost(&blocks[2]);
        let plan = plan(
            &rows,
            1,
            handoff(&blocks, &[2]),
            [&empty, &empty],
            Budget {
                max_bytes,
                pending: 0,
            },
        )
        .unwrap();
        assert_eq!(shape(&plan), [(0, false), (2, true)]);
        assert_eq!(plan.bytes, max_bytes);
    }

    #[test]
    fn an_exhausted_budget_delivers_nothing() {
        let blocks = [block(1)];
        let rows = rows(&blocks);
        let empty = cache(&[]);
        let plan = plan(
            &rows,
            1,
            handoff(&blocks, &[0]),
            [&empty, &empty],
            Budget {
                max_bytes: 10,
                pending: 10,
            },
        )
        .unwrap();
        assert!(shape(&plan).is_empty());
        assert_eq!((plan.bytes, plan.pending_bytes), (0, 10));
    }
}
