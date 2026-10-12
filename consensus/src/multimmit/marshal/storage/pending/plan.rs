//! Pure planning of bounded body-read groups.

use super::read::BodyLocator;
use crate::multimmit::marshal::storage::Error;
use commonware_cryptography::Digest;
use std::{
    collections::BTreeMap,
    num::{NonZeroU64, NonZeroUsize},
};

/// Located entries of one planned group, with their total encoded bytes.
pub(super) struct PlannedGroup<D: Digest> {
    /// Segment every entry lies in.
    pub(super) segment: u64,
    /// Entries in ascending storage position, keeping their requested output indexes.
    pub(super) entries: Vec<(usize, BodyLocator<D>)>,
}

/// Splits located reads into single-segment groups.
///
/// Each group holds positions from one segment in ascending order, and a block is never split.
/// Groups first fill an equal share of `max_bytes` (`max_bytes / max_groups`) per segment, except
/// that one individually larger block forms a group alone so reads can make progress. Groups are
/// then split further, largest average group first, until there are `max_groups` jobs or every
/// group holds one entry.
pub(super) fn plan_groups<D: Digest>(
    by_segment: BTreeMap<u64, Vec<(usize, BodyLocator<D>)>>,
    max_bytes: NonZeroU64,
    max_groups: NonZeroUsize,
) -> Result<Vec<PlannedGroup<D>>, Error> {
    let total_entries = by_segment.values().map(Vec::len).sum::<usize>();
    let max_groups = max_groups.get();
    let group_bytes = (max_bytes.get() / max_groups as u64).max(1);

    let mut byte_groups = Vec::new();
    for (segment, mut entries) in by_segment {
        entries.sort_unstable_by_key(|(_, locator)| locator.position);
        let mut chunk = Vec::new();
        let mut chunk_bytes = 0u64;
        for entry @ (_, locator) in entries {
            let next_bytes = chunk_bytes.checked_add(locator.encoded_len);
            if !chunk.is_empty() && next_bytes.is_none_or(|bytes| bytes > group_bytes) {
                byte_groups.push((segment, chunk_bytes, std::mem::take(&mut chunk)));
                chunk_bytes = 0;
            }
            chunk_bytes = chunk_bytes
                .checked_add(locator.encoded_len)
                .ok_or(Error::Inconsistent("pending body read bytes overflow"))?;
            chunk.push(entry);
        }
        if !chunk.is_empty() {
            byte_groups.push((segment, chunk_bytes, chunk));
        }
    }

    let target_groups = max_groups.min(total_entries).max(byte_groups.len());
    let mut allocations = vec![1usize; byte_groups.len()];
    for _ in byte_groups.len()..target_groups {
        let index = (0..byte_groups.len())
            .filter(|&index| allocations[index] < byte_groups[index].2.len())
            .max_by_key(|&index| byte_groups[index].1.div_ceil(allocations[index] as u64))
            .expect("a body read group can be split toward its job target");
        allocations[index] += 1;
    }

    let mut groups = Vec::with_capacity(target_groups);
    for ((segment, mut remaining_bytes, entries), mut remaining_groups) in
        byte_groups.into_iter().zip(allocations)
    {
        let mut entries = entries.into_iter().peekable();
        let mut remaining_entries = entries.len();
        while remaining_groups > 0 {
            let target_bytes = remaining_bytes.div_ceil(remaining_groups as u64);
            let mut chunk = Vec::new();
            let mut chunk_bytes = 0u64;
            while remaining_entries > remaining_groups - 1 {
                let locator = &entries.peek().expect("a planned body entry exists").1;
                let next_bytes = chunk_bytes.checked_add(locator.encoded_len);
                if !chunk.is_empty() && next_bytes.is_none_or(|bytes| bytes > target_bytes) {
                    break;
                }
                chunk_bytes =
                    next_bytes.expect("a byte-safe body group cannot overflow its encoded length");
                remaining_bytes = remaining_bytes
                    .checked_sub(locator.encoded_len)
                    .expect("a byte group covers its planned entries");
                remaining_entries -= 1;
                chunk.push(entries.next().expect("a peeked body read entry exists"));
            }
            groups.push(PlannedGroup {
                segment,
                entries: chunk,
            });
            remaining_groups -= 1;
        }
    }
    Ok(groups)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::types::{BlockRef, ChainId},
        types::Height,
    };
    use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest as Sha256Digest};
    use commonware_utils::{NZU64, NZUsize};

    /// Locators at consecutive positions starting at `first`, with the given encoded lengths.
    fn locators(first: u64, lengths: &[u64]) -> Vec<BodyLocator<Sha256Digest>> {
        lengths
            .iter()
            .zip(first..)
            .map(|(&encoded_len, position)| BodyLocator {
                position,
                reference: BlockRef::new(
                    ChainId::new(0),
                    Height::new(position + 1),
                    Sha256::hash(&[&position.to_be_bytes()]),
                ),
                encoded_len,
                offset: position * 100,
                size: 10,
            })
            .collect()
    }

    /// Groups the requested locators by `segment_capacity` in request order.
    fn by_segment(
        requests: impl IntoIterator<Item = BodyLocator<Sha256Digest>>,
        segment_capacity: u64,
    ) -> BTreeMap<u64, Vec<(usize, BodyLocator<Sha256Digest>)>> {
        let mut by_segment = BTreeMap::<u64, Vec<_>>::new();
        for (output, locator) in requests.into_iter().enumerate() {
            by_segment
                .entry(locator.position / segment_capacity)
                .or_default()
                .push((output, locator));
        }
        by_segment
    }

    fn positions(groups: &[PlannedGroup<Sha256Digest>]) -> Vec<(u64, Vec<u64>)> {
        groups
            .iter()
            .map(|group| {
                (
                    group.segment,
                    group
                        .entries
                        .iter()
                        .map(|(_, locator)| locator.position)
                        .collect(),
                )
            })
            .collect()
    }

    fn bytes(group: &PlannedGroup<Sha256Digest>) -> u64 {
        group
            .entries
            .iter()
            .map(|(_, locator)| locator.encoded_len)
            .sum()
    }

    #[test]
    fn groups_preserve_a_contiguous_segment_run() {
        let located = locators(0, &[10; 6]);
        let requests = [0, 3, 1, 4, 2, 5].map(|index| located[index]);
        let groups = plan_groups(by_segment(requests, 8), NZU64!(u64::MAX), NZUsize!(1)).unwrap();
        assert_eq!(positions(&groups), vec![(0, vec![0, 1, 2, 3, 4, 5])]);
    }

    #[test]
    fn groups_split_at_byte_and_segment_boundaries() {
        let located = locators(0, &[10; 7]);
        let requests = [6, 2, 4, 1, 5, 0, 3].map(|index| located[index]);
        let groups = plan_groups(by_segment(requests, 3), NZU64!(20), NZUsize!(1)).unwrap();
        assert_eq!(
            positions(&groups),
            vec![
                (0, vec![0, 1]),
                (0, vec![2]),
                (1, vec![3, 4]),
                (1, vec![5]),
                (2, vec![6]),
            ]
        );
        assert_eq!(
            groups.iter().map(bytes).collect::<Vec<_>>(),
            [20, 10, 20, 10, 10]
        );
    }

    #[test]
    fn groups_do_not_exceed_the_job_target() {
        const MAX_GROUPS: usize = 16;
        let groups = plan_groups(
            by_segment(locators(0, &[10; 31]), 64),
            NZU64!(10 * 2 * MAX_GROUPS as u64),
            NZUsize!(MAX_GROUPS),
        )
        .unwrap();
        assert_eq!(groups.len(), MAX_GROUPS);
        assert!(groups.iter().all(|group| bytes(group) <= 20));
        assert_eq!(
            groups
                .iter()
                .map(|group| group.entries.len())
                .collect::<Vec<_>>(),
            [vec![2; MAX_GROUPS - 1], vec![1]].concat()
        );
    }

    #[test]
    fn groups_fill_byte_capacity_before_exceeding_the_job_target() {
        const MAX_GROUPS: usize = 16;
        let lengths = (0..48)
            .map(|index| if index < 46 { 1 } else { 5 })
            .collect::<Vec<_>>();
        let groups = plan_groups(
            by_segment(locators(0, &lengths), 64),
            NZU64!(160),
            NZUsize!(MAX_GROUPS),
        )
        .unwrap();
        assert_eq!(groups.len(), MAX_GROUPS);
        assert!(groups.iter().all(|group| bytes(group) <= 10));
        assert_eq!(
            groups
                .iter()
                .map(|group| group.entries.len())
                .sum::<usize>(),
            lengths.len()
        );
    }

    #[test]
    fn one_oversized_body_forms_its_own_group() {
        let groups =
            plan_groups(by_segment(locators(0, &[10]), 2), NZU64!(9), NZUsize!(1)).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(bytes(&groups[0]), 10);
        assert_eq!(groups[0].entries.len(), 1);
    }

    #[test]
    fn empty_requests_plan_no_groups() {
        assert!(
            plan_groups::<Sha256Digest>(BTreeMap::new(), NZU64!(10), NZUsize!(4))
                .unwrap()
                .is_empty()
        );
    }
}
