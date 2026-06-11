#![no_main]

use arbitrary::Arbitrary;
use commonware_storage::rmap::RMap;
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;

#[derive(Arbitrary, Debug, Clone)]
enum RMapOperation {
    Insert(u64),
    InsertEdge(u8),
    Remove { start: u64, end: u64 },
    Get(u64),
    NextGap(u64),
    Iter,
    FirstLastIndex,
    IterFrom(u64),
    IterFromEdge(u8),
    MissingItems { start: u64, max: u8 },
    MissingItemsEdge { start: u8, max: u8 },
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    operations: Vec<RMapOperation>,
}

fn edge(value: u8) -> u64 {
    match value {
        0 => 0,
        1 => 1,
        2 => u64::MAX,
        _ => u64::MAX - u64::from(value - 2),
    }
}

fn ranges(state: &BTreeSet<u64>) -> Vec<(u64, u64)> {
    let mut ranges = Vec::new();
    let mut iter = state.iter();
    let Some(&first) = iter.next() else {
        return ranges;
    };

    let mut start = first;
    let mut end = first;
    for &value in iter {
        if end != u64::MAX && value == end + 1 {
            end = value;
            continue;
        }
        ranges.push((start, end));
        start = value;
        end = value;
    }
    ranges.push((start, end));
    ranges
}

fn expected_missing_items(state: &BTreeSet<u64>, start: u64, max: usize) -> Vec<u64> {
    let ranges = ranges(state);
    let mut current = start;
    let mut missing = Vec::with_capacity(max);

    loop {
        if let Some((_, end)) = ranges
            .iter()
            .find(|(range_start, range_end)| *range_start <= current && current <= *range_end)
        {
            if *end == u64::MAX {
                break missing;
            }
            current = end + 1;
            continue;
        }

        let Some((next_start, _)) = ranges
            .iter()
            .find(|(range_start, _)| *range_start > current)
        else {
            break missing;
        };

        let items_needed = max - missing.len();
        let gap_end = (next_start - 1).min(current.saturating_add(items_needed as u64 - 1));
        for value in current..=gap_end {
            missing.push(value);
        }

        if missing.len() >= max {
            break missing;
        }
        current = *next_start;
    }
}

fn fuzz(data: FuzzInput) {
    let mut rmap = RMap::new();
    let mut expected_state = BTreeSet::new();

    for op in &data.operations {
        match op {
            RMapOperation::Insert(value) => {
                rmap.insert(*value);
                expected_state.insert(*value);
            }

            RMapOperation::InsertEdge(value) => {
                let value = edge(*value);
                rmap.insert(value);
                expected_state.insert(value);
            }

            RMapOperation::Remove { start, end } => {
                // Ensure start <= end for valid range
                let (start, end) = if start <= end {
                    (*start, *end)
                } else {
                    (*end, *start)
                };

                rmap.remove(start, end);

                expected_state.retain(|&v| v < start || v > end);

                // Verify removal
                for value in start..=end.min(start.saturating_add(1000)) {
                    if let Some((range_start, range_end)) = rmap.get(&value) {
                        // The value should not be in a range that was fully contained in [start, end]
                        assert!(
                            !(range_start >= start && range_end <= end),
                            "Value {value} should not be in range [{range_start}, {range_end}] after removal of [{start}, {end}]",
                        );
                    }
                }
            }

            RMapOperation::Get(value) => {
                let range = rmap.get(value);
                let in_reference = expected_state.contains(value);

                if in_reference {
                    assert!(
                        range.is_some(),
                        "Value {value} should be found in RMap since it's in reference set",
                    );
                    let (start, end) = range.unwrap();
                    assert!(
                        start <= *value && *value <= end,
                        "Value {value} should be within range [{start}, {end}]",
                    );
                } else {
                    assert!(
                        range.is_none(),
                        "Value {value} should not be in reference set"
                    );
                }
            }

            RMapOperation::NextGap(value) => {
                let gap = rmap.next_gap(*value);

                // next_gap returns (Option<u64>, Option<u64>)
                let (before_end, after_start) = gap;

                // If we have a before_end, verify the gap after it
                if let Some(before_end) = before_end {
                    // before_end + 1 should not be in the map
                    if before_end < u64::MAX {
                        let should_be_gap = rmap.get(&(before_end + 1));
                        assert!(
                            should_be_gap.is_none(),
                            "Found value at {} which should be a gap",
                            before_end + 1
                        );
                    }
                }

                // If we have an after_start, verify the gap before it
                if let Some(after_start) = after_start {
                    // after_start - 1 should not be in the map
                    if after_start > 0 {
                        let should_be_gap = rmap.get(&(after_start - 1));
                        assert!(
                            should_be_gap.is_none(),
                            "Found value at {} which should be a gap",
                            after_start - 1
                        );
                    }

                    // after_start should be in the map
                    let should_exist = rmap.get(&after_start);
                    assert!(
                        should_exist.is_some(),
                        "Value {after_start} should exist as it's the start of the next range",
                    );
                }
            }

            RMapOperation::Iter => {
                let ranges: Vec<_> = rmap.iter().collect();

                // Check that ranges are disjoint and ordered
                for i in 1..ranges.len() {
                    let (_, prev_end) = ranges[i - 1];
                    let (curr_start, _) = ranges[i];
                    assert!(
                        prev_end < curr_start,
                        "Ranges should be disjoint: prev_end={prev_end}, curr_start={curr_start}",
                    );
                }

                // Check that all values in reference set covered by ranges
                for &value in &expected_state {
                    let found = ranges
                        .iter()
                        .any(|&(start, end)| start <= &value && &value <= end);
                    assert!(
                        found,
                        "Value {value} from reference set not found in ranges",
                    );
                }
            }

            RMapOperation::FirstLastIndex => {
                assert_eq!(rmap.first_index(), expected_state.first().copied());
                assert_eq!(rmap.last_index(), expected_state.last().copied());
            }

            RMapOperation::IterFrom(value) => {
                let actual: Vec<_> = rmap
                    .iter_from(*value)
                    .map(|(&start, &end)| (start, end))
                    .collect();
                let expected: Vec<_> = ranges(&expected_state)
                    .into_iter()
                    .filter(|(_, end)| end >= value)
                    .collect();
                assert_eq!(actual, expected);
            }

            RMapOperation::IterFromEdge(value) => {
                let value = edge(*value);
                let actual: Vec<_> = rmap
                    .iter_from(value)
                    .map(|(&start, &end)| (start, end))
                    .collect();
                let expected: Vec<_> = ranges(&expected_state)
                    .into_iter()
                    .filter(|(_, end)| *end >= value)
                    .collect();
                assert_eq!(actual, expected);
            }

            RMapOperation::MissingItems { start, max } => {
                let max = usize::from(*max % 64) + 1;
                assert_eq!(
                    rmap.missing_items(*start, max),
                    expected_missing_items(&expected_state, *start, max)
                );
            }

            RMapOperation::MissingItemsEdge { start, max } => {
                let start = edge(*start);
                let max = usize::from(*max % 64) + 1;
                assert_eq!(
                    rmap.missing_items(start, max),
                    expected_missing_items(&expected_state, start, max)
                );
            }
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
