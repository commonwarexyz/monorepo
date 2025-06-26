#![no_main]
use arbitrary::Arbitrary;
use commonware_storage::rmap::RMap;
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;

#[derive(Arbitrary, Debug, Clone)]
enum RMapOperation {
    Insert(u64),
    Remove { start: u64, end: u64 },
    Get(u64),
    NextGap(u64),
    Iter,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    operations: Vec<RMapOperation>,
}

fn fuzz(data: FuzzInput) {
    if data.operations.is_empty() || data.operations.len() > 106 {
        return;
    }
    let mut rmap = RMap::new();
    let mut reference_set = BTreeSet::new();

    for op in &data.operations {
        match op {
            RMapOperation::Insert(value) => {
                rmap.insert(*value);
                reference_set.insert(*value);

                // Verify that the value can be found
                let range = rmap.get(value);
                assert!(
                    range.is_some(),
                    "Value {} should be found after insertion",
                    value
                );
                let (start, end) = range.unwrap();
                assert!(
                    start <= *value && *value <= end,
                    "Value {} should be within range [{}, {}]",
                    value,
                    start,
                    end
                );
            }

            RMapOperation::Remove { start, end } => {
                // Ensure start <= end for valid range
                let (start, end) = if start <= end {
                    (*start, *end)
                } else {
                    (*end, *start)
                };

                rmap.remove(start, end);

                // Remove from reference set
                reference_set.retain(|&v| v < start || v > end);

                // Verify removal
                for value in start..=end.min(start.saturating_add(1000)) {
                    let range = rmap.get(&value);
                    if range.is_some() {
                        let (range_start, range_end) = range.unwrap();
                        // The value should not be in a range that was fully contained in [start, end]
                        assert!(
                            !(range_start >= start && range_end <= end),
                            "Value {} should not be in range [{}, {}] after removal of [{}, {}]",
                            value,
                            range_start,
                            range_end,
                            start,
                            end
                        );
                    }
                }
            }

            RMapOperation::Get(value) => {
                let range = rmap.get(value);
                let in_reference = reference_set.contains(value);

                if in_reference {
                    assert!(
                        range.is_some(),
                        "Value {} should be found in RMap since it's in reference set",
                        value
                    );
                    let (start, end) = range.unwrap();
                    assert!(
                        start <= *value && *value <= end,
                        "Value {} should be within range [{}, {}]",
                        value,
                        start,
                        end
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
                        "Value {} should exist as it's the start of the next range",
                        after_start
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
                        "Ranges should be disjoint: prev_end={}, curr_start={}",
                        prev_end,
                        curr_start
                    );
                }

                // Check that all values in reference set are covered by ranges
                for &value in &reference_set {
                    let found = ranges
                        .iter()
                        .any(|&(start, end)| start <= &value && &value <= end);
                    assert!(
                        found,
                        "Value {} from reference set not found in ranges",
                        value
                    );
                }
            }
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
