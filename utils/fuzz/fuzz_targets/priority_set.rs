#![no_main]

use arbitrary::Arbitrary;
use commonware_utils::PrioritySet;
use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;

#[derive(Arbitrary, Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Item(u32);

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Priority(u32);

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    Put {
        item: Item,
        priority: Priority,
    },
    Get {
        item: Item,
    },
    Remove {
        item: Item,
    },
    Reconcile {
        keep: Vec<Item>,
        default: Priority,
    },
    Retain {
        item: Item,
    },
    Contains {
        item: Item,
    },
    Peek,
    Pop,
    Len,
    IsEmpty,
    Clear,
    Cmp,
    PartialCmp,
    PutSamePriority {
        items: Vec<Item>,
        priority: Priority,
    },
}

fn fuzz(input: Vec<FuzzInput>) {
    let mut set: PrioritySet<Item, Priority> = PrioritySet::new();
    let mut expected_items: HashSet<Item> = HashSet::new();

    for op in input {
        match op {
            FuzzInput::Put { item, priority } => {
                set.put(item.clone(), priority);
                expected_items.insert(item.clone());

                assert_eq!(set.get(&item), Some(priority));
                assert!(set.contains(&item));
            }

            FuzzInput::Get { item } => {
                let result = set.get(&item);
                if expected_items.contains(&item) {
                    assert!(result.is_some());
                } else {
                    assert!(result.is_none());
                }
            }

            FuzzInput::Retain { item } => {
                set.retain(|key| key.le(&item));
                expected_items.retain(|key| key.le(&item));
            }

            FuzzInput::Remove { item } => {
                let removed = set.remove(&item);
                if expected_items.remove(&item) {
                    assert!(removed);
                    assert!(!set.contains(&item));
                    assert!(set.get(&item).is_none());
                } else {
                    assert!(!removed);
                }
            }

            FuzzInput::Reconcile { keep, default } => {
                let keep = if keep.len() > 4 {
                    &keep[..4]
                } else {
                    &keep[..]
                };

                set.reconcile(keep, default);

                expected_items.clear();
                for item in keep {
                    expected_items.insert(item.clone());
                }

                assert_eq!(set.len(), expected_items.len());
                for item in expected_items.iter() {
                    assert!(set.contains(item));
                }

                let collected: HashSet<_> = set.iter().map(|(k, _)| k.clone()).collect();
                assert_eq!(collected.len(), expected_items.len());
            }

            FuzzInput::Contains { item } => {
                let result = set.contains(&item);
                assert_eq!(result, expected_items.contains(&item));
            }

            FuzzInput::Peek => {
                let peeked = set.peek();
                if expected_items.is_empty() {
                    assert!(peeked.is_none());
                } else {
                    assert!(peeked.is_some());
                    let (item, _) = peeked.unwrap();
                    assert!(expected_items.contains(item));

                    assert!(set.contains(item));
                }
            }

            FuzzInput::Pop => {
                let popped = set.pop();
                if expected_items.is_empty() {
                    assert!(popped.is_none());
                } else {
                    assert!(popped.is_some());
                    let (item, _) = popped.unwrap();
                    assert!(expected_items.remove(&item));

                    assert!(!set.contains(&item));
                }
            }

            FuzzInput::Len => {
                assert_eq!(set.len(), expected_items.len());
            }

            FuzzInput::IsEmpty => {
                assert_eq!(set.is_empty(), expected_items.is_empty());
            }

            FuzzInput::Clear => {
                set.clear();
                expected_items.clear();
                while set.pop().is_some() {}
                assert!(set.is_empty());
                assert_eq!(set.len(), 0);
            }

            FuzzInput::Cmp => {
                set.iter().cmp(PrioritySet::new().iter());
            }

            FuzzInput::PartialCmp => {
                set.iter().partial_cmp(PrioritySet::new().iter());
            }

            FuzzInput::PutSamePriority { items, priority } => {
                // Insert multiple items with same priority to trigger Entry::partial_cmp
                for item in items.into_iter().take(3) {
                    set.put(item.clone(), priority);
                    expected_items.insert(item);
                }
            }
        }

        assert_eq!(set.is_empty(), set.is_empty());
        assert_eq!(set.is_empty(), set.peek().is_none());

        let iter_count = set.iter().count();
        assert_eq!(iter_count, set.len());

        for (item, _) in set.iter() {
            assert!(expected_items.contains(item));
        }
    }

    let mut ordered_set: PrioritySet<u32, u32> = PrioritySet::new();
    ordered_set.put(1, 10);
    ordered_set.put(2, 5);
    ordered_set.put(3, 15);
    ordered_set.put(4, 5);

    assert_eq!(ordered_set.pop(), Some((2, 5)));
    let next = ordered_set.pop();
    assert!(next == Some((4, 5)) || next == Some((1, 10)));

    let mut update_set: PrioritySet<u32, u32> = PrioritySet::new();
    update_set.put(1, 10);
    assert_eq!(update_set.get(&1), Some(10));
    update_set.put(1, 5);
    assert_eq!(update_set.get(&1), Some(5));
    assert_eq!(update_set.len(), 1);
}

fuzz_target!(|input: Vec<FuzzInput>| {
    fuzz(input);
});
