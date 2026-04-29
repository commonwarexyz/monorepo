#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{EncodeSize, Write};
use commonware_utils::{
    ordered::{BiMap, Map, Set},
    sync::Once,
};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;

static BASELINE: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    bytes: Vec<u8>,
}

fn pairs(seed: u32) -> [(u32, u64); 3] {
    [
        (seed, u64::from(seed).wrapping_add(10)),
        (seed.wrapping_add(1), u64::from(seed).wrapping_add(20)),
        (seed.wrapping_add(2), u64::from(seed).wrapping_add(30)),
    ]
}

fn assert_strictly_sorted(items: &[u32]) {
    for window in items.windows(2) {
        assert!(window[0] < window[1]);
    }
}

fn exercise_set(seed: u32) {
    let items = [seed, seed.wrapping_add(1), seed.wrapping_add(2)];
    let set = Set::<u32>::try_from(items.to_vec()).unwrap();
    let _ = Set::<u32>::try_from(items).unwrap();
    let _ = Set::<u32>::try_from(&items).unwrap();
    assert!(Set::<u32>::try_from(vec![seed, seed]).is_err());

    assert!(format!("{set:?}").starts_with("Set"));
    assert!(format!("{set}").starts_with("["));
    assert_eq!(&set[0..set.len()], set.as_ref());
}

fn exercise_map(seed: u32) {
    let items = pairs(seed);
    let _ = Map::<u32, u64>::try_from(items.to_vec()).unwrap();
    let _ = Map::<u32, u64>::try_from(&items[..]).unwrap();
    let _ = Map::<u32, u64>::try_from(items).unwrap();
    let _ = Map::<u32, u64>::try_from(&items).unwrap();
    assert!(Map::<u32, u64>::try_from(vec![(seed, 1), (seed, 2)]).is_err());

    let mut map = Map::<u32, u64>::try_from(pairs(seed)).unwrap();
    let first_key = *map.get(0).unwrap();
    let first_value = *map.value(0).unwrap();
    assert_eq!(map.get_value(&first_key), Some(&first_value));
    *map.get_value_mut(&first_key).unwrap() = first_value.wrapping_add(1);
    assert_eq!(
        map.get_value(&first_key),
        Some(&first_value.wrapping_add(1))
    );

    assert_eq!(map.values().len(), map.len());
    let values = map.values_mut();
    values[0] = values[0].wrapping_add(1);
    assert_eq!(map.value(0), Some(&first_value.wrapping_add(2)));

    for (key, value) in map.iter_pairs_mut() {
        *value = value.wrapping_add(u64::from(*key));
    }
    assert_eq!(map.iter().count(), map.len());
    assert!(format!("{map:?}").starts_with("Map"));
    assert!(format!("{map}").starts_with("["));

    let keys: &[u32] = map.as_ref();
    assert_eq!(keys.len(), map.len());
    let keys: &Set<u32> = map.as_ref();
    assert_eq!(keys.len(), map.len());

    let vec: Vec<(u32, u64)> = map.clone().into();
    assert_eq!(vec.len(), map.len());

    map.truncate(2);
    assert_eq!(map.len(), 2);
    assert_eq!(map.values().len(), 2);

    let mut iter = map.into_iter();
    assert!(iter.next_back().is_some());
}

fn exercise_bimap(seed: u32) {
    let empty = BiMap::<u32, u64>::default();
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);

    let items = pairs(seed);
    let _ = BiMap::<u32, u64>::try_from(items.to_vec()).unwrap();
    let _ = BiMap::<u32, u64>::try_from(&items[..]).unwrap();
    let _ = BiMap::<u32, u64>::try_from(items).unwrap();
    let _ = BiMap::<u32, u64>::try_from(&items).unwrap();
    assert!(BiMap::<u32, u64>::try_from(vec![(seed, 1), (seed.wrapping_add(1), 1),]).is_err());

    let bimap = BiMap::<u32, u64>::try_from(pairs(seed)).unwrap();
    assert!(!bimap.is_empty());
    assert_eq!(bimap.iter().count(), bimap.len());
    assert_eq!(bimap.iter_pairs().count(), bimap.len());
    let first = *bimap.get(0).unwrap();
    assert_eq!(bimap.position(&first), Some(0));
    let first_value = *bimap.value(0).unwrap();
    assert_eq!(bimap.get_value(&first), Some(&first_value));
    assert_eq!(bimap.get_key(&first_value), Some(&first));
    assert_eq!(bimap.values().len(), bimap.len());
    assert_eq!(bimap.keys().len(), bimap.len());
    assert_eq!(bimap.clone().into_keys().len(), bimap.len());
    assert!(format!("{bimap:?}").starts_with("BiMap"));
    assert!(format!("{bimap}").starts_with("["));

    let keys: &[u32] = bimap.as_ref();
    assert_eq!(keys.len(), bimap.len());
    let keys: &Set<u32> = bimap.as_ref();
    assert_eq!(keys.len(), bimap.len());

    let vec: Vec<(u32, u64)> = bimap.clone().into();
    assert_eq!(vec.len(), bimap.len());

    let mut buf = Vec::with_capacity(bimap.encode_size());
    bimap.write(&mut buf);
    assert_eq!(buf.len(), bimap.encode_size());

    assert_eq!((&bimap).into_iter().count(), bimap.len());
}

fn exercise_arbitrary(bytes: &[u8]) {
    let mut unstructured = arbitrary::Unstructured::new(bytes);
    if let Ok(set) = Set::<u32>::arbitrary(&mut unstructured) {
        let items: &[u32] = set.as_ref();
        assert_strictly_sorted(items);
    }

    let mut unstructured = arbitrary::Unstructured::new(bytes);
    if let Ok(map) = Map::<u32, u64>::arbitrary(&mut unstructured) {
        let keys: &[u32] = map.as_ref();
        assert_strictly_sorted(keys);
        assert_eq!(map.values().len(), map.len());
    }

    let mut unstructured = arbitrary::Unstructured::new(bytes);
    if let Ok(bimap) = BiMap::<u32, u64>::arbitrary(&mut unstructured) {
        let keys: &[u32] = bimap.as_ref();
        assert_strictly_sorted(keys);
        let values: BTreeSet<u64> = bimap.values().iter().copied().collect();
        assert_eq!(values.len(), bimap.len());
    }
}

fn fuzz(input: FuzzInput) {
    BASELINE.call_once(|| {
        exercise_set(0);
        exercise_map(0);
        exercise_bimap(0);
    });

    exercise_arbitrary(&input.bytes);
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
