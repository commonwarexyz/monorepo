#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{EncodeSize, Write};
use commonware_utils::ordered::{BiMap, Map, Set};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;

#[derive(Debug)]
enum FuzzInput {
    Set {
        items: Vec<u32>,
        array: [u32; 3],
        range_start: usize,
        range_len: usize,
    },
    Map {
        pairs: Vec<(u32, u64)>,
        array: [(u32, u64); 3],
        index: usize,
        search_key: u32,
        write_value: u64,
        truncate_to: usize,
    },
    BiMap {
        pairs: Vec<(u32, u64)>,
        array: [(u32, u64); 3],
        index: usize,
        search_key: u32,
        search_value: u64,
    },
    Arbitrary {
        bytes: Vec<u8>,
    },
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=3)? {
            0 => Ok(Self::Set {
                items: arbitrary_vec_low_empty(u)?,
                array: u.arbitrary()?,
                range_start: u.arbitrary()?,
                range_len: u.arbitrary()?,
            }),
            1 => Ok(Self::Map {
                pairs: arbitrary_vec_low_empty(u)?,
                array: u.arbitrary()?,
                index: u.arbitrary()?,
                search_key: u.arbitrary()?,
                write_value: u.arbitrary()?,
                truncate_to: u.arbitrary()?,
            }),
            2 => Ok(Self::BiMap {
                pairs: arbitrary_vec_low_empty(u)?,
                array: u.arbitrary()?,
                index: u.arbitrary()?,
                search_key: u.arbitrary()?,
                search_value: u.arbitrary()?,
            }),
            _ => Ok(Self::Arbitrary {
                bytes: arbitrary_vec_low_empty(u)?,
            }),
        }
    }
}

fn arbitrary_vec_low_empty<'a, T: Arbitrary<'a>>(
    u: &mut arbitrary::Unstructured<'a>,
) -> arbitrary::Result<Vec<T>> {
    if u.ratio(1, 16)? {
        return Ok(Vec::new());
    }

    let first = T::arbitrary(u)?;
    let mut rest = Vec::<T>::arbitrary(u)?;
    let mut items = Vec::with_capacity(1 + rest.len());
    items.push(first);
    items.append(&mut rest);
    Ok(items)
}

fn assert_strictly_sorted(items: &[u32]) {
    for window in items.windows(2) {
        assert!(window[0] < window[1]);
    }
}

fn unique_bimap_pairs(pairs: Vec<(u32, u64)>) -> Vec<(u32, u64)> {
    let mut keys = BTreeSet::new();
    let mut values = BTreeSet::new();
    let mut unique = Vec::new();
    for (key, value) in pairs {
        if keys.insert(key) && values.insert(value) {
            unique.push((key, value));
        }
    }
    unique
}

fn exercise_set(items: Vec<u32>, array: [u32; 3], range_start: usize, range_len: usize) {
    let set = Set::from_iter_dedup(items.clone());
    let _ = Set::<u32>::try_from(items.clone());
    let _ = Set::<u32>::try_from(items.as_slice());
    let _ = Set::<u32>::try_from(array);
    let _ = Set::<u32>::try_from(&array);

    if let Some(first) = items.first() {
        assert!(Set::<u32>::try_from(vec![*first, *first]).is_err());
    }

    assert_strictly_sorted(set.as_ref());
    assert!(format!("{set:?}").starts_with("Set"));
    assert!(format!("{set}").starts_with("["));

    if !set.is_empty() {
        let start = range_start % set.len();
        let end = (start + range_len % (set.len() - start + 1)).min(set.len());
        assert_eq!(&set[start..end], &set.as_ref()[start..end]);
    }
}

fn exercise_map(
    pairs: Vec<(u32, u64)>,
    array: [(u32, u64); 3],
    index: usize,
    search_key: u32,
    write_value: u64,
    truncate_to: usize,
) {
    let _ = Map::<u32, u64>::try_from(pairs.clone());
    let _ = Map::<u32, u64>::try_from(pairs.as_slice());
    let _ = Map::<u32, u64>::try_from(array);
    let _ = Map::<u32, u64>::try_from(&array);

    if let Some((key, value)) = pairs.first() {
        assert!(
            Map::<u32, u64>::try_from(vec![(*key, *value), (*key, value.wrapping_add(1))]).is_err()
        );
    }

    let mut map = Map::from_iter_dedup(pairs);
    assert_strictly_sorted(map.as_ref());
    assert_eq!(map.values().len(), map.len());
    assert_eq!(map.iter().count(), map.len());
    assert_eq!(map.iter_pairs().count(), map.len());
    assert!(format!("{map:?}").starts_with("Map"));
    assert!(format!("{map}").starts_with("["));

    let keys: &[u32] = map.as_ref();
    assert_eq!(keys.len(), map.len());
    let keys: &Set<u32> = map.as_ref();
    assert_eq!(keys.len(), map.len());

    if !map.is_empty() {
        let idx = index % map.len();
        let key = *map.get(idx).unwrap();
        let old_value = *map.value(idx).unwrap();
        assert_eq!(map.get_value(&key), Some(&old_value));
        *map.get_value_mut(&key).unwrap() = write_value;
        assert_eq!(map.get_value(&key), Some(&write_value));
        map.values_mut()[idx] = old_value;
        assert_eq!(map.value(idx), Some(&old_value));
    }

    for (key, value) in map.iter_pairs_mut() {
        *value = value.wrapping_add(u64::from(*key));
    }
    let _ = map.get_value(&search_key);

    let vec: Vec<(u32, u64)> = map.clone().into();
    assert_eq!(vec.len(), map.len());

    let target = if map.is_empty() {
        0
    } else {
        truncate_to % (map.len() + 1)
    };
    map.truncate(target);
    assert_eq!(map.len(), target);
    assert_eq!(map.values().len(), target);

    let mut iter = map.into_iter();
    let _ = iter.next_back();
}

fn exercise_bimap(
    pairs: Vec<(u32, u64)>,
    array: [(u32, u64); 3],
    index: usize,
    search_key: u32,
    search_value: u64,
) {
    let empty = BiMap::<u32, u64>::default();
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);

    let _ = BiMap::<u32, u64>::try_from(pairs.clone());
    let _ = BiMap::<u32, u64>::try_from(pairs.as_slice());
    let _ = BiMap::<u32, u64>::try_from(array);
    let _ = BiMap::<u32, u64>::try_from(&array);

    if let Some((key, value)) = pairs.first() {
        assert!(
            BiMap::<u32, u64>::try_from(vec![(*key, *value), (key.wrapping_add(1), *value),])
                .is_err()
        );
    }

    let bimap = BiMap::<u32, u64>::try_from(unique_bimap_pairs(pairs)).unwrap();
    assert_strictly_sorted(bimap.as_ref());
    assert_eq!(bimap.iter().count(), bimap.len());
    assert_eq!(bimap.iter_pairs().count(), bimap.len());
    assert_eq!(bimap.values().len(), bimap.len());
    assert_eq!(bimap.keys().len(), bimap.len());
    assert_eq!(bimap.clone().into_keys().len(), bimap.len());
    assert!(format!("{bimap:?}").starts_with("BiMap"));
    assert!(format!("{bimap}").starts_with("["));

    let keys: &[u32] = bimap.as_ref();
    assert_eq!(keys.len(), bimap.len());
    let keys: &Set<u32> = bimap.as_ref();
    assert_eq!(keys.len(), bimap.len());

    if !bimap.is_empty() {
        let idx = index % bimap.len();
        let key = *bimap.get(idx).unwrap();
        let value = *bimap.value(idx).unwrap();
        assert_eq!(bimap.position(&key), Some(idx));
        assert_eq!(bimap.get_value(&key), Some(&value));
        assert_eq!(bimap.get_key(&value), Some(&key));
    }

    let _ = bimap.position(&search_key);
    let _ = bimap.get_value(&search_key);
    let _ = bimap.get_key(&search_value);

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
        assert_strictly_sorted(set.as_ref());
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
    match input {
        FuzzInput::Set {
            items,
            array,
            range_start,
            range_len,
        } => exercise_set(items, array, range_start, range_len),
        FuzzInput::Map {
            pairs,
            array,
            index,
            search_key,
            write_value,
            truncate_to,
        } => exercise_map(pairs, array, index, search_key, write_value, truncate_to),
        FuzzInput::BiMap {
            pairs,
            array,
            index,
            search_key,
            search_value,
        } => exercise_bimap(pairs, array, index, search_key, search_value),
        FuzzInput::Arbitrary { bytes } => exercise_arbitrary(&bytes),
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
