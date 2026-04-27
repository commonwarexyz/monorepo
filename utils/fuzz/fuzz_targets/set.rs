#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{Encode, RangeCfg, Read};
use commonware_utils::{
    ordered::{BiMap, Error as OrderedError, Map, Quorum, Set},
    N3f1, TryFromIterator,
};
use libfuzzer_sys::fuzz_target;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    FromVec {
        data: Vec<u32>,
    },
    FromSlice {
        data: Vec<u32>,
    },
    FromArray {
        data: [u32; 8],
    },
    Operations {
        data: Vec<u32>,
        index: usize,
        search: u32,
    },
    AssociatedInsert {
        keys: Vec<u32>,
        values: Vec<u64>,
    },
    AssociatedOperations {
        keys: Vec<u32>,
        values: Vec<u64>,
        search_key: u32,
        index: usize,
    },
    /// Codec-rejection oracle: the wire form of `Set<u32>` is identical to
    /// `Vec<u32>`. Encoding an arbitrary vec lets us probe whether the
    /// decoder enforces "items must be sorted and unique"
    /// (utils/src/ordered.rs:117).
    SetCodec {
        items: Vec<u32>,
    },
    /// Quorum trait + BFT safety: 2*q > n + f and q + f == n.
    QuorumOnSet {
        data: Vec<u32>,
    },
    /// `BiMap` enforces unique keys AND unique values. Exercise the
    /// `get_key(get_value(k)) == k` round-trip and the duplicate-rejection
    /// branches.
    BiMapOps {
        keys: Vec<u32>,
        values: Vec<u64>,
    },
    /// Codec-rejection for BiMap: same wire as Map, but BiMap rejects
    /// duplicate values during deserialization
    /// (utils/src/ordered.rs:836).
    BiMapCodec {
        keys: Vec<u32>,
        values: Vec<u64>,
    },
    /// `Map::truncate`, `Map::get_value_mut`, and `try_from_iter` duplicate
    /// rejection.
    MapMutate {
        keys: Vec<u32>,
        values: Vec<u64>,
        write_key: u32,
        write_value: u64,
        truncate_to: usize,
    },
}

fn fuzz(input: FuzzInput) {
    match input {
        FuzzInput::FromVec { data } => {
            // Build the model first (consumes data via reference) before the
            // existing pipeline takes ownership.
            let model: BTreeSet<u32> = data.iter().copied().collect();
            let model_sorted: Vec<u32> = model.iter().copied().collect();

            let set = Set::from_iter_dedup(data);
            let _ = set.len();
            let _ = set.is_empty();
            let _ = set.iter().count();
            // Invariant: from_iter_dedup yields a strictly increasing sequence
            // and matches the BTreeSet model.
            assert_eq!(set.len(), model.len());
            assert!(set.iter().is_sorted());
            let collected: Vec<u32> = set.iter().copied().collect();
            assert_eq!(collected, model_sorted);
            let _: Vec<u32> = set.into();
        }

        FuzzInput::FromSlice { data } => {
            let set = Set::from_iter_dedup(data.iter().cloned());
            let _ = set.len();
            let _ = set.is_empty();
        }

        FuzzInput::FromArray { data } => {
            let set = Set::from_iter_dedup(data);
            let _ = set.len();
        }

        FuzzInput::Operations {
            data,
            index,
            search,
        } => {
            // Build the model up front so the existing pipeline below can keep
            // owning `data`.
            let model: BTreeSet<u32> = data.iter().copied().collect();

            let set = Set::from_iter_dedup(data);
            let _ = set.get(index);
            let _ = set.position(&search);
            let _ = set.iter().count();
            // Invariants: get(i) is Some iff i < len; position(x) returns the
            // index whose item equals x; the two are inverse on hits.
            assert_eq!(set.get(index).is_some(), index < set.len());
            let pos = set.position(&search);
            assert_eq!(pos.is_some(), model.contains(&search));
            if let Some(p) = pos {
                assert_eq!(set.get(p), Some(&search));
            }
            // try_from_iter: rejects iff the input had duplicates.
            let raw: Vec<u32> = model.iter().copied().collect();
            let try_unique = <Set<u32> as TryFromIterator<u32>>::try_from_iter(raw.iter().copied());
            assert!(try_unique.is_ok());
            // Build a guaranteed-duplicate input by repeating the first element.
            if let Some(&first) = model.iter().next() {
                let mut dup = raw.clone();
                dup.push(first);
                let try_dup =
                    <Set<u32> as TryFromIterator<u32>>::try_from_iter(dup.iter().copied());
                assert_eq!(try_dup.unwrap_err(), OrderedError::DuplicateKey);
            }
        }

        FuzzInput::AssociatedInsert { keys, values } => {
            let pairs = keys.iter().zip(values.iter()).map(|(k, v)| (*k, *v));
            let map = Map::from_iter_dedup(pairs);

            let _ = map.is_empty();
            let _ = map.len();

            for (i, _) in map.keys().iter().enumerate() {
                let _ = map.value(i);
            }
        }

        FuzzInput::AssociatedOperations {
            keys,
            values,
            search_key,
            index,
        } => {
            let pairs = keys.iter().zip(values.iter()).map(|(k, v)| (*k, *v));
            let map = Map::from_iter_dedup(pairs);

            let _ = map.len();
            let _ = map.position(&search_key);
            let _ = map.get(index);
            let _ = map.value(index);
            let _ = map.get_value(&search_key);
            let _ = map.keys();
            let _ = map.values();

            for _ in map.iter_pairs() {}

            // Invariants: keys are strictly sorted; position/get_value agree
            // with a BTreeMap model that takes the first occurrence of each key
            // (matching `dedup_by` over the stable-sorted input).
            assert!(map.keys().iter().is_sorted());
            let mut model: BTreeMap<u32, u64> = BTreeMap::new();
            for (k, v) in keys.iter().copied().zip(values.iter().copied()) {
                model.entry(k).or_insert(v);
            }
            assert_eq!(map.len(), model.len());
            for (i, k) in map.keys().iter().enumerate() {
                assert_eq!(map.get(i), Some(k));
                assert_eq!(map.position(k), Some(i));
                assert_eq!(map.value(i), model.get(k));
                assert_eq!(map.get_value(k), model.get(k));
            }
            assert_eq!(map.get_value(&search_key), model.get(&search_key));
        }

        FuzzInput::SetCodec { items } => {
            // Encode an arbitrary Vec<u32> (whose wire matches Set<u32>) and
            // decode through Set::read_cfg. The decoder must accept iff the
            // items are strictly sorted and unique.
            let encoded = items.encode();
            let cfg = (RangeCfg::from(..), ());
            let decoded = Set::<u32>::read_cfg(&mut encoded.as_ref(), &cfg);

            let mut sorted_unique = items.clone();
            sorted_unique.sort();
            sorted_unique.dedup();
            let is_strictly_sorted = items == sorted_unique;
            assert_eq!(decoded.is_ok(), is_strictly_sorted);
            if let Ok(set) = decoded {
                // Round-trip preserves the wire form.
                assert_eq!(set.encode().as_ref(), encoded.as_ref());
            }
        }

        FuzzInput::QuorumOnSet { data } => {
            let set = Set::from_iter_dedup(data);
            let n = u32::try_from(set.len()).unwrap();
            if n == 0 {
                return;
            }
            let f = <Set<u32> as Quorum>::max_faults::<N3f1>(&set);
            let q = <Set<u32> as Quorum>::quorum::<N3f1>(&set);
            assert_eq!(q + f, n);
            // BFT safety / quorum-intersection: 2q > n + f.
            assert!(2 * u64::from(q) > u64::from(n) + u64::from(f));
        }

        FuzzInput::BiMapOps { keys, values } => {
            let pairs: Vec<(u32, u64)> = keys
                .iter()
                .copied()
                .zip(values.iter().copied().chain(core::iter::repeat(0)))
                .take(keys.len())
                .collect();

            // Decide expected outcome from a model that mirrors the
            // BiMap rules: keys must be unique and values must be unique.
            let mut model: BTreeMap<u32, u64> = BTreeMap::new();
            for (k, v) in pairs.iter() {
                model.entry(*k).or_insert(*v);
            }
            let has_dup_keys = pairs.len() != model.len();
            let unique_values: BTreeSet<u64> = model.values().copied().collect();
            let has_dup_values = unique_values.len() != model.len();

            let result = <BiMap<u32, u64> as TryFromIterator<(u32, u64)>>::try_from_iter(
                pairs.iter().copied(),
            );
            match (has_dup_keys, has_dup_values) {
                (true, _) => {
                    assert_eq!(result.unwrap_err(), OrderedError::DuplicateKey);
                }
                (false, true) => {
                    assert_eq!(result.unwrap_err(), OrderedError::DuplicateValue);
                }
                (false, false) => {
                    let bimap = result.unwrap();
                    // Round-trip property: get_key(get_value(k)) == Some(&k).
                    for (k, v) in model.iter() {
                        assert_eq!(bimap.get_value(k), Some(v));
                        assert_eq!(bimap.get_key(v), Some(k));
                    }
                }
            }
        }

        FuzzInput::BiMapCodec { keys, values } => {
            // Build a wire payload matching Map<K,V> = Set<K> || Vec<V>.
            // Skip cases that the Set decoder would reject so we isolate the
            // BiMap-specific (duplicate value) branch.
            let n = keys.len().min(values.len());
            let keys = &keys[..n];
            let values = &values[..n];

            let mut sorted = keys.to_vec();
            sorted.sort();
            sorted.dedup();
            if sorted != keys {
                return;
            }

            let mut payload = Vec::new();
            payload.extend_from_slice(keys.encode().as_ref());
            payload.extend_from_slice(values.encode().as_ref());

            let cfg = (RangeCfg::from(..), (), ());
            let decoded = BiMap::<u32, u64>::read_cfg(&mut payload.as_slice(), &cfg);

            let unique_values: BTreeSet<u64> = values.iter().copied().collect();
            let has_dup_values = unique_values.len() != values.len();
            assert_eq!(decoded.is_ok(), !has_dup_values);
        }

        FuzzInput::MapMutate {
            keys,
            values,
            write_key,
            write_value,
            truncate_to,
        } => {
            let pairs: Vec<(u32, u64)> = keys
                .iter()
                .copied()
                .zip(values.iter().copied().chain(core::iter::repeat(0)))
                .take(keys.len())
                .collect();

            let mut model: BTreeMap<u32, u64> = BTreeMap::new();
            for (k, v) in pairs.iter() {
                model.entry(*k).or_insert(*v);
            }

            // try_from_iter: Err on duplicate keys.
            let has_dup_keys = pairs.len() != model.len();
            let try_result = <Map<u32, u64> as TryFromIterator<(u32, u64)>>::try_from_iter(
                pairs.iter().copied(),
            );
            if has_dup_keys {
                assert_eq!(try_result.unwrap_err(), OrderedError::DuplicateKey);
            } else {
                try_result.unwrap();
            }

            let mut map = Map::<u32, u64>::from_iter_dedup(pairs.iter().copied());

            // get_value_mut writes through.
            if let Some(v) = map.get_value_mut(&write_key) {
                *v = write_value;
                assert_eq!(map.get_value(&write_key), Some(&write_value));
            } else {
                assert!(!model.contains_key(&write_key));
            }

            // truncate caps len; remaining prefix is preserved.
            let target = truncate_to.min(map.len() + 1);
            let prefix_keys: Vec<u32> = map.keys().iter().take(target).copied().collect();
            let prefix_values: Vec<u64> = map.values().iter().take(target).copied().collect();
            map.truncate(target);
            assert_eq!(map.len(), target.min(prefix_keys.len()));
            let new_keys: Vec<u32> = map.keys().iter().copied().collect();
            assert_eq!(new_keys, prefix_keys);
            let new_values: Vec<u64> = map.values().iter().copied().collect();
            assert_eq!(new_values, prefix_values);
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
