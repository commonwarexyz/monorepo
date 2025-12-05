#![no_main]

use arbitrary::Arbitrary;
use commonware_utils::ordered::{Map, Set};
use libfuzzer_sys::fuzz_target;

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
}

fn fuzz(input: FuzzInput) {
    match input {
        FuzzInput::FromVec { data } => {
            let set = Set::from_iter_dedup(data);
            let _ = set.len();
            let _ = set.is_empty();
            let _ = set.iter().count();
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
            let set = Set::from_iter_dedup(data);
            let _ = set.get(index);
            let _ = set.position(&search);
            let _ = set.iter().count();
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
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
