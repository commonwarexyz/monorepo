#![no_main]

use arbitrary::Arbitrary;
use commonware_utils::set::{Ordered, OrderedAssociated};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    OrderedFromVec {
        data: Vec<u32>,
    },
    OrderedFromSlice {
        data: Vec<u32>,
    },
    OrderedFromArray {
        data: [u32; 8],
    },
    OrderedOperations {
        data: Vec<u32>,
        index: usize,
        search: u32,
    },
    OrderedAssociatedInsert {
        keys: Vec<u32>,
        values: Vec<u64>,
    },
    OrderedAssociatedOperations {
        keys: Vec<u32>,
        values: Vec<u64>,
        search_key: u32,
        index: usize,
    },
}

fn fuzz(input: FuzzInput) {
    match input {
        FuzzInput::OrderedFromVec { data } => {
            let ordered = Ordered::from(data.clone());
            let _ = ordered.len();
            let _ = ordered.is_empty();
            let _ = ordered.iter().count();
            let _: Vec<u32> = ordered.into();
        }

        FuzzInput::OrderedFromSlice { data } => {
            let ordered = Ordered::from(data.as_slice());
            let _ = ordered.len();
            let _ = ordered.is_empty();
        }

        FuzzInput::OrderedFromArray { data } => {
            let ordered = Ordered::from(data);
            let _ = ordered.len();
        }

        FuzzInput::OrderedOperations {
            data,
            index,
            search,
        } => {
            let ordered = Ordered::from(data);
            let _ = ordered.get(index);
            let _ = ordered.position(&search);
            let _ = ordered.iter().count();
        }

        FuzzInput::OrderedAssociatedInsert { keys, values } => {
            let pairs: Vec<(u32, u64)> = keys
                .iter()
                .zip(values.iter())
                .map(|(k, v)| (*k, *v))
                .collect();
            let assoc = OrderedAssociated::from(pairs);

            let _ = assoc.is_empty();
            let _ = assoc.len();

            for (i, _) in assoc.keys().iter().enumerate() {
                let _ = assoc.value(i);
            }
        }

        FuzzInput::OrderedAssociatedOperations {
            keys,
            values,
            search_key,
            index,
        } => {
            let pairs: Vec<(u32, u64)> = keys
                .iter()
                .zip(values.iter())
                .map(|(k, v)| (*k, *v))
                .collect();
            let assoc = OrderedAssociated::from(pairs);

            let _ = assoc.len();
            let _ = assoc.position(&search_key);
            let _ = assoc.get(index);
            let _ = assoc.value(index);
            let _ = assoc.get_value(&search_key);
            let _ = assoc.keys();
            let _ = assoc.values();

            for _ in assoc.iter_pairs() {
                // Just iterate, no checks
            }
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
