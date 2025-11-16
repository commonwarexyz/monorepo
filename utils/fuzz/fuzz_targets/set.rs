#![no_main]

use arbitrary::Arbitrary;
use commonware_utils::set::{Ordered, OrderedAssociated};
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
            let ordered = Ordered::from(data.clone());
            let _ = ordered.len();
            let _ = ordered.is_empty();
            let _ = ordered.iter().count();
            let _: Vec<u32> = ordered.into();
        }

        FuzzInput::FromSlice { data } => {
            let ordered = Ordered::from(data.as_slice());
            let _ = ordered.len();
            let _ = ordered.is_empty();
        }

        FuzzInput::FromArray { data } => {
            let ordered = Ordered::from(data);
            let _ = ordered.len();
        }

        FuzzInput::Operations {
            data,
            index,
            search,
        } => {
            let ordered = Ordered::from(data);
            let _ = ordered.get(index);
            let _ = ordered.position(&search);
            let _ = ordered.iter().count();
        }

        FuzzInput::AssociatedInsert { keys, values } => {
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

        FuzzInput::AssociatedOperations {
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
