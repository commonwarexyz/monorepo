//! Shared generator and checks for fold and map operations.

use crate::{Rayon, Sequential, Strategy, rayon::ThreadPoolBuilder};
use arbitrary::{Arbitrary, Unstructured};
use commonware_utils::NZUsize;

pub(super) fn parallel_strategy() -> Rayon {
    Rayon::new(ThreadPoolBuilder::new(NZUsize!(4))).unwrap()
}

/// An input for comparing fold and map operations.
#[derive(Debug)]
pub struct Plan(Vec<i32>);

impl Arbitrary<'_> for Plan {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        let (words, _) = u.bytes(u.len())?.as_chunks();
        let data = words.iter().copied().map(i32::from_le_bytes).collect();
        Ok(Self(data))
    }
}

impl Plan {
    /// Checks fold and map results against their sequential or equivalent operations.
    ///
    /// Panics if any result disagrees with its reference.
    pub fn run(self) {
        let parallel = parallel_strategy();
        self.parallel_fold_init_matches_sequential(&parallel);
        self.fold_equals_fold_init();
        self.parallel_try_fold_matches_sequential(&parallel);
        self.map_collect_vec_equals_fold();
        self.try_map_collect_vec_collects_successes(&parallel);
        self.try_map_collect_vec_returns_first_error();
        self.map_init_collect_vec_equals_fold_init();
        self.map_partition_collect_vec_returns_valid_results();
    }

    #[cfg(test)]
    pub(super) fn regressions() -> [Self; 3] {
        // Exercise empty and large inputs, and wrapping arithmetic on every run.
        [
            Self(Vec::new()),
            Self(vec![i32::MAX, i32::MAX, i32::MIN]),
            Self((1..=499).collect()),
        ]
    }

    pub(super) fn parallel_fold_init_matches_sequential(&self, parallel: &Rayon) {
        let data = self.0.as_slice();
        let sequential = Sequential;

        let seq_result: Vec<i32> = sequential.fold_init(
            data,
            || (),
            Vec::new,
            |mut acc, _, &x| {
                acc.push(x.wrapping_mul(2));
                acc
            },
            |mut a, b| {
                a.extend(b);
                a
            },
        );

        let par_result: Vec<i32> = parallel.fold_init(
            data,
            || (),
            Vec::new,
            |mut acc, _, &x| {
                acc.push(x.wrapping_mul(2));
                acc
            },
            |mut a, b| {
                a.extend(b);
                a
            },
        );

        assert_eq!(seq_result, par_result);
    }

    pub(super) fn fold_equals_fold_init(&self) {
        let data = self.0.as_slice();
        let s = Sequential;

        let via_fold: Vec<i32> = s.fold(
            data,
            Vec::new,
            |mut acc, &x| {
                acc.push(x);
                acc
            },
            |mut a, b| {
                a.extend(b);
                a
            },
        );

        let via_fold_init: Vec<i32> = s.fold_init(
            data,
            || (),
            Vec::new,
            |mut acc, _, &x| {
                acc.push(x);
                acc
            },
            |mut a, b| {
                a.extend(b);
                a
            },
        );

        assert_eq!(via_fold, via_fold_init);
    }

    pub(super) fn parallel_try_fold_matches_sequential(&self, parallel: &Rayon) {
        let data = self.0.as_slice();
        let sequential: Result<i32, ()> = Sequential.try_fold(
            data,
            || 0i32,
            |acc, &x| Ok(acc.wrapping_add(x)),
            |a, b| a.wrapping_add(b),
        );
        let parallel: Result<i32, ()> = parallel.try_fold(
            data,
            || 0i32,
            |acc, &x| Ok(acc.wrapping_add(x)),
            |a, b| a.wrapping_add(b),
        );

        assert_eq!(sequential, parallel);
    }

    pub(super) fn map_collect_vec_equals_fold(&self) {
        let data = self.0.as_slice();
        let s = Sequential;
        let map_op = |&x: &i32| x.wrapping_mul(3);

        let via_map: Vec<i32> = s.map_collect_vec(data, map_op);

        let via_fold: Vec<i32> = s.fold(
            data,
            Vec::new,
            |mut acc, item| {
                acc.push(map_op(item));
                acc
            },
            |mut a, b| {
                a.extend(b);
                a
            },
        );

        assert_eq!(via_map, via_fold);
    }

    pub(super) fn try_map_collect_vec_collects_successes(&self, parallel: &Rayon) {
        let data = self.0.as_slice();
        let expected: Vec<i32> = data.iter().map(|x| x.wrapping_mul(5)).collect();

        let sequential: Result<Vec<i32>, ()> =
            Sequential.try_map_collect_vec(data, |&x| Ok(x.wrapping_mul(5)));
        assert_eq!(sequential, Ok(expected.clone()));

        let parallel: Result<Vec<i32>, ()> =
            parallel.try_map_collect_vec(data, |&x| Ok(x.wrapping_mul(5)));
        assert_eq!(parallel, Ok(expected));
    }

    pub(super) fn try_map_collect_vec_returns_first_error(&self) {
        let data = self.0.as_slice();
        let expected_error = data.iter().position(|x| x % 7 == 0);
        let result: Result<Vec<i32>, usize> =
            Sequential.try_map_collect_vec(data.iter().enumerate(), |(i, &x)| {
                if x % 7 == 0 { Err(i) } else { Ok(x) }
            });

        match expected_error {
            Some(i) => assert_eq!(result, Err(i)),
            None => assert_eq!(result.as_deref(), Ok(data)),
        }
    }

    pub(super) fn map_init_collect_vec_equals_fold_init(&self) {
        let data = self.0.as_slice();
        let s = Sequential;

        let via_map: Vec<i32> = s.map_init_collect_vec(
            data,
            || 0i32,
            |counter, &x| {
                *counter += 1;
                x.wrapping_add(*counter)
            },
        );

        let via_fold_init: Vec<i32> = s.fold_init(
            data,
            || 0i32,
            Vec::new,
            |mut acc, counter, &x| {
                *counter += 1;
                acc.push(x.wrapping_add(*counter));
                acc
            },
            |mut a, b| {
                a.extend(b);
                a
            },
        );

        assert_eq!(via_map, via_fold_init);
    }

    pub(super) fn map_partition_collect_vec_returns_valid_results(&self) {
        let data = self.0.as_slice();
        let s = Sequential;

        let map_op = |&x: &i32| {
            let value = if x % 2 == 0 {
                Some(x.wrapping_mul(2))
            } else {
                None
            };
            (x, value)
        };

        let (results, filtered) = s.map_partition_collect_vec(data.iter(), map_op);

        // Verify results contains doubled even numbers
        let expected_results: Vec<i32> = data
            .iter()
            .filter(|&&x| x % 2 == 0)
            .map(|&x| x.wrapping_mul(2))
            .collect();
        assert_eq!(results, expected_results);

        // Verify filtered contains odd numbers
        let expected_filtered: Vec<i32> = data.iter().filter(|&&x| x % 2 != 0).copied().collect();
        assert_eq!(filtered, expected_filtered);
    }
}
