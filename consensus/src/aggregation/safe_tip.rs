use super::types::Index;
use commonware_utils::{max_faults, Array};
use std::collections::{btree_map, BTreeMap, HashMap, HashSet};

/// A data structure that keeps track of the reported tip for each validator.
/// It can efficiently query the `f`th highest tip, where `f` is the maximum number of faults
/// that can be tolerated for the given set of validators.
pub struct SafeTip<P: Array> {
    /// For each validator, the maximum tip that it has reported.
    tips: HashMap<P, Index>,

    /// The `f` highest tips, stored as a map from index to number of validators.
    ///
    /// We assume that all of these values could have been reported by faulty validators.
    hi: BTreeMap<Index, usize>,

    /// The `n-f` lowest tips, stored as a map from index to number of validators.
    ///
    /// Treat the highest value as the safe tip, which is the tip that at least one honest validator
    /// has reached.
    lo: BTreeMap<Index, usize>,
}

impl<P: Array> Default for SafeTip<P> {
    fn default() -> Self {
        Self {
            tips: HashMap::new(),
            hi: BTreeMap::new(),
            lo: BTreeMap::new(),
        }
    }
}

impl<P: Array> SafeTip<P> {
    /// Initializes an instance with the given validators.
    ///
    /// # Panics
    ///
    /// Panics if the validator set is empty or if the validators are not unique.
    pub fn init(&mut self, validators: &Vec<P>) {
        // Ensure the validator set is not empty and all validators are unique
        assert!(!validators.is_empty());

        // Get the number of validators and the maximum number of faults
        let n = validators.len();
        let f = max_faults(n as u32) as usize;

        // Initialize the tips map
        let mut tips = HashMap::with_capacity(n);
        for validator in validators {
            tips.insert(validator.clone(), Index::default());
        }
        assert!(tips.len() == validators.len()); // Ensure all validators are unique

        // Initialize the heaps
        let mut lo = BTreeMap::new();
        lo.insert(Index::default(), n - f);
        let mut hi = BTreeMap::new();
        if f > 0 {
            hi.insert(Index::default(), f);
        }

        self.tips = tips;
        self.hi = hi;
        self.lo = lo;
    }

    /// Updates the validator set. New validators are added with a default tip of 0.
    ///
    /// # Panics
    ///
    /// Panics if the new validator set is not unique and the same size as the existing set.
    pub fn reconcile(&mut self, validators: &Vec<P>) {
        // Verify the new validators and collect them into a set.
        assert!(
            validators.len() == self.tips.len(),
            "Validator set size mismatch"
        );
        let mut new_vals = HashSet::with_capacity(validators.len());
        for validator in validators {
            assert!(new_vals.insert(validator));
        }

        // Get the set of exiting validators.
        let mut exiting_vals = Vec::new();
        for val in self.tips.keys() {
            if !new_vals.contains(val) {
                exiting_vals.push(val.clone());
            }
        }

        // Remove validators that are no longer in the set.
        // Their old tip value gets set to the default value.
        for val in exiting_vals {
            // Remove the validator from the set of validators.
            let old = self.tips.remove(&val).unwrap();
            let new = Index::default();

            // Update the heaps. Since the value is decreasing (or stays at 0), there are four
            // cases, which we check in order-of-preference:
            // 1. No-op. The value was already `0`.
            // 2. The value can remain in the `lo` heap.
            // 3. The value can remain in the `hi` heap.
            // 4. The value must be moved from the `hi` heap to the `lo` heap.

            // Case 1: No-op
            if old == new {
                continue;
            }

            // Case 2: The value can remain in the `lo` heap.
            if self.lo.contains_key(&old) {
                dec(self.lo.entry(old));
                inc(self.lo.entry(new));
                continue;
            }

            // At this point, we know that the old value is in the `hi` heap. If every single value
            // in the `lo` heap is less-than-or-equal-to the new value, then the value can remain in
            // the `hi` heap.
            let stay_in_hi: bool = self
                .lo
                .last_entry()
                .map(|e| *e.key())
                .is_none_or(|max_lo| max_lo <= new);

            // Case 3: The value can remain in the `hi` heap.
            if stay_in_hi {
                dec(self.hi.entry(old));
                inc(self.hi.entry(new));
                continue;
            }

            // Case 4: The value must be moved from the `hi` heap to the `lo` heap.
            dec(self.hi.entry(old));
            inc(self.lo.entry(new));

            // Move the maximum value from the `lo` heap to the `hi` heap.
            let max_lo = *self.lo.last_entry().expect("Empty lo heap").key();
            assert!(max_lo > new); // Sanity-check
            dec(self.lo.entry(max_lo));
            inc(self.hi.entry(max_lo));
        }

        // Add new validators with default index
        for new_val in new_vals {
            self.tips.entry(new_val.clone()).or_default();
        }
    }

    /// Updates the tip for the given validator.
    ///
    /// Returns `None` if the validator is not in the set of validators.
    ///
    /// Returns `None` if the new tip is not higher than the old tip.
    ///
    /// Otherwise, returns the old tip.
    pub fn update(&mut self, public_key: P, new: Index) -> Option<Index> {
        // Update the tip for the given validator. Return early if the validator is not in the set.
        let &old = self.tips.get(&public_key)?;

        // If the new tip is not higher than the old tip, this is a no-op.
        if old >= new {
            return None;
        }

        // Update the tip for the given validator
        self.tips.insert(public_key, new);

        // Update the heaps. Since the value is strictly increasing, there are three cases, which we
        // check in order-of-preference:
        // 1. The value can remain in the `hi` heap.
        // 2. The value can remain in the `lo` heap.
        // 3. The value must be moved from the `lo` heap to the `hi` heap.

        // Case 1: The value can remain in the `hi` heap.
        if self.hi.contains_key(&old) {
            dec(self.hi.entry(old));
            inc(self.hi.entry(new));
            return Some(old);
        }

        // At this point, we know that the old value is in the `lo` heap. If every single value in
        // the `hi` heap is greater-than-or-equal-to the new value, then the value can remain in the
        // `lo` heap.
        let stay_in_lo: bool = self
            .hi
            .first_entry()
            .map(|e| *e.key())
            .is_none_or(|min_hi| min_hi >= new);

        // Case 2: The value can remain in the `lo` heap.
        if stay_in_lo {
            dec(self.lo.entry(old));
            inc(self.lo.entry(new));
            return Some(old);
        }

        // Case 3: The value must be moved from the `lo` heap to the `hi` heap.
        dec(self.lo.entry(old));
        inc(self.hi.entry(new));

        // Move the minimum value from the `hi` heap to the `lo` heap.
        let min_hi = *self.hi.first_entry().expect("Empty hi heap").key();
        assert!(min_hi < new); // Sanity-check
        dec(self.hi.entry(min_hi));
        inc(self.lo.entry(min_hi));

        Some(old)
    }

    /// Returns the `f`th highest tip.
    ///
    /// # Panics
    ///
    /// Panics if the set of validators is empty.
    pub fn get(&self) -> Index {
        self.lo
            .last_key_value()
            .map(|(k, _)| *k)
            .expect("Empty validator set")
    }
}

/// Increments the value of the entry in the map.
///
/// If the entry does not exist, it is created with a value of 1.
fn inc(entry: btree_map::Entry<'_, Index, usize>) {
    *entry.or_default() += 1;
}

/// Decrements the value of the entry in the map.
///
/// If the value reaches zero, the entry is removed from the map.
///
/// # Panics
///
/// Panics if the entry is [`btree_map::Entry::Vacant`].
fn dec(entry: btree_map::Entry<'_, Index, usize>) {
    let btree_map::Entry::Occupied(mut value) = entry else {
        panic!("Cannot decrement a non-existent entry");
    };
    *value.get_mut() -= 1;
    if *value.get() == 0 {
        value.remove();
    }
}
