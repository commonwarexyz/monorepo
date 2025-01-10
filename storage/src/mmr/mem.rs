//! A bare-bones MMR structure without pruning and where all elements are hashes & maintained in memory.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hash([u8; 32]); // TODO: Parameterize on length of hash?

/// Implementation of `InMemoryMMR`.
pub struct InMemoryMMR {
    elements: Vec<Hash>,
}

#[derive(Default)]
struct PeakIterator {
    sz: u64,    // Number of elements in the MMR at the point the iterator was initialized.
    peak: u64,  // 1-based index of the current peak, which may not be in the MMR.
    two_h: u64, // 2^(height+1) of the current peak, where a leaf has a height of 0.
}

/// A PeakIterator returns a (height, peak) tuple for each peak in the MMR. Height starts at 0 for leaves, and a peak is
/// a 0-based index of the represented element. You can change the MMR underneath during iteration, but the iterator
/// will only return the peaks that existed at the time of its initialization.
impl Iterator for PeakIterator {
    type Item = (u32, u64); // (height, peak)

    fn next(&mut self) -> Option<Self::Item> {
        while self.two_h > 1 {
            if self.peak <= self.sz {
                let r = (self.two_h.trailing_zeros() - 1, self.peak - 1);
                self.peak += self.two_h - 1; // move to the right sibling
                return Some(r);
            }
            self.two_h >>= 1;
            self.peak -= self.two_h; // descend to the left child
        }
        None
    }
}

impl InMemoryMMR {
    /// Return a new (empty) `InMemoryMMR`.
    pub fn new() -> Self {
        Self {
            //cfg,
            //hasher: Sha256::new(),
            elements: Vec::new(),
        }
    }

    /// Return a new iterator over the peaks of the MMR.
    fn peak_iterator(&self) -> PeakIterator {
        let sz = self.elements.len() as u64;
        if sz == 0 {
            return PeakIterator::default();
        }
        // Compute the starting peak. This starting peak will not be in the MMR unless it happens to be a full binary
        // tree, but that's OK as we'll just descend until we find one.
        let peak = u64::MAX >> sz.leading_zeros();
        let two_h = 1 << peak.trailing_ones();
        PeakIterator { sz, peak, two_h }
    }

    // If this MMR has a peak that is a leaf, this function returns it along with all other peaks of consecutively
    // increasing height. This is precisely the set of peaks we need from which to compute new parent nodes after
    // adding a new element to the MMR. Peaks are returned from highest to lowest (the leaf peak is last).
    fn peaks_from_leaf(&mut self, peaks: &mut Vec<u64>) {
        peaks.clear();
        let it = self.peak_iterator();
        let mut last_height = u32::MAX;
        for (height, peak) in it {
            assert!(last_height > 0);
            assert!(height < last_height);
            if height != last_height - 1 {
                peaks.clear();
            }
            peaks.push(peak);
            last_height = height;
        }
        if last_height != 0 {
            // there is no peak that is a leaf
            peaks.clear();
        }
    }

    /// Add a hash to the MMR and return its index.
    pub fn add_leaf_hash(&mut self, element: &Hash) -> u64 {
        let mut v = Vec::new();
        self.peaks_from_leaf(&mut v);
        let index = self.elements.len() as u64;
        self.elements.push(*element);
        // simulate adding new parents.. ultimately this will involve hashing pairs of elements of course
        for _ in 0..v.len() {
            self.elements.push(*element);
        }
        index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Test the `add_leaf_hash` function by adding 11 elements to the MMR. In the end the MMR should have 19 elements
    /// total with 3 peaks (14, 17, 18) as pictured in the MMR example here:
    /// https://docs.grin.mw/wiki/chain-state/merkle-mountain-range/
    fn test_add_elements() {
        let mut mmr = InMemoryMMR::new();
        // the empty iterator should have no peaks
        assert_eq!(mmr.peak_iterator().next(), None);

        let element = Hash(*b"01234567012345670123456701234567");
        for _ in 0..11 {
            mmr.add_leaf_hash(&element);
            let peaks: Vec<(u32, u64)> = mmr.peak_iterator().collect();
            assert_ne!(peaks.len(), 0);
            assert!(peaks.len() <= mmr.elements.len());
        }
        assert_eq!(mmr.elements.len(), 19);
        let peaks: Vec<(u32, u64)> = mmr.peak_iterator().collect();
        assert_eq!(peaks, vec![(3, 14), (1, 17), (0, 18)]);
    }
}
