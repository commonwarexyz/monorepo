//! A specialized in-memory MMR over bit values. Instead of treating each bit as a distinct element,
//! it concatenates consecutive bit elements into chunks of DIGEST_SIZE in order to reduce overhead.

use crate::mmr::{hasher::Hasher, mem::Mmr as MemMmr};
use commonware_cryptography::Hasher as CHasher;
use commonware_utils::SizedSerialize;

pub struct Mmr<H: CHasher> {
    mmr: MemMmr<H>,
    next_element: Vec<u8>,
    next_bit: u64,
}

impl<H: CHasher> Default for Mmr<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: CHasher> Mmr<H> {
    const CHUNK_SIZE: u64 = H::Digest::SERIALIZED_LEN as u64;

    pub fn new() -> Self {
        let next_element = vec![0u8; Self::CHUNK_SIZE as usize];
        Mmr {
            mmr: MemMmr::new(),
            next_element,
            next_bit: 0,
        }
    }

    pub fn size(&self) -> u64 {
        self.mmr.size() * (Self::CHUNK_SIZE * 8) + self.next_bit
    }

    /// Efficiently add a digest-worth of bits to the bitmap mmr assuming the MMR size is a multiple
    /// of the chunk size.  Returns the position of the first from the added chunk.
    pub fn add_chunk_unchecked(&mut self, hasher: &mut H, chunk: &H::Digest) -> u64 {
        if self.size() % Self::CHUNK_SIZE != 0 {
            panic!("size is not a multiple of CHUNK_SIZE");
        }
        self.mmr.add(hasher, chunk)
    }

    pub fn add(&mut self, hasher: &mut H, bit: bool) -> u64 {
        let pos = self.size();
        if bit {
            self.next_element[self.next_bit as usize / 8] |= (1 << (self.next_bit % 8)) as u8;
        }
        self.next_bit += 1;
        if self.next_bit < Self::CHUNK_SIZE * 8 {
            return pos;
        }

        let digest = &H::Digest::try_from(self.next_element.clone()).unwrap();
        self.mmr.add(hasher, digest);

        self.next_element = vec![0u8; Self::CHUNK_SIZE as usize];
        self.next_bit = 0;

        pos
    }

    /// Compute the root hash of the bitmap ignoring any pending bits. That is, it computes the root
    /// up to point of the last chunk boundary.
    pub fn root_no_pending_bits(&self, hasher: &mut H) -> H::Digest {
        let peaks = self
            .mmr
            .peak_iterator()
            .map(|(peak_pos, _)| self.mmr.get_node_unchecked(peak_pos));

        let size = self.size();

        Hasher::new(hasher).root_hash(size, peaks)
    }

    /// Compute the root hash of the bitmap MMR. The computation does not require the MMR to be at a
    /// chunk boundary.
    pub fn root(&mut self, hasher: &mut H) -> H::Digest {
        if self.next_bit == 0 {
            return self.root_no_pending_bits(hasher);
        }
        // TODO: implement this in a way that doesn't require mutating the MMR so we can drop the
        // &mut self.
        self.mmr.add(
            hasher,
            &H::Digest::try_from(self.next_element.clone()).unwrap(),
        );
        let r = self.root_no_pending_bits(hasher);
        assert!(self.mmr.pop().is_ok());
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{hash, Sha256};

    #[test]
    fn test_bitmap_mmr_build() {
        // Build a bitmap MMR with DIGEST_SIZE elements where bits come from the following digest:
        let test_digest = hash(b"test");
        let mut hasher = Sha256::new();

        // Add each bit one at a time.
        let mut mmr = Mmr::<Sha256>::new();
        let vec: Vec<u8> = test_digest.as_ref().to_vec();
        for b in vec {
            for j in 0..8 {
                let mask = 1 << j;
                let bit = (b & mask) != 0;
                mmr.add(&mut hasher, bit);
            }
        }

        assert_eq!(
            *mmr.mmr.get_node_unchecked(0),
            Hasher::new(&mut hasher).leaf_hash(0, &test_digest)
        );
        assert_eq!(mmr.mmr.size(), 1);
        assert_eq!(mmr.size(), Mmr::<Sha256>::CHUNK_SIZE * 8);

        let root = mmr.root(&mut hasher);
        let inner_root = mmr.mmr.root(&mut hasher);
        assert!(root != inner_root, "bitmap mmr root should differ");

        // Repeat the above MMR build only using add_chunk_unchecked instead, and make sure root
        // hashes match.
        let mut mmr2 = Mmr::<Sha256>::new();
        mmr2.add_chunk_unchecked(&mut hasher, &test_digest);
        let root2 = mmr.root(&mut hasher);
        assert_eq!(root, root2);

        mmr2.add_chunk_unchecked(&mut hasher, &test_digest);
        assert_eq!(mmr2.mmr.size(), 3);
        assert_eq!(mmr2.size(), Mmr::<Sha256>::CHUNK_SIZE * 3 * 8);
        assert_eq!(
            *mmr2.mmr.get_node_unchecked(1),
            Hasher::new(&mut hasher).leaf_hash(1, &test_digest)
        );

        // Make sure root hash changes as we add bits outside a chunk boundary
        mmr2.add(&mut hasher, false);
        let root3 = mmr2.root(&mut hasher);
        assert!(root != root3);
        mmr2.add(&mut hasher, false);
        let root4 = mmr2.root(&mut hasher);
        assert!(root3 != root4);
    }

    #[test]
    #[should_panic(expected = "size is not a multiple of CHUNK_SIZE")]
    fn test_bitmap_mmr_build_panic() {
        let mut hasher = Sha256::new();
        let mut mmr = Mmr::<Sha256>::default();
        assert_eq!(mmr.add_chunk_unchecked(&mut hasher, &hash(b"test")), 0);
        assert_eq!(mmr.add(&mut hasher, true), 256);
        mmr.add_chunk_unchecked(&mut hasher, &hash(b"should panic"));
    }
}
