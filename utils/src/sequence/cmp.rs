use core::cmp::Ordering;

/// Returns the same ordering as `a.cmp(b)`.
///
/// For 17 to 64 bytes, it compares big-endian `u64` words instead of calling `memcmp` (as the derived
/// `Ord` does on x86-64), which is fastest when keys differ early, as hashes do.
#[inline]
pub fn cmp_bytes<const N: usize>(a: &[u8; N], b: &[u8; N]) -> Ordering {
    // Up to 16 bytes the derived compare is already inlined; past 64 unrolling bloats call sites.
    if N <= 16 || N > 64 {
        return a.cmp(b);
    }
    let (a_words, _) = a.as_chunks::<8>();
    let (b_words, _) = b.as_chunks::<8>();
    for (a, b) in a_words.iter().zip(b_words) {
        let (a, b) = (u64::from_be_bytes(*a), u64::from_be_bytes(*b));
        if a != b {
            return a.cmp(&b);
        }
    }
    if N.is_multiple_of(8) {
        return Ordering::Equal;
    }
    // Every earlier byte is equal, so the last 8 bytes (overlapping the last whole word) decide.
    let last = |x: &[u8; N]| u64::from_be_bytes(*x.last_chunk::<8>().expect("N > 16"));
    last(a).cmp(&last(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_rng;
    use rand::RngExt as _;

    fn assert_matches<const N: usize>(a: &[u8; N], b: &[u8; N]) {
        assert_eq!(cmp_bytes(a, b), a.cmp(b));
        assert_eq!(cmp_bytes(b, a), b.cmp(a));
    }

    fn check<const N: usize>() {
        const BOUNDARIES: [u8; 4] = [0x00, 0x7f, 0x80, 0xff];
        let mut rng = test_rng();
        for _ in 0..8 {
            let a: [u8; N] = rng.random();
            assert_eq!(cmp_bytes(&a, &a), Ordering::Equal);
            // Make every position the first difference.
            for k in 0..N {
                let mut b = a;
                b[k] = a[k] ^ rng.random_range(1..=u8::MAX);
                for byte in &mut b[k + 1..] {
                    *byte = rng.random();
                }
                assert_matches(&a, &b);

                // Boundary bytes at `k`, with suffixes that order the other way for some pairs.
                for x in BOUNDARIES {
                    for y in BOUNDARIES {
                        let (mut a, mut b) = (a, a);
                        a[k] = x;
                        b[k] = y;
                        a[k + 1..].fill(0xff);
                        b[k + 1..].fill(0x00);
                        assert_matches(&a, &b);
                    }
                }
            }
        }
    }

    #[test]
    fn test_cmp_bytes_matches_byte_order() {
        check::<0>();
        check::<5>();
        check::<16>();
        check::<17>();
        check::<18>();
        check::<19>();
        check::<20>();
        check::<21>();
        check::<22>();
        check::<23>();
        check::<24>();
        check::<31>();
        check::<32>();
        check::<33>();
        check::<40>();
        check::<63>();
        check::<64>();
        check::<65>();
    }
}
