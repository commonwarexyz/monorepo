use super::{
    code::{Decoder, Encoder, Error, Impl},
    field::gf8::GF8,
};
use commonware_math::algebra::{Additive, Ring};
use commonware_utils::test_rng;
use rand::{Rng, seq::SliceRandom};

#[derive(Clone, Copy)]
struct Scalar;

impl Impl for Scalar {
    type Element = GF8;
    const BITS: usize = 8;

    fn basis() -> &'static [GF8] {
        &[
            GF8(1),
            GF8(188),
            GF8(92),
            GF8(12),
            GF8(174),
            GF8(90),
            GF8(14),
            GF8(132),
        ]
    }

    fn add_into(self, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        for (d, s) in dst.iter_mut().zip(src) {
            *d ^= s;
        }
    }

    fn sub_into(self, dst: &mut [u8], src: &[u8]) {
        self.add_into(dst, src);
    }

    fn mul_add(self, dst: &mut [u8], src: &[u8], c: GF8) {
        assert_eq!(dst.len(), src.len());
        for (d, s) in dst.iter_mut().zip(src) {
            *d ^= u8::from(GF8(*s) * c);
        }
    }

    fn mul_sub(self, dst: &mut [u8], src: &[u8], c: GF8) {
        self.mul_add(dst, src, c);
    }
}

#[test]
fn encode_empty_shards() {
    assert_eq!(
        Encoder::new(Scalar).encode(&[&[], &[]], 3),
        vec![Vec::<u8>::new(); 3]
    );
}

#[test]
#[should_panic(expected = "too many shards")]
fn encode_rejects_padded_count_overflow() {
    Encoder::new(Scalar).encode(&[&[1][..]; 127], 129);
}

fn check_recovery(
    decoder: &Decoder<Scalar>,
    original: &[Vec<u8>],
    recovery: &[Vec<u8>],
    erased: &[bool],
) {
    let k = original.len();
    let input: Vec<_> = original
        .iter()
        .chain(recovery)
        .zip(erased)
        .map(|(s, &missing)| (!missing).then_some(s.as_slice()))
        .collect();
    let decoded = decoder.decode(&input[..k], &input[k..]);
    let present = erased.iter().filter(|&&e| !e).count();
    if present < k {
        assert_eq!(
            decoded,
            Err(Error::InsufficientShards {
                present,
                required: k
            })
        );
        return;
    }
    let expected: Vec<_> = original
        .iter()
        .enumerate()
        .filter(|&(i, _)| erased[i])
        .map(|(i, s)| (i, s.clone()))
        .collect();
    assert_eq!(
        decoded.unwrap(),
        expected,
        "k={k}, r={}, erased={erased:?}",
        recovery.len()
    );
}

#[test]
fn all_small_erasure_patterns() {
    let encoder = Encoder::new(Scalar);
    let decoder = Decoder::new(Scalar);
    let mut rng = test_rng();
    for k in 1..=4 {
        for r in 0..=4 {
            let mut original = vec![vec![0; 7]; k];
            for s in &mut original {
                rng.fill_bytes(s);
            }
            let refs: Vec<_> = original.iter().map(Vec::as_slice).collect();
            let recovery = encoder.encode(&refs, r);
            for mask in 0..1 << (k + r) {
                let erased: Vec<_> = (0..k + r).map(|i| mask & (1 << i) != 0).collect();
                check_recovery(&decoder, &original, &recovery, &erased);
            }
        }
    }
}

#[test]
fn field_boundaries_and_shard_lengths() {
    let encoder = Encoder::new(Scalar);
    let decoder = Decoder::new(Scalar);
    let mut rng = test_rng();
    for (k, r) in [
        (1, 128),
        (3, 5),
        (65, 65),
        (128, 127),
        (128, 128),
        (192, 63),
        (255, 1),
        (256, 0),
    ] {
        for len in [0, 1, 16, 17, 65] {
            let mut original = vec![vec![0; len]; k];
            for s in &mut original {
                rng.fill_bytes(s);
            }
            let refs: Vec<_> = original.iter().map(Vec::as_slice).collect();
            let recovery = encoder.encode(&refs, r);
            let mut indices: Vec<_> = (0..k + r).collect();
            indices.shuffle(&mut rng);
            for count in [0, 1.min(r), r, r + 1] {
                let mut erased = vec![false; k + r];
                for &i in &indices[..count] {
                    erased[i] = true;
                }
                check_recovery(&decoder, &original, &recovery, &erased);
            }
            // Recover from parity alone whenever there is enough of it.
            if r >= k {
                let mut erased = vec![false; k + r];
                erased[..k].fill(true);
                check_recovery(&decoder, &original, &recovery, &erased);
            }
        }
    }
}

fn point(i: usize) -> GF8 {
    Scalar::basis()
        .iter()
        .enumerate()
        .filter(|(bit, _)| i & (1 << bit) != 0)
        .fold(GF8::zero(), |acc, (_, b)| acc + b)
}

/// Generate a codeword without the encoder or additive transforms.
fn polynomial_codeword(k: usize, r: usize, coefficients: &[GF8]) -> Vec<Vec<u8>> {
    let m = r.next_power_of_two();
    let n = (m + k).next_power_of_two();
    assert_eq!(coefficients.len(), k);
    (0..n)
        .map(|i| {
            let x = point(i);
            let p = coefficients
                .iter()
                .rev()
                .fold(GF8::zero(), |acc, c| acc * x + c);
            // The encoder's shortened code fixes the padded originals to zero.
            let padding = (m + k..n).fold(GF8::one(), |acc, j| acc * (x - point(j)));
            vec![u8::from(p * padding)]
        })
        .collect()
}

#[test]
fn independent_polynomial_evaluations() {
    let encoder = Encoder::new(Scalar);
    let decoder = Decoder::new(Scalar);
    let mut rng = test_rng();
    for (k, r) in [(1, 1), (2, 3), (3, 2), (5, 7), (7, 5), (17, 9), (127, 128)] {
        let coefficients: Vec<_> = (0..k).map(|_| GF8(rng.next_u32() as u8)).collect();
        let codeword = polynomial_codeword(k, r, &coefficients);
        let m = r.next_power_of_two();
        let original = &codeword[m..m + k];
        let recovery = &codeword[..r];
        let refs: Vec<_> = original.iter().map(Vec::as_slice).collect();
        assert_eq!(encoder.encode(&refs, r), recovery);
        let mut indices: Vec<_> = (0..k + r).collect();
        indices.shuffle(&mut rng);
        let mut erased = vec![false; k + r];
        for &i in &indices[..r] {
            erased[i] = true;
        }
        check_recovery(&decoder, original, recovery, &erased);
    }
}

#[test]
fn cantor_basis() {
    assert_eq!(Scalar::basis()[0], GF8::one());
    for pair in Scalar::basis().windows(2) {
        assert_eq!(pair[1] * pair[1] - pair[1], pair[0]);
    }
    let points: std::collections::BTreeSet<_> = (0..256).map(|i| u8::from(point(i))).collect();
    assert_eq!(points.len(), 256);
}

#[test]
fn invalid_decode_requests() {
    let decoder = Decoder::new(Scalar);
    let shard = Some(&[1][..]);
    assert_eq!(decoder.decode(&[], &[]), Err(Error::InvalidShardCount));
    assert_eq!(decoder.decode(&[], &[shard]), Err(Error::InvalidShardCount));
    assert_eq!(
        decoder.decode(&[shard; 257], &[]),
        Err(Error::InvalidShardCount)
    );
    assert_eq!(
        decoder.decode(&[shard; 127], &[shard; 129]),
        Err(Error::InvalidShardCount)
    );
    assert_eq!(
        decoder.decode(&[shard], &[shard; 256]),
        Err(Error::InvalidShardCount)
    );
    assert_eq!(
        decoder.decode(&[None], &[]),
        Err(Error::InsufficientShards {
            present: 0,
            required: 1
        })
    );
    assert_eq!(
        decoder.decode(&[None; 3], &[shard; 2]),
        Err(Error::InsufficientShards {
            present: 2,
            required: 3
        })
    );
    assert_eq!(
        decoder.decode(&[shard, Some(&[])], &[]),
        Err(Error::InvalidShardLength)
    );
    assert_eq!(
        decoder.decode(&[shard], &[Some(&[1, 2])]),
        Err(Error::InvalidShardLength)
    );
    assert_eq!(
        decoder.decode(&[None, shard], &[Some(&[1, 2])]),
        Err(Error::InvalidShardLength)
    );
    // Content is not checked by an erasure decoder.
    assert_eq!(decoder.decode(&[shard], &[Some(&[2])]), Ok(Vec::new()));
}
