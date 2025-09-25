use rand_core::CryptoRngCore;
use reed_solomon_simd::ReedSolomonEncoder;

fn gf16_mul(a: u16, b: u16) -> u16 {
    #[inline(always)]
    fn mul_u(a: u16, mut b: u16) -> (u16, u16) {
        let mut a = u32::from(a);
        let mut u = 0u32;
        while b > 0 {
            u ^= a & (0u32.wrapping_sub(u32::from(b & 1)));
            b >>= 1;
            a <<= 1;
        }
        (u as u16, (u >> 16) as u16)
    }
    let (mut out, mut hi) = mul_u(a, b);
    while hi > 0 {
        // 0x2D is the irreducible polynomial used in the RS Simd crate.
        let (l, h) = mul_u(hi, 0x2D);
        out ^= l;
        hi = h
    }
    out
}

#[derive(Clone, Copy, PartialEq)]
pub struct Gf16x8 {
    inner: u128,
}

impl std::fmt::Debug for Gf16x8 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:032X}", self.inner)
    }
}

impl Gf16x8 {
    pub fn zero() -> Self {
        Self { inner: 0u128 }
    }

    pub fn add(&self, other: &Self) -> Self {
        Self {
            inner: self.inner ^ other.inner,
        }
    }

    pub fn scale(&self, s: u16) -> Self {
        let mut inner = 0u128;
        for i in 0..8 {
            inner |= u128::from(gf16_mul(s, (self.inner >> 16 * i) as u16)) << 16 * i;
        }
        Self { inner }
    }

    pub fn rand(mut rng: impl CryptoRngCore) -> Self {
        let mut data = [0u8; 16];
        rng.fill_bytes(&mut data);
        Self {
            inner: u128::from_le_bytes(data),
        }
    }

    pub fn bytes(&self) -> [u8; 16] {
        self.inner.to_le_bytes()
    }

    pub fn u16s(&self) -> [u16; 8] {
        let mut out = [0u16; 8];
        let mut acc = self.inner;
        for u in out.iter_mut() {
            *u = acc as u16;
            acc >>= 16;
        }
        out
    }

    pub fn from_u16s(data: &[u16]) -> Self {
        let mut inner = 0u128;
        for &u in data.iter().rev() {
            inner |= u128::from(u);
            inner <<= 8;
        }
        Self { inner }
    }
}

impl TryFrom<&[u8]> for Gf16x8 {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            inner: u128::from_le_bytes(value.try_into().map_err(|_| ())?),
        })
    }
}

fn coeff_count(row_bytes: usize) -> usize {
    64 * row_bytes.div_ceil(64)
}

fn row_checksum(coeffs: &[Gf16x8], row: &[u8]) -> Gf16x8 {
    let u16s = row_to_u16s(row);
    let mut out = Gf16x8::zero();
    for (coeff, el) in coeffs.iter().zip(u16s.iter()) {
        out = out.add(&coeff.scale(*el));
    }
    out
}

fn encode_fes(fes: [Gf16x8; 4]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for i in 0..4 {
        for (j, chunk) in fes[i].bytes().chunks_exact(2).enumerate() {
            out[8 * i + j] = chunk[0];
            out[8 * i + j + 32] = chunk[1];
        }
    }
    out
}

fn decode_fes(b64: &[u8]) -> [Gf16x8; 4] {
    assert!(b64.len() <= 64);
    let mut data = [0u8; 64];
    data[..b64.len()].copy_from_slice(b64);
    let mut out = [Gf16x8::zero(); 4];
    for i in 0..4 {
        let mut fe_bytes = [0u8; 16];
        for j in 0..8 {
            fe_bytes[2 * j] = data[8 * i + j];
            fe_bytes[2 * j + 1] = data[8 * i + j + 32];
        }
        out[i] = Gf16x8::try_from(fe_bytes.as_slice()).unwrap();
    }
    out
}

fn row_to_u16s(data: &[u8]) -> Vec<u16> {
    let mut out = Vec::new();
    for chunk_data in data.chunks(64) {
        let mut chunk = [0u8; 64];
        chunk[..chunk_data.len()].copy_from_slice(chunk_data);
        for i in 0..32 {
            out.push(u16::from(chunk[i]) | (u16::from(chunk[i + 32]) << 8));
        }
    }
    out
}

fn u16s_to_row(data: &[u16]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in data.chunks(32) {
        for i in 0..32 {
            let u = chunk.get(i).copied().unwrap_or_default();
            out.push(u as u8);
        }
        for i in 0..32 {
            let u = chunk.get(i).copied().unwrap_or_default();
            out.push((u >> 8) as u8);
        }
    }
    out
}

fn encode_checks(min_rows: usize, extra_rows: usize, mut checks: Vec<Gf16x8>) -> Vec<Gf16x8> {
    let mut encoder = ReedSolomonEncoder::new(min_rows, extra_rows, 64).unwrap();
    for check in &checks {
        encoder
            .add_original_shard(&u16s_to_row(&check.u16s()))
            .unwrap();
    }
    for extra in encoder.encode().unwrap().recovery_iter() {
        checks.push(Gf16x8::from_u16s(&row_to_u16s(extra)));
    }
    checks
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    fn any_fe() -> impl Strategy<Value = Gf16x8> {
        any::<u128>().prop_map(|inner| Gf16x8 { inner })
    }

    fn test_checksum_calculation(
        min_rows: usize,
        extra_rows: usize,
        data: &[u8],
        coeffs: &[Gf16x8],
    ) {
        let chunk_size = 2 * coeffs.len();
        let rows = {
            let mut out = Vec::with_capacity(min_rows + extra_rows);
            let mut encoder = ReedSolomonEncoder::new(min_rows, extra_rows, chunk_size)
                .expect("failed to construct RS Encoder");
            for i in 0..min_rows {
                let mut chunk = vec![0u8; chunk_size];
                let start = chunk_size * i;
                let end = start + chunk_size;
                let slice = &data[start.min(data.len())..end.min(data.len())];
                chunk[..slice.len()].copy_from_slice(slice);
                encoder
                    .add_original_shard(&chunk)
                    .expect("failed to add chunk");
                out.push(chunk);
            }
            let res = encoder.encode().expect("failed to encode data");
            for chunk in res.recovery_iter() {
                out.push(chunk.to_vec());
            }
            out
        };
        assert_eq!(
            rows.len(),
            min_rows + extra_rows,
            "we should have the right number of rows"
        );
        let checks = (0..min_rows)
            .map(|i| row_checksum(coeffs, &rows[i]))
            .collect::<Vec<_>>();
        dbg!(&checks);
        let checks_a = encode_checks(min_rows, extra_rows, checks);
        dbg!(&checks_a);
        let checks_b = rows
            .iter()
            .map(|row| row_checksum(coeffs, row))
            .collect::<Vec<_>>();
        dbg!(&checks_b);
        assert_eq!(checks_a, checks_b);
    }

    fn test_rs_linearity_inner(a: u16, b: Gf16x8) {
        fn extended_row(row: &[u8]) -> Vec<u8> {
            let mut encoder = ReedSolomonEncoder::new(1, 1, row.len()).unwrap();
            encoder.add_original_shard(row).unwrap();
            let res = encoder.encode().unwrap();
            res.recovery_iter().next().unwrap().to_vec()
        }
        let way0 = extended_row(&u16s_to_row(&b.scale(a).u16s()));
        let way1 = u16s_to_row(
            &b.scale(row_to_u16s(&extended_row(&u16s_to_row(&[a])))[0])
                .u16s(),
        );
        assert_eq!(way0, way1);
    }

    proptest! {
        #[test]
        fn test_mul_commutative(a: u16, b: u16) {
            assert_eq!(gf16_mul(a, b), gf16_mul(b, a));
        }

        #[test]
        fn test_mul_associative(a: u16, b: u16, c: u16) {
            assert_eq!(gf16_mul(a, gf16_mul(b, c)), gf16_mul(gf16_mul(a, b), c));
        }

        #[test]
        fn test_mul_distributive(a: u16, b: u16, c: u16) {
            assert_eq!(gf16_mul(a, b ^ c), gf16_mul(a, b) ^ gf16_mul(a, c));
        }

        #[test]
        fn test_mul_0_eq_0(a: u16) {
            assert_eq!(gf16_mul(0, a), 0);
        }

        #[test]
        fn test_mul_1_does_nothing(a: u16) {
            assert_eq!(gf16_mul(1, a), a);
        }

        #[test]
        fn test_scale_associative(a: u16, b: u16, x in any_fe()) {
            assert_eq!(x.scale(gf16_mul(a, b)), x.scale(a).scale(b));
        }

        #[test]
        fn test_scale_distributive(a: u16, b: u16, x in any_fe()) {
            assert_eq!(x.scale(a ^ b), x.scale(a).add(&x.scale(b)));
        }

        #[test]
        fn test_scale_1_does_nothing(x in any_fe()) {
            assert_eq!(x, x.scale(1));
        }

        #[test]
        fn test_scale_0_eq_0(x in any_fe()) {
            assert_eq!(x.scale(0), Gf16x8::zero());
        }

        #[test]
        fn test_rs_linearity(a: u16, x in any_fe()) {
            test_rs_linearity_inner(a, x);
        }

        #[test]
        fn test_checksum_calculation_proptest(
            data in prop::collection::vec(any::<u16>(), 32),
            coeffs in prop::collection::vec(any_fe(), 32),
            min_rows in 1usize..10,
            extra_rows in 1usize..10
        ) {
            test_checksum_calculation(min_rows, extra_rows, &u16s_to_row(&data), &coeffs);
        }
    }
}
