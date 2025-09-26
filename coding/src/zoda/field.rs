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
            inner <<= 16;
            inner |= u128::from(u);
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

    fn test_rs_linearity_simple_inner(data: &[[u16; 2]], c: [u16; 2], extra: usize) {
        fn extend(data: &[u16], extra: usize) -> Vec<u16> {
            let mut out = data.to_vec();
            let mut encoder = ReedSolomonEncoder::new(data.len(), extra, 64).unwrap();
            for x in data {
                encoder.add_original_shard(&u16s_to_row(&[*x])).unwrap();
            }
            for chunk in encoder.encode().unwrap().recovery_iter() {
                out.push(row_to_u16s(chunk)[0]);
            }
            out
        }
        let data_a = extend(&data.iter().map(|x| x[0]).collect::<Vec<_>>(), extra);
        let data_b = extend(&data.iter().map(|x| x[1]).collect::<Vec<_>>(), extra);
        let data_c0 = extend(
            &data
                .iter()
                .map(|x| gf16_mul(c[0], x[0]) ^ gf16_mul(c[1], x[1]))
                .collect::<Vec<_>>(),
            extra,
        );
        let data_c1 = data_a
            .iter()
            .zip(data_b.iter())
            .map(|(a, b)| gf16_mul(c[0], *a) ^ gf16_mul(c[1], *b))
            .collect::<Vec<_>>();
        println!("===NEW (extra={})===", extra);
        println!("C:");
        println!("{:016b} {:016b}", c[0], c[1]);
        for (name, slice) in [
            ("Data_A", &data_a),
            ("Data_B", &data_b),
            ("Data_C0", &data_c0),
            ("Data_C1", &data_c1),
        ] {
            println!("{}", name);
            for x in slice {
                print!("{:016b} ", x);
                println!("");
            }
        }
        assert_eq!(data_c0, data_c1);
    }

    fn test_checksum_calculation(
        min_rows: usize,
        extra_rows: usize,
        data: &[u8],
        coeffs: &[Gf16x8],
    ) {
        let chunk_size = (data.len().div_ceil(min_rows) + 63) & !63;
        let data_rows = {
            let mut out = Vec::new();
            let mut encoder = ReedSolomonEncoder::new(min_rows, extra_rows, chunk_size).unwrap();
            for i in 0..min_rows {
                let mut row = vec![0u8; chunk_size];
                let start = (chunk_size * i).min(data.len());
                let end = (start + chunk_size).min(data.len());
                row[..(end - start)].copy_from_slice(&data[start..end]);
                encoder.add_original_shard(&row).unwrap();
                out.push(row);
            }
            let res = encoder.encode().unwrap();
            for row in res.recovery_iter() {
                out.push(row.to_vec());
            }
            out
        };
        println!(
            "\n===NEW ROUND (n={}) (k={}) (chunk_size={})===",
            min_rows, extra_rows, chunk_size
        );
        println!("\nCoeffients:");
        for c in coeffs {
            println!("{:?}", c);
        }
        println!("\nEncoded Data:");
        for row in &data_rows {
            for x in row {
                print!("{:02X} ", x);
            }
            println!("")
        }
        let data_rows_u16 = data_rows
            .iter()
            .map(|row| row_to_u16s(row))
            .collect::<Vec<_>>();
        println!("\nEncoded Data (u16):");
        for row in &data_rows_u16 {
            for x in row {
                print!("{:04X} ", x);
            }
            println!("")
        }
        let checks_a = data_rows_u16
            .iter()
            .map(|row| {
                let mut acc = Gf16x8::zero();
                for (x, c) in row.iter().zip(coeffs.iter()) {
                    acc = acc.add(&c.scale(*x));
                }
                acc
            })
            .collect::<Vec<_>>();

        println!("\nChecks A");
        for c in &checks_a {
            println!("{:?}", c);
        }

        let checks_data = {
            let mut out = Vec::new();
            for row in &data_rows[..min_rows] {
                out.push(u16s_to_row(&row_checksum(coeffs, row).u16s()));
            }
            let mut encoder = ReedSolomonEncoder::new(min_rows, extra_rows, 64).unwrap();
            for x in &out {
                encoder.add_original_shard(x).unwrap();
            }
            let res = encoder.encode().unwrap();
            for chunk in res.recovery_iter() {
                out.push(chunk.to_vec());
            }
            out
        };

        println!("\nChecks B (raw):");
        for row in &checks_data {
            for x in row {
                print!("{:02X} ", x);
            }
            println!("")
        }

        let checks_b = checks_data
            .iter()
            .map(|row| Gf16x8::from_u16s(&row_to_u16s(row)))
            .collect::<Vec<_>>();

        println!("\nChecks B");
        for c in &checks_b {
            println!("{:?}", c);
        }

        assert_eq!(checks_a, checks_b);
    }

    fn test_rs_linearity_inner(a: [u16; 4], b: [Gf16x8; 2]) {
        fn extended_row(rows: &[&[u8]]) -> Vec<u8> {
            let mut encoder = ReedSolomonEncoder::new(rows.len(), 1, rows[0].len()).unwrap();
            for row in rows {
                encoder.add_original_shard(row).unwrap();
            }
            let res = encoder.encode().unwrap();
            res.recovery_iter().next().unwrap().to_vec()
        }
        println!("Original Data:");
        for row in a.chunks(2) {
            for x in row {
                print!("{:02X} ", x);
            }
            println!("")
        }
        println!("Check Coefficients:");
        println!("{:?}", &b);

        let mut a_bytes = vec![u16s_to_row(&a[..2]).to_vec(), u16s_to_row(&a[2..])];
        a_bytes.push(extended_row(&[&a_bytes[0], &a_bytes[1]]));

        println!("Data:");
        for row in &a_bytes {
            for x in row {
                print!("{:02X} ", x);
            }
            println!("");
        }

        let a_u16s = a_bytes
            .iter()
            .map(|row| row_to_u16s(row))
            .collect::<Vec<_>>();
        println!("Data (u16):");
        for row in &a_u16s {
            for x in row {
                print!("{:04X} ", x);
            }
            println!("");
        }

        let checks = a_u16s
            .iter()
            .map(|row| {
                let mut acc = Gf16x8::zero();
                for (x, c) in row.iter().zip(b.iter()) {
                    acc = acc.add(&c.scale(*x));
                }
                acc
            })
            .collect::<Vec<_>>();
        println!("Checks (Gf16x8):");
        for c in &checks {
            println!("{:?}", c);
        }
        let mut checks_data = checks
            .iter()
            .take(2)
            .map(|c| u16s_to_row(&c.u16s()))
            .collect::<Vec<_>>();
        checks_data.push(extended_row(&[&checks_data[0], &checks_data[1]]));
        println!("Checks:");
        for row in &checks_data {
            for x in row {
                print!("{:02X} ", x);
            }
            println!("");
        }
        println!("Checks (u16):");

        for row in &checks_data {
            for x in &row_to_u16s(row) {
                print!("{:04X} ", x);
            }
            println!("");
        }

        let checks2 = checks_data
            .iter()
            .map(|row| Gf16x8::from_u16s(&row_to_u16s(row)))
            .collect::<Vec<_>>();

        assert_eq!(&checks, &checks2);
    }

    #[test]
    fn test_row_conversion_roundtrip() {
        let original_u16s = vec![0x1234, 0x5678, 0x9ABC, 0xDEF0];
        let bytes = u16s_to_row(&original_u16s);
        let recovered_u16s = row_to_u16s(&bytes);

        println!("Original u16s: {:?}", &original_u16s[..4]);
        println!("Recovered u16s: {:?}", &recovered_u16s[..4]);

        assert_eq!(&original_u16s[..4], &recovered_u16s[..4]);
    }

    #[test]
    fn test_short_row_conversion() {
        // Test with 2-byte row (like in the failing test)
        let short_bytes = vec![0x01u8, 0x00u8];
        let u16s = row_to_u16s(&short_bytes);
        println!("Short bytes: {:?}", short_bytes);
        println!("Converted to u16s: {:?}", &u16s[..4]);
        println!("Length: {}", u16s.len());

        let recovered_bytes = u16s_to_row(&u16s);
        println!(
            "Recovered bytes: {:?}",
            &recovered_bytes[..short_bytes.len()]
        );

        assert_eq!(&short_bytes, &recovered_bytes[..short_bytes.len()]);
    }

    #[test]
    fn test_gf16x8_u16s_roundtrip() {
        let original = Gf16x8 {
            inner: 0x123456789ABCDEF0,
        };
        let u16s = original.u16s();
        let recovered = Gf16x8::from_u16s(&u16s);

        println!("Original: {:?}", original);
        println!("U16s: {:?}", u16s);
        println!("Recovered: {:?}", recovered);

        assert_eq!(original, recovered);
    }

    #[test]
    fn test_checksum_via_row_conversion() {
        // Test the exact path used in Checks B
        let checksum = Gf16x8 {
            inner: 0x123456789ABCDEF0,
        };

        // Path 1: Direct access
        let direct = checksum;

        // Path 2: Convert via row format (like Checks B does)
        let as_bytes = u16s_to_row(&checksum.u16s());
        let as_u16s = row_to_u16s(&as_bytes);
        let via_row = Gf16x8::from_u16s(&as_u16s);

        println!("Direct: {:?}", direct);
        println!("Via row: {:?}", via_row);

        assert_eq!(direct, via_row);
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
        fn test_rs_linearity(a: [u16; 4], x0 in any_fe(), x1 in any_fe()) {
            test_rs_linearity_inner(a, [x0, x1]);
        }

        #[test]
        fn test_rs_linearity_simple(data in prop::collection::vec(any::<[u16; 2]>(), 1..=10), c: [u16; 2], extra in 1usize..=10) {
            test_rs_linearity_simple_inner(&data, c, extra);
        }

        #[test]
        fn test_checksum_calculation_proptest(
            data in prop::collection::vec(any::<u8>(), 1..128),
            coeffs in prop::collection::vec(any_fe(), 0..32),
            min_rows in 2usize..=2,
            extra_rows in 1usize..=2
        ) {
            test_checksum_calculation(min_rows, extra_rows, &data, &coeffs);
        }
    }
}
