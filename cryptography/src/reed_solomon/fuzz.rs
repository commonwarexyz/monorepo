//! Bounded deterministic fuzzing helpers for the vendored Reed-Solomon implementation.

#[cfg(target_arch = "aarch64")]
use super::engine::Neon;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use super::engine::{Avx2, Ssse3};
use super::{
    Decoder,
    engine::{
        CANTOR_BASIS, DefaultEngine, Engine, GF_MODULUS, GF_ORDER, GF_POLYNOMIAL, GfElement, Naive,
        NoSimd, SHARD_CHUNK_BYTES, ShardsRefMut,
    },
    rate::{DefaultRate, HighRate, LowRate, Rate, RateDecoder, RateEncoder},
};

const SHARD_SIZES: [usize; 6] = [2, 62, 64, 66, 126, 130];

macro_rules! selected_engine {
    ($selector:expr, $runner:ident, $case_a:expr, $case_b:expr) => {{
        match $selector % 4 {
            0 => $runner::<NoSimd>($case_a, $case_b, NoSimd::new),
            1 => $runner::<DefaultEngine>($case_a, $case_b, DefaultEngine::new),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            2 if std::arch::is_x86_feature_detected!("avx2") => {
                $runner::<Avx2>($case_a, $case_b, Avx2::new)
            }
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            3 if std::arch::is_x86_feature_detected!("ssse3") => {
                $runner::<Ssse3>($case_a, $case_b, Ssse3::new)
            }
            #[cfg(target_arch = "aarch64")]
            2 if std::arch::is_aarch64_feature_detected!("neon") => {
                $runner::<Neon>($case_a, $case_b, Neon::new)
            }
            _ => $runner::<NoSimd>($case_a, $case_b, NoSimd::new),
        }
    }};
}

/// Compares bounded multiplication and FFT/IFFT inputs against the naive engine.
pub fn differential_engine(input: &[u8]) {
    let mut input = Input::new(input);
    let log_m = match input.byte() % 8 {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => GF_MODULUS / 2,
        4 => GF_MODULUS / 2 + 1,
        5 => GF_MODULUS - 1,
        6 => GF_MODULUS,
        _ => input.word(),
    };
    let mul_chunks = usize::from(input.byte() % 4) + 1;
    let mut mul_input = vec![[0; SHARD_CHUNK_BYTES]; mul_chunks];
    fill_chunks(&mut mul_input, &mut input);
    compare_mul(&mul_input, log_m);

    let size = 1usize << (input.byte() % 6);
    let pos = usize::from(input.byte() % 4);
    let suffix = usize::from(input.byte() % 4);
    let truncated_size = usize::from(input.byte()) % (size + 1);
    let max_skew = GF_ORDER - size;
    let skew_delta = match input.byte() % 5 {
        0 => 0,
        1 => 1.min(max_skew),
        2 => 7.min(max_skew),
        3 => max_skew,
        _ => usize::from(input.word()) % (max_skew + 1),
    };
    let shard_chunks = usize::from(input.byte() % 3) + 1;
    let shard_count = pos + size + suffix;
    let mut transform_input = vec![[0; SHARD_CHUNK_BYTES]; shard_count * shard_chunks];
    fill_chunks(&mut transform_input, &mut input);
    compare_transform(
        &transform_input,
        shard_count,
        shard_chunks,
        pos,
        size,
        truncated_size,
        skew_delta,
    );
}

/// Compares bounded high-, low-, or default-rate operations against naive encoding.
///
/// Inputs also select a recovery-decoding sequence that checks automatic reuse after dropping a
/// result, explicit reset across configurations, and reconstruction of missing recovery shards.
pub fn differential_rate(input: &[u8]) {
    let mut input = Input::new(input);
    let operation = input.byte() % 4;
    let engine = input.byte();
    let small = usize::from(input.byte() % 3) + 2;
    let large = usize::from(input.byte() % 4) + 9;
    let shard_bytes_a = SHARD_SIZES[usize::from(input.byte()) % SHARD_SIZES.len()];
    let shard_bytes_b = SHARD_SIZES[usize::from(input.byte()) % SHARD_SIZES.len()];

    let (counts_a, counts_b) = match operation {
        0 => ((large, small), (large - 1, small + 1)),
        1 => ((small, large), (small + 1, large - 1)),
        _ => ((large, small), (small, large)),
    };
    let case_a = RateCase::new(counts_a.0, counts_a.1, shard_bytes_a, &mut input);
    let case_b = RateCase::new(counts_b.0, counts_b.1, shard_bytes_b, &mut input);

    match operation {
        0 => selected_engine!(engine, exercise_high, &case_a, &case_b),
        1 => selected_engine!(engine, exercise_low, &case_a, &case_b),
        2 => selected_engine!(engine, exercise_default, &case_a, &case_b),
        _ => exercise_recovery_reuse(&case_a, &case_b),
    }
}

struct Input<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Input<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    const fn byte(&mut self) -> u8 {
        if self.bytes.is_empty() {
            return 0;
        }
        let byte = self.bytes[self.offset % self.bytes.len()];
        self.offset += 1;
        byte
    }

    const fn word(&mut self) -> u16 {
        u16::from_le_bytes([self.byte(), self.byte()])
    }
}

fn fill_chunks(chunks: &mut [[u8; SHARD_CHUNK_BYTES]], input: &mut Input<'_>) {
    for (chunk_index, chunk) in chunks.iter_mut().enumerate() {
        let (low, high) = chunk.split_at_mut(SHARD_CHUNK_BYTES / 2);
        for lane in 0..SHARD_CHUNK_BYTES / 2 {
            low[lane] = input
                .byte()
                .wrapping_add((chunk_index as u8).wrapping_mul(29))
                .wrapping_add(lane as u8);
            high[lane] = input
                .byte()
                .wrapping_add((chunk_index as u8).wrapping_mul(53))
                .wrapping_sub(lane as u8);
        }
    }
}

fn candidate_engines() -> Vec<(&'static str, Box<dyn Engine>)> {
    let mut engines: Vec<(&'static str, Box<dyn Engine>)> = vec![
        ("NoSimd", Box::new(NoSimd::new())),
        ("DefaultEngine", Box::new(DefaultEngine::new())),
    ];

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if std::arch::is_x86_feature_detected!("avx2") {
            engines.push(("Avx2", Box::new(Avx2::new())));
        }
        if std::arch::is_x86_feature_detected!("ssse3") {
            engines.push(("Ssse3", Box::new(Ssse3::new())));
        }
    }
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("neon") {
        engines.push(("Neon", Box::new(Neon::new())));
    }

    engines
}

fn compare_mul(input: &[[u8; SHARD_CHUNK_BYTES]], log_m: GfElement) {
    let mut expected = input.to_vec();
    for chunk in &mut expected {
        let (low, high) = chunk.split_at_mut(SHARD_CHUNK_BYTES / 2);
        for lane in 0..SHARD_CHUNK_BYTES / 2 {
            let value = GfElement::from(low[lane]) | (GfElement::from(high[lane]) << 8);
            let product = independent_mul(value, log_m);
            low[lane] = product as u8;
            high[lane] = (product >> 8) as u8;
        }
    }

    let mut naive = input.to_vec();
    Naive::new().mul(&mut naive, log_m);
    assert_eq!(naive, expected, "Naive mul differs for log {log_m}");

    for (name, engine) in candidate_engines() {
        let mut actual = input.to_vec();
        engine.mul(&mut actual, log_m);
        assert_eq!(actual, expected, "{name} mul differs for log {log_m}");
    }
}

fn independent_mul(value: GfElement, log_m: GfElement) -> GfElement {
    let mut coefficient = 1;
    let mut alpha = 2;
    let mut exponent = usize::from(log_m) % usize::from(GF_MODULUS);
    while exponent > 0 {
        if exponent & 1 == 1 {
            coefficient = polynomial_mul(coefficient, alpha);
        }
        alpha = polynomial_mul(alpha, alpha);
        exponent >>= 1;
    }
    independent_mul_coefficient(value, coefficient)
}

fn independent_mul_coefficient(value: GfElement, coefficient: GfElement) -> GfElement {
    polynomial_to_cantor(polynomial_mul(cantor_to_polynomial(value), coefficient))
}

fn cantor_to_polynomial(value: GfElement) -> GfElement {
    let mut polynomial = 0;
    for (bit, basis) in CANTOR_BASIS.iter().enumerate() {
        if value & (1 << bit) != 0 {
            polynomial ^= basis;
        }
    }
    polynomial
}

fn polynomial_to_cantor(value: GfElement) -> GfElement {
    static INVERSE: std::sync::OnceLock<[GfElement; 16]> = std::sync::OnceLock::new();
    let inverse = INVERSE.get_or_init(|| {
        let mut values = CANTOR_BASIS;
        let mut coordinates = core::array::from_fn(|index| 1 << index);
        for pivot in 0..16 {
            let row = (pivot..16)
                .find(|row| values[*row] & (1 << pivot) != 0)
                .unwrap();
            values.swap(pivot, row);
            coordinates.swap(pivot, row);
            for row in 0..16 {
                if row != pivot && values[row] & (1 << pivot) != 0 {
                    values[row] ^= values[pivot];
                    coordinates[row] ^= coordinates[pivot];
                }
            }
        }
        debug_assert_eq!(values, core::array::from_fn(|index| 1 << index));
        coordinates
    });

    let mut coordinates = 0;
    for (bit, coordinate) in inverse.iter().enumerate() {
        if value & (1 << bit) != 0 {
            coordinates ^= coordinate;
        }
    }
    coordinates
}

fn polynomial_mul(left: GfElement, right: GfElement) -> GfElement {
    let mut product = 0u32;
    for bit in 0..16 {
        if right & (1 << bit) != 0 {
            product ^= u32::from(left) << bit;
        }
    }
    for bit in (16..=30).rev() {
        if product & (1 << bit) != 0 {
            product ^= (GF_POLYNOMIAL as u32) << (bit - 16);
        }
    }
    product as GfElement
}

fn compare_transform(
    input: &[[u8; SHARD_CHUNK_BYTES]],
    shard_count: usize,
    shard_chunks: usize,
    pos: usize,
    size: usize,
    truncated_size: usize,
    skew_delta: usize,
) {
    assert!(size.is_power_of_two());
    assert!(size <= GF_ORDER);
    assert!(truncated_size <= size);
    assert!(pos.checked_add(size).is_some_and(|end| end <= shard_count));
    assert!(size == 1 || skew_delta <= GF_ORDER - size);

    for inverse in [false, true] {
        let mut operation_input = input.to_vec();
        if inverse {
            for shard in pos + truncated_size..pos + size {
                operation_input[shard * shard_chunks..(shard + 1) * shard_chunks]
                    .fill([0; SHARD_CHUNK_BYTES]);
            }
        }

        let mut expected = operation_input.clone();
        apply_transform(
            &Naive::new(),
            &mut expected,
            shard_count,
            shard_chunks,
            pos,
            size,
            truncated_size,
            skew_delta,
            inverse,
        );

        for (name, engine) in candidate_engines() {
            let mut actual = operation_input.clone();
            apply_transform(
                engine.as_ref(),
                &mut actual,
                shard_count,
                shard_chunks,
                pos,
                size,
                truncated_size,
                skew_delta,
                inverse,
            );
            for shard in 0..shard_count {
                let chunks = shard * shard_chunks..(shard + 1) * shard_chunks;

                if shard < pos || shard >= pos + size {
                    assert_eq!(
                        expected[chunks.clone()],
                        input[chunks.clone()],
                        "Naive {} changed sentinel shard {shard}",
                        if inverse { "ifft" } else { "fft" },
                    );
                    assert_eq!(
                        actual[chunks.clone()],
                        input[chunks],
                        "{name} {} changed sentinel shard {shard}",
                        if inverse { "ifft" } else { "fft" },
                    );
                    continue;
                }

                // FFT prunes outputs after the requested prefix. IFFT instead prunes its input, so
                // a zero input suffix has a defined full-block result.
                if inverse || shard < pos + truncated_size {
                    assert_eq!(
                        actual[chunks.clone()],
                        expected[chunks],
                        "{name} {} differs at shard {shard} for pos={pos} size={size} truncated={truncated_size} skew={skew_delta}",
                        if inverse { "ifft" } else { "fft" },
                    );
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_transform(
    engine: &dyn Engine,
    data: &mut [[u8; SHARD_CHUNK_BYTES]],
    shard_count: usize,
    shard_chunks: usize,
    pos: usize,
    size: usize,
    truncated_size: usize,
    skew_delta: usize,
    inverse: bool,
) {
    let mut shards = ShardsRefMut::new(shard_count, shard_chunks, data);
    if inverse {
        engine.ifft(&mut shards, pos, size, truncated_size, skew_delta);
    } else {
        engine.fft(&mut shards, pos, size, truncated_size, skew_delta);
    }
}

#[derive(Clone)]
struct RateCase {
    original_count: usize,
    recovery_count: usize,
    shard_bytes: usize,
    originals: Vec<Vec<u8>>,
    original_start: usize,
    recovery_start: usize,
}

impl RateCase {
    fn new(
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
        input: &mut Input<'_>,
    ) -> Self {
        let original_start = usize::from(input.byte()) % original_count;
        let recovery_start = usize::from(input.byte()) % recovery_count;
        let mut originals = vec![vec![0; shard_bytes]; original_count];
        for (shard_index, shard) in originals.iter_mut().enumerate() {
            for (byte_index, byte) in shard.iter_mut().enumerate() {
                *byte = input
                    .byte()
                    .wrapping_add((shard_index as u8).wrapping_mul(31))
                    .wrapping_add((byte_index as u8).wrapping_mul(17));
            }
        }
        Self {
            original_count,
            recovery_count,
            shard_bytes,
            originals,
            original_start,
            recovery_start,
        }
    }

    fn missing_count(&self) -> usize {
        self.original_count.min(self.recovery_count - 1).max(1)
    }

    fn missing_originals(&self, start_delta: usize) -> Vec<bool> {
        let mut missing = vec![false; self.original_count];
        for offset in 0..self.missing_count() {
            missing[(self.original_start + start_delta + offset) % self.original_count] = true;
        }
        missing
    }

    fn provided_recoveries(&self, start_delta: usize) -> Vec<bool> {
        let mut provided = vec![false; self.recovery_count];
        for offset in 0..self.missing_count() {
            provided[(self.recovery_start + start_delta + offset) % self.recovery_count] = true;
        }
        provided
    }
}

fn encode<R, E>(case: &RateCase, engine: E) -> Vec<Vec<u8>>
where
    R: Rate<E>,
    E: Engine,
{
    let mut encoder = R::encoder(
        case.original_count,
        case.recovery_count,
        case.shard_bytes,
        engine,
        None,
    )
    .unwrap();
    encode_with::<R, E>(&mut encoder, case)
}

fn encode_with<R, E>(encoder: &mut R::RateEncoder, case: &RateCase) -> Vec<Vec<u8>>
where
    R: Rate<E>,
    E: Engine,
{
    for original in &case.originals {
        encoder.add_original_shard(original).unwrap();
    }
    encoder
        .encode()
        .unwrap()
        .recovery_iter()
        .map(<[u8]>::to_vec)
        .collect()
}

fn decode_with<R, E>(
    decoder: &mut R::RateDecoder,
    case: &RateCase,
    recovery: &[Vec<u8>],
    start_delta: usize,
) where
    R: Rate<E>,
    E: Engine,
{
    let missing = case.missing_originals(start_delta);
    let provided_recovery = case.provided_recoveries(start_delta);
    for (index, original) in case.originals.iter().enumerate() {
        if !missing[index] {
            decoder.add_original_shard(index, original).unwrap();
        }
    }
    for (index, shard) in recovery.iter().enumerate() {
        if provided_recovery[index] {
            decoder.add_recovery_shard(index, shard).unwrap();
        }
    }

    let result = decoder.decode(false).unwrap().unwrap();
    for (index, original) in case.originals.iter().enumerate() {
        if missing[index] {
            assert_eq!(result.original(index), Some(original.as_slice()));
        } else {
            assert_eq!(result.original(index), None);
        }
    }
}

fn exercise_rounds<R, E>(
    case_a: &RateCase,
    case_b: &RateCase,
    expected_a: &[Vec<u8>],
    expected_b: &[Vec<u8>],
    new_engine: fn() -> E,
) where
    R: Rate<E>,
    E: Engine,
{
    let mut encoder = R::encoder(
        case_a.original_count,
        case_a.recovery_count,
        case_a.shard_bytes,
        new_engine(),
        None,
    )
    .unwrap();
    assert_eq!(encode_with::<R, E>(&mut encoder, case_a), expected_a);
    encoder
        .reset(
            case_b.original_count,
            case_b.recovery_count,
            case_b.shard_bytes,
        )
        .unwrap();
    assert_eq!(encode_with::<R, E>(&mut encoder, case_b), expected_b);

    let mut decoder = R::decoder(
        case_a.original_count,
        case_a.recovery_count,
        case_a.shard_bytes,
        new_engine(),
        None,
    )
    .unwrap();
    decode_with::<R, E>(&mut decoder, case_a, expected_a, 0);
    decoder
        .reset(
            case_b.original_count,
            case_b.recovery_count,
            case_b.shard_bytes,
        )
        .unwrap();
    decode_with::<R, E>(&mut decoder, case_b, expected_b, 1);
}

fn exercise_high<E: Engine>(case_a: &RateCase, case_b: &RateCase, new_engine: fn() -> E) {
    let expected_a = encode::<HighRate<Naive>, _>(case_a, Naive::new());
    let expected_b = encode::<HighRate<Naive>, _>(case_b, Naive::new());
    exercise_rounds::<HighRate<E>, E>(case_a, case_b, &expected_a, &expected_b, new_engine);
}

fn exercise_low<E: Engine>(case_a: &RateCase, case_b: &RateCase, new_engine: fn() -> E) {
    let expected_a = encode::<LowRate<Naive>, _>(case_a, Naive::new());
    let expected_b = encode::<LowRate<Naive>, _>(case_b, Naive::new());
    exercise_rounds::<LowRate<E>, E>(case_a, case_b, &expected_a, &expected_b, new_engine);
}

fn exercise_default<E: Engine>(case_a: &RateCase, case_b: &RateCase, new_engine: fn() -> E) {
    let expected_a = encode::<DefaultRate<Naive>, _>(case_a, Naive::new());
    let expected_b = encode::<DefaultRate<Naive>, _>(case_b, Naive::new());
    exercise_rounds::<DefaultRate<E>, E>(case_a, case_b, &expected_a, &expected_b, new_engine);
}

fn recovery_round(
    decoder: &mut Decoder,
    case: &RateCase,
    recovery: &[Vec<u8>],
    start_delta: usize,
) {
    let missing = case.missing_originals(start_delta);
    let provided_recovery = case.provided_recoveries(start_delta);
    for (index, original) in case.originals.iter().enumerate() {
        if !missing[index] {
            decoder.add_original_shard(index, original).unwrap();
        }
    }
    for (index, shard) in recovery.iter().enumerate() {
        if provided_recovery[index] {
            decoder.add_recovery_shard(index, shard).unwrap();
        }
    }

    let result = decoder.decode_with_recovery().unwrap().unwrap();
    for (index, original) in case.originals.iter().enumerate() {
        let expected = missing[index].then_some(original.as_slice());
        assert_eq!(result.original(index), expected);
    }
    for (index, shard) in recovery.iter().enumerate() {
        let expected = (!provided_recovery[index]).then_some(shard.as_slice());
        assert_eq!(result.recovery(index), expected);
    }
}

fn exercise_recovery_reuse(case_a: &RateCase, case_b: &RateCase) {
    let expected_a = encode::<DefaultRate<Naive>, _>(case_a, Naive::new());
    let expected_b = encode::<DefaultRate<Naive>, _>(case_b, Naive::new());
    let mut decoder = Decoder::new(
        case_a.original_count,
        case_a.recovery_count,
        case_a.shard_bytes,
    )
    .unwrap();

    recovery_round(&mut decoder, case_a, &expected_a, 0);
    recovery_round(&mut decoder, case_a, &expected_a, 1);
    decoder
        .reset(
            case_b.original_count,
            case_b.recovery_count,
            case_b.shard_bytes,
        )
        .unwrap();
    recovery_round(&mut decoder, case_b, &expected_b, 0);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_case(
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
        seed: u8,
    ) -> RateCase {
        RateCase::new(
            original_count,
            recovery_count,
            shard_bytes,
            &mut Input::new(&[seed, seed.wrapping_mul(17), seed.wrapping_add(91)]),
        )
    }

    macro_rules! exercise_all_engines {
        ($runner:ident, $case_a:expr, $case_b:expr) => {{
            $runner::<NoSimd>($case_a, $case_b, NoSimd::new);
            $runner::<DefaultEngine>($case_a, $case_b, DefaultEngine::new);
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                if std::arch::is_x86_feature_detected!("avx2") {
                    $runner::<Avx2>($case_a, $case_b, Avx2::new);
                }
                if std::arch::is_x86_feature_detected!("ssse3") {
                    $runner::<Ssse3>($case_a, $case_b, Ssse3::new);
                }
            }
            #[cfg(target_arch = "aarch64")]
            if std::arch::is_aarch64_feature_detected!("neon") {
                $runner::<Neon>($case_a, $case_b, Neon::new);
            }
        }};
    }

    fn compare_eval_poly<E: Engine>(input: &[GfElement; GF_ORDER], truncated_size: usize) {
        let mut expected: Box<[GfElement; GF_ORDER]> =
            input.to_vec().into_boxed_slice().try_into().unwrap();
        Naive::eval_poly(expected.as_mut(), truncated_size);
        let mut actual: Box<[GfElement; GF_ORDER]> =
            input.to_vec().into_boxed_slice().try_into().unwrap();
        E::eval_poly(actual.as_mut(), truncated_size);
        assert_eq!(actual, expected);
    }

    #[test]
    fn engines_match_naive_on_field_and_log_edges() {
        let mut chunks = vec![[0; SHARD_CHUNK_BYTES]; 3];
        for (chunk_index, chunk) in chunks.iter_mut().enumerate() {
            let (low, high) = chunk.split_at_mut(SHARD_CHUNK_BYTES / 2);
            for lane in 0..SHARD_CHUNK_BYTES / 2 {
                let value = match (chunk_index * 32 + lane) % 8 {
                    0 => 0,
                    1 => 1,
                    2 => 0x00ff,
                    3 => 0x0100,
                    4 => 0x7fff,
                    5 => 0x8000,
                    6 => 0xfffe,
                    _ => 0xffff,
                };
                low[lane] = value as u8;
                high[lane] = (value >> 8) as u8;
            }
        }
        for log_m in [0, 1, 2, 0x7fff, 0x8000, 0xfffe, 0xffff] {
            compare_mul(&chunks, log_m);
        }
    }

    #[test]
    fn log_tables_match_independent_field_multiplication() {
        let tables = super::super::engine::tables::get_exp_log();
        let mut coefficient = 1;
        for log_m in 0..=GF_MODULUS {
            if log_m == GF_MODULUS {
                assert_eq!(coefficient, 1, "generator did not close at GF_MODULUS");
            } else if log_m > 0 {
                assert_ne!(coefficient, 1, "generator cycled early at log {log_m}");
            }
            for shift in [0, 4, 8, 12] {
                let bit_products: [GfElement; 4] = core::array::from_fn(|bit| {
                    independent_mul_coefficient(1 << (shift + bit), coefficient)
                });
                for nibble in 0..16 {
                    let value = nibble << shift;
                    let expected = bit_products
                        .iter()
                        .enumerate()
                        .filter(|(bit, _)| nibble & (1 << bit) != 0)
                        .fold(0, |product, (_, bit_product)| product ^ bit_product);
                    assert_eq!(
                        super::super::engine::tables::mul(value, log_m, &tables.exp, &tables.log,),
                        expected,
                        "table mul differs for value={value} log={log_m}",
                    );
                }
            }
            coefficient = polynomial_mul(coefficient, 2);
        }
    }

    #[test]
    fn engines_match_naive_on_offset_truncated_and_skewed_transforms() {
        for (pos, size, truncated_size, skew_delta, shard_chunks) in [
            (0, 1, 0, GF_ORDER - 1, 1),
            (1, 2, 1, 0, 2),
            (2, 4, 1, 3, 2),
            (3, 4, 3, 7, 1),
            (2, 8, 5, 31, 3),
            (5, 16, 16, GF_ORDER - 16, 2),
            (0, GF_ORDER, 1, 0, 1),
        ] {
            let shard_count = pos + size + 2;
            let mut input = vec![[0; SHARD_CHUNK_BYTES]; shard_count * shard_chunks];
            fill_chunks(&mut input, &mut Input::new(&[3, 0xff, 19, 0x80, 0]));
            compare_transform(
                &input,
                shard_count,
                shard_chunks,
                pos,
                size,
                truncated_size,
                skew_delta,
            );
        }
    }

    #[test]
    fn optimized_eval_poly_matches_naive() {
        for truncated_size in [0, 1, 257] {
            let mut input: Box<[GfElement; GF_ORDER]> =
                vec![0; GF_ORDER].into_boxed_slice().try_into().unwrap();
            for (index, value) in input.iter_mut().enumerate().take(truncated_size) {
                *value = [0, 1, 2, 0x7fff, 0x8000, 0xfffe, 0xffff][index % 7];
            }
            compare_eval_poly::<NoSimd>(&input, truncated_size);
            compare_eval_poly::<DefaultEngine>(&input, truncated_size);
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                if std::arch::is_x86_feature_detected!("avx2") {
                    compare_eval_poly::<Avx2>(&input, truncated_size);
                }
                if std::arch::is_x86_feature_detected!("ssse3") {
                    compare_eval_poly::<Ssse3>(&input, truncated_size);
                }
            }
            #[cfg(target_arch = "aarch64")]
            if std::arch::is_aarch64_feature_detected!("neon") {
                compare_eval_poly::<Neon>(&input, truncated_size);
            }
        }
    }

    #[test]
    fn rate_engines_match_naive_with_partial_chunks_and_mixed_erasures() {
        let high_a = fixed_case(11, 3, 66, 3);
        let high_b = fixed_case(9, 4, 130, 5);
        exercise_all_engines!(exercise_high, &high_a, &high_b);

        let low_a = fixed_case(3, 11, 126, 7);
        let low_b = fixed_case(4, 9, 62, 11);
        exercise_all_engines!(exercise_low, &low_a, &low_b);
    }

    #[test]
    fn default_rate_switches_and_recovery_decoder_reuses_work() {
        let high = fixed_case(11, 3, 66, 13);
        let low = fixed_case(3, 11, 130, 17);
        exercise_all_engines!(exercise_default, &high, &low);
        exercise_recovery_reuse(&high, &low);
    }
}
