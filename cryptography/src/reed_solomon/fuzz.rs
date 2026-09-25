//! Bounded deterministic fuzzing helpers for the vendored Reed-Solomon implementation.

#[cfg(target_arch = "aarch64")]
use super::engine::Neon;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use super::engine::{Avx2, Avx512, Ssse3};
use super::{
    Decoder,
    engine::{
        CANTOR_BASIS, DefaultEngine, Engine, GF_MODULUS, GF_ORDER, GF_POLYNOMIAL, GfElement, Naive,
        NoSimd, SHARD_CHUNK_BYTES, ShardsRefMut,
    },
    rate::{DefaultRate, HighRate, LowRate, Rate, RateDecoder, RateEncoder},
};
use arbitrary::Unstructured;

const SHARD_SIZES: [usize; 6] = [2, 62, 64, 66, 126, 130];

// Instantiate each supported engine, including implementations below the default CPU priority.
macro_rules! each_engine {
    ($runner:ident ( $($arg:expr),* )) => {{
        $runner::<NoSimd>($($arg,)* NoSimd::new);
        $runner::<DefaultEngine>($($arg,)* DefaultEngine::new);
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if std::arch::is_x86_feature_detected!("avx512f")
                && std::arch::is_x86_feature_detected!("avx512vl")
                && std::arch::is_x86_feature_detected!("avx512bw")
                && std::arch::is_x86_feature_detected!("gfni")
            {
                $runner::<Avx512>($($arg,)* Avx512::new);
            }
            if std::arch::is_x86_feature_detected!("avx2") {
                $runner::<Avx2>($($arg,)* Avx2::new);
            }
            if std::arch::is_x86_feature_detected!("ssse3") {
                $runner::<Ssse3>($($arg,)* Ssse3::new);
            }
        }
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("neon") {
            $runner::<Neon>($($arg,)* Neon::new);
        }
    }};
}

/// Bounded engine comparisons against independent field arithmetic and the naive engine.
#[derive(Clone, Copy, Debug, arbitrary::Arbitrary)]
pub enum EnginePlan {
    /// Compare multiplication, including empty and multi-chunk operands.
    Mul,
    /// Compare FFT and IFFT with offsets, truncation, and sentinel shards.
    Transform,
}

impl EnginePlan {
    /// Run the selected check on every engine supported by this host.
    pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        match self {
            Self::Mul => fuzz_mul(u),
            Self::Transform => fuzz_transform(u),
        }
    }
}

fn fuzz_mul(u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
    let log_m = match u.int_in_range(0..=7)? {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => GF_MODULUS / 2,
        4 => GF_MODULUS / 2 + 1,
        5 => GF_MODULUS - 1,
        6 => GF_MODULUS,
        _ => u.arbitrary()?,
    };
    let mul_chunks = match u.int_in_range(0..=5)? {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 3,
        4 => 65,
        _ => u.int_in_range(4..=16)?,
    };
    let mut mul_input = vec![[0; SHARD_CHUNK_BYTES]; mul_chunks];
    let mut input = Input::new(u.bytes(u.len())?);
    fill_chunks(&mut mul_input, &mut input);
    compare_mul(&mul_input, log_m);
    Ok(())
}

fn fuzz_transform(u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
    let size = 1usize << u.int_in_range(0..=6)?;
    let pos = u.int_in_range(0..=5)?;
    let suffix = u.int_in_range(0..=3)?;
    let truncated_size = u.int_in_range(0..=size)?;
    let max_skew = GF_ORDER - size;
    let skew_delta = match u.int_in_range(0..=5)? {
        0 => 0,
        1 => 1.min(max_skew),
        2 => 7.min(max_skew),
        3 => max_skew,
        4 => 17.min(max_skew),
        _ => usize::from(u.arbitrary::<u16>()?) % (max_skew + 1),
    };
    let shard_chunks = match u.int_in_range(0..=5)? {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 17,
        4 => 65,
        _ => u.int_in_range(3..=8)?,
    };
    let shard_count = pos + size + suffix;
    let mut transform_input = vec![[0; SHARD_CHUNK_BYTES]; shard_count * shard_chunks];
    let mut input = Input::new(u.bytes(u.len())?);
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
    Ok(())
}

/// Encoding rate exercised by the shared checks.
#[derive(Clone, Copy, Debug, arbitrary::Arbitrary)]
pub enum RateKind {
    /// More original shards than recovery shards.
    High,
    /// More recovery shards than original shards.
    Low,
    /// Switch between high and low rates when resetting.
    Default,
}

/// Bounded rate comparisons and backend-independent encoding/decoding contracts.
#[derive(Clone, Copy, Debug, arbitrary::Arbitrary)]
pub enum RatePlan {
    /// Compare encoding with the naive engine and decode its recovery shards.
    MatchesPortable(RateKind),
    /// Check roundtrips, automatic reuse, and reset with the same backend.
    Contract(RateKind),
    /// Check the public recovery decoder's reuse and missing recovery shards.
    Recovery,
}

impl RatePlan {
    /// Run rate checks on every supported engine, or exercise the public recovery decoder.
    pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        let small = u.int_in_range(2..=4)?;
        let large = u.int_in_range(9..=12)?;
        let shard_bytes_a = SHARD_SIZES[u.int_in_range(0..=5)?];
        let shard_bytes_b = SHARD_SIZES[u.int_in_range(0..=5)?];

        let (counts_a, counts_b) = match self {
            Self::MatchesPortable(RateKind::High) | Self::Contract(RateKind::High) => {
                ((large, small), (large - 1, small + 1))
            }
            Self::MatchesPortable(RateKind::Low) | Self::Contract(RateKind::Low) => {
                ((small, large), (small + 1, large - 1))
            }
            _ => ((large, small), (small, large)),
        };
        let mut input = Input::new(u.bytes(u.len())?);
        let case_a = RateCase::new(counts_a.0, counts_a.1, shard_bytes_a, &mut input);
        let case_b = RateCase::new(counts_b.0, counts_b.1, shard_bytes_b, &mut input);

        match self {
            Self::MatchesPortable(kind) => {
                each_engine!(rate_matches_portable(kind, &case_a, &case_b))
            }
            Self::Contract(kind) => {
                rate_contract::<Naive>(kind, &case_a, &case_b, Naive::new);
                each_engine!(rate_contract(kind, &case_a, &case_b));
            }
            Self::Recovery => exercise_recovery_reuse(&case_a, &case_b),
        }
        Ok(())
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

    each_engine!(check_mul(input, log_m, &naive));
}

fn check_mul<E: Engine>(
    input: &[[u8; SHARD_CHUNK_BYTES]],
    log_m: GfElement,
    expected: &[[u8; SHARD_CHUNK_BYTES]],
    new_engine: fn() -> E,
) {
    let mut actual = input.to_vec();
    new_engine().mul(&mut actual, log_m);
    assert_eq!(
        actual,
        expected,
        "{} mul differs for log {log_m}",
        core::any::type_name::<E>()
    );
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

        for shard in 0..shard_count {
            if shard < pos || shard >= pos + size {
                let chunks = shard * shard_chunks..(shard + 1) * shard_chunks;
                assert_eq!(
                    expected[chunks.clone()],
                    input[chunks],
                    "Naive changed sentinel shard {shard}"
                );
            }
        }
        each_engine!(check_transform(
            &operation_input,
            input,
            &expected,
            shard_count,
            shard_chunks,
            pos,
            size,
            truncated_size,
            skew_delta,
            inverse
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn check_transform<E: Engine>(
    operation_input: &[[u8; SHARD_CHUNK_BYTES]],
    input: &[[u8; SHARD_CHUNK_BYTES]],
    expected: &[[u8; SHARD_CHUNK_BYTES]],
    shard_count: usize,
    shard_chunks: usize,
    pos: usize,
    size: usize,
    truncated_size: usize,
    skew_delta: usize,
    inverse: bool,
    new_engine: fn() -> E,
) {
    let name = core::any::type_name::<E>();
    let mut actual = operation_input.to_vec();
    apply_transform(
        &new_engine(),
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
                actual[chunks.clone()],
                input[chunks],
                "{name} changed sentinel shard {shard}"
            );
        } else if inverse || shard < pos + truncated_size {
            // FFT specifies a prefix; IFFT specifies the entire block after zeroing its input suffix.
            assert_eq!(
                actual[chunks.clone()],
                expected[chunks],
                "{name} {} differs at shard {shard} for pos={pos} size={size} truncated={truncated_size} skew={skew_delta}",
                if inverse { "ifft" } else { "fft" }
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_transform<E: Engine>(
    engine: &E,
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

fn check_rate_contract<R, E>(case_a: &RateCase, case_b: &RateCase, new_engine: fn() -> E)
where
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
    let recovery_a = encode_with::<R, E>(&mut encoder, case_a);
    encoder
        .reset(
            case_b.original_count,
            case_b.recovery_count,
            case_b.shard_bytes,
        )
        .unwrap();
    let recovery_b = encode_with::<R, E>(&mut encoder, case_b);

    let mut decoder = R::decoder(
        case_a.original_count,
        case_a.recovery_count,
        case_a.shard_bytes,
        new_engine(),
        None,
    )
    .unwrap();
    decode_with::<R, E>(&mut decoder, case_a, &recovery_a, 0);
    decode_with::<R, E>(&mut decoder, case_a, &recovery_a, 1);
    decoder
        .reset(
            case_b.original_count,
            case_b.recovery_count,
            case_b.shard_bytes,
        )
        .unwrap();
    decode_with::<R, E>(&mut decoder, case_b, &recovery_b, 1);
    decode_with::<R, E>(&mut decoder, case_b, &recovery_b, 0);
}

fn decode_reference<R, E>(
    case_a: &RateCase,
    case_b: &RateCase,
    expected_a: &[Vec<u8>],
    expected_b: &[Vec<u8>],
    new_engine: fn() -> E,
) where
    R: Rate<E>,
    E: Engine,
{
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

fn rate_contract<E: Engine>(
    kind: RateKind,
    case_a: &RateCase,
    case_b: &RateCase,
    new_engine: fn() -> E,
) {
    match kind {
        RateKind::High => check_rate_contract::<HighRate<E>, E>(case_a, case_b, new_engine),
        RateKind::Low => check_rate_contract::<LowRate<E>, E>(case_a, case_b, new_engine),
        RateKind::Default => check_rate_contract::<DefaultRate<E>, E>(case_a, case_b, new_engine),
    }
}

fn rate_matches_portable<E: Engine>(
    kind: RateKind,
    case_a: &RateCase,
    case_b: &RateCase,
    new_engine: fn() -> E,
) {
    match kind {
        RateKind::High => {
            compare_rate::<HighRate<E>, HighRate<Naive>, E>(case_a, case_b, new_engine)
        }
        RateKind::Low => compare_rate::<LowRate<E>, LowRate<Naive>, E>(case_a, case_b, new_engine),
        RateKind::Default => {
            compare_rate::<DefaultRate<E>, DefaultRate<Naive>, E>(case_a, case_b, new_engine)
        }
    }
}

fn compare_rate<R, Reference, E>(case_a: &RateCase, case_b: &RateCase, new_engine: fn() -> E)
where
    R: Rate<E>,
    Reference: Rate<Naive>,
    E: Engine,
{
    let expected_a = encode::<Reference, _>(case_a, Naive::new());
    let expected_b = encode::<Reference, _>(case_b, Naive::new());
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
    decode_reference::<R, E>(case_a, case_b, &expected_a, &expected_b, new_engine);
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
    use commonware_invariants::minifuzz;

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

    fn compare_eval_poly<E: Engine>(
        input: &[GfElement; GF_ORDER],
        truncated_size: usize,
        _new_engine: fn() -> E,
    ) {
        let mut expected: Box<[GfElement; GF_ORDER]> =
            input.to_vec().into_boxed_slice().try_into().unwrap();
        Naive::eval_poly(expected.as_mut(), truncated_size);
        let mut actual: Box<[GfElement; GF_ORDER]> =
            input.to_vec().into_boxed_slice().try_into().unwrap();
        E::eval_poly(actual.as_mut(), truncated_size);
        assert_eq!(actual, expected);
    }

    #[test]
    fn minifuzz_mul() {
        minifuzz::Builder::default()
            .with_seed(0)
            .with_search_limit(64)
            .test(|u| EnginePlan::Mul.run(u));
    }

    #[test]
    fn minifuzz_transform() {
        minifuzz::Builder::default()
            .with_seed(0)
            .with_search_limit(64)
            .test(|u| EnginePlan::Transform.run(u));
    }

    #[test]
    fn minifuzz_rate_matches_portable() {
        for kind in [RateKind::High, RateKind::Low, RateKind::Default] {
            minifuzz::Builder::default()
                .with_seed(0)
                .with_search_limit(32)
                .test(|u| RatePlan::MatchesPortable(kind).run(u));
        }
    }

    #[test]
    fn minifuzz_rate_contract() {
        for kind in [RateKind::High, RateKind::Low, RateKind::Default] {
            minifuzz::Builder::default()
                .with_seed(0)
                .with_search_limit(32)
                .test(|u| RatePlan::Contract(kind).run(u));
        }
    }

    #[test]
    fn minifuzz_recovery() {
        minifuzz::Builder::default()
            .with_seed(0)
            .with_search_limit(32)
            .test(|u| RatePlan::Recovery.run(u));
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
            compare_mul(&[], log_m);
            compare_mul(&chunks, log_m);
        }
        let mut multi_vector = vec![[0; SHARD_CHUNK_BYTES]; 65];
        fill_chunks(&mut multi_vector, &mut Input::new(&[3, 0xff, 19, 0x80, 0]));
        compare_mul(&multi_vector, 12_345);
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
            (1, 4, 4, 4, 0),
            (1, 4, 0, 4, 1),
            (1, 4, 4, 0, 1),
            (2, 4, 3, 1, 65),
            (3, 4, 2, 2, 1),
            (2, 4, 4, 4, 65),
            (1, 16, 13, 0, 1),
            (2, 64, 37, 17, 17),
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
    fn maximum_domain_transform_regression() {
        let mut input = vec![[0; SHARD_CHUNK_BYTES]; GF_ORDER];
        fill_chunks(&mut input, &mut Input::new(&[3, 0xff, 19, 0x80, 0]));
        compare_transform(&input, GF_ORDER, 1, 0, GF_ORDER, 1, 0);
    }

    #[test]
    fn optimized_eval_poly_matches_naive() {
        for truncated_size in [0, 1, 257] {
            let mut input: Box<[GfElement; GF_ORDER]> =
                vec![0; GF_ORDER].into_boxed_slice().try_into().unwrap();
            for (index, value) in input.iter_mut().enumerate().take(truncated_size) {
                *value = [0, 1, 2, 0x7fff, 0x8000, 0xfffe, 0xffff][index % 7];
            }
            each_engine!(compare_eval_poly(&input, truncated_size));
        }
    }

    #[test]
    fn rate_engines_match_naive_with_partial_chunks_and_mixed_erasures() {
        let high_a = fixed_case(11, 3, 66, 3);
        let high_b = fixed_case(9, 4, 130, 5);
        each_engine!(rate_matches_portable(RateKind::High, &high_a, &high_b));

        let low_a = fixed_case(3, 11, 126, 7);
        let low_b = fixed_case(4, 9, 62, 11);
        each_engine!(rate_matches_portable(RateKind::Low, &low_a, &low_b));
    }

    #[test]
    fn default_rate_switches_and_recovery_decoder_reuses_work() {
        let high = fixed_case(11, 3, 66, 13);
        let low = fixed_case(3, 11, 130, 17);
        each_engine!(rate_matches_portable(RateKind::Default, &high, &low));
        exercise_recovery_reuse(&high, &low);
    }
}
