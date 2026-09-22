//! Private, nonidentity G1 joint-codec experiments on the Vroom field backend.
//!
//! Pair and triple formats retain 48 bytes per point but change the wire format.
//! See `cryptography/DECOMPRESSION_RESEARCH.md` for the algebra and exceptional
//! fibers. Public G1 values are returned only after the native subgroup check.

use super::{G1, check, filled, homogeneous};
use crate::bls12381::Fp;
use commonware_cryptography_vroom::{
    Backend, Bls12381, WithBackend,
    rns::{Ring, Standard},
    with_backend,
};
use rand_core::CryptoRng;

mod receive;
mod tests;
mod triple;

type Field = Standard<Bls12381>;

// Canonical 2^((p - 1) / 9); from_raw uses ordinary, not Montgomery, limbs.
const ROOT_NINE: Fp = Fp::from_raw(&[
    0x40ef_8707_1b64_7b54,
    0x7799_e9d9_c455_2a7e,
    0x5b98_f722_777c_7c3c,
    0x3484_83b2_5987_0047,
    0x6d70_2ebe_18e4_6fbe,
    0x0443_9131_30e9_94ba,
])
.expect("canonical ninth root");

#[derive(Clone, Copy)]
struct Affine {
    x: Field,
    y: Field,
}

impl Affine {
    const ZERO: Self = Self {
        x: Field::ZERO,
        y: Field::ZERO,
    };
}

fn field_bytes(value: &Field) -> [u8; 48] {
    Fp::from(*value).to_bytes()
}

fn read_field(bytes: &[u8; 48]) -> Option<Field> {
    Fp::from_bytes(bytes).map(Into::into)
}

fn reserved<T>(len: usize) -> Option<Vec<T>> {
    let mut result = Vec::new();
    result.try_reserve_exact(len).ok()?;
    Some(result)
}

#[derive(Clone, Copy)]
enum RootWidth {
    One,
    Two,
    Four,
    Eight,
}

struct Arithmetic<B: Backend> {
    ring: Ring<Bls12381, B>,
    roots: RootWidth,
}

impl<B: Backend> Arithmetic<B> {
    #[inline(always)]
    fn fp_mul(&self, a: &Field, b: &Field) -> Field {
        self.ring.mul(*a, *b)
    }
    #[inline(always)]
    fn fp_add(&self, a: &Field, b: &Field) -> Field {
        self.ring.add(*a, *b)
    }
    #[inline(always)]
    fn fp_sub(&self, a: &Field, b: &Field) -> Field {
        self.ring.sub(*a, *b)
    }
    #[inline(always)]
    fn fp_neg(&self, a: &Field) -> Field {
        self.ring.standard_negate(*a)
    }
    #[inline(always)]
    fn fp_sqr(&self, a: &Field) -> Field {
        self.fp_mul(a, a)
    }
    #[inline(always)]
    fn fp_is_zero(&self, a: &Field) -> bool {
        bool::from(self.ring.is_zero(*a))
    }
    #[inline(always)]
    fn fp_eq(&self, a: &Field, b: &Field) -> bool {
        Fp::from(*a) == Fp::from(*b)
    }
    #[inline(always)]
    fn cube(&self, a: &Field) -> Field {
        self.fp_mul(&self.fp_sqr(a), a)
    }
    #[inline(always)]
    fn four(&self) -> Field {
        Fp::from_u64(4).into()
    }
    #[inline(always)]
    fn roots(&self, x: Field) -> [Field; 3] {
        let omega = self.cube(&ROOT_NINE.into());
        let second = self.fp_mul(&x, &omega);
        [x, second, self.fp_mul(&second, &omega)]
    }
    #[inline(always)]
    fn valid_affine(&self, point: &Affine) -> bool {
        !self.fp_is_zero(&point.x)
            && !self.fp_is_zero(&point.y)
            && self.fp_eq(
                &self.fp_sqr(&point.y),
                &self.fp_add(&self.cube(&point.x), &self.four()),
            )
    }

    #[inline(always)]
    fn ranked_root(&self, x: Field, rank: usize) -> Field {
        let mut candidates = self.roots(x).map(|x| (field_bytes(&x), x));
        candidates.sort_unstable_by_key(|candidate| candidate.0);
        candidates[rank].1
    }

    #[inline(always)]
    fn valid_points<const N: usize>(&self, points: &[Affine; N]) -> bool {
        let x = points.map(|point| point.x);
        let squared = self.products(&x, &x);
        let ring = &self.ring;
        // Each residual is y^2 - x^3 - 4. Signed wide products share one
        // reduction without ever assuming any curve equation from the input.
        let checks = core::array::from_fn(|i| {
            ring.ready::<800>(
                ring.prep_left(points[i].y) * points[i].y
                    + ring.prep_left(squared[i]) * ring.negate(points[i].x)
                    + ring.prep_left(self.four()) * ring.negate(Field::ONE),
            )
        });
        let residuals: [Field; N] = ring.batch_reduce_expand(&checks);
        points.iter().zip(residuals).all(|(point, residual)| {
            !self.fp_is_zero(&point.x) && !self.fp_is_zero(&point.y) && self.fp_is_zero(&residual)
        })
    }

    #[inline(always)]
    fn products<const N: usize>(&self, a: &[Field; N], b: &[Field; N]) -> [Field; N] {
        let pending =
            core::array::from_fn(|i| self.ring.ready::<800>(self.ring.prep_left(a[i]) * b[i]));
        self.ring.batch_reduce_expand(&pending)
    }

    // Keep independent chains in the same RNS reduction batch and backend entry.
    #[inline(always)]
    fn extract<const N: usize>(&self, inputs: &[Field; N]) -> Option<[Field; N]> {
        if inputs.iter().any(|a| self.fp_is_zero(a)) {
            return None;
        }
        let squares = self.products(inputs, inputs);
        let mut powers = [*inputs; 16];
        for index in 1..powers.len() {
            powers[index] = self.products(&powers[index - 1], &squares);
        }
        let mut roots = powers[(SIXTH_ROOT[0].1 / 2) as usize];
        for &(squares, power) in &SIXTH_ROOT[1..] {
            for _ in 0..squares {
                roots = self.products(&roots, &roots);
            }
            roots = self.products(&roots, &powers[(power / 2) as usize]);
        }
        let ninth = ROOT_NINE.into();
        let correction = self.cube(&self.fp_sqr(&ninth));
        for (root, input) in roots.iter_mut().zip(inputs) {
            let mut sixth = self.cube(&self.fp_sqr(root));
            if !self.fp_eq(&sixth, input) {
                *root = self.fp_mul(root, &ninth);
                sixth = self.fp_mul(&sixth, &correction);
                if !self.fp_eq(&sixth, input) {
                    *root = self.fp_mul(root, &ninth);
                    sixth = self.fp_mul(&sixth, &correction);
                    if !self.fp_eq(&sixth, input) {
                        return None;
                    }
                }
            }
        }
        Some(roots)
    }

    fn root_batch(&self, inputs: &[Field]) -> Option<Vec<Field>> {
        match self.roots {
            RootWidth::One => extract_roots::<1>(inputs),
            RootWidth::Two => extract_roots::<2>(inputs),
            RootWidth::Four => extract_roots::<4>(inputs),
            RootWidth::Eight => extract_roots::<8>(inputs),
        }
    }

    #[inline(always)]
    fn batch_invert(&self, values: &mut [Field], scratch: &mut Vec<Field>) -> Option<()> {
        if values.is_empty() {
            return Some(());
        }
        scratch.clear();
        scratch.try_reserve_exact(values.len()).ok()?;
        let mut product = Field::ONE;
        for value in values.iter() {
            scratch.push(product);
            product = self.fp_mul(&product, value);
        }
        let mut inverse = self.ring.invert(product)?;
        for (value, prefix) in values.iter_mut().zip(scratch).rev() {
            let next = self.fp_mul(&inverse, value);
            *value = self.fp_mul(&inverse, prefix);
            inverse = next;
        }
        Some(())
    }

    #[inline(always)]
    fn encode_standard(&self, point: &Affine) -> [u8; 48] {
        assert!(self.valid_affine(point));
        let mut bytes = field_bytes(&point.x);
        bytes[0] |= 0x80 | (Fp::from(point.y).lexicographically_largest().unwrap_u8() << 5);
        bytes
    }

    #[inline(always)]
    fn decode_standard(&self, bytes: &[u8]) -> Option<Affine> {
        let point = G1::on_curve(bytes.try_into().ok()?)?;
        if self.fp_is_zero(&point.z) {
            return None;
        }
        let point = Affine {
            x: point.x,
            y: point.y,
        };
        self.valid_affine(&point).then_some(point)
    }
    #[inline(always)]
    fn encode_pairs(&self, points: &[Affine]) -> Vec<u8> {
        let affine = points;
        assert!(affine.iter().all(|point| self.valid_affine(point)));
        let mut inverses: Vec<_> = affine
            .chunks_exact(2)
            .flat_map(|pair| [pair[1].x, pair[1].y])
            .collect();
        self.batch_invert(&mut inverses, &mut Vec::new()).unwrap();
        let mut bytes = Vec::with_capacity(48 * points.len());
        for (pair, inverses) in affine.chunks_exact(2).zip(inverses.chunks_exact(2)) {
            let x = self.fp_mul(&pair[0].x, &inverses[0]);
            let y = self.fp_mul(&pair[0].y, &inverses[1]);
            let orbit = self.fp_eq(&self.cube(&x), &self.fp_sqr(&y));
            let (x, y, selector) = if orbit {
                let index = self
                    .roots(pair[0].x)
                    .iter()
                    .position(|x| self.fp_eq(x, &pair[1].x))
                    .unwrap();
                let negative = !self.fp_eq(&pair[0].y, &pair[1].y);
                (pair[0].x, pair[0].y, 2 * index + usize::from(negative))
            } else {
                let mut candidates = self.roots(pair[1].x).map(|x| field_bytes(&x));
                candidates.sort_unstable();
                let index = candidates
                    .iter()
                    .position(|x| *x == field_bytes(&pair[1].x))
                    .unwrap();
                let negative = field_bytes(&pair[1].y) > field_bytes(&self.fp_neg(&pair[1].y));
                (x, y, 2 * index + usize::from(negative))
            };
            let mut x = field_bytes(&x);
            let mut y = field_bytes(&y);
            x[0] |= (selector as u8) << 5;
            y[0] |= u8::from(orbit) << 5;
            bytes.extend(x);
            bytes.extend(y);
        }
        if !points.len().is_multiple_of(2) {
            bytes.extend(self.encode_standard(points.last().unwrap()));
        }
        bytes
    }

    #[inline(always)]
    fn decode_pairs(&self, bytes: &[u8]) -> Option<Vec<Affine>> {
        if !bytes.len().is_multiple_of(48) {
            return None;
        }
        let count = bytes.len() / 96;
        let mut records = reserved(count)?;
        let mut inverses = reserved(count)?;
        for pair in bytes.chunks_exact(96) {
            let mut x: [u8; 48] = pair[..48].try_into().unwrap();
            let mut y: [u8; 48] = pair[48..].try_into().unwrap();
            let (selector, orbit) = (x[0] >> 5, y[0] >> 5);
            if selector >= 6 || orbit >= 2 {
                return None;
            }
            x[0] &= 0x1f;
            y[0] &= 0x1f;
            let (x, y) = (read_field(&x)?, read_field(&y)?);
            let denominator = if orbit == 1 {
                if !self.valid_affine(&Affine { x, y }) {
                    return None;
                }
                Field::ONE
            } else {
                let denominator = self.fp_sub(&self.fp_sqr(&y), &self.cube(&x));
                if self.fp_is_zero(&denominator) {
                    return None;
                }
                denominator
            };
            records.push((x, y, selector, orbit));
            inverses.push(denominator);
        }
        let mut scratch = Vec::new();
        self.batch_invert(&mut inverses, &mut scratch)?;
        let mut radicands = reserved(count)?;
        let mut products = reserved(count)?;
        for (&(_, y, _, orbit), inverse) in records.iter().zip(&inverses) {
            if orbit == 1 {
                continue;
            }
            let u = self.fp_mul(
                &self.fp_mul(&self.four(), &self.fp_sub(&Field::ONE, &self.fp_sqr(&y))),
                inverse,
            );
            let v = self.fp_add(&u, &self.four());
            let uv = self.fp_mul(&u, &v);
            products.push(uv);
            radicands.push(self.fp_mul(&v, &self.fp_sqr(&uv)));
        }
        let extracted = self.root_batch(&radicands)?;
        inverses.clear();
        inverses.extend(
            products
                .iter()
                .zip(&extracted)
                .map(|(uv, r)| self.fp_mul(&self.fp_sqr(r), uv)),
        );
        self.batch_invert(&mut inverses, &mut scratch)?;
        let mut generic = products.iter().zip(&extracted).zip(&inverses);
        let mut decoded = reserved(bytes.len() / 48)?;
        for (x, y, selector, orbit) in records {
            let index = usize::from(selector / 2);
            let negative = selector & 1 != 0;
            let (first, second) = if orbit == 1 {
                (
                    Affine { x, y },
                    Affine {
                        x: self.roots(x)[index],
                        y: if negative { self.fp_neg(&y) } else { y },
                    },
                )
            } else {
                let ((uv, root), inverse) = generic.next().unwrap();
                // root^6 = u^2 v^3; one inverse recovers both affine coordinates.
                let mut base = Affine {
                    x: self.ranked_root(self.fp_mul(&self.fp_sqr(uv), inverse), index),
                    y: self.fp_mul(
                        &self.fp_mul(&self.fp_sqr(&self.fp_sqr(root)), root),
                        inverse,
                    ),
                };
                if bool::from(Fp::from(base.y).lexicographically_largest()) != negative {
                    base.y = self.fp_neg(&base.y);
                }
                (
                    Affine {
                        x: self.fp_mul(&x, &base.x),
                        y: self.fp_mul(&y, &base.y),
                    },
                    base,
                )
            };
            let pair = [first, second];
            if !self.valid_points(&pair) {
                return None;
            }
            decoded.extend(pair);
        }
        let tail = bytes.chunks_exact(96).remainder();
        if !tail.is_empty() {
            decoded.push(self.decode_standard(tail)?);
        }
        Some(decoded)
    }
}

// Share the exponentiation loop across pair/triple charts and RNG types.
// This bulk entry keeps every root operation in the selected feature context.
#[inline(never)]
fn extract_roots<const LANES: usize>(inputs: &[Field]) -> Option<Vec<Field>> {
    with_backend(RootBatch::<LANES>(inputs))
}

struct RootBatch<'a, const LANES: usize>(&'a [Field]);

impl<const LANES: usize> WithBackend for RootBatch<'_, LANES> {
    type Output = Option<Vec<Field>>;

    #[inline(always)]
    fn call<B: Backend>(self, backend: B) -> Self::Output {
        const {
            assert!(LANES > 0);
        }
        let arithmetic = Arithmetic::<B> {
            ring: Ring::new(backend),
            roots: RootWidth::Four,
        };
        let mut output = reserved(self.0.len())?;
        for chunk in self.0.chunks(LANES) {
            let mut lanes = [Field::ONE; LANES];
            lanes[..chunk.len()].copy_from_slice(chunk);
            output.extend_from_slice(&arithmetic.extract(&lanes)?[..chunk.len()]);
        }
        Some(output)
    }
}

#[derive(Clone, Copy, Debug)]
enum Format {
    Standard,
    Pair,
    Triple,
}

struct Receive<'a, R> {
    bytes: &'a [u8],
    format: Format,
    roots: RootWidth,
    rng: &'a mut R,
}

impl<R: CryptoRng> Receive<'_, R> {
    fn run(self) -> Option<Vec<G1>> {
        let points = with_backend(Decode {
            bytes: self.bytes,
            format: self.format,
            roots: self.roots,
        })?;
        validate(points, self.rng)
    }
}

struct Decode<'a> {
    bytes: &'a [u8],
    format: Format,
    roots: RootWidth,
}

impl WithBackend for Decode<'_> {
    type Output = Option<Vec<Affine>>;

    #[inline(always)]
    fn call<B: Backend>(self, backend: B) -> Self::Output {
        let arithmetic = Arithmetic::<B> {
            ring: Ring::new(backend),
            roots: self.roots,
        };
        match self.format {
            Format::Standard => {
                if !self.bytes.len().is_multiple_of(48) {
                    return None;
                }
                let mut result = reserved(self.bytes.len() / 48)?;
                for bytes in self.bytes.chunks_exact(48) {
                    result.push(arithmetic.decode_standard(bytes)?);
                }
                Some(result)
            }
            Format::Pair => arithmetic.decode_pairs(self.bytes),
            Format::Triple => arithmetic.decode_triples(self.bytes),
        }
    }
}

// A separate bulk backend entry shares the checker across root-chain widths.
// Arithmetic still stays inside the selected AVX-512 target-feature context.
#[inline(never)]
fn validate(points: Vec<Affine>, rng: &mut impl CryptoRng) -> Option<Vec<G1>> {
    with_backend(Validate { points, rng })
}

struct Validate<'a, R> {
    points: Vec<Affine>,
    rng: &'a mut R,
}

impl<R: CryptoRng> WithBackend for Validate<'_, R> {
    type Output = Option<Vec<G1>>;

    #[inline(always)]
    fn call<B: Backend>(self, backend: B) -> Self::Output {
        let ring = Ring::<Bls12381, B>::new(backend);
        let mut points = reserved(self.points.len())?;
        for point in self.points {
            points.push(homogeneous::G1Point {
                x: point.x,
                y: point.y,
                z: Field::ONE,
            });
        }
        if !check(
            &points,
            self.rng,
            &ring,
            homogeneous::G1Point::identity(),
            &|point| with_backend(homogeneous::InSubgroup(point)),
        )? {
            return None;
        }
        let mut result = reserved(points.len())?;
        for point in points {
            result.push(G1 {
                x: point.x.into(),
                y: point.y.into(),
                z: point.z.into(),
            });
        }
        Some(result)
    }
}

// Sliding-window schedule for e = (p + 17) / 108: (squarings, odd power).
const SIXTH_ROOT: &[(u8, u8)] = &[
    (4, 15),
    (5, 13),
    (8, 29),
    (2, 3),
    (8, 21),
    (5, 31),
    (2, 3),
    (8, 9),
    (6, 29),
    (5, 27),
    (5, 31),
    (7, 19),
    (5, 25),
    (6, 9),
    (6, 17),
    (5, 23),
    (1, 1),
    (9, 23),
    (4, 15),
    (7, 21),
    (6, 9),
    (11, 27),
    (5, 23),
    (7, 23),
    (8, 15),
    (8, 19),
    (6, 21),
    (7, 13),
    (8, 21),
    (1, 1),
    (9, 7),
    (7, 11),
    (6, 25),
    (8, 29),
    (5, 13),
    (6, 27),
    (5, 9),
    (4, 7),
    (11, 29),
    (11, 29),
    (8, 29),
    (11, 25),
    (5, 15),
    (5, 13),
    (9, 17),
    (5, 13),
    (7, 29),
    (5, 29),
    (3, 5),
    (8, 9),
    (6, 29),
    (1, 1),
    (8, 9),
    (4, 7),
    (6, 7),
    (6, 7),
    (6, 7),
    (6, 7),
    (6, 7),
    (9, 31),
    (3, 5),
];
