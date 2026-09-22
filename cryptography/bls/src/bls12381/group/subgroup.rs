//! Private batch membership checks on points of the full curves.
//!
//! Small batches use exact predicates or 81 independent signed-trit rows. Large
//! batches use two signed passes through the degree-47 girth-eight graph. Each
//! side is checked through a fresh degree-19 graph and 63 signed-trit rows.
//! The inner circuit's effective columns certify exact rejection of one or two
//! bad inputs: zero columns and every member of a repeated projective column
//! class are checked individually. Both actual curve cofactors are coprime to
//! 2, 5, and 7, so the remaining two-column minors are units on the cofactor
//! groups. This condition is stronger than odd group order.
//!
//! The inner error is below 3^-61; the joint outer compression bound gives an
//! error below 2^-129.13. Separate sides use fresh randomness. Chunks are ANDed,
//! so a fixed invalid batch has a fixed invalid chunk with that same bound.
//! Raw points and sampled circuits never escape this module's decoding call.

use super::{G1, G2, homogeneous, msm::Point};
use alloc::vec::Vec;
use commonware_cryptography_vroom::{Backend, Bls12381, WithBackend, rns::Ring, with_backend};
use rand_core::CryptoRng;

#[cfg(test)]
pub(crate) mod decompression;

const DIRECT_MAX: usize = 81;
const GRAPH_MIN: usize = 65_536;
const OUTER_Q: u32 = 47;
const INNER_Q: u32 = 19;
const OUTER_EDGES: usize = 4_879_681;
const INNER_ROWS: usize = 63;
const INNER_WIDTH: usize = 7;

pub(super) struct DecodeBatch<'a, R, const N: usize> {
    pub rng: &'a mut R,
    pub bytes: &'a [[u8; N]],
}

macro_rules! decode {
    ($group:ident, $point:ident, $size:literal) => {
        impl<R: CryptoRng> WithBackend for DecodeBatch<'_, R, $size> {
            type Output = Option<Vec<$group>>;

            #[inline(always)]
            fn call<B: Backend>(self, backend: B) -> Self::Output {
                let mut points = Vec::new();
                points.try_reserve_exact(self.bytes.len()).ok()?;
                for bytes in self.bytes {
                    points.push($group::on_curve(bytes)?);
                }

                let ring = Ring::<Bls12381, B>::new(backend);

                // Exact predicates own their backend entry because the callback may be outlined.
                if !check(
                    &points,
                    self.rng,
                    &ring,
                    homogeneous::$point::identity(),
                    &|point| with_backend(homogeneous::InSubgroup(point)),
                )? {
                    return None;
                }

                // Decompression produces only affine points or the canonical identity.
                // Their original coordinates become public only after every check passes.
                let mut result = Vec::new();
                result.try_reserve_exact(points.len()).ok()?;
                for point in points {
                    result.push($group {
                        x: point.x.into(),
                        y: point.y.into(),
                        z: point.z.into(),
                    });
                }
                Some(result)
            }
        }
    };
}

decode!(G1, G1Point, 48);
decode!(G2, G2Point, 96);

fn filled<T: Clone>(len: usize, value: T) -> Option<Vec<T>> {
    let mut result = Vec::new();
    result.try_reserve_exact(len).ok()?;
    result.resize(len, value);
    Some(result)
}

#[inline(always)]
fn check<P: Point<C>, C>(
    points: &[P],
    rng: &mut impl CryptoRng,
    context: &C,
    identity: P,
    exact: &impl Fn(&P) -> bool,
) -> Option<bool> {
    for chunk in points.chunks(OUTER_EDGES) {
        let valid = if chunk.len() <= DIRECT_MAX {
            chunk.iter().all(exact)
        } else if chunk.len() < GRAPH_MIN {
            joint(
                chunk,
                rng,
                context,
                identity,
                exact,
                joint_width(chunk.len()),
                None,
            )?
        } else {
            let buckets =
                Graph::sample(OUTER_Q, chunk.len(), rng)?.scatter(chunk, context, identity)?;
            let (left, right) = buckets.split_at(buckets.len() / 2);
            certified(left, rng, context, identity, exact)?
                && certified(right, rng, context, identity, exact)?
        };
        if !valid {
            return Some(false);
        }
    }
    Some(true)
}

fn joint_width(len: usize) -> usize {
    (1..=9)
        .min_by_key(|&width| 81usize.div_ceil(width) * (len + 3 * 3usize.pow(width as u32)))
        .unwrap()
}

/// Rejection leaves a multiple of the requested range, including both endpoints
/// of every residue class equally often. Bounds are positive graph sizes.
fn uniform_below(rng: &mut impl CryptoRng, bound: u32) -> u32 {
    let bound = u64::from(bound);
    let limit = u64::MAX - u64::MAX % bound;
    loop {
        let value = rng.next_u64();
        if value < limit {
            return (value % bound) as u32;
        }
    }
}

struct Trits<'a, R> {
    rng: &'a mut R,
    word: u32,
    remaining: usize,
}

impl<R: CryptoRng> Trits<'_, R> {
    fn block(&mut self, width: usize) -> u16 {
        if self.remaining < width {
            loop {
                self.word = self.rng.next_u32();
                if self.word < 3u32.pow(20) {
                    break;
                }
            }
            self.remaining = 20;
        }
        let radix = 3u32.pow(width as u32);
        let result = (self.word % radix) as u16;
        self.word /= radix;
        self.remaining -= width;
        result
    }
}

#[inline(always)]
fn accumulate<P: Point<C>, C>(sum: &mut Option<P>, point: P, context: &C) {
    match sum {
        Some(previous) => *previous = previous.add(&point, context),
        None => *sum = Some(point),
    }
}

/// Each bucket represents the complete signed-trit vector of its inputs. The
/// destructive ternary transform recovers each row without changing its digits.
#[inline(always)]
fn joint_block<P: Point<C>, C>(
    points: &[P],
    ids: &[u16],
    width: usize,
    context: &C,
    identity: P,
    mut row: impl FnMut(usize, &P) -> bool,
) -> Option<bool> {
    debug_assert_eq!(points.len(), ids.len());
    let mut buckets = filled(3usize.pow(width as u32), None)?;
    for (point, &id) in points.iter().zip(ids) {
        accumulate(&mut buckets[usize::from(id)], *point, context);
    }

    let mut len = buckets.len();
    for digit in 0..width {
        let mut sum = None;
        for i in 0..len / 3 {
            let [minus, zero, plus] = [buckets[3 * i], buckets[3 * i + 1], buckets[3 * i + 2]];
            if let Some(point) = minus {
                accumulate(&mut sum, point.neg(context), context);
            }
            if let Some(point) = plus {
                accumulate(&mut sum, point, context);
            }
            let mut collapsed = minus;
            if let Some(point) = zero {
                accumulate(&mut collapsed, point, context);
            }
            if let Some(point) = plus {
                accumulate(&mut collapsed, point, context);
            }
            buckets[i] = collapsed;
        }
        if !row(digit, &sum.unwrap_or(identity)) {
            return Some(false);
        }
        len /= 3;
    }
    Some(true)
}

#[inline(always)]
fn joint<P: Point<C>, C>(
    points: &[P],
    rng: &mut impl CryptoRng,
    context: &C,
    identity: P,
    exact: &impl Fn(&P) -> bool,
    width: usize,
    mut columns: Option<&mut [Column]>,
) -> Option<bool> {
    let rows = if columns.is_some() { INNER_ROWS } else { 81 };
    let mut trits = Trits {
        rng,
        word: 0,
        remaining: 0,
    };
    let mut ids = filled(points.len(), 0)?;
    for start in (0..rows).step_by(width) {
        let width = width.min(rows - start);
        for (i, id) in ids.iter_mut().enumerate() {
            *id = trits.block(width);
            if let Some(columns) = columns.as_deref_mut() {
                columns[i].append(*id, start, width);
            }
        }
        if !joint_block(points, &ids, width, context, identity, |_, point| {
            exact(point)
        })? {
            return Some(false);
        }
    }
    Some(true)
}

/// Two disjoint bit planes encode all 63 coefficients in F3. A projective key
/// identifies a column only with its global negation, not per-row sign changes.
#[derive(Clone, Copy, Default)]
struct Column {
    positive: u64,
    negative: u64,
}

impl Column {
    fn append(&mut self, mut id: u16, start: usize, width: usize) {
        for row in start..start + width {
            match id % 3 {
                0 => self.negative |= 1 << row,
                2 => self.positive |= 1 << row,
                _ => {}
            }
            id /= 3;
        }
    }

    const fn signed(self, negative: bool) -> Self {
        if negative {
            Self {
                positive: self.negative,
                negative: self.positive,
            }
        } else {
            self
        }
    }

    const fn add(self, other: Self) -> Self {
        let a_zero = !(self.positive | self.negative);
        let b_zero = !(other.positive | other.negative);
        Self {
            positive: (self.positive & b_zero)
                | (a_zero & other.positive)
                | (self.negative & other.negative),
            negative: (self.negative & b_zero)
                | (a_zero & other.negative)
                | (self.positive & other.positive),
        }
    }

    fn key(self) -> u128 {
        let forward = (u128::from(self.positive) << 64) | u128::from(self.negative);
        let reverse = (u128::from(self.negative) << 64) | u128::from(self.positive);
        forward.min(reverse)
    }
}

/// Edge (u,v,w,t) joins (u,v,w) to (t,ut-v,ut^2-w) over Fq. The
/// low two bits hold independent endpoint signs; the remaining bits identify
/// one edge in a uniformly sampled injection. Preparation is private to a call.
struct Graph {
    q: u32,
    edges: Vec<u32>,
}

impl Graph {
    fn sample(q: u32, len: usize, rng: &mut impl CryptoRng) -> Option<Self> {
        let count = q.checked_pow(4)?;
        if len > count as usize {
            return None;
        }
        let mut edges = Vec::new();
        edges.try_reserve_exact(count as usize).ok()?;
        edges.extend(0..count);
        for i in 0..len {
            let j = i + uniform_below(rng, count - i as u32) as usize;
            edges.swap(i, j);
            edges[i] = (edges[i] << 2) | (rng.next_u32() & 3);
        }
        edges.truncate(len);
        Some(Self { q, edges })
    }

    const fn vertices(&self) -> usize {
        self.q.pow(3) as usize
    }

    const fn endpoints(&self, edge: u32) -> (usize, usize) {
        let q = self.q;
        let edge = edge >> 2;
        let left = edge / q;
        let t = edge % q;
        let u = left / (q * q);
        let v = (left / q) % q;
        let w = left % q;
        let right = (t * q + (u * t + q - v) % q) * q + (u * t * t + q - w) % q;
        (left as usize, right as usize)
    }

    #[inline(always)]
    fn scatter<P: Point<C>, C>(&self, points: &[P], context: &C, identity: P) -> Option<Vec<P>> {
        debug_assert_eq!(points.len(), self.edges.len());
        let side = self.vertices();
        let mut buckets = filled(2 * side, identity)?;
        let mut occupied = filled(2 * side, false)?;
        for (point, &edge) in points.iter().zip(&self.edges) {
            let (left, right) = self.endpoints(edge);
            for (index, negative) in [(left, edge & 1 != 0), (side + right, edge & 2 != 0)] {
                let point = if negative { point.neg(context) } else { *point };
                buckets[index] = if occupied[index] {
                    buckets[index].add(&point, context)
                } else {
                    occupied[index] = true;
                    point
                };
            }
        }
        Some(buckets)
    }

    #[inline(always)]
    fn certify<P>(
        &self,
        points: &[P],
        columns: &[Column],
        exact: &impl Fn(&P) -> bool,
    ) -> Option<bool> {
        let side = self.vertices();
        let mut keys = Vec::new();
        keys.try_reserve_exact(points.len()).ok()?;
        for (i, &edge) in self.edges.iter().enumerate() {
            let (left, right) = self.endpoints(edge);
            let column = columns[left]
                .signed(edge & 1 != 0)
                .add(columns[side + right].signed(edge & 2 != 0));
            keys.push((column.key(), i));
        }
        keys.sort_unstable_by_key(|&(key, _)| key);
        let mut start = 0;
        while start < keys.len() {
            let key = keys[start].0;
            let mut end = start + 1;
            while end < keys.len() && keys[end].0 == key {
                end += 1;
            }
            if key == 0 || end - start > 1 {
                for &(_, index) in &keys[start..end] {
                    if !exact(&points[index]) {
                        return Some(false);
                    }
                }
            }
            start = end;
        }
        Some(true)
    }
}

#[inline(always)]
fn certified<P: Point<C>, C>(
    points: &[P],
    rng: &mut impl CryptoRng,
    context: &C,
    identity: P,
    exact: &impl Fn(&P) -> bool,
) -> Option<bool> {
    let graph = Graph::sample(INNER_Q, points.len(), rng)?;
    let buckets = graph.scatter(points, context, identity)?;
    let mut columns = filled(buckets.len(), Column::default())?;
    if !joint(
        &buckets,
        rng,
        context,
        identity,
        exact,
        INNER_WIDTH,
        Some(&mut columns),
    )? {
        return Some(false);
    }
    graph.certify(points, &columns, exact)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::{Fp, extension::Fp2, scalar::ORDER};
    use alloc::{collections::BTreeSet, vec};
    use commonware_utils::{ScriptedRng, TestRng};
    use num_bigint::BigUint;
    use rand_core::Rng;

    const H1: &str = "76329603384216526031706109802092473003";
    const H2: &str = "305502333931268344200999753193121504214466019254188142667664032982267604182971884026507427359259977847832272839041616661285803823378372096355777062779109";

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Integer(i64);

    impl Point<i64> for Integer {
        fn add(&self, other: &Self, modulus: &i64) -> Self {
            Self((self.0 + other.0).rem_euclid(*modulus))
        }
        fn double(&self, modulus: &i64) -> Self {
            self.add(self, modulus)
        }
        fn neg(&self, modulus: &i64) -> Self {
            Self((-self.0).rem_euclid(*modulus))
        }
    }

    fn coefficient(id: u16, digit: usize) -> i64 {
        i64::from(id / 3u16.pow(digit as u32) % 3) - 1
    }

    #[test]
    fn samplers_preserve_uniform_domains() {
        let limit = 3u32.pow(20);
        let mut rng = ScriptedRng::new([
            u64::from(u32::MAX),
            u64::from(limit),
            u64::from(limit - 1),
            0,
            73,
        ]);
        let mut trits = Trits {
            rng: &mut rng,
            word: 0,
            remaining: 0,
        };
        assert_eq!(trits.block(9), 3u16.pow(9) - 1);
        assert_eq!(trits.block(9), 3u16.pow(9) - 1);
        assert_eq!(trits.block(3), 0);
        assert_eq!(rng.next_u64(), 73);

        for width in 1..=7 {
            let count = 3u32.pow(width);
            for value in 0..count {
                let mut rng = ScriptedRng::new([u64::from(value)]);
                let mut trits = Trits {
                    rng: &mut rng,
                    word: 0,
                    remaining: 0,
                };
                assert_eq!(u32::from(trits.block(width as usize)), value);
            }
        }
        for bound in [1, 19, 47, OUTER_EDGES as u32] {
            let limit = u64::MAX - u64::MAX % u64::from(bound);
            let mut rng = ScriptedRng::new([u64::MAX, limit, u64::from(bound - 1), 73]);
            assert_eq!(uniform_below(&mut rng, bound), bound - 1);
            assert_eq!(rng.next_u64(), 73);
        }

        // Modulo reduction of a random byte gives one trit 86/256 probability.
        let threshold = BigUint::from(1u8) << 128usize;
        assert!(BigUint::from(3u8).pow(81) > threshold);
        assert!(BigUint::from(3u8).pow(80) < threshold);
        assert!(BigUint::from(86u8).pow(81) * threshold > BigUint::from(256u16).pow(81));
    }

    #[test]
    fn joint_rows_match_independent_coefficients() {
        for modulus in [3, 11, 13, 33, 299] {
            for width in 1..=7 {
                let ids: Vec<_> = (0..3u16.pow(width)).collect();
                let points: Vec<_> = ids
                    .iter()
                    .map(|&id| Integer(i64::from(id) % modulus))
                    .collect();
                let mut observed = Vec::new();
                assert_eq!(
                    joint_block(
                        &points,
                        &ids,
                        width as usize,
                        &modulus,
                        Integer(0),
                        |_, point| {
                            observed.push(*point);
                            true
                        }
                    ),
                    Some(true)
                );
                for (digit, point) in observed.iter().enumerate() {
                    let expected: i64 = points
                        .iter()
                        .zip(&ids)
                        .map(|(point, &id)| point.0 * coefficient(id, digit))
                        .sum();
                    assert_eq!(*point, Integer(expected.rem_euclid(modulus)));
                }
            }
        }

        // Every position of every row has a separate nonzero impulse.
        for width in 1..=7 {
            let center = (3u16.pow(width) - 1) / 2;
            for digit in 0..width {
                for sign in [-1i32, 1] {
                    let id = (i32::from(center) + sign * i32::from(3u16.pow(digit))) as u16;
                    assert_eq!(
                        joint_block(
                            &[Integer(1)],
                            &[id],
                            width as usize,
                            &13,
                            Integer(0),
                            |row, point| {
                                let expected = if row == digit as usize {
                                    i64::from(sign).rem_euclid(13)
                                } else {
                                    0
                                };
                                assert_eq!(*point, Integer(expected));
                                true
                            }
                        ),
                        Some(true)
                    );
                }
            }
        }
    }

    #[test]
    fn graph_injection_and_coefficient_certificate() {
        let mut rng = TestRng::new(97);
        let graph = Graph::sample(3, 81, &mut rng).unwrap();
        let edges: BTreeSet<_> = graph.edges.iter().map(|edge| edge >> 2).collect();
        assert_eq!(edges, (0..81).collect());
        let signs: BTreeSet<_> = graph.edges.iter().map(|edge| edge & 3).collect();
        assert_eq!(signs, (0..4).collect());
        assert!(Graph::sample(3, 82, &mut rng).is_none());

        let side = graph.vertices();
        let mut neighbors = vec![BTreeSet::new(); side];
        for &edge in &graph.edges {
            let (left, right) = graph.endpoints(edge);
            assert!(left < side && right < side);
            assert!(neighbors[left].insert(right));
        }
        assert!(neighbors.iter().all(|set| set.len() == 3));
        for a in 0..side {
            for b in 0..a {
                let ab: Vec<_> = neighbors[a].intersection(&neighbors[b]).copied().collect();
                assert!(ab.len() <= 1);
                for c in 0..b {
                    let ac: Vec<_> = neighbors[a].intersection(&neighbors[c]).copied().collect();
                    let bc: Vec<_> = neighbors[b].intersection(&neighbors[c]).copied().collect();
                    if let ([ab], [ac], [bc]) = (&ab[..], &ac[..], &bc[..]) {
                        assert!(ab == ac || ab == bc || ac == bc);
                    }
                }
            }
        }

        let points: Vec<_> = (0..81).map(|i| Integer(i % 299)).collect();
        let buckets = graph.scatter(&points, &299, Integer(0)).unwrap();
        let mut columns = vec![Column::default(); 2 * side];
        let mut trits = Trits {
            rng: &mut rng,
            word: 0,
            remaining: 0,
        };
        for start in (0..63).step_by(7) {
            let ids: Vec<_> = (0..2 * side).map(|_| trits.block(7)).collect();
            for (column, &id) in columns.iter_mut().zip(&ids) {
                column.append(id, start, 7);
            }
            assert_eq!(
                joint_block(&buckets, &ids, 7, &299, Integer(0), |digit, row| {
                    let expected: i64 = points
                        .iter()
                        .zip(&graph.edges)
                        .map(|(point, &edge)| {
                            let (left, right) = graph.endpoints(edge);
                            let alpha = if edge & 1 == 0 { 1 } else { -1 };
                            let beta = if edge & 2 == 0 { 1 } else { -1 };
                            point.0
                                * (alpha * coefficient(ids[left], digit)
                                    + beta * coefficient(ids[side + right], digit))
                        })
                        .sum();
                    assert_eq!(*row, Integer(expected.rem_euclid(299)));
                    true
                }),
                Some(true)
            );
        }
        for &edge in &graph.edges {
            let (left, right) = graph.endpoints(edge);
            let a = columns[left].signed(edge & 1 != 0);
            let b = columns[side + right].signed(edge & 2 != 0);
            let sum = a.add(b);
            assert_eq!(sum.positive & sum.negative, 0);
            for bit in 0..63 {
                let value = |column: Column| {
                    ((column.positive >> bit) & 1) as i32 - ((column.negative >> bit) & 1) as i32
                };
                assert_eq!(
                    value(sum).rem_euclid(3),
                    (value(a) + value(b)).rem_euclid(3)
                );
            }
        }
        let a = Column {
            positive: 3,
            negative: 0,
        };
        let b = Column {
            positive: 1,
            negative: 2,
        };
        assert_ne!(a.key(), b.key());
        assert_eq!(a.key(), a.signed(true).key());
    }

    #[test]
    fn sampled_rows_and_certificate_share_every_coefficient() {
        let mut rng = TestRng::new(71);
        let points: Vec<_> = (0..54).map(Integer).collect();
        let mut columns = vec![Column::default(); points.len()];
        let observed = core::cell::RefCell::new(Vec::new());
        assert_eq!(
            joint(
                &points,
                &mut rng,
                &299,
                Integer(0),
                &|point| {
                    observed.borrow_mut().push(*point);
                    true
                },
                INNER_WIDTH,
                Some(&mut columns),
            ),
            Some(true)
        );
        let observed = observed.into_inner();
        assert_eq!(observed.len(), INNER_ROWS);
        let mut distinct_rows = BTreeSet::new();
        for (row, point) in observed.iter().enumerate() {
            let coefficients: Vec<_> = columns
                .iter()
                .map(|column| {
                    ((column.positive >> row) & 1) as i64 - ((column.negative >> row) & 1) as i64
                })
                .collect();
            let expected: i64 = points
                .iter()
                .zip(&coefficients)
                .map(|(point, coefficient)| point.0 * coefficient)
                .sum();
            assert_eq!(*point, Integer(expected.rem_euclid(299)));
            distinct_rows.insert(coefficients);
        }
        assert_eq!(distinct_rows.len(), INNER_ROWS);

        let graph = Graph {
            q: 3,
            edges: vec![0, 4, 8],
        };
        let columns = vec![
            Column {
                positive: (1 << INNER_ROWS) - 1,
                negative: 0
            };
            54
        ];
        let visited = core::cell::RefCell::new(BTreeSet::new());
        assert_eq!(
            graph.certify(&[0, 1, 2], &columns, &|index| {
                visited.borrow_mut().insert(*index);
                true
            }),
            Some(true)
        );
        assert_eq!(visited.into_inner(), [0, 1, 2].into_iter().collect());
    }

    #[test]
    fn production_graph_sizes_and_chunk_paths() {
        let mut rng = TestRng::new(42);
        for q in [INNER_Q, OUTER_Q] {
            let graph = Graph::sample(q, 129, &mut rng).unwrap();
            assert_eq!(graph.vertices(), q.pow(3) as usize);
            assert!(graph.edges.iter().all(|&edge| {
                let (left, right) = graph.endpoints(edge);
                left < graph.vertices() && right < graph.vertices()
            }));
        }
        let points = vec![Integer(0); GRAPH_MIN];
        assert_eq!(
            check(&points, &mut rng, &33, Integer(0), &|point| point.0 == 0),
            Some(true)
        );
        let mut points = points;
        points[GRAPH_MIN - 1] = Integer(1);
        assert_eq!(
            check(&points, &mut rng, &33, Integer(0), &|point| point.0 == 0),
            Some(false)
        );
        assert!(filled::<[u8; 16]>(usize::MAX, [0; 16]).is_none());
    }

    #[test]
    fn actual_cofactors_support_the_certificate() {
        for h in [H1, H2] {
            let h = h.parse::<BigUint>().unwrap();
            for a in -2i32..=2 {
                for b in -2i32..=2 {
                    for c in -2i32..=2 {
                        for d in -2i32..=2 {
                            let determinant = a * d - b * c;
                            if determinant % 3 == 0 {
                                continue;
                            }
                            let mut u = h.clone();
                            let mut v = BigUint::from(determinant.unsigned_abs());
                            while v != BigUint::from(0u8) {
                                (u, v) = (v.clone(), u % v);
                            }
                            assert_eq!(u, BigUint::from(1u8));
                        }
                    }
                }
            }
        }
        assert_eq!(H1.parse::<BigUint>().unwrap() % 3u8, BigUint::from(0u8));
        assert_ne!(H2.parse::<BigUint>().unwrap() % 3u8, BigUint::from(0u8));
        // Odd order alone is insufficient: this independent pair vanishes modulo 5.
        let matrix = [[2i32, 1], [1, -2]];
        let torsion = [1, 3];
        for row in matrix {
            assert_eq!(
                row.iter()
                    .zip(torsion)
                    .map(|(a, b)| a * b)
                    .sum::<i32>()
                    .rem_euclid(5),
                0
            );
        }
        assert_ne!(
            (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]).rem_euclid(3),
            0
        );
    }

    macro_rules! native_tests {
        ($module:ident, $group:ident, $point:ident, $field:ty, $b:expr, $h:ident, $blst:ty) => {
            mod $module {
                use super::*;

                struct Batch<'a> {
                    points: &'a [homogeneous::$point],
                    rng: &'a mut TestRng,
                }

                impl WithBackend for Batch<'_> {
                    type Output = bool;

                    #[inline(always)]
                    fn call<B: Backend>(self, backend: B) -> bool {
                        check(
                            self.points,
                            self.rng,
                            &Ring::<Bls12381, B>::new(backend),
                            homogeneous::$point::identity(),
                            &|point| with_backend(homogeneous::InSubgroup(point)),
                        )
                        .unwrap()
                    }
                }

                struct Individual<'a>(&'a [homogeneous::$point]);

                impl WithBackend for Individual<'_> {
                    type Output = bool;

                    #[inline(always)]
                    fn call<B: Backend>(self, backend: B) -> bool {
                        for point in self.0 {
                            if !homogeneous::InSubgroup(point).call(backend) {
                                return false;
                            }
                        }
                        true
                    }
                }

                fn torsion() -> $group {
                    let point = (0..32)
                        .find_map(|value| {
                            let x = <$field>::from_u64(value);
                            let y = x.square().mul(x).add($b).sqrt()?;
                            let point = $group::from_affine(x, y).mul_words_jacobian(&ORDER);
                            (!point.is_identity()).then_some(point)
                        })
                        .unwrap();
                    let h = $h.parse::<BigUint>().unwrap().to_u64_digits();
                    assert!(point.mul_words_jacobian(&h).is_identity());
                    assert!($group::from_bytes(&point.to_bytes()).is_none());
                    point
                }

                #[test]
                fn batch_decode_preserves_exact_order_and_domain() {
                    let generator = $group::generator();
                    let corpus = [generator, $group::IDENTITY, generator.neg(), generator];
                    let mut rng = TestRng::new(97);
                    for count in [0, 1, 3, DIRECT_MAX, DIRECT_MAX + 1, 97] {
                        let points: Vec<_> = (0..count).map(|i| corpus[i % corpus.len()]).collect();
                        let bytes: Vec<_> = points.iter().map(|point| point.to_bytes()).collect();
                        assert_eq!($group::batch_from_bytes(&mut rng, &bytes), Some(points));
                    }

                    let bad = torsion();
                    let mixed = generator.add_jacobian(&bad);
                    for point in [bad, bad.neg(), mixed, mixed.neg()] {
                        for count in [1, DIRECT_MAX + 1] {
                            let mut bytes = vec![generator.to_bytes(); count];
                            bytes[count - 1] = point.to_bytes();
                            assert_eq!($group::batch_from_bytes(&mut rng, &bytes), None);
                        }
                    }
                }

                #[test]
                fn decoding_finishes_before_randomness_and_failure_never_publishes() {
                    let bytes = $group::generator().to_bytes();
                    let mut batch = vec![bytes; DIRECT_MAX + 1];
                    let last = batch.last_mut().unwrap();
                    last[0] &= 0x7f;
                    assert!($group::batch_from_bytes(&mut ScriptedRng::new([]), &batch).is_none());
                    *batch.last_mut().unwrap() = bytes;
                    let failure = std::panic::catch_unwind(|| {
                        $group::batch_from_bytes(&mut ScriptedRng::new([]), &batch)
                    });
                    assert!(failure.is_err());
                }

                #[test]
                fn native_rows_and_sparse_certificate_are_causal() {
                    struct Run;
                    impl WithBackend for Run {
                        type Output = ();
                        #[inline(always)]
                        fn call<B: Backend>(self, backend: B) {
                            let ring = Ring::<Bls12381, B>::new(backend);
                            let identity = homogeneous::$point::identity();
                            let t = torsion();
                            let g = $group::generator();
                            let points = [g, t, t.neg(), g.add_jacobian(&t), $group::IDENTITY];
                            let raw: Vec<_> = points
                                .iter()
                                .map(|point| homogeneous::$point::from_jacobian(point, &ring))
                                .collect();
                            let ids = [0, 1, 5, 17, 26];
                            assert_eq!(
                                joint_block(&raw, &ids, 3, &ring, identity, |digit, row| {
                                    let expected = points.iter().zip(ids).fold(
                                        $group::IDENTITY,
                                        |sum, (point, id)| match coefficient(id, digit) {
                                            -1 => sum.add_jacobian(&point.neg()),
                                            0 => sum,
                                            1 => sum.add_jacobian(point),
                                            _ => unreachable!(),
                                        },
                                    );
                                    assert_eq!(row.to_jacobian(&ring), expected);
                                    true
                                }),
                                Some(true)
                            );

                            let graph = Graph {
                                q: 3,
                                edges: vec![0, 4, 8],
                            };
                            let points = &raw[..3];
                            let buckets = graph.scatter(points, &ring, identity).unwrap();
                            let ids = vec![0; buckets.len()];
                            let mut columns = vec![Column::default(); buckets.len()];
                            for start in (0..INNER_ROWS).step_by(INNER_WIDTH) {
                                for column in &mut columns {
                                    column.append(0, start, INNER_WIDTH);
                                }
                                assert_eq!(
                                    joint_block(
                                        &buckets,
                                        &ids,
                                        INNER_WIDTH,
                                        &ring,
                                        identity,
                                        |_, point| { homogeneous::InSubgroup(point).call(backend) }
                                    ),
                                    Some(true)
                                );
                            }
                            // A good first representative cannot stand for its two cancelling bad peers.
                            assert!(homogeneous::InSubgroup(&points[0]).call(backend));
                            assert_eq!(
                                graph.certify(points, &columns, &|point| {
                                    homogeneous::InSubgroup(point).call(backend)
                                }),
                                Some(false)
                            );

                            let graph = Graph {
                                q: 3,
                                edges: vec![0],
                            };
                            let points = &raw[1..2];
                            let buckets = graph.scatter(points, &ring, identity).unwrap();
                            let side = graph.vertices();
                            let mut columns = vec![Column::default(); 2 * side];
                            let mut ids = vec![3u16.pow(INNER_WIDTH as u32) - 1; 2 * side];
                            ids[side..].fill(0);
                            for start in (0..INNER_ROWS).step_by(INNER_WIDTH) {
                                for (column, &id) in columns.iter_mut().zip(&ids) {
                                    column.append(id, start, INNER_WIDTH);
                                }
                                assert_eq!(
                                    joint_block(
                                        &buckets,
                                        &ids,
                                        INNER_WIDTH,
                                        &ring,
                                        identity,
                                        |_, point| { homogeneous::InSubgroup(point).call(backend) }
                                    ),
                                    Some(true)
                                );
                            }
                            assert_eq!(
                                graph.certify(points, &columns, &|point| {
                                    homogeneous::InSubgroup(point).call(backend)
                                }),
                                Some(false)
                            );
                        }
                    }
                    with_backend(Run);
                }

                #[test]
                fn raw_membership_baselines_match() {
                    let generator = $group::generator();
                    let bad = torsion();
                    for point in [
                        generator,
                        $group::IDENTITY,
                        generator.neg(),
                        bad,
                        bad.neg(),
                        generator.add_jacobian(&bad),
                    ] {
                        let bytes = point.to_bytes();
                        let native = $group::on_curve(&bytes).unwrap();
                        let expected = $group::from_bytes(&bytes).is_some();
                        assert_eq!(with_backend(homogeneous::InSubgroup(&native)), expected);
                        let points = [$group::on_curve(&generator.to_bytes()).unwrap(), native];
                        assert_eq!(with_backend(Individual(&points)), expected);
                        assert_eq!(
                            with_backend(Batch {
                                points: &points,
                                rng: &mut TestRng::new(97),
                            }),
                            expected
                        );

                        // The blst G1 decoder rejects x=0 before its subgroup predicate.
                        match <$blst>::from_bytes(&bytes) {
                            Ok(reference) => {
                                assert_eq!(reference.to_bytes(), bytes);
                                assert_eq!(reference.subgroup_check(), expected);
                            }
                            Err(error) => {
                                assert!(!expected);
                                assert_eq!(error, blst::BLST_ERROR::BLST_POINT_NOT_IN_GROUP);
                            }
                        }
                    }
                }

                #[test]
                #[ignore = "opt-in full q47/q19 native subgroup gate"]
                fn full_graph_accepts_members_and_rejects_late_torsion() {
                    struct Run;
                    impl WithBackend for Run {
                        type Output = ();

                        #[inline(always)]
                        fn call<B: Backend>(self, backend: B) {
                            let count = 100_000;
                            assert!((GRAPH_MIN..=OUTER_EDGES).contains(&count));
                            let generator = $group::generator();
                            let corpus = [generator, $group::IDENTITY, generator.neg(), generator]
                                .map(|point| $group::on_curve(&point.to_bytes()).unwrap());
                            let mut points: Vec<_> =
                                (0..count).map(|i| corpus[i % corpus.len()]).collect();
                            let ring = Ring::<Bls12381, B>::new(backend);
                            let exact = |point: &homogeneous::$point| {
                                homogeneous::InSubgroup(point).call(backend)
                            };
                            let identity = homogeneous::$point::identity();
                            assert_eq!(
                                check(&points, &mut TestRng::new(97), &ring, identity, &exact),
                                Some(true)
                            );

                            let bad = torsion();
                            for point in [bad, generator.add_jacobian(&bad)] {
                                let point = $group::on_curve(&point.to_bytes()).unwrap();
                                assert!(!exact(&point));
                                *points.last_mut().unwrap() = point;
                                assert_eq!(
                                    check(&points, &mut TestRng::new(98), &ring, identity, &exact),
                                    Some(false)
                                );
                            }
                        }
                    }
                    with_backend(Run);
                }

                #[test]
                #[ignore = "opt-in complete output gate; set COMMONWARE_SUBGROUP_POINTS"]
                fn full_batch_decode_preserves_every_output() {
                    let count = std::env::var("COMMONWARE_SUBGROUP_POINTS")
                        .unwrap_or_else(|_| "100000".into())
                        .parse::<usize>()
                        .unwrap();
                    assert!([100_000, 1_000_000].contains(&count));
                    let generator = $group::generator();
                    let mut corpus = vec![
                        $group::IDENTITY.to_bytes(),
                        generator.to_bytes(),
                        generator.neg().to_bytes(),
                        generator.to_bytes(),
                    ];
                    let mut point = generator.add(&generator);
                    while corpus.len() < 1024 {
                        corpus.push(point.to_bytes());
                        point = point.add(&generator);
                    }
                    for bytes in &corpus {
                        assert_eq!($group::from_bytes(bytes).unwrap().to_bytes(), *bytes);
                        let reference = <$blst>::from_bytes(bytes).unwrap();
                        assert!(reference.subgroup_check());
                        assert_eq!(reference.to_bytes(), *bytes);
                    }

                    let encoded: Vec<_> = (0..count).map(|i| corpus[i % corpus.len()]).collect();
                    let decoded =
                        $group::batch_from_bytes(&mut TestRng::new(97), &encoded).unwrap();
                    assert_eq!(decoded.len(), encoded.len());
                    for (index, (point, bytes)) in decoded.iter().zip(&encoded).enumerate() {
                        assert_eq!(point.to_bytes(), *bytes, "output mismatch at {index}");
                    }
                }

                #[test]
                #[ignore = "opt-in subgroup-only benchmark; set COMMONWARE_SUBGROUP_POINTS"]
                fn subgroup_work_benchmark() {
                    let count = std::env::var("COMMONWARE_SUBGROUP_POINTS")
                        .unwrap_or_else(|_| "4096".into())
                        .parse::<usize>()
                        .unwrap();
                    assert!([1, 8, 64, 512, 4096, 100_000, 1_000_000].contains(&count));
                    let distinct = match std::env::var("COMMONWARE_SUBGROUP_DISTINCT") {
                        Err(std::env::VarError::NotPresent) => count.min(1024),
                        Ok(value) if value == "1" => count,
                        _ => panic!("COMMONWARE_SUBGROUP_DISTINCT must be unset or 1"),
                    };
                    let generator = $group::generator();
                    let mut point = generator;
                    let mut corpus = Vec::with_capacity(distinct);
                    let mut blst_corpus = Vec::with_capacity(distinct);
                    for _ in 0..distinct {
                        let bytes = point.to_bytes();
                        corpus.push($group::on_curve(&bytes).unwrap());
                        blst_corpus.push(<$blst>::from_bytes(&bytes).unwrap());
                        point = point.add(&generator);
                    }
                    let (points, blst_points) = if distinct == count {
                        (corpus, blst_corpus)
                    } else {
                        (
                            (0..count).map(|i| corpus[i % distinct]).collect(),
                            (0..count).map(|i| blst_corpus[i % distinct]).collect(),
                        )
                    };
                    let mut c = criterion::Criterion::default().sample_size(10);
                    let mut rng = TestRng::new(97);

                    // Each timed operation owns its backend entry because Criterion outlines callbacks.
                    c.bench_function(
                        &std::format!(
                            "{}::membership/points={count} corpus={distinct} impl=batch",
                            module_path!()
                        ),
                        |b| {
                            b.iter(|| {
                                assert!(with_backend(Batch {
                                    points: std::hint::black_box(&points),
                                    rng: std::hint::black_box(&mut rng),
                                }))
                            })
                        },
                    );
                    c.bench_function(
                        &std::format!(
                            "{}::membership/points={count} corpus={distinct} impl=individual",
                            module_path!()
                        ),
                        |b| {
                            b.iter(|| {
                                assert!(with_backend(Individual(std::hint::black_box(&points))))
                            })
                        },
                    );
                    c.bench_function(
                        &std::format!(
                            "{}::membership/points={count} corpus={distinct} impl=blst_individual",
                            module_path!()
                        ),
                        |b| {
                            b.iter(|| {
                                assert!(
                                    std::hint::black_box(&blst_points)
                                        .iter()
                                        .all(<$blst>::subgroup_check)
                                )
                            })
                        },
                    );
                    c.final_summary();
                }
            }
        };
    }

    native_tests!(
        g1,
        G1,
        G1Point,
        Fp,
        Fp::from_u64(4),
        H1,
        blst::min_sig::Signature
    );
    native_tests!(
        g2,
        G2,
        G2Point,
        Fp2,
        Fp2::from_u64(4).add(Fp2 {
            c0: Fp::ZERO,
            c1: Fp::from_u64(4)
        }),
        H2,
        blst::min_pk::Signature
    );
}
