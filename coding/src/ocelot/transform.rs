//! Additive transforms shared by encoding and decoding.

use super::code::Impl;
use commonware_math::algebra::{Field, Ring};
use std::sync::{Arc, OnceLock};

const WORK_ALIGN: usize = 64;
const LOCATOR_FWT_MAX_BITS: usize = 16;
const LOCATOR_FWT_THRESHOLD: usize = 4;

/// A fixed number of equally sized shards, in one aligned allocation.
///
/// Each `len`-byte region uses the same byte layout as an external shard.
/// Full stripes keep every shard aligned for native vector loads and stores.
pub struct Shards {
    storage: Vec<u8>,
    offset: usize,
    count: usize,
    size: usize,
    len: usize,
}

impl Shards {
    pub fn new(count: usize, len: usize) -> Self {
        let size = count.checked_mul(len).expect("workspace size overflow");
        let allocated = size
            .checked_add(WORK_ALIGN - 1)
            .expect("workspace size overflow");
        let storage = vec![0; allocated];
        let offset = storage.as_ptr().align_offset(WORK_ALIGN);
        Self {
            storage,
            offset,
            count,
            size,
            len,
        }
    }

    /// Reuse this allocation for a new shard count and maximum width.
    pub fn reset(&mut self, count: usize, len: usize) {
        let size = count.checked_mul(len).expect("workspace size overflow");
        let allocated = size
            .checked_add(WORK_ALIGN - 1)
            .expect("workspace size overflow");
        if self.storage.len() < allocated {
            self.storage.resize(allocated, 0);
            self.offset = self.storage.as_ptr().align_offset(WORK_ALIGN);
        }
        self.count = count;
        self.size = size;
        self.len = len;
    }

    /// Set the shard width within the original allocation. Contents are scratch space.
    pub fn resize(&mut self, len: usize) {
        let size = self
            .count
            .checked_mul(len)
            .expect("workspace size overflow");
        assert!(
            size <= self.storage.len() - (WORK_ALIGN - 1),
            "workspace capacity exceeded"
        );
        self.size = size;
        self.len = len;
    }

    pub fn data(&self) -> &[u8] {
        &self.storage[self.offset..self.offset + self.size]
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.storage[self.offset..self.offset + self.size]
    }

    pub fn shards(&self) -> impl Iterator<Item = &[u8]> {
        self.data().chunks_exact(self.len)
    }

    pub fn shards_mut(&mut self) -> impl Iterator<Item = &mut [u8]> {
        let len = self.len;
        self.data_mut().chunks_exact_mut(len)
    }

    /// Split shards `[r, r + 2 * dist)` into two halves of `dist` shards each.
    pub fn halves_mut(
        &mut self,
        r: usize,
        dist: usize,
    ) -> impl Iterator<Item = (&mut [u8], &mut [u8])> {
        let len = self.len;
        let (lo, hi) = self.data_mut()[r * len..(r + 2 * dist) * len].split_at_mut(dist * len);
        lo.chunks_exact_mut(len).zip(hi.chunks_exact_mut(len))
    }

    /// Split shards `[r, r + 4 * dist)` into four equal contiguous quarters.
    fn quarters_mut(&mut self, r: usize, dist: usize) -> [&mut [u8]; 4] {
        let len = self.len;
        let quarter = dist * len;
        let data = &mut self.data_mut()[r * len..(r + 4 * dist) * len];
        let (q0, rest) = data.split_at_mut(quarter);
        let (q1, rest) = rest.split_at_mut(quarter);
        let (q2, q3) = rest.split_at_mut(quarter);
        [q0, q1, q2, q3]
    }
}

struct DyadicBlocks<'a> {
    erased: &'a [usize],
    next_run: usize,
    base: usize,
    limit: usize,
}

impl<'a> DyadicBlocks<'a> {
    const fn new(erased: &'a [usize]) -> Self {
        Self {
            erased,
            next_run: 0,
            base: 0,
            limit: 0,
        }
    }
}

impl Iterator for DyadicBlocks<'_> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        if self.base == self.limit {
            if self.next_run == self.erased.len() {
                return None;
            }

            self.base = self.erased[self.next_run];
            self.next_run += 1;
            while self.next_run < self.erased.len()
                && self.erased[self.next_run] == self.erased[self.next_run - 1] + 1
            {
                self.next_run += 1;
            }
            self.limit = self.erased[self.next_run - 1] + 1;
        }

        let remaining = self.limit - self.base;
        let by_length = 1usize << remaining.ilog2();
        let by_alignment = if self.base == 0 {
            by_length
        } else {
            1usize << self.base.trailing_zeros()
        };
        let block_len = by_length.min(by_alignment);
        let block = (self.base, block_len);
        self.base += block_len;
        Some(block)
    }
}

/// Multiplicative logs and normalized Walsh kernels for locator convolution.
struct LocatorTables<E> {
    log: Box<[u32]>,
    exp: Box<[E]>,
    kernels: Box<[OnceLock<Box<[u32]>>]>,
}

impl<E: Field + Copy + 'static> LocatorTables<E> {
    fn new<I: Impl<Element = E>>(points: &[E]) -> Option<Self> {
        if !(2..=LOCATOR_FWT_MAX_BITS).contains(&I::BITS)
            || I::ORDER != 1usize << I::BITS
            || points.len() != I::ORDER
            || points[0] != E::zero()
            || points[1] != E::one()
        {
            return None;
        }

        let modulus = (I::ORDER - 1) as u32;
        let mut factors = Vec::new();
        let mut remainder = modulus;
        let mut factor = 2;
        while u64::from(factor) * u64::from(factor) <= u64::from(remainder) {
            if remainder.is_multiple_of(factor) {
                factors.push(factor);
                while remainder.is_multiple_of(factor) {
                    remainder /= factor;
                }
            }
            factor += 1;
        }
        if remainder > 1 {
            factors.push(remainder);
        }

        // A candidate generates the nonzero field elements exactly when its
        // order has every prime-power factor present in ORDER - 1.
        let one = E::one();
        let generator = points.iter().copied().skip(1).find(|candidate| {
            candidate.exp(&[u64::from(modulus)]) == one
                && factors
                    .iter()
                    .all(|factor| candidate.exp(&[u64::from(modulus / factor)]) != one)
        })?;

        // Multiplication by the generator is GF(2)-linear. Locate its action
        // on each Cantor basis vector to obtain its binary matrix columns.
        let mut columns = Vec::with_capacity(I::BITS);
        for bit in 0..I::BITS {
            let product = generator * &points[1 << bit];
            columns.push(points.iter().position(|&point| point == product)?);
        }

        let mut multiply = vec![0; I::ORDER];
        for coordinate in 1..I::ORDER {
            let bit = coordinate.trailing_zeros() as usize;
            multiply[coordinate] = multiply[coordinate ^ (1 << bit)] ^ columns[bit];
        }

        // Following the linear map from coordinate one must visit every
        // nonzero coordinate exactly once. log[0] = 0 makes a zero locator
        // difference contribute the multiplicative identity.
        let mut log = vec![u32::MAX; I::ORDER];
        log[0] = 0;
        let mut exp = Vec::with_capacity(modulus as usize);
        let mut coordinate = 1;
        for exponent in 0..modulus {
            if coordinate == 0 || log[coordinate] != u32::MAX {
                return None;
            }
            log[coordinate] = exponent;
            exp.push(points[coordinate]);
            coordinate = multiply[coordinate];
        }
        if coordinate != 1 || log[1..].contains(&u32::MAX) {
            return None;
        }

        let kernels = (0..=I::BITS)
            .map(|_| OnceLock::new())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Some(Self {
            log: log.into_boxed_slice(),
            exp: exp.into_boxed_slice(),
            kernels,
        })
    }

    fn kernel(&self, n: usize) -> &[u32] {
        let layer = n.ilog2() as usize;
        self.kernels[layer]
            .get_or_init(|| {
                let modulus = (self.log.len() - 1) as u32;
                let mut kernel = self.log[..n].to_vec();
                fwt(&mut kernel, modulus);
                // The Walsh matrix squares to n*I. Since n divides ORDER,
                // ORDER / n is n's inverse modulo ORDER - 1.
                let inverse = ((self.log.len() / n) % (self.log.len() - 1)) as u32;
                for value in &mut kernel {
                    *value = multiply_mod(*value, inverse, modulus);
                }
                kernel.into_boxed_slice()
            })
            .as_ref()
    }
}

#[inline]
fn multiply_mod(x: u32, y: u32, modulus: u32) -> u32 {
    (u64::from(x) * u64::from(y) % u64::from(modulus)) as u32
}

fn fwt(values: &mut [u32], modulus: u32) {
    // ORDER - 1 is odd, so every power-of-two transform length is invertible
    // even though this residue ring need not be a field.
    debug_assert!(values.len().is_power_of_two());
    debug_assert!(modulus <= u16::MAX as u32);
    debug_assert!(values.iter().all(|&value| value < modulus));
    let mut half = 1;
    while half < values.len() {
        for chunk in values.chunks_exact_mut(2 * half) {
            let (lo, hi) = chunk.split_at_mut(half);
            for (x, y) in lo.iter_mut().zip(hi) {
                let a = *x;
                let b = *y;
                // Reduced values fit in 16 bits. Wrapping operations allow
                // vectorization without overflow checks on each butterfly.
                let sum = a.wrapping_add(b);
                *x = if sum >= modulus { sum - modulus } else { sum };
                *y = if a >= b {
                    a - b
                } else {
                    a.wrapping_add(modulus).wrapping_sub(b)
                };
            }
        }
        half *= 2;
    }
}

/// Immutable field tables shared by all arithmetic kernels for an implementation.
pub struct Tables<E> {
    /// Field points in codeword order, expressed in the Cantor basis.
    pub points: Box<[E]>,
    /// The twiddle factors of the transform, indexed by codeword position.
    ///
    /// Let `j` be the number of trailing zeros of `x`, and `b` be `x` with
    /// bit `j` cleared. Then `skews[x]` is `s_j(w_b)`, where `w_b` is the
    /// point at position `b`, and `s_j` is the polynomial vanishing on the
    /// span of the first `j` basis elements, normalized so `s_j(v_j) = 1`.
    /// Index 0 is unused.
    skews: Box<[E]>,
    locator: OnceLock<Option<LocatorTables<E>>>,
}

impl<E: Field + Copy + 'static> Tables<E> {
    pub fn new<I: Impl<Element = E>>() -> Self {
        let basis = I::basis();
        assert_eq!(basis.len(), I::BITS, "basis has the wrong size");

        // subspace[i] holds s_j(v_i) for the current layer j. At j = 0, s_0 is
        // the identity. Each layer, s_(j+1)(X) = s_j(X) * s_j(X - v_j), and
        // since s_j is linear with s_j(v_j) = 1, this is s_j(X)^2 - s_j(X).
        let mut subspace = basis.to_vec();
        let mut skews = vec![E::zero(); I::ORDER];
        for j in 0..I::BITS {
            // Fill every position whose lowest set bit is j. By linearity,
            // s_j(w_b) is the sum of s_j(v_i) over the bits i of b, and bits
            // below j contribute nothing, so we build the table one bit at a
            // time, from the entries already filled with smaller bits.
            let low = 1 << j;
            skews[low] = E::zero();
            for (i, s) in subspace.iter().enumerate().skip(j + 1) {
                let bit = 1 << i;
                for b in (0..bit).step_by(low << 1) {
                    skews[b + bit + low] = skews[b + low] + s;
                }
            }
            for s in subspace.iter_mut() {
                let squared = *s * &*s;
                *s = squared - &*s;
            }
        }

        let mut points = vec![E::zero(); I::ORDER];
        for (i, basis) in basis.iter().enumerate() {
            let bit = 1 << i;
            for j in 0..bit {
                points[bit + j] = points[j] + basis;
            }
        }
        Self {
            points: points.into_boxed_slice(),
            skews: skews.into_boxed_slice(),
            locator: OnceLock::new(),
        }
    }
}

pub struct Transform<I: Impl> {
    pub imp: I,
    pub tables: Arc<Tables<I::Element>>,
}

impl<I: Impl> Transform<I> {
    /// Use the implementation's shared field tables.
    pub fn new(imp: I) -> Self {
        Self {
            imp,
            tables: I::tables(),
        }
    }

    /// Evaluate the erasure locator at `queries`, in iterator order.
    ///
    /// At an erased point, the point's zero factor is omitted, yielding the
    /// derivative of the locator there. `erased` must be sorted and unique,
    /// and `queries` should be cheaply cloneable.
    ///
    /// Aligned blocks of 2^j erasures contribute shifted subspace polynomials
    /// s_j, whose derivatives are one in the Cantor basis. Highly fragmented
    /// sets use an equivalent log-domain XOR convolution.
    pub fn locator(
        &self,
        erased: &[usize],
        queries: impl Iterator<Item = usize> + Clone,
    ) -> Vec<I::Element> {
        assert!(
            erased.iter().all(|&i| i < I::ORDER),
            "erasure position exceeds field order"
        );
        assert!(
            erased.windows(2).all(|pair| pair[0] < pair[1]),
            "erasure positions are not sorted and unique"
        );
        assert!(
            queries.clone().all(|i| i < I::ORDER),
            "locator query exceeds field order"
        );

        let query_count = queries.clone().count();
        if query_count == 0 {
            return Vec::new();
        }
        let highest = erased
            .last()
            .copied()
            .into_iter()
            .chain(queries.clone())
            .max()
            .expect("at least one query");
        let n = (highest + 1).next_power_of_two();
        let block_count = DyadicBlocks::new(erased).count();
        let fwt_work = n.saturating_mul(2 * n.ilog2() as usize + 1);
        if query_count.saturating_mul(block_count) > LOCATOR_FWT_THRESHOLD.saturating_mul(fwt_work)
            && let Some(locator) = self.locator_fwt(erased, queries.clone(), query_count, n)
        {
            return locator;
        }
        self.locator_dyadic(erased, queries, query_count)
    }

    fn locator_fwt(
        &self,
        erased: &[usize],
        queries: impl Iterator<Item = usize> + Clone,
        query_count: usize,
        n: usize,
    ) -> Option<Vec<I::Element>> {
        let tables = self
            .tables
            .locator
            .get_or_init(|| LocatorTables::new::<I>(&self.tables.points))
            .as_ref()?;
        let kernel = tables.kernel(n);
        let modulus = (I::ORDER - 1) as u32;
        let mut work = vec![0u32; n];
        let mut output = vec![I::Element::one(); query_count];

        // Walsh convolution computes sum(log(point[x xor e])). The zero
        // difference at an erased query has log value zero and is thus omitted.
        for &position in erased {
            work[position] = 1;
        }
        fwt(&mut work, modulus);
        for (value, &coefficient) in work.iter_mut().zip(kernel) {
            *value = multiply_mod(*value, coefficient, modulus);
        }
        fwt(&mut work, modulus);
        for (value, position) in output.iter_mut().zip(queries) {
            *value = tables.exp[work[position] as usize];
        }
        Some(output)
    }

    fn locator_dyadic(
        &self,
        erased: &[usize],
        queries: impl Iterator<Item = usize> + Clone,
        query_count: usize,
    ) -> Vec<I::Element> {
        let one = I::Element::one();
        let mut locator = vec![one; query_count];
        for (base, block_len) in DyadicBlocks::new(erased) {
            // A full-field block contains every queried point. Its
            // skipped-root product is the derivative s_BITS' = 1.
            if block_len < I::ORDER {
                let low_mask = 2 * block_len - 1;
                for (x, value) in queries.clone().zip(&mut locator) {
                    let relative = x ^ base;
                    if relative < block_len {
                        continue;
                    }

                    // skews[index] omits bit j from its point. Restore its
                    // normalized contribution s_j(v_j) = 1 when present.
                    let index = (relative & !low_mask) | block_len;
                    let mut factor = self.tables.skews[index];
                    if relative & block_len != 0 {
                        factor += &one;
                    }
                    *value *= &factor;
                }
            } else {
                debug_assert_eq!(base, 0);
            }
        }
        locator
    }

    /// Inverse transform `work` in place at `shift`.
    ///
    /// `work.count` must be a power of two, `nonzero <= work.count`, and
    /// `shift + work.count <= I::ORDER` so all twiddle indices fit in the field tables.
    /// Shards at or past `nonzero` must be zero.
    pub fn ifft(&self, work: &mut Shards, nonzero: usize, shift: usize) {
        let m = work.count;
        assert!(nonzero <= m);

        let mut dist = 1;
        while 2 * dist < m {
            // Groups starting at or past nonzero are all zero. A group whose
            // right half is also known zero retains the pruned three-butterfly
            // schedule; fully live groups fuse both layers.
            for r in (0..nonzero).step_by(4 * dist) {
                let coefficients = [
                    self.tables.skews[shift + r + dist],
                    self.tables.skews[shift + r + 3 * dist],
                    self.tables.skews[shift + r + 2 * dist],
                ];
                if r + 2 * dist < nonzero {
                    let len = work.len;
                    self.imp.ifft_butterfly_two_layers(
                        work.quarters_mut(r, dist),
                        len,
                        coefficients,
                    );
                } else {
                    for (x, y) in work.halves_mut(r, dist) {
                        self.imp.ifft_butterfly(x, y, coefficients[0]);
                    }
                    for (x, y) in work.halves_mut(r, 2 * dist) {
                        self.imp.ifft_butterfly(x, y, coefficients[2]);
                    }
                }
            }
            dist <<= 2;
        }
        if dist < m {
            for r in (0..nonzero).step_by(2 * dist) {
                let c = self.tables.skews[shift + r + dist];
                for (x, y) in work.halves_mut(r, dist) {
                    self.imp.ifft_butterfly(x, y, c);
                }
            }
        }
    }

    /// Forward transform `work` in place, at position 0.
    ///
    /// `work.count` must be a power of two not exceeding `I::ORDER`, and
    /// `needed <= work.count`.
    /// Only the first `needed` outputs are guaranteed to be computed.
    pub fn fft(&self, work: &mut Shards, needed: usize) {
        let m = work.count;
        assert!(needed <= m);

        let mut dist = m / 2;
        while dist > 1 {
            let quarter = dist / 2;
            // A group whose right half has no needed outputs retains the
            // pruned three-butterfly schedule; fully needed groups fuse both
            // layers in reverse order from the inverse transform.
            for r in (0..needed).step_by(2 * dist) {
                let coefficients = [
                    self.tables.skews[r + quarter],
                    self.tables.skews[r + 3 * quarter],
                    self.tables.skews[r + dist],
                ];
                if r + dist < needed {
                    let len = work.len;
                    self.imp.fft_butterfly_two_layers(
                        work.quarters_mut(r, quarter),
                        len,
                        coefficients,
                    );
                } else {
                    for (x, y) in work.halves_mut(r, dist) {
                        self.imp.fft_butterfly(x, y, coefficients[2]);
                    }
                    for (x, y) in work.halves_mut(r, quarter) {
                        self.imp.fft_butterfly(x, y, coefficients[0]);
                    }
                }
            }
            dist >>= 2;
        }
        if dist == 1 {
            for r in (0..needed).step_by(2) {
                let c = self.tables.skews[r + 1];
                for (x, y) in work.halves_mut(r, 1) {
                    self.imp.fft_butterfly(x, y, c);
                }
            }
        }
    }
}

/// Fuzz plans for transform workspaces, schedules, and locators.
#[cfg(any(test, feature = "fuzz"))]
pub mod fuzz {
    use super::{Shards, Transform, WORK_ALIGN};
    use crate::ocelot::{Impl8, code::Impl, impl16::Impl16, kernel::portable::Portable};
    use arbitrary::{Arbitrary, Unstructured};
    #[cfg(test)]
    use commonware_invariants::minifuzz::Builder;
    use commonware_math::algebra::Ring as _;

    /// A bounded property check for transform support code.
    #[derive(Debug, Arbitrary)]
    pub enum Plan {
        /// Check workspace reset, resize, alignment, and shard partitioning.
        Workspace,
        /// Compare fused transform schedules with their unfused equivalents.
        Schedules,
        /// Compare the GF(2^8) locator with direct evaluation.
        Locator8,
        /// Compare the GF(2^16) locator with direct evaluation.
        Locator16,
        /// Compare the GF(2^8) FWT locator with direct evaluation.
        FwtLocator8,
        /// Compare the GF(2^16) FWT locator with direct evaluation.
        FwtLocator16,
    }

    impl Plan {
        /// Run this fuzz plan using additional structured input from `u`.
        pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
            match self {
                Self::Workspace => fuzz_workspace(u),
                Self::Schedules => fuzz_schedules(u),
                Self::Locator8 => fuzz_locator(u, &Transform::new(Impl8::new(Portable)), false),
                Self::Locator16 => fuzz_locator(u, &Transform::new(Impl16::new(Portable)), false),
                Self::FwtLocator8 => fuzz_locator(u, &Transform::new(Impl8::new(Portable)), true),
                Self::FwtLocator16 => fuzz_locator(u, &Transform::new(Impl16::new(Portable)), true),
            }
        }
    }

    fn copy(work: &Shards) -> Shards {
        let mut copy = Shards::new(work.count, work.len);
        copy.data_mut().copy_from_slice(work.data());
        copy
    }

    fn ifft_unfused<I: Impl>(
        transform: &Transform<I>,
        work: &mut Shards,
        nonzero: usize,
        shift: usize,
    ) {
        let mut dist = 1;
        while dist < work.count {
            for r in (0..nonzero).step_by(2 * dist) {
                let c = transform.tables.skews[shift + r + dist];
                for (x, y) in work.halves_mut(r, dist) {
                    transform.imp.ifft_butterfly(x, y, c);
                }
            }
            dist <<= 1;
        }
    }

    fn fft_unfused<I: Impl>(transform: &Transform<I>, work: &mut Shards, needed: usize) {
        let mut dist = work.count / 2;
        while dist >= 1 {
            for r in (0..needed).step_by(2 * dist) {
                let c = transform.tables.skews[r + dist];
                for (x, y) in work.halves_mut(r, dist) {
                    transform.imp.fft_butterfly(x, y, c);
                }
            }
            dist >>= 1;
        }
    }

    fn fuzz_schedules(u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        let transform = Transform::new(Impl8::new(Portable));
        let count = 1 << u.int_in_range(0..=5)?;
        let len = u.int_in_range(1..=130)?;
        let nonzero = u.int_in_range(0..=count)?;
        let needed = u.int_in_range(0..=count)?;
        let shift = u.int_in_range(0..=<Impl8<Portable> as Impl>::ORDER - count)?;
        let mut input = Shards::new(count, len);
        u.fill_buffer(input.data_mut())?;

        for needed in [0, needed, count] {
            let mut actual = copy(&input);
            let mut expected = copy(&input);
            transform.fft(&mut actual, needed);
            fft_unfused(&transform, &mut expected, needed);
            assert_eq!(actual.data(), expected.data());
        }
        for nonzero in [count, nonzero, 0] {
            for shard in input.shards_mut().skip(nonzero) {
                shard.fill(0);
            }
            let mut actual = copy(&input);
            let mut expected = copy(&input);
            transform.ifft(&mut actual, nonzero, shift);
            ifft_unfused(&transform, &mut expected, nonzero, shift);
            assert_eq!(actual.data(), expected.data());
        }
        Ok(())
    }

    fn fuzz_workspace(u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        let mut work = Shards::new(1, 1);
        for _ in 0..8 {
            let count = u.int_in_range(1..=128)?;
            let capacity = u.int_in_range(1..=4096)?;
            work.reset(count, capacity);
            for len in [capacity, u.int_in_range(1..=capacity)?, capacity] {
                work.resize(len);
                assert_eq!(work.data().as_ptr().align_offset(WORK_ALIGN), 0);
                assert_eq!(work.shards().count(), count);
                for (index, shard) in work.shards_mut().enumerate() {
                    assert_eq!(shard.len(), len);
                    shard.fill(index as u8);
                }
                for (index, shard) in work.shards().enumerate() {
                    assert!(shard.iter().all(|&byte| byte == index as u8));
                }
            }
        }
        Ok(())
    }

    fn locator_reference<I: Impl>(
        transform: &Transform<I>,
        erased: &[usize],
        queries: impl Iterator<Item = usize>,
    ) -> Vec<I::Element> {
        queries
            .map(|x| {
                erased
                    .iter()
                    .filter(|&&e| e != x)
                    .fold(I::Element::one(), |value, &e| {
                        value * &transform.tables.points[x ^ e]
                    })
            })
            .collect()
    }

    fn compare_locator<I: Impl>(
        transform: &Transform<I>,
        erased: &[usize],
        queries: impl Iterator<Item = usize> + Clone,
    ) {
        assert_eq!(
            transform.locator(erased, queries.clone()),
            locator_reference(transform, erased, queries.clone()),
            "locator differs for {} erasures and {} queries",
            erased.len(),
            queries.count(),
        );
    }

    fn compare_fwt_locator<I: Impl>(
        transform: &Transform<I>,
        erased: &[usize],
        queries: impl Iterator<Item = usize> + Clone,
        n: usize,
    ) {
        assert!(erased.iter().all(|&position| position < n));
        assert!(queries.clone().all(|position| position < n));
        assert_eq!(
            transform
                .locator_fwt(erased, queries.clone(), queries.clone().count(), n)
                .expect("FWT locator tables must build"),
            locator_reference(transform, erased, queries.clone()),
            "FWT locator differs for {} erasures, {} queries, and prefix {n}",
            erased.len(),
            queries.count(),
        );
    }

    #[cfg(test)]
    fn check_locator_tables<I: Impl>(transform: &Transform<I>) {
        let tables = transform
            .tables
            .locator
            .get_or_init(|| super::LocatorTables::new::<I>(&transform.tables.points))
            .as_ref()
            .expect("locator tables must build");
        for coordinate in 1..I::ORDER {
            let exponent = tables.log[coordinate] as usize;
            assert_eq!(tables.exp[exponent], transform.tables.points[coordinate]);
        }
    }

    fn fuzz_locator<I: Impl>(
        u: &mut Unstructured<'_>,
        transform: &Transform<I>,
        fwt: bool,
    ) -> arbitrary::Result<()> {
        let bits = if fwt { I::BITS.min(11) } else { I::BITS };
        let n = 1usize << u.int_in_range(0..=bits)?;
        let count = u.int_in_range(0..=64.min(n))?;
        let mut erased = (0..count)
            .map(|_| u.int_in_range(0..=n - 1))
            .collect::<arbitrary::Result<Vec<_>>>()?;
        // Include translated dyadic blocks as well as scattered erasures.
        let block_len = 1 << u.int_in_range(0..=n.ilog2().min(9))?;
        let base = u.int_in_range(0..=n / block_len - 1)? * block_len;
        erased.extend(base..base + block_len);
        erased.sort_unstable();
        erased.dedup();
        let count = u.int_in_range(0..=64)?;
        let queries = (0..count)
            .map(|_| u.int_in_range(0..=n - 1))
            .collect::<arbitrary::Result<Vec<_>>>()?;
        if fwt {
            compare_fwt_locator(transform, &[], queries.iter().copied(), n);
            compare_fwt_locator(transform, &erased, queries.into_iter(), n);
        } else {
            compare_locator(transform, &erased, queries.into_iter());
        }
        Ok(())
    }

    #[test]
    fn minifuzz_workspace() {
        Builder::default()
            .with_seed(0)
            .with_search_limit(256)
            .test(|u| Plan::Workspace.run(u));
    }

    #[test]
    fn minifuzz_paired_layers() {
        Builder::default()
            .with_seed(0)
            .with_search_limit(512)
            .test(|u| Plan::Schedules.run(u));
    }

    #[test]
    fn minifuzz_locator8() {
        Builder::default()
            .with_seed(0)
            .with_search_limit(256)
            .test(|u| Plan::Locator8.run(u));
    }

    #[test]
    fn minifuzz_locator16() {
        Builder::default()
            .with_seed(0)
            .with_search_limit(256)
            .test(|u| Plan::Locator16.run(u));
    }

    #[test]
    fn minifuzz_fwt_locator8() {
        check_locator_tables(&Transform::new(Impl8::new(Portable)));
        Builder::default()
            .with_seed(0)
            .with_search_limit(256)
            .test(|u| Plan::FwtLocator8.run(u));
    }

    #[test]
    fn minifuzz_fwt_locator16() {
        check_locator_tables(&Transform::new(Impl16::new(Portable)));
        Builder::default()
            .with_seed(0)
            .with_search_limit(256)
            .test(|u| Plan::FwtLocator16.run(u));
    }

    #[test]
    fn locator_field_boundaries() {
        let gf16 = Transform::new(Impl16::new(Portable));
        const ORDER: usize = <Impl16<Portable> as Impl>::ORDER;
        compare_locator(&gf16, &[], 0..ORDER);
        compare_locator(&gf16, &[ORDER - 1], 0..ORDER);
        let erased: Vec<_> = (0..21845).chain(21846..32769).collect();
        compare_locator(&gf16, &erased, [21845, 32768].into_iter());

        // Full-field blocks have derivative one and no skew-table entry.
        let erased: Vec<_> = (0..ORDER).collect();
        assert!(
            gf16.locator(&erased, 0..ORDER)
                .iter()
                .all(|value| *value == <Impl16<Portable> as Impl>::Element::one())
        );
        let queries = [0, 1, ORDER / 2, ORDER - 1];
        let locator = gf16
            .locator_fwt(&erased, queries.into_iter(), queries.len(), ORDER)
            .unwrap();
        assert!(
            locator
                .iter()
                .all(|value| *value == <Impl16<Portable> as Impl>::Element::one())
        );

        // Fragmentation forces the public locator to select the FWT path.
        let erased: Vec<_> = (512..1536).step_by(2).collect();
        compare_locator(&gf16, &erased, 0..1537);
    }
}
