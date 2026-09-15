//! Additive transforms shared by encoding and decoding.

use super::code::Impl;
use commonware_math::algebra::Field;
use std::sync::Arc;

const WORK_ALIGN: usize = 64;

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
}

impl<E: Field + Copy + 'static> Tables<E> {
    pub fn new<I: Impl<Element = E>>() -> Self {
        let basis = I::basis();
        assert_eq!(basis.len(), I::BITS, "basis has the wrong size");

        // subspace[i] holds s_j(v_i) for the current layer j. At j = 0, s_0 is
        // the identity. Each layer, s_(j+1)(X) = s_j(X) * s_j(X - v_j), and
        // since s_j is linear with s_j(v_j) = 1, this is s_j(X)^2 - s_j(X).
        let mut subspace = basis.to_vec();
        let mut skews = vec![I::Element::zero(); I::ORDER];
        for j in 0..I::BITS {
            // Fill every position whose lowest set bit is j. By linearity,
            // s_j(w_b) is the sum of s_j(v_i) over the bits i of b, and bits
            // below j contribute nothing, so we build the table one bit at a
            // time, from the entries already filled with smaller bits.
            let low = 1 << j;
            skews[low] = I::Element::zero();
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

    /// Inverse transform `work` in place at `shift`.
    ///
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

#[cfg(test)]
mod tests {
    use super::{Shards, Transform, WORK_ALIGN};
    use crate::ocelot::{Impl8, code::Impl, impl16::Impl16, kernel::portable::Portable};
    use std::ops::Range;

    #[derive(Clone, Copy)]
    struct DefaultImpl<I>(I);

    impl<I: Impl> Impl for DefaultImpl<I> {
        type Element = I::Element;

        const BITS: usize = I::BITS;
        const STRIPE_ALIGN: usize = I::STRIPE_ALIGN;
        const NAMESPACE: &'static [u8] = I::NAMESPACE;

        fn basis() -> &'static [Self::Element] {
            I::basis()
        }

        fn add_into(self, dst: &mut [u8], src: &[u8]) {
            self.0.add_into(dst, src);
        }

        fn sub_into(self, dst: &mut [u8], src: &[u8]) {
            self.0.sub_into(dst, src);
        }

        fn mul_add(self, dst: &mut [u8], src: &[u8], c: Self::Element) {
            self.0.mul_add(dst, src, c);
        }

        fn mul_sub(self, dst: &mut [u8], src: &[u8], c: Self::Element) {
            self.0.mul_sub(dst, src, c);
        }

        fn checksum_range(
            self,
            shard: &[u8],
            coefficients: &[u8],
            range: Range<usize>,
            out: &mut [u8],
        ) {
            self.0.checksum_range(shard, coefficients, range, out);
        }

        fn fft_butterfly(self, x: &mut [u8], y: &mut [u8], c: Self::Element) {
            self.0.fft_butterfly(x, y, c);
        }

        fn ifft_butterfly(self, x: &mut [u8], y: &mut [u8], c: Self::Element) {
            self.0.ifft_butterfly(x, y, c);
        }
    }

    fn copy(work: &Shards) -> Shards {
        let mut copy = Shards::new(work.count, work.len);
        copy.data_mut().copy_from_slice(work.data());
        copy
    }

    fn fill(work: &mut Shards) {
        for (i, byte) in work.data_mut().iter_mut().enumerate() {
            *byte = (i.wrapping_mul(157) ^ i.rotate_left(3) ^ 0xa5) as u8;
        }
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

    fn compare_schedules<I: Impl>(imp: I, lengths: &[usize]) {
        let transform = Transform::new(imp);
        for &count in &[1, 2, 4, 8, 16] {
            for &len in lengths {
                let mut input = Shards::new(count, len);
                fill(&mut input);

                for nonzero in 0..=count {
                    let mut input = copy(&input);
                    for shard in input.shards_mut().skip(nonzero) {
                        shard.fill(0);
                    }
                    for shift in [0, 1, I::ORDER - count] {
                        let mut actual = copy(&input);
                        let mut expected = copy(&input);
                        transform.ifft(&mut actual, nonzero, shift);
                        ifft_unfused(&transform, &mut expected, nonzero, shift);
                        assert_eq!(
                            actual.data(),
                            expected.data(),
                            "IFFT differs: count={count} len={len} nonzero={nonzero} shift={shift}"
                        );
                    }
                }

                for needed in 0..=count {
                    let mut actual = copy(&input);
                    let mut expected = copy(&input);
                    transform.fft(&mut actual, needed);
                    fft_unfused(&transform, &mut expected, needed);
                    assert_eq!(
                        actual.data(),
                        expected.data(),
                        "FFT differs: count={count} len={len} needed={needed}"
                    );
                }
            }
        }
    }

    #[test]
    fn workspace_keeps_alignment_and_shard_count() {
        let mut work = Shards::new(1, 2);
        for count in [1, 3, 64, 2, 128, 1] {
            work.reset(count, 4096);
            for len in [4096, 130, 2, 4096] {
                work.resize(len);
                assert!(work.data().as_ptr().align_offset(WORK_ALIGN) == 0);
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
    }

    #[test]
    fn paired_layers_match_unfused_schedule() {
        compare_schedules(Impl8::new(Portable), &[1, 17, 65]);
        compare_schedules(DefaultImpl(Impl8::new(Portable)), &[3]);
        compare_schedules(Impl16::new(Portable), &[2, 126, 130]);
    }
}
