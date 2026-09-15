//! Ocelot arithmetic over GF(2^16).
//!
//! Shards consist of 128-byte blocks containing up to 64 field elements. The
//! low bytes occupy the first half of each block and the high bytes the second
//! half. A shorter final block is split equally in the same way.

use super::{
    AddInto, Impl8,
    code::Impl,
    field::{
        gf8::GF8,
        gf16::{GF16, GF16Constant, GF16Vec},
    },
    kernel::{Kernel, WithKernel},
    transform::Tables,
};
use std::{
    ops::Range,
    sync::{Arc, OnceLock},
};

const BLOCK_BYTES: usize = 128;
const BLOCK_SYMBOLS: usize = BLOCK_BYTES / 2;

/// Ocelot's GF(2^16) arithmetic, using a concrete byte kernel.
#[derive(Clone, Copy)]
pub struct Impl16<K: Kernel> {
    kernel: K,
}

impl<K: Kernel> Impl16<K> {
    /// Use `kernel` for operations on whole shards.
    pub const fn new(kernel: K) -> Self {
        Self { kernel }
    }
}

impl<K: Kernel> Impl for Impl16<K> {
    type Element = GF16;

    const BITS: usize = 16;
    const STRIPE_ALIGN: usize = BLOCK_BYTES;
    const NAMESPACE: &'static [u8] = b"_COMMONWARE_CODING_OCELOT16";

    fn tables() -> Arc<Tables<GF16>> {
        static TABLES: OnceLock<Arc<Tables<GF16>>> = OnceLock::new();
        TABLES
            .get_or_init(|| Arc::new(Tables::new::<Self>()))
            .clone()
    }

    fn basis() -> &'static [GF16] {
        &[
            GF16(0x0001),
            GF16(0x00bc),
            GF16(0x005c),
            GF16(0x000c),
            GF16(0x00ae),
            GF16(0x005a),
            GF16(0x000e),
            GF16(0x0084),
            GF16(0x0128),
            GF16(0xbc3c),
            GF16(0x5c8e),
            GF16(0x0c3c),
            GF16(0xae2e),
            GF16(0x5a5c),
            GF16(0x0e44),
            GF16(0x84e4),
        ]
    }

    fn add_into(self, dst: &mut [u8], src: &[u8]) {
        self.kernel.run(AddInto { dst, src });
    }

    fn derivative_four(self, quarters: [&mut [u8]; 4]) {
        Impl8::new(self.kernel).derivative_four(quarters);
    }

    fn derivative_sixteen(self, blocks: [&mut [u8]; 16]) {
        Impl8::new(self.kernel).derivative_sixteen(blocks);
    }

    fn sub_into(self, dst: &mut [u8], src: &[u8]) {
        self.add_into(dst, src);
    }

    fn mul_add(self, dst: &mut [u8], src: &[u8], c: GF16) {
        assert!(src.len().is_multiple_of(2), "shard length is not aligned");
        // Subfield coefficients multiply both byte planes independently.
        if c.0 <= u8::MAX as u16 {
            return Impl8::new(self.kernel).mul_add(dst, src, GF8(c.0 as u8));
        }
        self.kernel.run(MulAdd::<true> { dst, src, c });
    }

    fn mul_into(self, dst: &mut [u8], src: &[u8], c: GF16) {
        assert!(src.len().is_multiple_of(2), "shard length is not aligned");
        // Subfield coefficients multiply both byte planes independently.
        if c.0 <= u8::MAX as u16 {
            return Impl8::new(self.kernel).mul_into(dst, src, GF8(c.0 as u8));
        }
        self.kernel.run(MulAdd::<false> { dst, src, c });
    }

    fn mul_sub(self, dst: &mut [u8], src: &[u8], c: GF16) {
        self.mul_add(dst, src, c);
    }

    fn fft_butterfly(self, x: &mut [u8], y: &mut [u8], c: GF16) {
        assert!(x.len().is_multiple_of(2), "shard length is not aligned");
        if c.0 <= u8::MAX as u16 {
            return Impl8::new(self.kernel).fft_butterfly(x, y, GF8(c.0 as u8));
        }
        self.kernel.run(Butterfly::<false> { x, y, c });
    }

    fn ifft_butterfly(self, x: &mut [u8], y: &mut [u8], c: GF16) {
        assert!(x.len().is_multiple_of(2), "shard length is not aligned");
        if c.0 <= u8::MAX as u16 {
            return Impl8::new(self.kernel).ifft_butterfly(x, y, GF8(c.0 as u8));
        }
        self.kernel.run(Butterfly::<true> { x, y, c });
    }

    fn fft_butterfly_two_layers(
        self,
        quarters: [&mut [u8]; 4],
        shard_len: usize,
        coefficients: [GF16; 3],
    ) {
        if coefficients.iter().all(|c| c.0 <= u8::MAX as u16) {
            return Impl8::new(self.kernel).fft_butterfly_two_layers(
                quarters,
                shard_len,
                coefficients.map(|c| GF8(c.0 as u8)),
            );
        }
        self.kernel.run(ButterflyTwoLayers::<false> {
            quarters,
            shard_len,
            coefficients,
        });
    }

    fn ifft_butterfly_two_layers(
        self,
        quarters: [&mut [u8]; 4],
        shard_len: usize,
        coefficients: [GF16; 3],
    ) {
        if coefficients.iter().all(|c| c.0 <= u8::MAX as u16) {
            return Impl8::new(self.kernel).ifft_butterfly_two_layers(
                quarters,
                shard_len,
                coefficients.map(|c| GF8(c.0 as u8)),
            );
        }
        self.kernel.run(ButterflyTwoLayers::<true> {
            quarters,
            shard_len,
            coefficients,
        });
    }

    fn checksum_range(
        self,
        shard: &[u8],
        coefficients: &[u8],
        range: Range<usize>,
        out: &mut [u8],
    ) {
        self.kernel.run(ChecksumRange {
            shard,
            coefficients,
            range,
            out,
        });
    }
}

struct MulAdd<'a, const ADD: bool> {
    dst: &'a mut [u8],
    src: &'a [u8],
    c: GF16,
}

impl<const ADD: bool> WithKernel for MulAdd<'_, ADD> {
    type Output = ();

    #[inline(always)]
    fn call<K: Kernel>(self, kernel: K) {
        let Self { dst, src, c } = self;
        assert_eq!(dst.len(), src.len(), "shard lengths differ");
        assert!(src.len().is_multiple_of(2), "shard length is not aligned");
        let prepared = GF16Constant::new(kernel, c);
        let (dst_blocks, dst_tail) = dst.as_chunks_mut::<BLOCK_BYTES>();
        let (src_blocks, src_tail) = src.as_chunks::<BLOCK_BYTES>();
        for (dst, src) in dst_blocks.iter_mut().zip(src_blocks.iter()) {
            Self::block(kernel, dst, src, c, prepared);
        }
        if !dst_tail.is_empty() {
            Self::block(kernel, dst_tail, src_tail, c, prepared);
        }
    }
}

impl<const ADD: bool> MulAdd<'_, ADD> {
    #[inline(always)]
    fn block<K: Kernel>(kernel: K, dst: &mut [u8], src: &[u8], c: GF16, prepared: GF16Constant<K>) {
        let symbols = src.len() / 2;
        let (dst_lo, dst_hi) = dst.split_at_mut(symbols);
        let (src_lo, src_hi) = src.split_at(symbols);
        let full = symbols / K::LANES * K::LANES;
        for start in (0..full).step_by(K::LANES) {
            let end = start + K::LANES;
            let product = GF16Vec::load_planes(kernel, &src_lo[start..end], &src_hi[start..end])
                .mul_prepared(prepared);
            let sum = if ADD {
                GF16Vec::load_planes(kernel, &dst_lo[start..end], &dst_hi[start..end]) + product
            } else {
                product
            };
            sum.store_planes(&mut dst_lo[start..end], &mut dst_hi[start..end]);
        }
        let partial = full + (symbols - full) / K::PARTIAL_GRANULARITY * K::PARTIAL_GRANULARITY;
        if partial > full {
            let range = full..partial;
            let product = GF16Vec::load_partial_planes(
                kernel,
                &src_lo[range.clone()],
                &src_hi[range.clone()],
            )
            .mul_prepared(prepared);
            let sum = if ADD {
                GF16Vec::load_partial_planes(kernel, &dst_lo[range.clone()], &dst_hi[range.clone()])
                    + product
            } else {
                product
            };
            sum.store_partial_planes(&mut dst_lo[range.clone()], &mut dst_hi[range]);
        }
        for i in partial..symbols {
            let src = GF16(u16::from(src_lo[i]) | (u16::from(src_hi[i]) << 8));
            let product = src * c;
            let sum = if ADD {
                GF16(u16::from(dst_lo[i]) | (u16::from(dst_hi[i]) << 8)) + product
            } else {
                product
            };
            dst_lo[i] = sum.0 as u8;
            dst_hi[i] = (sum.0 >> 8) as u8;
        }
    }
}

struct Butterfly<'a, const INVERSE: bool> {
    x: &'a mut [u8],
    y: &'a mut [u8],
    c: GF16,
}

impl<const INVERSE: bool> WithKernel for Butterfly<'_, INVERSE> {
    type Output = ();

    #[inline(always)]
    fn call<K: Kernel>(self, kernel: K) {
        let Self { x, y, c } = self;
        assert_eq!(x.len(), y.len(), "shard lengths differ");
        assert!(x.len().is_multiple_of(2), "shard length is not aligned");
        let prepared = GF16Constant::new(kernel, c);
        let (x_blocks, x_tail) = x.as_chunks_mut::<BLOCK_BYTES>();
        let (y_blocks, y_tail) = y.as_chunks_mut::<BLOCK_BYTES>();
        for (x, y) in x_blocks.iter_mut().zip(y_blocks.iter_mut()) {
            Self::block(kernel, x, y, c, prepared);
        }
        if !x_tail.is_empty() {
            Self::block(kernel, x_tail, y_tail, c, prepared);
        }
    }
}

impl<const INVERSE: bool> Butterfly<'_, INVERSE> {
    #[inline(always)]
    fn block<K: Kernel>(kernel: K, x: &mut [u8], y: &mut [u8], c: GF16, prepared: GF16Constant<K>) {
        let symbols = x.len() / 2;
        let (x_lo, x_hi) = x.split_at_mut(symbols);
        let (y_lo, y_hi) = y.split_at_mut(symbols);
        let full = symbols / K::LANES * K::LANES;
        for start in (0..full).step_by(K::LANES) {
            let end = start + K::LANES;
            let mut a = GF16Vec::load_planes(kernel, &x_lo[start..end], &x_hi[start..end]);
            let mut b = GF16Vec::load_planes(kernel, &y_lo[start..end], &y_hi[start..end]);
            if INVERSE {
                b += &a;
                a += &b.mul_prepared(prepared);
            } else {
                a += &b.mul_prepared(prepared);
                b += &a;
            }
            a.store_planes(&mut x_lo[start..end], &mut x_hi[start..end]);
            b.store_planes(&mut y_lo[start..end], &mut y_hi[start..end]);
        }
        let partial = full + (symbols - full) / K::PARTIAL_GRANULARITY * K::PARTIAL_GRANULARITY;
        if partial > full {
            let range = full..partial;
            let mut a =
                GF16Vec::load_partial_planes(kernel, &x_lo[range.clone()], &x_hi[range.clone()]);
            let mut b =
                GF16Vec::load_partial_planes(kernel, &y_lo[range.clone()], &y_hi[range.clone()]);
            if INVERSE {
                b += &a;
                a += &b.mul_prepared(prepared);
            } else {
                a += &b.mul_prepared(prepared);
                b += &a;
            }
            a.store_partial_planes(&mut x_lo[range.clone()], &mut x_hi[range.clone()]);
            b.store_partial_planes(&mut y_lo[range.clone()], &mut y_hi[range]);
        }
        for i in partial..symbols {
            let mut a = GF16(u16::from(x_lo[i]) | (u16::from(x_hi[i]) << 8));
            let mut b = GF16(u16::from(y_lo[i]) | (u16::from(y_hi[i]) << 8));
            if INVERSE {
                b += &a;
                a += &(b * c);
            } else {
                a += &(b * c);
                b += &a;
            }
            x_lo[i] = a.0 as u8;
            x_hi[i] = (a.0 >> 8) as u8;
            y_lo[i] = b.0 as u8;
            y_hi[i] = (b.0 >> 8) as u8;
        }
    }
}

struct ButterflyTwoLayers<'a, const INVERSE: bool> {
    quarters: [&'a mut [u8]; 4],
    shard_len: usize,
    coefficients: [GF16; 3],
}

impl<const INVERSE: bool> WithKernel for ButterflyTwoLayers<'_, INVERSE> {
    type Output = ();

    #[inline(always)]
    fn call<K: Kernel>(self, kernel: K) {
        let Self {
            quarters,
            shard_len,
            coefficients,
        } = self;
        let [q0, q1, q2, q3] = quarters;
        assert!(shard_len > 0, "shard length is zero");
        assert!(shard_len.is_multiple_of(2), "shard length is not aligned");
        assert_eq!(q0.len(), q1.len(), "quarter lengths differ");
        assert_eq!(q0.len(), q2.len(), "quarter lengths differ");
        assert_eq!(q0.len(), q3.len(), "quarter lengths differ");
        assert!(q0.len().is_multiple_of(shard_len), "partial shard group");

        let prepared = [
            GF16Constant::new(kernel, coefficients[0]),
            GF16Constant::new(kernel, coefficients[1]),
            GF16Constant::new(kernel, coefficients[2]),
        ];
        // Complete layout blocks compose across shard boundaries.
        if shard_len.is_multiple_of(BLOCK_BYTES) {
            return Self::shard(kernel, [q0, q1, q2, q3], coefficients, prepared);
        }
        for (((x0, x1), x2), x3) in q0
            .chunks_exact_mut(shard_len)
            .zip(q1.chunks_exact_mut(shard_len))
            .zip(q2.chunks_exact_mut(shard_len))
            .zip(q3.chunks_exact_mut(shard_len))
        {
            Self::shard(kernel, [x0, x1, x2, x3], coefficients, prepared);
        }
    }
}

impl<const INVERSE: bool> ButterflyTwoLayers<'_, INVERSE> {
    #[inline(always)]
    fn shard<K: Kernel>(
        kernel: K,
        shards: [&mut [u8]; 4],
        coefficients: [GF16; 3],
        prepared: [GF16Constant<K>; 3],
    ) {
        let [x0, x1, x2, x3] = shards;
        let (x0, x0_tail) = x0.as_chunks_mut::<BLOCK_BYTES>();
        let (x1, x1_tail) = x1.as_chunks_mut::<BLOCK_BYTES>();
        let (x2, x2_tail) = x2.as_chunks_mut::<BLOCK_BYTES>();
        let (x3, x3_tail) = x3.as_chunks_mut::<BLOCK_BYTES>();
        for (((x0, x1), x2), x3) in x0
            .iter_mut()
            .zip(x1.iter_mut())
            .zip(x2.iter_mut())
            .zip(x3.iter_mut())
        {
            Self::block(kernel, [x0, x1, x2, x3], coefficients, prepared);
        }
        let tails = [x0_tail, x1_tail, x2_tail, x3_tail];
        if !tails[0].is_empty() {
            Self::block(kernel, tails, coefficients, prepared);
        }
    }

    #[inline(always)]
    fn block<K: Kernel>(
        kernel: K,
        blocks: [&mut [u8]; 4],
        coefficients: [GF16; 3],
        prepared: [GF16Constant<K>; 3],
    ) {
        let [x0, x1, x2, x3] = blocks;
        let symbols = x0.len() / 2;
        let (x0_lo, x0_hi) = x0.split_at_mut(symbols);
        let (x1_lo, x1_hi) = x1.split_at_mut(symbols);
        let (x2_lo, x2_hi) = x2.split_at_mut(symbols);
        let (x3_lo, x3_hi) = x3.split_at_mut(symbols);
        let full = symbols / K::LANES * K::LANES;
        for start in (0..full).step_by(K::LANES) {
            let end = start + K::LANES;
            let values = [
                GF16Vec::load_planes(kernel, &x0_lo[start..end], &x0_hi[start..end]),
                GF16Vec::load_planes(kernel, &x1_lo[start..end], &x1_hi[start..end]),
                GF16Vec::load_planes(kernel, &x2_lo[start..end], &x2_hi[start..end]),
                GF16Vec::load_planes(kernel, &x3_lo[start..end], &x3_hi[start..end]),
            ];
            let values = Self::apply(values, prepared);
            values[0].store_planes(&mut x0_lo[start..end], &mut x0_hi[start..end]);
            values[1].store_planes(&mut x1_lo[start..end], &mut x1_hi[start..end]);
            values[2].store_planes(&mut x2_lo[start..end], &mut x2_hi[start..end]);
            values[3].store_planes(&mut x3_lo[start..end], &mut x3_hi[start..end]);
        }

        let partial = full + (symbols - full) / K::PARTIAL_GRANULARITY * K::PARTIAL_GRANULARITY;
        if partial > full {
            let range = full..partial;
            let values = [
                GF16Vec::load_partial_planes(kernel, &x0_lo[range.clone()], &x0_hi[range.clone()]),
                GF16Vec::load_partial_planes(kernel, &x1_lo[range.clone()], &x1_hi[range.clone()]),
                GF16Vec::load_partial_planes(kernel, &x2_lo[range.clone()], &x2_hi[range.clone()]),
                GF16Vec::load_partial_planes(kernel, &x3_lo[range.clone()], &x3_hi[range.clone()]),
            ];
            let values = Self::apply(values, prepared);
            values[0].store_partial_planes(&mut x0_lo[range.clone()], &mut x0_hi[range.clone()]);
            values[1].store_partial_planes(&mut x1_lo[range.clone()], &mut x1_hi[range.clone()]);
            values[2].store_partial_planes(&mut x2_lo[range.clone()], &mut x2_hi[range.clone()]);
            values[3].store_partial_planes(&mut x3_lo[range.clone()], &mut x3_hi[range]);
        }
        for i in partial..symbols {
            let mut values = [
                GF16(u16::from(x0_lo[i]) | (u16::from(x0_hi[i]) << 8)),
                GF16(u16::from(x1_lo[i]) | (u16::from(x1_hi[i]) << 8)),
                GF16(u16::from(x2_lo[i]) | (u16::from(x2_hi[i]) << 8)),
                GF16(u16::from(x3_lo[i]) | (u16::from(x3_hi[i]) << 8)),
            ];
            Self::apply_scalar(&mut values, coefficients);
            x0_lo[i] = values[0].0 as u8;
            x0_hi[i] = (values[0].0 >> 8) as u8;
            x1_lo[i] = values[1].0 as u8;
            x1_hi[i] = (values[1].0 >> 8) as u8;
            x2_lo[i] = values[2].0 as u8;
            x2_hi[i] = (values[2].0 >> 8) as u8;
            x3_lo[i] = values[3].0 as u8;
            x3_hi[i] = (values[3].0 >> 8) as u8;
        }
    }

    #[inline(always)]
    fn apply<K: Kernel>(
        mut values: [GF16Vec<K>; 4],
        prepared: [GF16Constant<K>; 3],
    ) -> [GF16Vec<K>; 4] {
        if INVERSE {
            Self::apply_pair(&mut values, 0, 1, prepared[0]);
            Self::apply_pair(&mut values, 2, 3, prepared[1]);
            Self::apply_pair(&mut values, 0, 2, prepared[2]);
            Self::apply_pair(&mut values, 1, 3, prepared[2]);
        } else {
            Self::apply_pair(&mut values, 0, 2, prepared[2]);
            Self::apply_pair(&mut values, 1, 3, prepared[2]);
            Self::apply_pair(&mut values, 0, 1, prepared[0]);
            Self::apply_pair(&mut values, 2, 3, prepared[1]);
        }
        values
    }

    #[inline(always)]
    fn apply_pair<K: Kernel>(
        values: &mut [GF16Vec<K>; 4],
        x: usize,
        y: usize,
        prepared: GF16Constant<K>,
    ) {
        let mut a = values[x];
        let mut b = values[y];
        if INVERSE {
            b += &a;
            a += &b.mul_prepared(prepared);
        } else {
            a += &b.mul_prepared(prepared);
            b += &a;
        }
        values[x] = a;
        values[y] = b;
    }

    #[inline(always)]
    fn apply_scalar(values: &mut [GF16; 4], coefficients: [GF16; 3]) {
        let apply_pair = |values: &mut [GF16; 4], x: usize, y: usize, c: GF16| {
            let mut a = values[x];
            let mut b = values[y];
            if INVERSE {
                b += &a;
                a += &(b * c);
            } else {
                a += &(b * c);
                b += &a;
            }
            values[x] = a;
            values[y] = b;
        };
        if INVERSE {
            apply_pair(values, 0, 1, coefficients[0]);
            apply_pair(values, 2, 3, coefficients[1]);
            apply_pair(values, 0, 2, coefficients[2]);
            apply_pair(values, 1, 3, coefficients[2]);
        } else {
            apply_pair(values, 0, 2, coefficients[2]);
            apply_pair(values, 1, 3, coefficients[2]);
            apply_pair(values, 0, 1, coefficients[0]);
            apply_pair(values, 2, 3, coefficients[1]);
        }
    }
}

struct ChecksumRange<'a> {
    shard: &'a [u8],
    coefficients: &'a [u8],
    range: Range<usize>,
    out: &'a mut [u8],
}

struct ChecksumAccumulator<V> {
    vector_lo: V,
    vector_hi: V,
    scalar_lo: u8,
    scalar_hi: u8,
}

#[inline(always)]
fn checksum_edge<K: Kernel>(
    kernel: K,
    block: &[u8],
    coefficients: &[u8],
    range: Range<usize>,
    sum: &mut ChecksumAccumulator<K::Vector>,
) {
    let block_symbols = block.len() / 2;
    let (values_lo, values_hi) = block.split_at(block_symbols);
    let full_end = range.start + (range.len() / K::LANES) * K::LANES;
    for offset in (range.start..full_end).step_by(K::LANES) {
        let lanes = offset..offset + K::LANES;
        let coefficients = kernel.load(&coefficients[lanes.clone()]);
        sum.vector_lo = kernel.xor(
            sum.vector_lo,
            kernel.gf8_mul_vec(kernel.load(&values_lo[lanes.clone()]), coefficients),
        );
        sum.vector_hi = kernel.xor(
            sum.vector_hi,
            kernel.gf8_mul_vec(kernel.load(&values_hi[lanes]), coefficients),
        );
    }

    let partial_end =
        full_end + ((range.end - full_end) / K::PARTIAL_GRANULARITY) * K::PARTIAL_GRANULARITY;
    if partial_end > full_end {
        let lanes = full_end..partial_end;
        let coefficients = kernel.load_partial(&coefficients[lanes.clone()]);
        sum.vector_lo = kernel.xor(
            sum.vector_lo,
            kernel.gf8_mul_vec(kernel.load_partial(&values_lo[lanes.clone()]), coefficients),
        );
        sum.vector_hi = kernel.xor(
            sum.vector_hi,
            kernel.gf8_mul_vec(kernel.load_partial(&values_hi[lanes]), coefficients),
        );
    }

    for i in partial_end..range.end {
        let coefficient = GF8(coefficients[i]);
        sum.scalar_lo ^= GF8(values_lo[i]).mul_inner(coefficient).0;
        sum.scalar_hi ^= GF8(values_hi[i]).mul_inner(coefficient).0;
    }
}

fn checksum_scalar(shard: &[u8], coefficients: &[u8], range: Range<usize>) -> (u8, u8) {
    let symbols = shard.len() / 2;
    let mut lo = 0;
    let mut hi = 0;
    for i in range {
        let block_start = i / BLOCK_SYMBOLS * BLOCK_BYTES;
        let block_symbols = (symbols - i / BLOCK_SYMBOLS * BLOCK_SYMBOLS).min(BLOCK_SYMBOLS);
        let lane = i % BLOCK_SYMBOLS;
        let coefficient = GF8(coefficients[i]);
        lo ^= GF8(shard[block_start + lane]).mul_inner(coefficient).0;
        hi ^= GF8(shard[block_start + block_symbols + lane])
            .mul_inner(coefficient)
            .0;
    }
    (lo, hi)
}

impl WithKernel for ChecksumRange<'_> {
    type Output = ();

    #[inline(always)]
    fn call<K: Kernel>(self, kernel: K) {
        let Self {
            shard,
            coefficients,
            range,
            out,
        } = self;
        assert!(shard.len().is_multiple_of(2), "shard length is not aligned");
        assert!(out.len().is_multiple_of(2), "output length is not aligned");
        assert!(range.start <= range.end, "invalid checksum range");
        assert!(range.end <= shard.len(), "checksum range exceeds shard");
        assert!(
            range.start.is_multiple_of(2) && range.end.is_multiple_of(2),
            "checksum range is not aligned"
        );
        let symbols = shard.len() / 2;
        let output_symbols = out.len() / 2;
        assert_eq!(
            coefficients.len(),
            symbols
                .checked_mul(output_symbols)
                .expect("checksum dimensions overflow"),
            "coefficient length does not match checksum dimensions"
        );
        out.fill(0);
        if range.is_empty() {
            return;
        }

        let start = range.start / 2;
        let end = range.end / 2;
        let zero = [0; BLOCK_SYMBOLS];
        for (output_block, out) in out.chunks_mut(BLOCK_BYTES).enumerate() {
            let block_symbols = out.len() / 2;
            let (out_lo, out_hi) = out.split_at_mut(block_symbols);
            for (lane, (out_lo, out_hi)) in out_lo.iter_mut().zip(out_hi).enumerate() {
                let output = output_block * BLOCK_SYMBOLS + lane;
                let row = &coefficients[output * symbols..(output + 1) * symbols];
                if K::LANES > BLOCK_SYMBOLS {
                    (*out_lo, *out_hi) = checksum_scalar(shard, row, start..end);
                    continue;
                }

                let zero = kernel.load(&zero[..K::LANES]);
                let mut sum = ChecksumAccumulator {
                    vector_lo: zero,
                    vector_hi: zero,
                    scalar_lo: 0,
                    scalar_hi: 0,
                };
                let mut cursor = start;

                if !cursor.is_multiple_of(BLOCK_SYMBOLS) {
                    let block_start = cursor / BLOCK_SYMBOLS * BLOCK_SYMBOLS;
                    let block_end = (block_start + BLOCK_SYMBOLS).min(end);
                    let byte_start = block_start / BLOCK_SYMBOLS * BLOCK_BYTES;
                    let byte_end = (byte_start + BLOCK_BYTES).min(shard.len());
                    checksum_edge(
                        kernel,
                        &shard[byte_start..byte_end],
                        &row[block_start..block_start + (byte_end - byte_start) / 2],
                        cursor - block_start..block_end - block_start,
                        &mut sum,
                    );
                    cursor = block_end;
                }

                let full_end = end / BLOCK_SYMBOLS * BLOCK_SYMBOLS;
                if cursor < full_end {
                    let byte_start = cursor / BLOCK_SYMBOLS * BLOCK_BYTES;
                    let byte_end = byte_start + (full_end - cursor) / BLOCK_SYMBOLS * BLOCK_BYTES;
                    let (blocks, block_remainder) =
                        shard[byte_start..byte_end].as_chunks::<BLOCK_BYTES>();
                    let (coefficient_blocks, coefficient_remainder) =
                        row[cursor..full_end].as_chunks::<BLOCK_SYMBOLS>();
                    debug_assert!(block_remainder.is_empty());
                    debug_assert!(coefficient_remainder.is_empty());
                    for (block, coefficients) in blocks.iter().zip(coefficient_blocks) {
                        let (values_lo, values_hi) = block.split_at(BLOCK_SYMBOLS);
                        if BLOCK_SYMBOLS.is_multiple_of(K::LANES) {
                            for offset in (0..BLOCK_SYMBOLS).step_by(K::LANES) {
                                let lanes = offset..offset + K::LANES;
                                let coefficients = kernel.load(&coefficients[lanes.clone()]);
                                sum.vector_lo = kernel.xor(
                                    sum.vector_lo,
                                    kernel.gf8_mul_vec(
                                        kernel.load(&values_lo[lanes.clone()]),
                                        coefficients,
                                    ),
                                );
                                sum.vector_hi = kernel.xor(
                                    sum.vector_hi,
                                    kernel
                                        .gf8_mul_vec(kernel.load(&values_hi[lanes]), coefficients),
                                );
                            }
                        } else {
                            checksum_edge(kernel, block, coefficients, 0..BLOCK_SYMBOLS, &mut sum);
                        }
                    }
                    cursor = full_end;
                }

                if cursor < end {
                    let byte_start = cursor / BLOCK_SYMBOLS * BLOCK_BYTES;
                    let byte_end = (byte_start + BLOCK_BYTES).min(shard.len());
                    let block_symbols = (byte_end - byte_start) / 2;
                    checksum_edge(
                        kernel,
                        &shard[byte_start..byte_end],
                        &row[cursor..cursor + block_symbols],
                        0..end - cursor,
                        &mut sum,
                    );
                }

                *out_lo = sum.scalar_lo ^ kernel.xor_fold(sum.vector_lo);
                *out_hi = sum.scalar_hi ^ kernel.xor_fold(sum.vector_hi);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ocelot::{
        code::{Decoder, Encoder, stripe_bytes, test_suites::fuzz_code},
        kernel::{portable::Portable, with_kernel},
    };
    use commonware_parallel::{Rayon, Strategy};
    use commonware_utils::{NZUsize, test_rng};
    use rand_core::Rng as _;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    fn elements(bytes: &[u8]) -> Vec<GF16> {
        assert!(bytes.len().is_multiple_of(2));
        bytes
            .chunks(BLOCK_BYTES)
            .flat_map(|block| {
                let (lo, hi) = block.split_at(block.len() / 2);
                lo.iter()
                    .zip(hi)
                    .map(|(&lo, &hi)| GF16(u16::from(lo) | (u16::from(hi) << 8)))
            })
            .collect()
    }

    fn layout(elements: &[GF16]) -> Vec<u8> {
        let mut bytes = vec![0; 2 * elements.len()];
        for (block_index, block) in bytes.chunks_mut(BLOCK_BYTES).enumerate() {
            let (lo, hi) = block.split_at_mut(block.len() / 2);
            let elements = &elements[block_index * BLOCK_SYMBOLS..][..lo.len()];
            for ((lo, hi), element) in lo.iter_mut().zip(hi).zip(elements) {
                *lo = element.0 as u8;
                *hi = (element.0 >> 8) as u8;
            }
        }
        bytes
    }

    fn checksum_reference(
        shard: &[u8],
        coefficients: &[u8],
        range: Range<usize>,
        output_symbols: usize,
    ) -> Vec<u8> {
        let input_symbols = shard.len() / 2;
        let values = elements(shard);
        let mut out = Vec::with_capacity(output_symbols);
        for output in 0..output_symbols {
            let mut sum = GF16(0);
            for i in range.start / 2..range.end / 2 {
                sum += &(values[i] * GF16(u16::from(coefficients[output * input_symbols + i])));
            }
            out.push(sum);
        }
        layout(&out)
    }

    struct TestCode;

    impl WithKernel for TestCode {
        type Output = ();

        fn call<K: Kernel>(self, kernel: K) {
            commonware_invariants::minifuzz::test(|u| fuzz_code(u, Impl16::new(kernel)));
        }
    }

    #[test]
    fn test_ocelot16() {
        with_kernel(TestCode);
    }

    struct TestArithmetic;

    impl WithKernel for TestArithmetic {
        type Output = ();

        fn call<K: Kernel>(self, kernel: K) {
            let imp = Impl16::new(kernel);
            let mut rng = test_rng();
            for len in (0..=3 * BLOCK_BYTES).step_by(2) {
                let offset = 1 + len / 2 % 7;
                let range = offset..offset + len;
                let mut x = vec![0xa5; offset + len + 7];
                let mut y = vec![0x5a; offset + len + 7];
                rng.fill_bytes(&mut x[range.clone()]);
                rng.fill_bytes(&mut y[range.clone()]);

                for c in [0, 1, 0x80, 0xff, 0x0100, 0x0128, 0x84e4, 0xffff].map(GF16) {
                    let mut overwritten = x.clone();
                    overwritten[range.clone()].fill(0xa5);
                    imp.mul_into(&mut overwritten[range.clone()], &y[range.clone()], c);
                    let products: Vec<_> = elements(&y[range.clone()])
                        .into_iter()
                        .map(|y| y * c)
                        .collect();
                    let mut expected_overwrite = overwritten.clone();
                    expected_overwrite[range.clone()].copy_from_slice(&layout(&products));
                    assert_eq!(overwritten, expected_overwrite);

                    let mut actual = x.clone();
                    imp.mul_add(&mut actual[range.clone()], &y[range.clone()], c);
                    let products: Vec<_> = elements(&x[range.clone()])
                        .into_iter()
                        .zip(elements(&y[range.clone()]))
                        .map(|(x, y)| x + y * c)
                        .collect();
                    let mut expected = x.clone();
                    expected[range.clone()].copy_from_slice(&layout(&products));
                    assert_eq!(actual, expected);

                    let mut actual_x = x.clone();
                    let mut actual_y = y.clone();
                    let mut expected_x = elements(&x[range.clone()]);
                    let mut expected_y = elements(&y[range.clone()]);
                    for (x, y) in expected_x.iter_mut().zip(&mut expected_y) {
                        *x += &(*y * c);
                        *y += x;
                    }
                    imp.fft_butterfly(
                        &mut actual_x[range.clone()],
                        &mut actual_y[range.clone()],
                        c,
                    );
                    let mut expected = x.clone();
                    expected[range.clone()].copy_from_slice(&layout(&expected_x));
                    assert_eq!(actual_x, expected);
                    let mut expected = y.clone();
                    expected[range.clone()].copy_from_slice(&layout(&expected_y));
                    assert_eq!(actual_y, expected);
                    imp.ifft_butterfly(
                        &mut actual_x[range.clone()],
                        &mut actual_y[range.clone()],
                        c,
                    );
                    assert_eq!(actual_x, x);
                    assert_eq!(actual_y, y);
                }
            }

            for shard_len in [2, 6, 126, 128, 130, 258] {
                let shard_count = 3;
                let len = shard_len * shard_count;
                let offset = 1 + shard_len / 2 % 7;
                let range = offset..offset + len;
                let mut original: [Vec<u8>; 4] =
                    std::array::from_fn(|_| vec![0xa5; offset + len + 7]);
                for quarter in &mut original {
                    rng.fill_bytes(&mut quarter[range.clone()]);
                }
                for coefficients in [
                    [GF16(0), GF16(1), GF16(0xff)],
                    [GF16(0), GF16(0x0128), GF16(0x80)],
                    [GF16(0x0100), GF16(0x84e4), GF16(0xffff)],
                ] {
                    let mut actual = original.clone();
                    let mut expected = original.clone();
                    for shard in 0..shard_count {
                        let start = offset + shard * shard_len;
                        let end = start + shard_len;
                        let mut values: [Vec<GF16>; 4] =
                            std::array::from_fn(|q| elements(&expected[q][start..end]));
                        for i in 0..shard_len / 2 {
                            let mut lanes =
                                [values[0][i], values[1][i], values[2][i], values[3][i]];
                            let apply = |lanes: &mut [GF16; 4], x: usize, y: usize, c: GF16| {
                                let mut a = lanes[x];
                                let mut b = lanes[y];
                                a += &(b * c);
                                b += &a;
                                lanes[x] = a;
                                lanes[y] = b;
                            };
                            apply(&mut lanes, 0, 2, coefficients[2]);
                            apply(&mut lanes, 1, 3, coefficients[2]);
                            apply(&mut lanes, 0, 1, coefficients[0]);
                            apply(&mut lanes, 2, 3, coefficients[1]);
                            for (values, value) in values.iter_mut().zip(lanes) {
                                values[i] = value;
                            }
                        }
                        for (quarter, values) in expected.iter_mut().zip(values) {
                            quarter[start..end].copy_from_slice(&layout(&values));
                        }
                    }
                    let [q0, q1, q2, q3] = &mut actual;
                    imp.fft_butterfly_two_layers(
                        [
                            &mut q0[range.clone()],
                            &mut q1[range.clone()],
                            &mut q2[range.clone()],
                            &mut q3[range.clone()],
                        ],
                        shard_len,
                        coefficients,
                    );
                    assert_eq!(actual, expected);
                    let [q0, q1, q2, q3] = &mut actual;
                    imp.ifft_butterfly_two_layers(
                        [
                            &mut q0[range.clone()],
                            &mut q1[range.clone()],
                            &mut q2[range.clone()],
                            &mut q3[range.clone()],
                        ],
                        shard_len,
                        coefficients,
                    );
                    assert_eq!(actual, original);
                }
            }
        }
    }

    #[test]
    fn arithmetic_and_butterflies_match_scalar() {
        TestArithmetic.call(Portable);
        with_kernel(TestArithmetic);
    }

    struct TestChecksum;

    impl WithKernel for TestChecksum {
        type Output = ();

        fn call<K: Kernel>(self, kernel: K) {
            let imp = Impl16::new(kernel);
            let mut rng = test_rng();
            let len = 3 * BLOCK_BYTES + 42;
            let symbols = len / 2;
            let mut shard_backing = vec![0xa5; len + 9];
            let shard = &mut shard_backing[1..1 + len];
            rng.fill_bytes(shard);

            for output_symbols in [16, BLOCK_SYMBOLS + 3] {
                let coefficient_len = symbols * output_symbols;
                let mut coefficient_backing = vec![0x5a; coefficient_len + 11];
                let coefficients = &mut coefficient_backing[3..3 + coefficient_len];
                rng.fill_bytes(coefficients);

                let check_range = |range: Range<usize>| {
                    let output_len = 2 * output_symbols;
                    let mut actual = vec![0xcc; output_len + 12];
                    imp.checksum_range(
                        shard,
                        coefficients,
                        range.clone(),
                        &mut actual[5..5 + output_len],
                    );
                    assert_eq!(
                        &actual[5..5 + output_len],
                        checksum_reference(shard, coefficients, range.clone(), output_symbols),
                        "range {range:?}"
                    );
                    assert!(actual[..5].iter().all(|&byte| byte == 0xcc));
                    assert!(actual[5 + output_len..].iter().all(|&byte| byte == 0xcc));
                };

                for range in [
                    0..0,
                    18..18,
                    0..len,
                    14..2 * (BLOCK_SYMBOLS + 11),
                    2 * (BLOCK_SYMBOLS - 3)..2 * (2 * BLOCK_SYMBOLS + 5),
                    2 * (2 * BLOCK_SYMBOLS + 7)..len,
                    len - 10..len,
                ] {
                    check_range(range);
                }
                for remainder in 0..=K::LANES.min(BLOCK_SYMBOLS - 1) {
                    check_range(0..2 * remainder);
                }

                let mut full = vec![0; 2 * output_symbols];
                imp.checksum_range(shard, coefficients, 0..len, &mut full);
                let partitions = [
                    0,
                    10,
                    2 * (BLOCK_SYMBOLS - 3),
                    2 * (BLOCK_SYMBOLS + 11),
                    4 * BLOCK_SYMBOLS,
                    len - 10,
                    len,
                ];
                let mut partitioned = vec![0; full.len()];
                for bounds in partitions.windows(2) {
                    let mut part = vec![0; full.len()];
                    imp.checksum_range(shard, coefficients, bounds[0]..bounds[1], &mut part);
                    imp.add_into(&mut partitioned, &part);
                }
                assert_eq!(partitioned, full);

                let invalid_tape = catch_unwind(AssertUnwindSafe(|| {
                    imp.checksum_range(
                        shard,
                        &coefficients[..coefficients.len() - 1],
                        0..len,
                        &mut vec![0; full.len()],
                    );
                }));
                assert!(invalid_tape.is_err());
                let invalid_range = catch_unwind(AssertUnwindSafe(|| {
                    imp.checksum_range(shard, coefficients, 1..len, &mut vec![0; full.len()]);
                }));
                assert!(invalid_range.is_err());
            }
        }
    }

    #[test]
    fn checksums_match_scalar_and_partition() {
        TestChecksum.call(Portable);
        with_kernel(TestChecksum);
    }

    struct TestChecksumCommutation;

    impl WithKernel for TestChecksumCommutation {
        type Output = ();

        fn call<K: Kernel>(self, kernel: K) {
            const OUTPUT_SYMBOLS: usize = 4;
            let imp = Impl16::new(kernel);
            let mut rng = test_rng();
            let symbols = K::LANES + 3;
            let mut original = vec![vec![0; 2 * symbols]; 5];
            for shard in &mut original {
                rng.fill_bytes(shard);
            }
            let mut coefficients = vec![0; symbols * OUTPUT_SYMBOLS];
            rng.fill_bytes(&mut coefficients);
            let encoder = Encoder::new(imp);
            let strategy = Rayon::new(NZUsize!(4)).unwrap().manual();
            let original_refs: Vec<_> = original.iter().map(Vec::as_slice).collect();
            let recovery = encoder.encode(&original_refs, 3, &strategy);
            let checksums: Vec<_> = original
                .iter()
                .map(|shard| {
                    let mut out = vec![0; 2 * OUTPUT_SYMBOLS];
                    imp.checksum_range(shard, &coefficients, 0..shard.len(), &mut out);
                    out
                })
                .collect();
            let checksum_refs: Vec<_> = checksums.iter().map(Vec::as_slice).collect();
            let encoded_checksums = encoder.encode(&checksum_refs, 3, &strategy);
            for (shard, expected) in recovery.iter().zip(encoded_checksums) {
                let mut actual = vec![0; 2 * OUTPUT_SYMBOLS];
                imp.checksum_range(shard, &coefficients, 0..shard.len(), &mut actual);
                assert_eq!(actual, expected);
            }
        }
    }

    #[test]
    fn checksums_commute_with_encoding() {
        with_kernel(TestChecksumCommutation);
    }

    struct TestCodeEdges;

    impl WithKernel for TestCodeEdges {
        type Output = ();

        fn call<K: Kernel>(self, kernel: K) {
            let imp = Impl16::new(kernel);
            let encoder = Encoder::new(imp);
            let decoder = Decoder::new(imp);
            let strategy = Rayon::new(NZUsize!(4)).unwrap().manual();
            let mut rng = test_rng();

            let len = stripe_bytes::<Impl16<K>>() + 2;
            let mut original = vec![vec![0; len]; 3];
            for shard in &mut original {
                rng.fill_bytes(shard);
            }
            let refs: Vec<_> = original.iter().map(Vec::as_slice).collect();
            let recovery = encoder.encode(&refs, 2, &strategy);
            let recovered = decoder
                .decode(
                    &[None, Some(original[1].as_slice()), None],
                    &recovery
                        .iter()
                        .map(|shard| Some(shard.as_slice()))
                        .collect::<Vec<_>>(),
                    &strategy,
                )
                .unwrap();
            assert_eq!(
                recovered,
                vec![(0, original[0].clone()), (2, original[2].clone())]
            );

            let mut original = vec![vec![0; 4096 + BLOCK_BYTES + 2]; 67];
            for shard in &mut original {
                rng.fill_bytes(shard);
            }
            let refs: Vec<_> = original.iter().map(Vec::as_slice).collect();
            let recovery = encoder.encode(&refs, 33, &strategy);
            let mut available: Vec<_> = refs.iter().copied().map(Some).collect();
            available[0] = None;
            available[66] = None;
            let recovered = decoder
                .decode(
                    &available,
                    &recovery
                        .iter()
                        .map(|shard| Some(shard.as_slice()))
                        .collect::<Vec<_>>(),
                    &strategy,
                )
                .unwrap();
            assert_eq!(
                recovered,
                vec![(0, original[0].clone()), (66, original[66].clone())]
            );

            for (k, r) in [(257, 2), (u16::MAX as usize, 1)] {
                let mut original = vec![vec![0; 2]; k];
                for shard in &mut original {
                    rng.fill_bytes(shard);
                }
                let refs: Vec<_> = original.iter().map(Vec::as_slice).collect();
                let recovery = encoder.encode(&refs, r, &strategy);
                let mut available: Vec<_> = original
                    .iter()
                    .map(|shard| Some(shard.as_slice()))
                    .collect();
                available[k - 1] = None;
                let recovered = decoder
                    .decode(
                        &available,
                        &recovery
                            .iter()
                            .map(|shard| Some(shard.as_slice()))
                            .collect::<Vec<_>>(),
                        &strategy,
                    )
                    .unwrap();
                assert_eq!(recovered, vec![(k - 1, original[k - 1].clone())]);
            }
        }
    }

    #[test]
    fn code_handles_stripe_tails_and_field_boundaries() {
        with_kernel(TestCodeEdges);
    }
}
