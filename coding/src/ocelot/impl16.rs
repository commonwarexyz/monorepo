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

    fn sub_into(self, dst: &mut [u8], src: &[u8]) {
        self.add_into(dst, src);
    }

    fn mul_add(self, dst: &mut [u8], src: &[u8], c: GF16) {
        assert!(src.len().is_multiple_of(2), "shard length is not aligned");
        // Subfield coefficients multiply both byte planes independently.
        if let Some(c) = c.subfield() {
            return Impl8::new(self.kernel).mul_add(dst, src, c);
        }
        self.kernel.run(MulAdd::<true> { dst, src, c });
    }

    fn mul_into(self, dst: &mut [u8], src: &[u8], c: GF16) {
        assert!(src.len().is_multiple_of(2), "shard length is not aligned");
        // Subfield coefficients multiply both byte planes independently.
        if let Some(c) = c.subfield() {
            return Impl8::new(self.kernel).mul_into(dst, src, c);
        }
        self.kernel.run(MulAdd::<false> { dst, src, c });
    }

    fn mul_sub(self, dst: &mut [u8], src: &[u8], c: GF16) {
        self.mul_add(dst, src, c);
    }

    fn derivative_four(self, quarters: [&mut [u8]; 4]) {
        Impl8::new(self.kernel).derivative_four(quarters);
    }

    fn derivative_sixteen(self, blocks: [&mut [u8]; 16]) {
        Impl8::new(self.kernel).derivative_sixteen(blocks);
    }

    fn fft_butterfly(self, x: &mut [u8], y: &mut [u8], c: GF16) {
        assert!(x.len().is_multiple_of(2), "shard length is not aligned");
        if let Some(c) = c.subfield() {
            return Impl8::new(self.kernel).fft_butterfly(x, y, c);
        }
        self.kernel.run(Butterfly::<false> { x, y, c });
    }

    fn ifft_butterfly(self, x: &mut [u8], y: &mut [u8], c: GF16) {
        assert!(x.len().is_multiple_of(2), "shard length is not aligned");
        if let Some(c) = c.subfield() {
            return Impl8::new(self.kernel).ifft_butterfly(x, y, c);
        }
        self.kernel.run(Butterfly::<true> { x, y, c });
    }

    fn fft_butterfly_two_layers(
        self,
        quarters: [&mut [u8]; 4],
        shard_len: usize,
        coefficients: [GF16; 3],
    ) {
        if let [Some(c0), Some(c1), Some(c2)] = coefficients.map(GF16::subfield) {
            return Impl8::new(self.kernel).fft_butterfly_two_layers(
                quarters,
                shard_len,
                [c0, c1, c2],
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
        if let [Some(c0), Some(c1), Some(c2)] = coefficients.map(GF16::subfield) {
            return Impl8::new(self.kernel).ifft_butterfly_two_layers(
                quarters,
                shard_len,
                [c0, c1, c2],
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

impl WithKernel for ChecksumRange<'_> {
    type Output = ();

    #[inline(always)]
    fn call<K: Kernel>(self, kernel: K) {
        const {
            assert!(K::LANES > 0 && K::LANES <= BLOCK_SYMBOLS);
        }
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
        let zero = kernel.load(&zero[..K::LANES]);
        for (output_block, out) in out.chunks_mut(BLOCK_BYTES).enumerate() {
            let block_symbols = out.len() / 2;
            let (out_lo, out_hi) = out.split_at_mut(block_symbols);
            for (lane, (out_lo, out_hi)) in out_lo.iter_mut().zip(out_hi).enumerate() {
                let output = output_block * BLOCK_SYMBOLS + lane;
                let row = &coefficients[output * symbols..(output + 1) * symbols];
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

/// Fuzz plans for the GF(2^16) coding implementation.
#[cfg(any(test, feature = "fuzz"))]
pub mod fuzz {
    use super::*;
    use crate::ocelot::{
        code::test_suites::{
            DefaultImpl, ImplPlan, fuzz_code, fuzz_impl, fuzz_impl_matches_reference,
        },
        kernel::{portable::Portable, with_kernel},
    };
    use arbitrary::{Arbitrary, Unstructured};

    const OCELOT16: Impl16<Portable> = Impl16::new(Portable);

    /// A bounded property check for the GF(2^16) implementation.
    #[derive(Debug, Arbitrary)]
    pub enum Plan {
        /// Check portable encoding and erasure recovery.
        PortableCode,
        /// Check a specialized implementation method against scalar arithmetic.
        Implementation(ImplPlan),
        /// Check the default-method adapter against scalar arithmetic.
        DefaultMethods(ImplPlan),
        /// Compare the dispatched implementation with the portable implementation.
        DispatchedDifferential(ImplPlan),
    }

    impl Plan {
        /// Run this fuzz plan using additional structured input from `u`.
        pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
            match self {
                Self::PortableCode => fuzz_code(u, OCELOT16),
                Self::Implementation(plan) => fuzz_impl(
                    u,
                    OCELOT16,
                    plan,
                    2 * Portable::LANES,
                    elements,
                    layout,
                    |coefficient| GF16(u16::from(coefficient)),
                ),
                Self::DefaultMethods(plan) => fuzz_impl(
                    u,
                    DefaultImpl(OCELOT16),
                    plan,
                    2 * Portable::LANES,
                    elements,
                    layout,
                    |coefficient| GF16(u16::from(coefficient)),
                ),
                Self::DispatchedDifferential(plan) => with_kernel(FuzzImplDifferential { u, plan }),
            }
        }
    }

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

    struct FuzzImplDifferential<'a, 'b> {
        u: &'a mut Unstructured<'b>,
        plan: ImplPlan,
    }

    impl WithKernel for FuzzImplDifferential<'_, '_> {
        type Output = arbitrary::Result<()>;

        fn call<K: Kernel>(self, kernel: K) -> Self::Output {
            fuzz_impl_matches_reference(
                self.u,
                Impl16::new(kernel),
                OCELOT16,
                self.plan,
                2 * K::LANES,
                elements,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ocelot::{
        code::test_suites::ImplPlan, impl16::fuzz::Plan, kernel::portable::Portable,
    };

    #[test]
    fn minifuzz_code() {
        commonware_invariants::minifuzz::Builder::default()
            .with_seed(0)
            .with_search_limit(100)
            .test(|u| Plan::PortableCode.run(u));
    }

    #[test]
    fn minifuzz_impl_contract() {
        for plan in ImplPlan::ALL {
            commonware_invariants::minifuzz::Builder::default()
                .with_seed(0)
                .with_search_limit(100)
                .test(|u| Plan::Implementation(plan).run(u));
        }
    }

    #[test]
    fn minifuzz_default_methods() {
        for plan in ImplPlan::DEFAULTS {
            commonware_invariants::minifuzz::Builder::default()
                .with_seed(0)
                .with_search_limit(100)
                .test(|u| Plan::DefaultMethods(plan).run(u));
        }
    }

    #[test]
    fn minifuzz_impl_matches_portable() {
        eprintln!(
            "Ocelot GF16 differential backend: {}",
            crate::ocelot::kernel::selected_name()
        );
        for plan in ImplPlan::ALL {
            commonware_invariants::minifuzz::Builder::default()
                .with_seed(0)
                .with_search_limit(100)
                .test(|u| Plan::DispatchedDifferential(plan).run(u));
        }
    }

    #[test]
    fn cantor_basis_is_linearly_independent() {
        let basis = <Impl16<Portable> as Impl>::basis();
        assert_eq!(basis.len(), <Impl16<Portable> as Impl>::BITS);
        assert_eq!(basis[0], GF16(1));
        for pair in basis.windows(2) {
            assert_eq!(pair[1] * pair[1] + pair[1], pair[0]);
        }

        let mut pivots = [0u16; 16];
        for value in basis {
            let mut value = value.0;
            while value != 0 {
                let bit = value.ilog2() as usize;
                if pivots[bit] == 0 {
                    pivots[bit] = value;
                    break;
                }
                value ^= pivots[bit];
            }
            assert_ne!(value, 0);
        }
    }
}
