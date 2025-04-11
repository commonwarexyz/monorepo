#![allow(unused_imports)]
use commonware_cryptography::{hash, Hasher, Sha256};
use commonware_runtime::{deterministic::Executor, Runner};
use commonware_storage::mmr::bitmap::Bitmap;
use criterion::{criterion_group, Criterion};
use std::hint::black_box;

// Variant 1
fn set_bit_original(bitmap: &mut [u8], byte_offset: usize, mask: u8, bit: bool) {
    if bit {
        bitmap[byte_offset] |= mask;
    } else {
        bitmap[byte_offset] &= !mask;
    }
}

// Variant 2: Current branchless XOR
fn set_bit_xor(bitmap: &mut [u8], byte_offset: usize, mask: u8, bit: bool) {
    bitmap[byte_offset] ^= ((-(bit as i8) as u8) ^ bitmap[byte_offset]) & mask;
}

// Variant 3: Superscalar
fn set_bit_superscalar(bitmap: &mut [u8], byte_offset: usize, mask: u8, bit: bool) {
    bitmap[byte_offset] = (bitmap[byte_offset] & !mask) | ((-(bit as i8) as u8) & mask);
}

fn setup_bitmap(hasher: &mut Sha256) -> Bitmap<Sha256> {
    let mut bitmap = Bitmap::default();
    let test_digest = hash(b"test");
    bitmap.append_chunk_unchecked(hasher, &test_digest);
    bitmap.append_chunk_unchecked(hasher, &test_digest);
    bitmap.append_byte_unchecked(hasher, 0xF1);
    bitmap.append(hasher, true);
    bitmap.append(hasher, false);
    bitmap.append(hasher, true);
    bitmap
}

#[cfg(any(feature = "bench_internal"))]
fn bench_set_bit_variants(c: &mut Criterion) {
    use commonware_storage::mmr::bitmap;

    let mut group = c.benchmark_group("set_bit_variants_from_test");

    // Original branching variant
    group.bench_function("set_bit_original", |b| {
        let mut bitmap = setup_bitmap(&mut Sha256::new());
        let mut hasher = Sha256::new();
        b.iter(|| {
            for bit_pos in (0..bitmap.bit_count()).rev() {
                let bit = bitmap.get_bit(bit_pos);
                let byte_offset = bit_pos as usize / 8;
                let mask = 1 << (bit_pos % 8);
                set_bit_original(bitmap.get_bitmap_mut(), byte_offset, mask, black_box(!bit));
                let _new_root = bitmap.root(&mut hasher);
            }
        });
    });

    // Original branching xor
    group.bench_function("set_bit_xor", |b| {
        let mut bitmap = setup_bitmap(&mut Sha256::new());
        let mut hasher = Sha256::new();
        b.iter(|| {
            for bit_pos in (0..bitmap.bit_count()).rev() {
                let bit = bitmap.get_bit(bit_pos);
                let byte_offset = bit_pos as usize / 8;
                let mask = 1 << (bit_pos % 8);
                set_bit_xor(bitmap.get_bitmap_mut(), byte_offset, mask, black_box(!bit));
                let _new_root = bitmap.root(&mut hasher);
            }
        });
    });

    // Original branching superscalar
    group.bench_function("set_bit_superscalar", |b| {
        let mut bitmap = setup_bitmap(&mut Sha256::new());
        let mut hasher = Sha256::new();
        b.iter(|| {
            for bit_pos in (0..bitmap.bit_count()).rev() {
                let bit = bitmap.get_bit(bit_pos);
                let byte_offset = bit_pos as usize / 8;
                let mask = 1 << (bit_pos % 8);
                set_bit_superscalar(bitmap.get_bitmap_mut(), byte_offset, mask, black_box(!bit));
                let _new_root = bitmap.root(&mut hasher);
            }
        });
    });
}

#[cfg(any(feature = "bench_internal"))]
criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(1000);

    targets = bench_set_bit_variants
}
