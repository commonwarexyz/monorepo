// First, let's define both implementations

#[allow(dead_code)]
pub struct MyStruct([u8; 8 + 1]);

impl MyStruct {
    pub fn new_slice(prefix: u8, value: u64) -> Self {
        let mut arr = [0; 8 + 1];
        arr[0] = prefix;
        arr[1..].copy_from_slice(&value.to_be_bytes());
        Self(arr)
    }

    pub fn new_loop(prefix: u8, value: u64) -> Self {
        let mut arr = [0; 9];
        arr[0] = prefix;

        let value_bytes = value.to_be_bytes();
        let arr_ptr = unsafe { arr.as_mut_ptr().add(1) as *mut [u8; 8]};
        unsafe {
            *arr_ptr = value_bytes;
        }

        Self(arr)
    }
}

use std::hint::black_box;

use criterion::{criterion_group, Criterion};

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("new_slice", |b| {
        b.iter(|| MyStruct::new_slice(black_box(42), black_box(12345678)))
    });

    c.bench_function("new_loop", |b| {
        b.iter(|| MyStruct::new_loop(black_box(42), black_box(12345678)))
    });
}

criterion_group!(benches, criterion_benchmark);
