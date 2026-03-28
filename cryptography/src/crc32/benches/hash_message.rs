use commonware_cryptography::{crc32::Crc32, Hasher};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};

#[cfg(feature = "isa-l")]
use core::ffi::{c_uchar, c_uint};

#[cfg(feature = "isa-l")]
unsafe extern "C" {
    fn crc32_iscsi(buffer: *mut c_uchar, len: i32, crc_init: c_uint) -> c_uint;
}

#[cfg(feature = "isa-l")]
fn isa_l_checksum(data: &[u8]) -> u32 {
    if data.is_empty() {
        return 0;
    }
    let mut state = u32::MAX;
    let mut remaining = data;
    while !remaining.is_empty() {
        let len = remaining.len().min(i32::MAX as usize);
        let (chunk, rest) = remaining.split_at(len);
        // SAFETY: the buffer is valid for `len` bytes and ISA-L only reads it.
        state = unsafe { crc32_iscsi(chunk.as_ptr() as *mut c_uchar, len as i32, state as c_uint) }
            as u32;
        remaining = rest;
    }
    !state
}

#[cfg(feature = "isa-l")]
fn crc_fast_checksum(data: &[u8]) -> u32 {
    crc_fast::checksum(crc_fast::CrcAlgorithm::Crc32Iscsi, data) as u32
}

#[cfg(not(feature = "isa-l"))]
fn crc_fast_checksum(data: &[u8]) -> u32 {
    Crc32::checksum(data)
}

fn bench_hash_message(c: &mut Criterion) {
    let mut sampler = StdRng::seed_from_u64(0);
    let cases = [8, 12, 16, 19, 20, 24].map(|i| 2usize.pow(i));
    for message_length in cases.into_iter() {
        let mut msg = vec![0u8; message_length];
        sampler.fill_bytes(msg.as_mut_slice());
        let msg = msg.into_boxed_slice();

        c.bench_function(
            &format!("{}/backend=commonware msg_len={message_length}", module_path!()),
            |b| {
                b.iter(|| {
                    let mut hasher = Crc32::new();
                    hasher.update(&msg);
                    hasher.finalize();
                });
            },
        );

        c.bench_function(
            &format!("{}/backend=crc_fast msg_len={message_length}", module_path!()),
            |b| b.iter(|| crc_fast_checksum(&msg)),
        );

        #[cfg(feature = "isa-l")]
        c.bench_function(
            &format!("{}/backend=isa_l msg_len={message_length}", module_path!()),
            |b| b.iter(|| isa_l_checksum(&msg)),
        );
    }
}

criterion_group!(benches, bench_hash_message);
