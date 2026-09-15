use bytes::Bytes;
use commonware_codec::{Buf, Read, ReadExt as _, varint::UInt};
use commonware_runtime::{IoBuf, IoBufs};
use criterion::{BatchSize, Criterion};
use std::hint::black_box;

const VALUES: usize = 1024;

fn bench_input<B: Buf + Clone>(c: &mut Criterion, input: &str, chunks: usize, source: B) {
    for mode in ["scalar", "vector", "array", "varint"] {
        c.bench_function(
            &format!(
                "{}/input={input} chunks={chunks} mode={mode}",
                module_path!()
            ),
            |b| {
                b.iter_batched(
                    || source.clone(),
                    |mut buf| match mode {
                        "scalar" => {
                            for _ in 0..VALUES {
                                black_box(u32::read(&mut buf).unwrap());
                            }
                        }
                        "vector" => {
                            black_box(u32::read_vec(&mut buf, VALUES, &()).unwrap());
                        }
                        "array" => {
                            black_box(u32::read_array::<VALUES>(&mut buf, &()).unwrap());
                        }
                        "varint" => {
                            for _ in 0..VALUES * 4 {
                                black_box(UInt::<u32>::read(&mut buf).unwrap());
                            }
                        }
                        _ => unreachable!(),
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
}

pub fn bench(c: &mut Criterion) {
    let data = Bytes::from(vec![1; VALUES * 4]);
    bench_input(c, "bytes", 1, data.clone());
    bench_input(c, "iobuf", 1, IoBuf::from(data.clone()));
    for chunks in [1, 4, 16, 256] {
        let len = data.len() / chunks;
        let source = IoBufs::from(
            (0..chunks)
                .map(|index| IoBuf::from(data.slice(index * len..(index + 1) * len)))
                .collect::<Vec<_>>(),
        );
        bench_input(c, "iobufs", chunks, source);
    }
}
