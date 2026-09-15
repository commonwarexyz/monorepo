use bytes::{Buf as _, BufMut as _};
use commonware_runtime::{IoBufMut, IoBufsMut};
use criterion::Criterion;
use std::hint::black_box;

pub fn bench(c: &mut Criterion) {
    for chunks in [1, 4, 16, 256] {
        for (position, readable) in [("front", 0), ("back", chunks - 1), ("empty", chunks)] {
            let bufs = IoBufsMut::from(
                (0..chunks)
                    .map(|index| {
                        let mut buf = IoBufMut::with_capacity(8);
                        if index == readable {
                            buf.put_u8(1);
                        }
                        buf
                    })
                    .collect::<Vec<_>>(),
            );
            c.bench_function(
                &format!("{}/chunks={chunks} readable={position}", module_path!()),
                |b| b.iter(|| black_box(black_box(&bufs).has_remaining())),
            );
        }
    }
}
