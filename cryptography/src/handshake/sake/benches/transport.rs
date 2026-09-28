use commonware_cryptography::{ChaCha20Poly1305, Cipher};
use criterion::{Criterion, criterion_group};

fn bench_transport(c: &mut Criterion) {
    let (send, recv) = super::connect().unwrap();
    let (mut send, mut recv) = (Some(send), Some(recv));
    for n in [1 << 12, 1 << 16, 1 << 20] {
        let data = vec![0; n + ChaCha20Poly1305::TAG_SIZE];
        c.bench_function(&format!("{}/n={}", module_path!(), n), |b| {
            b.iter(|| {
                let mut buf = data.clone();
                send = Some(send.take().unwrap().seal(&[], &mut buf).unwrap());
                let (next, len) = recv.take().unwrap().open(&[], &mut buf).unwrap();
                recv = Some(next);
                len
            })
        });
    }
}

criterion_group!(benches, bench_transport);
