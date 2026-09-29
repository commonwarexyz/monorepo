use commonware_cryptography::Cipher;
use criterion::{Criterion, criterion_group};

fn bench_transport(c: &mut Criterion) {
    let (send, recv) = super::connect().unwrap();

    // Sealing and opening consume each cipher and return the next one.
    let (mut send, mut recv) = (Some(send), Some(recv));
    for n in [1 << 12, 1 << 16, 1 << 20] {
        let data = vec![0; n];
        c.bench_function(&format!("{}/n={}", module_path!(), n), |b| {
            b.iter(|| {
                // Copy the plaintext because sealing encrypts it in place.
                let mut buf = data.clone();
                let (next, tag) = send.take().unwrap().seal(&[], &mut buf).unwrap();
                send = Some(next);
                recv = Some(recv.take().unwrap().open(&[], &mut buf, &tag).unwrap());
                buf
            })
        });
    }
}

criterion_group!(benches, bench_transport);
