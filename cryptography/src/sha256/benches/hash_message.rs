use commonware_cryptography::{Hasher, Sha256};
use commonware_parallel::Sequential;
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};
use rand::Rng;

fn bench_hash_message(c: &mut Criterion) {
    let mut sampler = test_rng();
    let cases = [8, 12, 16, 19, 20, 24].map(|i| 2usize.pow(i));
    for message_length in cases.into_iter() {
        let mut msg = vec![0u8; message_length];
        sampler.fill_bytes(msg.as_mut_slice());
        let msg = msg.as_slice();
        c.bench_function(&format!("{}/msg_len={}", module_path!(), msg.len()), |b| {
            b.iter(|| Sha256::hash(&[msg]));
        });
    }
}

fn bench_hash_many(c: &mut Criterion) {
    let mut sampler = test_rng();
    let cases = [8, 12, 14, 16, 18].map(|i| 2usize.pow(i));
    for message_length in cases {
        let mut messages: [Vec<u8>; 16] = core::array::from_fn(|_| vec![0u8; message_length]);
        for message in &mut messages {
            sampler.fill_bytes(message);
        }
        let messages = messages.each_ref().map(Vec::as_slice);

        c.bench_function(
            &format!(
                "{}::individual/count=16 len={message_length}",
                module_path!()
            ),
            |b| {
                b.iter(|| {
                    messages
                        .iter()
                        .map(|&message| Sha256::hash(&[message]))
                        .collect::<Vec<_>>()
                })
            },
        );
        c.bench_function(
            &format!("{}::many/count=16 len={message_length}", module_path!()),
            |b| b.iter(|| Sha256::hash_many(&messages, &Sequential)),
        );
    }
}

criterion_group!(benches, bench_hash_message, bench_hash_many);
