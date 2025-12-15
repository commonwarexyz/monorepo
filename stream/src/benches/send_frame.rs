use commonware_runtime::{benchmarks::tokio, mocks, Stream as _};
use commonware_stream::utils::codec::{send_frame, BufferedSender};
use criterion::{criterion_group, Criterion, Throughput};
use rand::{Rng, RngCore, SeedableRng as _};
use rand_chacha::ChaCha8Rng;
use std::time::{Duration, Instant};

/// Maximum message size for benchmarks.
const MAX_MESSAGE_SIZE: usize = 2usize.pow(17);

fn generate_message_sizes(
    rng: &mut ChaCha8Rng,
    count: usize,
    min: usize,
    max: usize,
) -> Vec<usize> {
    (0..count).map(|_| rng.gen_range(min..=max)).collect()
}

fn generate_messages(rng: &mut ChaCha8Rng, sizes: &[usize]) -> Vec<Vec<u8>> {
    sizes
        .iter()
        .map(|&size| {
            let mut data = vec![0u8; size];
            rng.fill_bytes(&mut data);
            data
        })
        .collect()
}

fn bench_send_frame(c: &mut Criterion) {
    let runner = tokio::Runner::default();

    // Test different traffic patterns
    let patterns = [
        (32, 256, 5000),     // Small control messages
        (1024, 65536, 5000), // Large data messages
        (64, 8192, 5000),    // Typical mix
    ];

    for (min_size, max_size, count) in patterns {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let sizes = generate_message_sizes(&mut rng, count, min_size, max_size);
        let messages = generate_messages(&mut rng, &sizes);
        let total_bytes: usize = sizes.iter().sum();

        let mut group = c.benchmark_group(module_path!());
        group.throughput(Throughput::Bytes(total_bytes as u64));

        let bench_name = move |method: &str| {
            format!("{method}/num_messages={count} min_size={min_size} max_size={max_size}",)
        };
        group.bench_function(bench_name("unbuffered_sender"), |b| {
            b.to_async(&runner).iter_custom(|iters| {
                let messages = messages.clone();
                async move {
                    let mut duration = Duration::ZERO;

                    for _ in 0..iters {
                        let (mut sink, mut stream) = mocks::Channel::init();

                        let start = Instant::now();
                        for msg in messages.iter() {
                            send_frame(&mut sink, msg, MAX_MESSAGE_SIZE).await.unwrap();
                        }
                        duration += start.elapsed();

                        // drain
                        for msg in messages.iter() {
                            let _ = stream.recv(vec![0u8; 4 + msg.len()]).await;
                        }
                    }

                    duration
                }
            });
        });

        group.bench_function(bench_name("buffered_sender"), |b| {
            b.to_async(&runner).iter_custom(|iters| {
                let messages = messages.clone();
                async move {
                    let mut duration = Duration::ZERO;

                    for _ in 0..iters {
                        let (sink, mut stream) = mocks::Channel::init();
                        let mut sender = BufferedSender::new(sink, MAX_MESSAGE_SIZE);

                        let start = Instant::now();
                        for msg in messages.iter() {
                            sender.send_frame(msg).await.unwrap();
                        }
                        duration += start.elapsed();

                        // drain
                        for msg in messages.iter() {
                            let _ = stream.recv(vec![0u8; 4 + msg.len()]).await;
                        }
                    }

                    duration
                }
            });
        });

        group.finish();
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = bench_send_frame
}
