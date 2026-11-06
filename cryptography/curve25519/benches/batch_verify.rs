//! Throughput of the public batch-verification API across batch sizes. Each signature is from an
//! independent key over an independent 32-byte message (no key/message reuse to amortize), the
//! harder case for the underlying MSM. Fixture generation is not timed, and each [`Mode`] sets
//! what the timed region covers.

use commonware_allocator::mimalloc;
use commonware_cryptography::{BatchEntry, BatchVerifier as _, Validated as _};
use commonware_cryptography_curve25519::signing::{
    PublicKey, PublicKeyBytes, Signature, SignatureBytes, SigningKey,
};
use commonware_math::algebra::Random;
use commonware_parallel::{Rayon, Sequential, Strategy, rayon::ThreadPoolBuilder};
use commonware_utils::{TestRng, test_rng};
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_CURVE25519_BATCH_VERIFY_BENCH";
const MESSAGE_SIZE: usize = 32;

/// What the timed region covers.
#[derive(Clone, Copy)]
enum Mode {
    /// Verifying keys and signatures converted ahead of time.
    VerifyOnly,
    /// Converting the signature encodings together, then verifying with keys converted ahead of
    /// time.
    ConvertSignaturesThenVerify,
    /// Converting the key and signature encodings together, then verifying.
    ConvertThenVerify,
}

impl Mode {
    const ALL: [Self; 3] = [
        Self::VerifyOnly,
        Self::ConvertSignaturesThenVerify,
        Self::ConvertThenVerify,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::VerifyOnly => "verify_only",
            Self::ConvertSignaturesThenVerify => "convert_signatures_then_verify",
            Self::ConvertThenVerify => "convert_then_verify",
        }
    }
}

/// Valid signatures by independent keys over independent 32-byte messages, as converted keys
/// and signatures and as their encodings.
struct Batch {
    keys: Vec<PublicKey>,
    key_bytes: Vec<PublicKeyBytes>,
    signatures: Vec<Signature>,
    signature_bytes: Vec<SignatureBytes>,
    messages: Vec<Vec<u8>>,
}

impl Batch {
    /// Generates `n` signatures using the public API.
    fn generate(n: usize) -> Self {
        let mut rng = test_rng();
        let mut batch = Self {
            keys: Vec::with_capacity(n),
            key_bytes: Vec::with_capacity(n),
            signatures: Vec::with_capacity(n),
            signature_bytes: Vec::with_capacity(n),
            messages: Vec::with_capacity(n),
        };
        for i in 0..n {
            let signing_key = SigningKey::random(&mut rng);
            let mut message = vec![0u8; MESSAGE_SIZE];
            message[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let signature = signing_key.sign(NAMESPACE, &message);
            let key = signing_key.public_key();
            batch.key_bytes.push(key.clone().into());
            batch.keys.push(key);
            batch.signature_bytes.push(signature.clone().into());
            batch.signatures.push(signature);
            batch.messages.push(message);
        }
        batch
    }

    /// Runs the timed region of `mode`.
    fn run(&self, mode: Mode, rng: &mut TestRng, strategy: &impl Strategy) -> bool {
        match mode {
            Mode::VerifyOnly => verify(rng, &self.messages, &self.keys, &self.signatures, strategy),
            Mode::ConvertSignaturesThenVerify => {
                let signatures = Signature::try_from_batch(&self.signature_bytes, strategy);
                let Some(signatures) = signatures.into_iter().collect::<Option<Vec<_>>>() else {
                    return false;
                };
                verify(rng, &self.messages, &self.keys, &signatures, strategy)
            }
            Mode::ConvertThenVerify => {
                let keys = PublicKey::try_from_batch(&self.key_bytes, strategy);
                let signatures = Signature::try_from_batch(&self.signature_bytes, strategy);
                let (Some(keys), Some(signatures)) = (
                    keys.into_iter().collect::<Option<Vec<_>>>(),
                    signatures.into_iter().collect::<Option<Vec<_>>>(),
                ) else {
                    return false;
                };
                verify(rng, &self.messages, &keys, &signatures, strategy)
            }
        }
    }
}

fn verify(
    rng: &mut TestRng,
    messages: &[Vec<u8>],
    keys: &[PublicKey],
    signatures: &[Signature],
    strategy: &impl Strategy,
) -> bool {
    PublicKey::verify_batch(
        rng,
        messages,
        |i, message| BatchEntry {
            namespace: NAMESPACE,
            message,
            public_key: &keys[i],
            signature: &signatures[i],
        },
        strategy,
    )
}

/// Nested so `module_path!()` includes the crate::module separator the benchmark-name lint (and
/// the benchmark-tracking dashboard) expect.
mod verify_batch_bytes_bench {
    use super::{
        Batch, BatchSize, Criterion, Mode, Rayon, Sequential, TestRng, ThreadPoolBuilder,
        Throughput, black_box,
    };
    use commonware_utils::NZUsize;

    pub fn bench(c: &mut Criterion) {
        let mut group = c.benchmark_group(module_path!());
        for n in [1, 10, 100, 1_000, 10_000, 16_384] {
            let batch = Batch::generate(n);
            for concurrency in [1, 8, 16, 32] {
                let rayon = (concurrency > 1)
                    .then(|| Rayon::new(ThreadPoolBuilder::new(NZUsize!(concurrency))).unwrap());
                for mode in Mode::ALL {
                    group.throughput(Throughput::Elements(n as u64));
                    group.bench_function(
                        format!("sigs={n} conc={concurrency} mode={}", mode.name()),
                        |b| {
                            b.iter_batched(
                                || TestRng::new(1),
                                |mut rng| {
                                    if let Some(rayon) = rayon.as_ref() {
                                        black_box(batch.run(mode, &mut rng, rayon))
                                    } else {
                                        black_box(batch.run(mode, &mut rng, &Sequential))
                                    }
                                },
                                BatchSize::SmallInput,
                            );
                        },
                    );
                }
            }
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = verify_batch_bytes_bench::bench
}

criterion_main!(benches);
