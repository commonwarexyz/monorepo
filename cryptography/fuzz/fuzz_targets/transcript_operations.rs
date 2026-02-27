#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::transcript::Transcript;
use libfuzzer_sys::fuzz_target;
use rand::RngCore;

const LABELS: &[&[u8]] = &[
    b"test", b"fork", b"label", b"A", b"B", b"C", b"data", b"noise",
];

const MAX_OPERATIONS: usize = 100;

#[derive(Debug, Arbitrary)]
enum TranscriptOperation {
    Commit { data: Vec<u8> },
    Append { data: Vec<u8> },
    Fork { label_index: u8, data: Vec<u8> },
    Noise { label_index: u8, output_size: u8 },
    Resume,
    Summarize,
}

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    operations: Vec<TranscriptOperation>,
    namespace: Vec<u8>,
}

fn fuzz(input: FuzzInput) {
    let mut transcript = Transcript::new(input.namespace.as_slice());

    for operation in input.operations.into_iter().take(MAX_OPERATIONS) {
        match operation {
            TranscriptOperation::Commit { data } => {
                let _ = transcript.commit(data.as_slice());
            }

            TranscriptOperation::Append { data } => {
                transcript.append(data.as_slice());
                let _ = transcript.commit(&[] as &[u8]);
            }

            TranscriptOperation::Fork { label_index, data } => {
                let label = LABELS[label_index as usize % LABELS.len()];
                let _ = transcript.commit(data.as_slice());
                let _ = transcript.fork(label);
            }

            TranscriptOperation::Noise {
                label_index,
                output_size,
            } => {
                let _ = transcript.commit(&[] as &[u8]);
                let label = LABELS[label_index as usize % LABELS.len()];
                let mut rng = transcript.noise(label);
                let mut _output = vec![0u8; output_size as usize];
                rng.fill_bytes(&mut _output);
            }

            TranscriptOperation::Resume => {
                let _ = transcript.commit(&[] as &[u8]);
                let summary = transcript.summarize();
                transcript = Transcript::resume(summary);
            }

            TranscriptOperation::Summarize => {
                let _ = transcript.commit(&[] as &[u8]);
                let _ = transcript.summarize();
            }
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
