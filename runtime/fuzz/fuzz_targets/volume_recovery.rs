//! Fuzz `Volume` recovery at exact inner-storage I/O failure cut points.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_runtime::{
    deterministic::{self, FaultConfig},
    Blob as _, Runner as _, Storage as _,
};
use libfuzzer_sys::fuzz_target;

const PARTITION: &str = "volume_recovery_fuzz";
const NAMES: [&[u8]; 2] = [b"a", b"b"];
const MAX_OPERATIONS: usize = 48;
const MAX_SIZE: usize = 5 * 4096 + 127;

#[derive(Debug)]
struct FuzzInput {
    seed: u64,
    fail_after: u16,
    partial_progress: bool,
    crash_fan: bool,
    operations: Vec<Operation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let count = u.int_in_range(0..=MAX_OPERATIONS)?;
        let operations = (0..count)
            .map(|_| Operation::arbitrary(u))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            seed: u.arbitrary()?,
            fail_after: u.arbitrary()?,
            partial_progress: u.arbitrary()?,
            crash_fan: u.arbitrary()?,
            operations,
        })
    }
}

#[derive(Arbitrary, Debug)]
enum Operation {
    Write {
        blob: bool,
        offset: u16,
        len: u8,
        value: u8,
    },
    WriteAtSync {
        blob: bool,
        offset: u16,
        len: u8,
        value: u8,
    },
    Resize {
        blob: bool,
        len: u16,
    },
    Prune {
        blob: bool,
        offset: u16,
    },
    Sync {
        blob: bool,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct BlobState {
    bytes: Vec<u8>,
    floor: usize,
}

impl BlobState {
    fn write(&mut self, offset: usize, len: usize, value: u8) -> (usize, Vec<u8>) {
        if self.floor == MAX_SIZE {
            return (MAX_SIZE, Vec::new());
        }
        let offset = self.floor + offset % (MAX_SIZE - self.floor);
        let len = len.max(1).min(MAX_SIZE - offset);
        let data = vec![value; len];
        if self.bytes.len() < offset + len {
            self.bytes.resize(offset + len, 0);
        }
        self.bytes[offset..offset + len].copy_from_slice(&data);
        (offset, data)
    }

    fn resize(&mut self, len: usize) -> usize {
        let len = self.floor + len % (MAX_SIZE + 1 - self.floor);
        self.bytes.resize(len, 0);
        len
    }

    fn prune(&mut self, offset: usize) -> usize {
        let offset = self.floor + offset % (self.bytes.len() + 1 - self.floor);
        self.floor = offset;
        offset
    }
}

fn selected(blob: bool) -> usize {
    usize::from(blob)
}

fn candidate_for(stable: &[BlobState; 2], current: &[BlobState; 2], blob: usize) -> [BlobState; 2] {
    let mut candidate = stable.clone();
    candidate[blob] = current[blob].clone();
    candidate
}

fn equivalent(actual: &[BlobState; 2], expected: &[BlobState; 2]) -> bool {
    actual.iter().zip(expected).all(|(actual, expected)| {
        actual.floor == expected.floor
            && actual.bytes.len() == expected.bytes.len()
            && actual.bytes[actual.floor..] == expected.bytes[expected.floor..]
    })
}

fn fuzz(input: FuzzInput) {
    let config = deterministic::Config::default()
        .with_seed(input.seed)
        .with_storage_crash_fan(input.crash_fan);
    let runner = deterministic::Runner::new(config);

    let ((stable, possible), checkpoint) = runner.start_and_recover(|context| async move {
        let (blob_a, _) = context.open(PARTITION, NAMES[0]).await.unwrap();
        let (blob_b, _) = context.open(PARTITION, NAMES[1]).await.unwrap();
        let blobs = [blob_a, blob_b];

        for (index, blob) in blobs.iter().enumerate() {
            let baseline = vec![0x40 + index as u8; 64];
            blob.write_at(0, baseline).await.unwrap();
            blob.sync().await.unwrap();
        }

        let mut stable = [
            BlobState {
                bytes: vec![0x40; 64],
                floor: 0,
            },
            BlobState {
                bytes: vec![0x41; 64],
                floor: 0,
            },
        ];
        let mut current = stable.clone();
        let schedule = FaultConfig::default()
            .fail_after(u64::from(input.fail_after))
            .partial_write(f64::from(input.partial_progress))
            .partial_resize(f64::from(input.partial_progress));
        *context.storage_fault_config().write() = schedule;

        let mut possible = None;
        for operation in input.operations {
            let (blob, candidate, result) = match operation {
                Operation::Write {
                    blob,
                    offset,
                    len,
                    value,
                } => {
                    let index = selected(blob);
                    let (offset, data) = current[index].write(offset.into(), len.into(), value);
                    (
                        index,
                        None,
                        blobs[index].write_at(offset as u64, data).await,
                    )
                }
                Operation::WriteAtSync {
                    blob,
                    offset,
                    len,
                    value,
                } => {
                    let index = selected(blob);
                    let (offset, data) = current[index].write(offset.into(), len.into(), value);
                    let candidate = candidate_for(&stable, &current, index);
                    (
                        index,
                        Some(candidate),
                        blobs[index].write_at_sync(offset as u64, data).await,
                    )
                }
                Operation::Resize { blob, len } => {
                    let index = selected(blob);
                    let len = current[index].resize(len.into());
                    (index, None, blobs[index].resize(len as u64).await)
                }
                Operation::Prune { blob, offset } => {
                    let index = selected(blob);
                    let offset = current[index].prune(offset.into());
                    (index, None, blobs[index].prune(offset as u64).await)
                }
                Operation::Sync { blob } => {
                    let index = selected(blob);
                    let candidate = candidate_for(&stable, &current, index);
                    (index, Some(candidate), blobs[index].sync().await)
                }
            };

            match result {
                Ok(()) => {
                    if candidate.is_some() {
                        stable[blob] = current[blob].clone();
                    }
                }
                Err(_) => {
                    possible = candidate;
                    break;
                }
            }
        }

        // Recovery itself is checked without fault injection. The one-shot
        // schedule may not have fired if the generated history was short.
        *context.storage_fault_config().write() = FaultConfig::default();
        (stable, possible)
    });

    deterministic::Runner::from(checkpoint).start(|context| async move {
        let names = context.scan(PARTITION).await.unwrap();
        assert_eq!(names, NAMES.map(<[u8]>::to_vec));

        let mut actual = [BlobState::default(), BlobState::default()];
        for (index, name) in NAMES.iter().enumerate() {
            let (blob, size) = context.open(PARTITION, name).await.unwrap();
            let floor = blob.floor() as usize;
            let mut bytes = vec![0; size as usize];
            if floor < bytes.len() {
                let readable = blob
                    .read_at(floor as u64, bytes.len() - floor)
                    .await
                    .unwrap()
                    .coalesce();
                bytes[floor..].copy_from_slice(readable.as_ref());
            }
            actual[index] = BlobState { bytes, floor };
        }

        assert!(
            equivalent(&actual, &stable)
                || possible
                    .as_ref()
                    .is_some_and(|possible| equivalent(&actual, possible)),
            "recovery returned a state outside the commit oracle: actual={actual:?}, stable={stable:?}, possible={possible:?}"
        );
    });
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = FuzzInput::arbitrary(&mut unstructured) else {
        return;
    };
    fuzz(input);
});
