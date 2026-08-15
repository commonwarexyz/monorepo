//! Model-based fuzzing for ordinary-to-atomic migration.
//!
//! Every attempt runs in its own deterministic runtime cycle. The faulty storage wrapper injects
//! errors immediately before or after the in-memory replacement, which are the two crash-visible
//! migration outcomes: the durable ordinary value or the complete atomic value. The next cycle
//! reopens the name, validates the selected outcome, and may retry. A final fault-free retry and
//! atomic append prove that every trace leaves a usable migrated blob.

#![cfg_attr(not(test), no_main)]

use arbitrary::{Arbitrary, Unstructured};
use commonware_runtime::{
    ATOMIC_BLOB_TAG_LEN, AtomicBlob as _, AtomicStorage as _, Blob as _, DEFAULT_BLOB_VERSION,
    IntegrityScheme, Runner as _, Storage as _, WriteOptions,
    deterministic::{self, FaultConfig},
};
#[cfg(not(test))]
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;

const PARTITION: &str = "atomic-migration-fuzz";
const NAME: &[u8] = b"blob";
const MAX_ATTEMPTS: usize = 8;
const MAX_PAYLOAD_LEN: usize = 256;
const FINAL_BYTE: u8 = 0xA5;

#[derive(Arbitrary, Clone, Copy, Debug, Eq, PartialEq)]
enum MigrationFault {
    None,
    BeforeCommit,
    AfterCommit,
}

impl MigrationFault {
    fn config(self) -> FaultConfig {
        match self {
            Self::None => FaultConfig::default(),
            Self::BeforeCommit => FaultConfig::default().migrate(1.0),
            Self::AfterCommit => FaultConfig::default().migrate_post_commit(1.0),
        }
    }
}

#[derive(Debug)]
struct FuzzInput {
    seed: u64,
    use_default_version: bool,
    version: u16,
    attempts: Vec<MigrationFault>,
    payload: Vec<u8>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let seed = u.arbitrary()?;
        let use_default_version = u.arbitrary()?;
        let version = u.arbitrary()?;
        let attempt_count = u.int_in_range(0..=MAX_ATTEMPTS)?;
        let attempts = (0..attempt_count)
            .map(|_| u.arbitrary())
            .collect::<Result<Vec<_>, _>>()?;
        let payload_len = u.int_in_range(0..=MAX_PAYLOAD_LEN)?;
        let payload = u.bytes(payload_len)?.to_vec();
        Ok(Self {
            seed,
            use_default_version,
            version,
            attempts,
            payload,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Layout {
    Ordinary,
    Atomic,
}

fn source_version(input: &FuzzInput) -> u16 {
    if input.use_default_version {
        DEFAULT_BLOB_VERSION
    } else if input.version == DEFAULT_BLOB_VERSION {
        input.version ^ 1
    } else {
        input.version
    }
}

fn disable_faults(context: &deterministic::Context) {
    *context.storage_fault_config().write() = FaultConfig::default();
}

async fn assert_layout(
    context: &deterministic::Context,
    layout: Layout,
    source_version: u16,
    payload: &[u8],
) {
    match layout {
        Layout::Ordinary => {
            let (blob, len, version) = context
                .open_versioned(PARTITION, NAME, u16::MIN..=u16::MAX)
                .await
                .expect("reopen durable ordinary migration source");
            assert_eq!(len, payload.len() as u64);
            assert_eq!(version, source_version);
            if !payload.is_empty() {
                assert_eq!(
                    blob.read_at(0, payload.len())
                        .await
                        .expect("read durable ordinary migration source")
                        .coalesce()
                        .as_ref(),
                    payload
                );
            }
        }
        Layout::Atomic => {
            let (blob, len) = context
                .open_atomic(PARTITION, NAME)
                .await
                .expect("reopen complete atomic migration result");
            assert_eq!(len, payload.len() as u64);
            if !payload.is_empty() {
                assert_eq!(
                    blob.read_at(0, payload.len())
                        .await
                        .expect("read complete atomic migration result")
                        .coalesce()
                        .as_ref(),
                    payload
                );
            }
            let snapshot = blob
                .integrity_snapshot()
                .await
                .expect("snapshot migrated integrity state");
            assert_eq!(snapshot.encoded_len, payload.len() as u64);
            assert_eq!(snapshot.scheme, IntegrityScheme::Unbound);
            assert_eq!(snapshot.tag, [0; ATOMIC_BLOB_TAG_LEN]);
        }
    }
}

fn migrate_once(
    runner: deterministic::Runner,
    expected: Layout,
    source_version: u16,
    payload: Arc<[u8]>,
    fault: MigrationFault,
) -> (Layout, deterministic::Checkpoint) {
    let (result, checkpoint) = runner.start_and_recover(move |context| async move {
        disable_faults(&context);
        assert_layout(&context, expected, source_version, &payload).await;
        let (blob, _, _) = context
            .open_versioned(PARTITION, NAME, u16::MIN..=u16::MAX)
            .await
            .expect("open fresh migration source");
        *context.storage_fault_config().write() = fault.config();
        context.migrate_atomic(blob).await
    });

    match fault {
        MigrationFault::None => assert!(result.is_ok(), "fault-free migration failed: {result:?}"),
        MigrationFault::BeforeCommit | MigrationFault::AfterCommit => {
            assert!(result.is_err(), "injected migration fault did not fire")
        }
    }
    let expected = match fault {
        MigrationFault::BeforeCommit => expected,
        MigrationFault::None | MigrationFault::AfterCommit => Layout::Atomic,
    };
    (expected, checkpoint)
}

fn run(input: FuzzInput) {
    let source_version = source_version(&input);
    let payload: Arc<[u8]> = input.payload.into();
    let initial_payload = payload.clone();
    let (_, mut checkpoint) =
        deterministic::Runner::seeded(input.seed).start_and_recover(move |context| async move {
            disable_faults(&context);
            let (blob, _, version) = context
                .open_versioned(PARTITION, NAME, source_version..=source_version)
                .await
                .expect("create ordinary migration source");
            assert_eq!(version, source_version);
            blob.write_at(0, initial_payload.to_vec(), WriteOptions::default())
                .await
                .expect("write ordinary migration source");
            blob.sync()
                .await
                .expect("make ordinary migration source durable");
        });

    let mut expected = Layout::Ordinary;
    for fault in input.attempts {
        (expected, checkpoint) = migrate_once(
            deterministic::Runner::from(checkpoint),
            expected,
            source_version,
            payload.clone(),
            fault,
        );
    }

    // Every generated trace ends with a fresh, fault-free retry. This also exercises idempotent
    // migration when an earlier post-commit error already installed the atomic image.
    (expected, checkpoint) = migrate_once(
        deterministic::Runner::from(checkpoint),
        expected,
        source_version,
        payload.clone(),
        MigrationFault::None,
    );
    assert_eq!(expected, Layout::Atomic);

    let mutation_payload = payload.clone();
    let (_, checkpoint) =
        deterministic::Runner::from(checkpoint).start_and_recover(move |context| async move {
            disable_faults(&context);
            assert_layout(&context, Layout::Atomic, source_version, &mutation_payload).await;
            let (blob, _) = context
                .open_atomic(PARTITION, NAME)
                .await
                .expect("open migrated blob for a final mutation");
            let offset = blob
                .append(vec![FINAL_BYTE])
                .await
                .expect("append to migrated blob");
            assert_eq!(offset, mutation_payload.len() as u64);
            blob.sync().await.expect("publish final migrated append");
        });

    let mut final_payload = payload.to_vec();
    final_payload.push(FINAL_BYTE);
    deterministic::Runner::from(checkpoint).start(move |context| async move {
        disable_faults(&context);
        assert_layout(&context, Layout::Atomic, source_version, &final_payload).await;
    });
}

#[cfg(not(test))]
fuzz_target!(|input: FuzzInput| {
    run(input);
});

#[cfg(test)]
mod tests {
    use super::*;

    fn input(version: u16, payload: &[u8], attempts: Vec<MigrationFault>) -> FuzzInput {
        FuzzInput {
            seed: 0xA701_C001,
            use_default_version: version == DEFAULT_BLOB_VERSION,
            version,
            attempts,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn retries_a_precommit_failure_after_restart() {
        run(input(7, b"ordinary", vec![MigrationFault::BeforeCommit]));
    }

    #[test]
    fn retries_a_postcommit_failure_after_restart() {
        run(input(
            DEFAULT_BLOB_VERSION,
            b"atomic",
            vec![MigrationFault::AfterCommit],
        ));
    }

    #[test]
    fn repeated_failures_and_retries_preserve_an_empty_value() {
        run(input(
            9,
            b"",
            vec![
                MigrationFault::BeforeCommit,
                MigrationFault::BeforeCommit,
                MigrationFault::AfterCommit,
                MigrationFault::BeforeCommit,
                MigrationFault::None,
                MigrationFault::AfterCommit,
            ],
        ));
    }
}
