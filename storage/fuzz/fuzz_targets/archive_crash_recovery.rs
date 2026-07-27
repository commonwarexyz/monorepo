#![no_main]

//! Crash-recovery fuzzing shared by immutable and prunable archives.
//!
//! Each `Crash` ends the current deterministic runtime without syncing the archive. Recovery must
//! retain every entry covered by the last completed archive sync and must not invent any other
//! index/value pair. Immutable restores its exact published checkpoint; Prunable may additionally
//! retain a contiguous prefix of the unsynced tail in each physical section.

use arbitrary::{Arbitrary, Unstructured};
use commonware_runtime::{Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    archive::{
        Archive as ArchiveTrait, Error, Identifier,
        immutable::{Archive as ImmutableArchive, Config as ImmutableConfig},
        prunable::{Archive as PrunableArchive, Config as PrunableConfig},
    },
    translator::EightCap,
};
use commonware_utils::{FuzzRng, NZU16, NZUsize, sequence::FixedBytes};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
};

type Key = FixedBytes<16>;
type Value = FixedBytes<32>;
type RawValue = [u8; 32];
type Model = BTreeMap<u64, RawValue>;

const MAX_OPERATIONS: usize = 48;
const RNG_BYTES: usize = 32;
const FIRST_SENTINEL_INDEX: u64 = 64;
const SECOND_SENTINEL_INDEX: u64 = 65;
const PRUNE_SENTINEL_INDICES: [u64; 4] = [48, 52, 56, 60];
const PAGE_SIZE: NonZeroU16 = NZU16!(64);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(2);
const WRITE_BUFFER: NonZeroUsize = NZUsize!(1);
const REPLAY_BUFFER: NonZeroUsize = NZUsize!(4096);

#[derive(Clone, Copy, Debug)]
enum Kind {
    Immutable,
    Prunable,
}

#[derive(Clone, Debug)]
enum Operation {
    Put { value: RawValue },
    Sync,
    StartSync,
    Prune { min: u64 },
    Crash,
}

#[derive(Debug)]
struct FuzzInput {
    raw_bytes: [u8; RNG_BYTES],
    kind: Kind,
    compression: bool,
    items_per_section: NonZeroU64,
    operations: Vec<Operation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let raw_bytes = u.arbitrary()?;
        let kind = if u.arbitrary()? {
            Kind::Immutable
        } else {
            Kind::Prunable
        };
        let compression = u.arbitrary()?;
        let items_per_section = NonZeroU64::new(u.int_in_range(1..=4)?).unwrap();
        let operation_count = u.int_in_range(1..=MAX_OPERATIONS)?;
        let mut operations = Vec::with_capacity(operation_count);
        for _ in 0..operation_count {
            // Bias toward puts so small inputs still cross several archive sections.
            let operation = match u.int_in_range(0..=7)? {
                0..=3 => Operation::Put {
                    value: u.arbitrary()?,
                },
                4 => Operation::Sync,
                5 => Operation::StartSync,
                6 => Operation::Prune {
                    min: u.int_in_range(0..=MAX_OPERATIONS as u64)?,
                },
                _ => Operation::Crash,
            };
            operations.push(operation);
        }

        Ok(Self {
            raw_bytes,
            kind,
            compression,
            items_per_section,
            operations,
        })
    }
}

#[derive(Clone, Copy)]
struct Settings {
    compression: Option<u8>,
    items_per_section: NonZeroU64,
}

#[derive(Clone, Default)]
struct Expected {
    /// Entries known to survive the next crash.
    durable: Model,
    /// Exact entries that may or may not survive the next crash.
    optional: Model,
    /// Every index ever presented to `put`.
    seen: BTreeSet<u64>,
    /// Next fresh index assigned to a generated put.
    next_index: u64,
}

#[derive(Clone, Copy)]
enum OptionalRecovery {
    None,
    SectionPrefix,
    Any,
}

trait Variant: Send + 'static {
    type Store: ArchiveTrait<Key = Key, Value = Value> + 'static;
    const PRUNABLE: bool;

    fn init(
        context: deterministic::Context,
        settings: Settings,
    ) -> impl Future<Output = Result<Self::Store, Error>> + Send;

    fn prune(
        store: Self::Store,
        min: u64,
    ) -> impl Future<Output = Result<Self::Store, Error>> + Send;
}

struct Immutable;

impl Variant for Immutable {
    type Store = ImmutableArchive<deterministic::Context, Key, Value>;
    const PRUNABLE: bool = false;

    async fn init(
        context: deterministic::Context,
        settings: Settings,
    ) -> Result<Self::Store, Error> {
        let config = ImmutableConfig {
            metadata_partition: "archive-crash-immutable-metadata".into(),
            freezer_table_partition: "archive-crash-immutable-table".into(),
            freezer_table_initial_size: 4,
            freezer_table_resize_frequency: 2,
            freezer_table_resize_chunk_size: 1,
            freezer_key_partition: "archive-crash-immutable-keys".into(),
            freezer_key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            freezer_value_partition: "archive-crash-immutable-values".into(),
            freezer_value_target_size: 64,
            freezer_value_compression: settings.compression,
            ordinal_partition: "archive-crash-immutable-ordinal".into(),
            items_per_section: settings.items_per_section,
            freezer_key_write_buffer: WRITE_BUFFER,
            freezer_value_write_buffer: WRITE_BUFFER,
            ordinal_write_buffer: WRITE_BUFFER,
            replay_buffer: REPLAY_BUFFER,
            codec_config: (),
        };
        ImmutableArchive::init(context.child("archive"), config).await
    }

    async fn prune(store: Self::Store, _min: u64) -> Result<Self::Store, Error> {
        Ok(store)
    }
}

struct Prunable;

impl Variant for Prunable {
    type Store = PrunableArchive<EightCap, deterministic::Context, Key, Value>;
    const PRUNABLE: bool = true;

    async fn init(
        context: deterministic::Context,
        settings: Settings,
    ) -> Result<Self::Store, Error> {
        let config = PrunableConfig {
            translator: EightCap,
            metadata_partition: "archive-crash-prunable-metadata".into(),
            key_partition: "archive-crash-prunable-keys".into(),
            key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            value_partition: "archive-crash-prunable-values".into(),
            compression: settings.compression,
            codec_config: (),
            items_per_section: settings.items_per_section,
            key_write_buffer: WRITE_BUFFER,
            value_write_buffer: WRITE_BUFFER,
            replay_buffer: REPLAY_BUFFER,
        };
        PrunableArchive::init(context.child("archive"), config).await
    }

    async fn prune(store: Self::Store, min: u64) -> Result<Self::Store, Error> {
        PrunableArchive::prune(store, min).await
    }
}

fn key_for(index: u64) -> Key {
    let index = index.to_be_bytes();
    let mut key = [0u8; 16];
    key[..8].copy_from_slice(&index);
    key[8..].copy_from_slice(&index);
    Key::new(key)
}

/// Verify a recovered archive and return the exact state it exposed.
async fn recover_model<A>(
    archive: &A,
    expected: &Expected,
    optional_recovery: OptionalRecovery,
    items_per_section: NonZeroU64,
) -> Model
where
    A: ArchiveTrait<Key = Key, Value = Value>,
{
    let mut actual = Model::new();
    let mut indices = (0..=MAX_OPERATIONS as u64).collect::<BTreeSet<_>>();
    indices.extend(expected.seen.iter().copied());

    for index in indices {
        let recovered = archive
            .get(Identifier::Index(index))
            .await
            .unwrap_or_else(|error| panic!("get({index}) after recovery failed: {error:?}"));
        let key = key_for(index);
        let recovered_by_key = archive
            .get(Identifier::Key(&key))
            .await
            .unwrap_or_else(|error| panic!("key get for {index} after recovery failed: {error:?}"));
        assert_eq!(
            recovered_by_key, recovered,
            "index and key lookup disagree for {index}"
        );

        if let Some(value) = expected.durable.get(&index) {
            assert_eq!(
                recovered,
                Some(Value::new(*value)),
                "durable archive entry {index} changed or disappeared"
            );
            actual.insert(index, *value);
            continue;
        }

        let Some(value) = expected.optional.get(&index) else {
            assert_eq!(recovered, None, "archive invented index {index}");
            continue;
        };

        if let Some(recovered) = recovered {
            assert_eq!(
                recovered,
                Value::new(*value),
                "optional archive entry {index} recovered with different bytes"
            );
            actual.insert(index, *value);
        }
    }

    match optional_recovery {
        OptionalRecovery::SectionPrefix => {
            let mut missing_sections = BTreeSet::new();
            for &index in expected.optional.keys() {
                let section = index / items_per_section.get();
                let present = actual.contains_key(&index);
                assert!(
                    !present || !missing_sections.contains(&section),
                    "optional entry {index} survived after an earlier hole in section {section}"
                );
                if !present {
                    missing_sections.insert(section);
                }
            }
        }
        OptionalRecovery::None => assert!(
            expected
                .optional
                .keys()
                .all(|index| !actual.contains_key(index)),
            "archive retained data beyond its published checkpoint"
        ),
        OptionalRecovery::Any => {}
    }

    let mut ranged = BTreeSet::new();
    for (start, end) in archive.ranges() {
        assert!(start <= end, "archive returned an inverted range");
        assert!(
            end <= SECOND_SENTINEL_INDEX,
            "archive invented an out-of-model range ending at {end}"
        );
        for index in start..=end {
            ranged.insert(index);
        }
    }
    assert_eq!(ranged, actual.keys().copied().collect());
    assert_eq!(
        archive.first_index(),
        actual.first_key_value().map(|(&index, _)| index)
    );
    assert_eq!(
        archive.last_index(),
        actual.last_key_value().map(|(&index, _)| index)
    );

    actual
}

fn assert_interrupted_prune(
    actual: &Model,
    before: &Model,
    min: u64,
    items_per_section: NonZeroU64,
) {
    let mut sections = BTreeMap::<u64, Vec<u64>>::new();
    for &index in before.keys().filter(|&&index| index < min) {
        sections
            .entry(index / items_per_section.get())
            .or_default()
            .push(index);
    }

    let mut retained = false;
    for (section, indices) in sections {
        let recovered = indices
            .iter()
            .filter(|index| actual.contains_key(index))
            .count();
        assert!(
            recovered == 0 || recovered == indices.len(),
            "interrupted prune retained only {recovered}/{} entries in section {section}",
            indices.len()
        );
        if recovered == 0 {
            assert!(
                !retained,
                "interrupted ascending prune removed section {section} after retaining a lower section"
            );
        } else {
            retained = true;
        }
    }
}

fn split_cycles(operations: Vec<Operation>) -> Vec<Vec<Operation>> {
    let mut cycles = Vec::new();
    let mut current = Vec::new();
    for operation in operations {
        if matches!(operation, Operation::Crash) {
            cycles.push(std::mem::take(&mut current));
        } else {
            current.push(operation);
        }
    }
    cycles.push(current);
    cycles
}

fn run_cycle<V: Variant>(
    runner: deterministic::Runner,
    expected: Expected,
    operations: Vec<Operation>,
    settings: Settings,
) -> (Expected, deterministic::Checkpoint) {
    runner.start_and_recover(move |context| async move {
        let mut archive = V::init(context, settings)
            .await
            .expect("archive recovery should succeed");

        // Once recovery exposes an entry, it is the exact baseline for this boot. New puts remain
        // optional until an archive sync completes.
        let mut live = recover_model(
            &archive,
            &expected,
            if V::PRUNABLE {
                OptionalRecovery::SectionPrefix
            } else {
                OptionalRecovery::None
            },
            settings.items_per_section,
        )
        .await;
        let mut durable = live.clone();
        let mut seen = expected.seen;
        let mut next_index = expected.next_index;
        // The prune floor belongs to an archive instance; reopening permits indices below a floor
        // established by the previous instance after its old sections have been removed.
        let mut prune_floor = 0;

        for operation in operations {
            match operation {
                Operation::Put { value } => {
                    let index = next_index;
                    next_index += 1;
                    archive = archive
                        .put(index, key_for(index), Value::new(value))
                        .await
                        .expect("archive put should succeed");
                    seen.insert(index);
                    if index >= prune_floor {
                        live.entry(index).or_insert(value);
                    }
                }
                Operation::Sync => {
                    archive = archive.sync().await.expect("archive sync should succeed");
                    durable.clone_from(&live);
                }
                Operation::StartSync => {
                    let (next, handle) = archive
                        .start_sync()
                        .await
                        .expect("archive start_sync should succeed");
                    archive = next;
                    handle
                        .await
                        .expect("archive start_sync handle should succeed");
                    durable.clone_from(&live);
                }
                Operation::Prune { min } => {
                    archive = V::prune(archive, min)
                        .await
                        .expect("archive prune should succeed");
                    if V::PRUNABLE {
                        let section_size = settings.items_per_section.get();
                        let floor = min / section_size * section_size;
                        prune_floor = prune_floor.max(floor);
                        live.retain(|&index, _| index >= prune_floor);
                        durable.retain(|&index, _| index >= prune_floor);
                    }
                }
                Operation::Crash => unreachable!("Crash operations are cycle separators"),
            }
        }

        let optional = live
            .into_iter()
            .filter(|(index, _)| !durable.contains_key(index))
            .collect();
        Expected {
            durable,
            optional,
            seen,
            next_index,
        }
    })
}

fn run<V: Variant>(input: FuzzInput) {
    let settings = Settings {
        compression: input.compression.then_some(3),
        items_per_section: input.items_per_section,
    };
    let rng = FuzzRng::new(input.raw_bytes.to_vec());
    let mut runner =
        deterministic::Runner::new(deterministic::Config::default().with_rng(Box::new(rng)));
    let mut expected = Expected::default();

    for cycle in split_cycles(input.operations) {
        let checkpoint;
        (expected, checkpoint) = run_cycle::<V>(runner, expected, cycle, settings);
        runner = deterministic::Runner::from(checkpoint);
    }

    // Recover the last fuzz cycle, append and sync a sentinel, then crash once more.
    let (next_expected, checkpoint) = runner.start_and_recover(move |context| async move {
        let mut archive = V::init(context, settings)
            .await
            .expect("final archive recovery should succeed");
        let mut live = recover_model(
            &archive,
            &expected,
            if V::PRUNABLE {
                OptionalRecovery::SectionPrefix
            } else {
                OptionalRecovery::None
            },
            settings.items_per_section,
        )
        .await;
        let sentinel = [0xA5; 32];
        archive = archive
            .put(
                FIRST_SENTINEL_INDEX,
                key_for(FIRST_SENTINEL_INDEX),
                Value::new(sentinel),
            )
            .await
            .expect("put after recovery should succeed");
        live.insert(FIRST_SENTINEL_INDEX, sentinel);
        archive
            .sync()
            .await
            .expect("sync after recovery should succeed");
        let mut seen = expected.seen;
        seen.insert(FIRST_SENTINEL_INDEX);
        Expected {
            durable: live,
            optional: Model::new(),
            seen,
            next_index: expected.next_index,
        }
    });

    // Give Prunable several populated sections below a fixed floor, then interrupt its production
    // metadata-sync/index-prune/value-prune sequence under storage faults.
    let (prune_expected, checkpoint) =
        deterministic::Runner::from(checkpoint).start_and_recover(move |context| async move {
            let fault_config = context.storage_fault_config();
            let mut archive = V::init(context, settings)
                .await
                .expect("pre-prune archive recovery should succeed");
            let mut live = recover_model(
                &archive,
                &next_expected,
                if V::PRUNABLE {
                    OptionalRecovery::SectionPrefix
                } else {
                    OptionalRecovery::None
                },
                settings.items_per_section,
            )
            .await;
            let mut seen = next_expected.seen;

            if V::PRUNABLE {
                for index in PRUNE_SENTINEL_INDICES {
                    let value = [index as u8; 32];
                    archive = archive
                        .put(index, key_for(index), Value::new(value))
                        .await
                        .expect("pre-prune put should succeed");
                    live.insert(index, value);
                    seen.insert(index);
                }
                archive = archive.sync().await.expect("pre-prune sync should succeed");
                *fault_config.write() = deterministic::FaultConfig {
                    write_rate: Some(0.5),
                    partial_write_rate: Some(1.0),
                    sync_rate: Some(0.5),
                    remove_rate: Some(0.5),
                    ..Default::default()
                };
                let _ = V::prune(archive, FIRST_SENTINEL_INDEX).await;
            }

            Expected {
                durable: live,
                optional: Model::new(),
                seen,
                next_index: next_expected.next_index,
            }
        });

    // Recovery may expose old sections or the advanced prune floor. Retained entries at and above
    // the floor are invariant; retrying prune must converge before destroy is attempted.
    let (_, checkpoint) =
        deterministic::Runner::from(checkpoint).start_and_recover(move |context| async move {
            *context.storage_fault_config().write() = deterministic::FaultConfig::default();
            let fault_config = context.storage_fault_config();
            let mut archive = V::init(context, settings)
                .await
                .expect("archive must reopen after interrupted prune");
            let recovery_expected = if V::PRUNABLE {
                Expected {
                    durable: prune_expected
                        .durable
                        .iter()
                        .filter(|(index, _)| **index >= FIRST_SENTINEL_INDEX)
                        .map(|(&index, &value)| (index, value))
                        .collect(),
                    optional: prune_expected
                        .durable
                        .iter()
                        .filter(|(index, _)| **index < FIRST_SENTINEL_INDEX)
                        .map(|(&index, &value)| (index, value))
                        .collect(),
                    seen: prune_expected.seen.clone(),
                    next_index: prune_expected.next_index,
                }
            } else {
                prune_expected.clone()
            };
            let mut live = recover_model(
                &archive,
                &recovery_expected,
                if V::PRUNABLE {
                    OptionalRecovery::Any
                } else {
                    OptionalRecovery::None
                },
                settings.items_per_section,
            )
            .await;

            if V::PRUNABLE {
                assert_interrupted_prune(
                    &live,
                    &prune_expected.durable,
                    FIRST_SENTINEL_INDEX,
                    settings.items_per_section,
                );
            }

            archive = V::prune(archive, FIRST_SENTINEL_INDEX)
                .await
                .expect("prune retry should succeed");
            if V::PRUNABLE {
                live.retain(|&index, _| index >= FIRST_SENTINEL_INDEX);
                let post_prune = Expected {
                    durable: live.clone(),
                    optional: Model::new(),
                    seen: prune_expected.seen.clone(),
                    next_index: prune_expected.next_index,
                };
                recover_model(
                    &archive,
                    &post_prune,
                    OptionalRecovery::None,
                    settings.items_per_section,
                )
                .await;
            }

            let sentinel = [0x3C; 32];
            archive = archive
                .put(
                    SECOND_SENTINEL_INDEX,
                    key_for(SECOND_SENTINEL_INDEX),
                    Value::new(sentinel),
                )
                .await
                .expect("put after second recovery should succeed");
            live.insert(SECOND_SENTINEL_INDEX, sentinel);
            archive = archive
                .sync()
                .await
                .expect("sync after second recovery should succeed");
            assert_eq!(
                archive
                    .get(Identifier::Index(SECOND_SENTINEL_INDEX))
                    .await
                    .expect("sentinel get should succeed"),
                Some(Value::new(sentinel))
            );
            *fault_config.write() = deterministic::FaultConfig::default().remove(0.5);
            let _ = archive.destroy().await;
        });

    deterministic::Runner::from(checkpoint).start(move |context| async move {
        *context.storage_fault_config().write() = deterministic::FaultConfig::default();
        let archive = V::init(context, settings)
            .await
            .expect("archive must reopen after interrupted destroy");
        archive.destroy().await.expect("destroy retry must succeed");
    });
}

fn fuzz(input: FuzzInput) {
    match input.kind {
        Kind::Immutable => run::<Immutable>(input),
        Kind::Prunable => run::<Prunable>(input),
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
