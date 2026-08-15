//! Bounded same-directory replacement of an ordinary filesystem blob with an atomic backing.

use super::{Header, Layout};
use crate::Error;
use commonware_cryptography::{Crc32, Hasher as _};
use commonware_formatting::hex;
use std::{
    ffi::OsStr,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Seek as _, SeekFrom, Write as _},
    os::unix::fs::{FileExt, MetadataExt as _},
    path::{Path, PathBuf},
};

const COPY_BUFFER_LEN: usize = 1024 * 1024;
const STAGE_FILE_NAME: &str = ".commonware-atomic-migrate";

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq)]
enum MigrationStep {
    StageCreated,
    ChunkCopied(u64),
    StageSynced,
    Renamed,
}

#[cfg(test)]
fn migration_cut(step: MigrationStep, cut: Option<MigrationStep>) -> Result<(), Error> {
    if cut == Some(step) {
        return Err(io::Error::other("migration phase cut").into());
    }
    Ok(())
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn valid_file(metadata: &Metadata) -> bool {
    metadata.file_type().is_file()
}

fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn read_exact_at(file: &File, offset: u64, out: &mut [u8]) -> Result<(), Error> {
    FileExt::read_exact_at(file, out, offset).map_err(Into::into)
}

fn has_atomic_identity(file: &File, logical_len: u64, data_offset: u64) -> Result<bool, Error> {
    if data_offset != Layout::V1.data_offset() || logical_len < crate::atomic::IDENTITY_PAGE_LEN {
        return Ok(false);
    }
    let mut page = [0u8; crate::atomic::IDENTITY_PAGE_LEN as usize];
    read_exact_at(file, data_offset, &mut page)?;
    Ok(crate::atomic::decode_identity(&page).is_some())
}

pub(super) fn stage_path(live_path: &Path) -> io::Result<PathBuf> {
    live_path
        .file_name()
        .ok_or_else(|| invalid_input("migration target has no file name"))?;
    Ok(live_path.with_file_name(STAGE_FILE_NAME))
}

/// Returns true only for the canonical hidden name used by migration staging in this directory.
pub(super) fn is_stage_file_name(name: &OsStr) -> bool {
    name == OsStr::new(STAGE_FILE_NAME)
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn discard_stage(stage_path: &Path) -> io::Result<()> {
    match fs::remove_file(stage_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn ensure_current_source(live_path: &Path, source_metadata: &Metadata) -> Result<(), Error> {
    let live_metadata = fs::symlink_metadata(live_path)?;
    if !valid_file(source_metadata)
        || !valid_file(&live_metadata)
        || !same_file(source_metadata, &live_metadata)
    {
        return Err(invalid_input("migration source is no longer the live blob").into());
    }
    Ok(())
}

/// Replace the exact live source inode with a V1 inode whose logical bytes use the atomic format.
///
/// The caller serializes namespace access and excludes concurrent mutation through other handles.
/// The source remains open and readable after replacement. A retry against an inode with a complete
/// atomic identity only makes its directory ancestry durable.
fn migrate_live_inner(
    root: &Path,
    partition: &str,
    name: &[u8],
    source: &File,
    incarnation: [u8; 16],
    #[cfg(test)] cut: Option<MigrationStep>,
) -> Result<(), Error> {
    crate::atomic::validate_atomic_location(partition, name)?;
    let live_path = root.join(partition).join(hex(name));
    let parent = live_path
        .parent()
        .ok_or_else(|| invalid_input("migration target has no parent directory"))?;

    let source_metadata = source.metadata()?;
    ensure_current_source(&live_path, &source_metadata)?;
    source
        .sync_all()
        .map_err(|error| Error::BlobSyncFailed(partition.into(), hex(name), error.into()))?;

    let raw_len = source_metadata.len();
    if Header::missing(raw_len) {
        return Err(Error::BlobCorrupt(
            partition.into(),
            hex(name),
            "migration source has no complete header".into(),
        ));
    }
    let mut raw = vec![0u8; Header::resolve_len(raw_len)];
    read_exact_at(source, 0, &mut raw)?;
    let (logical_len, blob_version, data_offset) =
        Header::parse(&raw, raw_len, &(u16::MIN..=u16::MAX))
            .map_err(|error| error.into_error(partition, name))?;
    if blob_version == crate::DEFAULT_BLOB_VERSION
        && has_atomic_identity(source, logical_len, data_offset)?
    {
        sync_directory(parent)?;
        return Ok(());
    }

    let (atomic_header, atomic_version) =
        Header::create(&(crate::DEFAULT_BLOB_VERSION..=crate::DEFAULT_BLOB_VERSION));
    debug_assert_eq!(atomic_version, crate::DEFAULT_BLOB_VERSION);
    let replacement_data_offset = (atomic_header.len() as u64)
        .checked_add(crate::atomic::DATA_OFFSET)
        .ok_or(Error::OffsetOverflow)?;
    replacement_data_offset
        .checked_add(logical_len)
        .ok_or(Error::OffsetOverflow)?;

    let stage_path = stage_path(&live_path)?;
    discard_stage(&stage_path)?;
    let mut replacement = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&stage_path)?;
    #[cfg(test)]
    migration_cut(MigrationStep::StageCreated, cut)?;
    replacement.write_all(&atomic_header)?;
    replacement.seek(SeekFrom::Start(replacement_data_offset))?;

    let buffer_len = usize::try_from(logical_len.min(COPY_BUFFER_LEN as u64))
        .expect("migration copy chunks fit in usize");
    let mut buffer = vec![0u8; buffer_len];
    let mut copied = 0u64;
    let mut integrity_checksum = Crc32::default();
    while copied < logical_len {
        let len = usize::try_from((logical_len - copied).min(COPY_BUFFER_LEN as u64))
            .expect("migration copy chunks fit in usize");
        let source_offset = data_offset
            .checked_add(copied)
            .ok_or(Error::OffsetOverflow)?;
        read_exact_at(source, source_offset, &mut buffer[..len])?;
        integrity_checksum.update(&buffer[..len]);
        replacement.write_all(&buffer[..len])?;
        copied = copied
            .checked_add(len as u64)
            .ok_or(Error::OffsetOverflow)?;
        #[cfg(test)]
        migration_cut(MigrationStep::ChunkCopied(copied), cut)?;
    }
    let prefix = crate::atomic::migration_prefix(
        incarnation,
        logical_len,
        integrity_checksum.finalize().1.as_u32(),
    );
    replacement.seek(SeekFrom::Start(atomic_header.len() as u64))?;
    replacement.write_all(&prefix)?;
    replacement.sync_all()?;
    #[cfg(test)]
    migration_cut(MigrationStep::StageSynced, cut)?;

    fs::rename(&stage_path, &live_path)?;
    #[cfg(test)]
    migration_cut(MigrationStep::Renamed, cut)?;
    sync_directory(parent)?;
    Ok(())
}

pub(super) fn migrate_live(
    root: &Path,
    partition: &str,
    name: &[u8],
    source: &File,
    incarnation: [u8; 16],
) -> Result<(), Error> {
    #[cfg(test)]
    {
        migrate_live_inner(root, partition, name, source, incarnation, None)
    }
    #[cfg(not(test))]
    {
        migrate_live_inner(root, partition, name, source, incarnation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{Layout, header::tests::v0_blob_bytes};
    #[cfg(not(feature = "iouring-storage"))]
    use crate::{
        AtomicBlob as _, AtomicStorage as _, BufferPool, BufferPoolConfig, Storage as _,
        storage::tokio::{Config as TokioConfig, Storage as TokioStorage},
        telemetry::metrics::Registry,
    };
    use std::{
        env,
        ffi::OsString,
        os::unix::ffi::OsStringExt,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    fn test_root(label: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "commonware_{label}_{}_{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn source_bytes(v0: bool, version: u16, payload: &[u8]) -> Vec<u8> {
        if v0 {
            return v0_blob_bytes(version, payload);
        }
        let mut raw = Header::create(&(version..=version)).0;
        raw.extend_from_slice(payload);
        raw
    }

    #[cfg(not(feature = "iouring-storage"))]
    fn test_pool() -> BufferPool {
        let mut registry = Registry::default();
        BufferPool::new(BufferPoolConfig::for_storage(), &mut registry)
    }

    #[test]
    fn migration_streams_v0_and_v1_payloads_and_retry_is_inode_stable() {
        const VERSION: u16 = 7;
        const INCARNATION: [u8; 16] = [0x3C; 16];
        for v0 in [true, false] {
            for len in [
                0,
                1,
                COPY_BUFFER_LEN - 1,
                COPY_BUFFER_LEN,
                COPY_BUFFER_LEN + 1,
            ] {
                let root = test_root("atomic_migration");
                let partition = "partition";
                let name = if v0 {
                    b"v0".as_slice()
                } else {
                    b"v1".as_slice()
                };
                let parent = root.join(partition);
                fs::create_dir_all(&parent).unwrap();
                let live_path = parent.join(hex(name));
                let payload = (0u8..=255).cycle().take(len).collect::<Vec<_>>();
                let original = source_bytes(v0, VERSION, &payload);
                fs::write(&live_path, &original).unwrap();
                let source = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&live_path)
                    .unwrap();
                let source_inode = source.metadata().unwrap().ino();
                let prefix = crate::atomic::migration_prefix(
                    INCARNATION,
                    payload.len() as u64,
                    Crc32::checksum(&payload),
                );

                migrate_live(&root, partition, name, &source, INCARNATION).unwrap();

                let migrated = fs::read(&live_path).unwrap();
                assert_eq!(
                    migrated.len(),
                    Layout::V1.data_offset() as usize
                        + crate::atomic::DATA_OFFSET as usize
                        + payload.len()
                );
                let (logical_len, version, data_offset) = Header::parse(
                    &migrated[..Layout::V1.data_offset() as usize],
                    migrated.len() as u64,
                    &(crate::DEFAULT_BLOB_VERSION..=crate::DEFAULT_BLOB_VERSION),
                )
                .unwrap();
                assert_eq!(
                    logical_len as usize,
                    crate::atomic::DATA_OFFSET as usize + payload.len()
                );
                assert_eq!(version, crate::DEFAULT_BLOB_VERSION);
                assert_eq!(data_offset, Layout::V1.data_offset());
                assert_eq!(
                    &migrated[..data_offset as usize],
                    Header::create(&(crate::DEFAULT_BLOB_VERSION..=crate::DEFAULT_BLOB_VERSION))
                        .0
                        .as_slice()
                );
                let prefix_start = data_offset as usize;
                assert_eq!(
                    &migrated[prefix_start..prefix_start + prefix.len()],
                    &prefix
                );
                assert_eq!(&migrated[prefix_start + prefix.len()..], &payload);
                assert_ne!(source_inode, fs::metadata(&live_path).unwrap().ino());

                let mut old = vec![0u8; original.len()];
                read_exact_at(&source, 0, &mut old).unwrap();
                assert_eq!(old, original);

                let replacement = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&live_path)
                    .unwrap();
                let replacement_inode = replacement.metadata().unwrap().ino();
                migrate_live(&root, partition, name, &replacement, [0xA5; 16]).unwrap();
                assert_eq!(replacement_inode, fs::metadata(&live_path).unwrap().ino());
                assert_eq!(fs::read(&live_path).unwrap(), migrated);
                assert!(!stage_path(&live_path).unwrap().exists());

                fs::remove_dir_all(root).unwrap();
            }
        }
    }

    #[cfg(not(feature = "iouring-storage"))]
    #[tokio::test]
    async fn migration_phase_cuts_retry_through_a_fresh_storage_lineage() {
        const VERSION: u16 = 7;
        const INCARNATION: [u8; 16] = [0x3C; 16];
        let payload = (0u8..=255)
            .cycle()
            .take(COPY_BUFFER_LEN + 1)
            .collect::<Vec<_>>();
        let ordinary = source_bytes(true, VERSION, &payload);
        let atomic_header =
            Header::create(&(crate::DEFAULT_BLOB_VERSION..=crate::DEFAULT_BLOB_VERSION)).0;
        let prefix = crate::atomic::migration_prefix(
            INCARNATION,
            payload.len() as u64,
            Crc32::checksum(&payload),
        );
        let mut atomic = atomic_header.clone();
        atomic.extend_from_slice(&prefix);
        atomic.extend_from_slice(&payload);
        let steps = [
            MigrationStep::StageCreated,
            MigrationStep::ChunkCopied(COPY_BUFFER_LEN as u64),
            MigrationStep::ChunkCopied((COPY_BUFFER_LEN + 1) as u64),
            MigrationStep::StageSynced,
            MigrationStep::Renamed,
        ];

        for cut in steps {
            let root = test_root("atomic_migration_phase_cut");
            let partition = "partition";
            let name = b"blob";
            let parent = root.join(partition);
            fs::create_dir_all(&parent).unwrap();
            let live_path = parent.join(hex(name));
            fs::write(&live_path, &ordinary).unwrap();
            let source = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&live_path)
                .unwrap();
            let ordinary_inode = source.metadata().unwrap().ino();
            let stage = stage_path(&live_path).unwrap();
            let result =
                migrate_live_inner(&root, partition, name, &source, INCARNATION, Some(cut));
            assert!(result.is_err(), "cut {cut:?} completed migration");

            if cut != MigrationStep::Renamed {
                assert_eq!(fs::read(&live_path).unwrap(), ordinary);
                let staged = fs::read(&stage).unwrap();
                match cut {
                    MigrationStep::StageCreated => assert!(staged.is_empty()),
                    MigrationStep::ChunkCopied(copied) => {
                        let payload_start =
                            atomic_header.len() + crate::atomic::DATA_OFFSET as usize;
                        assert_eq!(
                            staged.len(),
                            payload_start + usize::try_from(copied).unwrap()
                        );
                        assert_eq!(&staged[..atomic_header.len()], &atomic_header);
                        assert!(
                            staged[atomic_header.len()..payload_start]
                                .iter()
                                .all(|byte| *byte == 0)
                        );
                        assert_eq!(
                            &staged[payload_start..],
                            &payload[..usize::try_from(copied).unwrap()]
                        );
                    }
                    MigrationStep::StageSynced => assert_eq!(staged, atomic),
                    MigrationStep::Renamed => unreachable!(),
                }
            } else {
                assert!(!stage.exists());
                assert_ne!(fs::metadata(&live_path).unwrap().ino(), ordinary_inode);
                assert_eq!(fs::read(&live_path).unwrap(), atomic);
            }
            drop(source);

            let storage = TokioStorage::new(
                TokioConfig::new(root.clone(), 2 * COPY_BUFFER_LEN),
                test_pool(),
            );
            let (fresh, _, _) = storage
                .open_versioned(partition, name, u16::MIN..=u16::MAX)
                .await
                .unwrap();
            storage.migrate_atomic(fresh).await.unwrap();
            assert!(!stage.exists());
            let (blob, len) = storage.open_atomic(partition, name).await.unwrap();
            assert_eq!(len as usize, payload.len());
            assert_eq!(
                blob.read_at(0, payload.len())
                    .await
                    .unwrap()
                    .coalesce()
                    .as_ref(),
                payload
            );
            blob.append(b"!").await.unwrap();
            blob.sync().await.unwrap();
            drop(blob);
            drop(storage);

            let storage = TokioStorage::new(
                TokioConfig::new(root.clone(), 2 * COPY_BUFFER_LEN),
                test_pool(),
            );
            let (blob, len) = storage.open_atomic(partition, name).await.unwrap();
            assert_eq!(len as usize, payload.len() + 1);
            let mut expected = payload.clone();
            expected.push(b'!');
            assert_eq!(
                blob.read_at(0, expected.len())
                    .await
                    .unwrap()
                    .coalesce()
                    .as_ref(),
                expected
            );
            drop(blob);
            drop(storage);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn migration_recognizes_identity_only_canonical_image() {
        const INSTALLED_INCARNATION: [u8; 16] = [0x3C; 16];
        const RETRY_INCARNATION: [u8; 16] = [0xA5; 16];

        let root = test_root("atomic_identity_only_migration");
        let partition = "partition";
        let name = b"blob";
        let parent = root.join(partition);
        fs::create_dir_all(&parent).unwrap();
        let live_path = parent.join(hex(name));
        let prefix = crate::atomic::migration_prefix(INSTALLED_INCARNATION, 0, 0);
        let original = source_bytes(
            false,
            crate::DEFAULT_BLOB_VERSION,
            &prefix[..crate::atomic::IDENTITY_PAGE_LEN as usize],
        );
        fs::write(&live_path, &original).unwrap();
        let source = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&live_path)
            .unwrap();
        let source_inode = source.metadata().unwrap().ino();

        migrate_live(&root, partition, name, &source, RETRY_INCARNATION).unwrap();

        assert_eq!(source_inode, fs::metadata(&live_path).unwrap().ino());
        assert_eq!(fs::read(&live_path).unwrap(), original);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn migration_wraps_identity_prefixed_noncanonical_container() {
        const VERSION: u16 = 7;
        const INCARNATION: [u8; 16] = [0x3C; 16];
        let root = test_root("atomic_identity_prefixed_migration");
        let partition = "partition";
        let name = b"blob";
        let parent = root.join(partition);
        fs::create_dir_all(&parent).unwrap();
        let live_path = parent.join(hex(name));
        let mut payload = crate::atomic::migration_prefix([0xA5; 16], 0, 0).to_vec();
        payload.extend_from_slice(b"ordinary payload");
        fs::write(&live_path, source_bytes(false, VERSION, &payload)).unwrap();
        let source = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&live_path)
            .unwrap();

        migrate_live(&root, partition, name, &source, INCARNATION).unwrap();

        let migrated = fs::read(&live_path).unwrap();
        let (logical_len, version, data_offset) = Header::parse(
            &migrated[..Layout::V1.data_offset() as usize],
            migrated.len() as u64,
            &(crate::DEFAULT_BLOB_VERSION..=crate::DEFAULT_BLOB_VERSION),
        )
        .unwrap();
        assert_eq!(version, crate::DEFAULT_BLOB_VERSION);
        assert_eq!(
            logical_len,
            crate::atomic::DATA_OFFSET + payload.len() as u64
        );
        let payload_start = data_offset as usize + crate::atomic::DATA_OFFSET as usize;
        assert_eq!(&migrated[payload_start..], payload.as_slice());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn migration_discards_a_prior_stage_and_rejects_a_stale_source() {
        let root = test_root("atomic_migration_stage");
        let parent = root.join("partition");
        fs::create_dir_all(&parent).unwrap();
        let live_path = parent.join(hex(b"blob"));
        fs::write(&live_path, source_bytes(false, 3, b"old")).unwrap();
        let stale = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&live_path)
            .unwrap();
        let stage = stage_path(&live_path).unwrap();
        fs::write(&stage, b"abandoned partial replacement").unwrap();

        let replacement = source_bytes(false, 3, b"new");
        let replacement_path = parent.join("replacement");
        fs::write(&replacement_path, &replacement).unwrap();
        fs::rename(&replacement_path, &live_path).unwrap();
        assert!(migrate_live(&root, "partition", b"blob", &stale, [0; 16],).is_err());
        assert_eq!(fs::read(&live_path).unwrap(), replacement);
        assert!(
            stage.exists(),
            "stale rejection must not touch another operation's stage"
        );

        let current = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&live_path)
            .unwrap();
        migrate_live(&root, "partition", b"blob", &current, [0; 16]).unwrap();
        assert!(!stage.exists());

        fs::create_dir(&stage).unwrap();
        assert!(discard_stage(&stage).is_err());
        fs::remove_dir(&stage).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn migration_rejects_incomplete_source_layouts() {
        let root = test_root("atomic_migration_invalid_source");
        let partition = "partition";
        let parent = root.join(partition);
        fs::create_dir_all(&parent).unwrap();
        let live_path = parent.join(hex(b"blob"));
        fs::write(&live_path, []).unwrap();
        let source = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&live_path)
            .unwrap();

        assert!(matches!(
            migrate_live(&root, partition, b"blob", &source, [0; 16],),
            Err(Error::BlobCorrupt(_, _, _))
        ));
        let mut byte = [0];
        assert!(read_exact_at(&source, 0, &mut byte).is_err());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stage_names_are_exact() {
        let stage = stage_path(Path::new("/tmp/626c6f62")).unwrap();
        let stage_name = stage.file_name().unwrap();
        assert_eq!(stage_name, OsStr::new(STAGE_FILE_NAME));
        assert!(is_stage_file_name(stage_name));

        let long_name = "ab".repeat(115);
        let other_stage = stage_path(Path::new("/tmp").join(long_name).as_path()).unwrap();
        assert_eq!(other_stage, stage);
        for name in [
            ".commonware-atomic-migrate-",
            ".commonware-atomic-migrate-626c6f62",
            ".commonware-atomic-migrate-ABC0",
            ".commonware-atomic-migrate-xyz",
            ".commonware-atomic-migrate0",
            "commonware-atomic-migrate-626c6f62",
            "626c6f62",
        ] {
            assert!(!is_stage_file_name(OsStr::new(name)), "{name}");
        }
        assert!(!is_stage_file_name(&OsString::from_vec(vec![0xff])));
    }
}
