//! Crash-recoverable filesystem removal of an exact storage namespace set.
//!
//! Every batch is validated and canonicalized before the namespace is mutated. Duplicate targets
//! are removed, and a partition target subsumes every blob target in that partition. The
//! filesystem implementation then uses a manifest with one durable commit point:
//!
//! 1. Write and sync the target set as the prepared manifest.
//! 2. Rename it to the committed manifest and sync the control directory. Completion of this
//!    directory sync commits the batch.
//! 3. Remove every target idempotently and sync the affected partition and storage directories.
//! 4. Remove the committed manifest and sync the control directory.
//!
//! The prepared file is renamed only after `write_all` and `sync_all` succeed. A short or
//! interrupted write therefore cannot commit and is discarded during recovery. The manifest has a
//! bounded length and a CRC32 over its complete body. Recovery validates the checksum, magic,
//! version, target count, encoding, and canonical order before removing any target. An invalid
//! committed manifest blocks namespace access instead of guessing which targets were recorded.
//!
//! Recovery runs while the storage namespace is locked and before another namespace operation is
//! exposed. It discards a prepared manifest. Before acting on a committed manifest or trusting its
//! absence, it syncs the control directory so the visible marker state is authoritative.
//!
//! | Control state | Meaning | Recovery action |
//! | --- | --- | --- |
//! | No manifest | No batch awaits recovery | Continue without removal recovery |
//! | Prepared manifest | The batch is not committed | Discard the prepared manifest |
//! | Committed manifest | The whole batch is committed | Repeat every removal, sync them, then remove the marker |
//!
//! Target removal is idempotent, so recovery may safely repeat any prefix completed before an
//! error, cancellation, or crash. The committed marker is removed only after target removals are
//! synced. If marker removal itself was not durable, the marker may reappear after a crash and the
//! same batch is completed again.
//!
//! On Windows, targets are first renamed into a private graveyard. This releases their public names
//! for new generations while handles opened before removal retain access to the detached files.
//! Directory-entry durability is best-effort on platforms that cannot synchronize directories.
//!
//! A filesystem storage root must not be accessed concurrently by another storage instance or
//! process. The manifest protocol relies on serialized namespace operations. CRC32 detects
//! accidental corruption and torn data, but does not authenticate a manifest against another
//! process with write access to the root.

use super::removal::is_canonical;
use crate::RemoveTarget;
use commonware_cryptography::Crc32;
use commonware_formatting::hex;
#[cfg(windows)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, ErrorKind, Read, Write},
    path::{Path, PathBuf},
};

const CONTROL_DIRECTORY: &str = ".commonware";
const COMMITTED_MANIFEST: &str = "_COMMONWARE_RUNTIME_REMOVE_BATCH";
const PREPARED_MANIFEST: &str = "_COMMONWARE_RUNTIME_REMOVE_BATCH_PREPARED";
#[cfg(windows)]
const GRAVEYARD_DIRECTORY: &str = "_COMMONWARE_RUNTIME_REMOVE_BATCH_GRAVEYARD";
#[cfg(windows)]
const DETACH_BATCH_SIZE: usize = 1024;
const MANIFEST_MAGIC: &[u8] = COMMITTED_MANIFEST.as_bytes();
const MANIFEST_VERSION: u16 = 1;
const MAX_MANIFEST_SIZE: u64 = 16 * 1024 * 1024;
const MAX_TARGETS: usize = 1_000_000;
const TAG_PARTITION: u8 = 0;
const TAG_BLOB: u8 = 1;
#[cfg(windows)]
static NEXT_GRAVEYARD: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Progress {
    Prepared,
    Committed,
    Removed(usize),
    MarkerRemoved,
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, message)
}

fn checked_add(total: &mut usize, amount: usize) -> io::Result<()> {
    *total = total
        .checked_add(amount)
        .ok_or_else(|| invalid_input("remove batch manifest length overflow"))?;
    if *total as u64 > MAX_MANIFEST_SIZE {
        return Err(invalid_input("remove batch manifest is too large"));
    }
    Ok(())
}

fn encoded_len(targets: &[RemoveTarget]) -> io::Result<usize> {
    if targets.len() > MAX_TARGETS || u32::try_from(targets.len()).is_err() {
        return Err(invalid_input("remove batch has too many targets"));
    }

    let mut len = MANIFEST_MAGIC.len() + size_of::<u16>() + size_of::<u32>();
    for target in targets {
        let (partition, name) = match target {
            RemoveTarget::Blob { partition, name } => (partition, Some(name)),
            RemoveTarget::Partition(partition) => (partition, None),
        };
        u32::try_from(partition.len())
            .map_err(|_| invalid_input("remove batch partition name is too large"))?;
        checked_add(&mut len, 1 + size_of::<u32>())?;
        checked_add(&mut len, partition.len())?;
        if let Some(name) = name {
            u32::try_from(name.len())
                .map_err(|_| invalid_input("remove batch blob name is too large"))?;
            checked_add(&mut len, size_of::<u32>())?;
            checked_add(&mut len, name.len())?;
        }
    }
    checked_add(&mut len, size_of::<u32>())?;
    Ok(len)
}

fn encode_manifest(targets: &[RemoveTarget]) -> io::Result<Vec<u8>> {
    let canonical = is_canonical(targets)
        .map_err(|_| invalid_input("remove batch contains an invalid partition name"))?;
    if !canonical {
        return Err(invalid_input("remove batch targets are not canonical"));
    }

    let mut encoded = Vec::with_capacity(encoded_len(targets)?);
    encoded.extend_from_slice(MANIFEST_MAGIC);
    encoded.extend_from_slice(&MANIFEST_VERSION.to_be_bytes());
    encoded.extend_from_slice(&(targets.len() as u32).to_be_bytes());
    for target in targets {
        match target {
            RemoveTarget::Partition(partition) => {
                encoded.push(TAG_PARTITION);
                encoded.extend_from_slice(&(partition.len() as u32).to_be_bytes());
                encoded.extend_from_slice(partition.as_bytes());
            }
            RemoveTarget::Blob { partition, name } => {
                encoded.push(TAG_BLOB);
                encoded.extend_from_slice(&(partition.len() as u32).to_be_bytes());
                encoded.extend_from_slice(partition.as_bytes());
                encoded.extend_from_slice(&(name.len() as u32).to_be_bytes());
                encoded.extend_from_slice(name);
            }
        }
    }
    let checksum = Crc32::checksum(&encoded);
    encoded.extend_from_slice(&checksum.to_be_bytes());
    Ok(encoded)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read(&mut self, len: usize) -> io::Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(len)
            .ok_or_else(|| invalid_data("remove batch manifest length overflow"))?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| invalid_data("remove batch manifest is truncated"))?;
        self.position = end;
        Ok(bytes)
    }

    fn read_u8(&mut self) -> io::Result<u8> {
        Ok(self.read(1)?[0])
    }

    fn read_u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_be_bytes(
            self.read(size_of::<u16>())?.try_into().unwrap(),
        ))
    }

    fn read_u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_be_bytes(
            self.read(size_of::<u32>())?.try_into().unwrap(),
        ))
    }

    const fn finished(&self) -> bool {
        self.position == self.bytes.len()
    }
}

fn decode_manifest(encoded: &[u8]) -> io::Result<Vec<RemoveTarget>> {
    let minimum_len = MANIFEST_MAGIC.len() + size_of::<u16>() + size_of::<u32>() + size_of::<u32>();
    if encoded.len() < minimum_len || encoded.len() as u64 > MAX_MANIFEST_SIZE {
        return Err(invalid_data("remove batch manifest has an invalid length"));
    }

    let checksum_offset = encoded.len() - size_of::<u32>();
    let (body, checksum) = encoded.split_at(checksum_offset);
    let checksum = u32::from_be_bytes(checksum.try_into().unwrap());
    if Crc32::checksum(body) != checksum {
        return Err(invalid_data("remove batch manifest checksum mismatch"));
    }

    let mut cursor = Cursor::new(body);
    if cursor.read(MANIFEST_MAGIC.len())? != MANIFEST_MAGIC {
        return Err(invalid_data("remove batch manifest magic mismatch"));
    }
    if cursor.read_u16()? != MANIFEST_VERSION {
        return Err(invalid_data("unsupported remove batch manifest version"));
    }
    let count = usize::try_from(cursor.read_u32()?)
        .map_err(|_| invalid_data("remove batch target count overflow"))?;
    if count == 0 || count > MAX_TARGETS {
        return Err(invalid_data(
            "remove batch manifest has an invalid target count",
        ));
    }
    const MIN_TARGET_SIZE: usize = 1 + size_of::<u32>() + 1;
    let remaining = cursor.bytes.len() - cursor.position;
    if count > remaining / MIN_TARGET_SIZE {
        return Err(invalid_data(
            "remove batch target count exceeds the manifest length",
        ));
    }

    let mut targets = Vec::with_capacity(count);
    for _ in 0..count {
        let tag = cursor.read_u8()?;
        let partition_len = usize::try_from(cursor.read_u32()?)
            .map_err(|_| invalid_data("remove batch partition length overflow"))?;
        let partition = std::str::from_utf8(cursor.read(partition_len)?)
            .map_err(|_| invalid_data("remove batch partition is not UTF-8"))?
            .to_string();
        let target = match tag {
            TAG_PARTITION => RemoveTarget::Partition(partition),
            TAG_BLOB => {
                let name_len = usize::try_from(cursor.read_u32()?)
                    .map_err(|_| invalid_data("remove batch blob length overflow"))?;
                let name = cursor.read(name_len)?.to_vec();
                RemoveTarget::Blob { partition, name }
            }
            _ => return Err(invalid_data("remove batch manifest target tag is invalid")),
        };
        targets.push(target);
    }
    if !cursor.finished() {
        return Err(invalid_data("remove batch manifest has trailing bytes"));
    }

    let canonical = is_canonical(&targets)
        .map_err(|_| invalid_data("remove batch manifest contains an invalid target"))?;
    if !canonical {
        return Err(invalid_data(
            "remove batch manifest targets are not canonical",
        ));
    }
    Ok(targets)
}

fn control_directory(root: &Path) -> PathBuf {
    root.join(CONTROL_DIRECTORY)
}

fn committed_manifest(root: &Path) -> PathBuf {
    control_directory(root).join(COMMITTED_MANIFEST)
}

fn prepared_manifest(root: &Path) -> PathBuf {
    control_directory(root).join(PREPARED_MANIFEST)
}

/// Directory entry durability is best-effort on platforms where directories cannot be
/// synchronized, matching the policy used by single-target removal.
#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn require_directory(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(true),
        Ok(_) => Err(invalid_data("remove batch control path is not a directory")),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn ensure_control_directory(root: &Path) -> io::Result<PathBuf> {
    let control = control_directory(root);
    if !require_directory(&control)? {
        fs::create_dir(&control)?;
    }
    // A visible control directory does not prove its root entry is durable. Establish that
    // prerequisite before every manifest commit.
    sync_directory(root)?;
    Ok(control)
}

#[cfg(windows)]
fn graveyard_directory(root: &Path) -> PathBuf {
    control_directory(root).join(GRAVEYARD_DIRECTORY)
}

/// Delete-pending Windows entries can remain inaccessible until old handles close. Cleanup is
/// opportunistic because those entries are detached from the user namespace already.
#[cfg(windows)]
fn cleanup_graveyards(root: &Path) {
    let graveyard = graveyard_directory(root);
    let Ok(metadata) = fs::symlink_metadata(&graveyard) else {
        return;
    };
    if !metadata.file_type().is_dir() {
        return;
    }
    let Ok(entries) = fs::read_dir(&graveyard) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        match entry.file_type() {
            Ok(file_type) if file_type.is_dir() => {
                let _ = fs::remove_dir_all(path);
            }
            Ok(_) => {
                let _ = fs::remove_file(path);
            }
            Err(_) => {}
        }
    }
    let _ = fs::remove_dir(graveyard);
}

#[cfg(windows)]
struct WindowsRemover {
    root: PathBuf,
    generation: Option<PathBuf>,
    next_slot: u64,
}

#[cfg(windows)]
impl WindowsRemover {
    fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            generation: None,
            next_slot: 0,
        }
    }

    fn ensure_generation(&mut self) -> io::Result<&Path> {
        if self.generation.is_none() {
            cleanup_graveyards(&self.root);
            let control = ensure_control_directory(&self.root)?;
            let graveyard = graveyard_directory(&self.root);
            if !require_directory(&graveyard)? {
                fs::create_dir(&graveyard)?;
                sync_directory(&control)?;
            }

            loop {
                let nonce = NEXT_GRAVEYARD.fetch_add(1, Ordering::Relaxed);
                let generation = graveyard.join(format!("{:08x}-{nonce:016x}", std::process::id()));
                match fs::create_dir(&generation) {
                    Ok(()) => {
                        self.generation = Some(generation);
                        break;
                    }
                    Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(self.generation.as_deref().unwrap())
    }

    fn detach(&mut self, source: &Path) -> io::Result<()> {
        let slot = self.next_slot;
        self.next_slot = self
            .next_slot
            .checked_add(1)
            .ok_or_else(|| invalid_data("remove batch graveyard slot overflow"))?;
        let destination = self.ensure_generation()?.join(format!("{slot:016x}"));
        fs::rename(source, &destination)?;

        // DeleteFile keeps this private name pending until every old handle closes. The
        // user-visible source name is already free for an independent generation.
        let _ = fs::remove_file(destination);
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for WindowsRemover {
    fn drop(&mut self) {
        let Some(generation) = self.generation.take() else {
            return;
        };
        let graveyard = generation.parent().map(Path::to_path_buf);
        let _ = fs::remove_dir_all(generation);
        if let Some(graveyard) = graveyard {
            let _ = fs::remove_dir(graveyard);
        }
    }
}

fn discard_prepared(root: &Path) -> io::Result<()> {
    let prepared = prepared_manifest(root);
    match fs::symlink_metadata(&prepared) {
        Ok(metadata) if metadata.file_type().is_file() => {
            fs::remove_file(prepared)?;
            sync_directory(&control_directory(root))?;
        }
        Ok(_) => return Err(invalid_data("prepared remove batch manifest is not a file")),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

fn read_committed(root: &Path) -> io::Result<Option<Vec<RemoveTarget>>> {
    let path = committed_manifest(root);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() => metadata,
        Ok(_) => {
            return Err(invalid_data(
                "committed remove batch manifest is not a file",
            ));
        }
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if metadata.len() > MAX_MANIFEST_SIZE {
        return Err(invalid_data("committed remove batch manifest is too large"));
    }

    let mut encoded = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?
        .take(MAX_MANIFEST_SIZE + 1)
        .read_to_end(&mut encoded)?;
    if encoded.len() as u64 > MAX_MANIFEST_SIZE {
        return Err(invalid_data("committed remove batch manifest is too large"));
    }
    decode_manifest(&encoded).map(Some)
}

#[cfg(not(windows))]
fn remove_target(root: &Path, target: &RemoveTarget) -> io::Result<()> {
    let result = match target {
        RemoveTarget::Blob { partition, name } => {
            if name.is_empty() {
                return Ok(());
            }
            let partition = root.join(partition);
            match fs::symlink_metadata(&partition) {
                Ok(metadata) if metadata.file_type().is_dir() => {}
                Ok(_) => return Err(invalid_data("blob partition path is not a directory")),
                Err(error) if path_is_missing(&error) => return Ok(()),
                Err(error) => return Err(error),
            }
            fs::remove_file(partition.join(hex(name)))
        }
        RemoveTarget::Partition(partition) => {
            let partition = root.join(partition);
            match fs::symlink_metadata(&partition) {
                Ok(metadata) if metadata.file_type().is_dir() => fs::remove_dir_all(partition),
                Ok(metadata) if metadata.file_type().is_symlink() => fs::remove_file(partition),
                Ok(_) => return Err(invalid_data("partition path is not a directory")),
                Err(error) if path_is_missing(&error) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    };
    match result {
        Ok(()) => Ok(()),
        Err(error) if path_is_missing(&error) => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(windows)]
fn remove_target(
    root: &Path,
    target: &RemoveTarget,
    remover: &mut WindowsRemover,
) -> io::Result<bool> {
    match target {
        RemoveTarget::Blob { partition, name } => {
            if name.is_empty() {
                return Ok(false);
            }
            let partition = root.join(partition);
            match fs::symlink_metadata(&partition) {
                Ok(metadata) if metadata.file_type().is_dir() => {}
                Ok(_) => return Err(invalid_data("blob partition path is not a directory")),
                Err(error) if path_is_missing(&error) => return Ok(false),
                Err(error) => return Err(error),
            }

            let blob = partition.join(hex(name));
            match fs::symlink_metadata(&blob) {
                Ok(metadata)
                    if metadata.file_type().is_file() || metadata.file_type().is_symlink() =>
                {
                    remover.detach(&blob)?;
                    Ok(true)
                }
                Ok(_) => Err(invalid_data("blob path is not a file")),
                Err(error) if path_is_missing(&error) => Ok(false),
                Err(error) => Err(error),
            }
        }
        RemoveTarget::Partition(partition) => {
            let partition = root.join(partition);
            match fs::symlink_metadata(&partition) {
                Ok(metadata) if metadata.file_type().is_dir() => {
                    for entry in fs::read_dir(&partition)? {
                        let entry = entry?;
                        if entry.file_type()?.is_dir() {
                            return Err(invalid_data(
                                "remove batch partition contains a directory",
                            ));
                        }
                    }

                    loop {
                        let entries = fs::read_dir(&partition)?
                            .take(DETACH_BATCH_SIZE)
                            .map(|entry| {
                                let entry = entry?;
                                if entry.file_type()?.is_dir() {
                                    return Err(invalid_data(
                                        "remove batch partition contains a directory",
                                    ));
                                }
                                Ok(entry.path())
                            })
                            .collect::<io::Result<Vec<_>>>()?;
                        if entries.is_empty() {
                            break;
                        }
                        for entry in entries {
                            remover.detach(&entry)?;
                        }
                    }
                    fs::remove_dir(partition)?;
                    Ok(true)
                }
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    remover.detach(&partition)?;
                    Ok(true)
                }
                Ok(_) => Err(invalid_data("partition path is not a directory")),
                Err(error) if path_is_missing(&error) => Ok(false),
                Err(error) => Err(error),
            }
        }
    }
}

#[cfg(windows)]
pub(crate) fn remove_windows(root: &Path, target: &RemoveTarget) -> io::Result<bool> {
    let mut remover = WindowsRemover::new(root);
    let removed = remove_target(root, target, &mut remover)?;
    if removed {
        sync_removals(root, std::slice::from_ref(target))?;
    }
    Ok(removed)
}

fn path_is_missing(error: &io::Error) -> bool {
    if error.kind() == ErrorKind::NotFound {
        return true;
    }
    #[cfg(unix)]
    if error.raw_os_error() == Some(libc::ENAMETOOLONG) {
        return true;
    }
    #[cfg(windows)]
    if error.raw_os_error() == Some(206) {
        return true;
    }
    false
}

fn sync_removals(root: &Path, targets: &[RemoveTarget]) -> io::Result<()> {
    let partitions = targets
        .iter()
        .filter_map(|target| match target {
            RemoveTarget::Blob { partition, .. } => Some(root.join(partition)),
            RemoveTarget::Partition(_) => None,
        })
        .collect::<BTreeSet<_>>();
    for partition in partitions {
        match fs::symlink_metadata(&partition) {
            Ok(metadata) if metadata.file_type().is_dir() => sync_directory(&partition)?,
            Ok(_) => return Err(invalid_data("blob partition path is not a directory")),
            Err(error) if path_is_missing(&error) => {}
            Err(error) => return Err(error),
        }
    }
    sync_directory(root)
}

fn finish_committed<F>(root: &Path, targets: &[RemoveTarget], hook: &mut F) -> io::Result<()>
where
    F: FnMut(Progress) -> io::Result<()>,
{
    #[cfg(windows)]
    let mut remover = WindowsRemover::new(root);
    for (index, target) in targets.iter().enumerate() {
        #[cfg(not(windows))]
        remove_target(root, target)?;
        #[cfg(windows)]
        remove_target(root, target, &mut remover)?;
        hook(Progress::Removed(index + 1))?;
    }
    sync_removals(root, targets)?;
    fs::remove_file(committed_manifest(root))?;
    hook(Progress::MarkerRemoved)?;
    sync_directory(&control_directory(root))
}

fn remove_batch_with<F>(root: &Path, targets: &[RemoveTarget], mut hook: F) -> io::Result<()>
where
    F: FnMut(Progress) -> io::Result<()>,
{
    if targets.is_empty() {
        return Ok(());
    }
    let encoded = encode_manifest(targets)?;

    let root_metadata = match fs::metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !root_metadata.is_dir() {
        // No control directory can exist below a non-directory root. Let the requested
        // namespace operation preserve its more specific error classification.
        return Ok(());
    }

    let control = ensure_control_directory(root)?;
    let prepared = prepared_manifest(root);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&prepared)?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    drop(file);
    hook(Progress::Prepared)?;

    fs::rename(prepared, committed_manifest(root))?;
    sync_directory(&control)?;
    hook(Progress::Committed)?;
    finish_committed(root, targets, &mut hook)
}

fn recover_with<F>(root: &Path, sync_control: F) -> io::Result<()>
where
    F: FnOnce(&Path) -> io::Result<()>,
{
    let root_metadata = match fs::metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !root_metadata.is_dir() {
        // No control directory can exist below a non-directory root. Let the requested
        // namespace operation preserve its more specific error classification.
        return Ok(());
    }
    let control = control_directory(root);
    if !require_directory(&control)? {
        return Ok(());
    }

    #[cfg(windows)]
    cleanup_graveyards(root);
    discard_prepared(root)?;
    let targets = read_committed(root)?;
    // Marker presence and absence become authoritative only after this directory is synced.
    sync_control(&control)?;
    let Some(targets) = targets else {
        return Ok(());
    };
    finish_committed(root, &targets, &mut |_| Ok(()))
}

/// Complete or discard any batch state before exposing the storage namespace.
pub(crate) fn recover(root: &Path) -> io::Result<()> {
    recover_with(root, sync_directory)
}

/// Durably commit and complete a canonical removal batch.
pub(crate) fn remove_batch(root: &Path, targets: &[RemoveTarget]) -> io::Result<()> {
    remove_batch_with(root, targets, |_| Ok(()))
}

#[cfg(test)]
pub(crate) fn interrupt_committed_for_test(
    root: &Path,
    targets: &[RemoveTarget],
    after_removals: usize,
) -> io::Result<()> {
    remove_batch_with(root, targets, |progress| {
        let stop = if after_removals == 0 {
            progress == Progress::Committed
        } else {
            progress == Progress::Removed(after_removals)
        };
        if stop {
            return Err(io::Error::other("injected committed batch interruption"));
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::removal::canonicalize;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_ROOT: AtomicU64 = AtomicU64::new(0);

    fn test_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "runtime_remove_batch_{name}_{}_{}",
            std::process::id(),
            NEXT_TEST_ROOT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn create_blob(root: &Path, partition: &str, name: &[u8]) -> PathBuf {
        let directory = root.join(partition);
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join(hex(name));
        fs::write(&path, b"blob").unwrap();
        path
    }

    #[test]
    fn canonicalizes_and_validates_before_returning() {
        let targets = vec![
            RemoveTarget::Blob {
                partition: "beta".into(),
                name: b"two".to_vec(),
            },
            RemoveTarget::Blob {
                partition: "alpha".into(),
                name: b"one".to_vec(),
            },
            RemoveTarget::Blob {
                partition: "beta".into(),
                name: b"two".to_vec(),
            },
            RemoveTarget::Partition("beta".into()),
        ];
        assert_eq!(
            canonicalize(targets).unwrap(),
            vec![
                RemoveTarget::Blob {
                    partition: "alpha".into(),
                    name: b"one".to_vec(),
                },
                RemoveTarget::Partition("beta".into()),
            ]
        );

        assert!(
            canonicalize(vec![
                RemoveTarget::Partition("valid".into()),
                RemoveTarget::Partition("../invalid".into()),
            ])
            .is_err()
        );
    }

    #[test]
    fn recovery_discards_uncommitted_staging() {
        let root = test_root("prepared");
        let blob = create_blob(&root, "partition", b"blob");
        let targets = canonicalize(vec![RemoveTarget::Blob {
            partition: "partition".into(),
            name: b"blob".to_vec(),
        }])
        .unwrap();

        let result = remove_batch_with(&root, &targets, |progress| {
            if progress == Progress::Prepared {
                return Err(io::Error::other("stop before commit"));
            }
            Ok(())
        });
        assert!(result.is_err());
        assert!(blob.exists());
        assert!(prepared_manifest(&root).exists());

        recover(&root).unwrap();
        assert!(blob.exists());
        assert!(!prepared_manifest(&root).exists());
        assert!(!committed_manifest(&root).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_completes_partially_applied_commit() {
        let root = test_root("committed");
        let first = create_blob(&root, "alpha", b"remove");
        let keep = create_blob(&root, "alpha", b"keep");
        let partition = create_blob(&root, "beta", b"remove");
        let untouched = create_blob(&root, "gamma", b"keep");
        let targets = canonicalize(vec![
            RemoveTarget::Partition("beta".into()),
            RemoveTarget::Blob {
                partition: "alpha".into(),
                name: b"remove".to_vec(),
            },
        ])
        .unwrap();

        let result = remove_batch_with(&root, &targets, |progress| {
            if progress == Progress::Removed(1) {
                return Err(io::Error::other("stop after first deletion"));
            }
            Ok(())
        });
        assert!(result.is_err());
        assert!(!first.exists());
        assert!(partition.exists());
        assert!(committed_manifest(&root).exists());

        recover(&root).unwrap();
        assert!(!first.exists());
        assert!(!root.join("beta").exists());
        assert!(keep.exists());
        assert!(untouched.exists());
        assert!(!committed_manifest(&root).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_retries_marker_removal_sync() {
        let root = test_root("marker_sync");
        let blob = create_blob(&root, "partition", b"blob");
        let targets = canonicalize(vec![RemoveTarget::Blob {
            partition: "partition".into(),
            name: b"blob".to_vec(),
        }])
        .unwrap();
        let result = remove_batch_with(&root, &targets, |progress| {
            if progress == Progress::MarkerRemoved {
                return Err(io::Error::other("injected marker sync failure"));
            }
            Ok(())
        });
        assert!(result.is_err());
        assert!(!blob.exists());
        assert!(!committed_manifest(&root).exists());

        // The marker's absence is not durable until recovery can open and sync its directory.
        assert!(recover_with(&root, |_| Err(io::Error::other("injected sync failure"))).is_err());
        recover(&root).unwrap();
        let recreated = create_blob(&root, "partition", b"blob");
        recover(&root).unwrap();
        assert!(recreated.exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_publishes_visible_commit_before_deleting() {
        let root = test_root("commit_sync");
        let blob = create_blob(&root, "partition", b"blob");
        let targets = canonicalize(vec![RemoveTarget::Blob {
            partition: "partition".into(),
            name: b"blob".to_vec(),
        }])
        .unwrap();
        let result = remove_batch_with(&root, &targets, |progress| {
            if progress == Progress::Committed {
                return Err(io::Error::other("injected committed interruption"));
            }
            Ok(())
        });
        assert!(result.is_err());
        assert!(blob.exists());
        assert!(committed_manifest(&root).exists());

        // Recovery cannot delete until the visible commit is durably published.
        assert!(recover_with(&root, |_| Err(io::Error::other("injected sync failure"))).is_err());
        assert!(blob.exists());
        recover(&root).unwrap();
        assert!(!blob.exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_recreates_names_while_old_handles_remain_open() {
        let root = test_root("windows_generations");
        let path = create_blob(&root, "blob_partition", b"blob");
        let targets = canonicalize(vec![RemoveTarget::Blob {
            partition: "blob_partition".into(),
            name: b"blob".to_vec(),
        }])
        .unwrap();
        let mut generations = Vec::new();

        for generation in 0..3 {
            let contents = format!("generation-{generation}").into_bytes();
            fs::write(&path, &contents).unwrap();
            generations.push((File::open(&path).unwrap(), contents));
            remove_batch(&root, &targets).unwrap();
        }
        fs::write(&path, b"current").unwrap();

        for (mut handle, expected) in generations {
            let mut actual = Vec::new();
            handle.read_to_end(&mut actual).unwrap();
            assert_eq!(actual, expected);
        }

        let partition_blob = create_blob(&root, "whole_partition", b"blob");
        let mut old_partition_handle = File::open(&partition_blob).unwrap();
        let targets =
            canonicalize(vec![RemoveTarget::Partition("whole_partition".into())]).unwrap();
        remove_batch(&root, &targets).unwrap();
        fs::create_dir(root.join("whole_partition")).unwrap();
        fs::write(&partition_blob, b"current partition").unwrap();

        let mut old_contents = Vec::new();
        old_partition_handle.read_to_end(&mut old_contents).unwrap();
        assert_eq!(old_contents, b"blob");

        drop(old_partition_handle);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_committed_manifest_blocks_recovery() {
        let root = test_root("malformed");
        let blob = create_blob(&root, "partition", b"blob");
        let targets = canonicalize(vec![RemoveTarget::Blob {
            partition: "partition".into(),
            name: b"blob".to_vec(),
        }])
        .unwrap();
        let control = ensure_control_directory(&root).unwrap();
        let mut encoded = encode_manifest(&targets).unwrap();
        encoded[0] ^= 1;
        fs::write(committed_manifest(&root), encoded).unwrap();

        let error = recover(&root).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert!(blob.exists());
        assert!(committed_manifest(&root).exists());

        fs::remove_file(committed_manifest(&root)).unwrap();
        fs::remove_dir(control).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn decoder_rejects_excessive_target_count_before_allocating() {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(MANIFEST_MAGIC);
        encoded.extend_from_slice(&MANIFEST_VERSION.to_be_bytes());
        encoded.extend_from_slice(&((MAX_TARGETS as u32) + 1).to_be_bytes());
        let checksum = Crc32::checksum(&encoded);
        encoded.extend_from_slice(&checksum.to_be_bytes());

        let error = decode_manifest(&encoded).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn manifest_layout_and_checksum_round_trip() {
        let targets = vec![
            RemoveTarget::Partition("alpha".into()),
            RemoveTarget::Blob {
                partition: "beta".into(),
                name: vec![0, 0xff],
            },
        ];
        let encoded = encode_manifest(&targets).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(MANIFEST_MAGIC);
        expected.extend_from_slice(&MANIFEST_VERSION.to_be_bytes());
        expected.extend_from_slice(&2u32.to_be_bytes());
        expected.push(TAG_PARTITION);
        expected.extend_from_slice(&5u32.to_be_bytes());
        expected.extend_from_slice(b"alpha");
        expected.push(TAG_BLOB);
        expected.extend_from_slice(&4u32.to_be_bytes());
        expected.extend_from_slice(b"beta");
        expected.extend_from_slice(&2u32.to_be_bytes());
        expected.extend_from_slice(&[0, 0xff]);
        let checksum = Crc32::checksum(&expected);
        expected.extend_from_slice(&checksum.to_be_bytes());

        assert_eq!(encoded, expected);
        assert_eq!(decode_manifest(&encoded).unwrap(), targets);
    }
}
