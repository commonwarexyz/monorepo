//! Filesystem helpers.

use crate::{
    config::WriteShape,
    error::{Error, Result},
};
use bytes::Bytes;
#[cfg(target_os = "linux")]
use commonware_formatting::hex;
use commonware_runtime::{AtomicStorage, Blob, IoBuf, IoBufs, Storage, WriteOptions};
use rand::Rng;
use std::{
    fs, io,
    path::{Path, PathBuf},
    process,
    time::{SystemTime, UNIX_EPOCH},
};
#[cfg(target_os = "linux")]
use std::{
    fs::OpenOptions,
    os::{fd::AsRawFd, unix::fs::MetadataExt as _},
};

const DEFAULT_FILL_CHUNK_SIZE: usize = 1024 * 1024;
pub const fn backend_name() -> &'static str {
    if cfg!(feature = "iouring-storage") {
        "iouring"
    } else {
        "tokio"
    }
}

/// Protocol used by blobs opened through [`AtomicStorage`].
pub const fn atomic_protocol() -> &'static str {
    "uno_r05_prepared_root"
}

/// Protocol used to publish prepared roots as one multi-blob decision.
pub const fn atomic_batch_protocol() -> &'static str {
    "uno_r08_embedded_participant_witness"
}

/// On-disk footprint of the benchmark blob after the timed workload.
#[derive(Clone, Copy)]
pub struct FileMetrics {
    pub file_count: u64,
    pub raw_len: u64,
    pub allocated_bytes: u64,
}

#[cfg(target_os = "linux")]
pub fn file_metrics(root: &Path, partition: &str, name: &[u8]) -> io::Result<Option<FileMetrics>> {
    Ok(Some(path_metrics(&root.join(partition).join(hex(name)))?))
}

#[cfg(not(target_os = "linux"))]
pub const fn file_metrics(
    _root: &Path,
    _partition: &str,
    _name: &[u8],
) -> io::Result<Option<FileMetrics>> {
    Ok(None)
}

/// Aggregate on-disk footprint across multi-blob participants.
#[cfg(target_os = "linux")]
pub fn group_file_metrics(
    root: &Path,
    partition: &str,
    names: &[Vec<u8>],
) -> io::Result<Option<FileMetrics>> {
    let mut total = FileMetrics {
        file_count: 0,
        raw_len: 0,
        allocated_bytes: 0,
    };
    for name in names {
        total.add(path_metrics(&root.join(partition).join(hex(name)))?);
    }
    Ok(Some(total))
}

#[cfg(not(target_os = "linux"))]
pub const fn group_file_metrics(
    _root: &Path,
    _partition: &str,
    _names: &[Vec<u8>],
) -> io::Result<Option<FileMetrics>> {
    Ok(None)
}

#[cfg(target_os = "linux")]
fn path_metrics(path: &Path) -> io::Result<FileMetrics> {
    let metadata = fs::metadata(path)?;
    Ok(FileMetrics {
        file_count: 1,
        raw_len: metadata.len(),
        allocated_bytes: metadata.blocks().saturating_mul(512),
    })
}

#[cfg(target_os = "linux")]
impl FileMetrics {
    const fn add(&mut self, other: Self) {
        self.file_count = self.file_count.saturating_add(other.file_count);
        self.raw_len = self.raw_len.saturating_add(other.raw_len);
        self.allocated_bytes = self.allocated_bytes.saturating_add(other.allocated_bytes);
    }
}

/// Current resident memory, for controlled before/after comparisons within one process.
#[cfg(target_os = "linux")]
pub fn resident_set_size() -> Option<u64> {
    let statm = fs::read_to_string("/proc/self/statm").ok()?;
    let resident_pages = statm.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    // SAFETY: `sysconf` has no pointer arguments and `_SC_PAGESIZE` has no side effects.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    (page_size > 0).then(|| resident_pages.saturating_mul(page_size as u64))
}

#[cfg(not(target_os = "linux"))]
pub const fn resident_set_size() -> Option<u64> {
    None
}

/// Create a unique storage root for one benchmark run under the configured parent.
pub fn prepare_root(parent: &Path) -> Result<PathBuf> {
    let metadata = fs::metadata(parent)?;
    if !metadata.is_dir() {
        return Err(Error::Harness(format!(
            "benchmark root parent is not a directory: {}",
            parent.display()
        )));
    }

    let pid = process::id();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let root = parent.join(format!("storage-bench-{pid}-{timestamp}"));
    fs::create_dir(&root)?;
    Ok(root)
}

/// Remove the per-run benchmark root created by [`prepare_root`].
pub fn cleanup_root(root: &Path) -> Result<()> {
    match fs::remove_dir_all(root) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(source.into()),
    }
}

/// Force physical allocation for a blob that already has the desired size.
///
/// Overwrite workloads call this so they measure the steady-state write path
/// rather than first-write allocation behavior.
#[cfg(target_os = "linux")]
fn preallocate_blob(root: &Path, partition: &str, name: &[u8]) -> io::Result<()> {
    let path = root.join(partition).join(hex(name));
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    let length = file.metadata()?.len();

    // SAFETY: The file descriptor is valid for the duration of the call, and
    // the length comes from the current file metadata.
    let result = unsafe {
        libc::posix_fallocate(
            file.as_raw_fd(),
            0,
            length
                .try_into()
                .map_err(|_| io::Error::other("blob too large for posix_fallocate"))?,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
const fn preallocate_blob(_root: &Path, _partition: &str, _name: &[u8]) -> std::io::Result<()> {
    Ok(())
}

/// Reserve an unwritten append range without changing the blob's raw length.
#[cfg(target_os = "linux")]
fn preallocate_blob_tail(root: &Path, partition: &str, name: &[u8], length: u64) -> io::Result<()> {
    let path = root.join(partition).join(hex(name));
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    let offset = file.metadata()?.len();
    let offset = libc::off_t::try_from(offset)
        .map_err(|_| io::Error::other("blob offset is too large for fallocate"))?;
    let length = libc::off_t::try_from(length)
        .map_err(|_| io::Error::other("blob length is too large for fallocate"))?;

    // SAFETY: The descriptor remains valid through the call, and both values were checked against
    // the platform's off_t range. KEEP_SIZE reserves blocks without changing the R05 log frontier.
    let result =
        unsafe { libc::fallocate(file.as_raw_fd(), libc::FALLOC_FL_KEEP_SIZE, offset, length) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    file.sync_all()
}

#[cfg(not(target_os = "linux"))]
const fn preallocate_blob_tail(
    _root: &Path,
    _partition: &str,
    _name: &[u8],
    _length: u64,
) -> std::io::Result<()> {
    Ok(())
}

/// Best-effort eviction of a blob from the OS page cache.
///
/// On Linux, `POSIX_FADV_DONTNEED` asks the kernel to discard cached pages
/// for the file. The effect is per-inode, not per-fd, so reopening the file
/// later does not undo it.
#[cfg(target_os = "linux")]
pub fn drop_page_cache(root: &Path, partition: &str, name: &[u8]) -> io::Result<()> {
    let path = root.join(partition).join(hex(name));
    let file = OpenOptions::new().read(true).write(true).open(path)?;

    // SAFETY: The file descriptor is valid for the duration of the call.
    let result = unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn drop_page_cache(_root: &Path, _partition: &str, _name: &[u8]) -> std::io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "page cache eviction is only supported on Linux",
    ))
}

/// Create a fixed-size, preallocated blob. Returns the open blob handle.
pub async fn prepare_blob<S: Storage>(
    storage: &S,
    root: &Path,
    partition: &str,
    name: &[u8],
    file_size: u64,
) -> Result<S::Blob> {
    let (blob, _) = storage.open(partition, name).await?;
    blob.resize(file_size).await?;
    blob.sync().await?;
    if file_size > 0 {
        // Drop the runtime handle before manipulating the file directly via
        // `posix_fallocate`.
        drop(blob);
        preallocate_blob(root, partition, name)?;
        let (blob, _) = storage.open(partition, name).await?;
        blob.sync().await?;
        return Ok(blob);
    }
    Ok(blob)
}

/// Create a fixed-size atomic blob and publish its initial logical length.
pub async fn prepare_atomic_blob<S: AtomicStorage>(
    storage: &S,
    root: &Path,
    partition: &str,
    name: &[u8],
    file_size: u64,
) -> Result<S::AtomicBlob> {
    let (blob, _) = storage.open_atomic(partition, name).await?;
    blob.resize(file_size).await?;
    blob.sync().await?;
    if file_size > 0 {
        drop(blob);
        preallocate_blob_tail(root, partition, name, file_size)?;
        let (blob, _) = storage.open_atomic(partition, name).await?;
        blob.sync().await?;
        return Ok(blob);
    }
    Ok(blob)
}

/// Create a fixed-size blob and fill it with random data.
///
/// Returns the open blob handle so the caller can reuse it for the timed phase.
pub async fn prepare_filled_blob<S: Storage>(
    rng: &mut impl Rng,
    storage: &S,
    root: &Path,
    partition: &str,
    name: &[u8],
    file_size: u64,
) -> Result<S::Blob> {
    let blob = prepare_blob(storage, root, partition, name, file_size).await?;

    let mut offset = 0u64;
    while offset < file_size {
        let len = ((file_size - offset) as usize).min(DEFAULT_FILL_CHUNK_SIZE);
        let mut payload = vec![0u8; len];
        rng.fill_bytes(&mut payload);
        blob.write_at(offset, payload, WriteOptions::default())
            .await?;
        offset += len as u64;
    }
    blob.sync().await?;
    Ok(blob)
}

/// Build a random write payload of the given size and shape.
pub fn random_write_payload(rng: &mut impl Rng, io_size: usize, shape: WriteShape) -> IoBufs {
    match shape {
        WriteShape::Contiguous => {
            let mut buf = vec![0u8; io_size];
            rng.fill_bytes(&mut buf);
            IoBufs::from(Bytes::from(buf))
        }
        WriteShape::Vectored => {
            const CHUNKS: usize = 4;
            let base = io_size / CHUNKS;
            let remainder = io_size % CHUNKS;
            let chunks = (0..CHUNKS)
                .map(|idx| {
                    let len = base + usize::from(idx < remainder);
                    let mut chunk = vec![0u8; len];
                    rng.fill_bytes(&mut chunk);
                    IoBuf::from(chunk)
                })
                .collect::<Vec<_>>();
            IoBufs::from(chunks)
        }
    }
}
