//! Filesystem helpers for `storage_bench`.
//!
//! The benchmark intentionally uses the runtime's normal storage selection
//! path. The active backend is therefore detected from compile-time feature
//! selection and reported at runtime so results cannot be mixed up.

use crate::config::{WriteShape, DEFAULT_IO_SIZE};
use bytes::Bytes;
use commonware_runtime::{Blob, IoBuf, IoBufs, Storage};
use commonware_utils::hex;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
#[cfg(unix)]
use std::{fs::OpenOptions, io, os::fd::AsRawFd};

/// Default partition used by the standalone benchmark harness.
pub(crate) const PARTITION: &str = "storage-bench";

/// Large chunk used when initially populating fixed-size files.
const DEFAULT_FILL_CHUNK_SIZE: usize = 1024 * 1024;

/// Create a fresh root directory for one benchmark run.
///
/// The benchmark process creates only one root, so a stable operation-scoped
/// directory is enough here. Any leftover directory from a previous interrupted
/// run is removed before the new benchmark starts.
pub(crate) fn prepare_root(root: &Path, scenario: &str) -> std::io::Result<PathBuf> {
    fs::create_dir_all(root)?;
    let root = root.join(format!("commonware_storage_bench_{scenario}"));
    let _ = fs::remove_dir_all(&root);
    Ok(root)
}

/// Remove a benchmark root after the runtime has dropped its storage state.
pub(crate) fn cleanup_root(root: &Path) {
    // The io_uring storage path owns a dedicated worker thread. Give it a
    // brief chance to observe dropped handles before removing the directory.
    std::thread::sleep(Duration::from_millis(10));
    let _ = fs::remove_dir_all(root);
}

/// Return the compiled storage backend name for this binary.
pub(crate) const fn backend_name() -> &'static str {
    #[cfg(feature = "iouring-storage")]
    {
        "iouring"
    }

    #[cfg(not(feature = "iouring-storage"))]
    {
        "tokio"
    }
}

/// Return the on-disk path of a blob.
pub(crate) fn blob_path(root: &Path, partition: &str, name: &[u8]) -> PathBuf {
    root.join(partition).join(hex(name))
}

/// Force physical allocation for a blob that already has the desired size.
///
/// The benchmark uses this for overwrite workloads so they focus on the
/// steady-state write path rather than on first-write allocation behavior.
#[cfg(unix)]
pub(crate) fn preallocate_blob(root: &Path, partition: &str, name: &[u8]) -> io::Result<()> {
    let path = blob_path(root, partition, name);
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
    file.sync_all()?;
    Ok(())
}

/// No-op fallback when physical preallocation is unavailable.
#[cfg(not(unix))]
pub(crate) fn preallocate_blob(
    _root: &Path,
    _partition: &str,
    _name: &[u8],
) -> std::io::Result<()> {
    Ok(())
}

/// Best-effort eviction of a blob from the OS page cache.
///
/// This is intentionally file-scoped rather than global. It avoids privileged
/// operations such as writing `/proc/sys/vm/drop_caches`.
///
/// On Linux, `POSIX_FADV_DONTNEED` asks the kernel to discard cached pages
/// associated with the file region rather than attaching some sticky state to
/// this particular file descriptor. Reopening the file later does not undo the
/// eviction; it simply creates a fresh handle that will fault data back into
/// the page cache as reads occur.
#[cfg(unix)]
pub(crate) fn evict_blob_cache(root: &Path, partition: &str, name: &[u8]) -> io::Result<()> {
    let path = blob_path(root, partition, name);
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    file.sync_all()?;

    // SAFETY: The file descriptor is valid for the duration of the call.
    let result = unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result));
    }
    Ok(())
}

/// No-op fallback when file-scoped cache eviction is unavailable.
#[cfg(not(unix))]
pub(crate) fn evict_blob_cache(
    _root: &Path,
    _partition: &str,
    _name: &[u8],
) -> std::io::Result<()> {
    Ok(())
}

/// Create and fully populate a fixed-size blob for read-heavy scenarios.
pub(crate) async fn prepare_prefilled_blob<S>(
    storage: &S,
    root: &Path,
    name: &[u8],
    file_size: u64,
    seed: u64,
) -> Result<(), String>
where
    S: Storage,
{
    let (blob, _) = storage
        .open(PARTITION, name)
        .await
        .map_err(|err| err.to_string())?;
    blob.resize(file_size)
        .await
        .map_err(|err| err.to_string())?;
    blob.sync().await.map_err(|err| err.to_string())?;
    preallocate_blob(root, PARTITION, name)
        .map_err(|err| format!("failed to preallocate {}: {err}", root.display()))?;

    let fill_chunk_size = DEFAULT_FILL_CHUNK_SIZE.max(DEFAULT_IO_SIZE);
    let mut offset = 0u64;
    while offset < file_size {
        let remaining = (file_size - offset) as usize;
        let len = remaining.min(fill_chunk_size);
        let payload = deterministic_bytes(len, seed ^ offset);
        blob.write_at(offset, payload)
            .await
            .map_err(|err| err.to_string())?;
        offset += len as u64;
    }
    blob.sync().await.map_err(|err| err.to_string())?;
    Ok(())
}

/// Create a fixed-size preallocated blob for overwrite workloads.
pub(crate) async fn prepare_preallocated_blob<S>(
    storage: &S,
    root: &Path,
    name: &[u8],
    file_size: u64,
) -> Result<(), String>
where
    S: Storage,
{
    let (blob, _) = storage
        .open(PARTITION, name)
        .await
        .map_err(|err| err.to_string())?;
    blob.resize(file_size)
        .await
        .map_err(|err| err.to_string())?;
    blob.sync().await.map_err(|err| err.to_string())?;
    preallocate_blob(root, PARTITION, name)
        .map_err(|err| format!("failed to preallocate {}: {err}", root.display()))?;
    Ok(())
}

/// Evict a blob from the page cache for a cold-cache benchmark.
pub(crate) fn prepare_cold_read_cache(root: &Path, name: &[u8]) -> Result<(), String> {
    evict_blob_cache(root, PARTITION, name)
        .map_err(|err| format!("failed to evict file cache: {err}"))?;
    Ok(())
}

/// Build a write payload according to the configured shape.
pub(crate) fn create_write_payload(io_size: usize, seed: u64, shape: WriteShape) -> IoBufs {
    match shape {
        WriteShape::Contiguous => IoBufs::from(deterministic_bytes(io_size, seed)),
        WriteShape::Vectored => vectored_payload(io_size, seed),
    }
}

/// Create a deterministic contiguous payload.
fn deterministic_bytes(size: usize, seed: u64) -> Bytes {
    let mut bytes = vec![0u8; size];
    seeded_rng(size, seed).fill_bytes(&mut bytes);
    Bytes::from(bytes)
}

/// Create a deterministic four-buffer vectored payload.
fn vectored_payload(size: usize, seed: u64) -> IoBufs {
    const CHUNKS: usize = 4;
    let base = size / CHUNKS;
    let remainder = size % CHUNKS;
    let mut rng = seeded_rng(size, seed);
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

/// Deterministic RNG used for benchmark payloads.
fn seeded_rng(size: usize, discriminator: u64) -> StdRng {
    StdRng::seed_from_u64((size as u64).rotate_left(17) ^ discriminator)
}
