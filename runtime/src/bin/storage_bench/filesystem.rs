//! Filesystem helpers for `storage_bench`.
//!
//! The benchmark uses the runtime's normal storage selection path. The active
//! backend is detected from compile-time feature selection and reported at
//! runtime so results cannot be mixed up.

use crate::{
    config::{WriteShape, DEFAULT_IO_SIZE},
    workers::ResultExt,
};
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

pub const PARTITION: &str = "storage-bench";
pub const PRIMARY_BLOB_NAME: &[u8] = b"blob";

const DEFAULT_FILL_CHUNK_SIZE: usize = 1024 * 1024;

/// Create a fresh root directory for one benchmark run.
///
/// Any leftover directory from a previous interrupted run is removed first.
pub fn prepare_root(root: &Path, scenario: &str) -> std::io::Result<PathBuf> {
    fs::create_dir_all(root)?;
    let root = root.join(format!("commonware_storage_bench_{scenario}"));
    let _ = fs::remove_dir_all(&root);
    Ok(root)
}

/// Remove the benchmark root after the runtime has dropped its storage state.
pub fn cleanup_root(root: &Path) {
    // The io_uring backend owns a dedicated worker thread; give it a brief
    // chance to observe dropped handles before removing the directory.
    std::thread::sleep(Duration::from_millis(10));
    let _ = fs::remove_dir_all(root);
}

pub const fn backend_name() -> &'static str {
    #[cfg(feature = "iouring-storage")]
    {
        "iouring"
    }

    #[cfg(not(feature = "iouring-storage"))]
    {
        "tokio"
    }
}

fn blob_path(root: &Path, partition: &str, name: &[u8]) -> PathBuf {
    root.join(partition).join(hex(name))
}

/// Force physical allocation for a blob that already has the desired size.
///
/// Overwrite workloads call this so they measure the steady-state write path
/// rather than first-write allocation behavior.
#[cfg(unix)]
fn preallocate_blob(root: &Path, partition: &str, name: &[u8]) -> io::Result<()> {
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

#[cfg(not(unix))]
fn preallocate_blob(_root: &Path, _partition: &str, _name: &[u8]) -> std::io::Result<()> {
    Ok(())
}

/// Best-effort eviction of a blob from the OS page cache.
///
/// On Linux, `POSIX_FADV_DONTNEED` asks the kernel to discard cached pages
/// for the file. The effect is per-inode, not per-fd, so reopening the file
/// later does not undo it.
#[cfg(unix)]
pub fn evict_blob_cache(root: &Path, partition: &str, name: &[u8]) -> io::Result<()> {
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

#[cfg(not(unix))]
pub fn evict_blob_cache(_root: &Path, _partition: &str, _name: &[u8]) -> std::io::Result<()> {
    Ok(())
}

/// Create a fixed-size, preallocated blob. Returns the open blob handle.
pub async fn prepare_blob<S>(
    storage: &S,
    root: &Path,
    name: &[u8],
    file_size: u64,
) -> Result<S::Blob, String>
where
    S: Storage,
{
    let (blob, _) = storage.open(PARTITION, name).await.str_err()?;
    blob.resize(file_size).await.str_err()?;
    blob.sync().await.str_err()?;
    preallocate_blob(root, PARTITION, name)
        .map_err(|err| format!("failed to preallocate {}: {err}", root.display()))?;
    Ok(blob)
}

/// Create a fixed-size blob and fill it with deterministic data.
///
/// Returns the open blob handle so the caller can reuse it for the timed phase.
pub async fn prepare_filled_blob<S>(
    storage: &S,
    root: &Path,
    name: &[u8],
    file_size: u64,
    seed: u64,
) -> Result<S::Blob, String>
where
    S: Storage,
{
    let blob = prepare_blob(storage, root, name, file_size).await?;

    let chunk_size = DEFAULT_FILL_CHUNK_SIZE.max(DEFAULT_IO_SIZE);
    let mut offset = 0u64;
    while offset < file_size {
        let len = ((file_size - offset) as usize).min(chunk_size);
        let payload = deterministic_bytes(len, seed ^ offset);
        blob.write_at(offset, payload).await.str_err()?;
        offset += len as u64;
    }
    blob.sync().await.str_err()?;
    Ok(blob)
}

/// Build a deterministic write payload of the given size and shape.
pub fn create_write_payload(io_size: usize, seed: u64, shape: WriteShape) -> IoBufs {
    match shape {
        WriteShape::Contiguous => IoBufs::from(deterministic_bytes(io_size, seed)),
        WriteShape::Vectored => vectored_payload(io_size, seed),
    }
}

fn deterministic_bytes(size: usize, seed: u64) -> Bytes {
    let mut bytes = vec![0u8; size];
    seeded_rng(size, seed).fill_bytes(&mut bytes);
    Bytes::from(bytes)
}

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

/// Create a deterministic RNG by mixing `size` and `discriminator`.
///
/// The rotation spreads the size bits across different positions before XORing
/// so that (size=4096, offset=0) and (size=0, offset=4096) produce different
/// seeds.
fn seeded_rng(size: usize, discriminator: u64) -> StdRng {
    StdRng::seed_from_u64((size as u64).rotate_left(17) ^ discriminator)
}
