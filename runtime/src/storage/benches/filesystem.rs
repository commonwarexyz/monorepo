//! Filesystem helpers.

use crate::{
    config::WriteShape,
    error::{Error, Result},
};
use bytes::Bytes;
use commonware_runtime::{Blob, IoBuf, IoBufs, Storage};
#[cfg(target_os = "linux")]
use commonware_utils::hex;
use rand::Rng;
use std::{
    fs, io,
    path::{Path, PathBuf},
    process,
    time::{SystemTime, UNIX_EPOCH},
};
#[cfg(target_os = "linux")]
use std::{fs::OpenOptions, os::fd::AsRawFd};

const DEFAULT_FILL_CHUNK_SIZE: usize = 1024 * 1024;

pub const fn backend_name() -> &'static str {
    if cfg!(feature = "iouring-storage") {
        "iouring"
    } else {
        "tokio"
    }
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
        blob.write_at(offset, payload).await?;
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
