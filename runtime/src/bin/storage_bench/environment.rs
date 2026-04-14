//! Filesystem and backend metadata for one benchmark run.
//!
//! The benchmark intentionally uses the runtime's normal storage selection
//! path. The active backend is therefore detected from compile-time feature
//! selection and reported at runtime so results cannot be mixed up.

use commonware_utils::hex;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
#[cfg(unix)]
use std::{fs::OpenOptions, io, os::fd::AsRawFd};

/// Default partition used by the standalone benchmark harness.
pub(crate) const PARTITION: &str = "storage-bench";

/// Per-run benchmark directory and file helpers.
#[derive(Debug)]
pub(crate) struct Environment {
    root: PathBuf,
}

impl Environment {
    /// Create a fresh root directory for one benchmark run.
    ///
    /// The benchmark process creates only one environment, so a stable
    /// operation-scoped directory is enough here. Any leftover directory from a
    /// previous interrupted run is removed before the new benchmark starts.
    pub(crate) fn new(operation: &str, base_root: &Path) -> std::io::Result<Self> {
        fs::create_dir_all(base_root)?;
        let root = base_root.join(format!("commonware_storage_bench_{operation}"));
        let _ = fs::remove_dir_all(&root);
        Ok(Self { root })
    }

    /// Return the root directory for this benchmark run.
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// Return the compiled storage backend name for this binary.
    pub(crate) const fn backend(&self) -> &'static str {
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
    pub(crate) fn blob_path(&self, partition: &str, name: &[u8]) -> PathBuf {
        self.root.join(partition).join(hex(name))
    }

    /// Force physical allocation for a blob that already has the desired size.
    ///
    /// The benchmark uses this for overwrite workloads so they focus on the
    /// steady-state write path rather than on first-write allocation behavior.
    #[cfg(unix)]
    pub(crate) fn preallocate_blob(&self, partition: &str, name: &[u8]) -> io::Result<()> {
        let path = self.blob_path(partition, name);
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let length = file.metadata()?.len();

        // SAFETY: The file descriptor is valid for the duration of the call,
        // and the length comes from the current file metadata.
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
    pub(crate) fn preallocate_blob(&self, _partition: &str, _name: &[u8]) -> std::io::Result<()> {
        Ok(())
    }

    /// Best-effort eviction of a blob from the OS page cache.
    ///
    /// This is intentionally file-scoped rather than global. It avoids
    /// privileged operations such as writing `/proc/sys/vm/drop_caches`.
    ///
    /// On Linux, `POSIX_FADV_DONTNEED` asks the kernel to discard cached pages
    /// associated with the file region rather than attaching some sticky state
    /// to this particular file descriptor. Reopening the file later does not
    /// undo the eviction; it simply creates a fresh handle that will fault data
    /// back into the page cache as reads occur.
    #[cfg(unix)]
    pub(crate) fn evict_blob_cache(&self, partition: &str, name: &[u8]) -> io::Result<()> {
        let path = self.blob_path(partition, name);
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        file.sync_all()?;

        // SAFETY: The file descriptor is valid for the duration of the call.
        let result =
            unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        Ok(())
    }

    /// No-op fallback when file-scoped cache eviction is unavailable.
    #[cfg(not(unix))]
    pub(crate) fn evict_blob_cache(&self, _partition: &str, _name: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for Environment {
    fn drop(&mut self) {
        // The io_uring storage path owns a dedicated worker thread. Give it a
        // brief chance to observe dropped handles before removing the
        // directory.
        std::thread::sleep(Duration::from_millis(10));
        let _ = fs::remove_dir_all(&self.root);
    }
}
