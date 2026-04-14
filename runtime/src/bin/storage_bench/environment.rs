//! Filesystem and backend metadata for one benchmark run.
//!
//! The benchmark intentionally uses the runtime's normal storage selection
//! path. The active backend is therefore detected from compile-time feature
//! selection and reported at runtime so results cannot be mixed up.

use commonware_utils::hex;
use std::{
    fs,
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
#[cfg(unix)]
use std::{fs::OpenOptions, io, os::fd::AsRawFd};

/// Default partition used by the standalone benchmark harness.
pub(crate) const PARTITION: &str = "storage-bench";

static NEXT_STORAGE_BENCH_DIRECTORY: AtomicU64 = AtomicU64::new(0);

/// Storage backend compiled into the current binary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Backend {
    /// The blocking-file-descriptor storage backend used by the Tokio runtime.
    #[cfg(not(feature = "iouring-storage"))]
    Tokio,
    /// The dedicated io_uring-loop storage backend.
    #[cfg(feature = "iouring-storage")]
    IoUring,
}

impl Backend {
    /// Stable backend name used in benchmark output.
    pub(crate) const fn name(self) -> &'static str {
        #[cfg(feature = "iouring-storage")]
        {
            "iouring"
        }

        #[cfg(not(feature = "iouring-storage"))]
        {
            "tokio"
        }
    }
}

/// Detect the storage backend selected for this binary.
pub(crate) const fn detected_backend() -> Backend {
    #[cfg(feature = "iouring-storage")]
    {
        Backend::IoUring
    }

    #[cfg(not(feature = "iouring-storage"))]
    {
        Backend::Tokio
    }
}

/// Per-run benchmark directory and file helpers.
#[derive(Clone, Debug)]
pub(crate) struct BenchmarkEnvironment {
    root: PathBuf,
}

impl BenchmarkEnvironment {
    /// Create a fresh unique root directory for one benchmark run.
    pub(crate) fn new(operation: &str, base_root: &Path) -> std::io::Result<Self> {
        fs::create_dir_all(base_root)?;
        let root = base_root.join(format!(
            "commonware_storage_bench_{operation}_{}_{}",
            process::id(),
            NEXT_STORAGE_BENCH_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        Ok(Self { root })
    }

    /// Return the root directory for this benchmark run.
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// Return the on-disk path of a blob.
    pub(crate) fn blob_path(&self, partition: &str, name: &[u8]) -> PathBuf {
        self.root.join(partition).join(hex(name))
    }

    /// Remove the benchmark root after the runtime has dropped its storage state.
    pub(crate) fn finish(self) {
        // The io_uring storage path owns a dedicated worker thread. Give it a
        // brief chance to observe dropped handles before removing the
        // directory.
        std::thread::sleep(Duration::from_millis(10));
        let _ = fs::remove_dir_all(self.root);
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
