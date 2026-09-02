//! An exclusive hold on a storage directory, ensuring operations dispatched by
//! a previous run never interfere with a successor.

use std::{
    fs::{File, OpenOptions, TryLockError},
    io,
    path::Path,
    sync::Arc,
};
use tracing::warn;

/// Name of the hold file at the storage directory root.
///
/// This never collides with stored data. Blobs live one level down inside a
/// partition directory, so none can occupy the root, and `validate_partition_name`
/// rejects the `.` in `.hold`, so no partition can either.
const HOLD_NAME: &str = ".hold";

/// An exclusive hold on a storage directory, backed by an OS advisory lock on
/// a file within it.
///
/// A backend shares the hold (via [Arc]) with everything that can still touch
/// the directory once its storage instance is gone: every blocking operation
/// it dispatches, every blob it opened, and (for io_uring) the ring thread. The
/// hold is released only once all of them have finished, including operations
/// whose futures were dropped mid-flight (dropping a future does not cancel
/// work already handed to a blocking pool or ring). [Hold::acquire] waits for
/// that release, so a successor never observes a previous run's operations
/// landing underneath it.
///
/// The lock is held by the open file description, not by the file's existence:
/// the operating system releases it when the holding process exits (cleanly or
/// not), so a crashed run never requires manual cleanup. The hold file is empty
/// and never deleted. It is only a lock target, so the holder of a contended
/// lock is found with the usual tools (`lsof`, `fuser`) rather than from its
/// contents. The lock is bound to the hold file's inode: removing or recreating
/// the storage directory while a run may still be alive voids the exclusion.
///
/// The guarantee is scoped to one machine and to filesystems with real
/// advisory locks: on network filesystems (NFS, SMB, FUSE) the lock may be
/// client-local or per process, excluding neither other machines nor other
/// instances in the same process. A filesystem without advisory-lock support
/// fails acquisition, which fails storage construction.
pub(crate) struct Hold {
    _file: File,
}

impl Hold {
    /// Acquire the hold for `dir`, creating the directory and hold file if
    /// missing. Blocks until any previous holder releases, warning first if
    /// the hold is contended. A handled signal does not interrupt the wait.
    pub(crate) fn acquire(dir: &Path) -> io::Result<Arc<Self>> {
        std::fs::create_dir_all(dir)?;
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join(HOLD_NAME))?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                warn!(
                    directory = %dir.display(),
                    "waiting for storage directory hold (operations from a previous run may still be finishing)"
                );

                // flock is not restarted after a handled signal, so keep waiting on EINTR.
                loop {
                    match file.lock() {
                        Ok(()) => break,
                        Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                        Err(err) => return Err(err),
                    }
                }
            }
            Err(TryLockError::Error(err)) => return Err(err),
        }
        Ok(Arc::new(Self { _file: file }))
    }
}

#[cfg(test)]
mod tests {
    use super::{HOLD_NAME, Hold};
    use crate::storage::validate_partition_name;
    use std::fs;

    #[test]
    fn test_hold_name_rejected_as_partition() {
        assert!(validate_partition_name(HOLD_NAME).is_err());
    }

    #[test]
    fn test_acquire_fails_on_unusable_root() {
        // A root occupied by a regular file can be neither created nor locked,
        // which fails storage construction.
        let dir =
            std::env::temp_dir().join(format!("commonware_hold_occupied_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::write(&dir, b"not a directory").unwrap();
        assert!(Hold::acquire(&dir).is_err());
        let _ = fs::remove_file(&dir);
    }
}
