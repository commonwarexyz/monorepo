//! An exclusive hold on a storage directory, so no operation from a previous
//! run is still in flight when a new run begins.

use std::{
    fs::{File, OpenOptions, TryLockError},
    io,
    path::Path,
    sync::Arc,
};
use tracing::warn;

/// Name of the hold file at the storage directory root.
///
/// It cannot collide with stored data: blobs live inside partition directories,
/// and `validate_partition_name` rejects the `.`, so no partition can take this
/// name.
const HOLD_NAME: &str = ".hold";

/// An exclusive hold on a storage directory, backed by an OS advisory lock on
/// a file within it.
///
/// A backend shares the hold (via [Arc]) with everything that can still touch
/// the directory after its storage instance is gone. For tokio that is every
/// blob's file handle and every dispatched blocking operation. For io_uring it
/// is storage, every blob's held file, and every admitted storage request, even
/// when an operation executes on a different worker or runner. The hold is
/// released only once all of them have finished, including mutations whose
/// futures were dropped. Dropping a future does not stop retained writes or
/// syncs already handed to a blocking pool or ring.
/// [Hold::acquire] waits for that release.
///
/// The lock lives on the open file description, not the file: the OS releases
/// it when the holding process exits, cleanly or not, so a crash needs no
/// cleanup. Every thread of the process shares that description, so a blocking
/// pool thread holds the lock through the same file, and exit releases it only
/// after every thread has stopped, so an operation still running when the
/// process dies cannot land under a successor. Child processes do not inherit
/// it, since the file is opened close-on-exec. The file is empty and never
/// deleted, so a contended holder is found with `lsof` or `fuser`. The lock is
/// bound to the inode: removing or recreating the directory while a run may
/// still be alive voids the exclusion.
///
/// The guarantee is scoped to one machine and to filesystems with real
/// advisory locks. On network filesystems (NFS, SMB, FUSE) the lock may be
/// client-local or per process, so it may exclude neither other machines nor
/// other instances in the same process. A filesystem that rejects the lock
/// fails storage construction.
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
