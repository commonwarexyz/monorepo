//! The real-filesystem [Medium]: one directory level under a root, positional I/O
//! through the blocking pool, fdatasync barriers, and directory fsyncs.

use super::medium::{File, Medium};
use crate::{Error, IoBufs};
use std::{fs, io, os::unix::fs::FileExt as _, path::PathBuf, sync::Arc};
use tokio::task;

/// A [Medium] over a real filesystem rooted at one directory. Holds an exclusive
/// advisory lock on the directory for its lifetime: two processes sharing one storage
/// directory would race each other's families.
#[derive(Clone)]
pub struct Fs {
    root: Arc<PathBuf>,
    /// Keeps the flock held until the last clone drops; also the descriptor
    /// [Medium::free_bytes] measures, since it lives on the root's filesystem.
    lock: Arc<fs::File>,
}

impl Fs {
    /// Uses `root` (created if absent) as the storage directory, taking its lock.
    pub fn new(root: PathBuf) -> Result<Self, Error> {
        fs::create_dir_all(&root).map_err(map_io)?;
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(root.join(".logstore.lock"))
            .map_err(map_io)?;
        // SAFETY: `lock` owns a valid fd that outlives the call; `flock` takes only
        // that fd, performs no memory access, and returns -1 on error.
        let held = unsafe {
            libc::flock(
                std::os::fd::AsRawFd::as_raw_fd(&lock),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        } == 0;
        if !held {
            return Err(map_io(io::Error::new(
                io::ErrorKind::WouldBlock,
                "storage directory is locked by another process",
            )));
        }
        Ok(Self {
            root: Arc::new(root),
            lock: Arc::new(lock),
        })
    }

    fn dir_path(&self, dir: &str) -> PathBuf {
        self.root.join(dir)
    }
}

/// A handle to one file. Clones share the descriptor.
#[derive(Clone)]
pub struct FsFile {
    file: Arc<fs::File>,
}

fn map_io(error: io::Error) -> Error {
    Error::Io(Arc::new(error))
}

/// Runs a blocking filesystem operation on the blocking pool.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> Result<T, Error> {
    task::spawn_blocking(f)
        .await
        .map_err(|_| Error::ReadFailed)?
        .map_err(map_io)
}

/// Fsyncs a directory, making its entries durable.
fn sync_dir_at(path: &PathBuf) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}

impl File for FsFile {
    async fn size(&self) -> Result<u64, Error> {
        let file = self.file.clone();
        blocking(move || Ok(file.metadata()?.len())).await
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<Vec<u8>, Error> {
        let file = self.file.clone();
        blocking(move || {
            let mut buf = vec![0u8; len];
            file.read_exact_at(&mut buf, offset)?;
            Ok(buf)
        })
        .await
        .map_err(|error| match error {
            // The contract distinguishes short reads from I/O failures.
            Error::Io(inner) if inner.kind() == io::ErrorKind::UnexpectedEof => {
                Error::LogInsufficientLength
            }
            other => other,
        })
    }

    async fn write_at(&self, offset: u64, data: impl Into<IoBufs> + Send) -> Result<(), Error> {
        let data = data.into().coalesce();
        if data.as_ref().is_empty() {
            return Ok(());
        }
        let file = self.file.clone();
        blocking(move || file.write_all_at(data.as_ref(), offset)).await
    }

    async fn sync(&self) -> Result<(), Error> {
        let file = self.file.clone();
        blocking(move || file.sync_data()).await
    }

    async fn set_len(&self, len: u64) -> Result<(), Error> {
        let file = self.file.clone();
        blocking(move || file.set_len(len)).await
    }
}

impl Medium for Fs {
    type File = FsFile;

    async fn create(&self, dir: &str, name: &str) -> Result<Self::File, Error> {
        let path = self.dir_path(dir);
        let file_path = path.join(name);
        let file = blocking(move || {
            fs::create_dir_all(&path)?;
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&file_path)
        })
        .await?;
        Ok(FsFile {
            file: Arc::new(file),
        })
    }

    async fn open(&self, dir: &str, name: &str) -> Result<Option<Self::File>, Error> {
        let file_path = self.dir_path(dir).join(name);
        let opened = blocking(move || {
            match fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&file_path)
            {
                Ok(file) => Ok(Some(file)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
            }
        })
        .await?;
        Ok(opened.map(|file| FsFile {
            file: Arc::new(file),
        }))
    }

    async fn rename(&self, dir: &str, from: &str, to: &str) -> Result<(), Error> {
        let path = self.dir_path(dir);
        let (from, to) = (path.join(from), path.join(to));
        blocking(move || fs::rename(from, to)).await
    }

    async fn remove(&self, dir: &str, name: &str) -> Result<(), Error> {
        let file_path = self.dir_path(dir).join(name);
        blocking(move || fs::remove_file(file_path)).await
    }

    async fn list(&self, dir: &str) -> Result<Option<Vec<String>>, Error> {
        let path = self.dir_path(dir);
        blocking(move || match fs::read_dir(&path) {
            Ok(entries) => {
                let mut names = Vec::new();
                for entry in entries {
                    let entry = entry?;
                    if entry.file_type()?.is_file() {
                        names.push(entry.file_name().to_string_lossy().into_owned());
                    }
                }
                names.sort();
                Ok(Some(names))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        })
        .await
    }

    async fn sync_dir(&self, dir: &str) -> Result<(), Error> {
        let path = self.dir_path(dir);
        blocking(move || sync_dir_at(&path)).await
    }

    async fn sync_root(&self) -> Result<(), Error> {
        let root = self.root.clone();
        blocking(move || sync_dir_at(&root)).await
    }

    async fn free_bytes(&self) -> Result<Option<u64>, Error> {
        let lock = self.lock.clone();
        blocking(move || {
            let fd = std::os::fd::AsRawFd::as_raw_fd(&*lock);
            let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
            loop {
                // SAFETY: `lock` owns a valid fd that outlives the call;
                // `fstatvfs` writes only into `stats` and returns -1 on error.
                if unsafe { libc::fstatvfs(fd, stats.as_mut_ptr()) } == 0 {
                    break;
                }
                match io::Error::last_os_error() {
                    error if error.raw_os_error() == Some(libc::EINTR) => continue,
                    // The platform cannot report free space: honestly unknown
                    // (callers treat None as unbounded). Any other failure is a
                    // real error; swallowing it would let the maintenance
                    // reserve gate admit writes it should refuse.
                    error if error.raw_os_error() == Some(libc::ENOSYS) => return Ok(None),
                    error => return Err(error),
                }
            }
            // SAFETY: `fstatvfs` returned 0, so `stats` is initialized.
            let stats = unsafe { stats.assume_init() };
            // Bytes available to unprivileged writes. The field widths vary by
            // platform (u32 on macOS, u64 on Linux), so one of these casts is
            // an identity depending on the target; saturate the product since
            // an overstated unbounded value changes nothing.
            #[allow(clippy::unnecessary_cast)]
            let free = (stats.f_bavail as u64).saturating_mul(stats.f_frsize as u64);
            Ok(Some(free))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::sys_rng;
    use rand_core::Rng as _;

    #[test]
    fn test_free_bytes_reports_plausible_capacity() {
        let root =
            std::env::temp_dir().join(format!("commonware_logstore_fs_{}", sys_rng().next_u64()));
        let runtime = ::tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let free = runtime.block_on(async {
            let fs = Fs::new(root.clone()).unwrap();
            fs.free_bytes().await.unwrap()
        });
        // A freshly created temp directory must report some free space, and
        // the magnitude must be sane (under 1 EiB).
        let free = free.expect("statvfs is available on every supported Unix");
        assert!(free > 0);
        assert!(free < 1 << 60);
        fs::remove_dir_all(&root).unwrap();
    }

    /// The tokio runtime's `Context` exposes this backend as its
    /// [crate::LogStorage]: exercise one commit through it.
    #[test]
    fn test_context_log_storage_round_trip() {
        use crate::{Log as _, LogFamily as _, LogStorage as _, LogTransaction as _, Runner as _};

        let runner = crate::tokio::Runner::default();
        runner.start(|context| async move {
            let family = context.open_family("pilot").await.unwrap();
            let mut txn = family.transaction().await.unwrap();
            let draft = txn.create(b"log").unwrap();
            txn.append_draft(&draft, b"hello".to_vec()).unwrap();
            txn.commit().await.unwrap();

            let log = family.open(b"log").await.unwrap().unwrap();
            assert_eq!(log.len().unwrap(), 5);
            let read = log.read_at(0, 5).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"hello");

            assert_eq!(context.scan_families().await.unwrap(), vec!["pilot"]);
            context.destroy_family("pilot").await.unwrap();
        });
    }
}
