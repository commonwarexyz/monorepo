//! The real-filesystem [Medium]: one directory level under a root, positional I/O
//! through the blocking pool, fdatasync barriers, and directory fsyncs.

use super::medium::{File, Medium};
use crate::{Error, IoBufs};
use std::{fs, io, os::unix::fs::FileExt as _, path::PathBuf, sync::Arc};
use tokio::task;

/// A [Medium] over a real filesystem rooted at one directory.
#[derive(Clone)]
pub struct Fs {
    root: Arc<PathBuf>,
}

impl Fs {
    /// Uses `root` (created if absent) as the storage directory.
    pub fn new(root: PathBuf) -> Result<Self, Error> {
        fs::create_dir_all(&root).map_err(map_io)?;
        Ok(Self {
            root: Arc::new(root),
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
                Error::BlobInsufficientLength
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
}
