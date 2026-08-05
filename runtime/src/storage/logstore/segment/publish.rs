//! The reachability rule's publication protocol, written once.
//!
//! A file may become reachable from a durable root or an acknowledged
//! transaction ONLY after both its contents and its directory entry are
//! durable, and a data barrier does not make a dentry durable. So every new
//! family file -- checkpoint segments, rotation's next active segment,
//! dedicated large-transaction segments, cleaning's copy segments -- goes
//! through [publish]: create under the staging name, write contents,
//! fdatasync, rename to the final name, fsync the directory. Only then may a
//! root or an acknowledgment reference it. Roots themselves flip through
//! [flip_root]: one manifest barrier per publication, never touching the
//! predecessor slot.

use super::{
    format::{Incarnation, ROOT_OFFSETS, Root},
    medium::{Claim, File as _, Medium},
};
use crate::Error;

/// Publishes `bytes` as `dir/name`: staged under `staging`, synced, renamed,
/// and its dentry made durable, in that order. Returns the open file. The
/// caller owns failure policy (a failed publication usually poisons the
/// family).
pub(super) async fn publish<M: Medium>(
    medium: &M,
    dir: &str,
    staging: &str,
    name: &str,
    bytes: Vec<u8>,
) -> Result<M::File, Error> {
    let len = bytes.len() as u64;
    let file = medium.create(dir, staging).await?;
    file.write_at(0, bytes).await?;
    file.sync().await?;
    medium.rename(dir, staging, name).await?;
    medium.sync_dir(dir).await?;
    debug_assert!(medium.covered(&Claim::Dentry { dir, name }));
    debug_assert!(medium.covered(&Claim::FileBytes {
        dir,
        name,
        start: 0,
        end: len,
    }));
    Ok(file)
}

/// Publishes `root` into its parity slot with one manifest barrier. Callers
/// have already made everything the root references durable (the
/// reachability rule).
pub(super) async fn flip_root<F: super::medium::File>(
    manifest: &F,
    incarnation: &Incarnation,
    root: &Root,
) -> Result<(), Error> {
    manifest
        .write_at(
            ROOT_OFFSETS[(root.seq & 1) as usize],
            root.encode(incarnation),
        )
        .await?;
    manifest.sync().await
}
