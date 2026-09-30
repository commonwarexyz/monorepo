//! Helpers of the tests of the crate path (`driver::build_crate`, DESIGN.md
//! §15.8): `sandblaster spec --accept` on an in-memory crate — the crate path
//! with `LockUse::Accepting`, whose permit `lock::accept` requires — so a
//! test crate carries the lock its own gates accepted (never a checked-in
//! lock, which every toolchain change would make stale). Included with
//! `#[path = "gated_util.rs"] mod gated;`; built alone it is an empty test
//! crate.
#![allow(dead_code)]

use std::path::Path;

use sandblaster_front::driver::{self, LockUse};
use sandblaster_front::loader::MemFs;
use sandblaster_front::lock::{self, Selection};
use sandblaster_front::target::TargetInfo;

/// The lock `sandblaster spec --accept` writes for the in-memory crate
/// `files` rooted at `root`, or the rendered failure when a gate other than
/// the lock fails.
pub fn accept_lock(files: &[(String, String)], root: &str, target: &TargetInfo) -> Result<String, String> {
    let fs = MemFs::from_files(files.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let c = driver::check(Path::new(root), &fs, target);
    if !c.ok() {
        return Err(c.render());
    }
    let b = driver::build_crate(&c, LockUse::Accepting, root);
    let (Some(permit), Some(surface)) = (&b.permit, &b.surface) else { return Err(b.render_failure(&c, root)) };
    let old = c.spec_lock.as_deref().and_then(|t| lock::Lock::parse(t).ok());
    let (l, _) = lock::accept(permit, old.as_ref(), surface, &Selection::All)?;
    Ok(l.render())
}

/// `files` with the accepted lock added at the root's lock path
/// (`lock::lock_path`).
pub fn with_accepted_lock(files: &[(String, String)], root: &str, target: &TargetInfo) -> Result<Vec<(String, String)>, String> {
    let text = accept_lock(files, root, target)?;
    let path = lock::lock_path(Path::new(root)).display().to_string();
    let mut out: Vec<(String, String)> = files.iter().filter(|(p, _)| *p != path).cloned().collect();
    out.push((path, text));
    Ok(out)
}
