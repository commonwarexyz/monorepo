//! A [crate::Storage] backend where blobs stay ordinary files and one write-ahead log
//! per family owns the namespace and, for atomic blobs, the committed lengths.
//!
//! The WAL delivers multi-blob atomicity -- after a crash, either all of a logical
//! group's changes are visible or none are -- without moving payload into a shared
//! container: files remain self-describing, payload keeps kernel fd isolation, and
//! recovery replays one log instead of reconstructing a decision from many files.
//!
//! # The master rule (M)
//!
//! A byte of blob-file content, a directory entry, or a directory may become
//! load-bearing (some durable WAL record or snapshot asserts state depending on it)
//! only after a completed barrier on the file or directory holding it, issued and
//! completed before the asserting record was written. The [medium::Checked] wrapper
//! makes this machine-checkable in every test.
//!
//! Built bottom-up: [medium] is the I/O seam and crash model; [format] the on-disk
//! layout; [catalog] the namespace as a fold over records; [journal] creation,
//! recovery, and checkpoints. The committer and the `Storage` implementation land on
//! top of these.

mod catalog;
mod format;
mod journal;
pub mod medium;
