//! The stand-in for `commonware_consensus::simplex`: the runtime template as its
//! `statelens` module. This directory exists so the `..` components of the path
//! resolve on disk.

#[path = "../../../../runtime/statelens.rs"]
pub mod statelens;
