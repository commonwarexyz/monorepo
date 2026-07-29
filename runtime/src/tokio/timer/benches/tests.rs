//! Unit-test entry point for shared timer benchmark helpers.

// This target imports complete benchmark modules while exercising only their
// pure helpers, so the remaining reporting functions are intentionally unused.
#![allow(dead_code)]

mod config;
pub(crate) use config::Config;
mod report;
