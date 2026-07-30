//! Unit-test entry point for shared timer benchmark helpers.

// This target imports complete benchmark modules for helper and orchestration
// tests, so the unselected benchmark entry points are intentionally unused.
#![allow(dead_code)]

mod accuracy;
mod backend;
pub(crate) use backend::{BenchSleep, poll_once, sleep_for, sleep_until, sleep_until_wall};
mod config;
pub(crate) use config::{Backend, Config, checked_observations};
mod peer_gap;
mod producer_gate;
mod report;
mod worst_case;
