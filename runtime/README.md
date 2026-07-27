# commonware-runtime

[![Crates.io](https://img.shields.io/crates/v/commonware-runtime.svg)](https://crates.io/crates/commonware-runtime)
[![Docs.rs](https://docs.rs/commonware-runtime/badge.svg)](https://docs.rs/commonware-runtime)

Execute asynchronous tasks with a configurable scheduler.

Three schedulers are provided: `deterministic` (reproducible execution for tests and simulation), `tokio` (production), and `iouring` (production, Linux 6.1+ behind the `iouring` feature). See the crate documentation for details.

## Status 

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.