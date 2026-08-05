//! Bake-off benches for the oversized journal: the per-file backend
//! (`backend=file`) against the log-storage adapter (`backend=segment`).
//! The adapter needs the tokio runtime's Unix-only [commonware_runtime::LogStorage].

#[cfg(unix)]
mod commit;
#[cfg(unix)]
mod utils;

#[cfg(unix)]
mod churn;
#[cfg(unix)]
mod replay;

#[cfg(unix)]
criterion::criterion_main!(commit::benches, churn::benches, replay::benches);

#[cfg(not(unix))]
fn main() {}
