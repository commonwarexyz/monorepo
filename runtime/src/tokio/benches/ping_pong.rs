use commonware_runtime::{
    tokio::{Config, Context, Runner},
    Handle, Runner as _, Spawner as _,
};
use commonware_utils::channel::mpsc;
use criterion::{Criterion, Throughput};
use std::{
    future::Future,
    mem::size_of,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Barrier;

const BATCHES: &[u64] = &[1, 10, 100];
const MSG_SIZES: &[usize] = &[1, 4, 8, 16, 32];
const CHANNEL_SIZE: usize = 128;

/// How to spawn a task.
#[derive(Clone, Copy)]
enum SpawnMode {
    Shared,
    Dedicated,
    Pinned(usize),
    Colocated,
}

impl SpawnMode {
    fn spawn<F, Fut, T>(self, ctx: Context, f: F) -> Handle<T>
    where
        F: FnOnce(Context) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        match self {
            Self::Shared => ctx.spawn(f),
            Self::Dedicated => ctx.dedicated().spawn(f),
            Self::Pinned(c) => ctx.pinned(c).spawn(f),
            Self::Colocated => ctx.colocated().spawn(f),
        }
    }
}

/// Send a batch of messages, then receive a batch. Repeat for `iters`.
/// Waits on the barrier before starting.
async fn ping_pong<const N: usize>(
    tx: mpsc::Sender<[u64; N]>,
    mut rx: mpsc::Receiver<[u64; N]>,
    barrier: Arc<Barrier>,
    batch: u64,
    iters: u64,
) {
    barrier.wait().await;
    let msg = [0u64; N];
    for _ in 0..iters {
        for _ in 0..batch {
            tx.send(msg).await.unwrap();
        }
        for _ in 0..batch {
            rx.recv().await.unwrap();
        }
    }
}

/// Spawn two ping-pong tasks, wait for both to be ready via a 3-party barrier,
/// then measure the time for all iterations to complete.
async fn run_ping_pong<const N: usize>(
    ctx: Context,
    batch: u64,
    iters: u64,
    spawn_a: SpawnMode,
    spawn_b: SpawnMode,
) -> Duration {
    let (tx_a, rx_a) = mpsc::channel(CHANNEL_SIZE);
    let (tx_b, rx_b) = mpsc::channel(CHANNEL_SIZE);
    let barrier = Arc::new(Barrier::new(3));

    let task_a = spawn_a.spawn(ctx.clone(), {
        let barrier = barrier.clone();
        move |_| ping_pong::<N>(tx_a, rx_b, barrier, batch, iters)
    });
    let task_b = spawn_b.spawn(ctx.clone(), {
        let barrier = barrier.clone();
        move |_| ping_pong::<N>(tx_b, rx_a, barrier, batch, iters)
    });

    barrier.wait().await;
    let start = Instant::now();
    task_a.await.unwrap();
    task_b.await.unwrap();
    start.elapsed()
}

fn bench_ping_pong<const N: usize>(
    cfg: Config,
    batch: u64,
    iters: u64,
    spawn_a: SpawnMode,
    spawn_b: SpawnMode,
    parent: Option<SpawnMode>,
) -> Duration {
    let executor = Runner::new(cfg);
    executor.start(|ctx| async move {
        match parent {
            None => run_ping_pong::<N>(ctx, batch, iters, spawn_a, spawn_b).await,
            Some(parent) => parent
                .spawn(ctx, move |ctx| async move {
                    run_ping_pong::<N>(ctx, batch, iters, spawn_a, spawn_b).await
                })
                .await
                .unwrap(),
        }
    })
}

/// Dispatch to the right const-generic instantiation.
macro_rules! dispatch {
    ($n:expr, $f:ident $(, $arg:expr)*) => {
        match $n {
            1 => $f::<1>($($arg),*),
            4 => $f::<4>($($arg),*),
            8 => $f::<8>($($arg),*),
            16 => $f::<16>($($arg),*),
            32 => $f::<32>($($arg),*),
            _ => panic!("unsupported message size: {}", $n),
        }
    };
}

pub fn bench(c: &mut Criterion) {
    use SpawnMode::*;
    let num_cores = commonware_runtime::available_cores();
    let cfg = match num_cores {
        Some(n) => Config::new().with_worker_threads(n),
        None => Config::new(),
    };

    let cores_same_die = cores_on_same_die();
    let cores_diff_die = corres_on_different_die();
    println!();
    println!("available_cores: {num_cores:?}, cores_same_die: {cores_same_die:?}, cores_diff_die: {cores_diff_die:?}");
    println!();

    for &batch in BATCHES {
        for &msg_size in MSG_SIZES {
            let total_messages = batch * 2;
            let mut group = c.benchmark_group("ping_pong");
            group.throughput(Throughput::Elements(total_messages));

            let id = |label: &str| {
                format!(
                    "{}/mode={label} batch={batch} msg_bytes={}",
                    module_path!(),
                    msg_size * size_of::<u64>(),
                )
            };

            group.bench_function(id("shared"), |b| {
                b.iter_custom(|iters| {
                    dispatch!(
                        msg_size,
                        bench_ping_pong,
                        cfg.clone(),
                        batch,
                        iters,
                        Shared,
                        Shared,
                        None
                    )
                });
            });

            group.bench_function(id("colocated"), |b| {
                b.iter_custom(|iters| {
                    dispatch!(
                        msg_size,
                        bench_ping_pong,
                        cfg.clone(),
                        batch,
                        iters,
                        Colocated,
                        Colocated,
                        Some(Dedicated)
                    )
                });
            });

            group.bench_function(id("dedicated"), |b| {
                b.iter_custom(|iters| {
                    dispatch!(
                        msg_size,
                        bench_ping_pong,
                        cfg.clone(),
                        batch,
                        iters,
                        Dedicated,
                        Dedicated,
                        None
                    )
                });
            });

            // The benchmarks below require support for core pinning which only
            // works on Linux
            if !cfg!(target_os = "linux") {
                group.finish();
                continue;
            };

            group.bench_function(id("dedicated_same_core"), |b| {
                b.iter_custom(|iters| {
                    dispatch!(
                        msg_size,
                        bench_ping_pong,
                        cfg.clone(),
                        batch,
                        iters,
                        Pinned(0),
                        Pinned(0),
                        None
                    )
                });
            });

            if let Some((core_a, core_b)) = cores_same_die {
                group.bench_function(id("dedicated_different_core"), |b| {
                    b.iter_custom(|iters| {
                        dispatch!(
                            msg_size,
                            bench_ping_pong,
                            cfg.clone(),
                            batch,
                            iters,
                            Pinned(core_a),
                            Pinned(core_b),
                            None
                        )
                    });
                });
            }

            if let Some((core_a, core_b)) = cores_diff_die {
                group.bench_function(id("dedicated_different_die"), |b| {
                    b.iter_custom(|iters| {
                        dispatch!(
                            msg_size,
                            bench_ping_pong,
                            cfg.clone(),
                            batch,
                            iters,
                            Pinned(core_a),
                            Pinned(core_b),
                            None
                        )
                    });
                });
            }

            group.bench_function(id("colocated_pinned"), |b| {
                b.iter_custom(|iters| {
                    dispatch!(
                        msg_size,
                        bench_ping_pong,
                        cfg.clone(),
                        batch,
                        iters,
                        Colocated,
                        Colocated,
                        Some(Pinned(0))
                    )
                });
            });

            group.finish();
        }
    }
}

/// Read the die_id for each core and group them by die.
#[cfg(target_os = "linux")]
fn die_topology() -> Option<std::collections::BTreeMap<String, Vec<usize>>> {
    use std::{collections::BTreeMap, fs};

    let num_cores = commonware_runtime::available_cores()?;
    let mut dies: BTreeMap<String, Vec<usize>> = BTreeMap::new();

    for cpu in 0..num_cores {
        let path = format!("/sys/devices/system/cpu/cpu{cpu}/topology/die_id");
        let die_id = fs::read_to_string(path).ok()?.trim().to_string();
        dies.entry(die_id).or_default().push(cpu);
    }

    Some(dies)
}

/// Returns two different core IDs on the same die, or `None` if every die
/// has only one core or topology cannot be determined.
#[cfg(target_os = "linux")]
fn cores_on_same_die() -> Option<(usize, usize)> {
    die_topology()?
        .values()
        .find(|cores| cores.len() >= 2)
        .map(|cores| (cores[0], cores[1]))
}

/// Returns two core IDs on different dies, or `None` if the system has only
/// one die or topology cannot be determined.
#[cfg(target_os = "linux")]
fn corres_on_different_die() -> Option<(usize, usize)> {
    let dies = die_topology()?;
    let mut iter = dies.values();
    let a = iter.next()?;
    let b = iter.next()?;
    Some((a[0], b[0]))
}

#[cfg(not(target_os = "linux"))]
fn cores_on_same_die() -> Option<(usize, usize)> {
    None
}

#[cfg(not(target_os = "linux"))]
fn cores_on_different_dies() -> Option<(usize, usize)> {
    None
}
