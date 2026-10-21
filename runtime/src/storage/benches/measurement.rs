//! CPU, scheduler, and device counters for one benchmark phase.
//!
//! Raw process and system counters include measurement overhead. The process CPU
//! total net of the sampler subtracts its final schedstat runtime, read just before
//! thread exit. The small exit tail and other measurement work remain included.
//! A separate idle phase can supply a baseline. Thread counts include the sampler
//! while it is alive. Departed iou-wrk threads retain their last sampled counters,
//! so their deltas are lower bounds. Other departed workload threads have null
//! counters. Polling uses 20 ms per 128 currently visible threads, rounded up
//! and capped at 200 ms, to limit directory scanning overhead in large processes.
//! Threads shorter than the polling interval can be missed, so thread peaks are
//! lower bounds. The largest requested interval is reported as sampler_interval_ns.
//! TID reuse within a phase can misattribute names and scheduler deltas.
//! Unavailable counters are reported as null.

use serde_json::{Value, json};
#[cfg(target_os = "linux")]
use std::fs;
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Default)]
struct Scheduler {
    runtime_ns: u64,
    wait_ns: u64,
    timeslices: u64,
}

impl Scheduler {
    const fn delta(self, before: Self) -> Self {
        Self {
            runtime_ns: self.runtime_ns.saturating_sub(before.runtime_ns),
            wait_ns: self.wait_ns.saturating_sub(before.wait_ns),
            timeslices: self.timeslices.saturating_sub(before.timeslices),
        }
    }
}

#[derive(Clone)]
struct Task {
    comm: Option<String>,
    scheduler: Option<Scheduler>,
}

type Tasks = BTreeMap<u32, Task>;

#[derive(Clone, Copy)]
struct ProcessUsage {
    user_ns: u64,
    system_ns: u64,
    minor_faults: u64,
    major_faults: u64,
}

impl ProcessUsage {
    const fn delta(self, before: Self) -> Self {
        Self {
            user_ns: self.user_ns.saturating_sub(before.user_ns),
            system_ns: self.system_ns.saturating_sub(before.system_ns),
            minor_faults: self.minor_faults.saturating_sub(before.minor_faults),
            major_faults: self.major_faults.saturating_sub(before.major_faults),
        }
    }
}

struct Snapshot {
    process: Option<ProcessUsage>,
    system_busy_ns: Option<u64>,
    device_bytes: Option<(u64, u64)>,
    tasks: Option<Tasks>,
}

impl Snapshot {
    fn read(device: Option<&str>, known: Option<&Tasks>) -> Self {
        Self {
            process: process_usage(),
            system_busy_ns: system_busy_ns(),
            device_bytes: device.and_then(device_bytes),
            tasks: tasks(known),
        }
    }
}

/// Counters and a worker sampler scoped to one timed phase.
pub struct Measurement {
    started: Instant,
    before: Snapshot,
    device: Option<String>,
    sampler: Option<Sampler>,
}

impl Measurement {
    /// Begin a phase, optionally tracking an exact kernel diskstats device name.
    pub fn start(device: Option<&str>) -> Self {
        let started = Instant::now();
        let before = Snapshot::read(device, None);
        let sampler = before.tasks.as_ref().and_then(Sampler::start);
        Self {
            started,
            before,
            device: device.map(str::to_owned),
            sampler,
        }
    }

    /// Stop sampling and return phase deltas as a JSON object.
    pub fn finish(mut self) -> Value {
        let sampled = self.sampler.take().and_then(|mut sampler| sampler.stop());
        let known = sampled
            .as_ref()
            .map(|sampled| &sampled.tasks)
            .or(self.before.tasks.as_ref());
        let after = Snapshot::read(self.device.as_deref(), known);
        let elapsed_ns = self.started.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        let process = self
            .before
            .process
            .zip(after.process)
            .map(|(before, after)| after.delta(before));
        let device = pair_delta(self.before.device_bytes, after.device_bytes);
        let busy = self
            .before
            .system_busy_ns
            .zip(after.system_busy_ns)
            .map(|(before, after)| after.saturating_sub(before));
        let process_cpu_ns = process.and_then(|value| value.user_ns.checked_add(value.system_ns));
        let sampler_runtime_ns = sampled.as_ref().and_then(|sampled| sampled.runtime_ns);
        let sampler_interval_ns = sampled.as_ref().map(|sampled| sampled.interval_max_ns);
        let process_cpu_net_sampler_ns = process_cpu_ns
            .zip(sampler_runtime_ns)
            .map(|(process, sampler)| process.saturating_sub(sampler));

        let mut observed = self.before.tasks.clone();
        let mut peak = worker_count(self.before.tasks.as_ref());
        let thread_count = after.tasks.as_ref().map(|tasks| tasks.len() as u64);
        let mut thread_count_peak = self.before.tasks.as_ref().map(|tasks| tasks.len() as u64);
        if let Some(sampled) = sampled {
            thread_count_peak = maximum(thread_count_peak, sampled.thread_count_peak);
            merge_tasks(&mut observed, Some(sampled.tasks));
            peak = maximum(peak, sampled.peak);
        }
        thread_count_peak = maximum(thread_count_peak, thread_count);
        peak = maximum(peak, worker_count(after.tasks.as_ref()));
        merge_tasks(&mut observed, after.tasks.clone());
        let threads = observed.map(|tasks| {
            tasks
                .into_iter()
                .map(|(tid, task)| {
                    let present = after.tasks.as_ref().map(|tasks| tasks.contains_key(&tid));
                    let retained = task.comm.as_deref().is_some_and(|comm| {
                        comm.starts_with("iou-wrk") || comm == "storage-measure"
                    });
                    let scheduler = match after.tasks.as_ref().and_then(|tasks| tasks.get(&tid)) {
                        Some(task) => task.scheduler,
                        None if retained => task.scheduler,
                        None => None,
                    };
                    let delta = scheduler_delta(self.before.tasks.as_ref(), tid, scheduler);
                    json!({
                        "tid": tid,
                        "comm": task.comm,
                        "runtime_ns": delta.map(|value| value.runtime_ns),
                        "wait_ns": delta.map(|value| value.wait_ns),
                        "timeslices": delta.map(|value| value.timeslices),
                        "present_at_finish": present,
                    })
                })
                .collect::<Vec<_>>()
        });

        json!({
            "elapsed_ns": elapsed_ns,
            "process_user_ns": process.map(|value| value.user_ns),
            "process_system_ns": process.map(|value| value.system_ns),
            "process_cpu_ns": process_cpu_ns,
            "sampler_runtime_ns": sampler_runtime_ns,
            "sampler_interval_ns": sampler_interval_ns,
            "process_cpu_net_sampler_ns": process_cpu_net_sampler_ns,
            "process_minor_faults": process.map(|value| value.minor_faults),
            "process_major_faults": process.map(|value| value.major_faults),
            "system_busy_ns": busy,
            "threads": threads,
            "thread_count": thread_count,
            "thread_count_peak": thread_count_peak,
            "iou_wrk_peak": peak,
            "device_read_bytes": device.map(|value| value.0),
            "device_write_bytes": device.map(|value| value.1),
        })
    }
}

fn pair_delta(before: Option<(u64, u64)>, after: Option<(u64, u64)>) -> Option<(u64, u64)> {
    before.zip(after).map(|(before, after)| {
        (
            after.0.saturating_sub(before.0),
            after.1.saturating_sub(before.1),
        )
    })
}

fn scheduler_delta(
    before: Option<&Tasks>,
    tid: u32,
    after: Option<Scheduler>,
) -> Option<Scheduler> {
    let before = match before?.get(&tid) {
        Some(task) => task.scheduler?,
        None => Scheduler::default(),
    };
    Some(after?.delta(before))
}

fn merge_tasks(observed: &mut Option<Tasks>, next: Option<Tasks>) {
    let Some(next) = next else {
        return;
    };
    let observed = observed.get_or_insert_with(Tasks::new);
    for (tid, task) in next {
        observed
            .entry(tid)
            .and_modify(|previous| {
                if task.comm.is_some() {
                    previous.comm.clone_from(&task.comm);
                }
                if task.scheduler.is_some() {
                    previous.scheduler = task.scheduler;
                }
            })
            .or_insert(task);
    }
}

fn maximum(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (left, right) => left.or(right),
    }
}

fn worker_count(tasks: Option<&Tasks>) -> Option<u64> {
    tasks?.values().try_fold(0, |count, task| {
        Some(count + u64::from(task.comm.as_ref()?.starts_with("iou-wrk")))
    })
}

struct Samples {
    tasks: Tasks,
    peak: Option<u64>,
    thread_count_peak: Option<u64>,
    runtime_ns: Option<u64>,
    interval_max_ns: u64,
}

struct Sampler {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<Samples>>,
}

impl Sampler {
    fn start(before: &Tasks) -> Option<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let signal = stop.clone();
        let mut observed = before.clone();
        let handle = thread::Builder::new()
            .name("storage-measure".to_owned())
            .spawn(move || {
                let mut peak = None;
                let mut thread_count_peak = None;
                let mut interval_ns = 20_000_000;
                let mut interval_max_ns = 0;
                loop {
                    if let Some((threads, workers)) = sample_tasks(&mut observed) {
                        thread_count_peak = maximum(thread_count_peak, Some(threads));
                        peak = maximum(peak, workers);
                        interval_ns = 20_000_000 * threads.div_ceil(128).clamp(1, 10);
                    }
                    if signal.load(Ordering::Acquire) {
                        break;
                    }
                    interval_max_ns = interval_max_ns.max(interval_ns);
                    thread::park_timeout(Duration::from_nanos(interval_ns));
                }
                let own = sampler_scheduler();
                if let Some((tid, scheduler)) = own {
                    observed.insert(
                        tid,
                        Task {
                            comm: Some("storage-measure".to_owned()),
                            scheduler: Some(scheduler),
                        },
                    );
                }
                Samples {
                    tasks: observed,
                    peak,
                    thread_count_peak,
                    runtime_ns: own.map(|(_, scheduler)| scheduler.runtime_ns),
                    interval_max_ns,
                }
            })
            .ok()?;
        Some(Self {
            stop,
            handle: Some(handle),
        })
    }

    fn stop(&mut self) -> Option<Samples> {
        let handle = self.handle.take()?;
        self.stop.store(true, Ordering::Release);
        handle.thread().unpark();
        handle.join().ok()
    }
}

impl Drop for Sampler {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(unix)]
fn process_usage() -> Option<ProcessUsage> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: usage points to writable, properly aligned storage for one rusage.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: A successful getrusage initialized the rusage structure.
    let usage = unsafe { usage.assume_init() };
    Some(ProcessUsage {
        user_ns: timeval_ns(usage.ru_utime)?,
        system_ns: timeval_ns(usage.ru_stime)?,
        minor_faults: u64::try_from(usage.ru_minflt).ok()?,
        major_faults: u64::try_from(usage.ru_majflt).ok()?,
    })
}

#[cfg(unix)]
fn timeval_ns(time: libc::timeval) -> Option<u64> {
    u64::try_from(time.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(time.tv_usec).ok()?.checked_mul(1_000)?)
}

#[cfg(not(unix))]
fn process_usage() -> Option<ProcessUsage> {
    None
}

cfg_if::cfg_if! {
    if #[cfg(target_os = "linux")] {
        fn system_busy_ns() -> Option<u64> {
            // SAFETY: sysconf takes a constant selector and does not access pointers.
            let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
            let ticks_per_second = u64::try_from(ticks_per_second).ok().filter(|value| *value != 0)?;
            let stat = fs::read_to_string("/proc/stat").ok()?;
            let ticks = busy_ticks(&stat)?;
            u64::try_from(u128::from(ticks) * 1_000_000_000 / u128::from(ticks_per_second)).ok()
        }

        fn busy_ticks(stat: &str) -> Option<u64> {
            let mut fields = stat.lines().find(|line| line.starts_with("cpu "))?.split_whitespace();
            fields.next()?;
            let fields = fields.take(7).map(str::parse::<u64>).collect::<Result<Vec<_>, _>>().ok()?;
            if fields.len() < 4 {
                return None;
            }
            // guest and guest_nice are already included in user and nice.
            // Idle, iowait, and steal do not represent consumed CPU time.
            fields.into_iter().enumerate().filter(|(index, _)| *index != 3 && *index != 4)
                .try_fold(0u64, |total, (_, ticks)| total.checked_add(ticks))
        }

        fn device_bytes(device: &str) -> Option<(u64, u64)> {
            disk_bytes(&fs::read_to_string("/proc/diskstats").ok()?, device)
        }

        fn disk_bytes(stats: &str, device: &str) -> Option<(u64, u64)> {
            for line in stats.lines() {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                if fields.get(2).copied() != Some(device) {
                    continue;
                }
                let read = fields.get(5)?.parse::<u64>().ok()?.checked_mul(512)?;
                let written = fields.get(9)?.parse::<u64>().ok()?.checked_mul(512)?;
                return Some((read, written));
            }
            None
        }

        fn tasks(known: Option<&Tasks>) -> Option<Tasks> {
            let mut tasks = Tasks::new();
            for entry in fs::read_dir("/proc/self/task").ok()? {
                let entry = entry.ok()?;
                let Ok(tid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                    continue;
                };
                let path = entry.path();
                let comm = known.and_then(|tasks| tasks.get(&tid)).map_or_else(
                    || fs::read_to_string(path.join("comm")).ok().map(|comm| comm.trim_end().to_owned()),
                    |task| task.comm.clone(),
                );
                let scheduler = fs::read_to_string(path.join("schedstat")).ok()
                    .and_then(|stat| scheduler(&stat));
                tasks.insert(tid, Task { comm, scheduler });
            }
            Some(tasks)
        }

        fn sample_tasks(observed: &mut Tasks) -> Option<(u64, Option<u64>)> {
            let mut threads = 0;
            let mut workers = Some(0);
            for entry in fs::read_dir("/proc/self/task").ok()? {
                let entry = entry.ok()?;
                let Ok(tid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                    continue;
                };
                threads += 1;
                let task = observed.entry(tid).or_insert_with(|| Task {
                    comm: fs::read_to_string(entry.path().join("comm")).ok()
                        .map(|comm| comm.trim_end().to_owned()),
                    scheduler: None,
                });
                let Some(comm) = &task.comm else {
                    workers = None;
                    continue;
                };
                if comm.starts_with("iou-wrk") {
                    workers = workers.map(|count| count + 1);
                    if let Some(scheduler) = fs::read_to_string(entry.path().join("schedstat")).ok()
                        .and_then(|stat| scheduler(&stat)) {
                        task.scheduler = Some(scheduler);
                    }
                }
            }
            // Count only this enumeration, not the retained departed workers.
            Some((threads, workers))
        }

        fn sampler_scheduler() -> Option<(u32, Scheduler)> {
            let path = fs::read_link("/proc/thread-self").ok()?;
            let tid = path.file_name()?.to_str()?.parse().ok()?;
            let stat = fs::read_to_string("/proc/thread-self/schedstat").ok()?;
            Some((tid, scheduler(&stat)?))
        }

        fn scheduler(stat: &str) -> Option<Scheduler> {
            let mut fields = stat.split_whitespace();
            Some(Scheduler {
                runtime_ns: fields.next()?.parse().ok()?,
                wait_ns: fields.next()?.parse().ok()?,
                timeslices: fields.next()?.parse().ok()?,
            })
        }
    } else {
        const fn system_busy_ns() -> Option<u64> {
            None
        }

        const fn device_bytes(_device: &str) -> Option<(u64, u64)> {
            None
        }

        const fn tasks(_known: Option<&Tasks>) -> Option<Tasks> {
            None
        }

        const fn sample_tasks(_observed: &mut Tasks) -> Option<(u64, Option<u64>)> {
            None
        }

        const fn sampler_scheduler() -> Option<(u32, Scheduler)> {
            None
        }
    }
}
