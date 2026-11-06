//! A ring futex wait queued before the process creates its first thread
//! still receives wakes once that thread exists.
//!
//! On Linux 6.16 and later without the fix for the private futex hash defect,
//! a private futex wait that io_uring queues while the process has one thread
//! lands in the global futex hash, and the first thread created afterwards
//! moves every later wake to a private hash, stranding that wait. The io_uring
//! runner creates a thread at startup to install the private hash first. A
//! libtest harness runs each test on a thread it created, so this test is its
//! own harness and runs its scenario on the process's only thread.

/// The one test, whose name contains "iouring" so that test runners skip it
/// where io_uring is unavailable.
const TEST: &str = "iouring_ring_wait_hears_wakes_after_the_first_thread";

/// Command-line options of the libtest protocol that nextest uses.
#[derive(Default)]
struct Options {
    /// List tests instead of running them.
    list: bool,
    /// Select only ignored tests, of which there are none.
    ignored: bool,
    /// Match filters against whole names rather than substrings.
    exact: bool,
    /// Names or substrings to select.
    filters: Vec<String>,
    /// Names or substrings to skip.
    skips: Vec<String>,
}

impl Options {
    /// Parse the options, ignoring flags that do not change the selection.
    fn parse() -> Self {
        let mut options = Self::default();
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--list" => options.list = true,
                "--ignored" => options.ignored = true,
                "--exact" => options.exact = true,
                "--skip" => options.skips.extend(args.next()),

                // These flags take a value that does not change the selection.
                "--format" | "--color" | "--test-threads" | "--logfile" | "--shuffle-seed"
                | "-Z" => {
                    args.next();
                }
                flag if flag.starts_with('-') => {}
                _ => options.filters.push(arg),
            }
        }
        options
    }

    /// Whether `pattern` matches the test's name.
    fn matches(&self, pattern: &str) -> bool {
        if self.exact {
            pattern == TEST
        } else {
            TEST.contains(pattern)
        }
    }

    /// Whether the options select the test on this platform.
    fn selected(&self) -> bool {
        cfg!(target_os = "linux")
            && !self.ignored
            && (self.filters.is_empty() || self.filters.iter().any(|filter| self.matches(filter)))
            && !self.skips.iter().any(|skip| self.matches(skip))
    }
}

fn main() {
    let options = Options::parse();
    if options.list {
        if options.selected() {
            println!("{TEST}: test");
        }
        return;
    }

    if options.selected() {
        #[cfg(target_os = "linux")]
        linux::ring_wait_hears_wakes_after_the_first_thread();
        println!("test {TEST} ... ok");
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use commonware_runtime::{
        Clock as _, Listener as _, Network as _, Runner as _, Spawner as _, Stream as _,
        Supervisor as _, iouring,
    };
    use std::{
        fs,
        net::SocketAddr,
        time::{Duration, Instant},
    };

    /// How long the scenario lets worker zero wait in its ring before the
    /// first thread exists.
    const RING_PARK: Duration = Duration::from_millis(50);
    /// How long the first thread runs before it wakes worker zero, so worker
    /// zero is waiting in its ring by then.
    const THREAD_RUN: Duration = Duration::from_millis(200);
    /// Longest acceptable delay between that wake and the root resuming, far
    /// below the process metrics period that otherwise ends the ring wait.
    const RESUME: Duration = Duration::from_secs(2);

    /// The number of threads in this process.
    fn threads() -> usize {
        let status = fs::read_to_string("/proc/self/status").unwrap();
        status
            .lines()
            .find_map(|line| line.strip_prefix("Threads:"))
            .and_then(|count| count.trim().parse().ok())
            .expect("procfs reports the thread count")
    }

    /// Worker zero waits in its ring before the process creates its first
    /// thread, then a wake from that thread must end a later ring wait.
    pub fn ring_wait_hears_wakes_after_the_first_thread() {
        // Run one worker on the process's only thread.
        assert_eq!(threads(), 1, "the scenario must start single threaded");
        let runner = iouring::Runner::new(iouring::Config::default().with_worker_threads(1));
        runner.start(|context| async move {
            // Keep a receive in flight, so worker zero parks in its ring with a
            // ring futex wait installed, and let one park end at a deadline,
            // which leaves the wait queued for later parks.
            let listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let (_sink, mut stream) = context.dial(listener.local_addr().unwrap()).await.unwrap();
            let _receive = context
                .child("receive")
                .spawn(move |_| async move { stream.recv(1).await });
            context.sleep(RING_PARK).await;
            assert_eq!(
                threads(),
                1,
                "a thread exists before the scenario creates one"
            );

            // Create the first thread since startup and let it wake the root
            // while worker zero waits in its ring.
            let woken = context
                .child("first_thread")
                .dedicated()
                .spawn(|_| async move {
                    std::thread::sleep(THREAD_RUN);
                    Instant::now()
                })
                .await
                .unwrap();

            // The wake ended worker zero's ring wait, not the next deadline.
            let delay = woken.elapsed();
            assert!(
                delay < RESUME,
                "worker zero resumed {delay:?} after the wake"
            );
        });
    }
}
