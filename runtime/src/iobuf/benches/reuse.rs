use commonware_runtime::{
    tokio, BufferPool, BufferPoolConfig, BufferPooler, IoBufMut, Runner as _,
};
use commonware_utils::NZUsize;
use criterion::Criterion;
use std::{
    alloc::{alloc, dealloc, handle_alloc_error, Layout},
    hint::spin_loop,
    ptr::NonNull,
    sync::{Arc, Barrier},
    thread,
    time::Instant,
};

const SIZES: &[usize] = &[256, 1024, 4096, 65536, 1024 * 1024, 8 * 1024 * 1024];

pub fn bench(c: &mut Criterion) {
    let threads = std::thread::available_parallelism().map_or(2, |n| n.get().clamp(2, 8));
    let page_size = page_size();

    for &size in SIZES {
        let pool = build_pool(size, threads);
        let alignment = pool.config().alignment.get();
        let single_pool = pool.clone();

        c.bench_function(&bench_name("bare", size, 1, alignment), |b| {
            b.iter(|| {
                run_bare(size, alignment, page_size);
            });
        });

        c.bench_function(&bench_name("pool", size, 1, alignment), |b| {
            b.iter(|| {
                run_pool(&single_pool, size, page_size);
            });
        });

        for pattern in ["tight_loop", "staggered"] {
            bench_multi_thread(c, "bare", pattern, size, threads, alignment, move || {
                run_bare(size, alignment, page_size)
            });

            bench_multi_thread(c, "pool", pattern, size, threads, alignment, {
                let pool = pool.clone();
                move || run_pool(&pool, size, page_size)
            });
        }
    }
}

fn bench_multi_thread<F, T>(
    c: &mut Criterion,
    allocator: &str,
    pattern: &str,
    size: usize,
    threads: usize,
    alignment: usize,
    op: F,
) where
    F: Fn() -> T + Send + Sync + 'static,
    T: 'static,
{
    let op = Arc::new(op);
    c.bench_function(
        &format!(
            "{}/allocator={} size={} threads={threads} alignment={} pattern={}",
            module_path!(),
            allocator,
            size,
            alignment,
            pattern,
        ),
        |b| {
            b.iter_custom(|iters| {
                let start = Instant::now();

                thread::scope(|scope| {
                    let barrier = Arc::new(Barrier::new(threads));
                    let iters = iters / threads as u64;

                    for thread_id in 0..threads {
                        let barrier = barrier.clone();
                        let op = op.clone();
                        scope.spawn(move || {
                            barrier.wait();
                            for iter in 0..iters {
                                let buffer = std::hint::black_box(op());
                                if pattern == "staggered" {
                                    let spins = (iter as usize)
                                        .wrapping_add(1)
                                        .wrapping_mul(thread_id.wrapping_mul(7).wrapping_add(1))
                                        & 0xF;
                                    for _ in 0..spins {
                                        spin_loop();
                                    }
                                }
                                drop(buffer);
                            }
                        });
                    }
                });
                start.elapsed()
            });
        },
    );
}

fn bench_name(allocator: &str, size: usize, threads: usize, alignment: usize) -> String {
    format!(
        "{}/allocator={} size={} threads={threads} alignment={}",
        module_path!(),
        allocator,
        size,
        alignment,
    )
}

fn run_bare(size: usize, alignment: usize, page_size: usize) -> AlignedBuffer {
    let buffer = AlignedBuffer::new(size, alignment);
    touch_pages(buffer.as_mut_ptr(), size, page_size);
    buffer
}

fn run_pool(pool: &BufferPool, size: usize, page_size: usize) -> IoBufMut {
    let mut buffer = pool
        .try_alloc(size)
        .expect("buffer pool exhausted during benchmark");
    touch_pages(buffer.as_mut_ptr(), size, page_size);
    buffer
}

fn build_pool(size: usize, threads: usize) -> BufferPool {
    let cfg = BufferPoolConfig::for_network()
        .with_min_size(NZUsize!(size))
        .with_max_size(NZUsize!(size))
        .with_max_per_class(NZUsize!(threads))
        .with_prefill(true);

    let runner_cfg = tokio::Config::default()
        .with_worker_threads(1)
        .with_network_buffer_pool_config(cfg);

    tokio::Runner::new(runner_cfg).start(|ctx| async move { ctx.network_buffer_pool().clone() })
}

fn touch_pages(ptr: *mut u8, size: usize, page_size: usize) {
    // SAFETY: `ptr` is valid for writes to `size` bytes.
    unsafe {
        for offset in (0..size).step_by(page_size) {
            ptr.add(offset).write_volatile(0);
        }
        ptr.add(size - 1).write_volatile(0);
    }
}

fn page_size() -> usize {
    #[cfg(unix)]
    {
        // SAFETY: sysconf is safe to call.
        let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if size <= 0 {
            4096
        } else {
            size as usize
        }
    }

    #[cfg(not(unix))]
    {
        4096
    }
}

struct AlignedBuffer {
    ptr: NonNull<u8>,
    layout: Layout,
}

impl AlignedBuffer {
    fn new(size: usize, alignment: usize) -> Self {
        let layout = Layout::from_size_align(size, alignment).expect("invalid layout");
        // SAFETY: layout is valid and non-zero sized.
        let ptr = unsafe { alloc(layout) };
        let ptr = NonNull::new(ptr).unwrap_or_else(|| handle_alloc_error(layout));
        Self { ptr, layout }
    }

    #[inline]
    fn as_mut_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }
}

impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        // SAFETY: ptr was allocated with this layout.
        unsafe { dealloc(self.ptr.as_ptr(), self.layout) };
    }
}
