//! Simple fuzzing harness for in-module tests.
//!
//! # Examples
//!
//! Basic usage:
//!
//! ```ignore
//! minifuzz::test(|u| {
//!     let x: u32 = u.arbitrary()?;
//!     let y: u32 = u.arbitrary()?;
//!     assert!(x.checked_add(y).is_some() || x > 1000);
//!     Ok(())
//! });
//! ```
//!
//! On failure, the output includes a hex token like `MINIFUZZ_BRANCH = 0x...`.
//! Use `with_reproduce` to replay that exact failure:
//!
//! ```ignore
//! Builder::default()
//!     .with_reproduce("0x000000000000002a0000002a")
//!     .test(|u| {
//!         // same test body
//!         Ok(())
//!     });
//! ```
//!
//! Use `with_search_limit` or `with_search_time` to control how long the fuzzer runs.

use arbitrary::Unstructured;
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore as _, SeedableRng};
use std::{
    panic::{catch_unwind, AssertUnwindSafe, RefUnwindSafe, UnwindSafe},
    time::{Duration, Instant},
};

enum Error {
    NoDisplay,
    String(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoDisplay => write!(f, "<not displayable>"),
            Self::String(s) => write!(f, "{}", s),
        }
    }
}

fn try_catch<T>(f: impl FnOnce() -> T + UnwindSafe) -> Result<T, Error> {
    catch_unwind(f).map_err(|e| {
        e.downcast_ref::<String>()
            .map(|s| Error::String(s.to_string()))
            .or_else(|| {
                e.downcast_ref::<&'static str>()
                    .map(|s| Error::String((*s).to_string()))
            })
            .unwrap_or(Error::NoDisplay)
    })
}

#[derive(Copy, Clone)]
struct Branch {
    seed: u32,
    thread: u32,
    size: u32,
}

impl Branch {
    const fn new(seed: u64) -> Self {
        Self {
            seed: (seed >> 32) as u32,
            thread: seed as u32,
            size: 0,
        }
    }

    fn from_hex(s: &str) -> Self {
        let s = s.strip_prefix("0x").unwrap_or(s);
        assert!(s.len() == 24, "expected 24 hex chars, got {}", s.len());
        let seed = u32::from_str_radix(&s[0..8], 16).expect("invalid hex for seed");
        let thread = u32::from_str_radix(&s[8..16], 16).expect("invalid hex for thread");
        let size = u32::from_str_radix(&s[16..24], 16).expect("invalid hex for size");
        Self { seed, thread, size }
    }

    const fn next(self) -> Self {
        Self {
            seed: self.seed,
            thread: self.thread.wrapping_add(1),
            size: self.size.saturating_add(1),
        }
    }

    const fn rng_seed(self) -> u64 {
        (self.seed as u64) << 32 | self.thread as u64
    }
}

impl std::fmt::Display for Branch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:08x}{:08x}{:08x}", self.seed, self.thread, self.size)
    }
}

const DIVISOR: usize = 1000;
const ADD_BYTES_COEFFS: [usize; 3] = [100, 1000, 8000];
const MODIFY_PREFIX_NUMERATOR: usize = 100;
const MODIFY_PREFIX_MIN_BYTES: usize = 8;
const COPY_PORTION_NUMERATOR: usize = 50;

const STRATEGY_WEIGHTS: [u32; 6] = [200, 20, 10, 50, 10, 200];

struct Sampler {
    rng: ChaCha8Rng,
    buf: Vec<u8>,
    count: i64,
    last_bytes_used: usize,
}

impl Sampler {
    fn new_with_buf(branch: Branch, mut buf: Vec<u8>) -> Self {
        buf.clear();
        let rng = ChaCha8Rng::seed_from_u64(branch.rng_seed());
        Self {
            rng,
            buf,
            count: branch.size.into(),
            last_bytes_used: 0,
        }
    }

    const fn set_bytes_used(&mut self, used: usize) {
        self.last_bytes_used = used;
    }

    fn new(branch: Branch) -> Self {
        Self::new_with_buf(branch, Vec::with_capacity(1 << 16))
    }

    fn switch(&mut self, branch: Branch) {
        let buf = std::mem::take(&mut self.buf);
        *self = Self::new_with_buf(branch, buf)
    }

    fn strategy_add_bytes(&mut self, force: bool) {
        const MAX_BUF_SIZE: usize = 1 << 13; // 8KB cap
        if !force && self.buf.len() >= MAX_BUF_SIZE {
            return;
        }
        let size = self.buf.len();
        let num_bytes =
            (ADD_BYTES_COEFFS[0] * size * size + ADD_BYTES_COEFFS[1] * size + ADD_BYTES_COEFFS[2])
                / DIVISOR;
        let new_size = if force {
            self.buf.len() + num_bytes
        } else {
            (self.buf.len() + num_bytes).min(MAX_BUF_SIZE)
        };
        let start = self.buf.len();
        self.buf.resize(new_size, 0);
        self.rng.fill_bytes(&mut self.buf[start..]);
    }

    fn strategy_modify_prefix(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        let max_by_proportion = self.buf.len() * MODIFY_PREFIX_NUMERATOR / DIVISOR;
        let prefix_len = max_by_proportion
            .max(MODIFY_PREFIX_MIN_BYTES)
            .min(self.buf.len());
        self.rng.fill_bytes(&mut self.buf[..prefix_len]);
    }

    fn strategy_copy_portion(&mut self) {
        if self.buf.len() < 2 {
            return;
        }
        let portion_size = (self.buf.len() * COPY_PORTION_NUMERATOR / DIVISOR).max(1);
        let portion_size = portion_size.min(self.buf.len() / 2);
        let src_start = (self.rng.next_u32() as usize) % (self.buf.len() - portion_size + 1);
        let dst_start = (self.rng.next_u32() as usize) % (self.buf.len() - portion_size + 1);
        self.buf
            .copy_within(src_start..src_start + portion_size, dst_start);
    }

    fn strategy_clear_non_prefix(&mut self) {
        let prefix_len = MODIFY_PREFIX_MIN_BYTES.min(self.buf.len());
        if prefix_len >= self.buf.len() {
            return;
        }
        let start = prefix_len + (self.rng.next_u32() as usize) % (self.buf.len() - prefix_len);
        let len = ((self.rng.next_u32() as usize) % (self.buf.len() - start)).max(1);
        self.buf[start..start + len].fill(0);
    }

    fn strategy_arithmetic_non_prefix(&mut self) {
        let prefix_len = MODIFY_PREFIX_MIN_BYTES.min(self.buf.len());
        if prefix_len >= self.buf.len() {
            return;
        }
        let start = prefix_len + (self.rng.next_u32() as usize) % (self.buf.len() - prefix_len);
        let len = ((self.rng.next_u32() as usize) % (self.buf.len() - start)).max(1);
        let delta = self.rng.next_u32() as u8;
        for b in &mut self.buf[start..start + len] {
            *b = b.wrapping_add(delta);
        }
    }

    fn pick_strategy(&mut self) -> u32 {
        let mut weights = STRATEGY_WEIGHTS;

        // If we have lots of unused bytes, reduce add_bytes weight (indices 4 and 5)
        let unused = self.buf.len().saturating_sub(self.last_bytes_used);
        if unused > 64 {
            weights[4] = 0; // Don't grow if we have plenty of unused bytes
            weights[5] = 0;
        } else if unused > 16 {
            weights[4] /= 4; // Reduce growth rate
            weights[5] /= 4;
        }

        // If buffer is small, favor modify_prefix more
        if self.buf.len() <= 16 {
            weights[0] = weights[0].saturating_mul(2);
        }

        let total: u32 = weights.iter().sum();
        if total == 0 {
            return 0; // Fallback to modify_prefix
        }
        let mut choice = self.rng.next_u32() % total;
        for (i, &w) in weights.iter().enumerate() {
            if choice < w {
                return i as u32;
            }
            choice -= w;
        }
        0
    }

    /// The reason this isn't in an impl Iterator is because of lifetimes.
    fn next(&mut self) -> Option<&[u8]> {
        if self.count < 0 {
            return None;
        }
        self.count -= 1;

        if self.buf.is_empty() {
            self.strategy_add_bytes(false);
        } else {
            match self.pick_strategy() {
                0 => self.strategy_modify_prefix(),
                1 => self.strategy_copy_portion(),
                2 => self.strategy_clear_non_prefix(),
                3 => self.strategy_arithmetic_non_prefix(),
                _ => self.strategy_add_bytes(false),
            }
        }

        Some(self.buf.as_slice())
    }
}

enum SearchBound {
    Limit(u64),
    Time(Duration),
}

/// Configures and runs a fuzz test.
pub struct Builder {
    search_bound: SearchBound,
    seed: Option<u64>,
    reproduce: Option<Branch>,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            search_bound: SearchBound::Limit(500_000),
            seed: None,
            reproduce: None,
        }
    }
}

impl Builder {
    /// Sets the RNG seed for deterministic fuzzing.
    pub const fn with_seed(self, seed: u64) -> Self {
        Self {
            seed: Some(seed),
            search_bound: self.search_bound,
            reproduce: self.reproduce,
        }
    }

    /// Limits the fuzzer to run a fixed number of test cases.
    pub const fn with_search_limit(self, search_limit: u64) -> Self {
        Self {
            search_bound: SearchBound::Limit(search_limit),
            seed: self.seed,
            reproduce: self.reproduce,
        }
    }

    /// Limits the fuzzer to run for a fixed duration.
    pub const fn with_search_time(self, duration: Duration) -> Self {
        Self {
            search_bound: SearchBound::Time(duration),
            seed: self.seed,
            reproduce: self.reproduce,
        }
    }

    /// Reproduces a failure from its hex token (the `MINIFUZZ_BRANCH = ...` output).
    pub fn with_reproduce(self, hex: &str) -> Self {
        Self {
            reproduce: Some(Branch::from_hex(hex)),
            ..self
        }
    }

    /// Runs the fuzz test. Panics if a failure is found.
    pub fn test(
        self,
        s: impl Fn(&mut arbitrary::Unstructured<'_>) -> Result<(), arbitrary::Error> + RefUnwindSafe,
    ) {
        let mut branch = match self.reproduce {
            Some(b) => b,
            None => {
                let initial_seed = self.seed.unwrap_or_else(rand::random);
                Branch::new(initial_seed)
            }
        };
        let mut sampler = Sampler::new(branch);
        let mut tries: u64 = 0;
        let deadline = match self.search_bound {
            SearchBound::Time(d) => Some(Instant::now() + d),
            SearchBound::Limit(_) => None,
        };
        let limit = match self.search_bound {
            SearchBound::Limit(l) => l,
            SearchBound::Time(_) => u64::MAX,
        };
        'search: loop {
            while let Some(sample) = sampler.next() {
                let sample_len = sample.len();
                let result = try_catch(AssertUnwindSafe(|| {
                    let mut u = Unstructured::new(sample);
                    let res = s(&mut u);
                    (res, u.len())
                }));
                match result {
                    Err(e) => {
                        panic!("failure (MINIFUZZ_BRANCH = {}):\n{}", branch, e)
                    }
                    Ok((Err(arbitrary::Error::NotEnoughData), _)) => {
                        sampler.strategy_add_bytes(true);
                    }
                    Ok((_, remaining)) => {
                        sampler.set_bytes_used(sample_len - remaining);
                        tries += 1;
                        let should_stop =
                            tries >= limit || deadline.is_some_and(|d| Instant::now() >= d);
                        if should_stop {
                            break 'search;
                        }
                    }
                }
            }
            branch = branch.next();
            sampler.switch(branch);
        }
        eprintln!("failed to find, final: {}", branch);
    }
}

/// Runs a fuzz test with default settings. See [`Builder`] for configuration options.
pub fn test(
    s: impl Fn(&mut arbitrary::Unstructured<'_>) -> Result<(), arbitrary::Error> + RefUnwindSafe,
) {
    Builder::default().test(s)
}

#[cfg(test)]
mod tests {
    use arbitrary::Unstructured;

    #[derive(Debug)]
    enum Plan {
        Leaf(u8),
        Branch(bool, Box<Self>),
    }

    impl Plan {
        fn generate(u: &mut Unstructured<'_>, depth: usize) -> arbitrary::Result<Self> {
            if depth == 0 {
                Ok(Self::Leaf(u.arbitrary()?))
            } else {
                let b: bool = u.arbitrary()?;
                let child = Self::generate(u, depth - 1)?;
                Ok(Self::Branch(b, Box::new(child)))
            }
        }

        fn follow_path(&self, path: &mut impl Iterator<Item = bool>) -> Option<u8> {
            match self {
                Self::Leaf(v) => Some(*v),
                Self::Branch(b, child) => {
                    if *b == path.next()? {
                        child.follow_path(path)
                    } else {
                        None
                    }
                }
            }
        }
    }

    fn search_haystack(depth: usize) {
        super::Builder::default().with_seed(0).test(|u| {
            let plan = Plan::generate(u, depth)?;
            let mut path = [true, false].into_iter().cycle();
            if let Some(leaf) = plan.follow_path(&mut path) {
                assert_ne!(leaf, 77);
            }
            Ok(())
        });
    }

    #[test]
    #[should_panic]
    fn search_haystack_depth_0() {
        search_haystack(0);
    }

    #[test]
    #[should_panic]
    fn search_haystack_depth_1() {
        search_haystack(1);
    }

    #[test]
    #[should_panic]
    fn search_haystack_depth_2() {
        search_haystack(2);
    }

    #[test]
    #[should_panic]
    fn search_haystack_depth_4() {
        search_haystack(4);
    }

    #[test]
    #[should_panic]
    fn search_haystack_depth_6() {
        search_haystack(6);
    }

    #[test]
    #[should_panic]
    fn search_haystack_depth_8() {
        search_haystack(8);
    }

    #[test]
    #[should_panic]
    fn search_haystack_depth_10() {
        search_haystack(10);
    }
}
