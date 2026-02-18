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
//!
//! # Why minifuzz?
//!
//! Minifuzz's goal is to both make it easier to write property tests, and to make
//! fuzz tests less burdensome to write. Fuzz tests, using an external fuzzer, require creating a binary
//! target, which is a lot more ceremony than just a unit test. A unit test, on the other hand,
//! is less extensive than a fuzz or property test.
//!
//! When using fuzzing in Rust, you have control over how random bytes are turned
//! into inputs, so they effectively act more like property tests. This module provides
//! a simple fuzzer, intended for unit tests. Unlike an actual fuzzer, this harness
//! does not use coverage information, and is not going to run for as long, so it will
//! naturally find fewer bugs. However, it can find many bugs pretty quickly,
//! and can usually do a much better job than a unit test.
//!
//! In places where you'd normally write a unit test, you should additionally consider
//! using minifuzz to cover more ground than that particular edge case, or test
//! more examples of that kind of edge case.
//!
//! Instead of considering particular examples you want to test, it's useful to
//! consider the *invariants* you want your code to satisfy. This both helps in
//! understanding and implementing your code, but also in more effectively testing
//! it.

use arbitrary::Unstructured;
use commonware_utils::{from_hex, hex};
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore as _, SeedableRng};
use std::{
    panic::{catch_unwind, AssertUnwindSafe, UnwindSafe},
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

    fn try_from_hex(s: &str) -> Option<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes: [u8; 12] = from_hex(s)?.try_into().ok()?;
        let seed = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let thread = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let size = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        Some(Self { seed, thread, size })
    }

    fn from_hex(s: &str) -> Self {
        Self::try_from_hex(s).expect("invalid MINIFUZZ_BRANCH hex format (expected 24 hex chars)")
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
        let mut bytes = [0u8; 12];
        bytes[0..4].copy_from_slice(&self.seed.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.thread.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.size.to_be_bytes());
        write!(f, "0x{}", hex(&bytes))
    }
}

const ENV_VAR: &str = "MINIFUZZ_BRANCH";

fn branch_from_env() -> Option<Branch> {
    std::env::var(ENV_VAR)
        .ok()
        .and_then(|s| Branch::try_from_hex(&s))
}

use std::num::Saturating;

const DIVISOR: usize = 1000;
const ADD_BYTES_COEFFS: [Saturating<usize>; 3] =
    [Saturating(100), Saturating(1000), Saturating(8000)];
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
        let size = Saturating(size);
        let num_bytes =
            (ADD_BYTES_COEFFS[0] * size * size + ADD_BYTES_COEFFS[1] * size + ADD_BYTES_COEFFS[2])
                .0
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
    min_iterations: u64,
    seed: Option<u64>,
    reproduce: Option<Branch>,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            search_bound: SearchBound::Time(Duration::from_secs(10)),
            min_iterations: 100,
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
            ..self
        }
    }

    /// Limits the fuzzer to run a fixed number of test cases.
    pub const fn with_search_limit(self, search_limit: u64) -> Self {
        let min_iterations = if self.min_iterations > search_limit {
            search_limit
        } else {
            self.min_iterations
        };
        Self {
            search_bound: SearchBound::Limit(search_limit),
            min_iterations,
            ..self
        }
    }

    /// Limits the fuzzer to run for a fixed duration.
    pub const fn with_search_time(self, duration: Duration) -> Self {
        Self {
            search_bound: SearchBound::Time(duration),
            ..self
        }
    }

    /// Sets the minimum number of iterations to run, even if the time limit is reached.
    pub const fn with_min_iterations(self, min_iterations: u64) -> Self {
        Self {
            min_iterations,
            ..self
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
        mut s: impl FnMut(&mut arbitrary::Unstructured<'_>) -> Result<(), arbitrary::Error>,
    ) {
        let mut branch = match (self.reproduce, self.seed) {
            (Some(b), _) => b,
            (None, Some(seed)) => Branch::new(seed),
            (None, None) => branch_from_env().unwrap_or_else(|| Branch::new(rand::random())),
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
                        panic!("failure ({ENV_VAR} = {branch}):\n{e}")
                    }
                    Ok((Err(arbitrary::Error::NotEnoughData), _)) => {
                        sampler.strategy_add_bytes(true);
                    }
                    Ok((_, remaining)) => {
                        sampler.set_bytes_used(sample_len - remaining);
                        tries += 1;
                        let past_min = tries >= self.min_iterations;
                        let past_limit =
                            tries >= limit || deadline.is_some_and(|d| Instant::now() >= d);
                        if past_min && past_limit {
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
pub fn test(s: impl FnMut(&mut arbitrary::Unstructured<'_>) -> Result<(), arbitrary::Error>) {
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
        super::Builder::default()
            .with_search_limit(1_000_000)
            .with_seed(0)
            .test(|u| {
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

    #[test]
    #[should_panic(expected = "MINIFUZZ_BRANCH = 0x")]
    fn reproduce_failure() {
        super::Builder::default()
            .with_reproduce("0x0000000000000000000000a0")
            .test(|u| {
                let v: u8 = u.arbitrary()?;
                assert_ne!(v, 42);
                Ok(())
            });
    }

    #[test]
    #[should_panic(expected = "<not displayable>")]
    fn panic_non_displayable() {
        struct NonDisplayable;
        super::Builder::default()
            .with_search_limit(1)
            .with_seed(0)
            .test(|_u| {
                std::panic::panic_any(NonDisplayable);
            });
    }

    #[test]
    fn search_limit_reduces_min_iterations() {
        let mut calls = 0u64;
        super::Builder::default()
            .with_min_iterations(1000)
            .with_search_limit(1)
            .with_seed(0)
            .test(|_u| {
                calls += 1;
                Ok(())
            });
        assert_eq!(calls, 1);
    }

    #[test]
    #[should_panic(expected = "MINIFUZZ_BRANCH = 0x")]
    fn min_iterations_overrides_search_time() {
        super::Builder::default()
            .with_search_time(std::time::Duration::ZERO)
            .with_min_iterations(1000)
            .with_seed(0)
            .test(|u| {
                let v: u8 = u.arbitrary()?;
                assert_ne!(v, 42);
                Ok(())
            });
    }
}
