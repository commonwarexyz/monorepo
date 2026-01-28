#![allow(dead_code)]

use std::panic::{catch_unwind, AssertUnwindSafe, RefUnwindSafe, UnwindSafe};

use arbitrary::Unstructured;
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore as _, SeedableRng};

enum Error {
    NoDisplay,
    String(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NoDisplay => write!(f, "<not displayable>"),
            Error::String(s) => write!(f, "{}", s),
        }
    }
}

fn try_catch<T>(f: impl FnOnce() -> T + UnwindSafe) -> Result<T, Error> {
    // Save the current panic hook and install a silent one
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    let result = catch_unwind(f).map_err(|e| {
        if let Some(s) = e.downcast_ref::<String>() {
            Error::String(s.to_string())
        } else if let Some(s) = e.downcast_ref::<&'static str>() {
            Error::String(s.to_string())
        } else {
            Error::NoDisplay
        }
    });

    // Restore the previous hook
    std::panic::set_hook(prev_hook);
    result
}

type Property = dyn Fn(&mut arbitrary::Unstructured<'_>) -> Result<(), arbitrary::Error>;

#[derive(Copy, Clone)]
struct Branch {
    seed: u32,
    thread: u32,
    size: u32,
}

impl Branch {
    fn new(seed: u64) -> Self {
        Self {
            seed: (seed >> 32) as u32,
            thread: seed as u32,
            size: 0,
        }
    }

    fn next(self) -> Self {
        Self {
            seed: self.seed,
            thread: self.thread.wrapping_add(1),
            size: self.size.saturating_add(1),
        }
    }

    fn seed(self) -> u64 {
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
    branch: Branch,
    rng: ChaCha8Rng,
    buf: Vec<u8>,
    count: i64,
    last_bytes_used: usize,
}

impl Sampler {
    fn new_with_buf(branch: Branch, mut buf: Vec<u8>) -> Self {
        buf.clear();
        let rng = ChaCha8Rng::seed_from_u64(branch.seed());
        Self {
            branch,
            rng,
            buf,
            count: branch.size.into(),
            last_bytes_used: 0,
        }
    }

    fn set_bytes_used(&mut self, used: usize) {
        self.last_bytes_used = used;
    }

    fn new(branch: Branch) -> Self {
        Self::new_with_buf(branch, Vec::with_capacity(1 << 16))
    }

    fn switch(&mut self, branch: Branch) {
        let buf = std::mem::take(&mut self.buf);
        *self = Self::new_with_buf(branch, buf)
    }

    fn strategy_add_bytes(&mut self) {
        const MAX_BUF_SIZE: usize = 1 << 13; // 8KB cap
        if self.buf.len() >= MAX_BUF_SIZE {
            return;
        }
        let size = self.buf.len();
        let num_bytes =
            (ADD_BYTES_COEFFS[0] * size * size + ADD_BYTES_COEFFS[1] * size + ADD_BYTES_COEFFS[2])
                / DIVISOR;
        let new_size = (self.buf.len() + num_bytes).min(MAX_BUF_SIZE);
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

        // If we have lots of unused bytes, reduce add_bytes weight
        let unused = self.buf.len().saturating_sub(self.last_bytes_used);
        if unused > 64 {
            weights[5] = 0; // Don't grow if we have plenty of unused bytes
        } else if unused > 16 {
            weights[5] /= 4; // Reduce growth rate
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
            self.strategy_add_bytes();
        } else {
            match self.pick_strategy() {
                0 => self.strategy_modify_prefix(),
                1 => self.strategy_copy_portion(),
                2 => self.strategy_clear_non_prefix(),
                3 => self.strategy_arithmetic_non_prefix(),
                _ => self.strategy_add_bytes(),
            }
        }

        Some(self.buf.as_slice())
    }
}

struct Builder {
    search_limit: u64,
}

impl Builder {
    fn new() -> Self {
        Self {
            search_limit: 100_000,
        }
    }

    fn test(
        self,
        s: impl Fn(&mut arbitrary::Unstructured<'_>) -> Result<(), arbitrary::Error> + RefUnwindSafe,
    ) {
        let mut branch = Branch {
            seed: 0,
            thread: 0,
            size: 0,
        };
        let mut sampler = Sampler::new(branch);
        let mut tries = 0;
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
                        sampler.strategy_add_bytes();
                    }
                    Ok((_, remaining)) => {
                        sampler.set_bytes_used(sample_len - remaining);
                        tries += 1;
                        if tries >= self.search_limit {
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

pub fn test(
    s: impl Fn(&mut arbitrary::Unstructured<'_>) -> Result<(), arbitrary::Error> + RefUnwindSafe,
) {
    Builder::new().test(s)
}

#[cfg(test)]
mod test {
    use arbitrary::Unstructured;

    #[derive(Debug)]
    enum Plan {
        Leaf(u8),
        Branch(bool, Box<Plan>),
    }

    impl Plan {
        fn generate(u: &mut Unstructured<'_>, depth: usize) -> arbitrary::Result<Self> {
            if depth == 0 {
                Ok(Plan::Leaf(u.arbitrary()?))
            } else {
                let b: bool = u.arbitrary()?;
                let child = Plan::generate(u, depth - 1)?;
                Ok(Plan::Branch(b, Box::new(child)))
            }
        }

        fn follow_path(&self, path: &mut impl Iterator<Item = bool>) -> Option<u8> {
            match self {
                Plan::Leaf(v) => Some(*v),
                Plan::Branch(b, child) => {
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
        super::test(|u| {
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
