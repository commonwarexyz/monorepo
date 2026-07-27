//! Adaptive idle spinning for the io_uring event loop.
//!
//! When the ring is fully idle, the loop would normally park on a futex
//! immediately. The futex park/wake round-trip has non-trivial cost due
//! to scheduler involvement. [`Spinner`] adds a short spin phase before
//! parking: if new work arrives during the spin, the park is avoided
//! entirely.
//!
//! The spin budget (in iteration counts) adapts based on outcomes:
//! - Hit (work arrived during spin): budget grows (+25%).
//! - Miss (spin expired, had to park): budget shrinks (-12.5%).
//! - Quick wake (parked but woke fast): budget grows aggressively (+50%).
//!
//! A quick wake indicates the loop committed to parking just before work
//! arrived. The observed park duration is roughly how much longer it should
//! have spun to avoid the scheduler round-trip. The spinner tracks a running
//! estimate of these durations as a *near-miss floor* that acts as a learned
//! lower bound on the budget. Without it, repeated misses would decay the
//! budget down to the configured minimum even when the workload's actual
//! near-miss cost is higher. The floor decays gently on misses (1/16 per miss)
//! so it doesn't stay pinned after a workload shift.
//!
//! A one-time calibration at construction converts user-facing microsecond
//! configuration into iteration counts. The caller provides a probe function
//! with the same cost profile as the real spin condition so calibration
//! accounts for per-iteration condition overhead.

use std::time::{Duration, Instant};

/// Number of iterations used by the calibration loop.
const CALIBRATION_ITERATIONS: usize = 100_000;

/// Spinner configuration. Values are in microseconds.
#[derive(Clone, Debug)]
pub struct Config {
    /// Initial and minimum spin budget in microseconds. The adaptive
    /// controller grows the budget on hits and shrinks it on misses, but
    /// never decays below this value. Set to 0 to disable spinning.
    pub budget_us: usize,
    /// Maximum spin budget in microseconds. The controller never exceeds
    /// this regardless of adaptation.
    pub max_budget_us: usize,
    /// Quick-wake threshold in microseconds. If the loop parks and wakes
    /// with real work in less than this duration, the controller grows the
    /// budget aggressively (the loop should have spun longer).
    pub quick_wake_us: usize,
}

impl Config {
    /// Returns a config that disables spinning entirely.
    pub const fn disabled() -> Self {
        Self {
            budget_us: 0,
            max_budget_us: 0,
            quick_wake_us: 0,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            budget_us: 50,
            max_budget_us: 300,
            quick_wake_us: 150,
        }
    }
}

/// Adaptive spin budget controller.
///
/// Call [`Spinner::spin`] with a condition to busy-wait up to the current
/// budget. On a miss, call [`Spinner::on_wake`] after the fallback park
/// returns, the spinner uses the park duration to adjust its budget.
pub struct Spinner {
    /// Current spin budget, in iterations.
    budget: usize,
    /// Minimum budget, in iterations. Budget never decays below this.
    min_budget: usize,
    /// Maximum budget, in iterations. Budget never grows above this.
    max_budget: usize,
    /// Learned near-miss floor, in iterations. Tracks a weighted average of
    /// recent quick-wake park durations. Can push the effective minimum above
    /// `min_budget`. Decays on misses at 1/16 per miss to avoid staying pinned
    /// after workload shifts.
    near_miss_floor: usize,
    /// Calibrated iterations per microsecond. Used to convert microsecond
    /// config values into iteration counts and to convert quick-wake park
    /// durations back into iteration counts for the near-miss floor.
    iters_per_us: usize,
    /// Quick-wake threshold. Parks shorter than this grow the budget.
    quick_wake: Duration,
}

impl Spinner {
    /// Create a new spinner. Runs a one-time calibration loop using `probe`
    /// to measure the per-iteration cost of the real spin condition. The probe
    /// should have the same cost as the condition passed to [`Spinner::spin`].
    ///
    /// Panics if `budget_us > max_budget_us`.
    pub fn new(cfg: &Config, probe: impl Fn() -> bool) -> Self {
        assert!(
            cfg.budget_us <= cfg.max_budget_us,
            "spinner budget_us ({}) must not exceed max_budget_us ({})",
            cfg.budget_us,
            cfg.max_budget_us,
        );
        let iters_per_us = calibrate(probe);
        let min_budget = cfg.budget_us.saturating_mul(iters_per_us);
        Self {
            budget: min_budget,
            min_budget,
            max_budget: cfg.max_budget_us.saturating_mul(iters_per_us),
            near_miss_floor: min_budget,
            iters_per_us,
            quick_wake: Duration::from_micros(cfg.quick_wake_us as u64),
        }
    }

    /// Spin for up to `budget` iterations, checking `condition` each time.
    /// Returns `true` if the condition was met (hit), `false` if the budget
    /// expired (miss). Adapts the budget internally based on the outcome.
    /// Returns `false` immediately without calling `condition` or adapting
    /// state when the budget is zero (spinning disabled).
    #[inline]
    pub fn spin(&mut self, mut condition: impl FnMut() -> bool) -> bool {
        if self.budget == 0 {
            return false;
        }
        for _ in 0..self.budget {
            if condition() {
                self.on_hit();
                return true;
            }
            core::hint::spin_loop();
        }
        self.on_miss();
        false
    }

    /// Work arrived during spin. Reward by growing the budget.
    #[inline]
    fn on_hit(&mut self) {
        // Grow by 25%, capped at max_budget.
        self.budget = (self.budget + self.budget / 4).min(self.max_budget);
    }

    /// Spin expired without work arriving. Gently reduce the budget
    /// and decay the near-miss floor so stale history doesn't keep the
    /// floor pinned.
    #[inline]
    fn on_miss(&mut self) {
        // Decay the learned floor by 1/16.
        self.near_miss_floor -= self.near_miss_floor / 16;
        // Shrink by 12.5%, clamped to the effective floor.
        let floor = self.near_miss_floor.max(self.min_budget);
        self.budget = self.budget.saturating_sub(self.budget / 8).max(floor);
    }

    /// Called after a futex park that actually slept. If the park was
    /// shorter than the quick-wake threshold, grows the budget by 50% (we
    /// should have spun longer) and updates the near-miss floor.
    #[inline]
    pub fn on_wake(&mut self, park_duration: Duration) {
        if park_duration <= self.quick_wake {
            // Grow by 50%, capped at max_budget.
            self.budget = (self.budget + self.budget / 2).min(self.max_budget);
            // Update the learned floor with a 1/4-weighted sample of the
            // observed park duration, clamped so it can't exceed max_budget.
            let park_iters = (park_duration.as_nanos() * self.iters_per_us as u128 / 1000) as usize;
            let floor = (self.near_miss_floor * 3 + park_iters) / 4;
            self.near_miss_floor = floor.min(self.max_budget);
        }
    }
}

/// Measure iterations per microsecond by running `probe` + `spin_loop()`
/// in a tight loop. The probe should match the real spin condition's cost.
fn calibrate(probe: impl Fn() -> bool) -> usize {
    let start = Instant::now();
    for _ in 0..CALIBRATION_ITERATIONS {
        std::hint::black_box(probe());
        core::hint::spin_loop();
    }
    let elapsed_us = start.elapsed().as_micros() as usize;
    CALIBRATION_ITERATIONS / elapsed_us.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config {
            budget_us: 10,
            max_budget_us: 50,
            quick_wake_us: 50,
        }
    }

    #[test]
    fn test_calibration_returns_nonzero() {
        assert!(calibrate(|| false) > 0);
    }

    #[test]
    fn test_spin_immediate_hit() {
        let mut s = Spinner::new(&cfg(), || false);
        assert!(s.spin(|| true));
    }

    #[test]
    fn test_spin_miss() {
        let mut s = Spinner::new(&cfg(), || false);
        assert!(!s.spin(|| false));
    }

    #[test]
    fn test_spin_delayed_hit() {
        let mut s = Spinner::new(&cfg(), || false);
        let mut count = 0usize;
        let hit = s.spin(|| {
            count += 1;
            count >= 50
        });
        assert!(hit);
        assert_eq!(count, 50);
    }

    #[test]
    fn test_hit_grows_budget() {
        let mut s = Spinner::new(&cfg(), || false);
        let initial = s.budget;
        s.spin(|| true);
        assert!(s.budget > initial);
    }

    #[test]
    fn test_miss_shrinks_budget() {
        let mut s = Spinner::new(&cfg(), || false);
        s.spin(|| true);
        let after_hit = s.budget;
        s.spin(|| false);
        assert!(s.budget < after_hit);
    }

    #[test]
    fn test_budget_does_not_go_below_min() {
        let mut s = Spinner::new(&cfg(), || false);
        for _ in 0..1000 {
            s.spin(|| false);
        }
        assert!(s.budget >= s.min_budget);
    }

    #[test]
    fn test_budget_does_not_exceed_max() {
        let mut s = Spinner::new(&cfg(), || false);
        for _ in 0..1000 {
            s.spin(|| true);
        }
        assert!(s.budget <= s.max_budget);
    }

    #[test]
    fn test_quick_wake_grows_budget_and_floor() {
        let mut s = Spinner::new(&cfg(), || false);
        assert_eq!(s.near_miss_floor, s.min_budget);
        let before = s.near_miss_floor;
        // Large quick-wake sample pushes the floor above min_budget.
        s.on_wake(Duration::from_micros(30));
        assert!(s.near_miss_floor > before);
    }

    #[test]
    fn test_slow_block_does_not_grow() {
        let mut s = Spinner::new(&cfg(), || false);
        let before = s.budget;
        s.on_wake(Duration::from_nanos(100_000));
        assert_eq!(s.budget, before);
    }

    #[test]
    fn test_near_miss_floor_decays_on_miss() {
        let mut s = Spinner::new(&cfg(), || false);
        s.on_wake(Duration::from_nanos(10_000));
        let floor_after_wake = s.near_miss_floor;
        assert!(floor_after_wake > 0);
        for _ in 0..100 {
            s.spin(|| false);
        }
        assert!(s.near_miss_floor < floor_after_wake);
    }

    #[test]
    fn test_near_miss_floor_clamped_to_max() {
        let mut s = Spinner::new(&cfg(), || false);
        s.on_wake(Duration::from_nanos(40_000));
        assert!(s.near_miss_floor <= s.max_budget);
    }

    #[test]
    #[should_panic(expected = "must not exceed max_budget_us")]
    fn test_new_panics_when_budget_exceeds_max() {
        let _ = Spinner::new(
            &Config {
                budget_us: 100,
                max_budget_us: 50,
                quick_wake_us: 50,
            },
            || false,
        );
    }

    #[test]
    fn test_disabled_spinner() {
        let mut s = Spinner::new(&Config::disabled(), || false);
        assert!(!s.spin(|| true));
    }
}
