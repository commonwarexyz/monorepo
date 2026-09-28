//! Optional local vote timing based on estimated one-way network delays.

use std::{sync::Arc, time::Duration};

/// Validated B-lambda vote pacing. Matrix rows and columns use committee participant order.
///
/// Pacing delays ordinary vote construction from receipt of the proposal that becomes locally valid.
/// The protocol's timeout and rescue vote remain authoritative. Estimates are advisory and need
/// not agree between validators. Omitting this configuration disables pacing.
#[derive(Clone, Debug)]
pub struct VotePacing {
    delays: Arc<[Duration]>,
    participants: usize,
    lambda: f64,
    cap: Duration,
}

/// Invalid local vote-pacing settings.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PacingError {
    /// The matrix is empty, non-square, or differs from the epoch's participant count.
    #[error("vote pacing matrix must be square and match the participant count")]
    Dimensions,
    /// A delay or lambda is negative, non-finite, or outside its supported range.
    #[error("vote pacing requires finite nonnegative delays and lambda in [0, 1]")]
    Value,
}

impl VotePacing {
    /// Validates a square matrix of one-way delays in milliseconds and lambda in `[0, 1]`.
    ///
    /// `cap` defaults to twice the median off-diagonal one-way delay (zero for one participant).
    /// The median of an even number of entries is the mean of the middle pair.
    ///
    /// # Errors
    ///
    /// Rejects an empty or non-square matrix, invalid lambda, and delays that cannot be
    /// represented as a nonnegative finite duration.
    pub fn new(
        matrix_ms: Vec<Vec<f64>>,
        lambda: f64,
        cap: Option<Duration>,
    ) -> Result<Self, PacingError> {
        let participants = matrix_ms.len();
        if participants == 0 || matrix_ms.iter().any(|row| row.len() != participants) {
            return Err(PacingError::Dimensions);
        }
        if !lambda.is_finite() || !(0.0..=1.0).contains(&lambda) {
            return Err(PacingError::Value);
        }
        let delays = matrix_ms
            .into_iter()
            .flatten()
            .map(|ms| {
                if !ms.is_finite() || ms < 0.0 {
                    return Err(PacingError::Value);
                }
                Duration::try_from_secs_f64(ms / 1000.0).map_err(|_| PacingError::Value)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let cap = cap.unwrap_or_else(|| {
            let mut samples = delays
                .iter()
                .enumerate()
                .filter_map(|(i, delay)| (i / participants != i % participants).then_some(*delay))
                .collect::<Vec<_>>();
            samples.sort_unstable();
            match samples.len() {
                0 => Duration::ZERO,
                n if n.is_multiple_of(2) => samples[n / 2 - 1].saturating_add(samples[n / 2]),
                n => samples[n / 2].saturating_mul(2),
            }
        });
        Ok(Self {
            delays: delays.into(),
            participants,
            lambda,
            cap,
        })
    }

    /// Checks that this matrix uses the epoch's committee size.
    ///
    /// # Errors
    ///
    /// Returns [`PacingError::Dimensions`] when the sizes differ.
    pub const fn validate_participants(&self, participants: usize) -> Result<(), PacingError> {
        if self.participants == participants {
            Ok(())
        } else {
            Err(PacingError::Dimensions)
        }
    }

    pub(crate) const fn participants(&self) -> usize {
        self.participants
    }

    pub(crate) fn delay(
        &self,
        leader: usize,
        next: usize,
        me: usize,
        quorum: usize,
        scores: &mut Vec<Duration>,
    ) -> Duration {
        scores.clear();
        scores.extend((0..self.participants).map(|q| {
            self.delays[leader * self.participants + q]
                .saturating_add(self.delays[q * self.participants + next])
        }));
        let local = scores[me];
        let (_, q0, _) = scores.select_nth_unstable(quorum - 1);
        Duration::try_from_secs_f64(q0.saturating_sub(local).as_secs_f64() * self.lambda)
            .unwrap_or(Duration::MAX)
            .min(self.cap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formula_uses_two_legs_quorum_and_cap() {
        let matrix = vec![
            vec![0., 10., 30., 40.],
            vec![10., 0., 20., 30.],
            vec![30., 20., 0., 10.],
            vec![40., 30., 10., 0.],
        ];
        let mut scratch = Vec::new();
        let pacing = VotePacing::new(matrix.clone(), 0.5, None).unwrap();
        // L=0, N=1: scores [10, 10, 50, 70], third smallest 50.
        assert_eq!(
            pacing.delay(0, 1, 0, 3, &mut scratch),
            Duration::from_millis(20)
        );
        assert_eq!(pacing.delay(0, 1, 3, 3, &mut scratch), Duration::ZERO);
        assert_eq!(pacing.cap, Duration::from_millis(50));
        let pacing = VotePacing::new(matrix.clone(), 1., Some(Duration::from_millis(7))).unwrap();
        assert_eq!(
            pacing.delay(0, 1, 0, 3, &mut scratch),
            Duration::from_millis(7)
        );
        let pacing = VotePacing::new(matrix, 0., None).unwrap();
        assert_eq!(pacing.delay(0, 1, 0, 3, &mut scratch), Duration::ZERO);
    }

    #[test]
    fn asymmetric_delays_use_the_scheduled_successor() {
        let pacing = VotePacing::new(
            vec![
                vec![0., 4., 20., 30.],
                vec![9., 0., 8., 7.],
                vec![6., 5., 0., 2.],
                vec![1., 12., 3., 0.],
            ],
            0.5,
            Some(Duration::from_secs(1)),
        )
        .unwrap();
        // L=0, N=2: scores [20, 12, 20, 33], third smallest 20.
        assert_eq!(
            pacing.delay(0, 2, 1, 3, &mut Vec::new()),
            Duration::from_millis(4)
        );
    }

    #[test]
    fn rejects_invalid_values_and_dimensions() {
        for matrix in [vec![], vec![vec![]], vec![vec![0., 1.]]] {
            assert_eq!(
                VotePacing::new(matrix, 1., None).unwrap_err(),
                PacingError::Dimensions
            );
        }
        for value in [f64::NAN, f64::INFINITY, -1., -f64::from_bits(1), f64::MAX] {
            assert!(VotePacing::new(vec![vec![value]], 1., None).is_err());
        }
        for lambda in [f64::NAN, f64::INFINITY, -1., 1.1] {
            assert!(VotePacing::new(vec![vec![0.]], lambda, None).is_err());
        }
        let pacing = VotePacing::new(vec![vec![0.]], 1., None).unwrap();
        assert_eq!(pacing.cap, Duration::ZERO);
        assert!(pacing.validate_participants(2).is_err());
    }
}
