//! Configuration for prover and verifier.

/// Verifier configuration (no prover-only dependencies).
#[derive(Clone, Debug)]
pub struct VerifierConfig {
    /// Number of recursive proof rounds.
    pub recursive_steps: usize,
    /// Log2 of the initial matrix row count.
    pub initial_dim: usize,
    /// Log2 of each recursive round's matrix row count.
    pub log_dims: Vec<usize>,
    /// Number of initial partial evaluation challenges.
    pub initial_k: usize,
    /// Number of sumcheck rounds per recursive step.
    pub ks: Vec<usize>,
    /// Number of query rows to open (security parameter).
    pub num_queries: usize,
}

impl VerifierConfig {
    /// Log2 of the committed polynomial size.
    pub fn poly_log_size(&self) -> usize {
        self.initial_dim + self.initial_k
    }
}

/// Prover configuration.
pub struct ProverConfig<T: crate::field::BinaryFieldElement, U: crate::field::BinaryFieldElement> {
    /// Number of recursive proof rounds.
    pub recursive_steps: usize,
    /// Initial matrix dimensions (rows, cols).
    pub initial_dims: (usize, usize),
    /// Recursive round matrix dimensions.
    pub dims: Vec<(usize, usize)>,
    /// Number of initial partial evaluation challenges.
    pub initial_k: usize,
    /// Number of sumcheck rounds per recursive step.
    pub ks: Vec<usize>,
    /// Initial round Reed-Solomon encoder.
    pub initial_reed_solomon: crate::reed_solomon::ReedSolomon<T>,
    /// Recursive round Reed-Solomon encoders.
    pub reed_solomon_codes: Vec<crate::reed_solomon::ReedSolomon<U>>,
    /// Number of query rows to open (>= 148 for 100-bit security).
    pub num_queries: usize,
}

impl<T: crate::field::BinaryFieldElement, U: crate::field::BinaryFieldElement> ProverConfig<T, U> {
    /// Validate configuration parameters.
    pub fn validate(&self) -> crate::Result<()> {
        if self.num_queries < 148 {
            return Err(crate::Error::InvalidConfig(
                "num_queries must be >= 148 for 100-bit security",
            ));
        }
        Ok(())
    }
}

// -- Autosizer: optimal configs for 2^20 through 2^30 --

/// Minimum supported polynomial size (log2).
pub const MIN_LOG_SIZE: u32 = 20;

/// Maximum supported polynomial size (log2).
pub const MAX_LOG_SIZE: u32 = 30;

/// Optimal parameters per size.
/// (log_size, recursive_steps, initial_dim_log, initial_k, &[(dim_log, k)])
const OPTIMAL_CONFIGS: [(u32, usize, u32, usize, &[(u32, usize)]); 11] = [
    (20, 1, 14, 6, &[(10, 4)]),
    (21, 1, 15, 6, &[(11, 4)]),
    (22, 2, 16, 6, &[(12, 4), (8, 4)]),
    (23, 2, 17, 6, &[(13, 4), (9, 4)]),
    (24, 2, 18, 6, &[(14, 4), (10, 4)]),
    (25, 2, 19, 6, &[(15, 4), (11, 4)]),
    (26, 3, 20, 6, &[(16, 4), (12, 4), (8, 4)]),
    (27, 3, 21, 6, &[(17, 4), (13, 4), (9, 4)]),
    (28, 3, 22, 6, &[(18, 4), (14, 4), (10, 4)]),
    (29, 3, 23, 6, &[(19, 4), (15, 4), (11, 4)]),
    (30, 3, 23, 7, &[(19, 4), (15, 4), (11, 4)]),
];

/// Log2 of the required padded size for a polynomial of `len` elements.
pub fn log_size_for_len(len: usize) -> u32 {
    if len == 0 {
        return MIN_LOG_SIZE;
    }
    let log = (len as f64).log2().ceil() as u32;
    log.clamp(MIN_LOG_SIZE, MAX_LOG_SIZE)
}

/// Select optimal prover config for a polynomial of `len` elements.
///
/// Returns `(config, padded_size)` where `padded_size` is the power-of-2
/// the polynomial should be zero-padded to.
pub fn prover_config_for_size<T, U>(len: usize) -> (ProverConfig<T, U>, usize)
where
    T: crate::field::BinaryFieldElement,
    U: crate::field::BinaryFieldElement,
{
    let log_size = log_size_for_len(len);
    let config = prover_config_for_log_size::<T, U>(log_size);
    (config, 1 << log_size)
}

/// Select optimal verifier config for a polynomial of `len` elements.
pub fn verifier_config_for_size(len: usize) -> VerifierConfig {
    let log_size = log_size_for_len(len);
    verifier_config_for_log_size(log_size)
}

/// Prover config for exact log2 size (20..=30).
pub fn prover_config_for_log_size<T, U>(log_size: u32) -> ProverConfig<T, U>
where
    T: crate::field::BinaryFieldElement,
    U: crate::field::BinaryFieldElement,
{
    let log_size = log_size.clamp(MIN_LOG_SIZE, MAX_LOG_SIZE);
    let idx = (log_size - MIN_LOG_SIZE) as usize;
    let (_, recursive_steps, initial_dim_log, initial_k, dims_ks) = OPTIMAL_CONFIGS[idx];

    let inv_rate = 4;
    let initial_dims = (1 << initial_dim_log, 1 << (log_size - initial_dim_log));

    let dims: Vec<(usize, usize)> = dims_ks
        .iter()
        .map(|&(dim_log, k)| (1 << (dim_log - k as u32), 1 << k))
        .collect();

    let ks: Vec<usize> = dims_ks.iter().map(|&(_, k)| k).collect();

    let initial_reed_solomon =
        crate::reed_solomon::reed_solomon::<T>(initial_dims.0, initial_dims.0 * inv_rate);
    let reed_solomon_codes = dims
        .iter()
        .map(|&(m, _)| crate::reed_solomon::reed_solomon::<U>(m, m * inv_rate))
        .collect();

    ProverConfig {
        recursive_steps,
        initial_dims,
        dims,
        initial_k,
        ks,
        initial_reed_solomon,
        reed_solomon_codes,
        num_queries: 148,
    }
}

/// Verifier config for exact log2 size (20..=30).
pub fn verifier_config_for_log_size(log_size: u32) -> VerifierConfig {
    let log_size = log_size.clamp(MIN_LOG_SIZE, MAX_LOG_SIZE);
    let idx = (log_size - MIN_LOG_SIZE) as usize;
    let (_, recursive_steps, initial_dim_log, initial_k, dims_ks) = OPTIMAL_CONFIGS[idx];

    let log_dims: Vec<usize> = dims_ks
        .iter()
        .map(|&(dim_log, k)| (dim_log - k as u32) as usize)
        .collect();

    let ks: Vec<usize> = dims_ks.iter().map(|&(_, k)| k).collect();

    VerifierConfig {
        recursive_steps,
        initial_dim: initial_dim_log as usize,
        log_dims,
        initial_k,
        ks,
        num_queries: 148,
    }
}

/// Shorthand for 2^20 prover config.
pub fn prover_config_20<T, U>() -> ProverConfig<T, U>
where
    T: crate::field::BinaryFieldElement,
    U: crate::field::BinaryFieldElement,
{
    prover_config_for_log_size(20)
}

/// Shorthand for 2^20 verifier config.
pub fn verifier_config_20() -> VerifierConfig {
    verifier_config_for_log_size(20)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_size_for_len() {
        assert_eq!(log_size_for_len(0), 20);
        assert_eq!(log_size_for_len(1), 20);
        assert_eq!(log_size_for_len(1 << 20), 20);
        assert_eq!(log_size_for_len((1 << 20) + 1), 21);
        assert_eq!(log_size_for_len(1 << 24), 24);
        assert_eq!(log_size_for_len(1 << 30), 30);
        assert_eq!(log_size_for_len(usize::MAX), 30);
    }

    #[test]
    fn test_verifier_config_consistency() {
        for log_size in MIN_LOG_SIZE..=MAX_LOG_SIZE {
            let config = verifier_config_for_log_size(log_size);

            assert_eq!(config.recursive_steps, config.log_dims.len());
            assert_eq!(config.recursive_steps, config.ks.len());
            assert!(config.initial_k > 0);
            assert!(config.initial_dim > 0);

            let initial_total = config.initial_dim + config.initial_k;
            assert_eq!(
                initial_total as u32, log_size,
                "initial_dim + initial_k should equal log_size for 2^{}",
                log_size
            );
        }
    }

    #[test]
    fn test_prover_config_consistency() {
        use crate::field::{BinaryElem128, BinaryElem32};

        // Only test a few sizes in debug (RS code generation is slow)
        for &log_size in &[20u32, 21, 22, 24] {
            let config = prover_config_for_log_size::<BinaryElem32, BinaryElem128>(log_size);

            let initial_size = config.initial_dims.0 * config.initial_dims.1;
            assert_eq!(
                initial_size,
                1 << log_size,
                "initial dims should multiply to 2^{}",
                log_size
            );

            assert_eq!(config.recursive_steps, config.dims.len());
            assert_eq!(config.recursive_steps, config.ks.len());
            assert_eq!(config.recursive_steps, config.reed_solomon_codes.len());
        }
    }
}
