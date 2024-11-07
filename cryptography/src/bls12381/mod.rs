//! Distributed Key Generation (DKG), Resharing, Signatures, and Threshold Signatures over the BLS12-381 curve.
//!
//! # Features
//!
//! This crate has the following features:
//!
//! - `portable`: Enables `portable` feature on `blst` (<https://github.com/supranational/blst?tab=readme-ov-file#platform-and-language-compatibility>).
//!
//! # Benchmarks
//!
//! _The following benchmarks were collected on 11/6/24 on a MacBook Pro (M3 Pro, Nov 2023)._
//!
//! ```bash
//! cargo bench
//! ```
//!
//! ## DKG Recovery (Contributor)
//!
//! ```txt
//! conc=1 n=5 t=3          time:   [7.8876 µs 8.0956 µs 8.4308 µs]
//! conc=1 n=10 t=7         time:   [33.342 µs 33.436 µs 33.554 µs]
//! conc=1 n=20 t=13        time:   [121.14 µs 123.02 µs 125.79 µs]
//! conc=1 n=50 t=33        time:   [753.15 µs 761.27 µs 773.15 µs]
//! conc=1 n=100 t=67       time:   [3.0440 ms 3.5310 ms 4.3212 ms]
//! conc=1 n=250 t=167      time:   [19.164 ms 19.226 ms 19.295 ms]
//! conc=1 n=500 t=333      time:   [79.523 ms 80.812 ms 82.645 ms]
//! ```
//!
//! ## Reshare Recovery (Contributor)
//!
//! ```txt
//! conc=1 n=5 t=3          time:   [241.59 µs 253.86 µs 263.90 µs]
//! conc=2 n=5 t=3          time:   [175.10 µs 178.24 µs 184.16 µs]
//! conc=4 n=5 t=3          time:   [134.88 µs 144.18 µs 151.21 µs]
//! conc=8 n=5 t=3          time:   [174.37 µs 184.76 µs 192.81 µs]
//! conc=1 n=10 t=7         time:   [1.4708 ms 1.5347 ms 1.6063 ms]
//! conc=2 n=10 t=7         time:   [827.54 µs 908.99 µs 986.19 µs]
//! conc=4 n=10 t=7         time:   [484.35 µs 504.77 µs 535.10 µs]
//! conc=8 n=10 t=7         time:   [508.29 µs 606.27 µs 699.82 µs]
//! conc=1 n=20 t=13        time:   [5.0725 ms 5.0793 ms 5.0857 ms]
//! conc=2 n=20 t=13        time:   [2.8032 ms 2.8116 ms 2.8222 ms]
//! conc=4 n=20 t=13        time:   [1.6856 ms 1.6892 ms 1.6938 ms]
//! conc=8 n=20 t=13        time:   [1.0313 ms 1.1604 ms 1.2300 ms]
//! conc=1 n=50 t=33        time:   [37.000 ms 37.248 ms 37.937 ms]
//! conc=2 n=50 t=33        time:   [19.346 ms 19.642 ms 20.312 ms]
//! conc=4 n=50 t=33        time:   [10.533 ms 10.567 ms 10.614 ms]
//! conc=8 n=50 t=33        time:   [6.3829 ms 6.4347 ms 6.4721 ms]
//! conc=1 n=100 t=67       time:   [174.30 ms 175.16 ms 176.05 ms]
//! conc=2 n=100 t=67       time:   [89.835 ms 90.204 ms 90.599 ms]
//! conc=4 n=100 t=67       time:   [46.736 ms 47.123 ms 47.531 ms]
//! conc=8 n=100 t=67       time:   [29.193 ms 29.519 ms 29.870 ms]
//! conc=1 n=250 t=167      time:   [1.4814 s 1.4927 s 1.5062 s]
//! conc=2 n=250 t=167      time:   [751.83 ms 762.08 ms 780.29 ms]
//! conc=4 n=250 t=167      time:   [394.18 ms 397.18 ms 400.52 ms]
//! conc=8 n=250 t=167      time:   [239.81 ms 245.78 ms 252.11 ms]
//! conc=1 n=500 t=333      time:   [6.9914 s 7.0182 s 7.0452 s]
//! conc=2 n=500 t=333      time:   [3.5483 s 3.5575 s 3.5670 s]
//! conc=4 n=500 t=333      time:   [1.8668 s 1.8851 s 1.9025 s]
//! conc=8 n=500 t=333      time:   [1.1176 s 1.1355 s 1.1539 s]
//! ```
//!
//! ## Partial Signature Aggregation
//!
//! ```txt
//! n=5 t=3                 time:   [126.85 µs 128.50 µs 130.67 µs]
//! n=10 t=7                time:   [378.70 µs 386.74 µs 397.13 µs]
//! n=20 t=13               time:   [764.59 µs 777.71 µs 796.76 µs]
//! n=50 t=33               time:   [2.1320 ms 2.1399 ms 2.1547 ms]
//! n=100 t=67              time:   [5.0113 ms 5.0155 ms 5.0203 ms]
//! n=250 t=167             time:   [16.922 ms 16.929 ms 16.937 ms]
//! n=500 t=333             time:   [37.642 ms 37.676 ms 37.729 ms]
//! ```
//! ## Signature Generation (Signing)
//!
//! ```txt
//! ns_len=9 msg_len=5      time:   [232.12 µs 233.63 µs 235.42 µs]
//! ```
//!
//! ## Signature Verification
//!
//! ```txt
//! ns_len=9 msg_len=5      time:   [980.92 µs 981.37 µs 981.88 µs]
//! ```
//!
//! ## Signature Aggregation (Same Public Key)
//!
//! ```txt
//! msgs=10                 time:   [11.731 µs 12.516 µs 13.316 µs]
//! msgs=100                time:   [117.02 µs 117.16 µs 117.37 µs]
//! msgs=1000               time:   [1.1751 ms 1.1777 ms 1.1803 ms]
//! msgs=10000              time:   [11.878 ms 11.966 ms 12.068 ms]
//! ```
//!
//! ## Aggregate Signature Verification (Same Public Key)
//!
//! ```txt
//! conc=1 msgs=10          time:   [1.9960 ms 2.0150 ms 2.0263 ms]
//! conc=2 msgs=10          time:   [1.3962 ms 1.3979 ms 1.3998 ms]
//! conc=4 msgs=10          time:   [1.1857 ms 1.1882 ms 1.1906 ms]
//! conc=8 msgs=10          time:   [1.1787 ms 1.1873 ms 1.2022 ms]
//! conc=16 msgs=10         time:   [1.3770 ms 1.3882 ms 1.4133 ms]
//! conc=1 msgs=100         time:   [12.687 ms 12.704 ms 12.723 ms]
//! conc=2 msgs=100         time:   [6.8790 ms 6.9518 ms 7.0950 ms]
//! conc=4 msgs=100         time:   [3.9784 ms 3.9912 ms 4.0085 ms]
//! conc=8 msgs=100         time:   [2.8804 ms 2.9236 ms 2.9558 ms]
//! conc=16 msgs=100        time:   [2.7870 ms 2.8007 ms 2.8139 ms]
//! conc=1 msgs=1000        time:   [119.06 ms 119.11 ms 119.17 ms]
//! conc=2 msgs=1000        time:   [61.170 ms 61.244 ms 61.332 ms]
//! conc=4 msgs=1000        time:   [31.822 ms 31.882 ms 31.948 ms]
//! conc=8 msgs=1000        time:   [19.635 ms 19.991 ms 20.547 ms]
//! conc=16 msgs=1000       time:   [16.950 ms 17.039 ms 17.126 ms]
//! conc=1 msgs=10000       time:   [1.1826 s 1.1905 s 1.2018 s]
//! conc=2 msgs=10000       time:   [603.82 ms 610.05 ms 618.48 ms]
//! conc=4 msgs=10000       time:   [309.44 ms 312.92 ms 318.01 ms]
//! conc=8 msgs=10000       time:   [187.57 ms 192.75 ms 198.37 ms]
//! conc=16 msgs=10000      time:   [158.16 ms 161.60 ms 165.44 ms]
//! conc=1 msgs=50000       time:   [5.9263 s 5.9377 s 5.9547 s]
//! conc=2 msgs=50000       time:   [3.0152 s 3.0266 s 3.0417 s]
//! conc=4 msgs=50000       time:   [1.5420 s 1.5458 s 1.5500 s]
//! conc=8 msgs=50000       time:   [925.32 ms 929.07 ms 933.83 ms]
//! conc=16 msgs=50000      time:   [769.73 ms 773.88 ms 777.97 ms]
//! ```

pub mod dkg;
pub mod primitives;
mod scheme;
pub use scheme::Bls12381;

#[cfg(test)]
mod tests {
    use super::*;
    use dkg::ops::generate_shares;
    use primitives::group::Private;
    use primitives::ops::{partial_aggregate, partial_sign, partial_verify, verify};
    use primitives::poly::public;
    use primitives::Error;

    #[test]
    fn test_partial_aggregate_signature() {
        let (n, t) = (5, 4);

        // Create the private key polynomial and evaluate it at `n`
        // points to generate the shares.
        //
        // If receiving a share from an untrusted party, the recipient
        // should verify the share is on the public polynomial.
        let (group, shares) = generate_shares(None, n, t);

        // Generate the partial signatures
        let namespace = b"test";
        let msg = b"hello";
        let partials = shares
            .iter()
            .map(|s| partial_sign(s, namespace, msg))
            .collect::<Vec<_>>();

        // Each partial sig can be partially verified against the public polynomial
        partials.iter().for_each(|partial| {
            partial_verify(&group, namespace, msg, partial).unwrap();
        });

        // Generate and verify the threshold sig
        let threshold_sig = partial_aggregate(t, partials).unwrap();
        let threshold_pub = public(&group);
        verify(&threshold_pub, namespace, msg, &threshold_sig).unwrap();
    }

    #[test]
    fn test_partial_aggregate_signature_bad_namespace() {
        let (n, t) = (5, 4);

        // Create the private key polynomial and evaluate it at `n`
        // points to generate the shares.
        //
        // If receiving a share from an untrusted party, the recipient
        // should verify the share is on the public polynomial.
        let (group, shares) = generate_shares(None, n, t);

        // Generate the partial signatures
        let namespace = b"test";
        let msg = b"hello";
        let partials = shares
            .iter()
            .map(|s| partial_sign(s, namespace, msg))
            .collect::<Vec<_>>();

        // Each partial sig can be partially verified against the public polynomial
        let namespace = b"bad";
        partials.iter().for_each(|partial| {
            assert!(matches!(
                partial_verify(&group, namespace, msg, partial).unwrap_err(),
                Error::InvalidSignature
            ));
        });

        // Generate and verify the threshold sig
        let threshold_sig = partial_aggregate(t, partials).unwrap();
        let threshold_pub = public(&group);
        assert!(matches!(
            verify(&threshold_pub, namespace, msg, &threshold_sig).unwrap_err(),
            Error::InvalidSignature
        ));
    }

    #[test]
    fn test_partial_aggregate_signature_insufficient() {
        let (n, t) = (5, 4);

        // Create the private key polynomial and evaluate it at `n`
        // points to generate the shares
        let (group, shares) = generate_shares(None, n, t);

        // Only take t-1 shares
        let shares = shares.into_iter().take(t as usize - 1).collect::<Vec<_>>();

        // Generate the partial signatures
        let namespace = b"test";
        let msg = b"hello";
        let partials = shares
            .iter()
            .map(|s| partial_sign(s, namespace, msg))
            .collect::<Vec<_>>();

        // Each partial sig can be partially verified against the public polynomial
        partials.iter().for_each(|partial| {
            partial_verify(&group, namespace, msg, partial).unwrap();
        });

        // Generate the threshold sig
        assert!(matches!(
            partial_aggregate(t, partials).unwrap_err(),
            Error::NotEnoughPartialSignatures(4, 3)
        ));
    }

    #[test]
    fn test_partial_aggregate_signature_insufficient_duplicates() {
        let (n, t) = (5, 4);

        // Create the private key polynomial and evaluate it at `n`
        // points to generate the shares
        let (group, shares) = generate_shares(None, n, t);

        // Only take t-1 shares
        let mut shares = shares.into_iter().take(t as usize - 1).collect::<Vec<_>>();
        shares.push(shares[0]);

        // Generate the partial signatures
        let namespace = b"test";
        let msg = b"hello";
        let partials = shares
            .iter()
            .map(|s| partial_sign(s, namespace, msg))
            .collect::<Vec<_>>();

        // Each partial sig can be partially verified against the public polynomial
        partials.iter().for_each(|partial| {
            partial_verify(&group, namespace, msg, partial).unwrap();
        });

        // Generate the threshold sig
        assert!(matches!(
            partial_aggregate(t, partials).unwrap_err(),
            Error::DuplicateEval,
        ));
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn test_partial_aggregate_signature_bad_share() {
        let (n, t) = (5, 4);

        // Create the private key polynomial and evaluate it at `n`
        // points to generate the shares
        let (group, mut shares) = generate_shares(None, n, t);

        // Corrupt a share
        let share = shares.get_mut(3).unwrap();
        share.private = Private::rand(&mut rand::thread_rng());

        // Generate the partial signatures
        let namespace = b"test";
        let msg = b"hello";
        let partials = shares
            .iter()
            .map(|s| partial_sign(s, namespace, msg))
            .collect::<Vec<_>>();

        // Each partial sig can be partially verified against the public polynomial
        partials.iter().for_each(|partial| {
            partial_verify(&group, namespace, msg, partial).unwrap();
        });

        // Generate and verify the threshold sig
        let threshold_sig = partial_aggregate(t, partials).unwrap();
        let threshold_pub = public(&group);
        verify(&threshold_pub, namespace, msg, &threshold_sig).unwrap();
    }
}
