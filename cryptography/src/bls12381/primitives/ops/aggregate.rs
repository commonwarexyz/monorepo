//! Aggregation operations for BLS12-381 signatures.
//!
//! This module provides functions for aggregating public keys and signatures,
//! as well as verifying aggregate signatures.
//!
//! # Security Considerations
//!
//! Some functions in this module are vulnerable to signature malleability attacks
//! when used incorrectly. See the documentation for each function for details.
//! Use [`batch`](super::batch) instead when you need to ensure each individual signature is valid.

use super::{
    super::{variant::Variant, Error},
    core::{hash_message, hash_message_namespace, verify_message},
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use commonware_math::algebra::Additive;
#[cfg(feature = "std")]
use rayon::{prelude::*, ThreadPoolBuilder};

/// Aggregates multiple public keys.
///
/// # Warning
///
/// This function assumes a group check was already performed on all `public_keys`,
/// that each `public_key` is unique, and that the caller has a Proof-of-Possession (PoP)
/// for each `public_key`. If any of these assumptions are violated, an attacker can
/// exploit this function to verify an incorrect aggregate signature.
pub fn aggregate_public_keys<'a, V, I>(public_keys: I) -> V::Public
where
    V: Variant,
    I: IntoIterator<Item = &'a V::Public>,
    V::Public: 'a,
{
    let mut p = V::Public::zero();
    for pk in public_keys {
        p += pk;
    }
    p
}

/// Aggregates multiple signatures.
///
/// # Warning
///
/// This function assumes a group check was already performed on each `signature` and
/// that each `signature` is unique. If any of these assumptions are violated, an attacker can
/// exploit this function to verify an incorrect aggregate signature.
pub fn aggregate_signatures<'a, V, I>(signatures: I) -> V::Signature
where
    V: Variant,
    I: IntoIterator<Item = &'a V::Signature>,
    V::Signature: 'a,
{
    let mut s = V::Signature::zero();
    for sig in signatures {
        s += sig;
    }
    s
}

/// Verifies the aggregate signature over a single message from multiple public keys.
///
/// # Warning
///
/// This function assumes the caller has performed a group check and collected a proof-of-possession
/// for all provided `public`. This function assumes a group check was already performed on the
/// `signature`. It is not safe to provide duplicate public keys.
pub fn aggregate_verify_multiple_public_keys<'a, V, I>(
    public: I,
    namespace: Option<&[u8]>,
    message: &[u8],
    signature: &V::Signature,
) -> Result<(), Error>
where
    V: Variant,
    I: IntoIterator<Item = &'a V::Public>,
    V::Public: 'a,
{
    // Aggregate public keys
    //
    // We can take advantage of the bilinearity property of pairings to aggregate public keys
    // that have all signed the same message (as long as all public keys are unique).
    let agg_public = aggregate_public_keys::<V, _>(public);

    // Verify the signature
    verify_message::<V>(&agg_public, namespace, message, signature)
}

/// Verifies an aggregate signature over multiple unique messages from a single public key.
///
/// Each entry is a tuple of (namespace, message). The signature must be the aggregate
/// of all individual signatures.
///
/// # Warning
///
/// This function is vulnerable to signature malleability when used with signatures
/// that were aggregated from different messages. An attacker can redistribute
/// signature components between messages while keeping the aggregate unchanged.
/// Use [`batch::verify_multiple_messages`](super::batch::verify_multiple_messages) instead when signatures are provided individually.
///
/// This function assumes a group check was already performed on `public` and `signature`.
/// It is not safe to provide an aggregate public key or to provide duplicate messages.
pub fn aggregate_verify_multiple_messages<'a, V, I>(
    public: &V::Public,
    messages: I,
    signature: &V::Signature,
    #[cfg_attr(not(feature = "std"), allow(unused_variables))] concurrency: usize,
) -> Result<(), Error>
where
    V: Variant,
    I: IntoIterator<Item = &'a (Option<&'a [u8]>, &'a [u8])> + Send + Sync,
    I::IntoIter: Send + Sync,
{
    #[cfg(not(feature = "std"))]
    let hm_sum = compute_hm_sum::<V, I>(messages);

    #[cfg(feature = "std")]
    let hm_sum = if concurrency == 1 {
        compute_hm_sum::<V, I>(messages)
    } else {
        let pool = ThreadPoolBuilder::new()
            .num_threads(concurrency)
            .build()
            .expect("Unable to build thread pool");

        pool.install(move || {
            messages
                .into_iter()
                .par_bridge()
                .map(|(namespace, msg)| {
                    namespace.as_ref().map_or_else(
                        || hash_message::<V>(V::MESSAGE, msg),
                        |namespace| hash_message_namespace::<V>(V::MESSAGE, namespace, msg),
                    )
                })
                .reduce(V::Signature::zero, |mut sum, hm| {
                    sum += &hm;
                    sum
                })
        })
    };

    V::verify(public, &hm_sum, signature)
}

/// Computes the sum over the hash of each message.
fn compute_hm_sum<'a, V, I>(messages: I) -> V::Signature
where
    V: Variant,
    I: IntoIterator<Item = &'a (Option<&'a [u8]>, &'a [u8])>,
{
    let mut hm_sum = V::Signature::zero();
    for (namespace, msg) in messages {
        let hm = namespace.as_ref().map_or_else(
            || hash_message::<V>(V::MESSAGE, msg),
            |namespace| hash_message_namespace::<V>(V::MESSAGE, namespace, msg),
        );
        hm_sum += &hm;
    }
    hm_sum
}
