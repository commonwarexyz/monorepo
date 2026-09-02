//! Collision-free marker names for protected source fragments.
//!
//! Formatters temporarily replace source that another formatting pass must not
//! interpret. This module constructs deterministic marker prefixes that cannot be
//! confused with text already present in the fragment.

/// Returns a deterministic marker prefix that does not occur in `source`.
///
/// `kind` identifies the marker's owner in diagnostic and intermediate text. A
/// caller may safely append a per-marker suffix because every resulting marker
/// still contains the absent prefix.
pub(crate) fn unique_prefix(source: &str, kind: &str) -> String {
    // The hash produces a compact, reproducible candidate. The absence check below,
    // rather than the hash, establishes the collision invariant.
    let mut hash = 0xcbf29ce484222325u64;
    for byte in source.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let mut prefix = format!("__commonware_fmt_{kind}_{hash:016x}_");
    // There is no retry limit because adversarial source may contain any finite
    // sequence of candidate prefixes.
    while source.contains(&prefix) {
        prefix.push('_');
    }
    prefix
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extends_a_colliding_prefix_without_a_nonce_limit() {
        let source = "value";
        let prefix = unique_prefix(source, "nested");
        let colliding = format!("{source} {prefix}");
        let resolved = unique_prefix(&colliding, "nested");

        assert!(!colliding.contains(&resolved));
    }
}
