//! Collision-free marker names for protected source fragments.

pub(crate) fn unique_prefix(source: &str, kind: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in source.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let mut prefix = format!("__commonware_fmt_{kind}_{}_{hash:x}_", source.len());
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
