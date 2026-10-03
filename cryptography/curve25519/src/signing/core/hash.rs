//! SHA-512 over up to [`LANES`] messages per call.

#[cfg(all(target_arch = "x86_64", any(feature = "std", test)))]
mod avx512;

/// Messages hashed per [`digest`] call.
pub(super) const LANES: usize = 8;

/// Returns `SHA-512(parts[0] || parts[1] || parts[2])` for each `parts` in `messages`, in order,
/// with the best implementation this CPU supports. Entries past `messages.len()` are zero.
///
/// # Panics
///
/// Panics if `messages` holds more than [`LANES`] messages.
pub(super) fn digest(messages: &[[&[u8]; 3]]) -> [[u8; 64]; LANES] {
    assert!(messages.len() <= LANES, "at most {LANES} messages");
    #[cfg(all(target_arch = "x86_64", any(feature = "std", test)))]
    if let Some(hasher) = avx512::Hasher::new() {
        return hasher.digest(messages);
    }
    portable(messages)
}

/// [`digest`], one message at a time.
fn portable(messages: &[[&[u8]; 3]]) -> [[u8; 64]; LANES] {
    let mut out = [[0u8; 64]; LANES];
    for (digest, parts) in out.iter_mut().zip(messages) {
        *digest = super::sha512(parts);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::test_rng;
    use rand_core::Rng;

    /// Checks `hash` against [`super::super::sha512`] for every message length in `0..=300`, and
    /// two longer lengths, in every lane, with random split points, random lengths in the other
    /// lanes, and every message count up to [`LANES`].
    fn check(hash: impl Fn(&[[&[u8]; 3]]) -> [[u8; 64]; LANES]) {
        assert_eq!(hash(&[]), [[0u8; 64]; LANES]);
        let mut rng = test_rng();
        let mut below = |n: usize| (rng.next_u64() % n as u64) as usize;
        for len in (0..=300).chain([1000, 4113]) {
            for target in 0..LANES {
                let count = (len % (LANES + 1)).max(target + 1);
                let messages: Vec<Vec<u8>> = (0..count)
                    .map(|lane| {
                        let len = if lane == target { len } else { below(301) };
                        (0..len).map(|_| below(256) as u8).collect()
                    })
                    .collect();
                let splits: Vec<[&[u8]; 3]> = messages
                    .iter()
                    .map(|message| {
                        let x = below(message.len() + 1);
                        let y = below(message.len() + 1);
                        let (x, y) = (x.min(y), x.max(y));
                        [&message[..x], &message[x..y], &message[y..]]
                    })
                    .collect();
                let digests = hash(&splits);
                for (lane, digest) in digests.iter().enumerate() {
                    let expected = messages
                        .get(lane)
                        .map_or([0u8; 64], |message| super::super::sha512(&[message]));
                    assert_eq!(
                        digest, &expected,
                        "length {len}, lane {lane}, count {count}"
                    );
                }
            }
        }
    }

    /// The fallback used where the AVX-512 hasher is unavailable.
    #[test]
    fn portable_matches_sha512() {
        check(portable);
    }

    /// The runtime-dispatched path.
    #[test]
    fn digest_matches_sha512() {
        check(digest);
    }

    /// The AVX-512 hasher, on CPUs that support it.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn avx512_matches_sha512() {
        if let Some(hasher) = avx512::Hasher::new() {
            check(|messages| hasher.digest(messages));
        }
    }

    /// More than [`LANES`] messages violates the caller contract.
    #[test]
    #[should_panic(expected = "at most 8 messages")]
    fn digest_rejects_too_many_messages() {
        let parts: [&[u8]; 3] = [&[], &[], &[]];
        digest(&[parts; LANES + 1]);
    }
}
