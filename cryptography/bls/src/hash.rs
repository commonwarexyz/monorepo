//! SHA-256 message expansion shared by the curve families.

use sha2::{Digest, Sha256};

pub(crate) fn expand_message_xmd<const N: usize>(msg: &[u8], dst: &[u8]) -> [u8; N] {
    debug_assert!(N <= 255 * 32);
    let oversized;
    let dst = if dst.len() > 255 {
        oversized = Sha256::new()
            .chain_update(b"H2C-OVERSIZE-DST-")
            .chain_update(dst)
            .finalize();
        oversized.as_slice()
    } else {
        dst
    };

    let mut b0_hasher = Sha256::new();
    b0_hasher.update([0; 64]);
    b0_hasher.update(msg);
    b0_hasher.update((N as u16).to_be_bytes());
    b0_hasher.update([0]);
    b0_hasher.update(dst);
    b0_hasher.update([dst.len() as u8]);
    let b0 = b0_hasher.finalize();

    let mut output = [0; N];
    let mut previous = Sha256::new()
        .chain_update(b0)
        .chain_update([1])
        .chain_update(dst)
        .chain_update([dst.len() as u8])
        .finalize();
    let first = N.min(32);
    output[..first].copy_from_slice(&previous[..first]);

    for index in 2..=N.div_ceil(32) {
        let xor = core::array::from_fn::<_, 32, _>(|i| b0[i] ^ previous[i]);
        previous = Sha256::new()
            .chain_update(xor)
            .chain_update([index as u8])
            .chain_update(dst)
            .chain_update([dst.len() as u8])
            .finalize();
        let start = (index - 1) * 32;
        let end = (start + 32).min(N);
        output[start..end].copy_from_slice(&previous[..end - start]);
    }
    output
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::*;

    fn check_xmd<const N: usize>(msg: &[u8], dst: &[u8]) {
        let mut expected = [0; N];
        // SAFETY: Every pointer covers its stated length, and expected has N writable bytes.
        unsafe {
            blst::blst_expand_message_xmd(
                expected.as_mut_ptr(),
                N,
                msg.as_ptr(),
                msg.len(),
                dst.as_ptr(),
                dst.len(),
            );
        }
        assert_eq!(expand_message_xmd::<N>(msg, dst), expected);
    }

    #[test]
    fn output_lengths_and_dst_boundaries_match_blst() {
        for length in [0, 255, 256, 1024] {
            let dst: Vec<_> = (0..length).map(|i| i as u8).collect();
            check_xmd::<48>(b"", &dst);
            check_xmd::<128>(b"xmd", &dst);
            check_xmd::<256>(b"xmd", &dst);
        }
    }
}
