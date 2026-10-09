use super::{PUBLIC_KEY_HEADER, PUBLIC_KEY_SIZE, SIGNATURE_HEADER, SIGNATURE_SIZE};
use fn_dsa_comm::codec::{modq_decode, modq_encode};

const DEGREE: usize = 512;
const MODULUS: u16 = 12289;
const SIGNATURE_PREFIX_SIZE: usize = 41;
const MAX_COEFFICIENT: u16 = 972;

pub(super) fn encode_signature(salt: &[u8; 40], s: &[i16; DEGREE], out: &mut [u8]) -> Option<()> {
    if out.len() != SIGNATURE_SIZE {
        return None;
    }
    let mut bit_len = 6 * DEGREE;
    for value in s {
        let magnitude = value.unsigned_abs();
        if magnitude > MAX_COEFFICIENT {
            return None;
        }
        bit_len += usize::from(magnitude >> 4);
    }
    if bit_len > (SIGNATURE_SIZE - SIGNATURE_PREFIX_SIZE) * 8 {
        return None;
    }

    out.fill(0);
    out[0] = SIGNATURE_HEADER;
    out[1..SIGNATURE_PREFIX_SIZE].copy_from_slice(salt);
    let body = &mut out[SIGNATURE_PREFIX_SIZE..];
    let mut position = 0;
    for value in s {
        let magnitude = value.unsigned_abs();
        body[position / 8] |= u8::from(*value < 0) << (7 - position % 8);
        position += 1;
        for shift in (0..4).rev() {
            body[position / 8] |= (((magnitude >> shift) & 1) as u8) << (7 - position % 8);
            position += 1;
        }
        position += usize::from(magnitude >> 4);
        body[position / 8] |= 1 << (7 - position % 8);
        position += 1;
    }
    Some(())
}

pub(super) fn decode_signature(raw: &[u8]) -> Option<([u8; 40], [i16; DEGREE])> {
    if raw.len() != SIGNATURE_SIZE || raw[0] != SIGNATURE_HEADER {
        return None;
    }
    let salt = raw[1..SIGNATURE_PREFIX_SIZE].try_into().ok()?;
    let body = &raw[SIGNATURE_PREFIX_SIZE..];
    let mut position = 0;
    let mut s = [0i16; DEGREE];
    for value in &mut s {
        if position + 5 > body.len() * 8 {
            return None;
        }
        let negative = (body[position / 8] >> (7 - position % 8)) & 1;
        position += 1;
        let mut magnitude = 0u16;
        for _ in 0..4 {
            magnitude =
                (magnitude << 1) | u16::from((body[position / 8] >> (7 - position % 8)) & 1);
            position += 1;
        }
        loop {
            if position == body.len() * 8 {
                return None;
            }
            let stop = (body[position / 8] >> (7 - position % 8)) & 1;
            position += 1;
            if stop != 0 {
                break;
            }
            magnitude += 16;
            if magnitude > MAX_COEFFICIENT {
                return None;
            }
        }
        if negative != 0 && magnitude == 0 {
            return None;
        }
        *value = if negative == 0 {
            magnitude as i16
        } else {
            -(magnitude as i16)
        };
    }

    if position % 8 != 0 && body[position / 8] & ((1 << (8 - position % 8)) - 1) != 0 {
        return None;
    }
    if body[position.div_ceil(8)..].iter().any(|byte| *byte != 0) {
        return None;
    }
    Some((salt, s))
}

pub(super) fn encode_public_key(h_ntt_external: &[u16; DEGREE]) -> [u8; PUBLIC_KEY_SIZE] {
    assert!(h_ntt_external.iter().all(|value| *value < MODULUS));
    let mut raw = [0u8; PUBLIC_KEY_SIZE];
    raw[0] = PUBLIC_KEY_HEADER;
    modq_encode(h_ntt_external, &mut raw[1..]);
    raw
}

pub(super) fn decode_public_key(raw: &[u8]) -> Option<[u16; DEGREE]> {
    if raw.len() != PUBLIC_KEY_SIZE || raw[0] != PUBLIC_KEY_HEADER {
        return None;
    }
    let mut h = [0u16; DEGREE];
    modq_decode(&raw[1..], &mut h)?;
    Some(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signature(s: &[i16; DEGREE]) -> [u8; SIGNATURE_SIZE] {
        let mut raw = [0u8; SIGNATURE_SIZE];
        encode_signature(&[0xA5; 40], s, &mut raw).unwrap();
        raw
    }

    #[test]
    fn zero_encoding() {
        let raw = signature(&[0; DEGREE]);
        assert_eq!(raw[0], 0xE2);
        assert_eq!(&raw[1..41], &[0xA5; 40]);
        for chunk in raw[41..425].as_chunks::<3>().0 {
            assert_eq!(chunk, &[0x04, 0x10, 0x41]);
        }
        assert!(raw[425..].iter().all(|byte| *byte == 0));
        assert_eq!(decode_signature(&raw), Some(([0xA5; 40], [0; DEGREE])));
    }

    #[test]
    fn every_coefficient_roundtrips() {
        let mut s = [0; DEGREE];
        for value in -972..=972 {
            s[0] = value;
            s[511] = -value;
            let raw = signature(&s);
            assert_eq!(decode_signature(&raw), Some(([0xA5; 40], s)));
        }
    }

    #[test]
    fn frame_boundary() {
        let mut s = [16; DEGREE];
        s[..184].fill(32);
        let raw = signature(&s);
        assert_eq!(raw[511] & 1, 1);
        assert_eq!(decode_signature(&raw), Some(([0xA5; 40], s)));

        s[184] = 32;
        let mut out = [0xA5; SIGNATURE_SIZE];
        assert_eq!(encode_signature(&[0; 40], &s, &mut out), None);
        assert_eq!(out, [0xA5; SIGNATURE_SIZE]);
    }

    #[test]
    fn rejects_malformed_signatures() {
        let valid = signature(&[0; DEGREE]);
        for len in 0..SIGNATURE_SIZE {
            assert!(decode_signature(&valid[..len]).is_none());
        }
        let mut oversized = [0; SIGNATURE_SIZE + 1];
        oversized[..SIGNATURE_SIZE].copy_from_slice(&valid);
        assert!(decode_signature(&oversized).is_none());

        let mut raw = valid;
        raw[0] = 0x39;
        assert!(decode_signature(&raw).is_none());
        raw = valid;
        raw[41] |= 0x80;
        assert!(decode_signature(&raw).is_none());
        raw = valid;
        raw[511] = 1;
        assert!(decode_signature(&raw).is_none());
        raw = valid;
        raw[41..].fill(0);
        assert!(decode_signature(&raw).is_none());

        let mut s = [0; DEGREE];
        s[0] = 972;
        raw = signature(&s);
        raw[41] |= 8;
        assert!(decode_signature(&raw).is_none());

        s[0] = 16;
        raw = signature(&s);
        raw[425] |= 0x40;
        assert!(decode_signature(&raw).is_none());
    }

    #[test]
    fn rejects_out_of_range_encoding() {
        for value in [973, -973, i16::MIN, i16::MAX] {
            let mut s = [0; DEGREE];
            s[0] = value;
            assert!(encode_signature(&[0; 40], &s, &mut [0; SIGNATURE_SIZE]).is_none());
        }
        assert!(encode_signature(&[0; 40], &[0; DEGREE], &mut [0; 511]).is_none());
        assert!(encode_signature(&[0; 40], &[0; DEGREE], &mut [0; 513]).is_none());
    }

    #[test]
    fn public_key_roundtrip_and_rejections() {
        let mut h = [0u16; DEGREE];
        for (i, value) in h.iter_mut().enumerate() {
            *value = ((i * 37) % usize::from(MODULUS)) as u16;
        }
        h[511] = MODULUS - 1;
        let valid = encode_public_key(&h);
        assert_eq!(decode_public_key(&valid), Some(h));
        for len in 0..PUBLIC_KEY_SIZE {
            assert!(decode_public_key(&valid[..len]).is_none());
        }
        let mut raw = valid;
        raw[0] = 9;
        assert!(decode_public_key(&raw).is_none());
        let mut raw = [0; PUBLIC_KEY_SIZE];
        raw[0] = PUBLIC_KEY_HEADER;
        raw[1] = 1;
        raw[2] = 0x30;
        assert!(decode_public_key(&raw).is_none());
        let mut oversized = [0; PUBLIC_KEY_SIZE + 1];
        oversized[..PUBLIC_KEY_SIZE].copy_from_slice(&valid);
        assert!(decode_public_key(&oversized).is_none());
    }
}
