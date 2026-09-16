use commonware_cryptography_bls::bls12381::{
    group::{G1, G2},
    scalar::Scalar,
};

pub const MESSAGE: &[u8] = b"BLS signature benchmark";
pub const MIN_PK_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
pub const MIN_SIG_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";

pub(super) struct GroupFixtures {
    pub(super) g1_left: [u8; 48],
    pub(super) g1_right: [u8; 48],
    pub(super) g2_left: [u8; 96],
    pub(super) g2_right: [u8; 96],
    pub(super) scalar: Scalar,
    pub(super) blst_scalar: [u8; 32],
}

pub(super) fn group_fixtures() -> GroupFixtures {
    let left = Scalar::from_u64(17);
    let right = Scalar::from_u64(29);
    let scalar = Scalar::from_u64(37);
    let mut blst_scalar = scalar.to_bytes();
    blst_scalar.reverse();
    GroupFixtures {
        g1_left: G1::generator().mul(&left).to_bytes(),
        g1_right: G1::generator().mul(&right).to_bytes(),
        g2_left: G2::generator().mul(&left).to_bytes(),
        g2_right: G2::generator().mul(&right).to_bytes(),
        scalar,
        blst_scalar,
    }
}

pub(super) fn blst_g1_decode(bytes: &[u8; 48]) -> blst::blst_p1 {
    let mut affine = blst::blst_p1_affine::default();
    let mut point = blst::blst_p1::default();
    // SAFETY: bytes has the compressed G1 size, and both outputs are valid writable points.
    unsafe {
        assert_eq!(
            blst::blst_p1_uncompress(&mut affine, bytes.as_ptr()),
            blst::BLST_ERROR::BLST_SUCCESS
        );
        assert!(blst::blst_p1_affine_in_g1(&affine));
        blst::blst_p1_from_affine(&mut point, &affine);
    }
    point
}

pub(super) fn blst_g2_decode(bytes: &[u8; 96]) -> blst::blst_p2 {
    let mut affine = blst::blst_p2_affine::default();
    let mut point = blst::blst_p2::default();
    // SAFETY: bytes has the compressed G2 size, and both outputs are valid writable points.
    unsafe {
        assert_eq!(
            blst::blst_p2_uncompress(&mut affine, bytes.as_ptr()),
            blst::BLST_ERROR::BLST_SUCCESS
        );
        assert!(blst::blst_p2_affine_in_g2(&affine));
        blst::blst_p2_from_affine(&mut point, &affine);
    }
    point
}

pub(super) fn blst_g1_encode(point: &blst::blst_p1) -> [u8; 48] {
    let mut encoded = [0; 48];
    // SAFETY: point is initialized and encoded has the compressed G1 size.
    unsafe { blst::blst_p1_compress(encoded.as_mut_ptr(), point) };
    encoded
}

pub(super) fn blst_g2_encode(point: &blst::blst_p2) -> [u8; 96] {
    let mut encoded = [0; 96];
    // SAFETY: point is initialized and encoded has the compressed G2 size.
    unsafe { blst::blst_p2_compress(encoded.as_mut_ptr(), point) };
    encoded
}
