// Copyright Supranational LLC
// Licensed under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0
//
// Isogeny constants adapted from blst 0.3.16's map_to_g1.c.

//! RFC 9380 BLS12381G1_XMD:SHA-256_SSWU_RO_.

use super::{Arithmetic, Curve, Fp, G1, MAX_LANES, Projective, Workload};
use crate::{
    fp::SQRT_EXPONENT,
    hash::{self, fp},
};
use alloc::vec::Vec;
use subtle::ConditionallySelectable;

// RFC 9380 Sections 8.8.1 and E.2, in ascending polynomial order.
const G1_A: Fp = fp([
    0x5cf4_2808_2d58_4c1d,
    0x9893_6f8d_a0e0_f97f,
    0xd8e8_981a_efd8_81ac,
    0xb0ea_9853_83ee_66a8,
    0x3d69_3a02_c96d_4982,
    0x0014_4698_a3b8_e943,
]);
const G1_B: Fp = fp([
    0xd1cc_48e9_8e17_2be0,
    0x5a23_215a_316c_eaa5,
    0xa0b9_c14f_cef3_5ef5,
    0x2016_c1f0_f24f_4070,
    0x018b_12e8_753e_ee3b,
    0x12e2_908d_1168_8030,
]);
const G1_Z: Fp = fp([
    0x0000_0000_0000_000b,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
]);

const G1_X_NUM: &[Fp] = &[
    fp([
        0xaeac_1662_7346_49b7,
        0x5610_c2d5_f2e6_2d6e,
        0xf262_7b56_cdb4_e2c8,
        0x6b30_3e88_a2d7_005f,
        0xb809_101d_d998_1585,
        0x11a0_5f2b_1e83_3340,
    ]),
    fp([
        0xe834_eef1_b3cb_83bb,
        0x4838_f2a6_f318_c356,
        0xf565_e33c_70d1_e86b,
        0x7c17_e75b_2f6a_8417,
        0x0588_bab2_2147_a81c,
        0x1729_4ed3_e943_ab2f,
    ]),
    fp([
        0xe017_9f9d_ac9e_dcb0,
        0x958c_3e3d_2a09_729f,
        0x6878_e501_ec68_e25c,
        0xce03_2473_2959_83e5,
        0x1d10_48c5_d10a_9a1b,
        0x0d54_005d_b976_78ec,
    ]),
    fp([
        0xc5b3_8864_1d9b_6861,
        0x5336_e25c_e310_7193,
        0xf1b3_3289_f1b3_3083,
        0xd7f5_e465_6a8d_bf25,
        0x4e06_09d3_07e5_5412,
        0x1778_e716_6fcc_6db7,
    ]),
    fp([
        0x5115_4ce9_ac88_95d9,
        0x985a_286f_301e_77c4,
        0x086e_eb65_982f_ac18,
        0x99db_995a_1257_fb3f,
        0x6642_b4b3_e411_8e54,
        0x0e99_726a_3199_f443,
    ]),
    fp([
        0xcd13_c1c6_6f65_2983,
        0xa087_0d2d_cae7_3d19,
        0x9ed3_ab90_97e6_8f90,
        0xdb3c_b17d_d952_799b,
        0x01d1_201b_f7a7_4ab5,
        0x1630_c325_0d73_13ff,
    ]),
    fp([
        0xddd7_f225_a139_ed84,
        0x8da2_5128_c105_2eca,
        0x9008_e218_f9c8_6b2a,
        0xb115_8626_4f0f_8ce1,
        0x6a37_26c3_8ae6_52bf,
        0x0d6e_d655_3fe4_4d29,
    ]),
    fp([
        0x9ccb_5618_e3f0_c88e,
        0x39b7_c8f8_c8f4_75af,
        0xa682_c62e_f0f2_7533,
        0x356d_e5ab_275b_4db1,
        0xe874_3884_d111_7e53,
        0x17b8_1e77_01ab_dbe2,
    ]),
    fp([
        0x6d71_986a_8497_e317,
        0x4fa2_95f2_96b7_4e95,
        0xa2c5_96c9_28c5_d1de,
        0xc43b_756c_e79f_5574,
        0x7b90_b335_63be_990d,
        0x080d_3cf1_f9a7_8fc4,
    ]),
    fp([
        0x7f24_1067_be39_0c9e,
        0xa319_0b2e_dc03_2779,
        0x6763_14ba_f4bb_1b7f,
        0xdd2e_cb80_3a0c_5c99,
        0x2e0c_3751_5d13_8f22,
        0x169b_1f8e_1bcf_a7c4,
    ]),
    fp([
        0xca67_df3f_1605_fb7b,
        0xf69b_771f_8c28_5dec,
        0xd50a_f360_03b1_4866,
        0xfa7d_ccdd_e678_7f96,
        0x72d8_ec09_d256_5b0d,
        0x1032_1da0_79ce_07e2,
    ]),
    fp([
        0xa9c8_ba2e_8ba2_d229,
        0xc24b_1b80_b64d_391f,
        0x23c0_bf1b_c24c_6b68,
        0x31d7_9d7e_22c8_37bc,
        0xbd1e_9623_81ed_ee3d,
        0x06e0_8c24_8e26_0e70,
    ]),
];
const G1_X_DEN: &[Fp] = &[
    fp([
        0x993c_f9fa_40d2_1b1c,
        0xb558_d681_be34_3df8,
        0x9c95_8861_7fc8_ac62,
        0x01d5_ef4b_a35b_48ba,
        0x18b2_e62f_4bd3_fa6f,
        0x08ca_8d54_8cff_19ae,
    ]),
    fp([
        0xe5c8_276e_c82b_3bff,
        0x13da_a884_6cb0_26e9,
        0x0126_c258_8c48_bf57,
        0x7041_e8ca_0cf0_800c,
        0x48b4_7112_98e5_3636,
        0x1256_1a5d_eb55_9c43,
    ]),
    fp([
        0xfcc2_39ba_5cb8_3e19,
        0xd6a3_d096_7c94_fedc,
        0xfca6_4e00_b11a_ceac,
        0x6f89_416f_5a71_8cd1,
        0x8137_e629_bff2_991f,
        0x0b29_62fe_57a3_225e,
    ]),
    fp([
        0x130d_e893_8dc6_2cd8,
        0x4976_d524_3eec_f5c4,
        0x54cc_a8ab_c28d_6fd0,
        0x5b08_243f_16b1_6551,
        0xc83a_afef_7c40_eb54,
        0x0342_5581_a58a_e2fe,
    ]),
    fp([
        0x539d_395b_3532_a21e,
        0x9bd2_9ba8_1f35_781d,
        0x8d6b_44e8_33b3_06da,
        0xffdf_c759_a120_62bb,
        0x0a6f_1d5f_43e7_a07d,
        0x13a8_e162_0229_14a8,
    ]),
    fp([
        0xc02d_f9a2_9f63_04a5,
        0x7400_d24b_c422_8f11,
        0x0a43_bcef_24b8_982f,
        0x3957_35e9_ce9c_ad4d,
        0x5539_0f7f_0506_c6e9,
        0x0e73_55f8_e4e6_67b9,
    ]),
    fp([
        0xec25_7449_6ee8_4a3a,
        0xea73_b353_8f0d_e06c,
        0x4e2e_0730_62ae_de9c,
        0x570f_5799_af53_a189,
        0x0f3e_0c63_e059_6721,
        0x0772_caac_f169_3619,
    ]),
    fp([
        0x11f7_d99b_bdcc_5a5e,
        0x0fa5_b948_9d11_e2d3,
        0x1996_e1cd_f982_2c58,
        0x6e7f_63c2_1bca_68a8,
        0x30b3_f5b0_74cf_0199,
        0x14a7_ac2a_9d64_a8b2,
    ]),
    fp([
        0x4776_ec3a_79a1_d641,
        0x0382_6692_abba_4370,
        0x7410_0da6_7f39_8835,
        0xe07f_8d1d_7161_366b,
        0x5e92_0b3d_afc7_a3cc,
        0x0a10_ecf6_ada5_4f82,
    ]),
    fp([
        0x2d63_84d1_68ec_dd0a,
        0x9317_4e4b_4b78_6500,
        0x76df_5339_78f3_1c15,
        0xf682_b4ee_96f7_d037,
        0x476d_6e3e_b3a5_6680,
        0x095f_c13a_b9e9_2ad4,
    ]),
    fp([
        0x0000_0000_0000_0001,
        0x0000_0000_0000_0000,
        0x0000_0000_0000_0000,
        0x0000_0000_0000_0000,
        0x0000_0000_0000_0000,
        0x0000_0000_0000_0000,
    ]),
];
const G1_Y_NUM: &[Fp] = &[
    fp([
        0xbe98_4571_9707_bb33,
        0xcd0c_7aee_9b3b_a3c2,
        0x2b52_af6c_9565_43d3,
        0x11ad_138e_48a8_6952,
        0x259d_1f09_4980_dcfa,
        0x090d_97c8_1ba2_4ee0,
    ]),
    fp([
        0xe097_e75a_2e41_c696,
        0xd6c5_6711_962f_a8bf,
        0x0f90_6343_eb67_ad34,
        0x1223_e96c_254f_383d,
        0xd510_36d7_76fb_4683,
        0x1349_96a1_04ee_5811,
    ]),
    fp([
        0xb8df_e240_c72d_e1f6,
        0xd26d_5216_28b0_0523,
        0xc344_be4b_9140_0da7,
        0x2552_e2d6_58a3_1ce2,
        0xf4a3_84c8_6a3b_4994,
        0x00cc_786b_aa96_6e66,
    ]),
    fp([
        0xa635_5c77_b0e5_f4cb,
        0xde40_5aba_9ec6_1dec,
        0x09e4_a3ec_0325_1cf9,
        0xd42a_a7b9_0eeb_791c,
        0x7898_751a_d874_6757,
        0x01f8_6376_e898_1c21,
    ]),
    fp([
        0x41b6_daec_f2e8_fedb,
        0x2ee7_f8dc_0990_40a8,
        0x7983_3fd2_2135_1adc,
        0x1955_36fb_e3ce_50b8,
        0x5caf_4fe2_a215_29c4,
        0x08cc_03fd_efe0_ff13,
    ]),
    fp([
        0x99b2_3ab1_3633_a5f0,
        0x203f_6326_c95a_8072,
        0x7650_5c3d_3ad5_544e,
        0x74a7_d0d4_afad_b7bd,
        0x2211_e11d_b8f0_a6a0,
        0x1660_3fca_4063_4b6a,
    ]),
    fp([
        0xc961_f885_5fe9_d6f2,
        0x47a8_7ac2_460f_415e,
        0x5231_413c_4d63_4f37,
        0xe75b_b8ca_2be1_84cb,
        0xb2c9_77d0_2779_6b3c,
        0x04ab_0b9b_cfac_1bbc,
    ]),
    fp([
        0xa15e_4ca3_1870_fb29,
        0x42f6_4550_fedf_e935,
        0xfd03_8da6_c26c_8426,
        0x170a_05bf_e3bd_d81f,
        0xde99_26bd_2ca6_c674,
        0x0987_c8d5_333a_b86f,
    ]),
    fp([
        0x6037_0e57_7bdb_a587,
        0x69d6_5201_c786_07a3,
        0x1e8b_6e6a_1f20_cabe,
        0x8f3a_bd16_679d_c26c,
        0xe88c_9e22_1e4d_a1bb,
        0x09fc_4018_bd96_684b,
    ]),
    fp([
        0x2baf_aaeb_ca73_1c30,
        0x9b3f_7055_dd4e_ba6f,
        0x0698_5e7e_d1e4_d43b,
        0xc42a_0ca7_915a_f6fe,
        0x223a_bde7_ada1_4a23,
        0x0e1b_ba7a_1186_bdb5,
    ]),
    fp([
        0xe813_711a_d011_c132,
        0x31bf_3a5c_ce3f_bafc,
        0xd118_3e41_6389_e610,
        0xcd2f_cbcb_6caf_493f,
        0x0dfd_0b8f_1d43_fb93,
        0x1971_3e47_937c_d1be,
    ]),
    fp([
        0xce07_c8a4_d007_4d8e,
        0x49d9_cdf4_1b44_d606,
        0x2e6b_fe7f_911f_6432,
        0x5235_59b8_aaf0_c246,
        0xb918_c143_fed2_edcc,
        0x18b4_6a90_8f36_f6de,
    ]),
    fp([
        0x0d4c_04f0_0b97_1ef8,
        0x06c8_51c1_9192_11f2,
        0xc027_10e8_07b4_633f,
        0x7aa7_b12a_3426_b08e,
        0xd155_0960_04f5_3f44,
        0x0b18_2cac_101b_9399,
    ]),
    fp([
        0x42d9_d3f5_db98_0133,
        0xc6cf_90ad_1c23_2a64,
        0x13e6_632d_3c40_659c,
        0x757b_3b08_0d4c_1580,
        0x72fc_00ae_7be3_15dc,
        0x0245_a394_ad1e_ca9b,
    ]),
    fp([
        0x866b_1e71_5475_224b,
        0x6ba1_049b_6579_afb7,
        0xd9ab_0f5d_396a_7ce4,
        0x5e67_3d81_d7e8_6568,
        0x02a1_59f7_48c4_a3fc,
        0x05c1_2964_5e44_cf11,
    ]),
    fp([
        0x04b4_56be_69c8_b604,
        0xb665_027e_fec0_1c77,
        0x57ad_d4fa_95af_01b2,
        0xcb18_1d8f_8496_5a39,
        0x4ea5_0b3b_42df_2eb5,
        0x15e6_be4e_990f_03ce,
    ]),
];
const G1_Y_DEN: &[Fp] = &[
    fp([
        0x0147_9253_b036_63c1,
        0x07f3_688e_f60c_206d,
        0xeec3_232b_5be7_2e7a,
        0x601a_6de5_7898_0be6,
        0x5218_1140_fad0_eae9,
        0x1611_2c4c_3a9c_98b2,
    ]),
    fp([
        0x32f6_102c_2e49_a03d,
        0x78a4_2607_6352_9e35,
        0xa4a1_0356_f453_e01f,
        0x85c8_4ff7_31c4_d59c,
        0x1a0c_bd6c_43c3_48b8,
        0x1962_d75c_2381_201e,
    ]),
    fp([
        0x1e25_38b5_3dbf_67f2,
        0xa675_7cd6_36f9_6f89,
        0x0c35_a5dd_279c_d2ec,
        0x78c4_8555_51ae_7f31,
        0x6faa_ae7d_6e8e_b157,
        0x058d_f330_6640_da27,
    ]),
    fp([
        0xa8d2_6d98_445f_5416,
        0x7273_64f2_c282_97ad,
        0x123d_a489_e726_af41,
        0xd115_c5db_ddbc_d30e,
        0xf20d_23bf_89ed_b4d1,
        0x16b7_d288_798e_5395,
    ]),
    fp([
        0xda39_1423_11a5_001d,
        0xa20b_15dc_0fd2_eded,
        0x542e_da0f_c9de_c916,
        0xc6d1_9c9f_0f69_bbb0,
        0xb00c_c912_f822_8ddc,
        0x0be0_e079_545f_43e4,
    ]),
    fp([
        0x02c6_477f_aaf9_b7ac,
        0x49f3_8db9_dfa9_cce2,
        0xc5ec_d87b_6f0f_5a64,
        0xb701_52c6_5550_d881,
        0x9fb2_66ea_ac78_3182,
        0x08d9_e529_7186_db2d,
    ]),
    fp([
        0x3d1a_1399_126a_775c,
        0xd5fa_9c01_a58b_1fb9,
        0x5dd3_65bc_400a_0051,
        0x5eec_fdfa_8d0c_f8ef,
        0xc3ba_8734_ace9_824b,
        0x1660_07c0_8a99_db2f,
    ]),
    fp([
        0x60ee_415a_1581_2ed9,
        0xb920_f5b0_0801_dee4,
        0xfeb3_4fd2_0635_7132,
        0xe5a4_375e_fa1f_4fd7,
        0x03bc_ddfa_bba6_ff6e,
        0x16a3_ef08_be3e_a7ea,
    ]),
    fp([
        0x6b23_3d9d_5553_5d4a,
        0x52cf_e2f7_bb92_4883,
        0xabc5_750c_4bf3_9b48,
        0xf9fb_0ce4_c6af_5920,
        0x1a1b_e54f_d1d7_4cc4,
        0x1866_c8ed_336c_6123,
    ]),
    fp([
        0x346e_f48b_b891_3f55,
        0xc738_5ea3_d529_b35e,
        0x5308_592e_7ea7_d4fb,
        0x3216_f763_e13d_87bb,
        0xea82_0597_d94a_8490,
        0x167a_55cd_a70a_6e1c,
    ]),
    fp([
        0x00f8_b49c_ba8f_6aa8,
        0x71a5_c29f_4f83_0604,
        0x0e59_1b36_e636_a5c8,
        0x9c6d_d039_bb61_a629,
        0x48f0_10a0_1ad2_911d,
        0x04d2_f259_eea4_05bd,
    ]),
    fp([
        0x9684_b529_e256_1092,
        0x16f9_6898_6f7e_bbea,
        0x8c0f_9a88_cea7_9135,
        0x7f94_ff8a_efce_42d2,
        0xf585_2c1e_48c5_0c47,
        0x0acc_bb67_481d_033f,
    ]),
    fp([
        0x1e99_b138_5733_45cc,
        0x9300_0763_e3b9_0ac1,
        0x7d5c_eef9_a00d_9b86,
        0x5433_46d9_8adf_0226,
        0xc361_3144_b45f_1496,
        0x0ad6_b951_4c76_7fe3,
    ]),
    fp([
        0xd1fa_dc13_26ed_06f7,
        0x4205_17bd_8714_cc80,
        0xcb74_8df2_7942_480e,
        0xbf56_5b94_e729_27c1,
        0x628b_dd0d_53cd_76f2,
        0x0266_0400_eb2e_4f3b,
    ]),
    fp([
        0x4415_473a_1d63_4b8f,
        0x5ca2_f570_f134_9780,
        0x324e_fcd6_356c_aa20,
        0x71c4_0f65_e273_b853,
        0x6b24_255e_0d78_19c1,
        0x0e0f_a1d8_16dd_c03e,
    ]),
    fp([
        0x0000_0000_0000_0001,
        0x0000_0000_0000_0000,
        0x0000_0000_0000_0000,
        0x0000_0000_0000_0000,
        0x0000_0000_0000_0000,
        0x0000_0000_0000_0000,
    ]),
];

/// (p - 3) / 4 for sqrt_ratio_3mod4 (RFC 9380, F.2.1.2).
const ROOT_EXPONENT: [u64; 6] = {
    let mut words = SQRT_EXPONENT;
    words[0] -= 1;
    words
};

/// sqrt(-Z); either root gives the same map after the sign correction.
const SQRT_MINUS_Z: Fp = Fp::from_u64(11).neg().pow(&SQRT_EXPONENT);

/// Hashes a message to two base-field elements (RFC 9380, 5.2).
fn hash_to_field(dst: &[u8], message: &[u8]) -> [Fp; 2] {
    hash::hash_to_field::<2, 128>(dst, message)
}

/// Maps to E' in homogeneous coordinates with one exponentiation per lane.
#[cfg_attr(not(debug_assertions), inline(always))]
fn map_to_curve<F: Arithmetic<Scalar = Fp>>(
    curve: &Curve<F>,
    u: F::Element,
) -> Projective<F::Element> {
    let f = curve.field;
    let hash::Swu {
        zuu,
        x1,
        x2,
        denominator,
        d3,
        numerator,
    } = hash::swu(curve, u, G1_A, G1_B, G1_Z);

    // sqrt_ratio_3mod4(numerator, d3), RFC 9380 F.2.1.2.
    let uv = f.mul(numerator, d3);
    let root = f.pow(f.mul(f.square(d3), uv), &ROOT_EXPONENT);
    let y1 = f.mul(root, uv);
    let check = f.mul(f.square(y1), d3);
    let y2 = f.mul(f.mul(f.mul(zuu, u), y1), f.constant(SQRT_MINUS_Z));
    let mut numerators = [Fp::ZERO; MAX_LANES];
    let mut checks = [Fp::ZERO; MAX_LANES];
    let mut us = [Fp::ZERO; MAX_LANES];
    let mut xs = [Fp::ZERO; MAX_LANES];
    let mut x2s = [Fp::ZERO; MAX_LANES];
    let mut ys = [Fp::ZERO; MAX_LANES];
    let mut y2s = [Fp::ZERO; MAX_LANES];
    f.store(numerator, &mut numerators);
    f.store(check, &mut checks);
    f.store(u, &mut us);
    f.store(x1, &mut xs);
    f.store(x2, &mut x2s);
    f.store(y1, &mut ys);
    f.store(y2, &mut y2s);
    for lane in 0..F::LANES {
        let square = subtle::ConstantTimeEq::ct_eq(&checks[lane], &numerators[lane]);
        xs[lane] = Fp::conditional_select(&x2s[lane], &xs[lane], square);
        let y = Fp::conditional_select(&y2s[lane], &ys[lane], square);
        ys[lane] = Fp::conditional_select(&y, &y.neg(), y.is_odd() ^ us[lane].is_odd());
    }
    Projective {
        x: f.load(&xs, Fp::ZERO),
        y: f.mul(f.load(&ys, Fp::ZERO), denominator),
        z: denominator,
    }
}

/// Applies the 11-isogeny, preserving homogeneous coordinates without an inversion.
#[cfg_attr(not(debug_assertions), inline(always))]
fn isogeny<F: Arithmetic<Scalar = Fp>>(
    curve: &Curve<F>,
    p: Projective<F::Element>,
) -> Projective<F::Element> {
    hash::isogeny(curve, p, G1_X_NUM, G1_X_DEN, G1_Y_NUM, G1_Y_DEN)
}

/// Multiplies by the suite's effective cofactor.
#[cfg_attr(not(debug_assertions), inline(always))]
fn clear_cofactor<F: Arithmetic<Scalar = Fp>>(
    curve: &Curve<F>,
    point: Projective<F::Element>,
) -> Projective<F::Element> {
    curve.mul_public(point, &[0xd201_0000_0001_0001])
}

/// Hashes one independent message per field lane.
#[derive(Clone, Copy)]
pub(super) struct HashToCurve<'a> {
    pub dst: &'a [u8],
    pub messages: &'a [&'a [u8]],
}

impl Workload<G1> for HashToCurve<'_> {
    type Output = Vec<G1>;

    fn parallel(&self) -> bool {
        self.messages.len() > 1
    }

    #[inline(always)]
    fn run<F: Arithmetic<Scalar = Fp>>(self, curve: &Curve<F>) -> Vec<G1> {
        let f = curve.field;
        let mut output = Vec::with_capacity(self.messages.len());
        for messages in self.messages.chunks(F::LANES) {
            let mut u0 = [Fp::ZERO; MAX_LANES];
            let mut u1 = [Fp::ZERO; MAX_LANES];
            for (lane, message) in messages.iter().enumerate() {
                [u0[lane], u1[lane]] = hash_to_field(self.dst, message);
            }
            let p = isogeny(curve, map_to_curve(curve, f.load(&u0, Fp::ZERO)));
            let q = isogeny(curve, map_to_curve(curve, f.load(&u1, Fp::ZERO)));
            let point = clear_cofactor(curve, curve.add(p, q));
            let mut points = [G1::IDENTITY.0; MAX_LANES];
            curve.store(point, &mut points);
            for point in &points[..messages.len()] {
                output.push(G1(*point));
            }
        }
        output
    }
}

#[cfg(test)]
mod tests;
