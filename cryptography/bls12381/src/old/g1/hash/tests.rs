//! Tests for hashing to G1.

use super::*;
use crate::old::g1::{
    Run, first,
    tests::{every_context, from_blst},
};
use arbitrary::Unstructured;
use commonware_invariants::minifuzz;
use commonware_simd::test_dispatch;

const RFC_DST: &[u8] = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";

/// Hashes with blst, as the reference implementation.
fn blst_hash(dst: &[u8], message: &[u8]) -> G1 {
    let mut out = blst::blst_p1::default();
    // SAFETY: valid pointers and lengths; a null augmentation has length zero.
    unsafe {
        blst::blst_hash_to_g1(
            &mut out,
            message.as_ptr(),
            message.len(),
            dst.as_ptr(),
            dst.len(),
            core::ptr::null(),
            0,
        )
    };
    from_blst(&out)
}

fn fp(s: &str) -> Fp {
    let mut out = [0u8; 48];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    Fp::from_bytes(&out).expect("canonical")
}

/// The messages of RFC 9380 appendix J.9.1.
fn rfc_messages() -> [Vec<u8>; 5] {
    [
        Vec::new(),
        b"abc".to_vec(),
        b"abcdef0123456789".to_vec(),
        [b"q128_".as_slice(), &[b'q'; 128]].concat(),
        [b"a512_".as_slice(), &[b'a'; 512]].concat(),
    ]
}

/// (P.x, P.y, u[0], u[1]) for each message of RFC 9380 appendix J.9.1.
const RFC_VECTORS: [(&str, &str, &str, &str); 5] = [
    (
        "052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1",
        "08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265",
        "0ba14bd907ad64a016293ee7c2d276b8eae71f25a4b941eece7b0d89f17f75cb3ae5438a614fb61d6835ad59f29c564f",
        "019b9bd7979f12657976de2884c7cce192b82c177c80e0ec604436a7f538d231552f0d96d9f7babe5fa3b19b3ff25ac9",
    ),
    (
        "03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903",
        "0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885d",
        "0d921c33f2bad966478a03ca35d05719bdf92d347557ea166e5bba579eea9b83e9afa5c088573c2281410369fbd32951",
        "003574a00b109ada2f26a37a91f9d1e740dffd8d69ec0c35e1e9f4652c7dba61123e9dd2e76c655d956e2b3462611139",
    ),
    (
        "11e0b079dea29a68f0383ee94fed1b940995272407e3bb916bbf268c263ddd57a6a27200a784cbc248e84f357ce82d98",
        "03a87ae2caf14e8ee52e51fa2ed8eefe80f02457004ba4d486d6aa1f517c0889501dc7413753f9599b099ebcbbd2d709",
        "062d1865eb80ebfa73dcfc45db1ad4266b9f3a93219976a3790ab8d52d3e5f1e62f3b01795e36834b17b70e7b76246d4",
        "0cdc3e2f271f29c4ff75020857ce6c5d36008c9b48385ea2f2bf6f96f428a3deb798aa033cd482d1cdc8b30178b08e3a",
    ),
    (
        "15f68eaa693b95ccb85215dc65fa81038d69629f70aeee0d0f677cf22285e7bf58d7cb86eefe8f2e9bc3f8cb84fac488",
        "1807a1d50c29f430b8cafc4f8638dfeeadf51211e1602a5f184443076715f91bb90a48ba1e370edce6ae1062f5e6dd38",
        "010476f6a060453c0b1ad0b628f3e57c23039ee16eea5e71bb87c3b5419b1255dc0e5883322e563b84a29543823c0e86",
        "0b1a912064fb0554b180e07af7e787f1f883a0470759c03c1b6509eb8ce980d1670305ae7b928226bb58fdc0a419f46e",
    ),
    (
        "082aabae8b7dedb0e78aeb619ad3bfd9277a2f77ba7fad20ef6aabdc6c31d19ba5a6d12283553294c1825c4b3ca2dcfe",
        "05b84ae5a942248eea39e1d91030458c40153f3b654ab7872d779ad1e942856a20c438e8d99bc8abfbf74729ce1f7ac8",
        "0a8ffa7447f6be1c5a2ea4b959c9454b431e29ccc0802bc052413a9c5b4f9aac67a93431bd480d15be1e057c8a08e8c6",
        "05d487032f602c90fa7625dbafe0f4a49ef4a6b0b33d7bb349ff4cf5410d297fd6241876e3e77b651cfc8191e40a68b7",
    ),
];

#[test]
fn rfc9380_vectors() {
    let messages = rfc_messages();
    for (message, (x, y, u0, u1)) in messages.iter().zip(RFC_VECTORS) {
        let expected = G1::from_affine_unchecked(fp(x), fp(y));
        assert!(bool::from(expected.is_on_curve()));
        assert_eq!(G1::hash_to_curve(RFC_DST, message), expected);
        assert_eq!(blst_hash(RFC_DST, message), expected);
        assert_eq!(hash_to_field(RFC_DST, message), [fp(u0), fp(u1)]);
    }
    let refs: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
    let batch = G1::hash_many(RFC_DST, &refs);
    assert_eq!(batch.len(), 5);
    for (point, (x, y, _, _)) in batch.iter().zip(RFC_VECTORS) {
        assert_eq!(*point, G1::from_affine_unchecked(fp(x), fp(y)));
    }
}

/// Draws a DST of 1 to 300 bytes, crossing the 255 byte limit that forces DST compression.
fn dst(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    let len = if u.ratio(1, 4)? {
        u.int_in_range(250..=300)?
    } else {
        u.int_in_range(1..=64)?
    };
    (0..len).map(|_| u.arbitrary()).collect()
}

/// Draws a message of 0 to 300 bytes.
fn message(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    let len = u.int_in_range(0..=300)?;
    (0..len).map(|_| u.arbitrary()).collect()
}

#[test]
fn hash_matches_blst() {
    minifuzz::test(|u| {
        let dst = dst(u)?;
        let message = message(u)?;
        let expected = blst_hash(&dst, &message);
        assert!(bool::from(expected.is_on_curve()));
        assert_eq!(G1::hash_to_curve(&dst, &message), expected);
        Ok(())
    });
}

#[test]
fn hash_many_matches_blst() {
    minifuzz::test(|u| {
        let dst = dst(u)?;
        let count = u.int_in_range(0..=20)?;
        let mut messages = Vec::with_capacity(count);
        for _ in 0..count {
            messages.push(message(u)?);
        }
        let refs: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
        let expected: Vec<G1> = refs.iter().map(|m| blst_hash(&dst, m)).collect();
        assert_eq!(G1::hash_many(&dst, &refs), expected);
        Ok(())
    });
}

#[test]
fn every_context_matches_blst() {
    let dst = [b'd'; 300];
    let messages: Vec<Vec<u8>> = (0..9usize)
        .map(|i| (0..i * 17).map(|j| (i + j) as u8).collect())
        .collect();
    let refs: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
    let expected: Vec<G1> = refs.iter().map(|m| blst_hash(&dst, m)).collect();
    assert_eq!(
        every_context(HashToCurve {
            dst: &dst,
            messages: &refs
        }),
        expected
    );
}

#[test]
fn empty_batch() {
    assert!(G1::hash_many(RFC_DST, &[]).is_empty());
}

#[test]
fn batch_lane_counts() {
    // Batch sizes around and across lane-width multiples, with distinct messages.
    let messages: Vec<Vec<u8>> = (0..33u8).map(|i| vec![i; i as usize]).collect();
    let refs: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
    let expected: Vec<G1> = refs.iter().map(|m| blst_hash(RFC_DST, m)).collect();
    for n in 0..=refs.len() {
        assert_eq!(G1::hash_many(RFC_DST, &refs[..n]), expected[..n], "n={n}");
    }
}

#[test]
fn duplicate_messages_agree() {
    let refs: Vec<&[u8]> = vec![b"same".as_slice(); 9];
    let out = G1::hash_many(RFC_DST, &refs);
    assert!(out.iter().all(|p| *p == out[0]));
    assert_eq!(out[0], G1::hash_to_curve(RFC_DST, b"same"));
}

const RFC_A: &str = "00144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d";
const RFC_B: &str = "12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0";

const RFC_X_NUM: &[&str] = &[
    "11a05f2b1e833340b809101dd99815856b303e88a2d7005ff2627b56cdb4e2c85610c2d5f2e62d6eaeac1662734649b7",
    "17294ed3e943ab2f0588bab22147a81c7c17e75b2f6a8417f565e33c70d1e86b4838f2a6f318c356e834eef1b3cb83bb",
    "0d54005db97678ec1d1048c5d10a9a1bce032473295983e56878e501ec68e25c958c3e3d2a09729fe0179f9dac9edcb0",
    "1778e7166fcc6db74e0609d307e55412d7f5e4656a8dbf25f1b33289f1b330835336e25ce3107193c5b388641d9b6861",
    "0e99726a3199f4436642b4b3e4118e5499db995a1257fb3f086eeb65982fac18985a286f301e77c451154ce9ac8895d9",
    "1630c3250d7313ff01d1201bf7a74ab5db3cb17dd952799b9ed3ab9097e68f90a0870d2dcae73d19cd13c1c66f652983",
    "0d6ed6553fe44d296a3726c38ae652bfb11586264f0f8ce19008e218f9c86b2a8da25128c1052ecaddd7f225a139ed84",
    "17b81e7701abdbe2e8743884d1117e53356de5ab275b4db1a682c62ef0f2753339b7c8f8c8f475af9ccb5618e3f0c88e",
    "080d3cf1f9a78fc47b90b33563be990dc43b756ce79f5574a2c596c928c5d1de4fa295f296b74e956d71986a8497e317",
    "169b1f8e1bcfa7c42e0c37515d138f22dd2ecb803a0c5c99676314baf4bb1b7fa3190b2edc0327797f241067be390c9e",
    "10321da079ce07e272d8ec09d2565b0dfa7dccdde6787f96d50af36003b14866f69b771f8c285decca67df3f1605fb7b",
    "06e08c248e260e70bd1e962381edee3d31d79d7e22c837bc23c0bf1bc24c6b68c24b1b80b64d391fa9c8ba2e8ba2d229",
];

const RFC_X_DEN: &[&str] = &[
    "08ca8d548cff19ae18b2e62f4bd3fa6f01d5ef4ba35b48ba9c9588617fc8ac62b558d681be343df8993cf9fa40d21b1c",
    "12561a5deb559c4348b4711298e536367041e8ca0cf0800c0126c2588c48bf5713daa8846cb026e9e5c8276ec82b3bff",
    "0b2962fe57a3225e8137e629bff2991f6f89416f5a718cd1fca64e00b11aceacd6a3d0967c94fedcfcc239ba5cb83e19",
    "03425581a58ae2fec83aafef7c40eb545b08243f16b1655154cca8abc28d6fd04976d5243eecf5c4130de8938dc62cd8",
    "13a8e162022914a80a6f1d5f43e7a07dffdfc759a12062bb8d6b44e833b306da9bd29ba81f35781d539d395b3532a21e",
    "0e7355f8e4e667b955390f7f0506c6e9395735e9ce9cad4d0a43bcef24b8982f7400d24bc4228f11c02df9a29f6304a5",
    "0772caacf16936190f3e0c63e0596721570f5799af53a1894e2e073062aede9cea73b3538f0de06cec2574496ee84a3a",
    "14a7ac2a9d64a8b230b3f5b074cf01996e7f63c21bca68a81996e1cdf9822c580fa5b9489d11e2d311f7d99bbdcc5a5e",
    "0a10ecf6ada54f825e920b3dafc7a3cce07f8d1d7161366b74100da67f39883503826692abba43704776ec3a79a1d641",
    "095fc13ab9e92ad4476d6e3eb3a56680f682b4ee96f7d03776df533978f31c1593174e4b4b7865002d6384d168ecdd0a",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
];

const RFC_Y_NUM: &[&str] = &[
    "090d97c81ba24ee0259d1f094980dcfa11ad138e48a869522b52af6c956543d3cd0c7aee9b3ba3c2be9845719707bb33",
    "134996a104ee5811d51036d776fb46831223e96c254f383d0f906343eb67ad34d6c56711962fa8bfe097e75a2e41c696",
    "00cc786baa966e66f4a384c86a3b49942552e2d658a31ce2c344be4b91400da7d26d521628b00523b8dfe240c72de1f6",
    "01f86376e8981c217898751ad8746757d42aa7b90eeb791c09e4a3ec03251cf9de405aba9ec61deca6355c77b0e5f4cb",
    "08cc03fdefe0ff135caf4fe2a21529c4195536fbe3ce50b879833fd221351adc2ee7f8dc099040a841b6daecf2e8fedb",
    "16603fca40634b6a2211e11db8f0a6a074a7d0d4afadb7bd76505c3d3ad5544e203f6326c95a807299b23ab13633a5f0",
    "04ab0b9bcfac1bbcb2c977d027796b3ce75bb8ca2be184cb5231413c4d634f3747a87ac2460f415ec961f8855fe9d6f2",
    "0987c8d5333ab86fde9926bd2ca6c674170a05bfe3bdd81ffd038da6c26c842642f64550fedfe935a15e4ca31870fb29",
    "09fc4018bd96684be88c9e221e4da1bb8f3abd16679dc26c1e8b6e6a1f20cabe69d65201c78607a360370e577bdba587",
    "0e1bba7a1186bdb5223abde7ada14a23c42a0ca7915af6fe06985e7ed1e4d43b9b3f7055dd4eba6f2bafaaebca731c30",
    "19713e47937cd1be0dfd0b8f1d43fb93cd2fcbcb6caf493fd1183e416389e61031bf3a5cce3fbafce813711ad011c132",
    "18b46a908f36f6deb918c143fed2edcc523559b8aaf0c2462e6bfe7f911f643249d9cdf41b44d606ce07c8a4d0074d8e",
    "0b182cac101b9399d155096004f53f447aa7b12a3426b08ec02710e807b4633f06c851c1919211f20d4c04f00b971ef8",
    "0245a394ad1eca9b72fc00ae7be315dc757b3b080d4c158013e6632d3c40659cc6cf90ad1c232a6442d9d3f5db980133",
    "05c129645e44cf1102a159f748c4a3fc5e673d81d7e86568d9ab0f5d396a7ce46ba1049b6579afb7866b1e715475224b",
    "15e6be4e990f03ce4ea50b3b42df2eb5cb181d8f84965a3957add4fa95af01b2b665027efec01c7704b456be69c8b604",
];

const RFC_Y_DEN: &[&str] = &[
    "16112c4c3a9c98b252181140fad0eae9601a6de578980be6eec3232b5be72e7a07f3688ef60c206d01479253b03663c1",
    "1962d75c2381201e1a0cbd6c43c348b885c84ff731c4d59ca4a10356f453e01f78a4260763529e3532f6102c2e49a03d",
    "058df3306640da276faaae7d6e8eb15778c4855551ae7f310c35a5dd279cd2eca6757cd636f96f891e2538b53dbf67f2",
    "16b7d288798e5395f20d23bf89edb4d1d115c5dbddbcd30e123da489e726af41727364f2c28297ada8d26d98445f5416",
    "0be0e079545f43e4b00cc912f8228ddcc6d19c9f0f69bbb0542eda0fc9dec916a20b15dc0fd2ededda39142311a5001d",
    "08d9e5297186db2d9fb266eaac783182b70152c65550d881c5ecd87b6f0f5a6449f38db9dfa9cce202c6477faaf9b7ac",
    "166007c08a99db2fc3ba8734ace9824b5eecfdfa8d0cf8ef5dd365bc400a0051d5fa9c01a58b1fb93d1a1399126a775c",
    "16a3ef08be3ea7ea03bcddfabba6ff6ee5a4375efa1f4fd7feb34fd206357132b920f5b00801dee460ee415a15812ed9",
    "1866c8ed336c61231a1be54fd1d74cc4f9fb0ce4c6af5920abc5750c4bf39b4852cfe2f7bb9248836b233d9d55535d4a",
    "167a55cda70a6e1cea820597d94a84903216f763e13d87bb5308592e7ea7d4fbc7385ea3d529b35e346ef48bb8913f55",
    "04d2f259eea405bd48f010a01ad2911d9c6dd039bb61a6290e591b36e636a5c871a5c29f4f83060400f8b49cba8f6aa8",
    "0accbb67481d033ff5852c1e48c50c477f94ff8aefce42d28c0f9a88cea7913516f968986f7ebbea9684b529e2561092",
    "0ad6b9514c767fe3c3613144b45f1496543346d98adf02267d5ceef9a00d9b8693000763e3b90ac11e99b138573345cc",
    "02660400eb2e4f3b628bdd0d53cd76f2bf565b94e72927c1cb748df27942480e420517bd8714cc80d1fadc1326ed06f7",
    "0e0fa1d816ddc03e6b24255e0d7819c171c40f65e273b853324efcd6356caa205ca2f570f13497804415473a1d634b8f",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
];

#[commonware_macros::test_group("miri")]
#[test]
fn constants_match_rfc() {
    assert_eq!(G1_A, fp(RFC_A));
    assert_eq!(G1_B, fp(RFC_B));
    assert_eq!(G1_Z, Fp::from_u64(11));
    assert_eq!(SQRT_MINUS_Z.square(), Fp::from_u64(11).neg());
    for (got, want) in [
        (G1_X_NUM, RFC_X_NUM),
        (G1_X_DEN, RFC_X_DEN),
        (G1_Y_NUM, RFC_Y_NUM),
        (G1_Y_DEN, RFC_Y_DEN),
    ] {
        assert_eq!(got.len(), want.len());
        for (g, w) in got.iter().zip(want) {
            assert_eq!(*g, fp(w));
        }
    }
}

/// Maps one field element through the full map to the curve, returning the intermediate
/// point on the isogenous curve and the final point.
#[derive(Clone, Copy)]
struct MapOne(Fp);

impl Workload<G1> for MapOne {
    type Output = ([Fp; 3], G1);

    fn run<F: Arithmetic<Scalar = Fp>>(self, curve: &Curve<F>) -> Self::Output {
        let f = curve.field;
        let mut us = [Fp::ZERO; MAX_LANES];
        us[0] = self.0;
        let mapped = map_to_curve(curve, f.load(&us, Fp::ZERO));
        let mut stored = [G1::IDENTITY.0; MAX_LANES];
        curve.store(mapped, &mut stored);
        let intermediate = [stored[0].x, stored[0].y, stored[0].z];
        let point = clear_cofactor(curve, isogeny(curve, mapped));
        (intermediate, first(curve, point))
    }
}

/// Applies the isogeny to a single homogeneous point of the isogenous curve.
#[derive(Clone, Copy)]
struct IsogenyOf([Fp; 3]);

impl Workload<G1> for IsogenyOf {
    type Output = G1;

    fn run<F: Arithmetic<Scalar = Fp>>(self, curve: &Curve<F>) -> G1 {
        let [x, y, z] = self.0;
        let point = curve.load([&Projective { x, y, z }]);
        first(curve, isogeny(curve, point))
    }
}

fn blst_map(u: Fp) -> G1 {
    let mut out = blst::blst_p1::default();
    let u = crate::old::fp::tests::to_blst(u);
    // SAFETY: valid pointers; a null second element selects the single-element map.
    unsafe { blst::blst_map_to_g1(&mut out, &u, core::ptr::null()) };
    from_blst(&out)
}

fn on_isogenous_curve([x, y, z]: [Fp; 3]) -> bool {
    let lhs = y.square().mul(z);
    let rhs = x
        .square()
        .mul(x)
        .add(G1_A.mul(x).mul(z.square()))
        .add(G1_B.mul(z.square().mul(z)));
    lhs == rhs && z != Fp::ZERO
}

#[test]
fn map_to_curve_matches_blst() {
    // Zero, small values, and RFC field elements.
    let mut inputs = vec![Fp::ZERO, Fp::ONE, Fp::ONE.neg(), Fp::from_u64(11)];
    inputs.push(SQRT_MINUS_Z);
    inputs.push(fp(POLE_U));
    for (i, message) in rfc_messages().iter().enumerate() {
        inputs.extend(hash_to_field(RFC_DST, message));
        inputs.push(Fp::from_u64(i as u64 + 2));
    }
    for u in inputs {
        let (intermediate, point) = test_dispatch(Run::<G1, _>::new(MapOne(u)));
        assert!(on_isogenous_curve(intermediate), "u={u:?}");
        assert!(bool::from(point.is_on_curve()));
        assert_eq!(point, blst_map(u), "u={u:?}");
    }
}

#[commonware_macros::test_group("miri")]
#[test]
fn isogeny_of_identity_is_identity() {
    let identity = [Fp::ZERO, Fp::ONE, Fp::ZERO];
    assert_eq!(test_dispatch(Run::<G1, _>::new(IsogenyOf(identity))), G1::IDENTITY);
    // Scaling a homogeneous representation of the identity changes nothing.
    let scaled = [Fp::ZERO, Fp::from_u64(7), Fp::ZERO];
    assert_eq!(test_dispatch(Run::<G1, _>::new(IsogenyOf(scaled))), G1::IDENTITY);
}

/// A field element whose mapped point lies in the kernel of the isogeny.
const POLE_U: &str = "146850b3bdc2495ed73bb803dfaa951a88abff0acb5c7aeac52b48f3c808e87ce3885b98ce916e17caef21a6cbc6b598";

/// Maps every element through the map to the isogenous curve and the isogeny, returning the
/// stored isogeny output and the sum of it with the generator, one entry per input.
#[derive(Clone, Copy)]
struct IsogenyMany<'a>(&'a [Fp]);

impl Workload<G1> for IsogenyMany<'_> {
    type Output = Vec<([Fp; 3], G1)>;

    fn run<F: Arithmetic<Scalar = Fp>>(self, curve: &Curve<F>) -> Self::Output {
        let f = curve.field;
        let mut output = Vec::with_capacity(self.0.len());
        for chunk in self.0.chunks(F::LANES) {
            let mut us = [Fp::ZERO; MAX_LANES];
            us[..chunk.len()].copy_from_slice(chunk);
            let point = isogeny(curve, map_to_curve(curve, f.load(&us, Fp::ZERO)));
            let mut stored = [G1::IDENTITY.0; MAX_LANES];
            curve.store(point, &mut stored);
            let mut sums = [G1::IDENTITY.0; MAX_LANES];
            curve.store(
                curve.add(point, Projective {
                    x: f.constant(G1::GENERATOR.0.x),
                    y: f.constant(G1::GENERATOR.0.y),
                    z: f.constant(G1::GENERATOR.0.z),
                }),
                &mut sums,
            );
            for lane in 0..chunk.len() {
                let p = stored[lane];
                output.push(([p.x, p.y, p.z], G1(sums[lane])));
            }
        }
        output
    }
}

#[test]
fn isogeny_pole_is_canonical_identity() {
    let pole = fp(POLE_U);
    // Mixed lanes: poles at several positions among ordinary inputs, with a partial last chunk.
    let inputs = [
        Fp::ZERO,
        Fp::ONE,
        pole,
        Fp::from_u64(2),
        Fp::from_u64(3),
        Fp::from_u64(4),
        Fp::from_u64(5),
        Fp::from_u64(6),
        pole,
        Fp::from_u64(7),
        Fp::ONE.neg(),
    ];
    let outputs = every_context(IsogenyMany(&inputs));
    assert_eq!(outputs.len(), inputs.len());
    for (u, (coordinates, sum)) in inputs.iter().zip(&outputs) {
        if *u == pole {
            assert_eq!(*coordinates, [Fp::ZERO, Fp::ONE, Fp::ZERO]);
            assert_eq!(*sum, G1::GENERATOR);
        } else {
            assert!(coordinates[2] != Fp::ZERO, "u={u:?}");
        }
    }
}
