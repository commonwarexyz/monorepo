//! Tests for hashing to G2.

use super::*;
use crate::{
    curve::{Curve, Projective},
    fp::{Arithmetic, Fp, lanes::MAX_LANES},
    fp2::{Fp2, tests as fp2},
    g2::{
        Run, first,
        tests::{every_context, from_blst},
    },
    group::Workload,
};
use arbitrary::Unstructured;
use commonware_invariants::minifuzz;
use commonware_simd::test_dispatch;

const RFC_DST: &[u8] = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";

/// An element of Fp2 as the big-endian hex of its (c0, c1) coordinates.
type Pair = (&'static str, &'static str);

/// Hashes with blst, as the reference implementation.
fn blst_hash(dst: &[u8], message: &[u8]) -> G2 {
    let mut out = blst::blst_p2::default();
    // SAFETY: valid pointers and lengths; a null augmentation has length zero.
    unsafe {
        blst::blst_hash_to_g2(
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

fn fp2_from((c0, c1): Pair) -> Fp2 {
    Fp2::new(fp(c0), fp(c1))
}

/// The messages of RFC 9380 appendix J.10.1.
fn rfc_messages() -> [Vec<u8>; 5] {
    [
        Vec::new(),
        b"abc".to_vec(),
        b"abcdef0123456789".to_vec(),
        [b"q128_".as_slice(), &[b'q'; 128]].concat(),
        [b"a512_".as_slice(), &[b'a'; 512]].concat(),
    ]
}

/// (P.x, P.y, u[0], u[1]) for each message of RFC 9380 appendix J.10.1.
const RFC_VECTORS: [(Pair, Pair, Pair, Pair); 5] = [
    (
        (
            "0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a",
            "05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d",
        ),
        (
            "0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92",
            "12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6",
        ),
        (
            "03dbc2cce174e91ba93cbb08f26b917f98194a2ea08d1cce75b2b9cc9f21689d80bd79b594a613d0a68eb807dfdc1cf8",
            "05a2acec64114845711a54199ea339abd125ba38253b70a92c876df10598bd1986b739cad67961eb94f7076511b3b39a",
        ),
        (
            "02f99798e8a5acdeed60d7e18e9120521ba1f47ec090984662846bc825de191b5b7641148c0dbc237726a334473eee94",
            "145a81e418d4010cc027a68f14391b30074e89e60ee7a22f87217b2f6eb0c4b94c9115b436e6fa4607e95a98de30a435",
        ),
    ),
    (
        (
            "02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6",
            "139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8",
        ),
        (
            "1787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba48",
            "00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd16",
        ),
        (
            "15f7c0aa8f6b296ab5ff9c2c7581ade64f4ee6f1bf18f55179ff44a2cf355fa53dd2a2158c5ecb17d7c52f63e7195771",
            "01c8067bf4c0ba709aa8b9abc3d1cef589a4758e09ef53732d670fd8739a7274e111ba2fcaa71b3d33df2a3a0c8529dd",
        ),
        (
            "187111d5e088b6b9acfdfad078c4dacf72dcd17ca17c82be35e79f8c372a693f60a033b461d81b025864a0ad051a06e4",
            "08b852331c96ed983e497ebc6dee9b75e373d923b729194af8e72a051ea586f3538a6ebb1e80881a082fa2b24df9f566",
        ),
    ),
    (
        (
            "121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4c0028add35aea8bb83d53c08cfc007c1e005723cd0",
            "190d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cbba169fb3968288b3fafb265f9ebd380512a71c3f2c",
        ),
        (
            "05571a0f8d3c08d094576981f4a3b8eda0a8e771fcdcc8ecceaf1356a6acf17574518acb506e435b639353c2e14827c8",
            "0bb5e7572275c567462d91807de765611490205a941a5a6af3b1691bfe596c31225d3aabdf15faff860cb4ef17c7c3be",
        ),
        (
            "0313d9325081b415bfd4e5364efaef392ecf69b087496973b229303e1816d2080971470f7da112c4eb43053130b785e1",
            "062f84cb21ed89406890c051a0e8b9cf6c575cf6e8e18ecf63ba86826b0ae02548d83b483b79e48512b82a6c0686df8f",
        ),
        (
            "1739123845406baa7be5c5dc74492051b6d42504de008c635f3535bb831d478a341420e67dcc7b46b2e8cba5379cca97",
            "01897665d9cb5db16a27657760bbea7951f67ad68f8d55f7113f24ba6ddd82caef240a9bfa627972279974894701d975",
        ),
    ),
    (
        (
            "19a84dd7248a1066f737cc34502ee5555bd3c19f2ecdb3c7d9e24dc65d4e25e50d83f0f77105e955d78f4762d33c17da",
            "0934aba516a52d8ae479939a91998299c76d39cc0c035cd18813bec433f587e2d7a4fef038260eef0cef4d02aae3eb91",
        ),
        (
            "14f81cd421617428bc3b9fe25afbb751d934a00493524bc4e065635b0555084dd54679df1536101b2c979c0152d09192",
            "09bcccfa036b4847c9950780733633f13619994394c23ff0b32fa6b795844f4a0673e20282d07bc69641cee04f5e5662",
        ),
        (
            "025820cefc7d06fd38de7d8e370e0da8a52498be9b53cba9927b2ef5c6de1e12e12f188bbc7bc923864883c57e49e253",
            "034147b77ce337a52e5948f66db0bab47a8d038e712123bb381899b6ab5ad20f02805601e6104c29df18c254b8618c7b",
        ),
        (
            "0930315cae1f9a6017c3f0c8f2314baa130e1cf13f6532bff0a8a1790cd70af918088c3db94bda214e896e1543629795",
            "10c4df2cacf67ea3cb3108b00d4cbd0b3968031ebc8eac4b1ebcefe84d6b715fde66bef0219951ece29d1facc8a520ef",
        ),
    ),
    (
        (
            "01a6ba2f9a11fa5598b2d8ace0fbe0a0eacb65deceb476fbbcb64fd24557c2f4b18ecfc5663e54ae16a84f5ab7f62534",
            "11fca2ff525572795a801eed17eb12785887c7b63fb77a42be46ce4a34131d71f7a73e95fee3f812aea3de78b4d01569",
        ),
        (
            "0b6798718c8aed24bc19cb27f866f1c9effcdbf92397ad6448b5c9db90d2b9da6cbabf48adc1adf59a1a28344e79d57e",
            "03a47f8e6d1763ba0cad63d6114c0accbef65707825a511b251a660a9b3994249ae4e63fac38b23da0c398689ee2ab52",
        ),
        (
            "190b513da3e66fc9a3587b78c76d1d132b1152174d0b83e3c1114066392579a45824c5fa17649ab89299ddd4bda54935",
            "12ab625b0fe0ebd1367fe9fac57bb1168891846039b4216b9d94007b674de2d79126870e88aeef54b2ec717a887dcf39",
        ),
        (
            "0e6a42010cf435fb5bacc156a585e1ea3294cc81d0ceb81924d95040298380b164f702275892cedd81b62de3aba3f6b5",
            "117d9a0defc57a33ed208428cb84e54c85a6840e7648480ae428838989d25d97a0af8e3255be62b25c2a85630d2dddd8",
        ),
    ),
];

/// (Q0.x, Q0.y, Q1.x, Q1.y) for each message of RFC 9380 appendix J.10.1, the images of u[0]
/// and u[1] under the map to the curve, before the cofactor is cleared.
const RFC_INTERMEDIATES: [(Pair, Pair, Pair, Pair); 5] = [
    (
        (
            "019ad3fc9c72425a998d7ab1ea0e646a1f6093444fc6965f1cad5a3195a7b1e099c050d57f45e3fa191cc6d75ed7458c",
            "171c88b0b0efb5eb2b88913a9e74fe111a4f68867b59db252ce5868af4d1254bfab77ebde5d61cd1a86fb2fe4a5a1c1d",
        ),
        (
            "0ba10604e62bdd9eeeb4156652066167b72c8d743b050fb4c1016c31b505129374f76e03fa127d6a156213576910fef3",
            "0eb22c7a543d3d376e9716a49b72e79a89c9bfe9feee8533ed931cbb5373dde1fbcd7411d8052e02693654f71e15410a",
        ),
        (
            "113d2b9cd4bd98aee53470b27abc658d91b47a78a51584f3d4b950677cfb8a3e99c24222c406128c91296ef6b45608be",
            "13855912321c5cb793e9d1e88f6f8d342d49c0b0dbac613ee9e17e3c0b3c97dfbb5a49cc3fb45102fdbaf65e0efe2632",
        ),
        (
            "0fd3def0b7574a1d801be44fde617162aa2e89da47f464317d9bb5abc3a7071763ce74180883ad7ad9a723a9afafcdca",
            "056f617902b3c0d0f78a9a8cbda43a26b65f602f8786540b9469b060db7b38417915b413ca65f875c130bebfaa59790c",
        ),
    ),
    (
        (
            "12b2e525281b5f4d2276954e84ac4f42cf4e13b6ac4228624e17760faf94ce5706d53f0ca1952f1c5ef75239aeed55ad",
            "05d8a724db78e570e34100c0bc4a5fa84ad5839359b40398151f37cff5a51de945c563463c9efbdda569850ee5a53e77",
        ),
        (
            "02eacdc556d0bdb5d18d22f23dcb086dd106cad713777c7e6407943edbe0b3d1efe391eedf11e977fac55f9b94f2489c",
            "04bbe48bfd5814648d0b9e30f0717b34015d45a861425fabc1ee06fdfce36384ae2c808185e693ae97dcde118f34de41",
        ),
        (
            "19f18cc5ec0c2f055e47c802acc3b0e40c337256a208001dde14b25afced146f37ea3d3ce16834c78175b3ed61f3c537",
            "15b0dadc256a258b4c68ea43605dffa6d312eef215c19e6474b3e101d33b661dfee43b51abbf96fee68fc6043ac56a58",
        ),
        (
            "05e47c1781286e61c7ade887512bd9c2cb9f640d3be9cf87ea0bad24bd0ebfe946497b48a581ab6c7d4ca74b5147287f",
            "19f98db2f4a1fcdf56a9ced7b320ea9deecf57c8e59236b0dc21f6ee7229aa9705ce9ac7fe7a31c72edca0d92370c096",
        ),
    ),
    (
        (
            "0f48f1ea1318ddb713697708f7327781fb39718971d72a9245b9731faaca4dbaa7cca433d6c434a820c28b18e20ea208",
            "06051467c8f85da5ba2540974758f7a1e0239a5981de441fdd87680a995649c211054869c50edbac1f3a86c561ba3162",
        ),
        (
            "168b3d6df80069dbbedb714d41b32961ad064c227355e1ce5fac8e105de5e49d77f0c64867f3834848f152497eb76333",
            "134e0e8331cee8cb12f9c2d0742714ed9eee78a84d634c9a95f6a7391b37125ed48bfc6e90bf3546e99930ff67cc97bc",
        ),
        (
            "004fd03968cd1c99a0dd84551f44c206c84dcbdb78076c5bfee24e89a92c8508b52b88b68a92258403cbe1ea2da3495f",
            "1674338ea298281b636b2eb0fe593008d03171195fd6dcd4531e8a1ed1f02a72da238a17a635de307d7d24aa2d969a47",
        ),
        (
            "0dc7fa13fff6b12558419e0a1e94bfc3cfaf67238009991c5f24ee94b632c3d09e27eca329989aee348a67b50d5e236c",
            "169585e164c131103d85324f2d7747b23b91d66ae5d947c449c8194a347969fc6bbd967729768da485ba71868df8aed2",
        ),
    ),
    (
        (
            "09eccbc53df677f0e5814e3f86e41e146422834854a224bf5a83a50e4cc0a77bfc56718e8166ad180f53526ea9194b57",
            "0c3633943f91daee715277bd644fba585168a72f96ded64fc5a384cce4ec884a4c3c30f08e09cd2129335dc8f67840ec",
        ),
        (
            "0eb6186a0457d5b12d132902d4468bfeb7315d83320b6c32f1c875f344efcba979952b4aa418589cb01af712f98cc555",
            "119e3cf167e69eb16c1c7830e8df88856d48be12e3ff0a40791a5cd2f7221311d4bf13b1847f371f467357b3f3c0b4c7",
        ),
        (
            "0eb3aabc1ddfce17ff18455fcc7167d15ce6b60ddc9eb9b59f8d40ab49420d35558686293d046fc1e42f864b7f60e381",
            "198bdfb19d7441ebcca61e8ff774b29d17da16547d2c10c273227a635cacea3f16826322ae85717630f0867539b5ed8b",
        ),
        (
            "0aaf1dee3adf3ed4c80e481c09b57ea4c705e1b8d25b897f0ceeec3990748716575f92abff22a1c8f4582aff7b872d52",
            "0d058d9061ed27d4259848a06c96c5ca68921a5d269b078650c882cb3c2bd424a8702b7a6ee4e0ead9982baf6843e924",
        ),
    ),
    (
        (
            "17cadf8d04a1a170f8347d42856526a24cc466cb2ddfd506cff01191666b7f944e31244d662c904de5440516a2b09004",
            "0d13ba91f2a8b0051cf3279ea0ee63a9f19bc9cb8bfcc7d78b3cbd8cc4fc43ba726774b28038213acf2b0095391c523e",
        ),
        (
            "17ef19497d6d9246fa94d35575c0f8d06ee02f21a284dbeaa78768cb1e25abd564e3381de87bda26acd04f41181610c5",
            "12c3c913ba4ed03c24f0721a81a6be7430f2971ffca8fd1729aafe496bb725807531b44b34b59b3ae5495e5a2dcbd5c8",
        ),
        (
            "16ec57b7fe04c71dfe34fb5ad84dbce5a2dbbd6ee085f1d8cd17f45e8868976fc3c51ad9eeda682c7869024d24579bfd",
            "13103f7aace1ae1420d208a537f7d3a9679c287208026e4e3439ab8cd534c12856284d95e27f5e1f33eec2ce656533b0",
        ),
        (
            "0958b2c4c2c10fcef5a6c59b9e92c4a67b0fae3e2e0f1b6b5edad9c940b8f3524ba9ebbc3f2ceb3cfe377655b3163bd7",
            "0ccb594ed8bd14ca64ed9cb4e0aba221be540f25dd0d6ba15a4a4be5d67bcf35df7853b2d8dad3ba245f1ea3697f66aa",
        ),
    ),
];

fn rfc_point((x, y, _, _): (Pair, Pair, Pair, Pair)) -> G2 {
    G2::from_affine_unchecked(fp2_from(x), fp2_from(y))
}

#[test]
fn rfc9380_vectors() {
    let messages = rfc_messages();
    for (message, vector) in messages.iter().zip(RFC_VECTORS) {
        assert_eq!(
            hash_to_field(RFC_DST, message),
            [fp2_from(vector.2), fp2_from(vector.3)]
        );
        let expected = rfc_point(vector);
        assert_proper(&expected);
        assert!(expected.is_in_subgroup());
        let hashed = G2::hash_to_curve(RFC_DST, message);
        assert_proper(&hashed);
        assert_eq!(hashed, expected);
        assert_eq!(blst_hash(RFC_DST, message), expected);
    }
    let refs: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
    let batch = G2::hash_many(RFC_DST, &refs);
    assert_eq!(batch.len(), 5);
    for (point, vector) in batch.iter().zip(RFC_VECTORS) {
        assert_proper(point);
        assert_eq!(*point, rfc_point(vector));
    }
}

/// Asserts that a point has a nonzero z coordinate, which projective equality alone does not,
/// since (0 : 0 : 0) compares equal to every point.
fn assert_proper(point: &G2) {
    assert!(point.0.z != Fp2::ZERO, "degenerate point {point:?}");
    assert!(!bool::from(point.is_identity()));
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
        assert_eq!(G2::hash_to_curve(&dst, &message), expected);
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
        let expected: Vec<G2> = refs.iter().map(|m| blst_hash(&dst, m)).collect();
        assert_eq!(G2::hash_many(&dst, &refs), expected);
        Ok(())
    });
}

/// Hashes once on every context, since emulating the vector backends is slow.
#[test]
fn every_context_matches_blst() {
    let dst = [b'd'; 300];
    let messages: Vec<Vec<u8>> = (0..9usize)
        .map(|i| (0..i * 17).map(|j| (i + j) as u8).collect())
        .collect();
    let refs: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
    let expected: Vec<G2> = refs.iter().map(|m| blst_hash(&dst, m)).collect();
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
    assert!(G2::hash_many(RFC_DST, &[]).is_empty());
}

#[test]
fn batch_lane_counts() {
    // Batch sizes around and across lane-width multiples, with distinct messages.
    let messages: Vec<Vec<u8>> = (0..33u8).map(|i| vec![i; i as usize]).collect();
    let refs: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
    let expected: Vec<G2> = refs.iter().map(|m| blst_hash(RFC_DST, m)).collect();
    for n in 0..=refs.len() {
        assert_eq!(G2::hash_many(RFC_DST, &refs[..n]), expected[..n], "n={n}");
    }
}

#[test]
fn duplicate_messages_agree() {
    let refs: Vec<&[u8]> = vec![b"same".as_slice(); 9];
    let out = G2::hash_many(RFC_DST, &refs);
    assert!(out.iter().all(|p| *p == out[0]));
    assert_eq!(out[0], G2::hash_to_curve(RFC_DST, b"same"));
}

// RFC 9380 Appendix E.3, in ascending polynomial order. The denominators are monic, so
// their leading coefficient of one is appended.
const RFC_X_NUM: &[Pair] = &[
    (
        "05c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6",
        "05c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6",
    ),
    (
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a",
    ),
    (
        "11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e",
        "08ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d",
    ),
    (
        "171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    ),
];

const RFC_X_DEN: &[Pair] = &[
    (
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63",
    ),
    (
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c",
        "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9f",
    ),
    (
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    ),
];

const RFC_Y_NUM: &[Pair] = &[
    (
        "1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706",
        "1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706",
    ),
    (
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "05c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97be",
    ),
    (
        "11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c",
        "08ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38f",
    ),
    (
        "124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    ),
];

const RFC_Y_DEN: &[Pair] = &[
    (
        "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb",
        "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb",
    ),
    (
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3",
    ),
    (
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012",
        "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99",
    ),
    (
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    ),
];

#[commonware_macros::test_group("miri")]
#[test]
fn constants_match_rfc() {
    // RFC 9380 Section 8.8.2: A' = 240 * I, B' = 1012 * (1 + I), Z = -(2 + I).
    assert_eq!(G2_A, Fp2::new(Fp::ZERO, Fp::from_u64(240)));
    assert_eq!(G2_B, Fp2::new(Fp::from_u64(1012), Fp::from_u64(1012)));
    assert_eq!(G2_Z, Fp2::new(Fp::from_u64(2), Fp::from_u64(1)).neg());
    for (got, want) in [
        (G2_X_NUM, RFC_X_NUM),
        (G2_X_DEN, RFC_X_DEN),
        (G2_Y_NUM, RFC_Y_NUM),
        (G2_Y_DEN, RFC_Y_DEN),
    ] {
        assert_eq!(got.len(), want.len());
        for (g, w) in got.iter().zip(want) {
            assert_eq!(*g, fp2_from(*w));
        }
    }
}

/// Maps one field element through the full map to the curve, returning the intermediate
/// point on the isogenous curve and the final point.
#[derive(Clone, Copy)]
struct MapOne(Fp2);

impl Workload<G2> for MapOne {
    type Output = ([Fp2; 3], G2);

    fn run<F: Arithmetic<Scalar = Fp2>>(self, curve: &Curve<F>) -> Self::Output {
        let f = curve.field;
        let mut us = [Fp2::ZERO; MAX_LANES];
        us[0] = self.0;
        let mapped = map_to_curve(curve, f.load(&us, Fp2::ZERO));
        let mut stored = [G2::IDENTITY.0; MAX_LANES];
        curve.store(mapped, &mut stored);
        let intermediate = [stored[0].x, stored[0].y, stored[0].z];
        let point = clear_cofactor(curve, isogeny(curve, mapped));
        (intermediate, first(curve, point))
    }
}

/// Applies the isogeny to a single homogeneous point of the isogenous curve.
#[derive(Clone, Copy)]
struct IsogenyOf([Fp2; 3]);

impl Workload<G2> for IsogenyOf {
    type Output = ([Fp2; 3], G2);

    fn run<F: Arithmetic<Scalar = Fp2>>(self, curve: &Curve<F>) -> Self::Output {
        let [x, y, z] = self.0;
        let point = curve.load([&Projective { x, y, z }]);
        let image = isogeny(curve, point);
        let mut stored = [G2::IDENTITY.0; MAX_LANES];
        curve.store(image, &mut stored);
        ([stored[0].x, stored[0].y, stored[0].z], first(curve, image))
    }
}

/// Maps a field element to the curve without clearing the cofactor.
#[derive(Clone, Copy)]
struct MapIsogeny(Fp2);

impl Workload<G2> for MapIsogeny {
    type Output = G2;

    fn run<F: Arithmetic<Scalar = Fp2>>(self, curve: &Curve<F>) -> G2 {
        let f = curve.field;
        let mut us = [Fp2::ZERO; MAX_LANES];
        us[0] = self.0;
        let mapped = map_to_curve(curve, f.load(&us, Fp2::ZERO));
        first(curve, isogeny(curve, mapped))
    }
}

/// Clears the cofactor of one point.
#[derive(Clone, Copy)]
struct ClearOf(G2);

impl Workload<G2> for ClearOf {
    type Output = G2;

    fn run<F: Arithmetic<Scalar = Fp2>>(self, curve: &Curve<F>) -> G2 {
        first(curve, clear_cofactor(curve, curve.load([&self.0.0])))
    }
}

/// Checks each stage of the composition against the RFC: the images Q0 and Q1 of u[0] and u[1],
/// clearing the cofactor of their sum, and the sum of the individually cleared images.
#[test]
fn rfc9380_composition() {
    for ((message, vector), (q0x, q0y, q1x, q1y)) in rfc_messages()
        .iter()
        .zip(RFC_VECTORS)
        .zip(RFC_INTERMEDIATES)
    {
        let [u0, u1] = hash_to_field(RFC_DST, message);
        let expected = rfc_point(vector);
        let q0 = G2::from_affine_unchecked(fp2_from(q0x), fp2_from(q0y));
        let q1 = G2::from_affine_unchecked(fp2_from(q1x), fp2_from(q1y));
        assert_eq!(test_dispatch(Run::<G2, _>::new(MapIsogeny(u0))), q0);
        assert_eq!(test_dispatch(Run::<G2, _>::new(MapIsogeny(u1))), q1);
        assert_eq!(
            test_dispatch(Run::<G2, _>::new(ClearOf(q0.add(&q1)))),
            expected
        );
        let (_, cleared0) = test_dispatch(Run::<G2, _>::new(MapOne(u0)));
        let (_, cleared1) = test_dispatch(Run::<G2, _>::new(MapOne(u1)));
        assert_eq!(cleared0, test_dispatch(Run::<G2, _>::new(ClearOf(q0))));
        assert_eq!(cleared1, test_dispatch(Run::<G2, _>::new(ClearOf(q1))));
        assert_proper(&cleared0);
        assert_proper(&cleared1);
        assert_eq!(cleared0.add(&cleared1), expected);
    }
}

fn blst_map(u: Fp2) -> G2 {
    let mut out = blst::blst_p2::default();
    let u = fp2::to_blst(u);
    // SAFETY: valid pointers; a null second element selects the single-element map.
    unsafe { blst::blst_map_to_g2(&mut out, &u, core::ptr::null()) };
    from_blst(&out)
}

fn on_isogenous_curve([x, y, z]: [Fp2; 3]) -> bool {
    let lhs = y.square().mul(z);
    let rhs = x
        .square()
        .mul(x)
        .add(G2_A.mul(x).mul(z.square()))
        .add(G2_B.mul(z.square().mul(z)));
    lhs == rhs && z != Fp2::ZERO
}

#[test]
fn map_to_curve_matches_blst() {
    // Zero (the exceptional denominator), small values, and RFC field elements.
    let i = Fp2::new(Fp::ZERO, Fp::ONE);
    let mut inputs = vec![
        Fp2::ZERO,
        Fp2::ONE,
        Fp2::ONE.neg(),
        i,
        i.neg(),
        G2_Z,
        G2_Z.neg(),
    ];
    for (n, message) in rfc_messages().iter().enumerate() {
        inputs.extend(hash_to_field(RFC_DST, message));
        inputs.push(Fp2::new(
            Fp::from_u64(n as u64 + 2),
            Fp::from_u64(n as u64 + 3),
        ));
    }
    for u in inputs {
        let (intermediate, point) = test_dispatch(Run::<G2, _>::new(MapOne(u)));
        assert!(on_isogenous_curve(intermediate), "u={u:?}");
        assert_proper(&point);
        assert!(bool::from(point.is_on_curve()));
        assert_eq!(point, blst_map(u), "u={u:?}");
    }
}

#[test]
fn map_to_curve_matches_blst_random() {
    minifuzz::test(|u| {
        let u = fp2::element(u)?;
        let (intermediate, point) = test_dispatch(Run::<G2, _>::new(MapOne(u)));
        assert!(on_isogenous_curve(intermediate));
        assert_proper(&point);
        assert_eq!(point, blst_map(u));
        Ok(())
    });
}

#[commonware_macros::test_group("miri")]
#[test]
fn isogeny_of_identity_is_identity() {
    for identity in [
        [Fp2::ZERO, Fp2::ONE, Fp2::ZERO],
        // Scaling a homogeneous representation of the identity changes nothing.
        [
            Fp2::ZERO,
            Fp2::new(Fp::from_u64(7), Fp::from_u64(3)),
            Fp2::ZERO,
        ],
    ] {
        let (coordinates, point) = test_dispatch(Run::<G2, _>::new(IsogenyOf(identity)));
        assert_eq!(coordinates, [Fp2::ZERO, Fp2::ONE, Fp2::ZERO]);
        assert_eq!(point, G2::IDENTITY);
    }
}

/// The x coordinate of the kernel of the 3-isogeny, the double root of the x denominator.
fn kernel_x() -> Fp2 {
    let two = Fp2::new(Fp::from_u64(2), Fp::ZERO);
    G2_X_DEN[1].neg().mul(two.invert())
}

fn evaluate_at(coefficients: &[Fp2], x: Fp2) -> Fp2 {
    coefficients
        .iter()
        .rev()
        .fold(Fp2::ZERO, |acc, c| acc.mul(x).add(*c))
}

#[commonware_macros::test_group("miri")]
#[test]
fn kernel_is_the_denominator_root() {
    // x_den = (x - x0)^2 and y_den = (x - x0)^3 vanish exactly at the kernel.
    let x0 = kernel_x();
    assert_eq!(G2_X_DEN[0], x0.square());
    assert_eq!(evaluate_at(G2_X_DEN, x0), Fp2::ZERO);
    assert_eq!(evaluate_at(G2_Y_DEN, x0), Fp2::ZERO);
    assert!(evaluate_at(G2_X_NUM, x0) != Fp2::ZERO);
}

/// Maps every element through the map to the isogenous curve, replaces the flagged lanes by
/// a point of the isogeny's kernel, and applies the isogeny. Returns the stored output and
/// its sum with the generator, one entry per input.
#[derive(Clone, Copy)]
struct IsogenyMixed<'a> {
    us: &'a [Fp2],
    poles: &'a [bool],
}

impl Workload<G2> for IsogenyMixed<'_> {
    type Output = Vec<([Fp2; 3], G2)>;

    fn run<F: Arithmetic<Scalar = Fp2>>(self, curve: &Curve<F>) -> Self::Output {
        let f = curve.field;
        let kernel = kernel_x();
        let mut output = Vec::with_capacity(self.us.len());
        for (us, poles) in self.us.chunks(F::LANES).zip(self.poles.chunks(F::LANES)) {
            let mut inputs = [Fp2::ZERO; MAX_LANES];
            inputs[..us.len()].copy_from_slice(us);
            let mapped = map_to_curve(curve, f.load(&inputs, Fp2::ZERO));
            let mut points = [G2::IDENTITY.0; MAX_LANES];
            curve.store(mapped, &mut points);
            // The kernel's y coordinate is not in Fp2, but the isogeny is algebraic, so any
            // y with a scaled z exercises the pole.
            for (lane, pole) in poles.iter().enumerate() {
                if *pole {
                    let z = Fp2::new(Fp::from_u64(lane as u64 + 1), Fp::from_u64(5));
                    points[lane] = Projective {
                        x: kernel.mul(z),
                        y: Fp2::ONE,
                        z,
                    };
                }
            }
            let point = isogeny(curve, curve.load(&points[..F::LANES]));
            let mut stored = [G2::IDENTITY.0; MAX_LANES];
            curve.store(point, &mut stored);
            let mut sums = [G2::IDENTITY.0; MAX_LANES];
            curve.store(
                curve.add(
                    point,
                    Projective {
                        x: f.constant(G2::GENERATOR.0.x),
                        y: f.constant(G2::GENERATOR.0.y),
                        z: f.constant(G2::GENERATOR.0.z),
                    },
                ),
                &mut sums,
            );
            for lane in 0..us.len() {
                let p = stored[lane];
                output.push(([p.x, p.y, p.z], G2(sums[lane])));
            }
        }
        output
    }
}

#[test]
fn isogeny_pole_is_canonical_identity() {
    let inputs = [
        Fp2::ZERO,
        Fp2::ONE,
        Fp2::ONE,
        Fp2::new(Fp::from_u64(2), Fp::from_u64(1)),
        Fp2::new(Fp::from_u64(3), Fp::from_u64(1)),
        Fp2::new(Fp::from_u64(4), Fp::from_u64(1)),
        Fp2::new(Fp::from_u64(5), Fp::from_u64(1)),
        Fp2::new(Fp::from_u64(6), Fp::from_u64(1)),
        Fp2::ONE,
        Fp2::new(Fp::from_u64(7), Fp::from_u64(1)),
        Fp2::ONE.neg(),
    ];
    // Poles at several positions among ordinary inputs, with a partial last chunk.
    let poles = [
        false, false, true, false, false, false, false, false, true, false, false,
    ];
    let outputs = every_context(IsogenyMixed {
        us: &inputs,
        poles: &poles,
    });
    assert_eq!(outputs.len(), inputs.len());
    for ((coordinates, sum), pole) in outputs.iter().zip(poles) {
        if pole {
            assert_eq!(*coordinates, [Fp2::ZERO, Fp2::ONE, Fp2::ZERO]);
            assert_eq!(*sum, G2::GENERATOR);
        } else {
            assert!(coordinates[2] != Fp2::ZERO);
            let image = G2(Projective {
                x: coordinates[0],
                y: coordinates[1],
                z: coordinates[2],
            });
            assert!(bool::from(image.is_on_curve()));
        }
    }
}

#[commonware_macros::test_group("miri")]
#[test]
fn kernel_is_not_rational() {
    // g(x0) = x0^3 + A' x0 + B' is a non-square in Fp2, so the kernel has no point over Fp2 and
    // no input of the map reaches the isogeny's poles.
    let x0 = kernel_x();
    let rhs = x0.square().mul(x0).add(G2_A.mul(x0)).add(G2_B);
    assert!(rhs.sqrt().is_none());
}

#[test]
fn hash_to_group_trait_matches_hash_to_curve() {
    use commonware_math::algebra::HashToGroup;
    for message in rfc_messages() {
        assert_eq!(
            <G2 as HashToGroup>::hash_to_group(RFC_DST, &message),
            G2::hash_to_curve(RFC_DST, &message)
        );
    }
}
/// Returns (p^2 + delta) >> shift as 12 little-endian words, for a small signed delta.
fn p_squared_shifted(delta: i64, shift: u32) -> [u64; 12] {
    let p = crate::fp::MODULUS;
    let mut square = [0u64; 12];
    for (i, a) in p.iter().enumerate() {
        let mut carry = 0u128;
        for (j, b) in p.iter().enumerate() {
            let value = u128::from(square[i + j]) + u128::from(*a) * u128::from(*b) + carry;
            square[i + j] = value as u64;
            carry = value >> 64;
        }
        square[i + 6] = carry as u64;
    }
    // p^2 is odd and far from both ends of the range, so a one-word carry or borrow suffices.
    if delta >= 0 {
        let (low, carry) = square[0].overflowing_add(delta as u64);
        square[0] = low;
        assert!(!carry);
    } else {
        let (low, borrow) = square[0].overflowing_sub(delta.unsigned_abs());
        square[0] = low;
        assert!(!borrow);
    }
    for _ in 0..shift {
        let mut carry = 0u64;
        for word in square.iter_mut().rev() {
            let next = *word & 1;
            *word = (*word >> 1) | (carry << 63);
            carry = next;
        }
    }
    square
}

#[commonware_macros::test_group("miri")]
#[test]
fn root_constants_match_their_definitions() {
    // (p^2 - 9) / 16, Z^((p^2 - 1) / 8), and Z^((p^2 + 7) / 16), RFC 9380 F.2.1.1.
    assert_eq!(ROOT_EXPONENT, p_squared_shifted(-9, 4));
    let unity = G2_Z.pow(&p_squared_shifted(-1, 3));
    assert_eq!(ROOT_OF_UNITY, unity);
    assert_eq!(ROOT_CORRECTION, G2_Z.pow(&p_squared_shifted(7, 4)));
    // A primitive eighth root of unity has order exactly eight.
    assert_eq!(unity.pow(&[4]), Fp2::ONE.neg());
    assert_eq!(unity.pow(&[8]), Fp2::ONE);
    // The correction squares to Z^((p^2 + 7) / 8) = Z * Z^((p^2 - 1) / 8).
    assert_eq!(ROOT_CORRECTION.square(), G2_Z.mul(unity));
}

#[commonware_macros::test_group("miri")]
#[test]
fn sign_matches_sgn0() {
    // RFC 9380 Section 4.1, m = 2: sign_0 or (zero_0 and sign_1).
    let cases = [
        ((0, 0), false),
        ((1, 0), true),
        ((2, 0), false),
        ((2, 1), false),
        ((3, 5), true),
        ((0, 1), true),
        ((0, 2), false),
        ((0, 3), true),
        ((4, 7), false),
    ];
    for ((c0, c1), expected) in cases {
        let value = Fp2::new(Fp::from_u64(c0), Fp::from_u64(c1));
        assert_eq!(bool::from(sign(value)), expected, "({c0}, {c1})");
    }
    // Negation flips the sign of every nonzero element, since p is odd.
    let value = Fp2::new(Fp::from_u64(6), Fp::from_u64(9));
    assert!(bool::from(sign(value)) != bool::from(sign(value.neg())));
    let value = Fp2::new(Fp::ZERO, Fp::from_u64(9));
    assert!(bool::from(sign(value)) != bool::from(sign(value.neg())));
}
