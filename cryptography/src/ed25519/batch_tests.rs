use super::*;
use crate::Signer as _;
use commonware_codec::{Copying, DecodeExt as _};
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::{NZUsize, TestRng, test_rng};

// ZIP215 encodings from the in-tree curve25519 vector corpus.
const ZIP215_POINTS: [[u8; 32]; 14] = [
    commonware_formatting::hex!(
        "0x0100000000000000000000000000000000000000000000000000000000000000"
    ),
    commonware_formatting::hex!(
        "0xc7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"
    ),
    commonware_formatting::hex!(
        "0x0000000000000000000000000000000000000000000000000000000000000080"
    ),
    commonware_formatting::hex!(
        "0x26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"
    ),
    commonware_formatting::hex!(
        "0xecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
    ),
    commonware_formatting::hex!(
        "0x26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"
    ),
    commonware_formatting::hex!(
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    ),
    commonware_formatting::hex!(
        "0xc7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"
    ),
    commonware_formatting::hex!(
        "0x0100000000000000000000000000000000000000000000000000000000000080"
    ),
    commonware_formatting::hex!(
        "0xecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    ),
    commonware_formatting::hex!(
        "0xedffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
    ),
    commonware_formatting::hex!(
        "0xedffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    ),
    commonware_formatting::hex!(
        "0xeeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
    ),
    commonware_formatting::hex!(
        "0xeeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    ),
];

type Item = (PublicKey, Signature, Vec<u8>);

fn compare(items: &[Item], strategy: &impl Strategy) {
    let expected = !items.is_empty()
        && items
            .iter()
            .all(|(key, sig, payload)| key.verify_inner(None, payload, sig));
    let batch = || {
        let mut batch = Batch::new(items.len());
        for (key, sig, payload) in items {
            batch.verifier.add_payload(payload.clone(), key, sig);
        }
        batch
    };
    for seed in [0, 1] {
        assert_eq!(
            batch().verify_dalek(&mut TestRng::new(seed), strategy),
            expected
        );
        assert_eq!(
            batch().verify_curve(&mut TestRng::new(seed), strategy),
            expected
        );
        assert_eq!(batch().verify(&mut TestRng::new(seed), strategy), expected);
    }
}

#[test]
fn batch_zip215_differential() {
    let parallel = Rayon::new(NZUsize!(4)).unwrap().manual();
    let mut items = Vec::new();
    for key in ZIP215_POINTS {
        let key = PublicKey::decode(Copying(key.as_slice())).unwrap();
        for r in ZIP215_POINTS {
            let mut raw = [0; 64];
            raw[..32].copy_from_slice(&r);
            let sig = Signature { raw };
            assert!(key.verify_inner(None, b"Zcash", &sig));
            items.push((key.clone(), sig, b"Zcash".to_vec()));
            compare(&items[items.len() - 1..], &Sequential);
        }
    }
    compare(&items, &parallel);
    compare(&items, &Sequential);
}

#[test]
fn batch_boundaries_and_mutations() {
    const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_ED25519_BATCH_DIFFERENTIAL";
    let parallel = Rayon::new(NZUsize!(4)).unwrap().manual();
    let mut rng = test_rng();
    let signers: Vec<_> = (0..17).map(|_| PrivateKey::random(&mut rng)).collect();
    for n in [
        0, 1, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 255, 256, 257,
    ] {
        let items: Vec<_> = (0..n)
            .map(|i: usize| {
                let signer = &signers[i % signers.len()];
                let message = i.to_le_bytes();
                (
                    signer.public_key(),
                    signer.sign(NAMESPACE, &message),
                    union_unique(NAMESPACE, &message),
                )
            })
            .collect();
        compare(&items, &Sequential);
        compare(&items, &parallel);
        if n == 0 {
            continue;
        }
        for index in [0, n / 2, n - 1] {
            for mutation in 0..5 {
                let mut bad = items.clone();
                let (key, sig, payload) = &mut bad[index];
                match mutation {
                    0 => *key = signers[(index + 1) % signers.len()].public_key(),
                    1 => payload.push(1),
                    2 => sig.raw[..32].fill(2),
                    3 => sig.raw[32..].copy_from_slice(&commonware_formatting::hex!(
                        "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"
                    )),
                    _ => sig.raw[63] |= 0x80,
                }
                assert!(!key.verify_inner(None, payload, sig));
                compare(&bad, &parallel);
            }
        }
    }
}

#[test]
fn batch_dispatch_preserves_framing() {
    let signer = PrivateKey::random(test_rng());
    let key = signer.public_key();
    let signature = signer.sign(b"namespace", b"message");
    for (namespace, message, expected) in [
        (b"namespace".as_slice(), b"message".as_slice(), true),
        (b"wrong".as_slice(), b"message".as_slice(), false),
        (b"namespace".as_slice(), b"wrong".as_slice(), false),
    ] {
        let mut batch = Batch::new(1);
        assert!(batch.add(namespace, message, &key, &signature));
        assert_eq!(batch.verify(&mut test_rng(), &Sequential), expected);
    }
    assert!(!Batch::new(0).verify(&mut test_rng(), &Sequential));
}
