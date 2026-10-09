use super::{super::VerifyingKey, *};
use sha2::{Digest as _, Sha256};

#[test]
fn rejects_unvalidated_secret_material() {
    let mut key = KeyMaterial {
        f: [0; 512],
        g: [0; 512],
        big_f: [0; 512],
        big_g: [0; 512],
    };
    // This exact NTRU solution has neither the profile distribution nor safe leaves.
    key.f[0] = 127;
    key.g[0] = 126;
    key.big_f[0] = -30;
    key.big_g[0] = 67;
    let mut out = [0; SIGNATURE_SIZE];
    assert!(sign(&key.encode(), b"message", &mut out).is_none());
    assert!(sign(&[0; SECRET_KEY_SIZE], b"message", &mut out).is_none());
    assert!(sign(&key.encode()[..SECRET_KEY_SIZE - 1], b"message", &mut out).is_none());
}

#[test]
fn key_generation_matches_independent_integer_oracle() {
    // The oracle independently implements the transcript, finite key sampler,
    // admission checks, exact NTRU solve, and weighted Babai reduction.
    let vectors = [
        (
            0x62,
            [
                0x7d, 0xa3, 0xd2, 0x1d, 0x36, 0x3e, 0x72, 0x33, 0x51, 0x7a, 0xae, 0x4d, 0xbb, 0x82,
                0x00, 0xd5, 0xf1, 0xd3, 0xee, 0x99, 0x33, 0xde, 0xf3, 0x16, 0x1b, 0x29, 0x54, 0x62,
                0x64, 0x05, 0x9b, 0x42,
            ],
        ),
        (
            0x31,
            [
                0xea, 0xdd, 0xed, 0xa3, 0xb1, 0x39, 0x19, 0xff, 0x85, 0xfa, 0x20, 0xd5, 0xa4, 0x10,
                0x87, 0xae, 0x42, 0x7a, 0x93, 0x39, 0x5b, 0xfd, 0x54, 0x5a, 0x87, 0x98, 0xfc, 0xee,
                0xf8, 0x8e, 0x7b, 0xc4,
            ],
        ),
        (
            0x32,
            [
                0x74, 0x9f, 0x38, 0xde, 0xb4, 0x6c, 0xb7, 0x3c, 0xe5, 0x8c, 0xcb, 0x67, 0x2f, 0xce,
                0xec, 0xcc, 0x7b, 0x02, 0xf8, 0x54, 0x82, 0xd4, 0x2d, 0xba, 0x27, 0xd6, 0xdc, 0x13,
                0x4f, 0xd7, 0x8c, 0x0f,
            ],
        ),
    ];
    for (seed, expected) in vectors {
        let (secret, _) = keygen(&[seed; 32]);
        let digest: [u8; 32] = Sha256::digest(&*secret).into();
        assert_eq!(digest, expected, "key-generation seed {seed:#x}");
    }
}

#[test]
fn key_regeneration_and_repeated_signing_are_deterministic() {
    let (secret, public) = keygen(&[0x31; 32]);
    let (secret_again, public_again) = keygen(&[0x31; 32]);
    assert_eq!(*secret, *secret_again);
    assert_eq!(public, public_again);
    let verifying_key = VerifyingKey::decode(&public).unwrap();
    let mut signature = [0; SIGNATURE_SIZE];
    let mut repeated = [0; SIGNATURE_SIZE];
    sign(&secret, b"message", &mut signature).unwrap();
    sign(&secret_again, b"message", &mut repeated).unwrap();
    assert_eq!(signature, repeated);
    assert!(signature_is_well_formed(&signature));
    assert!(verifying_key.verify(b"message", &signature));
    assert!(!verifying_key.verify(b"message\0", &signature));
    signature[1] ^= 1;
    assert!(signature_is_well_formed(&signature));
    assert!(!verifying_key.verify(b"message", &signature));
}

#[test]
fn distinct_private_bases_have_distinct_signing_transcripts() {
    let (secret, public) = keygen(&[0x32; 32]);
    let mut alternative = KeyMaterial::decode(&secret).unwrap();
    for i in 0..512 {
        alternative.big_f[i] += i16::from(alternative.f[i]);
        alternative.big_g[i] += i16::from(alternative.g[i]);
    }
    assert!(Prepared::new(&alternative).is_some());
    assert_eq!(alternative.public_key().as_slice(), public);
    let alternative = alternative.encode();
    let mut first = [0; SIGNATURE_SIZE];
    let mut second = [0; SIGNATURE_SIZE];
    sign(&secret, b"same target subject", &mut first).unwrap();
    sign(&alternative, b"same target subject", &mut second).unwrap();
    assert_ne!(first[1..41], second[1..41]);
    let verifying_key = VerifyingKey::decode(&public).unwrap();
    assert!(verifying_key.verify(b"same target subject", &first));
    assert!(verifying_key.verify(b"same target subject", &second));
}

#[test]
fn sample_moments_and_retries_match_profile_smoke_bounds() {
    const SAMPLES: u64 = 2048;
    let (secret, public) = keygen(&[0x62; 32]);
    let key = KeyMaterial::decode(&secret).unwrap();
    let prepared = Prepared::new(&key).unwrap();
    let key_hash = transcript::public_key_hash(&public);
    let seed = transcript::signing_seed(&secret, &key_hash);
    let verifying_key = VerifyingKey::decode(&public).unwrap();
    let mut h = codec::decode_public_key(&public).unwrap();
    mq::mqpoly_ext_to_int(9, &mut h);
    let mut sum_s = 0u64;
    let mut sum_residual = 0u64;
    let mut projections = [0u64; 512];
    let mut total_bits = 0u64;
    let mut domain_rejections = 0u64;
    let mut norm_rejections = 0u64;
    let mut codec_rejections = 0u64;
    for subject in 0..SAMPLES {
        let message = subject.to_le_bytes();
        let mu = transcript::message_representative_from_hash(&key_hash, &message);
        let mut accepted = false;
        for counter in 0..16 {
            let (salt, sampler_seed) = transcript::attempt(&seed, &mu, counter);
            let mut target = [0; 512];
            hash_to_point(&salt, &mu, &mut target);
            let Some(result) = prepared.sample(&target, &sampler_seed) else {
                domain_rejections += 1;
                continue;
            };
            let Some(s) = result else {
                norm_rejections += 1;
                continue;
            };
            let mut signature = [0; SIGNATURE_SIZE];
            if codec::encode_signature(&salt, &s, &mut signature).is_none() {
                codec_rejections += 1;
                continue;
            }
            assert!(verifying_key.verify(&message, &signature));
            sum_s += s.iter().map(|v| i64::from(*v).pow(2) as u64).sum::<u64>();
            total_bits += 41 * 8
                + 6 * 512
                + s.iter()
                    .map(|v| u64::from(v.unsigned_abs() >> 4))
                    .sum::<u64>();
            for (shift, projection) in projections.iter_mut().enumerate() {
                let mut dot = 0i64;
                for j in 0..512 {
                    if j + shift < 512 {
                        dot += i64::from(key.f[j]) * i64::from(s[j + shift]);
                    } else {
                        dot -= i64::from(key.f[j]) * i64::from(s[j + shift - 512]);
                    }
                }
                *projection += dot.pow(2) as u64;
            }
            let mut product = [0; 512];
            mq::mqpoly_signed_to_ext(9, &*s, &mut product);
            mq::mqpoly_ext_to_int(9, &mut product);
            mq::mqpoly_int_to_NTT(9, &mut product);
            mq::mqpoly_mul_ntt(9, &mut product, &h);
            mq::mqpoly_NTT_to_int(9, &mut product);
            mq::mqpoly_int_to_ext(9, &mut product);
            for i in 0..512 {
                let residual =
                    (i64::from(target[i]) - i64::from(product[i]) + 6144).rem_euclid(12289) - 6144;
                sum_residual += residual.pow(2) as u64;
            }
            accepted = true;
            break;
        }
        assert!(
            accepted,
            "subject {subject} exhausted the measured retry budget"
        );
    }
    let sigma_squared = (6.0f64 * 165.7366171829776).powi(2);
    let expected_s = sigma_squared / 1296.0;
    let mean_s = sum_s as f64 / (SAMPLES * 512) as f64;
    let mean_residual = sum_residual as f64 / (SAMPLES * 512) as f64;
    let projection_min =
        *projections.iter().min().unwrap() as f64 / (SAMPLES as f64 * expected_s * 233.0);
    let projection_max =
        *projections.iter().max().unwrap() as f64 / (SAMPLES as f64 * expected_s * 233.0);
    std::println!(
        "ELLIPSOIDAL_SAMPLING samples={SAMPLES} domain_rejections={domain_rejections} norm_rejections={norm_rejections} codec_rejections={codec_rejections} s_variance={mean_s:.6} residual_variance={mean_residual:.6} mean_framed_bytes={:.6} projection_min={projection_min:.6} projection_max={projection_max:.6}",
        total_bits as f64 / (8 * SAMPLES) as f64,
    );
    assert_eq!(domain_rejections, 0);
    assert!(norm_rejections < 32 && codec_rejections < 4);
    assert!((mean_s / expected_s - 1.0).abs() < 0.02);
    assert!((mean_residual / sigma_squared - 1.0).abs() < 0.02);
    assert!(projection_min > 0.7 && projection_max < 1.3);
}
