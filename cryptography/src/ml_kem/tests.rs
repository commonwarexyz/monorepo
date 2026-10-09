use super::{Ciphertext, EncapsulationKey, MlKem768};
use crate::Kem as _;
use commonware_codec::{Copying, DecodeExt, Encode, Error as CodecError, FixedSize};
use commonware_utils::{TestRng, test_rng};

#[test]
fn roundtrip() {
    let mut rng = test_rng();
    for _ in 0..16 {
        let (dk, ek) = MlKem768.generate(&mut rng);
        let ek = EncapsulationKey::decode(ek.encode()).unwrap();
        let (ct, sent) = MlKem768.encapsulate(&mut rng, &ek).unwrap();
        let ct = Ciphertext::decode(ct.encode()).unwrap();
        let received = MlKem768.decapsulate(dk, &ct).unwrap();
        assert_eq!(sent, received);
    }
}

#[test]
fn determinism() {
    let mut rng_a = TestRng::new(42);
    let mut rng_b = TestRng::new(42);
    let (dk_a, ek_a) = MlKem768.generate(&mut rng_a);
    let (dk_b, ek_b) = MlKem768.generate(&mut rng_b);
    assert_eq!(dk_a, dk_b);
    assert_eq!(ek_a, ek_b);
    let (ct_a, shared_a) = MlKem768.encapsulate(&mut rng_a, &ek_a).unwrap();
    let (ct_b, shared_b) = MlKem768.encapsulate(&mut rng_b, &ek_b).unwrap();
    assert_eq!(ct_a, ct_b);
    assert_eq!(shared_a, shared_b);
    assert_eq!(MlKem768.decapsulate(dk_a, &ct_a).unwrap(), shared_a);
    assert_eq!(MlKem768.decapsulate(dk_b, &ct_b).unwrap(), shared_b);
    assert_ne!(MlKem768.generate(&mut rng_a).1, ek_a);
}

#[test]
fn tampered_ciphertext_implicit_rejection() {
    let mut rng = test_rng();
    let (dk, ek) = MlKem768.generate(&mut rng);
    let (ct, shared) = MlKem768.encapsulate(&mut rng, &ek).unwrap();
    let mut raw = ct.encode().to_vec();
    raw[0] ^= 1;
    let ct = Ciphertext::decode(raw).unwrap();
    let rejected_a = MlKem768.decapsulate(dk.clone(), &ct).unwrap();
    let rejected_b = MlKem768.decapsulate(dk, &ct).unwrap();
    assert_ne!(shared, rejected_a);
    assert_eq!(rejected_a, rejected_b);
}

#[test]
fn malformed_modulus() {
    let (_, ek) = MlKem768.generate(test_rng());

    // The first 12-bit coefficient is 3329, the field modulus.
    let mut raw = ek.encode().to_vec();
    raw[0] = 0x01;
    raw[1] = (raw[1] & 0xf0) | 0x0d;
    assert!(matches!(
        EncapsulationKey::decode(Copying(&raw[..])),
        Err(CodecError::Invalid(_, _))
    ));

    let raw = [0xff; EncapsulationKey::SIZE];
    assert!(EncapsulationKey::decode(Copying(&raw[..])).is_err());
}

#[test]
fn wrong_lengths() {
    let mut rng = test_rng();
    let (_, ek) = MlKem768.generate(&mut rng);
    let (ct, _) = MlKem768.encapsulate(&mut rng, &ek).unwrap();

    for length in [0, 1, EncapsulationKey::SIZE - 1] {
        assert!(matches!(
            EncapsulationKey::decode(Copying(&ek.as_ref()[..length])),
            Err(CodecError::EndOfBuffer)
        ));
    }
    for length in [0, 1, Ciphertext::SIZE - 1] {
        assert!(matches!(
            Ciphertext::decode(Copying(&ct.as_ref()[..length])),
            Err(CodecError::EndOfBuffer)
        ));
    }

    let mut raw = ek.encode().to_vec();
    raw.push(0);
    assert!(matches!(
        EncapsulationKey::decode(raw),
        Err(CodecError::ExtraData(1))
    ));
    let mut raw = ct.encode().to_vec();
    raw.push(0);
    assert!(matches!(
        Ciphertext::decode(raw),
        Err(CodecError::ExtraData(1))
    ));
}

#[test]
fn modulus_check_accepts_boundary_values() {
    // 3328 is the largest canonical coefficient; zero coefficients are also valid.
    let mut raw = [0u8; EncapsulationKey::SIZE];
    raw[1] = 0x0d;
    let ek = EncapsulationKey::decode(Copying(&raw[..])).unwrap();
    assert_eq!(ek.as_ref(), raw);
    assert_eq!(ek, EncapsulationKey::decode(ek.encode()).unwrap());
}

#[cfg(feature = "arbitrary")]
mod conformance {
    use super::*;
    use commonware_codec::conformance::CodecConformance;

    commonware_conformance::conformance_tests! {
        CodecConformance<EncapsulationKey>,
        CodecConformance<Ciphertext>,
    }
}
