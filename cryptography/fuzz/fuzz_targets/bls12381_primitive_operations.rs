#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_codec::{ReadExt, Write};
use commonware_cryptography::bls12381::primitives::{
    group::{Private, Scalar, Share, G1, G1_MESSAGE, G2, G2_MESSAGE},
    ops::*,
    variant::{MinPk, MinSig, Variant},
};
use commonware_math::{
    algebra::{Additive, CryptoGroup, Field, HashToGroup, Ring, Space},
    poly::Poly,
};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};

#[derive(Debug, Clone)]
enum FuzzOperation {
    // Scalar operations
    ScalarArithmetic {
        a: Scalar,
        b: Scalar,
    },
    ScalarSubtraction {
        a: Scalar,
        b: Scalar,
    },
    ScalarInverse {
        scalar: Scalar,
    },
    // Point operations (G1)
    G1Arithmetic {
        a: G1,
        b: G1,
    },
    G1ScalarMul {
        point: G1,
        scalar: Scalar,
    },
    G1Msm {
        points: Vec<G1>,
        scalars: Vec<Scalar>,
    },
    G1HashToPoint {
        message: Vec<u8>,
    },

    // Point operations (G2)
    G2Arithmetic {
        a: G2,
        b: G2,
    },
    G2ScalarMul {
        point: G2,
        scalar: Scalar,
    },
    G2Msm {
        points: Vec<G2>,
        scalars: Vec<Scalar>,
    },
    G2HashToPoint {
        message: Vec<u8>,
    },

    // Key operations
    KeypairGeneration,
    ComputePublicKey {
        private: Scalar,
    },
    SharePublicKey {
        share: Share,
        use_minpk: bool,
    },

    // Hash operations
    HashMessage {
        message: Vec<u8>,
        use_minpk: bool,
    },
    HashMessageNamespace {
        namespace: Vec<u8>,
        message: Vec<u8>,
        use_minpk: bool,
    },

    // Single signature operations
    SignMinPk {
        private: Scalar,
        message: Vec<u8>,
    },
    SignMinPkWithNamespace {
        private: Scalar,
        namespace: Vec<u8>,
        message: Vec<u8>,
    },
    SignMinPkLowLevel {
        private: Scalar,
        message: Vec<u8>,
    },
    VerifyMinPk {
        public: G1,
        message: Vec<u8>,
        signature: G2,
    },
    VerifyMinPkWithNamespace {
        public: G1,
        namespace: Vec<u8>,
        message: Vec<u8>,
        signature: G2,
    },
    VerifyMinPkLowLevel {
        public: G1,
        message: Vec<u8>,
        signature: G2,
    },
    SignMinSig {
        private: Scalar,
        message: Vec<u8>,
    },
    SignMinSigWithNamespace {
        private: Scalar,
        namespace: Vec<u8>,
        message: Vec<u8>,
    },
    SignMinSigLowLevel {
        private: Scalar,
        message: Vec<u8>,
    },
    VerifyMinSig {
        public: G2,
        message: Vec<u8>,
        signature: G1,
    },
    VerifyMinSigWithNamespace {
        public: G2,
        namespace: Vec<u8>,
        message: Vec<u8>,
        signature: G1,
    },
    VerifyMinSigLowLevel {
        public: G2,
        message: Vec<u8>,
        signature: G1,
    },

    // Proof of possession
    SignProofOfPossessionMinPk {
        private: Private,
    },
    VerifyProofOfPossessionMinPk {
        public: G1,
        signature: G2,
    },
    SignProofOfPossessionMinSig {
        private: Private,
    },
    VerifyProofOfPossessionMinSig {
        public: G2,
        signature: G1,
    },

    // Partial signature operations - simplified
    PartialSignMessage {
        share: Share,
        message: Vec<u8>,
        use_minpk: bool,
    },

    // Polynomial operations
    PolyAdd {
        a: Poly<Scalar>,
        b: Poly<Scalar>,
    },
    PolyCommit {
        scalar_poly: Poly<Scalar>,
        use_g1: bool,
    },

    // Simple aggregate operations
    AggregatePublicKeysG1 {
        keys: Vec<G1>,
    },
    AggregatePublicKeysG2 {
        keys: Vec<G2>,
    },
    AggregateSignaturesG1 {
        sigs: Vec<G1>,
    },
    AggregateSignaturesG2 {
        sigs: Vec<G2>,
    },

    // Serialization round-trip
    SerializeScalar {
        scalar: Scalar,
    },
    SerializeG1 {
        point: G1,
    },
    SerializeG2 {
        point: G2,
    },
    SerializeShare {
        share: Share,
    },
}

impl<'a> Arbitrary<'a> for FuzzOperation {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
        let choice = u.int_in_range(0..=42)?;

        match choice {
            0 => Ok(FuzzOperation::ScalarArithmetic {
                a: arbitrary_scalar(u)?,
                b: arbitrary_scalar(u)?,
            }),
            1 => Ok(FuzzOperation::ScalarSubtraction {
                a: arbitrary_scalar(u)?,
                b: arbitrary_scalar(u)?,
            }),
            2 => Ok(FuzzOperation::ScalarInverse {
                scalar: arbitrary_scalar(u)?,
            }),
            3 => Ok(FuzzOperation::G1Arithmetic {
                a: arbitrary_g1(u)?,
                b: arbitrary_g1(u)?,
            }),
            4 => Ok(FuzzOperation::G1ScalarMul {
                point: arbitrary_g1(u)?,
                scalar: arbitrary_scalar(u)?,
            }),
            5 => Ok(FuzzOperation::G1Msm {
                points: arbitrary_vec_g1(u, 0, 10)?,
                scalars: arbitrary_vec_scalar(u, 0, 10)?,
            }),
            6 => Ok(FuzzOperation::G1HashToPoint {
                message: arbitrary_bytes(u, 0, 100)?,
            }),
            7 => Ok(FuzzOperation::G2Arithmetic {
                a: arbitrary_g2(u)?,
                b: arbitrary_g2(u)?,
            }),
            8 => Ok(FuzzOperation::G2ScalarMul {
                point: arbitrary_g2(u)?,
                scalar: arbitrary_scalar(u)?,
            }),
            9 => Ok(FuzzOperation::G2Msm {
                points: arbitrary_vec_g2(u, 0, 10)?,
                scalars: arbitrary_vec_scalar(u, 0, 10)?,
            }),
            10 => Ok(FuzzOperation::G2HashToPoint {
                message: arbitrary_bytes(u, 0, 100)?,
            }),
            11 => Ok(FuzzOperation::KeypairGeneration),
            12 => Ok(FuzzOperation::ComputePublicKey {
                private: arbitrary_scalar(u)?,
            }),
            13 => Ok(FuzzOperation::SharePublicKey {
                share: arbitrary_share(u)?,
                use_minpk: u.arbitrary()?,
            }),
            14 => Ok(FuzzOperation::HashMessage {
                message: arbitrary_bytes(u, 0, 100)?,
                use_minpk: u.arbitrary()?,
            }),
            15 => Ok(FuzzOperation::HashMessageNamespace {
                namespace: arbitrary_bytes(u, 0, 50)?,
                message: arbitrary_bytes(u, 0, 100)?,
                use_minpk: u.arbitrary()?,
            }),
            16 => Ok(FuzzOperation::SignMinPk {
                private: arbitrary_scalar(u)?,
                message: arbitrary_bytes(u, 0, 100)?,
            }),
            17 => Ok(FuzzOperation::SignMinPkWithNamespace {
                private: arbitrary_scalar(u)?,
                namespace: arbitrary_bytes(u, 0, 50)?,
                message: arbitrary_bytes(u, 0, 100)?,
            }),
            18 => Ok(FuzzOperation::SignMinPkLowLevel {
                private: arbitrary_scalar(u)?,
                message: arbitrary_bytes(u, 0, 100)?,
            }),
            19 => Ok(FuzzOperation::VerifyMinPk {
                public: arbitrary_g1(u)?,
                message: arbitrary_bytes(u, 0, 100)?,
                signature: arbitrary_g2(u)?,
            }),
            20 => Ok(FuzzOperation::VerifyMinPkWithNamespace {
                public: arbitrary_g1(u)?,
                namespace: arbitrary_bytes(u, 0, 50)?,
                message: arbitrary_bytes(u, 0, 100)?,
                signature: arbitrary_g2(u)?,
            }),
            21 => Ok(FuzzOperation::VerifyMinPkLowLevel {
                public: arbitrary_g1(u)?,
                message: arbitrary_bytes(u, 0, 100)?,
                signature: arbitrary_g2(u)?,
            }),
            22 => Ok(FuzzOperation::SignMinSig {
                private: arbitrary_scalar(u)?,
                message: arbitrary_bytes(u, 0, 100)?,
            }),
            23 => Ok(FuzzOperation::SignMinSigWithNamespace {
                private: arbitrary_scalar(u)?,
                namespace: arbitrary_bytes(u, 0, 50)?,
                message: arbitrary_bytes(u, 0, 100)?,
            }),
            24 => Ok(FuzzOperation::SignMinSigLowLevel {
                private: arbitrary_scalar(u)?,
                message: arbitrary_bytes(u, 0, 100)?,
            }),
            25 => Ok(FuzzOperation::VerifyMinSig {
                public: arbitrary_g2(u)?,
                message: arbitrary_bytes(u, 0, 100)?,
                signature: arbitrary_g1(u)?,
            }),
            26 => Ok(FuzzOperation::VerifyMinSigWithNamespace {
                public: arbitrary_g2(u)?,
                namespace: arbitrary_bytes(u, 0, 50)?,
                message: arbitrary_bytes(u, 0, 100)?,
                signature: arbitrary_g1(u)?,
            }),
            27 => Ok(FuzzOperation::VerifyMinSigLowLevel {
                public: arbitrary_g2(u)?,
                message: arbitrary_bytes(u, 0, 100)?,
                signature: arbitrary_g1(u)?,
            }),
            28 => Ok(FuzzOperation::SignProofOfPossessionMinPk {
                private: arbitrary_scalar(u)?,
            }),
            29 => Ok(FuzzOperation::VerifyProofOfPossessionMinPk {
                public: arbitrary_g1(u)?,
                signature: arbitrary_g2(u)?,
            }),
            30 => Ok(FuzzOperation::SignProofOfPossessionMinSig {
                private: arbitrary_scalar(u)?,
            }),
            31 => Ok(FuzzOperation::VerifyProofOfPossessionMinSig {
                public: arbitrary_g2(u)?,
                signature: arbitrary_g1(u)?,
            }),
            32 => Ok(FuzzOperation::PartialSignMessage {
                share: arbitrary_share(u)?,
                message: arbitrary_bytes(u, 0, 100)?,
                use_minpk: u.arbitrary()?,
            }),
            33 => Ok(FuzzOperation::PolyAdd {
                a: arbitrary_poly_scalar(u)?,
                b: arbitrary_poly_scalar(u)?,
            }),
            34 => Ok(FuzzOperation::PolyCommit {
                scalar_poly: arbitrary_poly_scalar(u)?,
                use_g1: u.arbitrary()?,
            }),
            35 => Ok(FuzzOperation::AggregatePublicKeysG1 {
                keys: arbitrary_vec_g1(u, 0, 10)?,
            }),
            36 => Ok(FuzzOperation::AggregatePublicKeysG2 {
                keys: arbitrary_vec_g2(u, 0, 10)?,
            }),
            37 => Ok(FuzzOperation::AggregateSignaturesG1 {
                sigs: arbitrary_vec_g1(u, 0, 10)?,
            }),
            38 => Ok(FuzzOperation::AggregateSignaturesG2 {
                sigs: arbitrary_vec_g2(u, 0, 10)?,
            }),
            39 => Ok(FuzzOperation::SerializeScalar {
                scalar: arbitrary_scalar(u)?,
            }),
            40 => Ok(FuzzOperation::SerializeG1 {
                point: arbitrary_g1(u)?,
            }),
            41 => Ok(FuzzOperation::SerializeG2 {
                point: arbitrary_g2(u)?,
            }),
            42 => Ok(FuzzOperation::SerializeShare {
                share: arbitrary_share(u)?,
            }),
            _ => Ok(FuzzOperation::KeypairGeneration),
        }
    }
}

fn arbitrary_scalar(u: &mut Unstructured) -> Result<Scalar, arbitrary::Error> {
    u.arbitrary()
}

fn arbitrary_g1(u: &mut Unstructured) -> Result<G1, arbitrary::Error> {
    let bytes: [u8; 48] = u.arbitrary()?;

    match G1::read(&mut bytes.as_slice()) {
        Ok(point) => Ok(point),
        Err(_) => {
            if u.arbitrary()? {
                Ok(G1::zero())
            } else {
                Ok(G1::generator())
            }
        }
    }
}

fn arbitrary_g2(u: &mut Unstructured) -> Result<G2, arbitrary::Error> {
    let bytes: [u8; 96] = u.arbitrary()?;

    match G2::read(&mut bytes.as_slice()) {
        Ok(point) => Ok(point),
        Err(_) => {
            if u.arbitrary()? {
                Ok(G2::zero())
            } else {
                Ok(G2::generator())
            }
        }
    }
}

fn arbitrary_share(u: &mut Unstructured) -> Result<Share, arbitrary::Error> {
    Ok(Share {
        index: u.int_in_range(1..=100)?,
        private: arbitrary_scalar(u)?,
    })
}

fn arbitrary_poly_scalar(u: &mut Unstructured) -> Result<Poly<Scalar>, arbitrary::Error> {
    let degree = u.int_in_range(0..=10)?;
    let seed: [u8; 32] = u.arbitrary()?;
    let constant = arbitrary_scalar(u)?;
    let mut rng = StdRng::from_seed(seed);
    Ok(Poly::new_with_constant(&mut rng, degree, constant))
}

fn arbitrary_vec_scalar(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<Scalar>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    (0..len).map(|_| arbitrary_scalar(u)).collect()
}

fn arbitrary_vec_g1(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<G1>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    (0..len).map(|_| arbitrary_g1(u)).collect()
}

fn arbitrary_vec_g2(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<G2>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    (0..len).map(|_| arbitrary_g2(u)).collect()
}

fn arbitrary_bytes(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<u8>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    u.bytes(len).map(|b| b.to_vec())
}

fn fuzz(op: FuzzOperation) {
    match op {
        FuzzOperation::ScalarArithmetic { mut a, b } => {
            let mut a_clone = a.clone();
            a += &b;
            a_clone *= &b;
        }

        FuzzOperation::ScalarSubtraction { mut a, b } => {
            a -= &b;
        }

        FuzzOperation::ScalarInverse { scalar } => {
            let inv = scalar.inv();
            if scalar == Scalar::zero() {
                assert_eq!(inv, Scalar::zero());
            } else {
                assert_eq!(scalar * &inv, Scalar::one());
            }
        }

        FuzzOperation::G1Arithmetic { mut a, b } => {
            a += &b;
        }

        FuzzOperation::G1ScalarMul { mut point, scalar } => {
            point *= &scalar;
        }

        FuzzOperation::G1Msm { points, scalars } => {
            let len = points.len().min(scalars.len());
            if len > 0 {
                let _ = G1::msm(&points[..len], &scalars[..len], 1);
            }
        }

        FuzzOperation::G1HashToPoint { message } => {
            let _ = G1::hash_to_group(G1_MESSAGE, &message);
        }

        FuzzOperation::G2Arithmetic { mut a, b } => {
            a += &b;
        }

        FuzzOperation::G2ScalarMul { mut point, scalar } => {
            point *= &scalar;
        }

        FuzzOperation::G2Msm { points, scalars } => {
            let len = points.len().min(scalars.len());
            if len > 0 {
                let _ = G2::msm(&points[..len], &scalars[..len], 1);
            }
        }

        FuzzOperation::G2HashToPoint { message } => {
            let _ = G2::hash_to_group(G2_MESSAGE, &message);
        }

        FuzzOperation::KeypairGeneration => {
            // Skip RNG operations that require external crates in fuzzing
        }

        FuzzOperation::ComputePublicKey { private } => {
            let _pub_pk: G1 = compute_public::<MinPk>(&private);
            let _pub_sig: G2 = compute_public::<MinSig>(&private);
        }

        FuzzOperation::SharePublicKey { share, use_minpk } => {
            if use_minpk {
                let _: G1 = share.public::<MinPk>();
            } else {
                let _: G2 = share.public::<MinSig>();
            }
        }

        FuzzOperation::HashMessage { message, use_minpk } => {
            if use_minpk {
                let _: G2 = hash_message::<MinPk>(MinPk::MESSAGE, &message);
            } else {
                let _: G1 = hash_message::<MinSig>(MinSig::MESSAGE, &message);
            }
        }

        FuzzOperation::HashMessageNamespace {
            namespace,
            message,
            use_minpk,
        } => {
            if use_minpk {
                let _: G2 = hash_message_namespace::<MinPk>(MinPk::MESSAGE, &namespace, &message);
            } else {
                let _: G1 = hash_message_namespace::<MinSig>(MinSig::MESSAGE, &namespace, &message);
            }
        }

        FuzzOperation::SignMinPk { private, message } => {
            let sig = sign_message::<MinPk>(&private, None, &message);
            let pub_key = compute_public::<MinPk>(&private);
            let _ = verify_message::<MinPk>(&pub_key, None, &message, &sig);
        }

        FuzzOperation::SignMinPkWithNamespace {
            private,
            namespace,
            message,
        } => {
            let sig = sign_message::<MinPk>(&private, Some(&namespace), &message);
            let pub_key = compute_public::<MinPk>(&private);
            let _ = verify_message::<MinPk>(&pub_key, Some(&namespace), &message, &sig);
        }

        FuzzOperation::SignMinPkLowLevel { private, message } => {
            // Use built-in DST instead of arbitrary bytes
            let sig = sign::<MinPk>(&private, MinPk::MESSAGE, &message);
            let pub_key = compute_public::<MinPk>(&private);
            let _ = verify::<MinPk>(&pub_key, MinPk::MESSAGE, &message, &sig);
        }

        FuzzOperation::VerifyMinPk {
            public,
            message,
            signature,
        } => {
            let _ = verify_message::<MinPk>(&public, None, &message, &signature);
        }

        FuzzOperation::VerifyMinPkWithNamespace {
            public,
            namespace,
            message,
            signature,
        } => {
            let _ = verify_message::<MinPk>(&public, Some(&namespace), &message, &signature);
        }

        FuzzOperation::VerifyMinPkLowLevel {
            public,
            message,
            signature,
        } => {
            // Use built-in DST instead of arbitrary bytes
            let _ = verify::<MinPk>(&public, MinPk::MESSAGE, &message, &signature);
        }

        FuzzOperation::SignMinSig { private, message } => {
            let sig = sign_message::<MinSig>(&private, None, &message);
            let pub_key = compute_public::<MinSig>(&private);
            let _ = verify_message::<MinSig>(&pub_key, None, &message, &sig);
        }

        FuzzOperation::SignMinSigWithNamespace {
            private,
            namespace,
            message,
        } => {
            let sig = sign_message::<MinSig>(&private, Some(&namespace), &message);
            let pub_key = compute_public::<MinSig>(&private);
            let _ = verify_message::<MinSig>(&pub_key, Some(&namespace), &message, &sig);
        }

        FuzzOperation::SignMinSigLowLevel { private, message } => {
            // Use built-in DST instead of arbitrary bytes
            let sig = sign::<MinSig>(&private, MinSig::MESSAGE, &message);
            let pub_key = compute_public::<MinSig>(&private);
            let _ = verify::<MinSig>(&pub_key, MinSig::MESSAGE, &message, &sig);
        }

        FuzzOperation::VerifyMinSig {
            public,
            message,
            signature,
        } => {
            let _ = verify_message::<MinSig>(&public, None, &message, &signature);
        }

        FuzzOperation::VerifyMinSigWithNamespace {
            public,
            namespace,
            message,
            signature,
        } => {
            let _ = verify_message::<MinSig>(&public, Some(&namespace), &message, &signature);
        }

        FuzzOperation::VerifyMinSigLowLevel {
            public,
            message,
            signature,
        } => {
            // Use built-in DST instead of arbitrary bytes
            let _ = verify::<MinSig>(&public, MinSig::MESSAGE, &message, &signature);
        }

        FuzzOperation::SignProofOfPossessionMinPk { private } => {
            let sig = sign_proof_of_possession::<MinPk>(&private);
            let pub_key = compute_public::<MinPk>(&private);
            let _ = verify_proof_of_possession::<MinPk>(&pub_key, &sig);
        }

        FuzzOperation::VerifyProofOfPossessionMinPk { public, signature } => {
            let _ = verify_proof_of_possession::<MinPk>(&public, &signature);
        }

        FuzzOperation::SignProofOfPossessionMinSig { private } => {
            let sig = sign_proof_of_possession::<MinSig>(&private);
            let pub_key = compute_public::<MinSig>(&private);
            let _ = verify_proof_of_possession::<MinSig>(&pub_key, &sig);
        }

        FuzzOperation::VerifyProofOfPossessionMinSig { public, signature } => {
            let _ = verify_proof_of_possession::<MinSig>(&public, &signature);
        }

        FuzzOperation::PartialSignMessage {
            share,
            message,
            use_minpk,
        } => {
            if use_minpk {
                let _ = partial_sign_message::<MinPk>(&share, None, &message);
            } else {
                let _ = partial_sign_message::<MinSig>(&share, None, &message);
            }
        }

        FuzzOperation::PolyAdd { a, b } => {
            let _ = a + &b;
        }

        FuzzOperation::PolyCommit {
            scalar_poly,
            use_g1,
        } => {
            if use_g1 {
                let _ = Poly::<G1>::commit(scalar_poly);
            } else {
                let _ = Poly::<G2>::commit(scalar_poly);
            }
        }

        FuzzOperation::AggregatePublicKeysG1 { keys } => {
            let _ = aggregate_public_keys::<MinPk, _>(&keys);
        }

        FuzzOperation::AggregatePublicKeysG2 { keys } => {
            let _ = aggregate_public_keys::<MinSig, _>(&keys);
        }

        FuzzOperation::AggregateSignaturesG1 { sigs } => {
            let _ = aggregate_signatures::<MinSig, _>(&sigs);
        }

        FuzzOperation::AggregateSignaturesG2 { sigs } => {
            let _ = aggregate_signatures::<MinPk, _>(&sigs);
        }

        FuzzOperation::SerializeScalar { scalar } => {
            let mut encoded = Vec::new();
            scalar.write(&mut encoded);
            if let Ok(decoded) = Scalar::read(&mut encoded.as_slice()) {
                assert_eq!(scalar, decoded);
            }
        }

        FuzzOperation::SerializeG1 { point } => {
            let mut encoded = Vec::new();
            point.write(&mut encoded);
            if let Ok(decoded) = G1::read(&mut encoded.as_slice()) {
                assert_eq!(point, decoded);
            }
        }

        FuzzOperation::SerializeG2 { point } => {
            let mut encoded = Vec::new();
            point.write(&mut encoded);
            if let Ok(decoded) = G2::read(&mut encoded.as_slice()) {
                assert_eq!(point, decoded);
            }
        }

        FuzzOperation::SerializeShare { share } => {
            let mut encoded = Vec::new();
            share.write(&mut encoded);
            if let Ok(decoded) = Share::read(&mut encoded.as_slice()) {
                assert_eq!(share, decoded);
            }
        }
    }
}

fuzz_target!(|ops: Vec<FuzzOperation>| {
    for op in ops {
        fuzz(op);
    }
});
