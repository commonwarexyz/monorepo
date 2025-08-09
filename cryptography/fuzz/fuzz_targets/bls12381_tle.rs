#![no_main]

mod common;

use arbitrary::{Arbitrary, Unstructured};
use common::{
    arbitrary_ciphertext_minpk, arbitrary_ciphertext_minsig, arbitrary_minpk_signature,
    arbitrary_minsig_signature,
};
use commonware_codec::ReadExt;
use commonware_cryptography::bls12381::{
    primitives::{
        group::Scalar,
        ops::{compute_public, sign_message},
        variant::{MinPk, MinSig, Variant},
    },
    tle::{decrypt, encrypt, Block, Ciphertext},
};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};

type Message = (Option<Vec<u8>>, Vec<u8>);

#[derive(Debug, Clone)]
enum FuzzOperation {
    EncryptDecryptMinPk {
        master_secret: Scalar,
        target: Vec<u8>,
        message: [u8; 32],
        rng_seed: u64,
    },
    EncryptDecryptMinSig {
        master_secret: Scalar,
        target: Vec<u8>,
        message: [u8; 32],
        rng_seed: u64,
    },
    EncryptDecryptWithNamespaceMinPk {
        master_secret: Scalar,
        namespace: Vec<u8>,
        target: Vec<u8>,
        message: [u8; 32],
        rng_seed: u64,
    },
    EncryptDecryptWithNamespaceMinSig {
        master_secret: Scalar,
        namespace: Vec<u8>,
        target: Vec<u8>,
        message: [u8; 32],
        rng_seed: u64,
    },
    DecryptWithWrongKeyMinPk {
        master_secret1: Scalar,
        master_secret2: Scalar,
        target: Vec<u8>,
        message: [u8; 32],
        rng_seed: u64,
    },
    DecryptWithWrongKeyMinSig {
        master_secret1: Scalar,
        master_secret2: Scalar,
        target: Vec<u8>,
        message: [u8; 32],
        rng_seed: u64,
    },
    TamperedCiphertextMinPk {
        master_secret: Scalar,
        target: Vec<u8>,
        message: [u8; 32],
        tamper_index: usize,
        tamper_value: u8,
        rng_seed: u64,
    },
    TamperedCiphertextMinSig {
        master_secret: Scalar,
        target: Vec<u8>,
        message: [u8; 32],
        tamper_index: usize,
        tamper_value: u8,
        rng_seed: u64,
    },
    DecryptArbitraryMinPk {
        signature: <MinPk as Variant>::Signature,
        ciphertext: Ciphertext<MinPk>,
    },
    DecryptArbitraryMinSig {
        signature: <MinSig as Variant>::Signature,
        ciphertext: Ciphertext<MinSig>,
    },
}

impl<'a> Arbitrary<'a> for FuzzOperation {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
        let choice = u.int_in_range(0..=9)?;

        match choice {
            0 => Ok(FuzzOperation::EncryptDecryptMinPk {
                master_secret: common::arbitrary_scalar(u)?,
                target: common::arbitrary_bytes(u, 0, 100)?,
                message: u.arbitrary()?,
                rng_seed: u.arbitrary()?,
            }),
            1 => Ok(FuzzOperation::EncryptDecryptMinSig {
                master_secret: common::arbitrary_scalar(u)?,
                target: common::arbitrary_bytes(u, 0, 100)?,
                message: u.arbitrary()?,
                rng_seed: u.arbitrary()?,
            }),
            2 => Ok(FuzzOperation::EncryptDecryptWithNamespaceMinPk {
                master_secret: common::arbitrary_scalar(u)?,
                namespace: common::arbitrary_bytes(u, 0, 50)?,
                target: common::arbitrary_bytes(u, 0, 100)?,
                message: u.arbitrary()?,
                rng_seed: u.arbitrary()?,
            }),
            3 => Ok(FuzzOperation::EncryptDecryptWithNamespaceMinSig {
                master_secret: common::arbitrary_scalar(u)?,
                namespace: common::arbitrary_bytes(u, 0, 50)?,
                target: common::arbitrary_bytes(u, 0, 100)?,
                message: u.arbitrary()?,
                rng_seed: u.arbitrary()?,
            }),
            4 => Ok(FuzzOperation::DecryptWithWrongKeyMinPk {
                master_secret1: common::arbitrary_scalar(u)?,
                master_secret2: common::arbitrary_scalar(u)?,
                target: common::arbitrary_bytes(u, 0, 100)?,
                message: u.arbitrary()?,
                rng_seed: u.arbitrary()?,
            }),
            5 => Ok(FuzzOperation::DecryptWithWrongKeyMinSig {
                master_secret1: common::arbitrary_scalar(u)?,
                master_secret2: common::arbitrary_scalar(u)?,
                target: common::arbitrary_bytes(u, 0, 100)?,
                message: u.arbitrary()?,
                rng_seed: u.arbitrary()?,
            }),
            6 => Ok(FuzzOperation::TamperedCiphertextMinPk {
                master_secret: common::arbitrary_scalar(u)?,
                target: common::arbitrary_bytes(u, 0, 100)?,
                message: u.arbitrary()?,
                tamper_index: u.int_in_range(0..=95)?,
                tamper_value: u.arbitrary()?,
                rng_seed: u.arbitrary()?,
            }),
            7 => Ok(FuzzOperation::TamperedCiphertextMinSig {
                master_secret: common::arbitrary_scalar(u)?,
                target: common::arbitrary_bytes(u, 0, 100)?,
                message: u.arbitrary()?,
                tamper_index: u.int_in_range(0..=95)?,
                tamper_value: u.arbitrary()?,
                rng_seed: u.arbitrary()?,
            }),
            8 => Ok(FuzzOperation::DecryptArbitraryMinPk {
                signature: arbitrary_minpk_signature(u)?,
                ciphertext: arbitrary_ciphertext_minpk(u)?,
            }),
            9 => Ok(FuzzOperation::DecryptArbitraryMinSig {
                signature: arbitrary_minsig_signature(u)?,
                ciphertext: arbitrary_ciphertext_minsig(u)?,
            }),
            _ => unreachable!(),
        }
    }
}

fn fuzz(op: FuzzOperation) {
    match op {
        FuzzOperation::EncryptDecryptMinPk {
            master_secret,
            target,
            message,
            rng_seed,
        } => {
            let master_public = compute_public::<MinPk>(&master_secret);
            let message_block = Block::new(message);

            let mut rng = StdRng::seed_from_u64(rng_seed);
            let ciphertext =
                encrypt::<_, MinPk>(&mut rng, master_public, (None, &target), &message_block);

            let signature = sign_message::<MinPk>(&master_secret, None, &target);
            let decrypted = decrypt::<MinPk>(&signature, &ciphertext);

            if let Some(decrypted_block) = decrypted {
                assert_eq!(message_block, decrypted_block);
            } else {
                panic!("Decryption failed for valid ciphertext");
            }
        }

        FuzzOperation::EncryptDecryptMinSig {
            master_secret,
            target,
            message,
            rng_seed,
        } => {
            let master_public = compute_public::<MinSig>(&master_secret);
            let message_block = Block::new(message);

            let mut rng = StdRng::seed_from_u64(rng_seed);
            let ciphertext =
                encrypt::<_, MinSig>(&mut rng, master_public, (None, &target), &message_block);

            let signature = sign_message::<MinSig>(&master_secret, None, &target);
            let decrypted = decrypt::<MinSig>(&signature, &ciphertext);

            if let Some(decrypted_block) = decrypted {
                assert_eq!(message_block, decrypted_block);
            } else {
                panic!("Decryption failed for valid ciphertext");
            }
        }

        FuzzOperation::EncryptDecryptWithNamespaceMinPk {
            master_secret,
            namespace,
            target,
            message,
            rng_seed,
        } => {
            let master_public = compute_public::<MinPk>(&master_secret);
            let message_block = Block::new(message);

            let mut rng = StdRng::seed_from_u64(rng_seed);
            let ciphertext = encrypt::<_, MinPk>(
                &mut rng,
                master_public,
                (Some(&namespace), &target),
                &message_block,
            );

            let signature = sign_message::<MinPk>(&master_secret, Some(&namespace), &target);
            let decrypted = decrypt::<MinPk>(&signature, &ciphertext);

            if let Some(decrypted_block) = decrypted {
                assert_eq!(message_block, decrypted_block);
            } else {
                panic!("Decryption failed for valid ciphertext with namespace");
            }
        }

        FuzzOperation::EncryptDecryptWithNamespaceMinSig {
            master_secret,
            namespace,
            target,
            message,
            rng_seed,
        } => {
            let master_public = compute_public::<MinSig>(&master_secret);
            let message_block = Block::new(message);

            let mut rng = StdRng::seed_from_u64(rng_seed);
            let ciphertext = encrypt::<_, MinSig>(
                &mut rng,
                master_public,
                (Some(&namespace), &target),
                &message_block,
            );

            let signature = sign_message::<MinSig>(&master_secret, Some(&namespace), &target);
            let decrypted = decrypt::<MinSig>(&signature, &ciphertext);

            if let Some(decrypted_block) = decrypted {
                assert_eq!(message_block, decrypted_block);
            } else {
                panic!("Decryption failed for valid ciphertext with namespace");
            }
        }

        FuzzOperation::DecryptWithWrongKeyMinPk {
            master_secret1,
            master_secret2,
            target,
            message,
            rng_seed,
        } => {
            let master_public1 = compute_public::<MinPk>(&master_secret1);
            let message_block = Block::new(message);

            let mut rng = StdRng::seed_from_u64(rng_seed);
            let ciphertext =
                encrypt::<_, MinPk>(&mut rng, master_public1, (None, &target), &message_block);

            let wrong_signature = sign_message::<MinPk>(&master_secret2, None, &target);
            let _ = decrypt::<MinPk>(&wrong_signature, &ciphertext);
        }

        FuzzOperation::DecryptWithWrongKeyMinSig {
            master_secret1,
            master_secret2,
            target,
            message,
            rng_seed,
        } => {
            let master_public1 = compute_public::<MinSig>(&master_secret1);
            let message_block = Block::new(message);

            let mut rng = StdRng::seed_from_u64(rng_seed);
            let ciphertext =
                encrypt::<_, MinSig>(&mut rng, master_public1, (None, &target), &message_block);

            let wrong_signature = sign_message::<MinSig>(&master_secret2, None, &target);
            let _ = decrypt::<MinSig>(&wrong_signature, &ciphertext);
        }

        FuzzOperation::TamperedCiphertextMinPk {
            master_secret,
            target,
            message,
            tamper_index,
            tamper_value,
            rng_seed,
        } => {
            let master_public = compute_public::<MinPk>(&master_secret);
            let message_block = Block::new(message);

            let mut rng = StdRng::seed_from_u64(rng_seed);
            let ciphertext =
                encrypt::<_, MinPk>(&mut rng, master_public, (None, &target), &message_block);

            let mut encoded = Vec::new();
            commonware_codec::Write::write(&ciphertext, &mut encoded);
            if tamper_index < encoded.len() {
                encoded[tamper_index] ^= tamper_value;
            }

            if let Ok(tampered) = Ciphertext::<MinPk>::read(&mut encoded.as_slice()) {
                let signature = sign_message::<MinPk>(&master_secret, None, &target);
                let _ = decrypt::<MinPk>(&signature, &tampered);
            }
        }

        FuzzOperation::TamperedCiphertextMinSig {
            master_secret,
            target,
            message,
            tamper_index,
            tamper_value,
            rng_seed,
        } => {
            let master_public = compute_public::<MinSig>(&master_secret);
            let message_block = Block::new(message);
            let mut rng = StdRng::seed_from_u64(rng_seed);

            let ciphertext =
                encrypt::<_, MinSig>(&mut rng, master_public, (None, &target), &message_block);

            let mut encoded = Vec::new();
            commonware_codec::Write::write(&ciphertext, &mut encoded);
            if tamper_index < encoded.len() {
                encoded[tamper_index] ^= tamper_value;
            }

            if let Ok(tampered) = Ciphertext::<MinSig>::read(&mut encoded.as_slice()) {
                let signature = sign_message::<MinSig>(&master_secret, None, &target);
                let _ = decrypt::<MinSig>(&signature, &tampered);
            }
        }

        FuzzOperation::DecryptArbitraryMinPk {
            signature,
            ciphertext,
        } => {
            let _ = decrypt::<MinPk>(&signature, &ciphertext);
        }

        FuzzOperation::DecryptArbitraryMinSig {
            signature,
            ciphertext,
        } => {
            let _ = decrypt::<MinSig>(&signature, &ciphertext);
        }
    }
}

fuzz_target!(|ops: Vec<FuzzOperation>| {
    for op in ops {
        fuzz(op);
    }
});
