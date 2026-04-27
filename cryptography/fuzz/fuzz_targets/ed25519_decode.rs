#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{
    ed25519::{PrivateKey, PublicKey, Signature},
    Signer, Verifier,
};
use commonware_utils::union_unique;
use ed25519_consensus::{
    Signature as ConsensusSignature, SigningKey as ConsensusPrivateKey,
    VerificationKey as ConsensusPublicKey,
};
use ed25519_zebra::{
    Signature as ZebraSignature, SigningKey as ZebraPrivateKey, VerificationKey as ZebraPublicKey,
    VerificationKeyBytes as ZebraPublicKeyBytes,
};
use libfuzzer_sys::fuzz_target;

#[derive(Debug)]
pub enum FuzzInput<'a> {
    PublicKey {
        pubkey: [u8; 32],
    },
    PublicKeyVariable {
        pubkey: &'a [u8],
    },
    Signature {
        signature: [u8; 64],
    },
    SignatureVariable {
        signature: &'a [u8],
    },
    Verification {
        pubkey: [u8; 32],
        signature: [u8; 64],
        namespace: &'a [u8],
        message: &'a [u8],
    },
    VerificationVariable {
        pubkey: &'a [u8],
        signature: &'a [u8],
        namespace: &'a [u8],
        message: &'a [u8],
    },
    Signing {
        seed: [u8; 32],
        namespace: &'a [u8],
        message: &'a [u8],
    },
}

impl<'a> Arbitrary<'a> for FuzzInput<'a> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut selector = [0];
        u.fill_buffer(&mut selector)?;
        let input = u.bytes(u.len())?;

        Ok(match selector[0] % 7 {
            // Fixed-size public key decode and canonical byte comparison.
            0 => Self::PublicKey {
                pubkey: fixed(input),
            },
            // Variable-size public key decode rejection and acceptance.
            1 => Self::PublicKeyVariable { pubkey: input },
            // Fixed-size signature decode and canonical byte comparison.
            2 => Self::Signature {
                signature: fixed(input),
            },
            // Variable-size signature decode rejection and acceptance.
            3 => Self::SignatureVariable { signature: input },
            // Verification agreement for padded fixed-size public key and signature bytes.
            4 => {
                let (namespace, message) = split_namespace_message(remainder(input, 96));
                Self::Verification {
                    pubkey: fixed(input),
                    signature: fixed(remainder(input, 32)),
                    namespace,
                    message,
                }
            }
            // Verification agreement for raw variable-size public key and signature bytes.
            5 => {
                let split = input.len().min(32);
                let (pubkey, rest) = input.split_at(split);
                let split = rest.len().min(64);
                let (signature, rest) = rest.split_at(split);
                let (namespace, message) = split_namespace_message(rest);
                Self::VerificationVariable {
                    pubkey,
                    signature,
                    namespace,
                    message,
                }
            }
            // Signing agreement from the same seed and domain-separated payload.
            6 => {
                let (namespace, message) = split_namespace_message(remainder(input, 32));
                Self::Signing {
                    seed: fixed(input),
                    namespace,
                    message,
                }
            }
            _ => unreachable!(),
        })
    }
}

fn fixed<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut output = [0; N];
    let len = bytes.len().min(N);
    output[..len].copy_from_slice(&bytes[..len]);
    output
}

fn remainder(bytes: &[u8], offset: usize) -> &[u8] {
    bytes.get(offset..).unwrap_or_default()
}

fn split_namespace_message(bytes: &[u8]) -> (&[u8], &[u8]) {
    let Some((&split, bytes)) = bytes.split_first() else {
        return (&[], &[]);
    };
    let split = (split as usize).min(bytes.len());
    bytes.split_at(split)
}

fn test_pubkey(pubkey: &[u8]) {
    let consensus_result = ConsensusPublicKey::try_from(pubkey);
    let zebra_result = ZebraPublicKey::try_from(pubkey);
    let our_result = PublicKey::decode(pubkey);

    // All implementations should agree on public key validity.
    assert_eq!(consensus_result.is_err(), our_result.is_err());
    assert_eq!(zebra_result.is_err(), our_result.is_err());

    // If all succeeded, check round-trip encoding.
    if let (Ok(consensus_key), Ok(zebra_key), Ok(our_key)) =
        (consensus_result, zebra_result, our_result)
    {
        let consensus_bytes = consensus_key.to_bytes().to_vec();
        let zebra_bytes = ZebraPublicKeyBytes::from(zebra_key).as_ref().to_vec();
        let our_bytes = our_key.encode().to_vec();
        assert_eq!(consensus_bytes, our_bytes);
        assert_eq!(zebra_bytes, our_bytes);
    }
}

fn test_signature(signature: &[u8]) {
    let consensus_result = ConsensusSignature::try_from(signature);
    let zebra_result = ZebraSignature::from_slice(signature);
    let our_result = Signature::decode(signature);

    // All implementations should agree on signature byte validity.
    assert_eq!(consensus_result.is_err(), our_result.is_err());
    assert_eq!(zebra_result.is_err(), our_result.is_err());

    // If all succeeded, check round-trip encoding.
    if let (Ok(consensus_signature), Ok(zebra_signature), Ok(our_signature)) =
        (consensus_result, zebra_result, our_result)
    {
        let consensus_bytes = consensus_signature.to_bytes().to_vec();
        let zebra_bytes = zebra_signature.to_bytes().to_vec();
        let our_bytes = our_signature.encode().to_vec();
        assert_eq!(consensus_bytes, our_bytes);
        assert_eq!(zebra_bytes, our_bytes);
    }
}

fn test_verification(pubkey: &[u8], signature: &[u8], namespace: &[u8], message: &[u8]) {
    let payload = union_unique(namespace, message);

    let consensus_result = match (
        ConsensusPublicKey::try_from(pubkey),
        ConsensusSignature::try_from(signature),
    ) {
        (Ok(public_key), Ok(signature)) => Some(public_key.verify(&signature, &payload).is_ok()),
        _ => None,
    };
    let zebra_result = match (
        ZebraPublicKey::try_from(pubkey),
        ZebraSignature::from_slice(signature),
    ) {
        (Ok(public_key), Ok(signature)) => Some(public_key.verify(&signature, &payload).is_ok()),
        _ => None,
    };
    let our_result = match (PublicKey::decode(pubkey), Signature::decode(signature)) {
        (Ok(public_key), Ok(signature)) => Some(public_key.verify(namespace, message, &signature)),
        _ => None,
    };

    // Decoding and verification should agree for arbitrary triples.
    assert_eq!(consensus_result, our_result);
    assert_eq!(zebra_result, our_result);
}

fn test_signing(seed: [u8; 32], namespace: &[u8], message: &[u8]) {
    let payload = union_unique(namespace, message);

    // Construct equivalent signing keys from the same raw seed.
    let consensus_private_key = ConsensusPrivateKey::from(seed);
    let zebra_private_key = ZebraPrivateKey::from(seed);
    let our_private_key = PrivateKey::decode(seed.as_ref()).unwrap();

    // The derived public keys should have identical encodings.
    let consensus_public_key = ConsensusPublicKey::from(&consensus_private_key);
    let zebra_public_key = ZebraPublicKey::from(&zebra_private_key);
    let our_public_key = our_private_key.public_key();

    assert_eq!(
        consensus_public_key.to_bytes().to_vec(),
        our_public_key.encode().to_vec()
    );
    assert_eq!(
        ZebraPublicKeyBytes::from(zebra_public_key).as_ref(),
        our_public_key.as_ref()
    );

    // Signing the same domain-separated payload should produce identical signatures.
    let consensus_signature = consensus_private_key.sign(&payload);
    let zebra_signature = zebra_private_key.sign(&payload);
    let our_signature = our_private_key.sign(namespace, message);

    assert_eq!(
        consensus_signature.to_bytes().to_vec(),
        our_signature.encode().to_vec()
    );
    assert_eq!(
        zebra_signature.to_bytes().to_vec(),
        our_signature.encode().to_vec()
    );

    // Each implementation should accept the signature it produced.
    assert!(consensus_public_key
        .verify(&consensus_signature, &payload)
        .is_ok());
    assert!(zebra_public_key.verify(&zebra_signature, &payload).is_ok());
    assert!(our_public_key.verify(namespace, message, &our_signature));
}

fn fuzz(input: FuzzInput<'_>) {
    match input {
        FuzzInput::PublicKey { pubkey } => test_pubkey(&pubkey),
        FuzzInput::PublicKeyVariable { pubkey } => test_pubkey(pubkey),
        FuzzInput::Signature { signature } => test_signature(&signature),
        FuzzInput::SignatureVariable { signature } => test_signature(signature),
        FuzzInput::Verification {
            pubkey,
            signature,
            namespace,
            message,
        } => test_verification(&pubkey, &signature, namespace, message),
        FuzzInput::VerificationVariable {
            pubkey,
            signature,
            namespace,
            message,
        } => test_verification(pubkey, signature, namespace, message),
        FuzzInput::Signing {
            seed,
            namespace,
            message,
        } => test_signing(seed, namespace, message),
    }
}

fuzz_target!(|input: FuzzInput<'_>| {
    fuzz(input);
});
