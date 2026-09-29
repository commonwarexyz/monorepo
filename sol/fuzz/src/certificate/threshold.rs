//! Seeded BLS12-381 threshold certificates.

use super::{BlsVariant, compact, compress, decode_hex, frame, pad, unpad};
use alloy_sol_macro::sol;
use alloy_sol_types::SolValue;
use clap::{Args, Subcommand};
use commonware_codec::DecodeExt;
use commonware_cryptography::bls12381::{
    dkg::feldman_desmedt,
    primitives::{
        ops::{self, threshold},
        sharing::Mode,
        variant::{MinPk, MinSig, Variant},
    },
};
use commonware_parallel::Sequential;
use commonware_utils::{N3f1, NZU32};
use rand::{SeedableRng, rngs::StdRng};

sol! {
    struct CertificateOutput {
        bytes signature;
        bytes public_key;
        bytes message;
        bytes hash_point;
    }
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Recover a 3-of-4 threshold signature for a namespace and message.
    Generate(GenerateArgs),
    /// Return ABI `bool` for a signature over a namespace and message.
    Check {
        #[arg(long, value_enum)]
        variant: BlsVariant,
        /// Hex-encoded public key.
        #[arg(long)]
        public_key: String,
        /// Hex-encoded namespace bytes.
        #[arg(long)]
        namespace: String,
        /// Hex-encoded message bytes.
        #[arg(long)]
        message: String,
        /// Hex-encoded signature.
        #[arg(long)]
        signature: String,
    },
}

#[derive(Args)]
pub(crate) struct GenerateArgs {
    #[arg(long, value_enum)]
    variant: BlsVariant,
    /// Hex-encoded namespace bytes.
    #[arg(long)]
    namespace: String,
    /// Hex-encoded message bytes.
    #[arg(long)]
    message: String,
    #[arg(long)]
    seed: u64,
}

/// ABI `(bytes signature, bytes publicKey, bytes message, bytes hashPoint)`.
/// Signatures use uncompressed 48-byte field elements (MinSig 96 bytes, MinPk 192).
/// Public keys and hash points pad each field to 64 bytes with 16 leading zeros.
/// Public keys are 256/128 bytes and hash points 128/256 bytes for MinSig/MinPk.
/// G2 coordinates are ordered x.c0, x.c1, y.c0, y.c1 throughout.
/// The message includes Commonware's namespace framing, whose length is a u32 varint.
/// Seeded shares model a local 3-of-4 quorum, without simulating a network or DKG.
pub(crate) struct Output {
    pub(crate) signature: Vec<u8>,
    pub(crate) public_key: Vec<u8>,
    pub(crate) message: Vec<u8>,
    pub(crate) hash_point: Vec<u8>,
}

pub(crate) fn generate<V: Variant>(
    namespace: &[u8],
    message: &[u8],
    seed: u64,
) -> Result<Output, String> {
    let framed = frame(namespace, message)?;
    let mut rng = StdRng::seed_from_u64(seed);
    let (sharing, shares) =
        feldman_desmedt::deal_anonymous::<V, N3f1>(&mut rng, Mode::NonZeroCounter, NZU32!(4));
    let partials: Vec<_> = shares
        .iter()
        .take(sharing.required() as usize)
        .map(|share| threshold::sign_message::<V>(share, namespace, message))
        .collect();
    for partial in &partials {
        threshold::verify_message::<V>(&sharing, namespace, message, partial)
            .map_err(|error| format!("invalid partial signature: {error}"))?;
    }
    let signature = threshold::recover::<V, _>(&sharing, &partials, &Sequential)
        .map_err(|error| format!("threshold recovery failed: {error}"))?;
    ops::verify_message::<V>(sharing.public(), namespace, message, &signature)
        .map_err(|error| format!("invalid recovered signature: {error}"))?;

    Ok(Output {
        signature: compact(&signature)?,
        public_key: pad(&compact(sharing.public())?),
        hash_point: pad(&compact(&ops::hash::<V>(V::MESSAGE, &framed))?),
        message: framed,
    })
}

pub(crate) fn generate_variant(
    variant: BlsVariant,
    namespace: &[u8],
    message: &[u8],
    seed: u64,
) -> Result<Output, String> {
    match variant {
        BlsVariant::Minsig => generate::<MinSig>(namespace, message, seed),
        BlsVariant::Minpk => generate::<MinPk>(namespace, message, seed),
    }
}

pub(crate) fn encode_output(output: Output) -> Vec<u8> {
    CertificateOutput {
        signature: output.signature.into(),
        public_key: output.public_key.into(),
        message: output.message.into(),
        hash_point: output.hash_point.into(),
    }
    .abi_encode_params()
}

fn check<V: Variant>(public: &[u8], namespace: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if u32::try_from(namespace.len()).is_err() {
        return false;
    }
    let public_fields = if V::MESSAGE == MinSig::MESSAGE { 4 } else { 2 };
    let Some(public) = unpad(public, public_fields).and_then(|bytes| compress(&bytes)) else {
        return false;
    };
    if signature.len() != (6 - public_fields) * 48 {
        return false;
    }
    let Some(signature) = compress(signature) else {
        return false;
    };
    let Ok(public) = V::Public::decode(public) else {
        return false;
    };
    let Ok(signature) = V::Signature::decode(signature) else {
        return false;
    };
    ops::verify_message::<V>(&public, namespace, message, &signature).is_ok()
}

impl Command {
    pub(crate) fn execute(self) -> Result<Vec<u8>, String> {
        match self {
            Self::Generate(args) => {
                let namespace = decode_hex(&args.namespace)?;
                let message = decode_hex(&args.message)?;
                Ok(encode_output(generate_variant(
                    args.variant,
                    &namespace,
                    &message,
                    args.seed,
                )?))
            }
            Self::Check {
                variant,
                public_key,
                namespace,
                message,
                signature,
            } => {
                let public = decode_hex(&public_key)?;
                let namespace = decode_hex(&namespace)?;
                let message = decode_hex(&message)?;
                let signature = decode_hex(&signature)?;
                let accepted = match variant {
                    BlsVariant::Minsig => {
                        check::<MinSig>(&public, &namespace, &message, &signature)
                    }
                    BlsVariant::Minpk => check::<MinPk>(&public, &namespace, &message, &signature),
                };
                Ok(accepted.abi_encode())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cli;
    use alloy_sol_types::{SolType, SolValue};
    use clap::Parser;

    fn threshold_cases<V: Variant>() {
        for (namespace, message) in [
            (b"generic-domain".as_slice(), b"generic message".as_slice()),
            (b"".as_slice(), b"".as_slice()),
        ] {
            for seed in [0, 42, u64::MAX] {
                let output = generate::<V>(namespace, message, seed).unwrap();
                assert!(check::<V>(
                    &output.public_key,
                    namespace,
                    message,
                    &output.signature
                ));
                assert_eq!(
                    output.signature,
                    generate::<V>(namespace, message, seed).unwrap().signature
                );
                let other = generate::<V>(namespace, message, seed.wrapping_add(1)).unwrap();
                assert!(!check::<V>(
                    &other.public_key,
                    namespace,
                    message,
                    &output.signature
                ));
                assert!(!check::<V>(
                    &output.public_key,
                    namespace,
                    b"changed",
                    &output.signature
                ));
                assert!(!check::<V>(
                    &output.public_key,
                    b"changed",
                    message,
                    &output.signature
                ));
                assert!(!check::<V>(
                    &output.public_key,
                    namespace,
                    message,
                    &output.signature[..output.signature.len() - 1]
                ));
                let mut signature = output.signature.clone();
                signature[0] |= 0x40;
                assert!(!check::<V>(
                    &output.public_key,
                    namespace,
                    message,
                    &signature
                ));
                signature.fill(0);
                assert!(!check::<V>(
                    &output.public_key,
                    namespace,
                    message,
                    &signature
                ));
                let mut public = output.public_key.clone();
                public[0] = 1;
                assert!(!check::<V>(&public, namespace, message, &output.signature));
                let framed = frame(namespace, message).unwrap();
                assert_eq!(output.message, framed);
                assert_eq!(
                    output.hash_point,
                    pad(&compact(&ops::hash::<V>(V::MESSAGE, &framed)).unwrap())
                );
            }
        }
    }

    #[test]
    fn recovered_signatures_verify_and_reject_mutations() {
        threshold_cases::<MinSig>();
        threshold_cases::<MinPk>();
    }

    fn quorum<V: Variant>() {
        let mut rng = StdRng::seed_from_u64(42);
        let (sharing, shares) =
            feldman_desmedt::deal_anonymous::<V, N3f1>(&mut rng, Mode::NonZeroCounter, NZU32!(4));
        assert_eq!(sharing.required(), 3);
        let partials: Vec<_> = shares
            .iter()
            .map(|share| threshold::sign_message::<V>(share, b"domain", b"body"))
            .collect();
        assert!(threshold::recover::<V, _>(&sharing, &partials[..2], &Sequential).is_err());
        let first = threshold::recover::<V, _>(&sharing, &partials[..3], &Sequential).unwrap();
        let last = threshold::recover::<V, _>(&sharing, &partials[1..], &Sequential).unwrap();
        assert_eq!(first, last);
        ops::verify_message::<V>(sharing.public(), b"domain", b"body", &first).unwrap();
    }

    #[test]
    fn threshold_requires_three_shares_and_recovers_unique_signature() {
        quorum::<MinSig>();
        quorum::<MinPk>();
    }

    #[test]
    fn cli_abi_contract_covers_both_variants() {
        for (variant, signature_len, public_len, hash_len) in
            [("minsig", 96, 256, 128), ("minpk", 192, 128, 256)]
        {
            let encoded = Cli::try_parse_from([
                "commonware-sol-fuzz",
                "certificate",
                "threshold",
                "generate",
                "--variant",
                variant,
                "--namespace",
                "0x74657374",
                "--message",
                "0x6d657373616765",
                "--seed",
                "42",
            ])
            .unwrap()
            .command
            .execute()
            .unwrap();
            assert_eq!(encoded.len() % 32, 0);
            let decoded =
                <CertificateOutput as SolValue>::abi_decode_params_validate(&encoded).unwrap();
            assert_eq!(
                (
                    decoded.signature.len(),
                    decoded.public_key.len(),
                    decoded.hash_point.len()
                ),
                (signature_len, public_len, hash_len)
            );
            assert_eq!(decoded.message.as_ref(), b"\x04testmessage");

            let checked = Cli::try_parse_from([
                "commonware-sol-fuzz",
                "certificate",
                "threshold",
                "check",
                "--variant",
                variant,
                "--public-key",
                &const_hex::encode(&decoded.public_key),
                "--namespace",
                "0x74657374",
                "--message",
                "0x6d657373616765",
                "--signature",
                &const_hex::encode(&decoded.signature),
            ])
            .unwrap()
            .command
            .execute()
            .unwrap();
            assert_eq!(checked, true.abi_encode());

            let hashed = Cli::try_parse_from([
                "commonware-sol-fuzz",
                "certificate",
                "hash",
                "--variant",
                variant,
                "--namespace",
                "0x74657374",
                "--message",
                "0x6d657373616765",
            ])
            .unwrap()
            .command
            .execute()
            .unwrap();
            assert_eq!(
                <sol!(bytes)>::abi_decode_validate(&hashed).unwrap(),
                decoded.hash_point
            );
        }
    }
}
