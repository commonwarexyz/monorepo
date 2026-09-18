//! Seeded BLS12-381 threshold certificates and EIP-2537 point encodings.

use alloy_sol_macro::sol;
use alloy_sol_types::{SolType, SolValue};
use clap::{Args, Subcommand, ValueEnum};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::bls12381::{
    dkg::feldman_desmedt,
    primitives::{
        ops::{self, threshold},
        sharing::Mode,
        variant::{MinPk, MinSig, Variant},
    },
};
use commonware_parallel::Sequential;
use commonware_utils::{N3f1, NZU32, union_unique};
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
    /// Hash a namespace and message to an EIP-2537 point, returned as ABI `bytes`.
    Hash {
        variant: BlsVariant,
        namespace_hex: String,
        message_hex: String,
    },
    /// Return ABI `bool` for a signature over a namespace and message.
    Check {
        variant: BlsVariant,
        public_key_hex: String,
        namespace_hex: String,
        message_hex: String,
        signature_hex: String,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum BlsVariant {
    Minsig,
    Minpk,
}

#[derive(Args)]
pub(crate) struct GenerateArgs {
    variant: BlsVariant,
    namespace_hex: String,
    message_hex: String,
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

pub(crate) fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    const_hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|error| format!("invalid hex: {error}"))
}

pub(crate) fn frame(namespace: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    // Commonware's codec encodes usize lengths through u32 for cross-platform compatibility.
    u32::try_from(namespace.len()).map_err(|_| "namespace exceeds u32")?;
    Ok(union_unique(namespace, message))
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

/// BLST serializes Fp2 as c1,c0; the Solidity interface uses c0,c1 for each coordinate.
fn swap_fp2(bytes: &mut [u8]) {
    for coordinate in bytes.as_chunks_mut::<96>().0 {
        let (c1, c0) = coordinate.split_at_mut(48);
        c1.swap_with_slice(c0);
    }
}

pub(crate) fn compact(point: &impl Encode) -> Result<Vec<u8>, String> {
    let compressed = point.encode();
    match compressed.len() {
        48 => blst::min_sig::Signature::from_bytes(&compressed)
            .map(|point| point.serialize().to_vec()),
        96 => blst::min_pk::Signature::from_bytes(&compressed).map(|point| {
            let mut bytes = point.serialize().to_vec();
            swap_fp2(&mut bytes);
            bytes
        }),
        _ => return Err("unsupported point size".into()),
    }
    .map_err(|error| format!("invalid Commonware point: {error:?}"))
}

pub(crate) fn pad(compact: &[u8]) -> Vec<u8> {
    let mut padded = Vec::with_capacity(compact.len() / 48 * 64);
    for field in compact.as_chunks::<48>().0 {
        padded.extend_from_slice(&[0; 16]);
        padded.extend_from_slice(field);
    }
    padded
}

pub(crate) fn unpad(padded: &[u8], fields: usize) -> Option<Vec<u8>> {
    if padded.len() != fields * 64 {
        return None;
    }
    let mut compact = Vec::with_capacity(fields * 48);
    for field in padded.as_chunks::<64>().0 {
        if field[..16].iter().any(|byte| *byte != 0) {
            return None;
        }
        compact.extend_from_slice(&field[16..]);
    }
    Some(compact)
}

/// Rejects serialization flags: this interface accepts only raw affine coordinates.
pub(crate) fn compress(compact: &[u8]) -> Option<Vec<u8>> {
    if compact
        .as_chunks::<48>()
        .0
        .iter()
        .any(|field| field[0] & 0xe0 != 0)
    {
        return None;
    }
    match compact.len() {
        96 => blst::min_sig::Signature::from_bytes(compact)
            .ok()
            .map(|point| point.compress().to_vec()),
        192 => {
            let mut bytes = compact.to_vec();
            swap_fp2(&mut bytes);
            blst::min_pk::Signature::from_bytes(&bytes)
                .ok()
                .map(|point| point.compress().to_vec())
        }
        _ => None,
    }
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
                let namespace = decode_hex(&args.namespace_hex)?;
                let message = decode_hex(&args.message_hex)?;
                Ok(encode_output(generate_variant(
                    args.variant,
                    &namespace,
                    &message,
                    args.seed,
                )?))
            }
            Self::Hash {
                variant,
                namespace_hex,
                message_hex,
            } => {
                let namespace = decode_hex(&namespace_hex)?;
                let message = decode_hex(&message_hex)?;
                let framed = frame(&namespace, &message)?;
                let point = match variant {
                    BlsVariant::Minsig => compact(&ops::hash::<MinSig>(MinSig::MESSAGE, &framed))?,
                    BlsVariant::Minpk => compact(&ops::hash::<MinPk>(MinPk::MESSAGE, &framed))?,
                };
                Ok(<sol!(bytes)>::abi_encode(&pad(&point)))
            }
            Self::Check {
                variant,
                public_key_hex,
                namespace_hex,
                message_hex,
                signature_hex,
            } => {
                let public = decode_hex(&public_key_hex)?;
                let namespace = decode_hex(&namespace_hex)?;
                let message = decode_hex(&message_hex)?;
                let signature = decode_hex(&signature_hex)?;
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
    fn framing_uses_u32_varint_namespace_length() {
        assert_eq!(frame(b"test", b"message").unwrap(), b"\x04testmessage");
        let namespace = [0; 128];
        assert_eq!(&frame(&namespace, b"").unwrap()[..2], &[0x80, 0x01]);
    }

    #[test]
    fn g2_coordinates_use_eip_order() {
        use commonware_cryptography::bls12381::primitives::group::G2;
        let mut secret = [0; 32];
        secret[31] = 1;
        let public = blst::min_sig::SecretKey::from_bytes(&secret)
            .unwrap()
            .sk_to_pk();
        let point = G2::decode(commonware_codec::Copying(&public.compress())).unwrap();
        let bytes = compact(&point).unwrap();
        assert_eq!(
            const_hex::encode(&bytes[..48]),
            "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
        );
        assert_eq!(
            const_hex::encode(&bytes[48..96]),
            "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
        );
        assert_eq!(compress(&bytes).unwrap(), public.compress());
    }

    #[test]
    fn cli_abi_contract_covers_both_variants() {
        for (variant, signature_len, public_len, hash_len) in
            [("minsig", 96, 256, 128), ("minpk", 192, 128, 256)]
        {
            let encoded = Cli::try_parse_from([
                "commonware-sol-fuzz",
                "certificate",
                "generate",
                variant,
                "0x74657374",
                "0x6d657373616765",
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
                "check",
                variant,
                &const_hex::encode(&decoded.public_key),
                "0x74657374",
                "0x6d657373616765",
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
                variant,
                "0x74657374",
                "0x6d657373616765",
            ])
            .unwrap()
            .command
            .execute()
            .unwrap();
            assert_eq!(&hashed[..32], &32u64.abi_encode());
            assert_eq!(hashed.len(), 64 + hash_len);
            assert_eq!(
                <sol!(bytes)>::abi_decode_validate(&hashed).unwrap(),
                decoded.hash_point
            );
        }
    }
}
