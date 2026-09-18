//! Seeded BLS12-381 certificates and EIP-2537 point encodings.

use alloy_sol_macro::sol;
use alloy_sol_types::SolType;
use clap::{Subcommand, ValueEnum};
use commonware_codec::Encode;
use commonware_cryptography::bls12381::primitives::{
    ops,
    variant::{MinPk, MinSig, Variant},
};
use commonware_utils::union_unique;

pub(crate) mod multisig;
pub(crate) mod threshold;

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Threshold certificates.
    #[command(subcommand)]
    Threshold(threshold::Command),
    /// Multi-signature certificates.
    #[command(subcommand)]
    Multisig(multisig::Command),
    /// Hash a namespace and message to an EIP-2537 point, returned as ABI `bytes`.
    Hash {
        variant: BlsVariant,
        namespace_hex: String,
        message_hex: String,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum BlsVariant {
    Minsig,
    Minpk,
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

impl Command {
    pub(crate) fn execute(self) -> Result<Vec<u8>, String> {
        match self {
            Self::Threshold(command) => command.execute(),
            Self::Multisig(command) => command.execute(),
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cli;
    use alloy_sol_types::SolValue;
    use clap::Parser;
    use commonware_codec::DecodeExt;

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
    fn hash_cli_covers_both_variants() {
        for (variant, hash_len) in [("minsig", 128), ("minpk", 256)] {
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
        }
    }
}
