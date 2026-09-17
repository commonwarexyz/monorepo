//! Seeded Commonware Simplex threshold inputs and EIP-2537 point encodings.

use alloy_sol_macro::sol;
use alloy_sol_types::{SolType, SolValue};
use clap::{Args, Subcommand, ValueEnum};
use commonware_codec::{DecodeExt, Encode};
use commonware_consensus::{
    simplex::{
        scheme::Namespace,
        types::{Proposal, Subject},
    },
    types::{Epoch, Round, View},
};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt,
        primitives::{
            ops::{self, threshold},
            sharing::Mode,
            variant::{MinPk, MinSig, Variant},
        },
    },
    certificate::Subject as _,
    keccak256,
};
use commonware_parallel::Sequential;
use commonware_utils::{N3f1, NZU32, union_unique};
use rand::{SeedableRng, rngs::StdRng};

sol! {
    struct SimplexOutput {
        bytes signature;
        bytes public_key;
        bytes message;
        bytes hash_point;
    }
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Recover a 3-of-4 threshold signature for a Simplex voting subject.
    Generate(GenerateArgs),
    /// Hash already-framed message bytes to an EIP-2537 point, returned as ABI `bytes`.
    Hash {
        variant: BlsVariant,
        message_hex: String,
    },
    /// Return ABI `bool` for a compact signature, padded public key, and framed message.
    Check {
        variant: BlsVariant,
        public_key_hex: String,
        message_hex: String,
        signature_hex: String,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum BlsVariant {
    Minsig,
    Minpk,
}

#[derive(Clone, Copy, ValueEnum)]
enum Kind {
    Notarize,
    Nullify,
    Finalize,
}

#[derive(Args)]
pub(crate) struct GenerateArgs {
    variant: BlsVariant,
    kind: Kind,
    namespace_hex: String,
    epoch: u64,
    view: u64,
    /// Ignored for nullification.
    parent: u64,
    /// A 32-byte digest, ignored for nullification.
    payload_hex: String,
    seed: u64,
}

/// ABI `(bytes signature, bytes publicKey, bytes message, bytes hashPoint)`.
/// Signatures use uncompressed 48-byte field elements (MinSig 96 bytes, MinPk 192).
/// Public keys and hash points pad each field to 64 bytes with 16 leading zeros.
/// Public keys are 256/128 bytes and hash points 128/256 bytes for MinSig/MinPk.
/// G2 coordinates are ordered x.c0, x.c1, y.c0, y.c1 throughout.
/// The message includes Commonware's namespace framing and encoded voting subject.
/// Seeded shares model a local 3-of-4 quorum, without simulating a network or DKG.
struct Output {
    signature: Vec<u8>,
    public_key: Vec<u8>,
    message: Vec<u8>,
    hash_point: Vec<u8>,
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    const_hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|error| format!("invalid hex: {error}"))
}

impl GenerateArgs {
    fn generate<V: Variant>(&self) -> Result<Output, String> {
        let namespace = Namespace::new(&decode_hex(&self.namespace_hex)?);
        let payload = decode_hex(&self.payload_hex)?;
        let payload: [u8; 32] = payload.try_into().map_err(|_| "payload must be 32 bytes")?;
        let round = Round::new(Epoch::new(self.epoch), View::new(self.view));
        let proposal = Proposal::new(round, View::new(self.parent), keccak256::Digest(payload));
        let subject = match self.kind {
            Kind::Notarize => Subject::Notarize {
                proposal: &proposal,
            },
            Kind::Nullify => Subject::Nullify { round },
            Kind::Finalize => Subject::Finalize {
                proposal: &proposal,
            },
        };
        let domain = subject.namespace(&namespace);
        u32::try_from(domain.len()).map_err(|_| "namespace exceeds u32")?;
        let body = subject.message();
        let message = union_unique(domain, &body);
        let mut rng = StdRng::seed_from_u64(self.seed);
        let (sharing, shares) =
            feldman_desmedt::deal_anonymous::<V, N3f1>(&mut rng, Mode::NonZeroCounter, NZU32!(4));
        let partials: Vec<_> = shares
            .iter()
            .take(sharing.required() as usize)
            .map(|share| threshold::sign_message::<V>(share, domain, &body))
            .collect();
        for partial in &partials {
            threshold::verify_message::<V>(&sharing, domain, &body, partial)
                .map_err(|error| format!("invalid partial signature: {error}"))?;
        }
        let signature = threshold::recover::<V, _>(&sharing, &partials, &Sequential)
            .map_err(|error| format!("threshold recovery failed: {error}"))?;
        ops::verify_message::<V>(sharing.public(), domain, &body, &signature)
            .map_err(|error| format!("invalid recovered signature: {error}"))?;
        Ok(Output {
            signature: compact(&signature)?,
            public_key: pad(&compact(sharing.public())?),
            message: message.clone(),
            hash_point: pad(&compact(&ops::hash::<V>(V::MESSAGE, &message))?),
        })
    }
}

/// BLST serializes Fp2 as c1,c0; the Solidity interface uses c0,c1 for each coordinate.
fn swap_fp2(bytes: &mut [u8]) {
    for coordinate in bytes.as_chunks_mut::<96>().0 {
        let (c1, c0) = coordinate.split_at_mut(48);
        c1.swap_with_slice(c0);
    }
}

fn compact(point: &impl Encode) -> Result<Vec<u8>, String> {
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

fn pad(compact: &[u8]) -> Vec<u8> {
    let mut padded = Vec::with_capacity(compact.len() / 48 * 64);
    for field in compact.as_chunks::<48>().0 {
        padded.extend_from_slice(&[0; 16]);
        padded.extend_from_slice(field);
    }
    padded
}

fn unpad(padded: &[u8], fields: usize) -> Option<Vec<u8>> {
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
fn compress(compact: &[u8]) -> Option<Vec<u8>> {
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

fn check<V: Variant>(public: &[u8], message: &[u8], signature: &[u8]) -> bool {
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
    ops::verify::<V>(&public, V::MESSAGE, message, &signature).is_ok()
}

impl Command {
    pub(crate) fn execute(self) -> Result<Vec<u8>, String> {
        match self {
            Self::Generate(args) => {
                let output = match args.variant {
                    BlsVariant::Minsig => args.generate::<MinSig>()?,
                    BlsVariant::Minpk => args.generate::<MinPk>()?,
                };
                Ok(SimplexOutput {
                    signature: output.signature.into(),
                    public_key: output.public_key.into(),
                    message: output.message.into(),
                    hash_point: output.hash_point.into(),
                }
                .abi_encode_params())
            }
            Self::Hash {
                variant,
                message_hex,
            } => {
                let message = decode_hex(&message_hex)?;
                let point = match variant {
                    BlsVariant::Minsig => compact(&ops::hash::<MinSig>(MinSig::MESSAGE, &message))?,
                    BlsVariant::Minpk => compact(&ops::hash::<MinPk>(MinPk::MESSAGE, &message))?,
                };
                Ok(<sol!(bytes)>::abi_encode(&pad(&point)))
            }
            Self::Check {
                variant,
                public_key_hex,
                message_hex,
                signature_hex,
            } => {
                let public = decode_hex(&public_key_hex)?;
                let message = decode_hex(&message_hex)?;
                let signature = decode_hex(&signature_hex)?;
                let accepted = match variant {
                    BlsVariant::Minsig => check::<MinSig>(&public, &message, &signature),
                    BlsVariant::Minpk => check::<MinPk>(&public, &message, &signature),
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

    fn args(kind: Kind, seed: u64) -> GenerateArgs {
        GenerateArgs {
            variant: BlsVariant::Minsig,
            kind,
            namespace_hex: const_hex::encode(b"test"),
            epoch: 127,
            view: 128,
            parent: u64::MAX,
            payload_hex: const_hex::encode([0xa5; 32]),
            seed,
        }
    }

    fn threshold_cases<V: Variant>() {
        for kind in [Kind::Notarize, Kind::Nullify, Kind::Finalize] {
            for seed in [0, 42, u64::MAX] {
                let input = args(kind, seed);
                let output = input.generate::<V>().unwrap();
                assert!(check::<V>(
                    &output.public_key,
                    &output.message,
                    &output.signature
                ));
                assert_eq!(output.signature, input.generate::<V>().unwrap().signature);
                let other = args(kind, seed.wrapping_add(1)).generate::<V>().unwrap();
                assert!(!check::<V>(
                    &other.public_key,
                    &output.message,
                    &output.signature
                ));
                let mut changed = output.message.clone();
                changed[1] ^= 1;
                assert!(!check::<V>(&output.public_key, &changed, &output.signature));
                assert!(!check::<V>(
                    &output.public_key,
                    &output.message,
                    &output.signature[..output.signature.len() - 1]
                ));
                let mut signature = output.signature.clone();
                signature[0] |= 0x40;
                assert!(!check::<V>(&output.public_key, &output.message, &signature));
                signature.fill(0);
                assert!(!check::<V>(&output.public_key, &output.message, &signature));
                let mut public = output.public_key.clone();
                public[0] = 1;
                assert!(!check::<V>(&public, &output.message, &output.signature));
                assert_eq!(
                    output.hash_point,
                    pad(&compact(&ops::hash::<V>(V::MESSAGE, &output.message)).unwrap())
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
    fn framing_matches_simplex_varints_and_nullification_fields() {
        for (kind, suffix) in [
            (Kind::Notarize, b"_NOTARIZE".as_slice()),
            (Kind::Nullify, b"_NULLIFY"),
            (Kind::Finalize, b"_FINALIZE"),
        ] {
            let input = args(kind, 7);
            let output = input.generate::<MinSig>().unwrap();
            let mut expected = vec![(4 + suffix.len()) as u8];
            expected.extend_from_slice(b"test");
            expected.extend_from_slice(suffix);
            expected.extend_from_slice(&[0x7f, 0x80, 0x01]);
            if !matches!(kind, Kind::Nullify) {
                expected.extend_from_slice(&[
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
                ]);
                expected.extend_from_slice(&[0xa5; 32]);
            }
            assert_eq!(output.message, expected);
        }
        let mut input = args(Kind::Nullify, 7);
        let before = input.generate::<MinSig>().unwrap();
        input.parent = 0;
        input.payload_hex = const_hex::encode([0; 32]);
        assert_eq!(
            before.signature,
            input.generate::<MinSig>().unwrap().signature
        );
        input.namespace_hex = const_hex::encode([0; 120]);
        assert_eq!(
            &input.generate::<MinSig>().unwrap().message[..2],
            &[0x80, 0x01]
        );
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
                "simplex",
                "generate",
                variant,
                "notarize",
                "0x74657374",
                "127",
                "128",
                "0",
                &const_hex::encode([0; 32]),
                "42",
            ])
            .unwrap()
            .command
            .execute()
            .unwrap();
            assert_eq!(encoded.len() % 32, 0);
            let decoded =
                <SimplexOutput as SolValue>::abi_decode_params_validate(&encoded).unwrap();
            let signature = &decoded.signature;
            let public = &decoded.public_key;
            let message = &decoded.message;
            let hash = &decoded.hash_point;
            assert_eq!(
                (signature.len(), public.len(), hash.len()),
                (signature_len, public_len, hash_len)
            );
            let check = Cli::try_parse_from([
                "commonware-sol-fuzz",
                "simplex",
                "check",
                variant,
                &const_hex::encode(public),
                &const_hex::encode(message),
                &const_hex::encode(signature),
            ])
            .unwrap()
            .command
            .execute()
            .unwrap();
            assert_eq!(check, true.abi_encode());
            let hashed = Cli::try_parse_from([
                "commonware-sol-fuzz",
                "simplex",
                "hash",
                variant,
                &const_hex::encode(message),
            ])
            .unwrap()
            .command
            .execute()
            .unwrap();
            assert_eq!(&hashed[..32], &32u64.abi_encode());
            assert_eq!(hashed.len(), 64 + hash_len);
            assert_eq!(<sol!(bytes)>::abi_decode_validate(&hashed).unwrap(), *hash);
        }
    }
}
