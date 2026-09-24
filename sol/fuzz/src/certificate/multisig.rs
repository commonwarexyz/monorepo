//! Seeded BLS12-381 multi-signatures and authenticated-key verification.

use super::{BlsVariant, compact, compress, decode_hex, frame, pad, unpad};
use alloy_sol_macro::sol;
use alloy_sol_types::SolValue;
use clap::{Args, Subcommand};
use commonware_codec::{DecodeExt, FixedSize};
use commonware_cryptography::{
    bls12381::primitives::{
        ops::{self, aggregate},
        variant::{MinPk, MinSig, Variant},
    },
    certificate::Signers,
};
use commonware_utils::{Participant, non_empty};
use rand::{SeedableRng, rngs::StdRng};
use std::collections::HashSet;

const MAX_PARTICIPANTS: u32 = 1024;
const POP_NAMESPACE: &[u8] = b"_COMMONWARE_SOL_FUZZ_MULTISIG_POP";

const fn public_size<V: Variant>() -> usize {
    V::Public::SIZE * 2 / 48 * 64
}

sol! {
    struct MultisigOutput {
        bytes signature;
        bytes public_keys;
        bytes signers;
        bytes message;
    }
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Generate an aggregate signature from a non-empty signer subset.
    Generate(GenerateArgs),
    /// Return ABI `bool` after checking quorum and the aggregate signature.
    ///
    /// Public keys must follow an authenticated participant order with distinct keys and
    /// validated proofs of possession. Signers use a raw LSB-first bitmap, exactly
    /// ceil(participants / 8) bytes with unused high bits cleared.
    Check {
        #[arg(long, value_enum)]
        variant: BlsVariant,
        /// Concatenated public keys, hex-encoded.
        #[arg(long)]
        public_keys: String,
        #[arg(long)]
        signers: String,
        #[arg(long)]
        quorum: String,
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
    participants: u32,
    #[arg(long)]
    signers: String,
    #[arg(long)]
    seed: u64,
}

/// ABI `(bytes signature, bytes publicKeys, bytes signers, bytes message)`.
///
/// Public keys are in authenticated participant order. Production callers must authenticate that
/// ordering and verify every registered key's proof of possession before using aggregate
/// verification. The seeded fixture verifies a PoP for every generated key.
pub(crate) struct Output {
    pub(crate) signature: Vec<u8>,
    pub(crate) public_keys: Vec<u8>,
    pub(crate) signers: Vec<u8>,
    pub(crate) message: Vec<u8>,
}

fn parse_signers(participants: u32, bitmap: &[u8]) -> Result<Signers, String> {
    if participants == 0 {
        return Err("participants must be nonzero".into());
    }
    let expected = (participants as usize).div_ceil(8);
    if bitmap.len() != expected {
        return Err(format!(
            "signers must be exactly {expected} bytes for {participants} participants"
        ));
    }
    let remainder = participants % 8;
    if remainder != 0 && bitmap[expected - 1] & !((1u8 << remainder) - 1) != 0 {
        return Err("unused high signer bits must be zero".into());
    }

    let selected = (0..participants)
        .filter(|index| bitmap[(*index / 8) as usize] & (1 << (*index % 8)) != 0)
        .map(Participant::new)
        .collect::<Vec<_>>();
    if selected.is_empty() {
        return Err("at least one signer is required".into());
    }
    Signers::new(participants, selected).map_err(|error| format!("invalid signers: {error}"))
}

pub(crate) fn generate<V: Variant>(
    namespace: &[u8],
    message: &[u8],
    participants: u32,
    bitmap: &[u8],
    seed: u64,
) -> Result<Output, String> {
    if participants > MAX_PARTICIPANTS {
        return Err(format!("participants exceeds {MAX_PARTICIPANTS}"));
    }
    let signers = parse_signers(participants, bitmap)?;
    let framed = frame(namespace, message)?;
    let mut rng = StdRng::seed_from_u64(seed);
    let mut privates = Vec::with_capacity(participants as usize);
    let mut publics = Vec::with_capacity(participants as usize);
    let mut unique = HashSet::with_capacity(participants as usize);

    for _ in 0..participants {
        let (private, public) = ops::keypair::<_, V>(&mut rng);
        if !unique.insert(public) {
            return Err("seed generated duplicate public keys".into());
        }
        let pop = ops::sign_proof_of_possession::<V>(&private, POP_NAMESPACE);
        ops::verify_proof_of_possession::<V>(&public, POP_NAMESPACE, &pop)
            .map_err(|error| format!("generated key has invalid proof of possession: {error}"))?;
        privates.push(private);
        publics.push(public);
    }

    let signatures = signers
        .iter()
        .map(|signer| ops::sign_message::<V>(&privates[usize::from(signer)], namespace, message))
        .collect::<Vec<_>>();
    let signature = aggregate::combine_signatures::<V, _>(non_empty![@signatures.iter()]);

    let selected_publics = signers
        .iter()
        .map(|signer| &publics[usize::from(signer)])
        .collect::<Vec<_>>();
    let aggregate_public =
        aggregate::combine_public_keys::<V, _>(non_empty![@selected_publics.into_iter()]);
    aggregate::verify_same_message::<V>(&aggregate_public, namespace, message, &signature)
        .map_err(|error| format!("generated aggregate signature is invalid: {error}"))?;

    let mut public_keys = Vec::with_capacity(participants as usize * public_size::<V>());
    for public in &publics {
        public_keys.extend_from_slice(&pad(&compact(public)?));
    }

    Ok(Output {
        signature: compact(&signature)?,
        public_keys,
        signers: bitmap.to_vec(),
        message: framed,
    })
}

pub(crate) fn generate_variant(
    variant: BlsVariant,
    namespace: &[u8],
    message: &[u8],
    participants: u32,
    signers: &[u8],
    seed: u64,
) -> Result<Output, String> {
    match variant {
        BlsVariant::Minsig => generate::<MinSig>(namespace, message, participants, signers, seed),
        BlsVariant::Minpk => generate::<MinPk>(namespace, message, participants, signers, seed),
    }
}

pub(crate) fn encode_output(output: Output) -> Vec<u8> {
    MultisigOutput {
        signature: output.signature.into(),
        public_keys: output.public_keys.into(),
        signers: output.signers.into(),
        message: output.message.into(),
    }
    .abi_encode_params()
}

fn check<V: Variant>(
    public_keys: &[u8],
    bitmap: &[u8],
    quorum: u32,
    namespace: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    if frame(namespace, message).is_err() {
        return false;
    }
    let public_size = public_size::<V>();
    if public_keys.is_empty() || !public_keys.len().is_multiple_of(public_size) {
        return false;
    }
    let participants = public_keys.len() / public_size;
    let Ok(participants) = u32::try_from(participants) else {
        return false;
    };
    if participants == 0 || quorum == 0 || quorum > participants {
        return false;
    }
    let Ok(signers) = parse_signers(participants, bitmap) else {
        return false;
    };
    if signers.count() < quorum as usize {
        return false;
    }

    let fields = public_size / 64;
    let mut selected = Vec::with_capacity(signers.count());
    for signer in signers.iter() {
        let start = usize::from(signer) * public_size;
        let padded = &public_keys[start..start + public_size];
        let Some(compressed) = unpad(padded, fields).and_then(|compact| compress(&compact)) else {
            return false;
        };
        let Ok(public) = V::Public::decode(compressed) else {
            return false;
        };
        selected.push(public);
    }

    if signature.len() != V::Signature::SIZE * 2 {
        return false;
    }
    let Some(signature) = compress(signature) else {
        return false;
    };
    let Ok(signature) = aggregate::Signature::<V>::decode(signature) else {
        return false;
    };

    let public = aggregate::combine_public_keys::<V, _>(non_empty![@selected.iter()]);
    aggregate::verify_same_message::<V>(&public, namespace, message, &signature).is_ok()
}

impl Command {
    pub(crate) fn execute(self) -> Result<Vec<u8>, String> {
        match self {
            Self::Generate(args) => {
                if args.participants > MAX_PARTICIPANTS {
                    return Err(format!("participants exceeds {MAX_PARTICIPANTS}"));
                }
                let namespace = decode_hex(&args.namespace)?;
                let message = decode_hex(&args.message)?;
                let signers = decode_hex(&args.signers)?;
                Ok(encode_output(generate_variant(
                    args.variant,
                    &namespace,
                    &message,
                    args.participants,
                    &signers,
                    args.seed,
                )?))
            }
            Self::Check {
                variant,
                public_keys,
                signers,
                quorum,
                namespace,
                message,
                signature,
            } => {
                let public_keys = decode_hex(&public_keys)?;
                let signers = decode_hex(&signers)?;
                let namespace = decode_hex(&namespace)?;
                let message = decode_hex(&message)?;
                let signature = decode_hex(&signature)?;
                let accepted = quorum.parse::<u32>().is_ok_and(|quorum| match variant {
                    BlsVariant::Minsig => check::<MinSig>(
                        &public_keys,
                        &signers,
                        quorum,
                        &namespace,
                        &message,
                        &signature,
                    ),
                    BlsVariant::Minpk => check::<MinPk>(
                        &public_keys,
                        &signers,
                        quorum,
                        &namespace,
                        &message,
                        &signature,
                    ),
                });
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

    fn roundtrip<V: Variant>() {
        for (participants, bitmap) in [(1, vec![0x01]), (8, vec![0x81]), (9, vec![0x01, 0x01])] {
            let output = generate::<V>(b"domain", b"message", participants, &bitmap, 42).unwrap();
            let repeated = generate::<V>(b"domain", b"message", participants, &bitmap, 42).unwrap();
            let other = generate::<V>(b"domain", b"message", participants, &bitmap, 43).unwrap();
            assert!(check::<V>(
                &output.public_keys,
                &output.signers,
                1,
                b"domain",
                b"message",
                &output.signature,
            ));
            assert_eq!(output.message, frame(b"domain", b"message").unwrap());
            assert_eq!(
                output.public_keys.len(),
                participants as usize * public_size::<V>()
            );
            assert_eq!(output.public_keys, repeated.public_keys);
            assert_eq!(output.signature, repeated.signature);
            assert_ne!(output.public_keys, other.public_keys);
        }
    }

    #[test]
    fn aggregate_signatures_roundtrip_for_both_variants_and_bitmap_boundaries() {
        roundtrip::<MinSig>();
        roundtrip::<MinPk>();
    }

    #[test]
    fn bitmap_validation_rejects_wrong_lengths_padding_and_empty_sets() {
        assert!(parse_signers(1, &[]).is_err());
        assert!(parse_signers(1, &[0, 0]).is_err());
        assert!(parse_signers(1, &[0x80]).is_err());
        assert!(parse_signers(1, &[0]).is_err());
        assert!(parse_signers(8, &[0x80]).is_ok());
        assert!(parse_signers(9, &[0, 0x01]).is_ok());
        assert!(parse_signers(9, &[0, 0x02]).is_err());
        let mut boundary = vec![0; 33];
        boundary[32] = 0x01;
        assert_eq!(parse_signers(257, &boundary).unwrap().count(), 1);
        boundary[32] = 0x02;
        assert!(parse_signers(257, &boundary).is_err());
    }

    fn rejection_cases<V: Variant>() {
        let output = generate::<V>(b"domain", b"message", 4, &[0x03], 7).unwrap();
        assert!(check::<V>(
            &output.public_keys,
            &output.signers,
            2,
            b"domain",
            b"message",
            &output.signature,
        ));
        assert!(!check::<V>(
            &output.public_keys,
            &output.signers,
            3,
            b"domain",
            b"message",
            &output.signature,
        ));

        let public_size = public_size::<V>();
        let mut unselected_swapped = output.public_keys.clone();
        let (head, tail) = unselected_swapped.split_at_mut(2 * public_size);
        head[..public_size].swap_with_slice(&mut tail[..public_size]);
        assert!(!check::<V>(
            &unselected_swapped,
            &output.signers,
            2,
            b"domain",
            b"message",
            &output.signature,
        ));
        let third = 2 * public_size;
        let fourth = 3 * public_size;
        let (before_fourth, from_fourth) = unselected_swapped.split_at_mut(fourth);
        before_fourth[third..fourth].swap_with_slice(&mut from_fourth[..public_size]);
        assert!(!check::<V>(
            &unselected_swapped,
            &output.signers,
            2,
            b"domain",
            b"message",
            &output.signature,
        ));

        let mut only_unselected_swapped = output.public_keys.clone();
        let (before_fourth, from_fourth) = only_unselected_swapped.split_at_mut(fourth);
        before_fourth[third..fourth].swap_with_slice(&mut from_fourth[..public_size]);
        assert!(check::<V>(
            &only_unselected_swapped,
            &output.signers,
            2,
            b"domain",
            b"message",
            &output.signature,
        ));
        assert!(!check::<V>(
            &output.public_keys,
            &output.signers,
            0,
            b"domain",
            b"message",
            &output.signature,
        ));
        assert!(!check::<V>(
            &output.public_keys,
            &output.signers,
            5,
            b"domain",
            b"message",
            &output.signature,
        ));
        assert!(!check::<V>(
            &output.public_keys,
            &output.signers,
            2,
            b"domain",
            b"changed",
            &output.signature,
        ));

        let mut signature = output.signature.clone();
        let last = signature.len() - 1;
        signature[last] ^= 1;
        assert!(!check::<V>(
            &output.public_keys,
            &output.signers,
            2,
            b"domain",
            b"message",
            &signature,
        ));
        let mut public_keys = output.public_keys.clone();
        public_keys[0] = 1;
        assert!(!check::<V>(
            &public_keys,
            &output.signers,
            2,
            b"domain",
            b"message",
            &output.signature,
        ));
        assert!(!check::<V>(
            &output.public_keys,
            &[0x07],
            2,
            b"domain",
            b"message",
            &output.signature,
        ));
        assert!(!check::<V>(
            &output.public_keys[..output.public_keys.len() - 1],
            &output.signers,
            2,
            b"domain",
            b"message",
            &output.signature,
        ));
    }

    #[test]
    fn checks_quorum_and_rejects_mutations_for_both_variants() {
        rejection_cases::<MinSig>();
        rejection_cases::<MinPk>();
    }

    #[test]
    fn cli_abi_contract_covers_both_variants() {
        for (variant, signature_len, public_len) in
            [("minsig", 96, 4 * 256), ("minpk", 192, 4 * 128)]
        {
            let encoded = Cli::try_parse_from([
                "commonware-sol-fuzz",
                "certificate",
                "multisig",
                "generate",
                "--variant",
                variant,
                "--namespace",
                "0x74657374",
                "--message",
                "0x6d657373616765",
                "--participants",
                "4",
                "--signers",
                "0x03",
                "--seed",
                "42",
            ])
            .unwrap()
            .command
            .execute()
            .unwrap();
            let decoded =
                <MultisigOutput as SolValue>::abi_decode_params_validate(&encoded).unwrap();
            assert_eq!(decoded.signature.len(), signature_len);
            assert_eq!(decoded.public_keys.len(), public_len);
            assert_eq!(decoded.signers.as_ref(), &[0x03]);
            assert_eq!(decoded.message.as_ref(), b"\x04testmessage");

            let checked = Cli::try_parse_from([
                "commonware-sol-fuzz",
                "certificate",
                "multisig",
                "check",
                "--variant",
                variant,
                "--public-keys",
                &const_hex::encode(&decoded.public_keys),
                "--signers",
                &const_hex::encode(&decoded.signers),
                "--quorum",
                "2",
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

            let excessive_quorum = Cli::try_parse_from([
                "commonware-sol-fuzz",
                "certificate",
                "multisig",
                "check",
                "--variant",
                variant,
                "--public-keys",
                &const_hex::encode(&decoded.public_keys),
                "--signers",
                &const_hex::encode(&decoded.signers),
                "--quorum",
                "115792089237316195423570985008687907853269984665640564039457584007913129639935",
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
            assert_eq!(excessive_quorum, false.abi_encode());
        }
    }
}
