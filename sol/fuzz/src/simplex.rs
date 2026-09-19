//! Seeded Commonware Simplex signatures.

use crate::certificate::{self, BlsVariant, multisig, threshold};
use clap::{Args, Subcommand, ValueEnum};
use commonware_consensus::{
    simplex::{
        scheme::Namespace,
        types::{Proposal, Subject},
    },
    types::{Epoch, Round, View},
};
use commonware_cryptography::{certificate::Subject as _, keccak256};

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Generate a signature for a Simplex voting subject.
    Generate {
        #[command(subcommand)]
        scheme: Scheme,
    },
}

#[derive(Subcommand)]
pub(crate) enum Scheme {
    Threshold(GenerateArgs),
    Multisig {
        #[command(flatten)]
        args: GenerateArgs,
        #[arg(long)]
        participants: u32,
        #[arg(long)]
        signers: String,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Kind {
    Notarize,
    Nullify,
    Finalize,
}

#[derive(Args)]
pub(crate) struct GenerateArgs {
    #[arg(long, value_enum)]
    variant: BlsVariant,
    #[arg(long, value_enum)]
    kind: Kind,
    #[arg(long)]
    namespace_hex: String,
    #[arg(long)]
    epoch: u64,
    #[arg(long)]
    view: u64,
    #[arg(
        long,
        required_if_eq("kind", "notarize"),
        required_if_eq("kind", "finalize")
    )]
    parent: Option<u64>,
    /// A 32-byte digest.
    #[arg(
        long,
        required_if_eq("kind", "notarize"),
        required_if_eq("kind", "finalize")
    )]
    payload_hex: Option<String>,
    #[arg(long)]
    seed: u64,
}

impl GenerateArgs {
    fn subject(&self) -> Result<(Vec<u8>, Vec<u8>), String> {
        let namespace = Namespace::new(&certificate::decode_hex(&self.namespace_hex)?);
        let round = Round::new(Epoch::new(self.epoch), View::new(self.view));
        match self.kind {
            Kind::Nullify => {
                if self.parent.is_some() || self.payload_hex.is_some() {
                    return Err("--parent and --payload-hex are invalid for nullify".to_string());
                }
                let subject = Subject::<keccak256::Digest>::Nullify { round };
                Ok((
                    subject.namespace(&namespace).to_vec(),
                    subject.message().to_vec(),
                ))
            }
            kind @ (Kind::Notarize | Kind::Finalize) => {
                let parent = self.parent.ok_or("--parent is required for proposals")?;
                let payload = self
                    .payload_hex
                    .as_deref()
                    .ok_or("--payload-hex is required for proposals")?;
                let payload = certificate::decode_hex(payload)?;
                let payload: [u8; 32] =
                    payload.try_into().map_err(|_| "payload must be 32 bytes")?;
                let proposal = Proposal::new(round, View::new(parent), keccak256::Digest(payload));
                let subject = if matches!(kind, Kind::Notarize) {
                    Subject::Notarize {
                        proposal: &proposal,
                    }
                } else {
                    Subject::Finalize {
                        proposal: &proposal,
                    }
                };
                Ok((
                    subject.namespace(&namespace).to_vec(),
                    subject.message().to_vec(),
                ))
            }
        }
    }
}

impl Scheme {
    fn execute(self) -> Result<Vec<u8>, String> {
        match self {
            Self::Threshold(args) => {
                let (namespace, message) = args.subject()?;
                Ok(threshold::encode_output(threshold::generate_variant(
                    args.variant,
                    &namespace,
                    &message,
                    args.seed,
                )?))
            }
            Self::Multisig {
                args,
                participants,
                signers,
            } => {
                let (namespace, message) = args.subject()?;
                let signers = certificate::decode_hex(&signers)?;
                Ok(multisig::encode_output(multisig::generate_variant(
                    args.variant,
                    &namespace,
                    &message,
                    participants,
                    &signers,
                    args.seed,
                )?))
            }
        }
    }
}

impl Command {
    pub(crate) fn execute(self) -> Result<Vec<u8>, String> {
        match self {
            Self::Generate { scheme } => scheme.execute(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cli;
    use alloy_sol_macro::sol;
    use alloy_sol_types::SolType;
    use clap::Parser;

    fn args(kind: Kind) -> GenerateArgs {
        let proposal = !matches!(kind, Kind::Nullify);
        GenerateArgs {
            variant: BlsVariant::Minsig,
            kind,
            namespace_hex: const_hex::encode(b"test"),
            epoch: 127,
            view: 128,
            parent: proposal.then_some(u64::MAX),
            payload_hex: proposal.then(|| const_hex::encode([0xa5; 32])),
            seed: 7,
        }
    }

    fn threshold_output(input: &GenerateArgs) -> threshold::Output {
        let (namespace, message) = input.subject().unwrap();
        threshold::generate_variant(input.variant, &namespace, &message, input.seed).unwrap()
    }

    fn subject_args<'a>(scheme: &'a str, variant: &'a str, kind: &'a str) -> Vec<&'a str> {
        let mut args = vec![
            "commonware-sol-fuzz",
            "simplex",
            "generate",
            scheme,
            "--variant",
            variant,
            "--kind",
            kind,
            "--namespace-hex",
            "0x74657374",
            "--epoch",
            "127",
            "--view",
            "128",
        ];
        if kind != "nullify" {
            args.extend([
                "--parent",
                "0",
                "--payload-hex",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ]);
        }
        args
    }

    #[test]
    fn framing_matches_simplex_subjects_and_namespace_domains() {
        for (kind, suffix) in [
            (Kind::Notarize, b"_NOTARIZE".as_slice()),
            (Kind::Nullify, b"_NULLIFY"),
            (Kind::Finalize, b"_FINALIZE"),
        ] {
            let input = args(kind);
            let output = threshold_output(&input);
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

        let mut input = args(Kind::Nullify);
        input.namespace_hex = const_hex::encode([0; 120]);
        assert_eq!(&threshold_output(&input).message[..2], &[0x80, 0x01]);
    }

    #[test]
    fn threshold_routes_both_variants_to_threshold_certificate_generation() {
        for (variant, signature_len, public_len, hash_len) in
            [("minsig", 96, 256, 128), ("minpk", 192, 128, 256)]
        {
            for kind in ["notarize", "nullify", "finalize"] {
                let encoded = Cli::try_parse_from(
                    subject_args("threshold", variant, kind)
                        .into_iter()
                        .chain(["--seed", "42"]),
                )
                .unwrap()
                .command
                .execute()
                .unwrap();
                let (signature, public_key, message, hash_point) =
                    <sol!((bytes, bytes, bytes, bytes))>::abi_decode_params_validate(&encoded)
                        .unwrap();
                assert_eq!(
                    (signature.len(), public_key.len(), hash_point.len()),
                    (signature_len, public_len, hash_len)
                );
                let suffix = match kind {
                    "notarize" => b"_NOTARIZE".as_slice(),
                    "nullify" => b"_NULLIFY",
                    "finalize" => b"_FINALIZE",
                    _ => unreachable!(),
                };
                let mut expected = vec![(4 + suffix.len()) as u8];
                expected.extend_from_slice(b"test");
                expected.extend_from_slice(suffix);
                expected.extend_from_slice(&[0x7f, 0x80, 0x01]);
                if kind != "nullify" {
                    expected.extend_from_slice(&[0; 33]);
                }
                assert_eq!(message.as_ref(), expected);
            }
        }
    }

    #[test]
    fn multisig_routes_both_variants_with_simplex_subject_framing() {
        for (variant, public_size) in [("minsig", 256), ("minpk", 128)] {
            for kind in ["notarize", "nullify", "finalize"] {
                let encoded = Cli::try_parse_from(
                    subject_args("multisig", variant, kind).into_iter().chain([
                        "--participants",
                        "9",
                        "--signers",
                        "0x0101",
                        "--seed",
                        "42",
                    ]),
                )
                .unwrap()
                .command
                .execute()
                .unwrap();
                let (_, public_keys, signers, message) =
                    <sol!((bytes, bytes, bytes, bytes))>::abi_decode_params_validate(&encoded)
                        .unwrap();
                assert_eq!(public_keys.len(), 9 * public_size);
                assert_eq!(signers.as_ref(), &[0x01, 0x01]);

                let mut input = args(match kind {
                    "notarize" => Kind::Notarize,
                    "nullify" => Kind::Nullify,
                    "finalize" => Kind::Finalize,
                    _ => unreachable!(),
                });
                if kind != "nullify" {
                    input.parent = Some(0);
                    input.payload_hex = Some(const_hex::encode([0; 32]));
                }
                let (namespace, subject_message) = input.subject().unwrap();
                assert_eq!(
                    message.as_ref(),
                    certificate::frame(&namespace, &subject_message).unwrap()
                );
            }
        }
    }

    #[test]
    fn schemes_require_named_inputs() {
        for scheme in ["threshold", "multisig"] {
            for (variant, public_size) in [("minsig", 256), ("minpk", 128)] {
                let mut complete = subject_args(scheme, variant, "nullify");
                let mut required = vec![
                    "--variant",
                    "--kind",
                    "--namespace-hex",
                    "--epoch",
                    "--view",
                    "--seed",
                ];
                if scheme == "multisig" {
                    complete.extend(["--participants", "4", "--signers", "0x01"]);
                    required.extend(["--participants", "--signers"]);
                }
                complete.extend(["--seed", "7"]);

                for option in required {
                    let mut missing = complete.clone();
                    let index = missing
                        .iter()
                        .position(|argument| *argument == option)
                        .unwrap();
                    missing.drain(index..=index + 1);
                    assert!(
                        Cli::try_parse_from(missing).is_err(),
                        "accepted {scheme} missing {option}"
                    );
                }

                let encoded = Cli::try_parse_from(complete.clone())
                    .unwrap()
                    .command
                    .execute()
                    .unwrap();
                if scheme == "multisig" {
                    let (_, public_keys, signers, _) =
                        <sol!((bytes, bytes, bytes, bytes))>::abi_decode_params_validate(&encoded)
                            .unwrap();
                    assert_eq!(public_keys.len(), 4 * public_size);
                    assert_eq!(signers.as_ref(), &[0x01]);
                    assert!(
                        Cli::try_parse_from(
                            complete.iter().copied().chain(["--signers-hex", "0x01"])
                        )
                        .is_err()
                    );
                }
            }
        }
    }

    #[test]
    fn proposal_fields_match_the_subject_kind_for_both_schemes() {
        for scheme in ["threshold", "multisig"] {
            for kind in ["notarize", "finalize"] {
                let mut complete = subject_args(scheme, "minsig", kind);
                if scheme == "multisig" {
                    complete.extend(["--participants", "4", "--signers", "0x01"]);
                }
                complete.extend(["--seed", "7"]);

                for option in ["--parent", "--payload-hex"] {
                    let mut missing = complete.clone();
                    let index = missing
                        .iter()
                        .position(|argument| *argument == option)
                        .unwrap();
                    missing.drain(index..=index + 1);
                    assert!(
                        Cli::try_parse_from(missing).is_err(),
                        "accepted {scheme} {kind} without {option}"
                    );
                }
            }

            let mut complete = subject_args(scheme, "minsig", "nullify");
            if scheme == "multisig" {
                complete.extend(["--participants", "4", "--signers", "0x01"]);
            }
            complete.extend(["--seed", "7"]);
            Cli::try_parse_from(complete.clone())
                .unwrap()
                .command
                .execute()
                .unwrap();

            for fields in [
                ["--parent", "0"],
                [
                    "--payload-hex",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                ],
            ] {
                assert!(
                    Cli::try_parse_from(complete.iter().copied().chain(fields))
                        .unwrap()
                        .command
                        .execute()
                        .is_err(),
                    "accepted {scheme} nullify with {}",
                    fields[0]
                );
            }
        }
    }

    #[test]
    fn threshold_rejects_multisig_fields_and_old_flags() {
        let base = subject_args("threshold", "minsig", "nullify");
        for fields in [
            ["4", "0x07"],
            ["--participants", "4"],
            ["--signers", "0x07"],
            ["--signers-hex", "0x07"],
        ] {
            assert!(
                Cli::try_parse_from(base.iter().copied().chain(["--seed", "7"]).chain(fields))
                    .is_err()
            );
        }

        assert!(
            Cli::try_parse_from([
                "commonware-sol-fuzz",
                "simplex",
                "generate-multisig",
                "minsig",
                "nullify",
            ])
            .is_err()
        );
        assert!(Cli::try_parse_from(["commonware-sol-fuzz", "multisig", "generate"]).is_err());
        assert!(
            Cli::try_parse_from(["commonware-sol-fuzz", "certificate", "generate", "minsig",])
                .is_err()
        );
    }
}
