//! Seeded Commonware Simplex threshold inputs.

use crate::certificate::{self, BlsVariant};
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
    /// Recover a 3-of-4 threshold signature for a Simplex voting subject.
    Generate(GenerateArgs),
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

impl GenerateArgs {
    fn generate(&self) -> Result<certificate::Output, String> {
        let namespace = Namespace::new(&certificate::decode_hex(&self.namespace_hex)?);
        let payload = certificate::decode_hex(&self.payload_hex)?;
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
        certificate::generate_variant(
            self.variant,
            subject.namespace(&namespace),
            &subject.message(),
            self.seed,
        )
    }
}

impl Command {
    pub(crate) fn execute(self) -> Result<Vec<u8>, String> {
        match self {
            Self::Generate(args) => Ok(certificate::encode_output(args.generate()?)),
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

    #[test]
    fn framing_matches_simplex_subjects_and_namespace_domains() {
        for (kind, suffix) in [
            (Kind::Notarize, b"_NOTARIZE".as_slice()),
            (Kind::Nullify, b"_NULLIFY"),
            (Kind::Finalize, b"_FINALIZE"),
        ] {
            let input = args(kind, 7);
            let output = input.generate().unwrap();
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
        let before = input.generate().unwrap();
        input.parent = 0;
        input.payload_hex = const_hex::encode([0; 32]);
        assert_eq!(before.signature, input.generate().unwrap().signature);
        input.namespace_hex = const_hex::encode([0; 120]);
        assert_eq!(&input.generate().unwrap().message[..2], &[0x80, 0x01]);
    }

    #[test]
    fn cli_generate_returns_expected_abi_for_both_variants() {
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
            let (signature, public_key, message, hash_point) =
                <sol!((bytes, bytes, bytes, bytes))>::abi_decode_params_validate(&encoded).unwrap();
            assert_eq!(
                (signature.len(), public_key.len(), hash_point.len()),
                (signature_len, public_len, hash_len)
            );
            let mut expected = b"\x0dtest_NOTARIZE\x7f\x80\x01\x00".to_vec();
            expected.extend_from_slice(&[0; 32]);
            assert_eq!(message.as_ref(), expected);
        }
    }
}
