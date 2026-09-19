//! Ordered exclusion fixtures with independently fixed or length-prefixed byte fields.

use super::{
    ExclusionMode, ExclusionTreeArgs, Materialized, current_output, materialize, validate_tree,
};
use crate::{
    Hash,
    merkle::{TreeKind, leaf},
};
use clap::{Args, ValueEnum};
use commonware_cryptography::{Hasher, Keccak256, Sha256};
use commonware_storage::{
    merkle::{Graftable, Location, mmb, mmr},
    qmdb::{
        any::{ordered::variable, value::VariableEncoding},
        current::ordered::proof::ExclusionProof,
        operation::Key,
    },
};
use commonware_utils::sequence::FixedBytes;

#[derive(Clone, Copy, ValueEnum)]
enum FieldSize {
    Variable,
    #[value(name = "0")]
    Fixed0,
    #[value(name = "1")]
    Fixed1,
    #[value(name = "4")]
    Fixed4,
    #[value(name = "32")]
    Fixed32,
}

#[derive(Args)]
pub(crate) struct ExcludeVariableArgs {
    #[command(flatten)]
    tree: ExclusionTreeArgs,
    #[arg(long)]
    key_hex: String,
    /// Length-prefixed vector or fixed key width.
    #[arg(long, value_enum)]
    key_size: FieldSize,
    /// Length-prefixed vector or fixed value width.
    #[arg(long, value_enum)]
    value_size: FieldSize,
    /// Raw vector value or metadata length, required for variable values.
    #[arg(long, required_if_eq("value_size", "variable"))]
    value_length: Option<u16>,
    /// Complete active key set as comma-separated hex, sorted into cyclic order.
    /// Use 0x for a zero-length key. Empty mode uses --derive-keys.
    #[arg(
        long,
        value_delimiter = ',',
        required_unless_present = "derive_keys",
        conflicts_with = "derive_keys"
    )]
    keys: Vec<String>,
    /// Derive the complete active key set from ordered integer indices.
    #[arg(long)]
    derive_keys: bool,
    #[arg(long, value_enum)]
    mode: ExclusionMode,
    #[arg(long)]
    metadata: bool,
}

trait FixtureBytes: Key {
    const SIZE: Option<usize>;
    fn from_raw(bytes: Vec<u8>) -> Result<Self, String>;
}

impl FixtureBytes for Vec<u8> {
    const SIZE: Option<usize> = None;

    fn from_raw(bytes: Vec<u8>) -> Result<Self, String> {
        Ok(bytes)
    }
}

impl<const N: usize> FixtureBytes for FixedBytes<N> {
    const SIZE: Option<usize> = Some(N);

    fn from_raw(bytes: Vec<u8>) -> Result<Self, String> {
        let length = bytes.len();
        Ok(Self::new(bytes.try_into().map_err(|_| {
            format!("expected {N} bytes, got {length}")
        })?))
    }
}

macro_rules! with_field_type {
    ($size:expr, |$t:ident| $body:expr) => {
        match $size {
            FieldSize::Variable => {
                type $t = Vec<u8>;
                $body
            }
            FieldSize::Fixed0 => {
                type $t = FixedBytes<0>;
                $body
            }
            FieldSize::Fixed1 => {
                type $t = FixedBytes<1>;
                $body
            }
            FieldSize::Fixed4 => {
                type $t = FixedBytes<4>;
                $body
            }
            FieldSize::Fixed32 => {
                type $t = FixedBytes<32>;
                $body
            }
        }
    };
}

impl ExcludeVariableArgs {
    pub(super) fn execute(self, hash: Hash) -> Result<Vec<u8>, String> {
        match (self.tree.family, hash) {
            (TreeKind::Mmr, Hash::Keccak256) => self.dispatch::<mmr::Family, Keccak256>(),
            (TreeKind::Mmr, Hash::Sha256) => self.dispatch::<mmr::Family, Sha256>(),
            (TreeKind::Mmb, Hash::Keccak256) => self.dispatch::<mmb::Family, Keccak256>(),
            (TreeKind::Mmb, Hash::Sha256) => self.dispatch::<mmb::Family, Sha256>(),
        }
    }

    fn dispatch<F: Graftable, H: Hasher>(&self) -> Result<Vec<u8>, String> {
        with_field_type!(self.key_size, |K| {
            with_field_type!(self.value_size, |V| generate::<F, H, K, V>(self))
        })
    }
}

fn raw_hex(input: &str) -> Result<Vec<u8>, String> {
    const_hex::decode(input.strip_prefix("0x").unwrap_or(input)).map_err(|e| e.to_string())
}

fn keys<K: FixtureBytes>(args: &ExcludeVariableArgs) -> Result<Vec<K>, String> {
    let count = match args.mode {
        ExclusionMode::Interval => args.tree.leaves as usize,
        ExclusionMode::Single => 1,
        ExclusionMode::Empty => 0,
    };
    let mut keys = if args.derive_keys {
        (0..count)
            .map(|index| {
                let ordinal = (index as u64).to_be_bytes();
                let raw = if let Some(size) = K::SIZE {
                    if size < ordinal.len()
                        && ordinal[..ordinal.len() - size].iter().any(|&b| b != 0)
                    {
                        return Err(
                            "active key count exceeds the configured fixed key space".into()
                        );
                    }
                    let mut raw = vec![0; size];
                    let copied = size.min(ordinal.len());
                    raw[size - copied..].copy_from_slice(&ordinal[ordinal.len() - copied..]);
                    raw
                } else {
                    // The ordinal orders distinct keys. Suffixes give one database several key lengths.
                    let mut raw = ordinal.to_vec();
                    raw.resize(raw.len() + index % 3, 0);
                    raw
                };
                K::from_raw(raw)
            })
            .collect::<Result<Vec<_>, String>>()?
    } else {
        if args.keys.len() != count {
            return Err(format!(
                "--keys requires exactly {count} active keys for this mode"
            ));
        }
        args.keys
            .iter()
            .map(|key| K::from_raw(raw_hex(key)?))
            .collect::<Result<Vec<_>, _>>()?
    };
    keys.sort();
    if keys.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("active keys must be distinct".into());
    }
    Ok(keys)
}

fn generate<F: Graftable, H: Hasher, K: FixtureBytes, V: FixtureBytes>(
    args: &ExcludeVariableArgs,
) -> Result<Vec<u8>, String> {
    let tree = args.tree.tree(args.mode);
    validate_tree(&tree)?;
    if args.metadata && !matches!(args.mode, ExclusionMode::Empty) {
        return Err("metadata requires empty mode".into());
    }
    if !matches!(args.mode, ExclusionMode::Interval) && args.tree.location != args.tree.leaves - 1 {
        return Err("empty and single modes require location = leaves - 1".into());
    }
    if args.value_length.is_some() && V::SIZE.is_some() {
        return Err("value-length requires --value-size variable".into());
    }
    let query = K::from_raw(raw_hex(&args.key_hex)?)?;
    let keys = keys::<K>(args)?;
    let length = V::SIZE
        .or(args.value_length.map(usize::from))
        .ok_or("variable values require --value-length")?;
    let value = V::from_raw(
        leaf(args.tree.seed, args.tree.location)
            .into_iter()
            .cycle()
            .take(length)
            .collect(),
    )?;
    let op = |index| match args.mode {
        ExclusionMode::Empty => variable::Operation::<F, K, V>::CommitFloor(
            args.metadata.then(|| value.clone()),
            Location::new(index),
        ),
        ExclusionMode::Interval | ExclusionMode::Single => {
            let current = if matches!(args.mode, ExclusionMode::Single) {
                0
            } else {
                index as usize
            };
            variable::Operation::Update(variable::Update {
                key: keys[current].clone(),
                value: value.clone(),
                next_key: keys[(current + 1) % keys.len()].clone(),
            })
        }
    };
    let Materialized {
        output,
        proof,
        root,
        ..
    } = materialize::<F, H, _>(&tree, args.tree.chunk_bytes, op, |index| {
        matches!(args.mode, ExclusionMode::Interval) || index == tree.location
    })?;
    let exclusion: ExclusionProof<F, K, VariableEncoding<V>, H::Digest, _> = match op(tree.location)
    {
        variable::Operation::Update(update) => ExclusionProof::KeyValue(proof, update),
        variable::Operation::CommitFloor(metadata, _) => ExclusionProof::Commit(proof, metadata),
        variable::Operation::Delete(_) => unreachable!(),
    };
    Ok(current_output(output, exclusion.verify::<H>(&query, &root)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cli;
    use alloy_sol_macro::sol;
    use alloy_sol_types::{SolType, SolValue};
    use clap::Parser;
    use commonware_codec::{Copying, Decode, Encode, RangeCfg};

    type Output = <sol!((bytes32, uint256, uint256, uint256, bytes, bytes32, bytes32, bytes32, bytes32[], bytes, bool)) as SolType>::RustType;

    fn run(hash: &str, arguments: &[&str]) -> Result<Output, String> {
        let encoded = Cli::try_parse_from(
            ["fuzz", "qmdb", "--hash", hash, "exclude-variable"]
                .into_iter()
                .chain(arguments.iter().copied()),
        )
        .map_err(|e| e.to_string())?
        .command
        .execute()?;
        Output::abi_decode_params_validate(&encoded).map_err(|e| e.to_string())
    }

    #[test]
    fn vector_keys_use_raw_order_and_vary_in_length() {
        for family in ["mmr", "mmb"] {
            for hash in ["keccak256", "sha256"] {
                for (location, query, expected) in [
                    ("0", "0000", true),
                    ("0", "00", false),
                    ("0", "01", false),
                    ("1", "0100", true),
                    ("2", "0x", true),
                ] {
                    let output = run(
                        hash,
                        &[
                            "--leaves",
                            "3",
                            "--location",
                            location,
                            "--seed",
                            "42",
                            "--key-hex",
                            query,
                            "--keys",
                            "00,01,010000",
                            "--family",
                            family,
                            "--chunk-bytes",
                            "32",
                            "--key-size",
                            "variable",
                            "--value-size",
                            "variable",
                            "--value-length",
                            "31",
                            "--mode",
                            "interval",
                        ],
                    )
                    .unwrap();
                    assert_eq!(output.10, expected);
                    let cfg = ((RangeCfg::from(..), ()), (RangeCfg::from(..), ()));
                    let operation =
                        variable::Operation::<mmb::Family, Vec<u8>, Vec<u8>>::decode_cfg(
                            Copying(output.9.as_ref()),
                            &cfg,
                        )
                        .unwrap();
                    assert!(matches!(operation, variable::Operation::Update(_)));
                }
            }
        }
        let args = ExcludeVariableArgs {
            tree: ExclusionTreeArgs {
                leaves: 3,
                location: 0,
                seed: 0,
                family: TreeKind::Mmb,
                chunk_bytes: 32,
            },
            key_hex: String::new(),
            key_size: FieldSize::Variable,
            value_size: FieldSize::Variable,
            value_length: Some(0),
            keys: vec![],
            derive_keys: true,
            mode: ExclusionMode::Interval,
            metadata: false,
        };
        let generated = keys::<Vec<u8>>(&args).unwrap();
        assert_eq!(
            generated.iter().map(Vec::len).collect::<Vec<_>>(),
            [8, 9, 10]
        );
        assert!(generated.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn fixed_and_vector_fields_match_production_operation_bytes() {
        for key_size in [None, Some(0), Some(1), Some(4), Some(32)] {
            for value_size in [None, Some(0), Some(1), Some(4), Some(32)] {
                let raw_key = vec![0; key_size.unwrap_or(33)];
                let raw_value = vec![0; value_size.unwrap_or(128)];
                let key_hex = const_hex::encode(&raw_key);
                let key_size_text =
                    key_size.map_or_else(|| "variable".into(), |size| size.to_string());
                let value_size_text =
                    value_size.map_or_else(|| "variable".into(), |size| size.to_string());
                let mut arguments = vec![
                    "--leaves",
                    "1",
                    "--location",
                    "0",
                    "--seed",
                    "42",
                    "--key-hex",
                    &key_hex,
                    "--mode",
                    "single",
                    "--family",
                    "mmb",
                    "--chunk-bytes",
                    "32",
                ];
                let explicit_key = format!("0x{key_hex}");
                arguments.extend(["--keys", &explicit_key]);
                arguments.extend([
                    "--key-size",
                    &key_size_text,
                    "--value-size",
                    &value_size_text,
                ]);
                if value_size.is_none() {
                    arguments.extend(["--value-length", "128"]);
                }
                let output = run("keccak256", &arguments).unwrap();
                assert!(!output.10);
                let mut expected = vec![0xd2];
                if key_size.is_none() {
                    expected.extend(raw_key.encode());
                } else {
                    expected.extend(&raw_key);
                }
                let actual_value = leaf(42, 0)
                    .into_iter()
                    .cycle()
                    .take(raw_value.len())
                    .collect::<Vec<_>>();
                if value_size.is_none() {
                    expected.extend(actual_value.encode());
                } else {
                    expected.extend(actual_value);
                }
                if key_size.is_none() {
                    expected.extend(raw_key.encode());
                } else {
                    expected.extend(raw_key);
                }
                assert_eq!(output.9.as_ref(), expected);
            }
        }
    }

    #[test]
    fn empty_commits_encode_option_and_varint_floor() {
        for floor in [0, 127, 128] {
            for metadata in [false, true] {
                for value_size in [None, Some(0), Some(1), Some(4), Some(32)] {
                    let leaves = (floor + 1).to_string();
                    let location = floor.to_string();
                    let width =
                        value_size.map_or_else(|| "variable".into(), |size| size.to_string());
                    let mut arguments = vec![
                        "--leaves",
                        leaves.as_str(),
                        "--location",
                        location.as_str(),
                        "--seed",
                        "42",
                        "--key-hex",
                        "0x",
                        "--mode",
                        "empty",
                        "--family",
                        "mmb",
                        "--chunk-bytes",
                        "32",
                    ];
                    if metadata {
                        arguments.push("--metadata");
                    }
                    arguments.extend([
                        "--key-size",
                        "variable",
                        "--value-size",
                        &width,
                        "--derive-keys",
                    ]);
                    if value_size.is_none() {
                        arguments.extend(["--value-length", "0"]);
                    }
                    let output = run("keccak256", &arguments).unwrap();
                    assert!(output.10);
                    let mut expected = vec![0xd3, u8::from(metadata)];
                    if metadata {
                        if let Some(size) = value_size {
                            expected.extend(leaf(42, floor).into_iter().cycle().take(size));
                        } else {
                            expected.push(0);
                        }
                    }
                    expected.extend(Location::<mmb::Family>::new(floor).encode());
                    assert_eq!(output.9.as_ref(), expected);
                }
            }
        }
    }

    #[test]
    fn selected_chunk_width_reaches_the_current_proof() {
        for chunk in ["1", "128"] {
            let output = run(
                "keccak256",
                &[
                    "--leaves",
                    "3",
                    "--location",
                    "0",
                    "--seed",
                    "42",
                    "--key-hex",
                    "0000",
                    "--keys",
                    "00,01,010000",
                    "--chunk-bytes",
                    chunk,
                    "--family",
                    "mmb",
                    "--key-size",
                    "variable",
                    "--value-size",
                    "variable",
                    "--value-length",
                    "31",
                    "--mode",
                    "interval",
                ],
            )
            .unwrap();
            assert!(output.10);
            assert_eq!(output.4.len(), chunk.parse::<usize>().unwrap());
        }
    }

    #[test]
    fn cli_requires_explicit_codecs_and_key_source() {
        use clap::error::ErrorKind;

        let args = vec![
            "fuzz",
            "qmdb",
            "--hash",
            "keccak256",
            "exclude-variable",
            "--leaves",
            "1",
            "--location",
            "0",
            "--seed",
            "42",
            "--family",
            "mmb",
            "--chunk-bytes",
            "32",
            "--key-hex",
            "0x",
            "--mode",
            "single",
            "--key-size",
            "variable",
            "--value-size",
            "variable",
            "--value-length",
            "0",
            "--keys",
            "0x",
        ];
        assert!(Cli::try_parse_from(&args).is_ok());
        for field in ["--key-size", "--value-size", "--value-length", "--keys"] {
            let mut missing = args.clone();
            let index = missing.iter().position(|arg| *arg == field).unwrap();
            missing.drain(index..index + 2);
            let error = Cli::try_parse_from(missing).err().unwrap();
            assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
            assert!(error.to_string().contains(field), "{error}");
        }
        let mut conflicting = args.clone();
        conflicting.push("--derive-keys");
        let error = Cli::try_parse_from(conflicting).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
        let mut irrelevant = args.clone();
        irrelevant.extend(["--inactivity-floor", "0"]);
        let error = Cli::try_parse_from(irrelevant).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
        assert!(error.to_string().contains("--inactivity-floor"), "{error}");
        let mut legacy = args.clone();
        let key_hex_index = legacy.iter().position(|arg| *arg == "--key-hex").unwrap();
        legacy[key_hex_index] = "--keyhex";
        let error = Cli::try_parse_from(legacy).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
        assert!(error.to_string().contains("--keyhex"), "{error}");
        let mut derived = args;
        derived.truncate(derived.len() - 2);
        derived.push("--derive-keys");
        assert!(Cli::try_parse_from(derived).is_ok());
    }

    #[test]
    fn invalid_fixture_requests_are_rejected() {
        for args in [
            vec![
                "--leaves",
                "1",
                "--location",
                "0",
                "--seed",
                "42",
                "--key-hex",
                "00",
                "--key-size",
                "2",
                "--family",
                "mmb",
                "--chunk-bytes",
                "32",
                "--mode",
                "interval",
                "--value-size",
                "variable",
                "--value-length",
                "31",
                "--derive-keys",
            ],
            vec![
                "--leaves",
                "1",
                "--location",
                "0",
                "--seed",
                "42",
                "--key-hex",
                "00",
                "--key-size",
                "4",
                "--family",
                "mmb",
                "--chunk-bytes",
                "32",
                "--mode",
                "interval",
                "--value-size",
                "variable",
                "--value-length",
                "31",
                "--derive-keys",
            ],
            vec![
                "--leaves",
                "1",
                "--location",
                "0",
                "--seed",
                "42",
                "--key-hex",
                "00",
                "--value-size",
                "1",
                "--value-length",
                "1",
                "--family",
                "mmb",
                "--chunk-bytes",
                "32",
                "--mode",
                "interval",
                "--key-size",
                "variable",
                "--derive-keys",
            ],
            vec![
                "--leaves",
                "2",
                "--location",
                "0",
                "--seed",
                "42",
                "--key-hex",
                "00",
                "--mode",
                "single",
                "--family",
                "mmb",
                "--chunk-bytes",
                "32",
                "--key-size",
                "variable",
                "--value-size",
                "variable",
                "--value-length",
                "31",
                "--derive-keys",
            ],
            vec![
                "--leaves",
                "2",
                "--location",
                "0",
                "--seed",
                "42",
                "--key-hex",
                "00",
                "--keys",
                "00,00",
                "--family",
                "mmb",
                "--chunk-bytes",
                "32",
                "--mode",
                "interval",
                "--key-size",
                "variable",
                "--value-size",
                "variable",
                "--value-length",
                "31",
            ],
            vec![
                "--leaves",
                "2",
                "--location",
                "0",
                "--seed",
                "42",
                "--key-hex",
                "00",
                "--keys",
                "00",
                "--family",
                "mmb",
                "--chunk-bytes",
                "32",
                "--mode",
                "interval",
                "--key-size",
                "variable",
                "--value-size",
                "variable",
                "--value-length",
                "31",
            ],
            vec![
                "--leaves",
                "1",
                "--location",
                "0",
                "--seed",
                "42",
                "--key-hex",
                "00",
                "--metadata",
                "--family",
                "mmb",
                "--chunk-bytes",
                "32",
                "--mode",
                "interval",
                "--key-size",
                "variable",
                "--value-size",
                "variable",
                "--value-length",
                "31",
                "--derive-keys",
            ],
            vec![
                "--leaves",
                "2",
                "--location",
                "0",
                "--seed",
                "42",
                "--key-hex",
                "0x",
                "--key-size",
                "0",
                "--family",
                "mmb",
                "--chunk-bytes",
                "32",
                "--mode",
                "interval",
                "--value-size",
                "variable",
                "--value-length",
                "31",
                "--derive-keys",
            ],
        ] {
            assert!(run("keccak256", &args).is_err(), "{args:?}");
        }
    }
}
