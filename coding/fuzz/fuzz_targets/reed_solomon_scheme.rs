#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use bytes::{BufMut, Bytes, BytesMut};
use commonware_codec::{Copying, Decode, DecodeExt as _, Encode, EncodeSize, Write};
use commonware_coding::{Config, ReedSolomon, ReedSolomonError as Error, Scheme};
use commonware_cryptography::{Sha256, reed_solomon::Error as RsError, sha256::Digest};
use commonware_parallel::{
    Rayon, Sequential, Strategy,
    mocks::{self, Explorer},
};
use commonware_runtime::{Runner, deterministic};
use commonware_utils::{Entropy, FuzzRng, NZU16};
use libfuzzer_sys::fuzz_target;
use rand_core::Rng as _;

type RS = ReedSolomon<Sha256>;
type Shard = <RS as Scheme>::Shard;
type Checked = <RS as Scheme>::CheckedShard;

const MAX_MINIMUM: u16 = 6;
const MAX_EXTRA: u16 = 6;
/// Payload bytes a narrow codeword carries.
const MAX_DATA: usize = 192;
/// The narrowest shard a strategy planning two tasks codes as two stripes.
const WIDE_SHARD: usize = 2 * 8 * 1024;
/// The shard of a two-shard codeword that is coded as several tiles.
const TILED_SHARD: usize = 1 << 20;
/// The shard counts the backend rejects, whose total still fits sixteen bits.
const UNSUPPORTED: Config = Config {
    minimum_shards: NZU16!(16385),
    extra_shards: NZU16!(32769),
};
/// The smallest shard counts whose total does not fit sixteen bits.
const OVERSIZED: Config = Config {
    minimum_shards: NZU16!(u16::MAX / 2 + 1),
    extra_shards: NZU16!(u16::MAX / 2 + 1),
};
const MAX_TAMPERS: usize = 3;
const MAX_MISCONFIGS: usize = 2;
const STREAM_BYTES: usize = 1 << 11;
const SEED_BYTES: usize = 8;
const ENTROPY_BYTES: usize = 32;

thread_local! {
    /// A single-worker pool planning more tasks than it has workers, so stripes are cut without
    /// another thread coding them.
    static POOL: Rayon = mocks::inline(mocks::TASKS);
}

/// How wide the codeword's shards are.
#[derive(Debug, Clone, Copy)]
enum Shape {
    /// A payload of a few bytes, coded as one stripe of one tile.
    Narrow,
    /// Shards wide enough for a strategy planning two tasks to code as two stripes.
    Wide,
    /// A two-shard codeword whose shard is coded as several tiles.
    Tiled,
}

/// A change to one shard's encoding.
#[derive(Debug, Clone, Copy)]
enum Fault {
    /// The shard resized to this many bytes.
    Width(u8),
    /// The embedded index replaced.
    Index(u16),
    /// A bit of the proof flipped.
    Proof(u16),
    /// A bit of the shard flipped.
    Shard(u16),
}

#[derive(Debug, Clone, Copy)]
struct Tamper {
    /// The shard to change.
    shard: u16,
    /// The index to check it at.
    index: u16,
    fault: Fault,
}

/// What checking a shard must return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Checked,
    InvalidIndex(u16),
    InvalidShardSize(usize),
    InvalidProof,
    /// Any error.
    Rejected,
}

#[derive(Debug)]
struct Run {
    shape: Shape,
    config: Config,
    /// The payload of a narrow codeword.
    data: Vec<u8>,
    /// The byte pattern of a wide or tiled codeword's payload.
    fill: u8,
    /// The payload bound shards are decoded with, relative to the payload length.
    slack: i8,
    /// The shards decoded from, in order.
    selection: Vec<u16>,
    tampers: Vec<Tamper>,
    /// Other minimum shard counts for the codeword's total.
    misconfigs: Vec<u16>,
    /// A configuration sampled through its `Arbitrary` implementation.
    wild: Config,
    /// A commitment sampled through its `Arbitrary` implementation.
    stray_commitment: Digest,
    /// A shard sampled through its `Arbitrary` implementation.
    stray: Shard,
}

#[derive(Debug)]
struct FuzzInput {
    run: Run,
    entropy: Entropy,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // libFuzzer starts from inputs of a few bytes and lengthens them slowly, and a run
        // sampled from so few bytes would hold no codeword. The input's head therefore seeds a
        // fixed-size stream of [`FuzzRng`] output that the rest of the input overwrites from its
        // start, so every input, even an empty one, samples a whole run, and a byte mutated past
        // the head changes only what is sampled from it.
        let seed = u.bytes(u.len().min(SEED_BYTES))?.to_vec();
        let mut stream = vec![0; STREAM_BYTES.max(u.len())];
        FuzzRng::new(seed).fill_bytes(&mut stream);
        let literal = u.bytes(u.len())?;
        stream[..literal.len()].copy_from_slice(literal);
        let (run, entropy) = stream.split_at(stream.len() - ENTROPY_BYTES);
        let u = &mut Unstructured::new(run);

        Ok(Self {
            run: run_input(u)?,
            entropy: Unstructured::new(entropy).arbitrary()?,
        })
    }
}

fn run_input(u: &mut Unstructured<'_>) -> arbitrary::Result<Run> {
    let shape = match u.int_in_range(0u8..=31)? {
        0..=27 => Shape::Narrow,
        28..=30 => Shape::Wide,
        _ => Shape::Tiled,
    };
    let config = match shape {
        Shape::Tiled => Config {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(1),
        },
        _ => Config {
            minimum_shards: NZU16!(u.int_in_range(1..=MAX_MINIMUM)?),
            extra_shards: NZU16!(u.int_in_range(1..=MAX_EXTRA)?),
        },
    };
    let minimum = config.minimum_shards.get();
    let total = minimum + config.extra_shards.get();
    let selection = selection(u, minimum, total)?;
    let tampers = (0..u.int_in_range(1..=MAX_TAMPERS)?)
        .map(|_| tamper(u, total))
        .collect::<arbitrary::Result<_>>()?;
    let misconfigs = (0..u.int_in_range(0..=MAX_MISCONFIGS)?)
        .map(|_| u.int_in_range(1..=total - 1))
        .collect::<arbitrary::Result<_>>()?;
    let fill = u.arbitrary()?;
    let slack = u.arbitrary()?;
    let wild = u.arbitrary()?;
    let stray_commitment = u.arbitrary()?;
    let len = u.int_in_range(0..=MAX_DATA)?;
    let data = u.bytes(len)?.to_vec();
    Ok(Run {
        shape,
        config,
        data,
        fill,
        slack,
        selection,
        tampers,
        misconfigs,
        wild,
        stray_commitment,
        stray: u.arbitrary()?,
    })
}

/// Samples between `minimum` and `total` distinct shard indices in a random order.
fn selection(u: &mut Unstructured<'_>, minimum: u16, total: u16) -> arbitrary::Result<Vec<u16>> {
    let count = usize::from(u.int_in_range(minimum..=total)?);
    let mut indices: Vec<u16> = (0..total).collect();
    for i in 0..count {
        let j = u.int_in_range(i..=indices.len() - 1)?;
        indices.swap(i, j);
    }
    indices.truncate(count);
    Ok(indices)
}

fn tamper(u: &mut Unstructured<'_>, total: u16) -> arbitrary::Result<Tamper> {
    let shard = u.int_in_range(0..=total - 1)?;
    let index = if u.ratio(3, 4)? {
        shard
    } else {
        u.int_in_range(0..=total)?
    };
    let fault = match u.int_in_range(0u8..=3)? {
        0 => Fault::Width(u.arbitrary()?),
        1 => Fault::Index(u.int_in_range(0..=total)?),
        2 => Fault::Proof(u.arbitrary()?),
        _ => Fault::Shard(u.arbitrary()?),
    };
    Ok(Tamper {
        shard,
        index,
        fault,
    })
}

/// A scheme that implements only what the trait requires, so it checks batches as the trait does
/// by default.
#[derive(Clone, Copy, Debug)]
struct Inherited;

impl Scheme for Inherited {
    type Commitment = Digest;
    type Shard = Shard;
    type CheckedShard = Checked;
    type Error = Error;

    fn max_shard_size(config: &Config, data: usize) -> usize {
        RS::max_shard_size(config, data)
    }

    fn encode(
        config: &Config,
        data: impl bytes::Buf,
        strategy: &impl Strategy,
    ) -> Result<(Digest, Vec<Shard>), Error> {
        RS::encode(config, data, strategy)
    }

    fn check(
        config: &Config,
        commitment: &Digest,
        index: u16,
        shard: &Shard,
        strategy: &impl Strategy,
    ) -> Result<Checked, Error> {
        RS::check(config, commitment, index, shard, strategy)
    }

    fn decode<'a>(
        config: &Config,
        commitment: &Digest,
        shards: impl Iterator<Item = &'a Checked>,
        strategy: &impl Strategy,
    ) -> Result<Vec<u8>, Error> {
        RS::decode(config, commitment, shards, strategy)
    }
}

/// A `Buf` of `len` zero bytes that never holds them: encoding must reject such a length before
/// reading any of it.
struct Claimed(usize);

impl bytes::Buf for Claimed {
    fn remaining(&self) -> usize {
        self.0
    }

    fn chunk(&self) -> &[u8] {
        static ZEROS: [u8; 64] = [0; 64];
        &ZEROS[..self.0.min(ZEROS.len())]
    }

    fn advance(&mut self, cnt: usize) {
        assert!(cnt <= self.0);
        self.0 -= cnt;
    }
}

/// Returns a payload of `len` bytes following `fill`.
fn pattern(len: usize, fill: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8) ^ fill).collect()
}

/// The width of the shards encoding `data` bytes into `minimum` original shards: the prefixed
/// payload split evenly, rounded up to an even width.
fn width(data: usize, minimum: usize) -> usize {
    let width = data.saturating_add(4).div_ceil(minimum);
    width.saturating_add(width % 2)
}

/// Whether the backend codes `minimum` original and `extra` recovery shards: the smaller count
/// rounded up to a power of two plus the larger count must fit the field.
fn supported(minimum: usize, extra: usize) -> bool {
    let smaller = minimum.next_power_of_two().min(extra.next_power_of_two());
    smaller + minimum.max(extra) <= 1 << 16
}

/// Whether `result` rejects `minimum` original and `extra` recovery shards as unsupported.
fn unsupported<T>(result: Result<T, Error>, minimum: usize, extra: usize) -> bool {
    matches!(
        result,
        Err(Error::ReedSolomon(RsError::UnsupportedShardCount {
            original_count,
            recovery_count,
        })) if original_count == minimum && recovery_count == extra
    )
}

fn outcome(result: &Result<Checked, Error>) -> Outcome {
    match result {
        Ok(_) => Outcome::Checked,
        Err(Error::InvalidIndex(index)) => Outcome::InvalidIndex(*index),
        Err(Error::ReedSolomon(RsError::InvalidShardSize { shard_bytes })) => {
            Outcome::InvalidShardSize(*shard_bytes)
        }
        Err(Error::InvalidProof) => Outcome::InvalidProof,
        Err(_) => Outcome::Rejected,
    }
}

/// What checking shard `tamper.shard` of a codeword of `total` shards of `width` bytes returns
/// at `tamper.index` after `tamper.fault`: the requested index, the width, the embedded index and
/// finally the proof are validated in that order.
fn expected(total: u16, width: usize, tamper: &Tamper) -> Outcome {
    let Tamper {
        shard,
        index,
        fault,
    } = *tamper;
    let (new_width, embedded, changed) = match fault {
        Fault::Width(new_width) => (
            usize::from(new_width),
            shard,
            usize::from(new_width) != width,
        ),
        Fault::Index(embedded) => (width, embedded, false),
        Fault::Shard(_) => (width, shard, true),
        Fault::Proof(_) => return Outcome::Rejected,
    };
    if index >= total {
        Outcome::InvalidIndex(index)
    } else if new_width == 0 || new_width % 2 == 1 {
        Outcome::InvalidShardSize(new_width)
    } else if embedded != index {
        Outcome::InvalidIndex(embedded)
    } else if changed || index != shard {
        Outcome::InvalidProof
    } else {
        Outcome::Checked
    }
}

/// Applies `fault` to the encoding of `shard`, whose data is `width` bytes, and decodes the
/// result, which a proof fault may leave undecodable.
fn tampered(shard: &Shard, width: usize, config: &Config, fault: Fault) -> Option<Shard> {
    let encoded = shard.encode();
    let head = width.encode_size() + width;
    let mut data = encoded[width.encode_size()..head].to_vec();
    let mut index = u16::decode(Copying(&encoded[head..head + 2])).expect("an index follows");
    let mut proof = encoded[head + 2..].to_vec();
    match fault {
        Fault::Width(new_width) => data.resize(usize::from(new_width), 0),
        Fault::Index(embedded) => index = embedded,
        Fault::Proof(bit) => {
            let at = usize::from(bit) % proof.len();
            proof[at] ^= 1 << (bit % 8);
        }
        Fault::Shard(bit) => data[usize::from(bit) % width] ^= 1 << (bit % 8),
    }
    let mut buf = BytesMut::new();
    Bytes::from(data).write(&mut buf);
    index.write(&mut buf);
    buf.put_slice(&proof);
    Shard::decode_cfg(buf.freeze(), &(*config, usize::MAX)).ok()
}

fn assert_same(a: &Result<Checked, Error>, b: &Result<Checked, Error>) {
    match (a, b) {
        (Ok(a), Ok(b)) => assert_eq!(a, b),
        (Err(a), Err(b)) => assert_eq!(format!("{a:?}"), format!("{b:?}")),
        _ => panic!("checks disagree: {a:?} and {b:?}"),
    }
}

/// Checks `items` one at a time, as a batch, and as the batch the trait checks by default, which
/// must agree, and returns the results.
fn check_all(
    config: &Config,
    commitment: &Digest,
    items: &[(u16, &Shard)],
    strategy: &impl Strategy,
) -> Vec<Result<Checked, Error>> {
    let single: Vec<_> = items
        .iter()
        .map(|&(index, shard)| RS::check(config, commitment, index, shard, strategy))
        .collect();
    let batched = RS::check_many(config, commitment, items, strategy);
    let inherited = Inherited::check_many(config, commitment, items, strategy);
    assert_eq!(batched.len(), items.len());
    assert_eq!(inherited.len(), items.len());
    for ((result, batched), inherited) in single.iter().zip(&batched).zip(&inherited) {
        assert_same(result, batched);
        assert_same(result, inherited);
    }
    single
}

/// Checks that a configuration no codeword was encoded with is rejected everywhere.
fn check_rejected(config: &Config, shard: &Shard, checked: &[Checked], strategy: &impl Strategy) {
    let total = config.total_shards();
    let (minimum, extra) = (
        usize::from(config.minimum_shards.get()),
        usize::from(config.extra_shards.get()),
    );
    let items = [(0, shard)];
    if u16::try_from(total).is_err() {
        assert!(matches!(
            RS::encode(config, [].as_slice(), strategy),
            Err(Error::TooManyTotalShards(n)) if n == total
        ));
        for result in check_all(config, &Digest::from([0; 32]), &items, strategy) {
            assert!(matches!(result, Err(Error::TooManyTotalShards(n)) if n == total));
        }
        assert!(matches!(
            RS::decode(config, &Digest::from([0; 32]), checked.iter(), strategy),
            Err(Error::TooManyTotalShards(n)) if n == total
        ));
    } else {
        assert!(!supported(minimum, extra));
        assert!(unsupported(
            RS::encode(config, [].as_slice(), strategy),
            minimum,
            extra
        ));
        assert!(unsupported(
            RS::decode(config, &Digest::from([0; 32]), checked.iter(), strategy),
            minimum,
            extra
        ));
        // The shard's proof is for another total.
        for result in check_all(config, &Digest::from([0; 32]), &items, strategy) {
            assert!(matches!(result, Err(Error::InvalidProof)));
        }
    }
}

fn run(run: Run, strategy: &impl Strategy) {
    let Run {
        shape,
        config,
        data,
        fill,
        slack,
        selection,
        tampers,
        misconfigs,
        wild,
        stray_commitment,
        stray,
    } = run;
    let minimum = config.minimum_shards.get();
    let extra = config.extra_shards.get();
    let total = minimum + extra;
    let data = match shape {
        Shape::Narrow => data,
        Shape::Wide => pattern(WIDE_SHARD * usize::from(minimum) - 4, fill),
        Shape::Tiled => pattern(TILED_SHARD - 4, fill),
    };
    let width = width(data.len(), usize::from(minimum));

    // A configuration serializes as its two counts.
    assert_eq!(
        Config::decode(config.encode()).expect("a configuration decodes"),
        config
    );

    // Every shard of the codeword fits the bound, which grows with the payload bound, and
    // decodes under a payload bound of at least its width.
    let (commitment, shards) =
        RS::encode(&config, data.as_slice(), strategy).expect("the configuration encodes");
    assert_eq!(shards.len(), usize::from(total));
    let bound = RS::max_shard_size(&config, data.len());
    let maximum = data.len().saturating_add_signed(slack.into());
    if maximum >= data.len() {
        assert!(RS::max_shard_size(&config, maximum) >= bound);
    }
    let fits = self::width(maximum.min(u32::MAX as usize), usize::from(minimum)) >= width;
    for shard in &shards {
        let encoded = shard.encode();
        assert_eq!(encoded.len(), shard.encode_size());
        assert!(encoded.len() <= bound);
        match Shard::decode_cfg(encoded.clone(), &(config, maximum)) {
            Ok(decoded) => {
                assert!(fits);
                assert_eq!(decoded, *shard);
                assert_eq!(decoded.encode(), encoded);
            }
            Err(_) => assert!(!fits),
        }
    }
    if let Ok(decoded) = Shard::decode_cfg(stray.encode(), &(config, usize::MAX)) {
        assert_eq!(decoded, stray);
    }

    // Every shard checks at its index, and a batch of them checks as the shards do alone.
    let valid: Vec<(u16, &Shard)> = (0u16..).zip(&shards).collect();
    let checked: Vec<Checked> = check_all(&config, &commitment, &valid, strategy)
        .into_iter()
        .map(|result| result.expect("a shard checks at its index"))
        .collect();

    // Changed shards, and a shard of no codeword, are rejected as the model predicts, alone and
    // in a batch with the valid shards.
    let mut suspects: Vec<(u16, Shard, Outcome)> = tampers
        .iter()
        .filter_map(|tamper| {
            let shard = tampered(
                &shards[usize::from(tamper.shard)],
                width,
                &config,
                tamper.fault,
            );
            if shard.is_none() {
                assert!(matches!(tamper.fault, Fault::Proof(_)));
            }
            shard.map(|shard| (tamper.index, shard, expected(total, width, tamper)))
        })
        .collect();
    suspects.push((selection[0], stray, Outcome::Rejected));
    let mixed: Vec<(u16, &Shard)> = valid
        .iter()
        .copied()
        .chain(suspects.iter().map(|(index, shard, _)| (*index, shard)))
        .collect();
    let results = check_all(&config, &commitment, &mixed, strategy);
    for (result, checked) in results.iter().zip(&checked) {
        assert_eq!(result.as_ref().ok(), Some(checked));
    }
    for ((_, _, expected), result) in suspects.iter().zip(&results[valid.len()..]) {
        match expected {
            Outcome::Rejected => assert!(result.is_err(), "{result:?}"),
            expected => assert_eq!(outcome(result), *expected, "{result:?}"),
        }
    }

    // A shard's proof is for its codeword's total.
    let larger = Config {
        minimum_shards: config.minimum_shards,
        extra_shards: NZU16!(extra + 1),
    };
    assert!(matches!(
        RS::check(&larger, &commitment, 0, &shards[0], strategy),
        Err(Error::InvalidProof)
    ));

    // The payload decodes from any selection of at least the minimum number of shards, in any
    // order, and from nothing less, nor from a repeated shard or a different commitment.
    let decode = |config: &Config, commitment: &Digest, indices: &[u16]| {
        RS::decode(
            config,
            commitment,
            indices.iter().map(|&index| &checked[usize::from(index)]),
            strategy,
        )
    };
    assert_eq!(
        decode(&config, &commitment, &selection).expect("the selection decodes"),
        data
    );
    assert!(matches!(
        decode(&config, &commitment, &[]),
        Err(Error::NotEnoughChunks)
    ));
    if minimum > 1 {
        assert!(matches!(
            decode(&config, &commitment, &selection[..usize::from(minimum) - 1]),
            Err(Error::NotEnoughChunks)
        ));
    }
    let first = selection[0];
    assert!(matches!(
        decode(&config, &commitment, &[first, first]),
        Err(Error::DuplicateIndex(index)) if index == first
    ));
    match decode(&config, &stray_commitment, &selection) {
        Ok(decoded) => {
            assert_eq!(stray_commitment, commitment);
            assert_eq!(decoded, data);
        }
        Err(Error::CommitmentMismatch) => assert_ne!(stray_commitment, commitment),
        Err(error) => panic!("unexpected error: {error:?}"),
    }

    // Another split of the same total reconstructs a different codeword, unless the shards
    // happen to form a codeword under both, and a total the shards exceed rejects them.
    let all: Vec<u16> = (0..total).collect();
    for &other in &misconfigs {
        let config = Config {
            minimum_shards: NZU16!(other),
            extra_shards: NZU16!(total - other),
        };
        for indices in [&all[..], &selection[..]] {
            match decode(&config, &commitment, indices) {
                Ok(decoded) => assert_eq!(decoded, data),
                Err(Error::NotEnoughChunks) => assert!(indices.len() < usize::from(other)),
                Err(Error::Inconsistent) => assert_ne!(other, minimum),
                Err(error) => panic!("unexpected error: {error:?}"),
            }
        }
    }
    assert!(matches!(
        decode(&larger, &commitment, &all),
        Err(Error::Inconsistent)
    ));
    if extra > 1 {
        let smaller = Config {
            minimum_shards: config.minimum_shards,
            extra_shards: NZU16!(extra - 1),
        };
        assert!(matches!(
            decode(&smaller, &commitment, &[total - 1]),
            Err(Error::InvalidIndex(index)) if index == total - 1
        ));
    }

    // Shard counts the backend rejects or that exceed the total, and payloads the length prefix
    // or the shard width cannot express, are rejected before anything is coded.
    check_rejected(&UNSUPPORTED, &shards[0], &checked, strategy);
    check_rejected(&OVERSIZED, &shards[0], &checked, strategy);
    let wild_total = wild.total_shards();
    if u16::try_from(wild_total).is_err()
        || !supported(
            usize::from(wild.minimum_shards.get()),
            usize::from(wild.extra_shards.get()),
        )
    {
        check_rejected(&wild, &shards[0], &checked, strategy);
    } else {
        RS::max_shard_size(&wild, data.len());
        let result = RS::check(&wild, &commitment, 0, &shards[0], strategy);
        if wild_total == u32::from(total) {
            assert_eq!(result.expect("the total matches"), checked[0]);
        } else {
            assert!(matches!(result, Err(Error::InvalidProof)));
        }
    }
    let max = u32::MAX as usize;
    assert!(matches!(
        RS::encode(&config, Claimed(max + 1), strategy),
        Err(Error::InvalidDataLength(len)) if len == max + 1
    ));
    let single = Config {
        minimum_shards: NZU16!(1),
        extra_shards: NZU16!(1),
    };
    assert!(matches!(
        RS::encode(&single, Claimed(max), strategy),
        Err(Error::InvalidDataLength(len)) if len == max
    ));
}

fn fuzz(input: FuzzInput) {
    let FuzzInput { run, entropy } = input;
    let cfg = deterministic::Config::new().with_rng(FuzzRng::from(entropy));
    let runner = deterministic::Runner::new(cfg);
    runner.start(|_| async move {
        match run.shape {
            Shape::Wide => POOL.with(|pool| self::run(run, &Explorer::parallel(pool))),
            Shape::Narrow | Shape::Tiled => self::run(run, &Sequential),
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
