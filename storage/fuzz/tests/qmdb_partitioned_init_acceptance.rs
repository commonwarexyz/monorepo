//! Acceptance tests for the partitioned QMDB initialization input model.
//!
//! The fast tests run with the crate suite. Process-heavy tests are ignored by default and use
//! binaries and LCOV directories supplied through the environment, so their builds and profiles
//! can stay outside the source tree.

use arbitrary::Unstructured;
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_storage_fuzz::{SEED_BYTES, STREAM_BYTES, stream};
use commonware_utils::{Entropy, FuzzRng};
use rand::Rng as _;
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const TARGET: &str = "fuzz_targets/qmdb_any_partitioned_init.rs";
const PARTITIONS: [u64; 8] = [0, 1, 63, 64, 127, 128, 254, 255];
const ASSERTION_LINES: [u64; 4] = [315, 320, 327, 332];

fn fuzz_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn required_path(variable: &str) -> PathBuf {
    env::var_os(variable)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("{variable} must name the acceptance artifact"))
}

fn fixed_inputs() -> Vec<(String, Vec<u8>)> {
    let mut inputs = vec![
        ("empty".to_string(), Vec::new()),
        ("nl".to_string(), vec![b'\n']),
    ];
    inputs.extend((0u8..32).map(|index| {
        (
            format!("s{index:02}"),
            vec![
                index.wrapping_mul(37).wrapping_add(11),
                index.wrapping_mul(101).wrapping_add(7),
            ],
        )
    }));
    inputs.extend([
        ("z4105".to_string(), vec![0; 4_105]),
        (
            "e_a".to_string(),
            [vec![0; 4_072], (0u8..32).collect()].concat(),
        ),
        (
            "e_b".to_string(),
            [vec![0; 4_072], (100u8..132).collect()].concat(),
        ),
    ]);
    inputs
}

fn expected_stream(input: &[u8]) -> Vec<u8> {
    let seed_len = input.len().min(SEED_BYTES);
    let mut expected = vec![0; STREAM_BYTES];
    FuzzRng::new(input[..seed_len].to_vec()).fill_bytes(&mut expected);
    let literal = &input[seed_len..input.len().min(seed_len + STREAM_BYTES)];
    expected[..literal.len()].copy_from_slice(literal);
    expected
}

#[derive(Debug)]
#[allow(dead_code)] // Fields exist to reproduce the target's derived Debug contract.
enum ReferenceWrite {
    Key {
        partition: u8,
        bucket: u8,
        suffix: u8,
        value: Option<u8>,
    },
    Flood {
        partition: u8,
        value: u8,
    },
}

#[derive(Debug)]
#[allow(dead_code)] // Fields exist to reproduce the target's derived Debug contract.
struct ReferenceCommit {
    hold: bool,
    writes: Vec<ReferenceWrite>,
}

#[derive(Debug)]
#[allow(dead_code)] // Fields exist to reproduce the target's derived Debug contract.
struct ReferenceInput {
    init_concurrency: u8,
    init_cache: u8,
    commits: Vec<ReferenceCommit>,
    probe: Vec<ReferenceWrite>,
    entropy: Entropy,
}

fn reference_concurrency(u: &mut Unstructured<'_>) -> u8 {
    match u.int_in_range(0..=7).unwrap() {
        0 => 0,
        1 | 2 => u.int_in_range(1..=2).unwrap(),
        3 => u8::MAX,
        _ => u.int_in_range(3..=u8::MAX - 1).unwrap(),
    }
}

fn reference_write(u: &mut Unstructured<'_>) -> ReferenceWrite {
    let partition = *u.choose(&PARTITIONS.map(|value| value as u8)).unwrap();
    if u.ratio(1, 64).unwrap() {
        ReferenceWrite::Flood {
            partition,
            value: u.arbitrary().unwrap(),
        }
    } else {
        ReferenceWrite::Key {
            partition,
            bucket: u.int_in_range(0..=3).unwrap(),
            suffix: u.int_in_range(0..=3).unwrap(),
            value: if u.ratio(1, 4).unwrap() {
                None
            } else {
                Some(u.arbitrary().unwrap())
            },
        }
    }
}

fn reference_writes(u: &mut Unstructured<'_>, min: usize) -> Vec<ReferenceWrite> {
    (0..u.int_in_range(min..=32).unwrap())
        .map(|_| reference_write(u))
        .collect()
}

fn reference_debug(input: &[u8]) -> String {
    let stream = expected_stream(input);
    let (scenario, entropy) = stream.split_at(STREAM_BYTES - 32);
    let u = &mut Unstructured::new(scenario);
    let init_concurrency = reference_concurrency(u);
    let init_cache = u.arbitrary().unwrap();
    let commits = (0..u.int_in_range(1..=8).unwrap())
        .map(|index| ReferenceCommit {
            hold: u.arbitrary().unwrap(),
            writes: reference_writes(u, usize::from(index == 0)),
        })
        .collect();
    let reference = ReferenceInput {
        init_concurrency,
        init_cache,
        commits,
        probe: reference_writes(u, 0),
        entropy: Unstructured::new(entropy).arbitrary().unwrap(),
    };
    normalized(&format!("{reference:#?}"))
        .replace("ReferenceInput", "FuzzInput")
        .replace("ReferenceCommit", "Commit")
}

#[test]
fn acceptance_at_004_stream_contract() {
    assert_eq!(SEED_BYTES, 8);
    assert_eq!(STREAM_BYTES, 1 << 12);

    let mut inputs = vec![Vec::new(), vec![b'\n'], (0u8..10).collect()];
    let mut before_limit = vec![0; SEED_BYTES + STREAM_BYTES + 1];
    let mut after_limit = before_limit.clone();
    before_limit[SEED_BYTES + STREAM_BYTES] = 1;
    after_limit[SEED_BYTES + STREAM_BYTES] = 2;
    inputs.extend([before_limit.clone(), after_limit.clone()]);

    for input in inputs {
        let actual = stream(&mut Unstructured::new(&input)).expect("the stream always decodes");
        assert_eq!(actual.len(), STREAM_BYTES);
        assert_eq!(actual, expected_stream(&input));
    }
    assert_eq!(
        stream(&mut Unstructured::new(&before_limit)).unwrap(),
        stream(&mut Unstructured::new(&after_limit)).unwrap(),
        "input after the seed and stream must be ignored"
    );

    let ten: Vec<u8> = (0..10).collect();
    let actual = stream(&mut Unstructured::new(&ten)).unwrap();
    assert_eq!(&actual[..2], &ten[8..]);
    assert_eq!(&actual[2..], &expected_stream(&ten[..8])[2..]);

    let library = fs::read_to_string(fuzz_dir().join("src/lib.rs")).unwrap();
    for documented_export in [
        "/// Input bytes that seed the [stream].\npub const SEED_BYTES: usize = 8;",
        "/// Length of the [stream] a scenario is sampled from.\npub const STREAM_BYTES: usize = 1 << 12;",
        "/// Decode the input into the stream a scenario is sampled from.",
        "pub fn stream(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<u8>>",
    ] {
        assert!(
            library.contains(documented_export),
            "missing documented stream API: {documented_export}"
        );
    }
}

#[test]
fn acceptance_at_001_003_005_006_014_015_016_025_source_contract() {
    let source = fs::read(fuzz_dir().join(TARGET)).expect("target source exists");
    assert_eq!(
        Sha256::hash(&[&source]).as_ref(),
        &[
            0x20, 0x83, 0xed, 0xab, 0xc6, 0x54, 0x27, 0x34, 0xbb, 0x48, 0xe8, 0x51, 0x20, 0x8f,
            0xdd, 0xf9, 0x6d, 0xd5, 0x2f, 0x04, 0x51, 0xb0, 0x0e, 0xb6, 0x57, 0xc9, 0x32, 0x77,
            0xcd, 0x7e, 0xa0, 0x3c,
        ],
        "the reviewed build no longer matches its declared reference implementation"
    );
    let text = String::from_utf8(source).unwrap();
    let compact: String = text.chars().filter(|byte| !byte.is_whitespace()).collect();
    assert!(compact.ends_with("fuzz_target!(|input:FuzzInput|{fuzz(input);});"));
    assert_eq!(
        text.matches("impl<'a> Arbitrary<'a> for FuzzInput").count(),
        1
    );
    assert!(!text.contains("fn size_hint"));
    assert!(!text.contains("Runner::default"));
    assert!(
        text.contains(
            "deterministic::Config::new().with_rng(FuzzRng::from(input.entropy.clone()))"
        )
    );
}

fn normalized(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn values_after(text: &str, marker: &str) -> Vec<u64> {
    let mut values = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find(marker) {
        rest = &rest[at + marker.len()..];
        let digits = rest
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>();
        values.push(digits.parse().expect("marker is followed by an integer"));
    }
    values
}

fn numbers(text: &str) -> Vec<u64> {
    text.split(|byte: char| !byte.is_ascii_digit())
        .filter(|digits| !digits.is_empty())
        .map(|digits| digits.parse().unwrap())
        .collect()
}

#[derive(Debug)]
struct Summary {
    concurrency: u64,
    cache: u64,
    commits: usize,
    writes: Vec<usize>,
    floods: Vec<usize>,
    deletes: Vec<usize>,
    holds: Vec<String>,
    probe: usize,
    probe_floods: usize,
    entropy: Vec<u64>,
}

fn summary(debug: &str) -> Summary {
    let text = normalized(debug);
    assert!(text.starts_with("FuzzInput {"), "not a FuzzInput: {text}");
    assert!(!text.contains("Arbitrary Error:"));
    let (body, probe) = text.split_once("probe: [").expect("probe field");
    let (probe, entropy) = probe.split_once("entropy:").expect("entropy field");
    let commits = body.split("Commit {").skip(1).collect::<Vec<_>>();
    let count = |part: &str, marker: &str| part.matches(marker).count();
    Summary {
        concurrency: values_after(&text, "init_concurrency: ")[0],
        cache: values_after(&text, "init_cache: ")[0],
        commits: commits.len(),
        writes: commits
            .iter()
            .map(|part| count(part, "Key {") + count(part, "Flood {"))
            .collect(),
        floods: commits.iter().map(|part| count(part, "Flood {")).collect(),
        deletes: commits
            .iter()
            .map(|part| count(part, "value: None"))
            .collect(),
        holds: commits
            .iter()
            .map(|part| {
                part.split_once("hold: ")
                    .unwrap()
                    .1
                    .split_once(',')
                    .unwrap()
                    .0
                    .to_string()
            })
            .collect(),
        probe: count(probe, "Key {") + count(probe, "Flood {"),
        probe_floods: count(probe, "Flood {"),
        entropy: numbers(entropy),
    }
}

fn assert_bounds(debug: &str) {
    let decoded = summary(debug);
    assert!((1..=8).contains(&decoded.commits));
    assert!((1..=32).contains(&decoded.writes[0]));
    assert!(decoded.writes.iter().all(|writes| *writes <= 32));
    assert!(decoded.probe <= 32);
    assert!(
        values_after(&normalized(debug), "partition: ")
            .iter()
            .all(|partition| PARTITIONS.contains(partition))
    );
    assert!(
        values_after(&normalized(debug), "bucket: ")
            .iter()
            .all(|bucket| *bucket < 4)
    );
    assert!(
        values_after(&normalized(debug), "suffix: ")
            .iter()
            .all(|suffix| *suffix < 4)
    );
    assert_eq!(decoded.entropy.len(), 32);
}

fn run_decode(binary: &Path, work: &Path, name: &str, input: &[u8]) -> String {
    fs::create_dir_all(work).unwrap();
    let input_path = work.join(format!("{name}.input"));
    let debug_path = work.join(format!("{name}.debug"));
    fs::write(&input_path, input).unwrap();
    _ = fs::remove_file(&debug_path);
    let output = Command::new(binary)
        .arg(&input_path)
        .env("RUST_LIBFUZZER_DEBUG_PATH", &debug_path)
        .env("LLVM_PROFILE_FILE", "/dev/null")
        .output()
        .expect("coverage binary runs");
    assert!(
        output.status.success(),
        "{name} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let debug = fs::read_to_string(&debug_path).expect("debug path was written");
    assert_eq!(
        normalized(&debug),
        reference_debug(input),
        "{name}: decoded value differs from the independent decoder"
    );
    fs::remove_file(input_path).unwrap();
    fs::remove_file(debug_path).unwrap();
    debug
}

fn summary_line(name: &str, decoded: &Summary) -> String {
    let holds = decoded
        .holds
        .iter()
        .map(|hold| format!("'{hold}'"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{name:<6} conc={:<3} cache={:<3} commits={} writes={:?} floods={:?} deletes={:?} hold=[{}] probe={} probe_floods={} entropy_bytes={}\n",
        decoded.concurrency,
        decoded.cache,
        decoded.commits,
        decoded.writes,
        decoded.floods,
        decoded.deletes,
        holds,
        decoded.probe,
        decoded.probe_floods,
        decoded.entropy.len(),
    )
}

#[test]
#[ignore = "requires QMDB_PARTITIONED_INIT_BIN and QMDB_PARTITIONED_INIT_WORK"]
fn acceptance_at_002_005_007_008_009_012_fixed_decoding() {
    let binary = required_path("QMDB_PARTITIONED_INIT_BIN");
    let work = required_path("QMDB_PARTITIONED_INIT_WORK").join("fixed-decoding");
    let mut actual = BTreeMap::new();
    for (name, input) in fixed_inputs() {
        let debug = run_decode(&binary, &work, &name, &input);
        assert_bounds(&debug);
        actual.insert(name, summary(&debug));
    }

    let empty = &actual["empty"];
    assert_eq!(
        (
            empty.concurrency,
            empty.cache,
            empty.commits,
            &empty.writes,
            &empty.floods,
            &empty.holds,
            empty.probe,
        ),
        (
            1,
            168,
            2,
            &vec![30, 14],
            &vec![0, 0],
            &vec!["true".into(), "false".into()],
            6
        )
    );
    let nl = &actual["nl"];
    assert_eq!(
        (
            nl.concurrency,
            nl.cache,
            nl.commits,
            &nl.writes,
            &nl.floods,
            &nl.holds,
            nl.probe,
        ),
        (
            255,
            60,
            2,
            &vec![20, 12],
            &vec![2, 1],
            &vec!["false".into(), "false".into()],
            19
        )
    );

    for name in ["z4105", "e_a", "e_b"] {
        let decoded = &actual[name];
        assert_eq!(decoded.concurrency, 0);
        assert_eq!(decoded.cache, 0);
        assert_eq!(decoded.commits, 1);
        assert_eq!(decoded.writes, [1]);
        assert_eq!(decoded.floods, [1]);
        assert_eq!(decoded.holds, ["false"]);
        assert_eq!(decoded.probe, 0);
    }
    assert_eq!(actual["z4105"].entropy, vec![0; 32]);
    assert_eq!(actual["e_a"].entropy, (0u64..32).collect::<Vec<_>>());
    assert_eq!(actual["e_b"].entropy, (100u64..132).collect::<Vec<_>>());

    let serial = actual
        .iter()
        .filter(|(name, decoded)| name.starts_with('s') && decoded.concurrency == 0)
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(serial, ["s00", "s07", "s19", "s21"]);

    let pin_names = ["e_a", "e_b", "empty", "nl"]
        .into_iter()
        .map(str::to_string)
        .chain((0..32).map(|index| format!("s{index:02}")))
        .chain(["z4105".to_string()]);
    let mut pins = String::new();
    for name in pin_names {
        pins.push_str(&summary_line(&name, &actual[&name]));
    }
    assert_eq!(
        Sha256::hash(&[pins.as_bytes()]).as_ref(),
        &[
            0x4f, 0x7a, 0x6b, 0x56, 0xab, 0xb2, 0xb5, 0xb8, 0x4f, 0x8a, 0xed, 0x3c, 0x8a, 0x00,
            0x9e, 0x9f, 0xee, 0x82, 0xda, 0x79, 0xec, 0x64, 0xab, 0xbc, 0x4a, 0x5a, 0xd0, 0xc1,
            0xaa, 0x8c, 0xa8, 0xc8,
        ],
        "the fixed decoding summaries changed"
    );
}

#[test]
#[ignore = "requires QMDB_PARTITIONED_INIT_BIN and QMDB_PARTITIONED_INIT_WORK; starts 65,792 processes"]
fn acceptance_at_002_007_all_one_and_two_byte_inputs_decode() {
    let binary = required_path("QMDB_PARTITIONED_INIT_BIN");
    let work = required_path("QMDB_PARTITIONED_INIT_WORK").join("all-short");
    fs::create_dir_all(&work).unwrap();
    let workers = 64;
    let mut threads = Vec::new();
    for worker in 0..workers {
        let binary = binary.clone();
        let work = work.join(format!("worker-{worker}"));
        threads.push(std::thread::spawn(move || {
            for first in (worker..256).step_by(workers) {
                let one = [first as u8];
                let debug = run_decode(&binary, &work, &format!("one-{first:02x}"), &one);
                assert_bounds(&debug);
                for second in 0u16..=255 {
                    let input = [first as u8, second as u8];
                    let debug = run_decode(
                        &binary,
                        &work,
                        &format!("two-{first:02x}-{second:02x}"),
                        &input,
                    );
                    assert_bounds(&debug);
                }
            }
        }));
    }
    for thread in threads {
        thread.join().expect("short-input worker passed");
    }
}

fn run_one(binary: &Path, work: &Path, name: &str, input: &[u8]) -> Output {
    fs::create_dir_all(work.join("artifacts")).unwrap();
    let input_path = work.join(format!("{name}.input"));
    fs::write(&input_path, input).unwrap();
    Command::new(binary)
        .arg(format!(
            "-artifact_prefix={}/",
            work.join("artifacts").display()
        ))
        .arg(input_path)
        .env("LLVM_PROFILE_FILE", "/dev/null")
        .output()
        .expect("fuzz binary runs one input")
}

#[test]
#[ignore = "requires QMDB_PARTITIONED_INIT_BIN and QMDB_PARTITIONED_INIT_WORK"]
fn acceptance_at_010_011_012_017_positive_runs() {
    let binary = required_path("QMDB_PARTITIONED_INIT_BIN");
    let work = required_path("QMDB_PARTITIONED_INIT_WORK").join("positive");
    for (name, input) in fixed_inputs() {
        let output = run_one(&binary, &work, &name, &input);
        assert!(
            output.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn parse_lcov(path: &Path) -> BTreeMap<(String, u64), u64> {
    let mut counts = BTreeMap::new();
    let mut source = None;
    for line in fs::read_to_string(path).unwrap().lines() {
        if let Some(path) = line.strip_prefix("SF:") {
            source = Some(path.to_string());
        } else if let (Some(path), Some(record)) = (&source, line.strip_prefix("DA:")) {
            let mut fields = record.split(',');
            let line = fields.next().unwrap().parse().unwrap();
            let count = fields.next().unwrap().parse().unwrap();
            counts.insert((path.clone(), line), count);
        }
    }
    counts
}

fn nightly_llvm(tool: &str) -> PathBuf {
    let sysroot = Command::new("rustc")
        .args(["+nightly-2026-11-12", "--print", "sysroot"])
        .output()
        .expect("nightly rustc is installed");
    assert!(sysroot.status.success());
    let host = Command::new("rustc")
        .args(["+nightly-2026-11-12", "-vV"])
        .output()
        .expect("nightly rustc reports its host");
    assert!(host.status.success());
    let host = String::from_utf8(host.stdout)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .unwrap()
        .to_string();
    PathBuf::from(String::from_utf8(sysroot.stdout).unwrap().trim())
        .join("lib/rustlib")
        .join(host)
        .join("bin")
        .join(tool)
}

fn profiled_run(
    binary: &Path,
    work: &Path,
    name: &str,
    input: &[u8],
) -> BTreeMap<(String, u64), u64> {
    fs::create_dir_all(work.join("artifacts")).unwrap();
    let input_path = work.join(format!("{name}.input"));
    let raw = work.join(format!("{name}.profraw"));
    let data = work.join(format!("{name}.profdata"));
    let lcov = work.join(format!("{name}.lcov"));
    fs::write(&input_path, input).unwrap();
    let output = Command::new(binary)
        .arg(format!(
            "-artifact_prefix={}/",
            work.join("artifacts").display()
        ))
        .arg(&input_path)
        .env("LLVM_PROFILE_FILE", &raw)
        .output()
        .expect("profiled replay runs");
    assert!(
        output.status.success(),
        "{name}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    command_passes(
        Command::new(nightly_llvm("llvm-profdata"))
            .args(["merge", "-sparse"])
            .arg(&raw)
            .arg("-o")
            .arg(&data),
        "merge replay profile",
    );
    let export = Command::new(nightly_llvm("llvm-cov"))
        .args(["export", "-format=lcov"])
        .arg(format!("-instr-profile={}", data.display()))
        .arg(binary)
        .output()
        .expect("replay profile exports");
    assert!(
        export.status.success(),
        "{name}: {}",
        String::from_utf8_lossy(&export.stderr)
    );
    fs::write(&lcov, export.stdout).unwrap();
    let counts = parse_lcov(&lcov);
    for path in [input_path, raw, data, lcov] {
        fs::remove_file(path).unwrap();
    }
    counts
}

fn scale_key(path: &str, line: u64) -> Option<&'static str> {
    let in_ranges = |ranges: &[(u64, u64)]| ranges.iter().any(|(a, b)| (*a..=*b).contains(&line));
    if path.ends_with("/storage/src/qmdb/snapshot.rs") {
        return (!in_ranges(&[(853, 869), (877, 883), (916, 928), (937, 949)]))
            .then_some("snapshot");
    }
    [
        (
            "/storage/src/index/partitioned/mod.rs",
            "mod",
            &[(81, 88)][..],
        ),
        (
            "/storage/src/index/partitioned/ordered/mod.rs",
            "ordered",
            &[(169, 182), (367, 495)][..],
        ),
        (
            "/storage/src/index/partitioned/ordered/partition.rs",
            "partition",
            &[(51, 54), (140, 142)][..],
        ),
        (
            "/storage/src/index/partitioned/ordered/handle.rs",
            "handle",
            &[(68, 98)][..],
        ),
        (
            "/storage/src/index/partitioned/unordered.rs",
            "unordered",
            &[(52, 116)][..],
        ),
    ]
    .into_iter()
    .find_map(|(suffix, name, ranges)| {
        (path.ends_with(suffix) && in_ranges(ranges)).then_some(name)
    })
}

#[test]
#[ignore = "requires QMDB_PARTITIONED_INIT_LCOV_DIR with empty, nl, z4105, and s00..s31 LCOV files"]
fn acceptance_at_010_011_017_023_024_coverage() {
    let directory = required_path("QMDB_PARTITIONED_INIT_LCOV_DIR");
    let mut all = BTreeSet::new();
    let mut covered = BTreeMap::new();
    for name in ["empty", "nl", "z4105"]
        .into_iter()
        .map(str::to_string)
        .chain((0..32).map(|index| format!("s{index:02}")))
    {
        let counts = parse_lcov(&directory.join(&name));
        let mut hits = BTreeSet::new();
        for ((path, line), count) in &counts {
            if let Some(file) = scale_key(path, *line) {
                all.insert((file, *line));
                if *count > 0 {
                    hits.insert((file, *line));
                }
            }
        }
        for line in ASSERTION_LINES {
            assert!(
                counts
                    .iter()
                    .any(|((path, at), count)| path.ends_with(TARGET) && *at == line && *count > 0),
                "{name}: assertion line {line} was not executed"
            );
        }
        covered.insert(name, hits);
    }
    assert_eq!(all.len(), 668);
    let startup = &covered["empty"] | &covered["nl"];
    assert_eq!(startup.len(), 522);
    let per_file = [
        ("snapshot", 415),
        ("mod", 2),
        ("ordered", 68),
        ("partition", 7),
        ("handle", 6),
        ("unordered", 24),
    ];
    for (file, expected) in per_file {
        assert_eq!(
            startup.iter().filter(|(name, _)| *name == file).count(),
            expected
        );
    }

    let seeds = (0..32)
        .map(|index| format!("s{index:02}"))
        .collect::<Vec<_>>();
    let mut percentages = Vec::new();
    for (index, left) in seeds.iter().enumerate() {
        for right in &seeds[index + 1..] {
            percentages.push(100.0 * (&covered[left] | &covered[right]).len() as f64 / 668.0);
        }
    }
    assert_eq!(percentages.len(), 496);
    let mean = percentages.iter().sum::<f64>() / percentages.len() as f64;
    let minimum = percentages.iter().copied().reduce(f64::min).unwrap();
    let share = percentages.iter().filter(|value| **value >= 76.0).count() as f64
        / percentages.len() as f64;
    assert_eq!(format!("{mean:.1}"), "82.6");
    assert_eq!(format!("{minimum:.1}"), "27.8");
    assert_eq!(format!("{:.0}", share * 100.0), "99");
}

#[test]
#[ignore = "requires QMDB_PARTITIONED_INIT_BIN and QMDB_PARTITIONED_INIT_WORK"]
fn acceptance_at_013_deterministic_replay() {
    let binary = required_path("QMDB_PARTITIONED_INIT_BIN");
    let work = required_path("QMDB_PARTITIONED_INIT_WORK").join("determinism");
    for input in ["empty", "nl", "z4105"] {
        let bytes = fixed_inputs()
            .into_iter()
            .find_map(|(name, bytes)| (name == input).then_some(bytes))
            .unwrap();
        let left_debug = run_decode(&binary, &work, &format!("{input}-a"), &bytes);
        let right_debug = run_decode(&binary, &work, &format!("{input}-b"), &bytes);
        assert_eq!(left_debug, right_debug, "{input}: debug text");
        let left = profiled_run(&binary, &work, &format!("{input}-a"), &bytes);
        let right = profiled_run(&binary, &work, &format!("{input}-b"), &bytes);
        let left_lines = left
            .iter()
            .filter(|(_, count)| **count > 0)
            .map(|(line, _)| line)
            .collect::<BTreeSet<_>>();
        let right_lines = right
            .iter()
            .filter(|(_, count)| **count > 0)
            .map(|(line, _)| line)
            .collect::<BTreeSet<_>>();
        assert_eq!(left_lines, right_lines, "{input}: executed line set");
        for (line, count) in left
            .iter()
            .filter(|((path, _), _)| path.contains("/storage/"))
        {
            assert_eq!(Some(count), right.get(line), "{input}: {line:?}");
        }
    }
}

#[test]
#[ignore = "requires the five QMDB_PARTITIONED_INIT_PLANT_P<N>_BIN variables and QMDB_PARTITIONED_INIT_WORK"]
fn acceptance_at_018_019_020_021_022_negative_controls() {
    let work = required_path("QMDB_PARTITIONED_INIT_WORK").join("plants");
    let inputs = fixed_inputs().into_iter().take(34).collect::<Vec<_>>();
    let p1 = [
        1, 2, 4, 8, 10, 12, 13, 14, 15, 16, 17, 20, 23, 25, 26, 27, 28, 30,
    ]
    .into_iter()
    .map(|index| format!("s{index:02}"))
    .collect::<BTreeSet<_>>();
    let p2 = ["s07", "s21"].into_iter().map(str::to_string).collect();
    let parallel = (0..32)
        .map(|index| format!("s{index:02}"))
        .chain(["empty".to_string(), "nl".to_string()])
        .filter(|name| !["s00", "s07", "s19", "s21"].contains(&name.as_str()))
        .collect::<BTreeSet<_>>();
    let all = inputs.iter().map(|(name, _)| name.clone()).collect();
    for (plant, expected, messages) in [
        (1, p1, &["value of ", "changed across reopen"][..]),
        (2, p2, &["value of ", "changed across reopen"][..]),
        (
            3,
            parallel.clone(),
            &["follow-up batch root changed across reopen"][..],
        ),
        (4, parallel, &["root changed across reopen"][..]),
        (5, all, &["floor changed across reopen"][..]),
    ] {
        let binary = required_path(&format!("QMDB_PARTITIONED_INIT_PLANT_P{plant}_BIN"));
        let mut failed = BTreeSet::new();
        for (name, input) in &inputs {
            let output = run_one(&binary, &work.join(format!("p{plant}")), name, input);
            if output.status.success() {
                continue;
            }
            failed.insert(name.clone());
            let stderr = String::from_utf8_lossy(&output.stderr);
            for message in messages {
                assert!(stderr.contains(message), "p{plant} {name}: {stderr}");
            }
            if plant == 4 {
                assert!(
                    !stderr.contains("follow-up batch root changed across reopen"),
                    "p4 must fire the rebuilt-root assertion: {stderr}"
                );
            }
            assert_eq!(stderr.matches("panicked at").count(), 1, "p{plant} {name}");
        }
        assert_eq!(failed, expected, "plant p{plant}");
    }
}

fn command_passes(command: &mut Command, label: &str) {
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("{label}: {error}"));
    assert!(
        output.status.success(),
        "{label}:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "runs the pinned fuzz build, Clippy, and rustfmt checks"]
fn acceptance_at_026_build_lint_and_format() {
    let repository = fuzz_dir().join("../..").canonicalize().unwrap();
    let work = required_path("QMDB_PARTITIONED_INIT_WORK").join("v1");
    fs::create_dir_all(&work).unwrap();
    let fuzz_target = env::var_os("QMDB_PARTITIONED_INIT_V1_FUZZ_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| work.join("target-fuzz"));
    let clippy_target = env::var_os("QMDB_PARTITIONED_INIT_V1_CLIPPY_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| work.join("target-clippy"));
    command_passes(
        Command::new("cargo")
            .current_dir(&repository)
            .args([
                "+nightly-2026-11-12",
                "fuzz",
                "build",
                "--fuzz-dir",
                "storage/fuzz",
                "--target-dir",
            ])
            .arg(fuzz_target)
            .arg("qmdb_any_partitioned_init"),
        "nightly fuzz build",
    );
    command_passes(
        Command::new("cargo")
            .current_dir(&repository)
            .env("CARGO_TARGET_DIR", clippy_target)
            .args([
                "+1.100.0",
                "clippy",
                "--manifest-path",
                "storage/fuzz/Cargo.toml",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ]),
        "pinned Clippy",
    );
    command_passes(
        Command::new("rustfmt").current_dir(&repository).args([
            "+nightly-2026-11-12",
            "--edition",
            "2024",
            "--check",
            "--config",
            "skip_children=true",
            "storage/fuzz/fuzz_targets/qmdb_any_partitioned_init.rs",
        ]),
        "pinned rustfmt",
    );
}

#[test]
#[ignore = "requires QMDB_PARTITIONED_INIT_FUZZ_BIN and QMDB_PARTITIONED_INIT_WORK; runs for two minutes"]
fn acceptance_at_027_smoke() {
    let binary = required_path("QMDB_PARTITIONED_INIT_FUZZ_BIN");
    let work = required_path("QMDB_PARTITIONED_INIT_WORK").join("smoke");
    let corpus = work.join("corpus");
    let artifacts = work.join("artifacts");
    assert!(
        !corpus.exists() || fs::read_dir(&corpus).unwrap().next().is_none(),
        "smoke corpus must start empty"
    );
    assert!(
        !artifacts.exists() || fs::read_dir(&artifacts).unwrap().next().is_none(),
        "artifact directory must start empty"
    );
    fs::create_dir_all(&corpus).unwrap();
    fs::create_dir_all(&artifacts).unwrap();
    let output = Command::new(binary)
        .arg(&corpus)
        .arg("-max_total_time=120")
        .arg(format!("-artifact_prefix={}/", artifacts.display()))
        .output()
        .expect("fuzz binary runs");
    let stderr = String::from_utf8_lossy(&output.stderr);
    fs::write(work.join("run.stderr"), output.stderr.as_slice()).unwrap();
    assert!(output.status.success(), "{stderr}");
    assert!(stderr.contains("exec/s:"), "{stderr}");
    assert!(stderr.contains("lim:"), "{stderr}");
    assert_eq!(fs::read_dir(artifacts).unwrap().count(), 0, "{stderr}");
}
