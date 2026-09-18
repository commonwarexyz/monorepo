#[path = "../naming.rs"]
mod naming;

use naming::type_to_ident;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::stdin,
    path::{Path, PathBuf},
    process::ExitCode,
};

type Inventories = BTreeMap<String, BTreeSet<String>>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Check,
    Prune,
}

impl Mode {
    fn parse() -> Result<Self, String> {
        match env::args().nth(1).as_deref() {
            Some("check") => Ok(Self::Check),
            Some("prune") => Ok(Self::Prune),
            _ => Err("usage: fixtures <check|prune>".to_string()),
        }
    }
}

#[derive(Deserialize)]
struct TestList {
    #[serde(rename = "rust-suites")]
    suites: BTreeMap<String, Suite>,
}

#[derive(Deserialize)]
struct Suite {
    #[serde(rename = "binary-name")]
    binary_name: String,
    cwd: PathBuf,
    status: String,
    #[serde(default)]
    testcases: BTreeMap<String, serde::de::IgnoredAny>,
}

fn collect_inventories(test_list: TestList) -> BTreeMap<PathBuf, Inventories> {
    let mut files = BTreeMap::<PathBuf, Inventories>::new();

    for suite in test_list.suites.into_values() {
        if suite.status != "listed" {
            continue;
        }

        let binary_name = suite.binary_name.replace('-', "_");
        let tests = files
            .entry(suite.cwd.join("conformance.toml"))
            .or_default()
            .entry(binary_name.clone())
            .or_default();

        tests.extend(
            suite
                .testcases
                .into_keys()
                .filter(|name| name.ends_with("_conformance_"))
                .map(|name| format!("{binary_name}::{name}")),
        );
    }

    files
}

fn has_test(fixture: &str, tests: &BTreeSet<String>) -> bool {
    tests.iter().any(|test| {
        let Some((module, test_name)) = test.rsplit_once("::test_") else {
            return false;
        };
        let Some(type_name) = fixture
            .strip_prefix(module)
            .and_then(|suffix| suffix.strip_prefix("::"))
        else {
            return false;
        };

        test_name == format!("{}_conformance_", type_to_ident(type_name))
    })
}

fn dangling_entries(file: &toml::Table, inventories: &Inventories) -> Vec<String> {
    file.keys()
        .filter(|fixture| {
            let Some((binary_name, _)) = fixture.split_once("::") else {
                return false;
            };
            let Some(tests) = inventories.get(binary_name) else {
                return false;
            };
            !has_test(fixture, tests)
        })
        .cloned()
        .collect()
}

fn inspect_file(mode: Mode, file: &mut toml::Table, inventories: &Inventories) -> Vec<String> {
    let dangling = dangling_entries(file, inventories);
    if mode == Mode::Prune {
        for fixture in &dangling {
            file.remove(fixture);
        }
    }
    dangling
}

fn process_file(mode: Mode, path: &Path, inventories: &Inventories) -> Result<Vec<String>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let contents = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let mut file = toml::from_str(&contents).map_err(|error| error.to_string())?;
    let dangling = inspect_file(mode, &mut file, inventories);

    if mode == Mode::Prune && !dangling.is_empty() {
        let contents = toml::to_string_pretty(&file).map_err(|error| error.to_string())?;
        fs::write(path, contents)
            .map_err(|error| format!("failed to write {}: {error}", path.display()))?;
    }

    Ok(dangling)
}

fn run() -> Result<(), String> {
    let mode = Mode::parse()?;
    let test_list = serde_json::from_reader(stdin().lock()).map_err(|error| error.to_string())?;
    let files = collect_inventories(test_list);
    let mut dangling_count = 0usize;

    for (path, inventories) in files {
        let dangling = process_file(mode, &path, &inventories)?;
        for fixture in &dangling {
            eprintln!("{}: dangling fixture `{fixture}`", path.display());
        }
        dangling_count += dangling.len();
    }

    if mode == Mode::Check && dangling_count > 0 {
        return Err(format!(
            "found {dangling_count} dangling conformance fixtures"
        ));
    }

    Ok(())
}

fn main() -> ExitCode {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_file(fixtures: &[&str]) -> toml::Table {
        fixtures
            .iter()
            .map(|fixture| {
                (
                    (*fixture).to_string(),
                    toml::Value::Table(toml::Table::new()),
                )
            })
            .collect()
    }

    fn inventory(tests: &[&str]) -> Inventories {
        BTreeMap::from([(
            "commonware_example".to_string(),
            tests.iter().map(|test| (*test).to_string()).collect(),
        )])
    }

    #[test]
    fn checks_and_prunes_dangling_entries_in_selected_crates() {
        const MODULE: &str = "commonware_example::tests::conformance";
        let live = format!("{MODULE}::CodecConformance<[u8;32]>");
        let dangling = format!("{MODULE}::CodecConformance<Vec<u16>>");
        let unrelated = "commonware_other::tests::conformance::CodecConformance<Vec<u8>>";
        let mut file = fixture_file(&[&live, &dangling, unrelated]);
        let inventories = inventory(&[&format!(
            "{MODULE}::test_codec_conformance_u8_32_conformance_"
        )]);

        assert_eq!(
            inspect_file(Mode::Check, &mut file, &inventories),
            std::slice::from_ref(&dangling)
        );
        assert_eq!(file.len(), 3);

        assert_eq!(
            inspect_file(Mode::Prune, &mut file, &inventories),
            [dangling]
        );
        assert_eq!(file.len(), 2);
        assert!(file.contains_key(unrelated));
    }

    #[test]
    fn collects_only_conformance_tests() {
        let test_list = TestList {
            suites: BTreeMap::from([(
                "commonware-example".to_string(),
                Suite {
                    binary_name: "commonware_example".to_string(),
                    cwd: PathBuf::from("/workspace/example"),
                    status: "listed".to_string(),
                    testcases: BTreeMap::from([
                        (
                            "tests::test_live_conformance_".to_string(),
                            serde::de::IgnoredAny,
                        ),
                        ("tests::test_ordinary".to_string(), serde::de::IgnoredAny),
                    ]),
                },
            )]),
        };

        let inventories = collect_inventories(test_list);

        assert_eq!(
            inventories[&PathBuf::from("/workspace/example/conformance.toml")]["commonware_example"],
            BTreeSet::from(["commonware_example::tests::test_live_conformance_".to_string()])
        );
    }
}
