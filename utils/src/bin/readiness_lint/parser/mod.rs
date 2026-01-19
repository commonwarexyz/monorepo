//! Parse the workspace to extract public items and readiness annotations using rustdoc JSON.

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Invalid workspace: {0}")]
    InvalidWorkspace(String),
    #[error("Rustdoc failed: {0}")]
    RustdocFailed(String),
}

/// Configuration for the readiness parser.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Config {
    /// Crate names to exclude entirely from output.
    #[serde(default)]
    pub ignore_crates: Vec<String>,
    /// Item path patterns to exclude from output (glob patterns supported).
    /// Use `*::tests` to match any path containing `tests`.
    #[serde(default)]
    pub ignore_paths: Vec<String>,
}

impl Config {
    /// Load config from .readiness.toml in the given directory.
    pub fn load(root: &Path) -> Result<Self, ParseError> {
        let config_path = root.join(".readiness.toml");
        if !config_path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(&config_path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }

    fn should_ignore_crate(&self, crate_name: &str) -> bool {
        self.ignore_crates.contains(&crate_name.to_string())
    }

    fn should_ignore_path(&self, path: &str) -> bool {
        for pattern in &self.ignore_paths {
            if matches_glob_pattern(pattern, path) {
                return true;
            }
        }
        false
    }
}

fn matches_glob_pattern(pattern: &str, path: &str) -> bool {
    pattern.strip_prefix("*::").map_or_else(
        || pattern == path,
        |suffix| path.ends_with(&format!("::{suffix}")) || path == suffix,
    )
}

/// A public item in the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    /// Full path (e.g., "commonware_codec::varint::UInt")
    pub path: String,
    /// Item kind (struct, enum, function, type_alias, method)
    pub kind: ItemKind,
    /// Readiness level if annotated, None if missing
    pub readiness: Option<u8>,
    /// Source file location
    pub span: Option<Span>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ItemKind {
    Struct,
    Enum,
    Function,
    TypeAlias,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Span {
    pub filename: String,
    pub line: u32,
}

/// A parsed crate with its public items.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Crate {
    pub name: String,
    pub path: PathBuf,
    pub items: Vec<Item>,
    pub dependencies: Vec<String>,
}

/// A parsed workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub crates: HashMap<String, Crate>,
}

/// Parse the workspace using rustdoc JSON.
pub fn parse_workspace(root: &Path, config: &Config) -> Result<Workspace, ParseError> {
    let cargo_toml_path = root.join("Cargo.toml");
    let cargo_toml_content = fs::read_to_string(&cargo_toml_path)?;
    let cargo_toml: toml::Value = toml::from_str(&cargo_toml_content)?;

    let members = cargo_toml
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(|m| m.as_array())
        .ok_or_else(|| ParseError::InvalidWorkspace("No workspace.members found".to_string()))?;

    let mut crates = HashMap::new();

    for member in members {
        let member_path = member
            .as_str()
            .ok_or_else(|| ParseError::InvalidWorkspace("Invalid member path".to_string()))?;

        // Skip fuzz crates and examples
        if member_path.contains("/fuzz") || member_path.starts_with("examples/") {
            continue;
        }

        let crate_path = root.join(member_path);
        let crate_name = get_crate_name(&crate_path)?;

        if config.should_ignore_crate(&crate_name) {
            continue;
        }

        match parse_crate(root, &crate_path, &crate_name, config) {
            Ok(krate) => {
                crates.insert(krate.name.clone(), krate);
            }
            Err(e) => {
                eprintln!("Warning: Failed to parse {}: {}", crate_name, e);
            }
        }
    }

    Ok(Workspace { crates })
}

fn get_crate_name(crate_path: &Path) -> Result<String, ParseError> {
    let cargo_toml_path = crate_path.join("Cargo.toml");
    let cargo_toml_content = fs::read_to_string(&cargo_toml_path)?;
    let cargo_toml: toml::Value = toml::from_str(&cargo_toml_content)?;

    cargo_toml
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| ParseError::InvalidWorkspace("No package.name found".to_string()))
}

fn parse_crate(
    workspace_root: &Path,
    crate_path: &Path,
    crate_name: &str,
    config: &Config,
) -> Result<Crate, ParseError> {
    // Run rustdoc to generate JSON
    let json_path = run_rustdoc(workspace_root, crate_name)?;

    // Parse the JSON
    let json_content = fs::read_to_string(&json_path)?;
    let doc: Value = serde_json::from_str(&json_content)?;

    // Extract items
    let items = extract_items(&doc, config)?;

    // Get dependencies
    let dependencies = get_dependencies(crate_path)?;

    Ok(Crate {
        name: crate_name.to_string(),
        path: crate_path.to_path_buf(),
        items,
        dependencies,
    })
}

fn run_rustdoc(workspace_root: &Path, crate_name: &str) -> Result<PathBuf, ParseError> {
    let output = Command::new("cargo")
        .arg("+nightly")
        .arg("rustdoc")
        .arg("-p")
        .arg(crate_name)
        .arg("--lib")
        .arg("--")
        .arg("-Z")
        .arg("unstable-options")
        .arg("--output-format")
        .arg("json")
        .current_dir(workspace_root)
        .output()
        .map_err(|e| ParseError::RustdocFailed(e.to_string()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ParseError::RustdocFailed(stderr.to_string()));
    }

    // The JSON file is at target/doc/{crate_name}.json (with underscores)
    let json_name = crate_name.replace('-', "_");
    let json_path = workspace_root.join("target/doc").join(format!("{json_name}.json"));

    if !json_path.exists() {
        return Err(ParseError::RustdocFailed(format!(
            "JSON file not found at {:?}",
            json_path
        )));
    }

    Ok(json_path)
}

fn extract_items(doc: &Value, config: &Config) -> Result<Vec<Item>, ParseError> {
    let mut items = Vec::new();

    let index = doc
        .get("index")
        .and_then(|i| i.as_object())
        .ok_or_else(|| ParseError::InvalidWorkspace("No index in rustdoc JSON".to_string()))?;

    let paths = doc
        .get("paths")
        .and_then(|p| p.as_object())
        .ok_or_else(|| ParseError::InvalidWorkspace("No paths in rustdoc JSON".to_string()))?;

    // Build a map of id -> path for items in this crate (crate_id == 0)
    let mut id_to_path: HashMap<String, (Vec<String>, String)> = HashMap::new();
    for (id, path_info) in paths {
        let crate_id = path_info.get("crate_id").and_then(|c| c.as_u64()).unwrap_or(1);
        if crate_id != 0 {
            continue;
        }

        let path_parts: Vec<String> = path_info
            .get("path")
            .and_then(|p| p.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();

        let kind = path_info
            .get("kind")
            .and_then(|k| k.as_str())
            .unwrap_or("")
            .to_string();

        id_to_path.insert(id.clone(), (path_parts, kind));
    }

    // Regex to extract readiness level from docs
    let readiness_re = Regex::new(r"\*\*Readiness:\s*(\d+)\*\*").unwrap();

    // Process items that have entries in the paths map (top-level public items)
    for (id, (path_parts, path_kind)) in &id_to_path {
        // Map rustdoc kind to our ItemKind
        let kind = match path_kind.as_str() {
            "struct" => ItemKind::Struct,
            "enum" => ItemKind::Enum,
            "function" => ItemKind::Function,
            "type_alias" => ItemKind::TypeAlias,
            // Skip traits, modules, variants, etc.
            _ => continue,
        };

        let path = path_parts.join("::");
        if path.is_empty() {
            continue;
        }

        // Check if path should be ignored
        if config.should_ignore_path(&path) {
            continue;
        }

        // Get the item info from index to extract docs and span
        let item_info = match index.get(id) {
            Some(info) => info,
            None => continue,
        };

        // Extract readiness from docs
        let docs = item_info.get("docs").and_then(|d| d.as_str()).unwrap_or("");
        let readiness = readiness_re.captures(docs).and_then(|c| {
            c.get(1).and_then(|m| m.as_str().parse::<u8>().ok())
        });

        // Extract span
        let span = item_info.get("span").and_then(|s| {
            let filename = s.get("filename")?.as_str()?.to_string();
            let line = s.get("begin")?.as_array()?.first()?.as_u64()? as u32;
            Some(Span { filename, line })
        });

        items.push(Item {
            path,
            kind,
            readiness,
            span,
        });
    }

    Ok(items)
}

fn get_dependencies(crate_path: &Path) -> Result<Vec<String>, ParseError> {
    let cargo_toml_path = crate_path.join("Cargo.toml");
    let cargo_toml_content = fs::read_to_string(&cargo_toml_path)?;
    let cargo_toml: toml::Value = toml::from_str(&cargo_toml_content)?;

    let deps = cargo_toml
        .get("dependencies")
        .and_then(|d| d.as_table())
        .map(|t| {
            t.keys()
                .filter(|k| k.starts_with("commonware-"))
                .cloned()
                .collect()
        })
        .unwrap_or_default();

    Ok(deps)
}

/// Get all items missing readiness annotations.
pub fn get_missing_annotations(workspace: &Workspace) -> Vec<String> {
    let mut missing = Vec::new();

    for krate in workspace.crates.values() {
        for item in &krate.items {
            if item.readiness.is_none() {
                missing.push(item.path.clone());
            }
        }
    }

    missing.sort();
    missing
}

