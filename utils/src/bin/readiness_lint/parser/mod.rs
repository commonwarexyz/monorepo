//! Parse the workspace to extract modules and readiness annotations.

mod cfg_if;

use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};
use thiserror::Error;
use toml::Value;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("Invalid workspace: {0}")]
    InvalidWorkspace(String),
}

/// Configuration for the readiness parser.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Config {
    /// Module path patterns to exclude from output (glob patterns supported).
    /// Use `*::tests` to match any module named `tests` at any depth.
    #[serde(default)]
    pub ignore_modules: Vec<String>,
}

impl Config {
    /// Load config from .readiness.toml in the given directory.
    /// Returns default config if file doesn't exist.
    pub fn load(root: &Path) -> Result<Self, ParseError> {
        let config_path = root.join(".readiness.toml");
        if !config_path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(&config_path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// Check if a module path should be ignored.
    pub fn should_ignore(&self, module_path: &str) -> bool {
        for pattern in &self.ignore_modules {
            if matches_glob_pattern(pattern, module_path) {
                return true;
            }
        }
        false
    }
}

/// Simple glob pattern matching for module paths.
/// Supports `*::` prefix to match any parent path.
fn matches_glob_pattern(pattern: &str, path: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*::") {
        path.ends_with(&format!("::{suffix}")) || path == suffix
    } else {
        pattern == path
    }
}

/// A parsed workspace containing all crates and their modules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub crates: HashMap<String, Crate>,
}

/// A parsed crate with its modules and dependencies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Crate {
    pub name: String,
    pub path: PathBuf,
    pub modules: HashMap<String, Module>,
    pub dependencies: Vec<String>,
    pub dev_dependencies: Vec<String>,
    /// Readiness level of the crate root (lib.rs)
    pub root_readiness: u8,
    /// Whether the root readiness was explicitly set
    pub root_is_explicit: bool,
}

/// How a module is exposed in the public API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    /// Directly public via `pub mod`
    #[default]
    Public,
    /// Private module with items reexported via `pub use`
    Reexported,
}

/// A module with its readiness level and submodules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Module {
    pub path: String,
    pub readiness: u8,
    pub file_path: PathBuf,
    pub submodules: HashMap<String, Module>,
    pub is_explicit: bool,
    /// How this module is exposed in the public API
    pub visibility: Visibility,
}

impl Default for Module {
    fn default() -> Self {
        Self {
            path: String::new(),
            readiness: 0,
            file_path: PathBuf::new(),
            submodules: HashMap::new(),
            is_explicit: false,
            visibility: Visibility::Public,
        }
    }
}

/// Parse the workspace at the given root path.
pub fn parse_workspace(root: &Path, config: &Config) -> Result<Workspace, ParseError> {
    let cargo_toml_path = root.join("Cargo.toml");
    let cargo_toml_content = fs::read_to_string(&cargo_toml_path)?;
    let cargo_toml: Value = toml::from_str(&cargo_toml_content)?;

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
        if let Ok(krate) = parse_crate(&crate_path, config) {
            crates.insert(krate.name.clone(), krate);
        }
    }

    Ok(Workspace { crates })
}

/// Parse a single crate.
fn parse_crate(path: &Path, config: &Config) -> Result<Crate, ParseError> {
    let cargo_toml_path = path.join("Cargo.toml");
    let cargo_toml_content = fs::read_to_string(&cargo_toml_path)?;
    let cargo_toml: Value = toml::from_str(&cargo_toml_content)?;

    let name = cargo_toml
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .ok_or_else(|| ParseError::InvalidWorkspace("No package.name found".to_string()))?
        .to_string();

    // Extract dependencies
    let dependencies = extract_deps(&cargo_toml, "dependencies");
    let dev_dependencies = extract_deps(&cargo_toml, "dev-dependencies");

    // Parse modules from lib.rs
    let lib_rs_path = path.join("src/lib.rs");
    let (modules, root_readiness) = if lib_rs_path.exists() {
        let root_readiness = extract_readiness_from_file(&lib_rs_path);
        let modules = parse_modules(&lib_rs_path, &path.join("src"), "", root_readiness, config)?;
        (modules, root_readiness)
    } else {
        (HashMap::new(), 0)
    };

    Ok(Crate {
        name,
        path: path.to_path_buf(),
        modules,
        dependencies,
        dev_dependencies,
        root_readiness,
        root_is_explicit: root_readiness > 0,
    })
}

/// Extract dependency names from Cargo.toml.
fn extract_deps(cargo_toml: &Value, section: &str) -> Vec<String> {
    cargo_toml
        .get(section)
        .and_then(|d| d.as_table())
        .map(|t| {
            t.keys()
                .filter(|k| k.starts_with("commonware-"))
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// Parse modules from a Rust source file.
fn parse_modules(
    file_path: &Path,
    src_dir: &Path,
    parent_path: &str,
    parent_readiness: u8,
    config: &Config,
) -> Result<HashMap<String, Module>, ParseError> {
    let content = fs::read_to_string(file_path)?;
    let mut modules = HashMap::new();

    // Parse the file to find module declarations
    let parsed = match syn::parse_file(&content) {
        Ok(f) => f,
        Err(_) => return Ok(modules),
    };

    // Also check for cfg_if! blocks (only public ones)
    let cfg_if_modules = cfg_if::extract_public_modules_from_cfg_if(&content);

    for item in &parsed.items {
        if let syn::Item::Mod(item_mod) = item {
            // Skip non-public modules (only include fully public `pub mod`)
            if !matches!(item_mod.vis, syn::Visibility::Public(_)) {
                continue;
            }

            let mod_name = item_mod.ident.to_string();
            let mod_path = if parent_path.is_empty() {
                mod_name.clone()
            } else {
                format!("{parent_path}::{mod_name}")
            };

            // Skip ignored modules
            if config.should_ignore(&mod_path) {
                continue;
            }

            // Determine the module file path
            let (mod_file_path, has_submodules) = if item_mod.content.is_some() {
                // Inline module
                (file_path.to_path_buf(), false)
            } else {
                // External module
                let mod_rs = src_dir.join(&mod_name).join("mod.rs");
                let mod_file = src_dir.join(format!("{mod_name}.rs"));
                if mod_rs.exists() {
                    (mod_rs, true)
                } else if mod_file.exists() {
                    (mod_file, false)
                } else {
                    continue;
                }
            };

            // Check for #[readiness(N)] inside the module file
            let explicit_readiness = extract_readiness_from_file(&mod_file_path);
            let is_explicit = explicit_readiness > 0;
            // Inherit from parent if no explicit readiness
            let readiness = if is_explicit {
                explicit_readiness
            } else {
                parent_readiness
            };

            // Recursively parse submodules
            let submodules = if has_submodules {
                let mod_dir = src_dir.join(&mod_name);
                parse_modules(&mod_file_path, &mod_dir, &mod_path, readiness, config)?
            } else {
                HashMap::new()
            };

            modules.insert(
                mod_name.clone(),
                Module {
                    path: mod_path,
                    readiness,
                    file_path: mod_file_path,
                    submodules,
                    is_explicit,
                    visibility: Visibility::Public,
                },
            );
        }
    }

    // Merge cfg_if modules (already filtered to public only)
    for mod_name in cfg_if_modules {
        let mod_path = if parent_path.is_empty() {
            mod_name.clone()
        } else {
            format!("{parent_path}::{mod_name}")
        };

        // Skip ignored modules
        if config.should_ignore(&mod_path) {
            continue;
        }

        let mod_rs = src_dir.join(&mod_name).join("mod.rs");
        let mod_file = src_dir.join(format!("{mod_name}.rs"));
        let (mod_file_path, has_submodules) = if mod_rs.exists() {
            (mod_rs, true)
        } else if mod_file.exists() {
            (mod_file, false)
        } else {
            continue;
        };

        // Check for #[readiness(N)] inside the module file
        let explicit_readiness = extract_readiness_from_file(&mod_file_path);
        let is_explicit = explicit_readiness > 0;
        // Inherit from parent if no explicit readiness
        let readiness = if is_explicit {
            explicit_readiness
        } else {
            parent_readiness
        };

        let submodules = if has_submodules {
            let mod_dir = src_dir.join(&mod_name);
            parse_modules(&mod_file_path, &mod_dir, &mod_path, readiness, config)?
        } else {
            HashMap::new()
        };

        modules
            .entry(mod_name.clone())
            .and_modify(|m| {
                if readiness > m.readiness {
                    m.readiness = readiness;
                    m.is_explicit = is_explicit;
                }
            })
            .or_insert(Module {
                path: mod_path,
                readiness,
                file_path: mod_file_path,
                submodules,
                is_explicit,
                visibility: Visibility::Public,
            });
    }

    // Parse pub use statements to find reexported private modules
    let reexported_modules = extract_reexported_modules(&parsed);
    for mod_name in reexported_modules {
        // Skip if already included as public
        if modules.contains_key(&mod_name) {
            continue;
        }

        let mod_path = if parent_path.is_empty() {
            mod_name.clone()
        } else {
            format!("{parent_path}::{mod_name}")
        };

        // Skip ignored modules
        if config.should_ignore(&mod_path) {
            continue;
        }

        // Find the module file
        let mod_rs = src_dir.join(&mod_name).join("mod.rs");
        let mod_file = src_dir.join(format!("{mod_name}.rs"));
        let (mod_file_path, has_submodules) = if mod_rs.exists() {
            (mod_rs, true)
        } else if mod_file.exists() {
            (mod_file, false)
        } else {
            continue;
        };

        // Check for readiness in the module file
        let explicit_readiness = extract_readiness_from_file(&mod_file_path);
        let is_explicit = explicit_readiness > 0;
        let readiness = if is_explicit {
            explicit_readiness
        } else {
            parent_readiness
        };

        // Recursively parse submodules (they inherit the reexported visibility context)
        let submodules = if has_submodules {
            let mod_dir = src_dir.join(&mod_name);
            parse_modules(&mod_file_path, &mod_dir, &mod_path, readiness, config)?
        } else {
            HashMap::new()
        };

        modules.insert(
            mod_name,
            Module {
                path: mod_path,
                readiness,
                file_path: mod_file_path,
                submodules,
                is_explicit,
                visibility: Visibility::Reexported,
            },
        );
    }

    Ok(modules)
}

/// Extract module names that have items reexported via `pub use`.
/// Looks for patterns like `pub use module::Item;` or `pub use module::{A, B};`
fn extract_reexported_modules(parsed: &syn::File) -> HashSet<String> {
    let mut modules = HashSet::new();

    for item in &parsed.items {
        if let syn::Item::Use(item_use) = item {
            // Only consider public use statements
            if !matches!(item_use.vis, syn::Visibility::Public(_)) {
                continue;
            }

            // Extract module names from the use tree
            extract_modules_from_use_tree(&item_use.tree, &mut modules);
        }
    }

    modules
}

/// Recursively extract module names from a use tree.
fn extract_modules_from_use_tree(tree: &syn::UseTree, modules: &mut HashSet<String>) {
    match tree {
        syn::UseTree::Path(path) => {
            let segment = path.ident.to_string();
            // Skip external crates and self/super/crate keywords
            if segment == "self" || segment == "super" || segment == "crate" {
                // For crate::module::Item, we want "module"
                if segment == "crate" {
                    if let syn::UseTree::Path(inner) = path.tree.as_ref() {
                        modules.insert(inner.ident.to_string());
                    }
                }
                return;
            }
            // For module::Item or module::{...}, add the first segment
            modules.insert(segment);
        }
        syn::UseTree::Group(group) => {
            for tree in &group.items {
                extract_modules_from_use_tree(tree, modules);
            }
        }
        syn::UseTree::Name(_) | syn::UseTree::Rename(_) | syn::UseTree::Glob(_) => {
            // These are leaf nodes (Item, Item as Alias, *)
        }
    }
}

/// Extract readiness level from a module file.
/// Looks for `readiness!(N)` patterns (with or without path prefix).
fn extract_readiness_from_file(file_path: &Path) -> u8 {
    let content = match fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(_) => return 0,
    };

    for line in content.lines() {
        let trimmed = line.trim();

        // Look for pattern: readiness!(N) or commonware_macros::readiness!(N)
        if let Some(pos) = trimmed.find("readiness!(") {
            let rest = &trimmed[pos + 11..];
            if let Some(end) = rest.find(')') {
                if let Ok(level) = rest[..end].trim().parse::<u8>() {
                    return level.min(4);
                }
            }
        }
    }

    0
}
