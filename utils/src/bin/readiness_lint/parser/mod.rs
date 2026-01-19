//! Parse the workspace to extract public items and readiness annotations.

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
    /// Crate names to exclude entirely from output.
    #[serde(default)]
    pub ignore_crates: Vec<String>,
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

    /// Check if a crate should be ignored.
    pub fn should_ignore_crate(&self, crate_name: &str) -> bool {
        self.ignore_crates.contains(&crate_name.to_string())
    }

    /// Check if a module path should be ignored.
    pub fn should_ignore_module(&self, module_path: &str) -> bool {
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
    /// Public items defined at crate root (lib.rs) with their readiness from #[ready(N)]
    #[serde(default)]
    pub root_items: HashMap<String, u8>,
    /// Public items at crate root that are missing #[ready(N)] annotation
    #[serde(default)]
    pub root_missing_items: Vec<String>,
}

/// A module with its submodules and items.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Module {
    pub path: String,
    pub file_path: PathBuf,
    pub submodules: HashMap<String, Module>,
    /// Public items in this module with their readiness from #[ready(N)]
    #[serde(default)]
    pub items: HashMap<String, u8>,
    /// Public items missing #[ready(N)] annotation
    #[serde(default)]
    pub missing_items: Vec<String>,
}

impl Default for Module {
    fn default() -> Self {
        Self {
            path: String::new(),
            file_path: PathBuf::new(),
            submodules: HashMap::new(),
            items: HashMap::new(),
            missing_items: Vec::new(),
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
            // Skip ignored crates
            if config.should_ignore_crate(&krate.name) {
                continue;
            }
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
    let (modules, root_items, root_missing_items) = if lib_rs_path.exists() {
        let modules = parse_modules(&lib_rs_path, &path.join("src"), "", config)?;
        let (root_items, root_missing_items) = extract_items_from_file(&lib_rs_path);
        (modules, root_items, root_missing_items)
    } else {
        (HashMap::new(), HashMap::new(), Vec::new())
    };

    Ok(Crate {
        name,
        path: path.to_path_buf(),
        modules,
        dependencies,
        dev_dependencies,
        root_items,
        root_missing_items,
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
            if config.should_ignore_module(&mod_path) {
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

            // Recursively parse submodules
            let submodules = if has_submodules {
                let mod_dir = src_dir.join(&mod_name);
                parse_modules(&mod_file_path, &mod_dir, &mod_path, config)?
            } else {
                HashMap::new()
            };

            let (items, missing_items) = extract_items_from_file(&mod_file_path);
            modules.insert(
                mod_name.clone(),
                Module {
                    path: mod_path,
                    file_path: mod_file_path.clone(),
                    submodules,
                    items,
                    missing_items,
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
        if config.should_ignore_module(&mod_path) {
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

        let submodules = if has_submodules {
            let mod_dir = src_dir.join(&mod_name);
            parse_modules(&mod_file_path, &mod_dir, &mod_path, config)?
        } else {
            HashMap::new()
        };

        let (items, missing_items) = extract_items_from_file(&mod_file_path);
        modules.entry(mod_name.clone()).or_insert(Module {
            path: mod_path,
            file_path: mod_file_path,
            submodules,
            items,
            missing_items,
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
        if config.should_ignore_module(&mod_path) {
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

        // Recursively parse submodules (they inherit the reexported visibility context)
        let submodules = if has_submodules {
            let mod_dir = src_dir.join(&mod_name);
            parse_modules(&mod_file_path, &mod_dir, &mod_path, config)?
        } else {
            HashMap::new()
        };

        let (items, missing_items) = extract_items_from_file(&mod_file_path);
        modules.insert(
            mod_name,
            Module {
                path: mod_path,
                file_path: mod_file_path,
                submodules,
                items,
                missing_items,
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

/// Extract public items and their readiness from #[ready(N)] attributes.
/// Returns a tuple of (items with readiness, items missing readiness).
/// Only checks structs, enums, functions, and type aliases (not traits or constants).
fn extract_items_from_file(file_path: &Path) -> (HashMap<String, u8>, Vec<String>) {
    let mut items = HashMap::new();
    let mut missing = Vec::new();

    let content = match fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(_) => return (items, missing),
    };

    let parsed = match syn::parse_file(&content) {
        Ok(f) => f,
        Err(_) => return (items, missing),
    };

    for item in &parsed.items {
        let (name, attrs, requires_annotation) = match item {
            syn::Item::Struct(s) if matches!(s.vis, syn::Visibility::Public(_)) => {
                (s.ident.to_string(), &s.attrs, true)
            }
            syn::Item::Enum(e) if matches!(e.vis, syn::Visibility::Public(_)) => {
                (e.ident.to_string(), &e.attrs, true)
            }
            syn::Item::Fn(f) if matches!(f.vis, syn::Visibility::Public(_)) => {
                (f.sig.ident.to_string(), &f.attrs, true)
            }
            syn::Item::Type(t) if matches!(t.vis, syn::Visibility::Public(_)) => {
                (t.ident.to_string(), &t.attrs, true)
            }
            // Traits and constants don't require annotations but we still track them
            syn::Item::Trait(t) if matches!(t.vis, syn::Visibility::Public(_)) => {
                (t.ident.to_string(), &t.attrs, false)
            }
            syn::Item::Const(c) if matches!(c.vis, syn::Visibility::Public(_)) => {
                (c.ident.to_string(), &c.attrs, false)
            }
            _ => continue,
        };

        if let Some(readiness) = get_ready_attribute(attrs) {
            items.insert(name, readiness);
        } else if requires_annotation {
            missing.push(name);
        }
    }

    (items, missing)
}

/// Extract readiness level from #[ready(N)] attribute.
fn get_ready_attribute(attrs: &[syn::Attribute]) -> Option<u8> {
    for attr in attrs {
        // Check for #[ready(N)] or #[commonware_macros::ready(N)]
        let path = attr.path();
        let is_ready = path.is_ident("ready")
            || (path.segments.len() == 2
                && path.segments[0].ident == "commonware_macros"
                && path.segments[1].ident == "ready");

        if is_ready {
            // Parse the argument as a literal integer
            if let syn::Meta::List(meta_list) = &attr.meta {
                let tokens = meta_list.tokens.to_string();
                if let Ok(level) = tokens.trim().parse::<u8>() {
                    return Some(level.min(4));
                }
            }
        }
    }
    None
}
