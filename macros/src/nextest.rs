use proc_macro2::Span;
use std::{
    collections::HashSet,
    env, fs,
    path::{Path, PathBuf},
    sync::OnceLock,
};
use syn::LitStr;
use toml::Value;

pub(crate) fn sanitize_group_literal(literal: &LitStr) -> Result<String, syn::Error> {
    normalize_group_name(&literal.value()).map_err(|msg| syn::Error::new(literal.span(), msg))
}

pub(crate) fn ensure_group_known(
    groups: &NextestGroups,
    group: &str,
    span: Span,
) -> Result<(), syn::Error> {
    if groups.names.contains(group) {
        Ok(())
    } else {
        Err(syn::Error::new(
            span,
            format!(
                "unknown test group `{}`; define it under [test-groups] in {}",
                group, groups.source
            ),
        ))
    }
}

pub(crate) struct NextestGroups {
    names: HashSet<String>,
    source: String,
}

static NEXTEST_GROUPS: OnceLock<Result<NextestGroups, String>> = OnceLock::new();

fn normalize_group_name(raw: &str) -> Result<String, &'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("test_group requires a non-empty filter group name");
    }

    let mut sanitized = String::with_capacity(trimmed.len());
    for ch in trimmed.chars() {
        match ch {
            'a'..='z' | '0'..='9' => sanitized.push(ch),
            'A'..='Z' => sanitized.push(ch.to_ascii_lowercase()),
            '_' => sanitized.push('_'),
            '-' => sanitized.push('_'),
            _ => {
                return Err(
                    "filter group names may only contain ASCII letters, digits, '_' or '-'",
                );
            }
        }
    }

    Ok(sanitized)
}

pub(crate) fn configured_test_groups() -> Result<&'static NextestGroups, String> {
    match NEXTEST_GROUPS.get_or_init(load_nextest_groups) {
        Ok(groups) => Ok(groups),
        Err(err) => Err(err.clone()),
    }
}

fn load_nextest_groups() -> Result<NextestGroups, String> {
    let path = resolve_nextest_config_path()?;
    let contents = fs::read_to_string(&path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let parsed: Value = toml::from_str(&contents)
        .map_err(|err| format!("failed to parse {}: {err}", path.display()))?;
    let table = parsed
        .get("test-groups")
        .and_then(Value::as_table)
        .ok_or_else(|| format!("missing [test-groups] table in {}", path.display()))?;

    let mut names = HashSet::with_capacity(table.len());
    for key in table.keys() {
        let normalized = normalize_group_name(key).map_err(|msg| {
            format!(
                "invalid test group name `{}` in {}: {}",
                key,
                path.display(),
                msg
            )
        })?;
        if names.contains(&normalized) {
            return Err(format!(
                "duplicate normalized test group `{}` in {}",
                normalized,
                path.display()
            ));
        }
        names.insert(normalized);
    }

    if names.is_empty() {
        return Err(format!(
            "no entries defined under [test-groups] in {}",
            path.display()
        ));
    }

    Ok(NextestGroups {
        names,
        source: path.display().to_string(),
    })
}

fn resolve_nextest_config_path() -> Result<PathBuf, String> {
    if let Ok(value) = env::var("COMMONWARE_NEXTEST_CONFIG") {
        let explicit = PathBuf::from(&value);
        if explicit.is_file() {
            return Ok(explicit);
        } else {
            return Err(format!(
                "COMMONWARE_NEXTEST_CONFIG points to `{}` but the file was not found",
                explicit.display()
            ));
        }
    }

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    for current in manifest_dir.ancestors() {
        let candidate = current.join(".config").join("nextest.toml");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    Err(format!(
        "unable to locate .config/nextest.toml relative to {} (set COMMONWARE_NEXTEST_CONFIG to override)",
        manifest_dir.display()
    ))
}
