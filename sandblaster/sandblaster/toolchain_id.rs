//! The toolchain identity (DESIGN.md §2.1 *Re-runs*): a SHA-256 over what
//! the verifier linked into a build script **is**, independent of how and
//! where that build script was compiled. It replaces the hash of the
//! build-script binary, which differed per feature set, profile and host
//! crate even for the same toolchain, so every build context re-verified.
//!
//! Computed by the facade's `build.rs` (this file is included there and by
//! `tests/toolchain_id.rs`; it is not part of the library) over:
//!
//! * every **local** package of the facade's dependency closure in
//!   `Cargo.lock` (the sandblaster crates: front end, kernel, targets,
//!   memguard, macros, the facade itself): the content of every file of
//!   the package directory except `tests/`, `benches/`, `examples/`,
//!   `target/` and dot files (sources, `Cargo.toml`, `build.rs`, the data
//!   the code `include_str!`s, and the data it reads at run time by path —
//!   `targets/core/*.core`, `targets/evidence/*.json` — which the binary
//!   hash never covered);
//! * every **registry or git** package of that closure by name, version,
//!   source and checksum (the lock pins their content);
//! * the facade's `rustc -vV`, the host triple and the encoded
//!   `RUSTFLAGS` of the build that compiles the toolchain (`--cfg` flags
//!   could change the code); the overflow-check setting is probed at run
//!   time by the verifier context (`sandblaster_front::driver::cache`).
//!
//! It fails closed: a closure it cannot resolve (no `Cargo.lock` above the
//! facade, a local package whose directory it cannot find) gives no
//! identity, and a build without one never reuses a verdict.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The identity format (bumped when the recipe changes).
pub const FORMAT: &str = "sandblaster-toolchain/1";

/// Top-level entries of a package directory that cannot change the
/// library a build script links.
pub const EXCLUDED: &[&str] = &["tests", "benches", "examples", "target"];

/// SHA-256 (FIPS 180-4).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut h: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_be_bytes());
    let mut w = [0u32; 64];
    for block in msg.as_chunks::<64>().0 {
        for (i, c) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*c);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v = [t1.wrapping_add(t2), v[0], v[1], v[2], v[3].wrapping_add(t1), v[4], v[5], v[6]];
        }
        for (a, b) in h.iter_mut().zip(v) {
            *a = a.wrapping_add(b);
        }
    }
    let mut out = [0u8; 32];
    for (i, x) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&x.to_be_bytes());
    }
    out
}

/// Lowercase hex.
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// One `[[package]]` of a `Cargo.lock`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockPackage {
    pub name: String,
    pub version: String,
    /// `None` for a local (path) package.
    pub source: Option<String>,
    pub checksum: Option<String>,
    /// As written: `name`, `name version` or `name version (source)`.
    pub dependencies: Vec<String>,
}

fn quoted(v: &str) -> Option<String> {
    let v = v.trim();
    v.strip_prefix('"').and_then(|x| x.strip_suffix('"')).map(str::to_string)
}

/// The packages of a `Cargo.lock` (versions 3 and 4).
pub fn parse_lock(text: &str) -> Result<Vec<LockPackage>, String> {
    let mut out: Vec<LockPackage> = Vec::new();
    let mut cur: Option<LockPackage> = None;
    let mut in_deps = false;
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if in_deps {
            if line == "]" {
                in_deps = false;
            } else if let (Some(p), Some(d)) = (cur.as_mut(), quoted(line.trim_end_matches(','))) {
                p.dependencies.push(d);
            } else if !line.is_empty() {
                return Err(format!("Cargo.lock line {}: unexpected `{line}` in a dependency list", n + 1));
            }
            continue;
        }
        if line.starts_with('[') {
            if let Some(p) = cur.take() {
                out.push(p);
            }
            if line == "[[package]]" {
                cur = Some(LockPackage { name: String::new(), version: String::new(), source: None, checksum: None, dependencies: Vec::new() });
            }
            continue;
        }
        let Some(p) = cur.as_mut() else { continue };
        let Some((k, v)) = line.split_once('=') else { continue };
        match k.trim() {
            "name" => p.name = quoted(v).ok_or_else(|| format!("Cargo.lock line {}: bad name", n + 1))?,
            "version" => p.version = quoted(v).ok_or_else(|| format!("Cargo.lock line {}: bad version", n + 1))?,
            "source" => p.source = quoted(v),
            "checksum" => p.checksum = quoted(v),
            "dependencies" => {
                let v = v.trim();
                if v == "[" {
                    in_deps = true;
                } else {
                    // a one-line list
                    let inner = v.strip_prefix('[').and_then(|x| x.strip_suffix(']')).ok_or_else(|| format!("Cargo.lock line {}: bad dependency list", n + 1))?;
                    for d in inner.split(',').filter(|d| !d.trim().is_empty()) {
                        p.dependencies.push(quoted(d).ok_or_else(|| format!("Cargo.lock line {}: bad dependency", n + 1))?);
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(p) = cur.take() {
        out.push(p);
    }
    if out.iter().any(|p| p.name.is_empty() || p.version.is_empty()) {
        return Err("Cargo.lock: a package without a name or version".into());
    }
    Ok(out)
}

/// The dependency closure of the package `root` (itself included), each
/// package once, sorted by name and version.
pub fn closure<'a>(pkgs: &'a [LockPackage], root: &str) -> Result<Vec<&'a LockPackage>, String> {
    let find = |spec: &str| -> Result<usize, String> {
        let mut w = spec.split(' ');
        let name = w.next().unwrap_or("");
        let version = w.next();
        let cands: Vec<usize> = (0..pkgs.len()).filter(|&i| pkgs[i].name == name && version.is_none_or(|v| pkgs[i].version == v)).collect();
        match cands.as_slice() {
            [i] => Ok(*i),
            [] => Err(format!("Cargo.lock has no package `{spec}`")),
            _ => {
                // `name version (source)`: pick by source
                let src = spec.split_once(" (").map(|(_, s)| s.trim_end_matches(')'));
                cands.iter().copied().find(|&i| src.is_some() && pkgs[i].source.as_deref() == src).ok_or_else(|| format!("Cargo.lock: `{spec}` is ambiguous"))
            }
        }
    };
    let mut seen: BTreeSet<usize> = BTreeSet::new();
    let mut stack = vec![find(root)?];
    while let Some(i) = stack.pop() {
        if !seen.insert(i) {
            continue;
        }
        for d in &pkgs[i].dependencies {
            stack.push(find(d)?);
        }
    }
    let mut v: Vec<&LockPackage> = seen.into_iter().map(|i| &pkgs[i]).collect();
    v.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    Ok(v)
}

/// The `[package] name` of a manifest.
pub fn manifest_name(text: &str) -> Option<String> {
    let mut in_pkg = false;
    for l in text.lines() {
        let l = l.trim();
        if l.starts_with('[') {
            in_pkg = l == "[package]";
            continue;
        }
        if in_pkg && let Some((k, v)) = l.split_once('=') && k.trim() == "name" {
            return quoted(v);
        }
    }
    None
}

/// The local packages under `dir` (each subdirectory with a `Cargo.toml`,
/// one level deep), by package name.
pub fn local_packages(dir: &Path) -> BTreeMap<String, PathBuf> {
    let mut out = BTreeMap::new();
    let Ok(rd) = std::fs::read_dir(dir) else { return out };
    for e in rd.flatten() {
        let p = e.path();
        if let Ok(t) = std::fs::read_to_string(p.join("Cargo.toml"))
            && let Some(n) = manifest_name(&t)
        {
            out.insert(n, p);
        }
    }
    out
}

/// The digest of a package directory's files (module docs: every file but
/// the [`EXCLUDED`] top-level entries and dot files, by relative path,
/// length and SHA-256) and the top-level entries a build must watch.
pub fn tree_digest(dir: &Path) -> Result<(String, Vec<PathBuf>), String> {
    fn walk(base: &Path, dir: &Path, top: bool, files: &mut Vec<(String, PathBuf)>, watch: &mut Vec<PathBuf>) -> Result<(), String> {
        let rd = std::fs::read_dir(dir).map_err(|e| format!("cannot list `{}`: {e}", dir.display()))?;
        let mut entries: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        entries.sort();
        for p in entries {
            let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            if name.starts_with('.') || (top && EXCLUDED.contains(&name.as_str())) {
                continue;
            }
            if top {
                watch.push(p.clone());
            }
            let md = std::fs::metadata(&p).map_err(|e| format!("cannot stat `{}`: {e}", p.display()))?;
            if md.is_dir() {
                walk(base, &p, false, files, watch)?;
            } else if md.is_file() {
                let rel = p.strip_prefix(base).unwrap_or(&p).components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect::<Vec<_>>().join("/");
                files.push((rel, p));
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    let mut watch = Vec::new();
    walk(dir, dir, true, &mut files, &mut watch)?;
    files.sort();
    let mut t = String::new();
    for (rel, p) in &files {
        let bytes = std::fs::read(p).map_err(|e| format!("cannot read `{}`: {e}", p.display()))?;
        t.push_str(&format!("file {rel} {} {}\n", bytes.len(), hex(&sha256(&bytes))));
    }
    Ok((hex(&sha256(t.as_bytes())), watch))
}

/// The toolchain identity text of the closure of `root` in the lock
/// `lock_text` (module docs); `locals` maps local package names to their
/// directories, `build` lists the build facts (`rustc`, host, flags).
/// Returns the identity (hex SHA-256), the text it hashes (for
/// diagnostics) and the paths a build must watch.
pub fn identity(lock_text: &str, root: &str, locals: &BTreeMap<String, PathBuf>, build: &[(&str, String)]) -> Result<(String, String, Vec<PathBuf>), String> {
    let pkgs = parse_lock(lock_text)?;
    let mut t = format!("{FORMAT}\nroot {root}\n");
    let mut watch = Vec::new();
    for p in closure(&pkgs, root)? {
        match &p.source {
            None => {
                let dir = locals.get(&p.name).ok_or_else(|| format!("the local package `{}` of the toolchain is not beside the facade", p.name))?;
                let (d, w) = tree_digest(dir)?;
                t.push_str(&format!("local {} {} {d}\n", p.name, p.version));
                watch.extend(w);
            }
            Some(src) => {
                let sum = p.checksum.as_deref().unwrap_or(if src.starts_with("git+") { "(pinned by the source's commit)" } else { "(none)" });
                t.push_str(&format!("dep {} {} {src} {sum}\n", p.name, p.version));
            }
        }
    }
    for (k, v) in build {
        t.push_str(&format!("build {k} {}\n", hex(&sha256(v.as_bytes()))));
    }
    Ok((hex(&sha256(t.as_bytes())), t, watch))
}

/// The nearest `Cargo.lock` at or above `dir`.
pub fn find_lock(dir: &Path) -> Option<PathBuf> {
    let mut d = Some(dir);
    while let Some(x) = d {
        let l = x.join("Cargo.lock");
        if l.is_file() {
            return Some(l);
        }
        d = x.parent();
    }
    None
}
