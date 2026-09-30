//! `SPEC.lock` (DESIGN.md §15.6; stage **S1**, agent D): the locked
//! specification surface ([`crate::surface`]) — a sorted, readable text
//! file in the DSL root directory with one entry per item of the **review
//! surface** (laws, their vocabulary, boundary signatures, trusted items,
//! sections and the known answers of the vocabulary; never proof
//! internals — `crate::surface`, *What is locked*) and a
//! header recording the lock format, the toolchain (kernel, prelude,
//! SEMANTICS, builtins and target-model hashes), the TCB statement and the
//! computed sections, and the Merkle root of it all.
//!
//! # Format (`sandblaster-spec-lock/1`)
//!
//! ```text
//! format sandblaster-spec-lock/1
//! root <H(header, (key, H(i))…)>
//! kernel <hash>           prelude <hash>      (one per line)
//! semantics <hash>        builtins <hash>
//! target aarch64 <hash>   (one line per accepted target)
//! sections 1
//! section section:crate::f R {crate::f} P {crate::f} Deps {} H <H(i)…> (one per section)
//! tcb <item of DESIGN.md §1.1> (one line each)
//!
//! item law:crate::laws::bounded
//!   hash <H(i)>
//!   canon <canon(stmt)>
//!   src <hash of src(stmt)>
//!   dep constant:crate::LIMIT <H(dep)> (an item dependency and its hash)
//!   dep-cycle contract:crate::g        (an item of the same cycle)
//!   ext prelude:base.core <hash>       (a toolchain file)
//!   | law crate::laws::bounded(x: u32)  (the de-elaborated statement)
//!   |   requires ((x < 1000u32) == true)
//!   kernel type (x : U32) -> ...       (the kernel statement, core text)
//! ```
//!
//! An entry that applies to only some of the accepted targets (a target
//! model, an item behind a `cfg`) carries `  targets aarch64`; an entry
//! without that line applies to every accepted target. Lines starting with
//! `#` are comments.
//!
//! # Enforcement
//!
//! [`compare`] matches the lock against the surface computed for one
//! target: the header must equal the toolchain, the entries of that target
//! must be exactly the computed items (same keys, hashes and statements),
//! every entry's hash must be `H(i)` of its own lines ([`verify_entries`]),
//! and the root must be the hash of the file's own header and entries. A
//! missing lock, or any added, removed or changed item, is a mismatch;
//! [`enforce`] turns a mismatch into `error[spec-lock]` diagnostics naming
//! each item. **Only `sandblaster spec --accept [ITEM…]` writes the lock**
//! ([`accept`]; never `build.rs`, never an environment variable).
//!
//! [`enforce`] is the lock gate of the crate path (`driver::gates`, DESIGN.md
//! §15.8): every build and every CLI command that states a crate verdict
//! fails on a missing, malformed or mismatched lock. The generated crate
//! exports the matching lock's root as `SANDBLASTER_SPEC_ROOT`.
//!
//! # One lock per root
//!
//! Each DSL root has its own lock in its directory ([`lock_path`]):
//! `SPEC.lock` for a root named `mod.rs` or `lib.rs`, `SPEC.<stem>.lock`
//! otherwise (`sandblaster/fixtures/qmdb/sandblaster/mod.rs` → `SPEC.lock`, `sandblaster/fixtures/qmdb/sandblaster/n1.rs`
//! → `SPEC.n1.lock`), so two roots in one directory never share a lock.

use std::collections::{BTreeMap, BTreeSet};

use crate::diag::{DiagKind, Diagnostic, Diagnostics};
use crate::json::Json;
use crate::span::Span;
use crate::surface::{hex, parse_hex, sha256, Hash, Surface, SurfaceItem, SurfaceKind, TCB};

/// The lock file of a root named `mod.rs` or `lib.rs`, in the DSL root
/// directory ([`lock_path`]).
pub const LOCK_FILE: &str = "SPEC.lock";

/// The lock of the DSL root `root` (see the module docs): `SPEC.lock` for
/// `mod.rs` and `lib.rs`, `SPEC.<stem>.lock` for any other root file.
pub fn lock_path(root: &std::path::Path) -> std::path::PathBuf {
    let dir = root.parent().unwrap_or(std::path::Path::new(""));
    match root.file_stem().and_then(|s| s.to_str()) {
        Some("mod" | "lib") | None => dir.join(LOCK_FILE),
        Some(stem) => dir.join(format!("SPEC.{stem}.lock")),
    }
}

/// The lock format.
pub const FORMAT: &str = "sandblaster-spec-lock/1";

/// The kernel's source files: the `kernel` hash of the lock header. A test
/// (`tests/spec15_lock.rs`) checks that the list is exactly the files of
/// `sandblaster/kernel/src`.
pub const KERNEL_SOURCES: &[(&str, &str)] = &[
    ("alpha.rs", include_str!("../../kernel/src/alpha.rs")),
    ("api.rs", include_str!("../../kernel/src/api.rs")),
    ("axioms.rs", include_str!("../../kernel/src/axioms.rs")),
    ("bvnorm/mod.rs", include_str!("../../kernel/src/bvnorm/mod.rs")),
    ("bvnorm/tripwire.rs", include_str!("../../kernel/src/bvnorm/tripwire.rs")),
    ("bvnorm/word.rs", include_str!("../../kernel/src/bvnorm/word.rs")),
    ("check.rs", include_str!("../../kernel/src/check.rs")),
    ("closed.rs", include_str!("../../kernel/src/closed.rs")),
    ("conv.rs", include_str!("../../kernel/src/conv.rs")),
    ("env.rs", include_str!("../../kernel/src/env.rs")),
    ("eval.rs", include_str!("../../kernel/src/eval.rs")),
    ("inductive.rs", include_str!("../../kernel/src/inductive.rs")),
    ("lib.rs", include_str!("../../kernel/src/lib.rs")),
    ("linarith.rs", include_str!("../../kernel/src/linarith.rs")),
    ("lincert.rs", include_str!("../../kernel/src/lincert.rs")),
    ("prelude.rs", include_str!("../../kernel/src/prelude.rs")),
    ("prim.rs", include_str!("../../kernel/src/prim.rs")),
    ("quote.rs", include_str!("../../kernel/src/quote.rs")),
    ("recursion.rs", include_str!("../../kernel/src/recursion.rs")),
    ("section.rs", include_str!("../../kernel/src/section.rs")),
    ("syntax/lexer.rs", include_str!("../../kernel/src/syntax/lexer.rs")),
    ("syntax/mod.rs", include_str!("../../kernel/src/syntax/mod.rs")),
    ("syntax/parser.rs", include_str!("../../kernel/src/syntax/parser.rs")),
    ("syntax/printer.rs", include_str!("../../kernel/src/syntax/printer.rs")),
    ("term.rs", include_str!("../../kernel/src/term.rs")),
    ("util.rs", include_str!("../../kernel/src/util.rs")),
    ("value.rs", include_str!("../../kernel/src/value.rs")),
];

/// `SEMANTICS.md` (the normative elaboration semantics, TCB items 2 and 6).
pub const SEMANTICS_MD: &str = include_str!("../../SEMANTICS.md");

/// The elaboration-semantics definitions (`Tuple1`, `array::copy_range`).
pub const SEMANTICS_RS: &str = include_str!("elab/semantics.rs");

/// The `builtins` hash of the lock header: the method/operator table, the
/// intrinsic table, the elaboration-semantics definitions and the ghost
/// library.
pub const BUILTIN_SOURCES: &[(&str, &str)] = &[
    ("builtins.rs", include_str!("builtins.rs")),
    ("intrinsics.rs", include_str!("intrinsics.rs")),
    ("elab/semantics.rs", include_str!("elab/semantics.rs")),
    ("elab/ghost.core", include_str!("elab/ghost.core")),
];

/// What a dependency line names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DepKind {
    /// `dep <key> <H(dep)>`: an item outside the entry's strongly connected
    /// component, with its hash when the entry was accepted.
    Item,
    /// `dep-cycle <key>`: an item of the entry's own component.
    Cycle,
    /// `ext <name> <hash>`: a toolchain file (`prelude:list.core`).
    Ext,
}

/// One dependency line of an entry.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LockDep {
    pub kind: DepKind,
    /// An item key or a toolchain dependency name.
    pub name: String,
    /// `None` for [`DepKind::Cycle`].
    pub hash: Option<Hash>,
}

/// One entry of `SPEC.lock`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockEntry {
    pub key: String,
    pub kind: SurfaceKind,
    /// The accepted targets it applies to.
    pub targets: BTreeSet<String>,
    /// The Merkle hash `H(i)`.
    pub hash: Hash,
    pub canon: Hash,
    pub src: Hash,
    pub deps: Vec<LockDep>,
    /// The statement as rendered for review (fully parenthesized).
    pub statement: Vec<String>,
    /// The kernel statement in core text, by part.
    pub kernel: Vec<(String, String)>,
    pub kernel_omitted: Vec<String>,
}

impl LockEntry {
    /// The entry of a computed item, for `target`.
    pub fn of(item: &SurfaceItem, target: &str) -> LockEntry {
        LockEntry {
            key: item.key.clone(),
            kind: item.kind,
            targets: [target.to_string()].into_iter().collect(),
            hash: item.hash,
            canon: item.canon,
            src: item.src,
            deps: item
                .deps
                .iter()
                .map(|d| match (d.item, d.cycle) {
                    (true, true) => LockDep { kind: DepKind::Cycle, name: d.name.clone(), hash: None },
                    (true, false) => LockDep { kind: DepKind::Item, name: d.name.clone(), hash: Some(d.hash) },
                    (false, _) => LockDep { kind: DepKind::Ext, name: d.name.clone(), hash: Some(d.hash) },
                })
                .collect(),
            statement: item.statement.iter().flat_map(|s| s.lines().map(str::to_string).collect::<Vec<_>>()).collect(),
            kernel: item.kernel.clone(),
            kernel_omitted: item.kernel_omitted.clone(),
        }
    }

    /// Same content (everything but the target set).
    fn same_content(&self, o: &LockEntry) -> bool {
        self.key == o.key && self.hash == o.hash && self.canon == o.canon && self.src == o.src && self.deps == o.deps && self.statement == o.statement && self.kernel == o.kernel && self.kernel_omitted == o.kernel_omitted
    }
}

/// The parsed lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lock {
    pub format: String,
    /// The root as written in the file.
    pub root: Hash,
    pub kernel: Hash,
    pub prelude: Hash,
    pub semantics: Hash,
    pub builtins: Hash,
    /// Accepted targets and their target-model hashes.
    pub targets: BTreeMap<String, Hash>,
    pub sections: usize,
    pub tcb: Vec<String>,
    /// Sorted by key, then targets.
    pub entries: Vec<LockEntry>,
}

impl Lock {
    /// The header's `section` lines (DESIGN.md §15.6: the header records
    /// every section, `R`, `P`, `Deps` and `H(complete_p)`): derived from the
    /// lock's own section entries (whose hashes the root covers), so they
    /// cannot disagree with them; a hand-edited line makes the lock malformed.
    pub fn section_lines(&self) -> Vec<String> {
        let all: BTreeSet<String> = self.targets.keys().cloned().collect();
        let mut out = Vec::new();
        for e in self.entries.iter().filter(|e| e.kind == SurfaceKind::Section) {
            let field = |prefix: &str| e.statement.iter().find_map(|l| l.trim_start().strip_prefix(prefix).map(|x| x.trim().to_string())).unwrap_or_default();
            let targets = if e.targets == all { String::new() } else { format!(" targets {}", e.targets.iter().cloned().collect::<Vec<_>>().join(",")) };
            out.push(format!("section {} R {} P {} Deps {} H {}…{targets}", e.key, field("section R = "), field("P(R) = "), field("Deps(R) = "), h8(&e.hash)));
        }
        out
    }

    /// An empty lock with the header of `s`.
    pub fn empty_for(s: &Surface) -> Lock {
        let sections = s.items.iter().filter(|i| i.kind == SurfaceKind::Section).count();
        let mut l = Lock { format: FORMAT.into(), root: [0; 32], kernel: s.kernel, prelude: s.prelude, semantics: s.semantics, builtins: s.builtins, targets: BTreeMap::new(), sections, tcb: TCB.iter().map(|x| x.to_string()).collect(), entries: vec![] };
        l.targets.insert(s.target.clone(), s.target_model);
        l.root = l.compute_root();
        l
    }

    /// The entries that apply to `target`.
    pub fn entries_for<'l>(&'l self, target: &'l str) -> impl Iterator<Item = &'l LockEntry> + 'l {
        self.entries.iter().filter(move |e| e.targets.contains(target))
    }

    fn sort(&mut self) {
        self.entries.sort_by(|a, b| (a.key.as_str(), &a.targets).cmp(&(b.key.as_str(), &b.targets)));
    }

    /// The Merkle root: the header and every entry's key, targets and
    /// `H(i)` (the rendered statements and kernel text are review aids; the
    /// hashes cover what they show).
    pub fn compute_root(&self) -> Hash {
        let mut b: Vec<u8> = Vec::new();
        let mut put = |s: &str| {
            b.extend_from_slice(&(s.len() as u64).to_le_bytes());
            b.extend_from_slice(s.as_bytes());
        };
        put("sandblaster-spec-root/1");
        put(&self.format);
        for (n, h) in [("kernel", &self.kernel), ("prelude", &self.prelude), ("semantics", &self.semantics), ("builtins", &self.builtins)] {
            put(n);
            put(&hex(h));
        }
        for (t, h) in &self.targets {
            put("target");
            put(t);
            put(&hex(h));
        }
        put(&format!("sections {}", self.sections));
        for t in &self.tcb {
            put("tcb");
            put(t);
        }
        let mut es: Vec<&LockEntry> = self.entries.iter().collect();
        es.sort_by(|a, c| (a.key.as_str(), &a.targets).cmp(&(c.key.as_str(), &c.targets)));
        for e in es {
            put("item");
            put(&e.key);
            put(&e.targets.iter().cloned().collect::<Vec<_>>().join(" "));
            put(&hex(&e.hash));
        }
        sha256(&b)
    }

    /// Renders the file (sorted; the root recomputed).
    pub fn render(&self) -> String {
        let mut l = self.clone();
        l.sort();
        let root = l.compute_root();
        let mut s = String::new();
        s.push_str("# SPEC.lock: the locked specification surface of this crate (DESIGN.md §15.6).\n");
        s.push_str("# Written only by `sandblaster spec --accept`; the build computes the surface and\n");
        s.push_str("# compares it with this file. Review every change of this file as a change of\n");
        s.push_str("# the specification: `sandblaster spec` prints the spec sheet, `sandblaster spec\n");
        s.push_str("# --diff <rev>` classifies changes (strengthened / weakened / equivalent / unrelated).\n");
        s.push_str(&format!("format {}\n", l.format));
        s.push_str(&format!("root {}\n", hex(&root)));
        s.push_str(&format!("kernel {}\nprelude {}\nsemantics {}\nbuiltins {}\n", hex(&l.kernel), hex(&l.prelude), hex(&l.semantics), hex(&l.builtins)));
        for (t, h) in &l.targets {
            s.push_str(&format!("target {t} {}\n", hex(h)));
        }
        s.push_str(&format!("sections {}\n", l.sections));
        for line in l.section_lines() {
            s.push_str(&line);
            s.push('\n');
        }
        for t in &l.tcb {
            s.push_str(&format!("tcb {t}\n"));
        }
        let all: BTreeSet<String> = l.targets.keys().cloned().collect();
        for e in &l.entries {
            s.push_str(&format!("\nitem {}\n", e.key));
            if e.targets != all {
                s.push_str(&format!("  targets {}\n", e.targets.iter().cloned().collect::<Vec<_>>().join(" ")));
            }
            s.push_str(&format!("  hash {}\n  canon {}\n  src {}\n", hex(&e.hash), hex(&e.canon), hex(&e.src)));
            for d in &e.deps {
                match (d.kind, &d.hash) {
                    (DepKind::Item, Some(h)) => s.push_str(&format!("  dep {} {}\n", d.name, hex(h))),
                    (DepKind::Ext, Some(h)) => s.push_str(&format!("  ext {} {}\n", d.name, hex(h))),
                    _ => s.push_str(&format!("  dep-cycle {}\n", d.name)),
                }
            }
            for st in &e.statement {
                s.push_str(&format!("  | {st}\n"));
            }
            for (part, text) in &e.kernel {
                for line in text.lines() {
                    s.push_str(&format!("  kernel {part} {line}\n"));
                }
            }
            for part in &e.kernel_omitted {
                s.push_str(&format!("  kernel-omitted {part}\n"));
            }
        }
        s
    }

    /// Parses a lock file.
    pub fn parse(text: &str) -> Result<Lock, String> {
        let mut format = None;
        let mut root = None;
        let mut hdr: BTreeMap<&str, Hash> = BTreeMap::new();
        let mut targets = BTreeMap::new();
        let mut sections = None;
        let mut section_lines: Vec<String> = Vec::new();
        let mut tcb = Vec::new();
        struct Raw {
            key: String,
            targets: Option<BTreeSet<String>>,
            hash: Option<Hash>,
            canon: Option<Hash>,
            src: Option<Hash>,
            deps: Vec<LockDep>,
            statement: Vec<String>,
            kernel: Vec<(String, String)>,
            omitted: Vec<String>,
            line: usize,
        }
        let mut raws: Vec<Raw> = Vec::new();
        let hash_of = |s: &str, n: usize| parse_hex(s).ok_or_else(|| format!("line {n}: `{s}` is not a 64-digit hex hash"));
        for (i, line) in text.lines().enumerate() {
            let n = i + 1;
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(rest) = line.strip_prefix("  ") {
                let Some(cur) = raws.last_mut() else { return Err(format!("line {n}: an indented line outside an item")) };
                if let Some(st) = rest.strip_prefix("| ") {
                    cur.statement.push(st.to_string());
                } else if rest == "|" {
                    cur.statement.push(String::new());
                } else {
                    let (w, arg) = rest.split_once(' ').unwrap_or((rest, ""));
                    match w {
                        "targets" => cur.targets = Some(arg.split_whitespace().map(str::to_string).collect()),
                        "hash" => cur.hash = Some(hash_of(arg, n)?),
                        "canon" => cur.canon = Some(hash_of(arg, n)?),
                        "src" => cur.src = Some(hash_of(arg, n)?),
                        "dep" | "ext" | "dep-cycle" => {
                            let mut it = arg.split_whitespace();
                            let name = it.next().ok_or_else(|| format!("line {n}: `{w}` without a name"))?.to_string();
                            let (kind, hash) = match w {
                                "dep" => (DepKind::Item, Some(hash_of(it.next().unwrap_or(""), n)?)),
                                "ext" => (DepKind::Ext, Some(hash_of(it.next().unwrap_or(""), n)?)),
                                _ => (DepKind::Cycle, None),
                            };
                            cur.deps.push(LockDep { kind, name, hash });
                        }
                        "kernel" => {
                            let (part, t) = arg.split_once(' ').unwrap_or((arg, ""));
                            match cur.kernel.iter_mut().find(|(p, _)| p == part) {
                                Some((_, text)) => {
                                    text.push('\n');
                                    text.push_str(t);
                                }
                                None => cur.kernel.push((part.to_string(), t.to_string())),
                            }
                        }
                        "kernel-omitted" => cur.omitted.push(arg.to_string()),
                        _ => return Err(format!("line {n}: unknown entry field `{w}`")),
                    }
                }
                continue;
            }
            let (w, arg) = line.split_once(' ').unwrap_or((line, ""));
            match w {
                "format" => format = Some(arg.to_string()),
                "root" => root = Some(hash_of(arg, n)?),
                "kernel" | "prelude" | "semantics" | "builtins" => {
                    let k: &str = match w {
                        "kernel" => "kernel",
                        "prelude" => "prelude",
                        "semantics" => "semantics",
                        _ => "builtins",
                    };
                    hdr.insert(k, hash_of(arg, n)?);
                }
                "target" => {
                    let (t, h) = arg.split_once(' ').ok_or_else(|| format!("line {n}: `target <arch> <hash>` expected"))?;
                    targets.insert(t.to_string(), hash_of(h, n)?);
                }
                "sections" => sections = Some(arg.trim().parse::<usize>().map_err(|_| format!("line {n}: `sections <count>` expected"))?),
                "section" => section_lines.push(line.to_string()),
                "tcb" => tcb.push(arg.to_string()),
                "item" => raws.push(Raw { key: arg.to_string(), targets: None, hash: None, canon: None, src: None, deps: vec![], statement: vec![], kernel: vec![], omitted: vec![], line: n }),
                _ => return Err(format!("line {n}: unknown header line `{w}`")),
            }
        }
        let format = format.ok_or("no `format` line")?;
        if format != FORMAT {
            return Err(format!("lock format `{format}` is not `{FORMAT}` (re-accept with this toolchain)"));
        }
        let get = |k: &str| hdr.get(k).copied().ok_or_else(|| format!("no `{k}` line"));
        let all: BTreeSet<String> = targets.keys().cloned().collect();
        let mut entries = Vec::new();
        for r in raws {
            let n = r.line;
            let kind = r.key.split(':').next().and_then(SurfaceKind::from_tag).ok_or_else(|| format!("line {n}: `{}` does not start with a surface kind", r.key))?;
            let targets = r.targets.unwrap_or_else(|| all.clone());
            if let Some(t) = targets.iter().find(|t| !all.contains(*t)) {
                return Err(format!("line {n}: target `{t}` has no `target` line"));
            }
            entries.push(LockEntry {
                key: r.key,
                kind,
                targets,
                hash: r.hash.ok_or_else(|| format!("line {n}: item without `hash`"))?,
                canon: r.canon.ok_or_else(|| format!("line {n}: item without `canon`"))?,
                src: r.src.ok_or_else(|| format!("line {n}: item without `src`"))?,
                deps: r.deps,
                statement: r.statement,
                kernel: r.kernel,
                kernel_omitted: r.omitted,
            });
        }
        let mut l = Lock { format, root: root.ok_or("no `root` line")?, kernel: get("kernel")?, prelude: get("prelude")?, semantics: get("semantics")?, builtins: get("builtins")?, targets, sections: sections.ok_or("no `sections` line")?, tcb, entries };
        l.sort();
        if section_lines != l.section_lines() {
            return Err("the header's `section` lines do not match the section entries (edited by hand?)".into());
        }
        for t in l.targets.keys() {
            let mut seen = BTreeSet::new();
            for e in l.entries_for(t) {
                if !seen.insert(e.key.as_str()) {
                    return Err(format!("`{}` appears twice for target {t}", e.key));
                }
            }
        }
        Ok(l)
    }
}

/// Checks that every entry's `hash` is `H(i)` of its own fields (kind, key,
/// `canon`, `src`, dependencies; DESIGN.md §15.6), so no line of an entry
/// can be edited without a visible change of its hash — and, through the
/// root, of the file's `root` line.
pub fn verify_entries(lock: &Lock) -> Result<(), String> {
    use crate::surface::{item_l, item_local, scc_member_hash};
    for t in lock.targets.keys() {
        let es: BTreeMap<&str, &LockEntry> = lock.entries_for(t).map(|e| (e.key.as_str(), e)).collect();
        let l_of = |e: &LockEntry| -> Hash {
            let local = item_local(e.kind, &e.key, &e.canon, &e.src);
            let mut ext: Vec<(&str, &Hash)> = e.deps.iter().filter(|d| d.kind == DepKind::Ext).filter_map(|d| d.hash.as_ref().map(|h| (d.name.as_str(), h))).collect();
            ext.sort();
            let mut items: Vec<(&str, Option<&Hash>)> = e.deps.iter().filter(|d| d.kind != DepKind::Ext).map(|d| (d.name.as_str(), d.hash.as_ref())).collect();
            items.sort();
            item_l(&local, &ext, &items)
        };
        for e in es.values() {
            let l = l_of(e);
            let expected = if e.deps.iter().any(|d| d.kind == DepKind::Cycle) {
                // the component: the closure of the cycle dependencies
                let mut members: BTreeSet<&str> = BTreeSet::new();
                let mut work = vec![e.key.as_str()];
                while let Some(k) = work.pop() {
                    if !members.insert(k) {
                        continue;
                    }
                    let m = es.get(k).ok_or_else(|| format!("`{}` names `{k}` in its cycle, which has no entry for target {t}", e.key))?;
                    work.extend(m.deps.iter().filter(|d| d.kind == DepKind::Cycle).map(|d| d.name.as_str()));
                }
                let ls: Vec<(String, Hash)> = members.iter().map(|k| (k.to_string(), l_of(es[k]))).collect();
                scc_member_hash(&l, &ls)
            } else {
                l
            };
            if expected != e.hash {
                return Err(format!("the entry of `{}` does not hash to its `hash` line (its fields were edited by hand?)", e.key));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// comparison
// ---------------------------------------------------------------------------

/// How an item differs between the lock and the computed surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum What {
    /// On the surface, not in the lock.
    Added,
    /// In the lock, not on the surface.
    Removed,
    /// A different hash.
    Changed,
    /// The same hash, a different rendered statement (the renderer changed).
    Restated,
}

impl What {
    pub fn word(self) -> &'static str {
        match self {
            What::Added => "added",
            What::Removed => "removed",
            What::Changed => "changed",
            What::Restated => "restated",
        }
    }
}

/// One difference.
#[derive(Clone, Debug)]
pub struct Mismatch {
    pub key: String,
    pub what: What,
    /// The locked statement (removed, changed, restated).
    pub old: Vec<String>,
    /// The computed statement (added, changed, restated).
    pub new: Vec<String>,
    pub span: Span,
    /// The changed dependencies of a changed item (by key).
    pub via: Vec<String>,
}

/// The state of the lock against the computed surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LockState {
    /// The surface was not computed (verification failed, test-only run).
    NotComputed(String),
    /// The surface has §15.6 errors (dependencies on unestablished exec
    /// globals): it cannot be locked.
    SurfaceErrors,
    /// No `SPEC.lock` in the DSL root directory.
    Missing,
    /// The file does not parse, or its root does not match its entries.
    Malformed(String),
    Matches,
    Mismatch,
}

/// The lock status of a build (Send: for the report, the CLI and
/// [`enforce`]).
#[derive(Clone, Debug)]
pub struct LockStatus {
    pub state: LockState,
    /// The lock file's path (display).
    pub file: String,
    pub target: String,
    /// Number of computed surface items (the review surface).
    pub items: usize,
    /// Number of computed items left out of the lock as proof internals
    /// (`crate::surface`, *What is locked*).
    pub internal: usize,
    /// `SANDBLASTER_SPEC_ROOT`: the lock's root when it matches, all zero
    /// otherwise.
    pub root: Hash,
    /// The root of the lock `sandblaster spec --accept` would write now.
    pub computed_root: Hash,
    /// Header differences (`kernel: locked …, now …`).
    pub header: Vec<String>,
    pub mismatches: Vec<Mismatch>,
    /// §15.6 errors of the surface: `(key, message, note, span)`.
    pub errors: Vec<(String, String, String, Span)>,
}

impl LockStatus {
    /// A status for a surface that was not computed.
    pub fn not_computed(file: &str, target: &str, why: &str) -> LockStatus {
        LockStatus { state: LockState::NotComputed(why.to_string()), file: file.to_string(), target: target.to_string(), items: 0, internal: 0, root: [0; 32], computed_root: [0; 32], header: vec![], mismatches: vec![], errors: vec![] }
    }

    pub fn matches(&self) -> bool {
        self.state == LockState::Matches
    }

    /// One line (for the build's summary and the CLI).
    pub fn summary(&self) -> String {
        match &self.state {
            LockState::NotComputed(why) => format!("not computed ({why})"),
            LockState::SurfaceErrors => format!("the surface cannot be locked: {} error(s) (§15.6)", self.errors.len()),
            LockState::Missing => format!("missing ({} surface item(s) not locked)", self.items),
            LockState::Malformed(why) => format!("malformed: {why}"),
            LockState::Matches => format!("matches ({} item(s), root {})", self.items, hex(&self.root)),
            LockState::Mismatch => {
                let count = |w: What| self.mismatches.iter().filter(|m| m.what == w).count();
                let mut parts = Vec::new();
                for w in [What::Added, What::Removed, What::Changed, What::Restated] {
                    if count(w) > 0 {
                        parts.push(format!("{} {}", count(w), w.word()));
                    }
                }
                if !self.header.is_empty() {
                    parts.push(format!("{} toolchain line(s) differ", self.header.len()));
                }
                format!("MISMATCH: {}", parts.join(", "))
            }
        }
    }

    /// The report's `spec` section.
    pub fn json(&self) -> Json {
        let mut j = Json::obj();
        j.str("lock_file", &self.file);
        j.str("target", &self.target);
        j.str(
            "status",
            match &self.state {
                LockState::NotComputed(_) => "not computed",
                LockState::SurfaceErrors => "surface errors",
                LockState::Missing => "missing",
                LockState::Malformed(_) => "malformed",
                LockState::Matches => "matches",
                LockState::Mismatch => "mismatch",
            },
        );
        j.str("summary", &self.summary());
        j.num("items", self.items as i64);
        j.num("internal_not_locked", self.internal as i64);
        j.str("root", &hex(&self.root));
        j.str("computed_root", &hex(&self.computed_root));
        j.put("header", Json::Arr(self.header.iter().map(|h| Json::string(h)).collect()));
        j.put(
            "mismatches",
            Json::Arr(
                self.mismatches
                    .iter()
                    .map(|m| {
                        let mut o = Json::obj();
                        o.str("item", &m.key);
                        o.str("change", m.what.word());
                        if !m.via.is_empty() {
                            o.put("through", Json::Arr(m.via.iter().map(|v| Json::string(v)).collect()));
                        }
                        o
                    })
                    .collect(),
            ),
        );
        j.put(
            "errors",
            Json::Arr(
                self.errors
                    .iter()
                    .map(|(k, m, _, _)| {
                        let mut o = Json::obj();
                        o.str("item", k);
                        o.str("message", m);
                        o
                    })
                    .collect(),
            ),
        );
        j
    }
}

fn h8(h: &Hash) -> String {
    hex(&h[..8])
}

/// The lock that accepting every item of `s` would produce from `old`.
fn full_accept(old: Option<&Lock>, s: &Surface) -> Lock {
    accept_into(old, s, &Selection::All).map(|x| x.0).unwrap_or_else(|_| Lock::empty_for(s))
}

/// Compares the lock text (`None`: no file) with the computed surface of
/// one target (see the module docs).
pub fn compare(text: Option<&str>, s: &Surface, file: &str) -> LockStatus {
    let mut st = LockStatus { state: LockState::Matches, file: file.to_string(), target: s.target.clone(), items: s.items.len(), internal: s.internal.len(), root: [0; 32], computed_root: [0; 32], header: vec![], mismatches: vec![], errors: vec![] };
    if !s.errors.is_empty() {
        st.state = LockState::SurfaceErrors;
        st.errors = s.errors.iter().map(|e| (e.key.clone(), e.msg.clone(), e.note.clone(), e.span)).collect();
        return st;
    }
    let lock = match text.map(Lock::parse) {
        None => {
            st.state = LockState::Missing;
            st.computed_root = full_accept(None, s).compute_root();
            st.mismatches = s.items.iter().map(|i| Mismatch { key: i.key.clone(), what: What::Added, old: vec![], new: i.statement.clone(), span: i.span, via: vec![] }).collect();
            return st;
        }
        Some(Err(e)) => {
            st.state = LockState::Malformed(e);
            st.computed_root = full_accept(None, s).compute_root();
            return st;
        }
        Some(Ok(l)) => l,
    };
    st.computed_root = full_accept(Some(&lock), s).compute_root();
    if lock.compute_root() != lock.root {
        st.state = LockState::Malformed("the `root` line is not the hash of the file's header and entries (edited by hand?); re-accept with `sandblaster spec --accept`".into());
        return st;
    }
    if let Err(e) = verify_entries(&lock) {
        st.state = LockState::Malformed(format!("{e}; re-accept with `sandblaster spec --accept`"));
        return st;
    }
    for (name, l, c) in [("kernel", lock.kernel, s.kernel), ("prelude", lock.prelude, s.prelude), ("semantics", lock.semantics, s.semantics), ("builtins", lock.builtins, s.builtins)] {
        if l != c {
            st.header.push(format!("{name}: locked {}…, this toolchain {}…", h8(&l), h8(&c)));
        }
    }
    match lock.targets.get(&s.target) {
        None => st.header.push(format!("target {}: not accepted for this target (accepted: {})", s.target, lock.targets.keys().cloned().collect::<Vec<_>>().join(", "))),
        Some(h) if *h != s.target_model => st.header.push(format!("target {}: target-model library locked {}…, this toolchain {}…", s.target, h8(h), h8(&s.target_model))),
        Some(_) => {}
    }
    if lock.tcb != TCB {
        st.header.push("tcb: the TCB statement differs from this toolchain's".into());
    }
    let locked: BTreeMap<&str, &LockEntry> = lock.entries_for(&s.target).map(|e| (e.key.as_str(), e)).collect();
    let changed_keys: BTreeSet<&str> = s.items.iter().filter(|i| locked.get(i.key.as_str()).is_none_or(|e| e.hash != i.hash)).map(|i| i.key.as_str()).collect();
    for i in &s.items {
        match locked.get(i.key.as_str()) {
            None => st.mismatches.push(Mismatch { key: i.key.clone(), what: What::Added, old: vec![], new: i.statement.clone(), span: i.span, via: vec![] }),
            Some(e) if e.hash != i.hash => {
                let via: Vec<String> = i.deps.iter().filter(|d| d.item && changed_keys.contains(d.name.as_str())).map(|d| d.name.clone()).collect();
                st.mismatches.push(Mismatch { key: i.key.clone(), what: What::Changed, old: e.statement.clone(), new: i.statement.clone(), span: i.span, via });
            }
            Some(e) if LockEntry::of(i, &s.target).statement != e.statement => st.mismatches.push(Mismatch { key: i.key.clone(), what: What::Restated, old: e.statement.clone(), new: i.statement.clone(), span: i.span, via: vec![] }),
            Some(_) => {}
        }
    }
    for (k, e) in &locked {
        if s.get(k).is_none() {
            st.mismatches.push(Mismatch { key: k.to_string(), what: What::Removed, old: e.statement.clone(), new: vec![], span: Span::DUMMY, via: vec![] });
        }
    }
    st.mismatches.sort_by(|a, b| a.key.cmp(&b.key));
    if st.header.is_empty() && st.mismatches.is_empty() {
        st.state = LockState::Matches;
        st.root = lock.root;
    } else {
        st.state = LockState::Mismatch;
    }
    st
}

// ---------------------------------------------------------------------------
// acceptance (only `sandblaster spec --accept` calls this, with the permit of
// the crate path)
// ---------------------------------------------------------------------------

/// What `--accept` accepts.
#[derive(Clone, Debug)]
pub enum Selection {
    /// Every item and the toolchain header.
    All,
    /// The named keys (`toolchain` names the header).
    Items(Vec<String>),
}

/// What an accept changed.
#[derive(Clone, Debug, Default)]
pub struct Accepted {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
    pub restated: Vec<String>,
    pub header: bool,
}

impl Accepted {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty() && self.restated.is_empty() && !self.header
    }
}

/// The lock after accepting `sel` of the computed surface `s` (for its
/// target) into `old`. Entries of other targets are kept; an item named
/// but on neither side is an error, and so is a surface with §15.6 errors.
///
/// `permit` is the crate path's proof that every §15 gate but the lock
/// passed for this surface (`driver::gates::build_crate` with
/// `LockUse::Accepting`, its only producer): a lock is never written for a
/// crate that fails a gate.
pub fn accept(permit: &crate::driver::gates::AcceptPermit, old: Option<&Lock>, s: &Surface, sel: &Selection) -> Result<(Lock, Accepted), String> {
    if !s.errors.is_empty() {
        return accept_into(old, s, sel);
    }
    if permit.target() != s.target {
        return Err(format!("the accept permit is for target {}, the surface for target {}", permit.target(), s.target));
    }
    if permit.surface_root() != full_accept(old, s).compute_root() {
        return Err("the accept permit is for another specification surface".into());
    }
    accept_into(old, s, sel)
}

/// What [`accept`] would write, without a permit and without writing
/// anything: for review tools and tests (lock mechanics on crates that do
/// not pass the gates). The only writer of a lock file is `sandblaster spec
/// --accept`, through [`accept`]; and a lock never makes a crate pass —
/// the build compares it with the computed surface and runs every gate.
pub fn preview_accept(old: Option<&Lock>, s: &Surface, sel: &Selection) -> Result<(Lock, Accepted), String> {
    accept_into(old, s, sel)
}

fn accept_into(old: Option<&Lock>, s: &Surface, sel: &Selection) -> Result<(Lock, Accepted), String> {
    if !s.errors.is_empty() {
        return Err(format!("the surface cannot be locked: {}", s.errors.iter().map(|e| e.msg.clone()).collect::<Vec<_>>().join("; ")));
    }
    let t = s.target.clone();
    let mut lock = match old {
        Some(l) => l.clone(),
        None => {
            let mut l = Lock::empty_for(s);
            l.targets.clear();
            l
        }
    };
    let mut acc = Accepted::default();
    let (keys, header): (BTreeSet<String>, bool) = match sel {
        Selection::All => {
            let mut k: BTreeSet<String> = s.items.iter().map(|i| i.key.clone()).collect();
            k.extend(lock.entries_for(&t).map(|e| e.key.clone()));
            (k, true)
        }
        Selection::Items(names) => {
            let mut k = BTreeSet::new();
            let mut header = old.is_none();
            for n in names {
                if n == "toolchain" {
                    header = true;
                    continue;
                }
                if s.get(n).is_none() && !lock.entries_for(&t).any(|e| &e.key == n) {
                    return Err(format!("`{n}` is neither a surface item nor an entry of the lock for target {t} (keys look like `law:crate::laws::name`; `sandblaster spec` lists them)"));
                }
                k.insert(n.clone());
            }
            (k, header)
        }
    };
    if header {
        let before = (lock.kernel, lock.prelude, lock.semantics, lock.builtins, lock.targets.get(&t).copied(), lock.tcb.clone(), lock.format.clone());
        lock.format = FORMAT.into();
        lock.kernel = s.kernel;
        lock.prelude = s.prelude;
        lock.semantics = s.semantics;
        lock.builtins = s.builtins;
        lock.tcb = TCB.iter().map(|x| x.to_string()).collect();
        lock.sections = s.items.iter().filter(|i| i.kind == SurfaceKind::Section).count();
        lock.targets.insert(t.clone(), s.target_model);
        acc.header = before != (lock.kernel, lock.prelude, lock.semantics, lock.builtins, Some(s.target_model), lock.tcb.clone(), lock.format.clone());
    } else if !lock.targets.contains_key(&t) {
        // the first entry accepted for this target records its model library
        lock.targets.insert(t.clone(), s.target_model);
        acc.header = true;
    }
    for k in &keys {
        let old_e: Option<LockEntry> = lock.entries_for(&t).find(|e| &e.key == k).cloned();
        // drop the target from the old entry of this key
        for e in lock.entries.iter_mut().filter(|e| &e.key == k) {
            e.targets.remove(&t);
        }
        lock.entries.retain(|e| !e.targets.is_empty());
        match s.get(k) {
            Some(i) => {
                let new = LockEntry::of(i, &t);
                match &old_e {
                    None => acc.added.push(k.clone()),
                    Some(o) if o.hash != new.hash => acc.changed.push(k.clone()),
                    Some(o) if !o.same_content(&new) => acc.restated.push(k.clone()),
                    Some(_) => {}
                }
                match lock.entries.iter_mut().find(|e| e.same_content(&new)) {
                    Some(e) => {
                        e.targets.insert(t.clone());
                    }
                    None => lock.entries.push(new),
                }
            }
            None => acc.removed.push(k.clone()),
        }
    }
    lock.sort();
    lock.root = lock.compute_root();
    Ok((lock, acc))
}

// ---------------------------------------------------------------------------
// enforcement (the lock gate of the crate path)
// ---------------------------------------------------------------------------

/// Turns a lock status into `error[spec-lock]` diagnostics naming each
/// item (DESIGN.md §15.6, §15.10): a missing, malformed or mismatched lock,
/// a toolchain difference, and every added, removed, changed or restated
/// item with its locked and computed statement (and the classification,
/// when `classes` gives one: `crate::specdiff`). The crate path
/// (`driver::gates`) calls it on every build with `LockUse::Enforce`.
pub fn enforce(st: &LockStatus, classes: &BTreeMap<String, String>, diags: &mut Diagnostics) {
    let accept_note = "only `sandblaster spec --accept` writes SPEC.lock (never the build, never an environment variable): review the change with `sandblaster spec` / `sandblaster spec --diff <rev>`, then accept it";
    match &st.state {
        LockState::Matches => {}
        LockState::NotComputed(why) => diags.push(Diagnostic::error(DiagKind::SpecLock, Span::DUMMY, format!("SPEC.lock: the specification surface could not be computed ({why})"))),
        LockState::SurfaceErrors => {
            for (k, m, note, sp) in &st.errors {
                diags.push(Diagnostic::error(DiagKind::SpecLock, *sp, format!("SPEC.lock: {m}")).note(format!("item `{k}`")).note(note.clone()));
            }
        }
        LockState::Missing => diags.push(
            Diagnostic::error(DiagKind::SpecLock, Span::DUMMY, format!("no SPEC.lock at `{}`: the specification surface ({} item(s)) is not locked", st.file, st.items))
                .note(accept_note)
                .note("`sandblaster spec --accept` writes the lock after you have reviewed the spec sheet (`sandblaster spec`)"),
        ),
        LockState::Malformed(why) => diags.push(Diagnostic::error(DiagKind::SpecLock, Span::DUMMY, format!("SPEC.lock at `{}` is malformed: {why}", st.file)).note(accept_note)),
        LockState::Mismatch => {
            for h in &st.header {
                diags.push(Diagnostic::error(DiagKind::SpecLock, Span::DUMMY, format!("SPEC.lock: the toolchain differs from the locked one: {h}")).note("after a toolchain upgrade, `sandblaster spec --accept --equivalent-only` re-accepts the items whose new statement is kernel-proven equivalent to the locked one").note(accept_note));
            }
            for m in &st.mismatches {
                let class = classes.get(&m.key).map(|c| format!(" ({c})")).unwrap_or_default();
                let mut d = Diagnostic::error(DiagKind::SpecLock, m.span, format!("SPEC.lock: `{}` {}{class}", m.key, m.what.word()));
                if !m.old.is_empty() {
                    d = d.note(format!("locked: {}", m.old.join(" ")));
                }
                if !m.new.is_empty() {
                    d = d.note(format!("now:    {}", m.new.join(" ")));
                }
                if !m.via.is_empty() {
                    d = d.note(format!("its hash covers its dependencies; changed among them: {}", m.via.join(", ")));
                }
                diags.push(d.note(accept_note));
            }
        }
    }
}
