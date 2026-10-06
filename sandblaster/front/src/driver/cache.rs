//! The verdict cache (DESIGN.md §2.1 *Re-runs*, §15.8 *Where the gates
//! run*; North star principle 5, "gates run at agent speed"): a
//! content-addressed store of results the build already computed, shared
//! across target directories and builds, so that a warm clean build (a new
//! `target/`, the same sources) and a one-function edit re-verify in
//! seconds instead of minutes.
//!
//! # What it stores
//!
//! Two namespaces, each keyed by a SHA-256 over **everything the result
//! depends on**; a result is reused only on an exact key match:
//!
//! * `verdict` — a whole crate verdict (the emitted file, the report and
//!   the timing) of `sandblaster::build::compile_module` / `compile`. The key
//!   ([`super::module`]'s verdict key) covers the verifier context
//!   ([`verifier_context`]: the toolchain identity, the toolchain's
//!   overflow checks and test hooks, the build's `rustc -vV`, every
//!   `SANDBLASTER_*` variable that can change a result), the target
//!   (`CARGO_CFG_TARGET_*`), the root, the module file, the host edition,
//!   and the content of every file the front end read (sources, data
//!   files, the lock, the profile). Only verdicts are stored: a failed
//!   build leaves no entry.
//!
//! # The toolchain identity
//!
//! A content hash of the toolchain (the facade's `toolchain_id.rs`,
//! computed by its `build.rs`): the inputs of every sandblaster crate the
//! build script links that can change a verdict (sources, manifests, build
//! scripts, embedded data, the data read at run time, the proof library and
//! every file a source includes by a literal path — not tests, benchmarks,
//! examples, fixtures or documents nothing includes), the lock entries of
//! every third-party crate, and the `rustc`, host and `RUSTFLAGS` that
//! compiled them. It does **not** depend on the
//! host crate, its features, the profile or the target directory, so
//! `cargo build`, `cargo test`, a release build and a dependent crate's
//! build of the same module share one verdict. (It replaced the hash of
//! the build-script binary, which differed in each of those contexts.)
//! What does not enter it, and why that cannot change a stored verdict:
//! the optimization level (the toolchain is deterministic integer code)
//! and `debug_assertions` (the toolchain's `debug_assert!`s are pure and
//! it never branches on `cfg(debug_assertions)` — checked by
//! `tests/build_loop.rs` —, so they can only add a panic, and a failed
//! build stores nothing). Overflow checks can change a result, so they are
//! part of the context.
//! * `mutant` — one spec mutant's verdict of the on-demand spec-mutation
//!   tool (`crate::mutate`, *Review mode*; `sandblaster mutate`; no build
//!   runs it). The key covers the toolchain, the
//!   target, the mutant (item, operator, site, diff), its plan (closure,
//!   known answers, observation points) and a position-independent
//!   fingerprint of every item its re-check can read (the reference
//!   closure of the clones, law checkers and compared functions). So an
//!   edit re-runs exactly the mutants whose statement or code — or the
//!   code of anything they read — changed (*incremental spec mutation*).
//!
//! # Integrity
//!
//! An entry is `sandblaster-cache/1`, its namespace and key, one line per
//! payload file (name, length, SHA-256), an HMAC-SHA-256 over all of it,
//! and the payload. [`Store::get`] recomputes every hash and the MAC:
//! a truncated, edited or forged entry (one written without the secret)
//! is **rejected** and the result recomputed, never used. The secret is
//! `SANDBLASTER_CACHE_KEY` (any string, e.g. a CI secret) or else a random
//! 32-byte key file created on first use (mode 0600) at
//! `SANDBLASTER_CACHE_KEY_FILE`, `$XDG_CONFIG_HOME/sandblaster/cache.key` or
//! `~/.config/sandblaster/cache.key` — outside the cache directory, so a
//! cache directory copied from elsewhere (a shared or restored CI cache)
//! cannot vouch for itself. Trust: whoever can write the key file and the
//! cache can make an unverified module look verified — the same trust as
//! `OUT_DIR` (which holds the emitted file itself) and the toolchain
//! binary. The cache never turns a failure into a pass: it only replays a
//! verdict the same toolchain computed for byte-identical inputs.
//!
//! # Location and limits
//!
//! `SANDBLASTER_CACHE_DIR`, else `$XDG_CACHE_HOME/sandblaster`, else
//! `~/.cache/sandblaster`. `SANDBLASTER_CACHE=off` disables it (a speed
//! setting: it never changes a verdict). Writes are atomic (a temporary
//! file renamed into place), so concurrent builds are safe. Each namespace
//! is capped at `SANDBLASTER_CACHE_MAX_MB` (default 2048): after a write the
//! least recently used entries are removed. None of these variables is
//! part of a key. An unusable location (no home directory, a read-only
//! file system) disables the cache with a warning; it never fails a build.

use std::path::{Path, PathBuf};

use crate::surface::{hex, sha256, Hash};

/// The entry format.
pub const FORMAT: &str = "sandblaster-cache/1";

/// The result of a lookup.
#[derive(Debug, PartialEq, Eq)]
pub enum Lookup {
    /// The payload files, by name, in the order they were stored.
    Hit(Vec<(String, String)>),
    Miss,
    /// An entry exists but failed its integrity check (the reason): it is
    /// ignored and the result recomputed (and the entry overwritten).
    Rejected(String),
}

/// A cache directory and its secret.
#[derive(Clone, Debug)]
pub struct Store {
    dir: PathBuf,
    secret: Hash,
    max_bytes: u64,
}

/// HMAC-SHA-256 (RFC 2104) over the concatenation of `parts`.
pub fn hmac(secret: &Hash, parts: &[&[u8]]) -> Hash {
    let mut k = [0u8; 64];
    k[..32].copy_from_slice(secret);
    let mut inner = Vec::with_capacity(64 + parts.iter().map(|p| p.len()).sum::<usize>());
    inner.extend(k.iter().map(|b| b ^ 0x36));
    for p in parts {
        inner.extend_from_slice(p);
    }
    let ih = sha256(&inner);
    let mut outer = Vec::with_capacity(96);
    outer.extend(k.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&ih);
    sha256(&outer)
}

fn is_key(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn is_name(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

impl Store {
    /// A store at `dir` with the secret `secret` (tests; [`Store::from_env`]
    /// for builds).
    pub fn open(dir: PathBuf, secret: Hash) -> Store {
        Store { dir, secret, max_bytes: 2048 << 20 }
    }

    /// The store the environment selects (module docs): `Ok(None)` when
    /// `SANDBLASTER_CACHE=off`, `Err` (a warning) when no usable location or
    /// secret exists.
    pub fn from_env(env: &dyn Fn(&str) -> Option<String>) -> Result<Option<Store>, String> {
        if env("SANDBLASTER_CACHE").is_some_and(|v| matches!(v.trim(), "off" | "0" | "false" | "no")) {
            return Ok(None);
        }
        let home = env("HOME").filter(|h| !h.is_empty()).map(PathBuf::from);
        let dir = match (env("SANDBLASTER_CACHE_DIR"), env("XDG_CACHE_HOME"), &home) {
            (Some(d), _, _) if !d.is_empty() => PathBuf::from(d),
            (_, Some(x), _) if !x.is_empty() => PathBuf::from(x).join("sandblaster"),
            (_, _, Some(h)) => h.join(".cache").join("sandblaster"),
            _ => return Err("no cache directory (set SANDBLASTER_CACHE_DIR or HOME)".into()),
        };
        let secret = match env("SANDBLASTER_CACHE_KEY").filter(|k| !k.is_empty()) {
            Some(k) => sha256(format!("sandblaster-cache-key/1\n{k}").as_bytes()),
            None => {
                let file = match (env("SANDBLASTER_CACHE_KEY_FILE"), env("XDG_CONFIG_HOME"), &home) {
                    (Some(f), _, _) if !f.is_empty() => PathBuf::from(f),
                    (_, Some(x), _) if !x.is_empty() => PathBuf::from(x).join("sandblaster").join("cache.key"),
                    (_, _, Some(h)) => h.join(".config").join("sandblaster").join("cache.key"),
                    _ => return Err("no cache key (set SANDBLASTER_CACHE_KEY or HOME)".into()),
                };
                key_file(&file)?
            }
        };
        let mut s = Store::open(dir, secret);
        if let Some(mb) = env("SANDBLASTER_CACHE_MAX_MB").and_then(|v| v.trim().parse::<u64>().ok()) {
            s.max_bytes = mb.saturating_mul(1 << 20);
        }
        std::fs::create_dir_all(s.dir.join(FORMAT.replace('/', "-"))).map_err(|e| format!("cannot create the cache directory `{}`: {e}", s.dir.display()))?;
        Ok(Some(s))
    }

    /// The cache directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, ns: &str, key: &str) -> PathBuf {
        self.dir.join(FORMAT.replace('/', "-")).join(ns).join(&key[..2]).join(key)
    }

    fn header(ns: &str, key: &str, files: &[(&str, &str)]) -> String {
        let mut h = format!("{FORMAT}\nns {ns}\nkey {key}\n");
        for (name, text) in files {
            h.push_str(&format!("file {name} {} {}\n", text.len(), hex(&sha256(text.as_bytes()))));
        }
        h
    }

    /// Looks `key` up in namespace `ns` (see [`Lookup`]).
    pub fn get(&self, ns: &str, key: &str) -> Lookup {
        if !is_name(ns) || !is_key(key) {
            return Lookup::Rejected(format!("malformed cache address `{ns}/{key}`"));
        }
        let p = self.path(ns, key);
        let bytes = match std::fs::read(&p) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Lookup::Miss,
            Err(e) => return Lookup::Rejected(format!("cannot read `{}`: {e}", p.display())),
        };
        match self.parse(ns, key, &bytes) {
            Ok(files) => {
                // least recently used: a hit refreshes the entry's time
                if let Ok(f) = std::fs::File::options().append(true).open(&p) {
                    let _ = f.set_modified(std::time::SystemTime::now());
                }
                Lookup::Hit(files)
            }
            Err(why) => Lookup::Rejected(why),
        }
    }

    fn parse(&self, ns: &str, key: &str, bytes: &[u8]) -> Result<Vec<(String, String)>, String> {
        let split = bytes.windows(2).position(|w| w == b"\n\n").ok_or("no header")?;
        let head = std::str::from_utf8(&bytes[..split + 1]).map_err(|_| "the header is not UTF-8")?;
        let body = &bytes[split + 2..];
        let mut lines = head.lines();
        if lines.next() != Some(FORMAT) {
            return Err("not a sandblaster-cache/1 entry".into());
        }
        if lines.next() != Some(&format!("ns {ns}")) || lines.next() != Some(&format!("key {key}")) {
            return Err("the entry is filed under another address".into());
        }
        let mut specs: Vec<(String, usize, String)> = Vec::new();
        let mut mac = None;
        for l in lines {
            let w: Vec<&str> = l.split(' ').collect();
            match w.as_slice() {
                ["file", name, len, h] if mac.is_none() => specs.push((name.to_string(), len.parse().map_err(|_| "a bad length")?, h.to_string())),
                ["mac", m] if mac.is_none() => mac = Some(m.to_string()),
                _ => return Err(format!("unexpected header line `{l}`")),
            }
        }
        let mac = mac.ok_or("no MAC")?;
        let signed_len = head.find("\nmac ").map(|i| i + 1).ok_or("no MAC line")?;
        let expect = hmac(&self.secret, &[&bytes[..signed_len], body]);
        if hex(&expect) != mac {
            return Err("the MAC does not match (edited, truncated, or written without this cache's key)".into());
        }
        let mut files = Vec::new();
        let mut at = 0usize;
        for (name, len, h) in specs {
            let end = at.checked_add(len).filter(|e| *e <= body.len()).ok_or("the payload is shorter than its header says")?;
            let chunk = &body[at..end];
            if hex(&sha256(chunk)) != h {
                return Err(format!("the payload `{name}` does not match its hash"));
            }
            files.push((name, String::from_utf8(chunk.to_vec()).map_err(|_| "a payload is not UTF-8")?));
            at = end;
        }
        if at != body.len() {
            return Err("the payload is longer than its header says".into());
        }
        Ok(files)
    }

    /// Stores `files` under `key` in namespace `ns` (atomically), then
    /// trims the namespace to the size cap.
    pub fn put(&self, ns: &str, key: &str, files: &[(&str, &str)]) -> Result<(), String> {
        self.write_entry(ns, key, files)?;
        self.trim(ns);
        Ok(())
    }

    /// Stores several entries of `ns`, then trims it once. Returns the
    /// first error (the other entries are still written).
    pub fn put_many(&self, ns: &str, entries: &[(String, Vec<(String, String)>)]) -> Result<(), String> {
        let mut first = Ok(());
        for (key, files) in entries {
            let fs: Vec<(&str, &str)> = files.iter().map(|(n, t)| (n.as_str(), t.as_str())).collect();
            if let Err(e) = self.write_entry(ns, key, &fs)
                && first.is_ok()
            {
                first = Err(e);
            }
        }
        self.trim(ns);
        first
    }

    fn write_entry(&self, ns: &str, key: &str, files: &[(&str, &str)]) -> Result<(), String> {
        if !is_name(ns) || !is_key(key) || files.iter().any(|(n, _)| !is_name(n)) {
            return Err(format!("malformed cache address `{ns}/{key}`"));
        }
        let head = Self::header(ns, key, files);
        let body: Vec<u8> = files.iter().flat_map(|(_, t)| t.as_bytes().iter().copied()).collect();
        let mac = hmac(&self.secret, &[head.as_bytes(), &body]);
        let mut out = head.into_bytes();
        out.extend_from_slice(format!("mac {}\n\n", hex(&mac)).as_bytes());
        out.extend_from_slice(&body);
        let p = self.path(ns, key);
        let dir = p.parent().ok_or("no parent directory")?;
        std::fs::create_dir_all(dir).map_err(|e| format!("cannot create `{}`: {e}", dir.display()))?;
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let tmp = dir.join(format!(".{key}.{}.{nanos}.tmp", std::process::id()));
        std::fs::write(&tmp, &out).map_err(|e| format!("cannot write `{}`: {e}", tmp.display()))?;
        std::fs::rename(&tmp, &p).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("cannot move the entry into `{}`: {e}", p.display())
        })?;
        Ok(())
    }

    /// Removes the least recently used entries of `ns` until it is under
    /// the cap.
    fn trim(&self, ns: &str) {
        let root = self.dir.join(FORMAT.replace('/', "-")).join(ns);
        let mut entries: Vec<(std::time::SystemTime, u64, PathBuf)> = Vec::new();
        let Ok(subs) = std::fs::read_dir(&root) else { return };
        for sub in subs.flatten() {
            let Ok(files) = std::fs::read_dir(sub.path()) else { continue };
            for f in files.flatten() {
                if let Ok(m) = f.metadata()
                    && m.is_file()
                {
                    entries.push((m.modified().unwrap_or(std::time::UNIX_EPOCH), m.len(), f.path()));
                }
            }
        }
        let mut total: u64 = entries.iter().map(|e| e.1).sum();
        if total <= self.max_bytes {
            return;
        }
        entries.sort();
        for (_, len, p) in entries {
            if total <= self.max_bytes {
                break;
            }
            if std::fs::remove_file(&p).is_ok() {
                total = total.saturating_sub(len);
            }
        }
    }
}

/// Reads the secret key file, creating it (32 random bytes, mode 0600)
/// when it does not exist.
fn key_file(file: &Path) -> Result<Hash, String> {
    match std::fs::read(file) {
        Ok(b) if b.len() >= 32 => return Ok(sha256(&b)),
        Ok(_) => return Err(format!("the cache key file `{}` is too short (want 32 bytes or more)", file.display())),
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(format!("cannot read the cache key file `{}`: {e}", file.display())),
        Err(_) => {}
    }
    let mut key = [0u8; 32];
    {
        use std::io::Read as _;
        let mut r = std::fs::File::open("/dev/urandom").map_err(|e| format!("no randomness for a cache key (/dev/urandom: {e})"))?;
        r.read_exact(&mut key).map_err(|e| format!("no randomness for a cache key: {e}"))?;
    }
    if let Some(d) = file.parent() {
        std::fs::create_dir_all(d).map_err(|e| format!("cannot create `{}`: {e}", d.display()))?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    match opts.open(file) {
        Ok(mut f) => {
            use std::io::Write as _;
            f.write_all(&key).map_err(|e| format!("cannot write the cache key file `{}`: {e}", file.display()))?;
            Ok(sha256(&key))
        }
        // another build created it first: use theirs
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => key_file(file),
        Err(e) => Err(format!("cannot create the cache key file `{}`: {e}", file.display())),
    }
}

/// A store plus the toolchain identity every key starts with (the hash of
/// the facade's verifier context, [`verifier_context`]).
#[derive(Clone, Debug)]
pub struct VerdictCache {
    pub store: Store,
    /// SHA-256 (hex) of the toolchain identity.
    pub toolchain: String,
}

impl VerdictCache {
    pub fn new(store: Store, context: &str) -> VerdictCache {
        VerdictCache { store, toolchain: hex(&sha256(context.as_bytes())) }
    }
}

/// Resource and cache settings: they never change a result, so they are
/// not part of the verifier context (a build with another memory limit,
/// worker count or cache directory reuses the same verdicts).
pub const NOT_IDENTITY: &[&str] = &["SANDBLASTER_MEM_LIMIT_GB", "SANDBLASTER_GATE_WORKERS", "SANDBLASTER_CACHE", "SANDBLASTER_CACHE_DIR", "SANDBLASTER_CACHE_KEY", "SANDBLASTER_CACHE_KEY_FILE", "SANDBLASTER_CACHE_MAX_MB"];

/// The context format (part of every verdict, mutant and conformance key).
pub const CONTEXT_FORMAT: &str = "sandblaster-verifier/2";

/// Whether this build of the front end has overflow checks (a probe: an
/// overflowing addition panics or wraps). An unchecked toolchain could
/// wrap where a checked one fails, so the setting is part of the context.
pub fn overflow_checks() -> bool {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let wrapped = std::panic::catch_unwind(|| std::hint::black_box(255u8) + std::hint::black_box(1u8));
    std::panic::set_hook(prev);
    wrapped.is_err()
}

/// The verifier context: what, besides the verified inputs, determines a
/// result (module docs, *The toolchain identity*). `toolchain_id` is the
/// facade's content hash of the toolchain (empty when it could not be
/// computed: `None`, nothing is reused); `rustc_vv` the `rustc -vV` of the
/// build's `RUSTC` (the lift conformance check compiles the source with
/// it); `vars` the process environment, of which every `SANDBLASTER_*`
/// variable but the [`NOT_IDENTITY`] ones enters (sorted). Nothing here
/// depends on the build-script binary, the host crate's features, the
/// profile or the target directory.
pub fn verifier_context(toolchain_id: &str, rustc_vv: Option<&str>, vars: &[(String, String)]) -> Option<String> {
    let id = toolchain_id.trim();
    if id.is_empty() {
        return None;
    }
    let mut ctx = format!("{CONTEXT_FORMAT}\ntoolchain {id}\n");
    ctx.push_str(&format!("overflow-checks {}\n", if overflow_checks() { "on" } else { "off" }));
    ctx.push_str(&format!("rustc {}\n", rustc_vv.map(|v| hex(&sha256(v.as_bytes()))).unwrap_or_else(|| "unavailable".into())));
    let mut vs: Vec<&(String, String)> = vars.iter().filter(|(k, _)| k.starts_with("SANDBLASTER_") && !NOT_IDENTITY.contains(&k.as_str())).collect();
    vs.sort();
    vs.dedup();
    for (k, v) in vs {
        ctx.push_str(&format!("{k}={v}\n"));
    }
    Some(ctx)
}
