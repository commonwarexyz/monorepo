//! The hints-only proof cache (plan O5; optimizer design §8): the equality
//! lemmas' proof terms of a previous build, under
//! `target/sandblaster/opt-cache/` (never checked in).
//!
//! An entry is a *hint*, never trusted: a hit is committed with `add_def`
//! like a freshly built proof, so the kernel re-checks every one, and a
//! forged or corrupted entry is rejected (must-reject R25). What the cache
//! saves is the proof builder's work (walking the process tree, the
//! decisions' replays, `auto` at the leaves), not the check.
//!
//! * The key is the lemma's name and statement (the residual and source
//!   applications, by global name), the hashes of those globals, and the
//!   cache format's version.
//! * An entry records every global its proof term mentions with a hash of
//!   that global's current type and body and, recursively, of everything
//!   they mention: when one of them changed (a callee's residual, a lemma
//!   library update), the entry is stale and is ignored (a miss, rebuilt
//!   and overwritten). A hit whose proof the kernel rejects is therefore a
//!   forged or corrupt entry: it is removed ([`Cache::reject`]) and the
//!   proof is built as on a miss (then stored afresh), and the optimizer
//!   reports the rejection ([`Cache::take_rejected`]; a warning, a build
//!   error under strict options).
//! * Terms are stored as a DAG in post-order (shared subterms once),
//!   globals and inductives by name, so an entry does not depend on the
//!   numbering of the environment.
//!
//! The cache never changes what is emitted: the residuals come from the
//! driver in every build; only their lemmas' proofs are reused, and a
//! rejected hit costs the rebuild, never the candidate (design §17: a miss
//! recomputes the identical result).
//!
//! Nor does it change what is reported or what a budget allows. An entry
//! records the metered steps its proof took to build and to check in the
//! build that stored it (its [`Cost`], [`Cache::store_lemma`]); a loop
//! summary's chain charges that cost on a hit, in place of the steps the
//! hit itself took (`loopsum::meter`), so its step budget and the report's
//! `budgets_used.loopsum_steps` are the same in a cold and a warm build.
//! (The kernel check of a decoded proof may take a few steps more or less
//! than that of the freshly built one: its memo tables were filled by
//! different work.) The driven lemmas' proofs are not metered: their
//! entries record a zero cost.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{Arm, AxiomId, BigInt, GlobalId, Idx, IndId, PrimOp, Rat, Rel, Sort, Term, Tm, Width};

/// Bumped whenever the entry format or the proofs' shape changes.
const VERSION: &str = "sandblaster-opt-cache 2";
const MAGIC: &[u8; 8] = b"ROPTC2\0\0";

/// The metered steps of a cached proof in the build that stored it: its
/// construction and its kernel check.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cost {
    pub build: u64,
    pub check: u64,
}

/// The cache of one optimizer run.
pub struct Cache {
    dir: PathBuf,
    /// Hashes of globals' current type and body, by global.
    hashes: RefCell<HashMap<GlobalId, u64>>,
    /// Hits, misses, stale entries, stores, rejected hits (the timing trace).
    pub stats: RefCell<CacheStats>,
    /// The hits the kernel rejected since the last [`Cache::take_rejected`].
    rejected: RefCell<Vec<Rejected>>,
    /// The hash of the choice inputs (plan O8: the tuning evidence and
    /// `PROFILE.json`, design §17 "the key is … the hashes of the tuning
    /// evidence and PROFILE.json"), part of every key.
    inputs: u64,
    /// The entries' file writes, done by a background thread (started on
    /// the first store) so the optimizer does not wait for the file system;
    /// joined when the cache is dropped, so every entry is on disk when the
    /// optimizer returns.
    writer: RefCell<Option<Writes>>,
    /// Set when the writer thread could not be started: the entries are
    /// then written in place, by the optimizer's thread.
    sync_writes: Cell<bool>,
}

/// The background writer of [`Cache`]: `(temporary path, entry path, bytes)`
/// per entry, written aside then renamed (a concurrent build reads a whole
/// entry or none).
struct Writes {
    tx: std::sync::mpsc::Sender<(PathBuf, PathBuf, Vec<u8>)>,
    thread: std::thread::JoinHandle<()>,
}

impl Writes {
    /// The writer, or `None` when the system refuses a thread.
    fn start(dir: PathBuf) -> Option<Writes> {
        let (tx, rx) = std::sync::mpsc::channel::<(PathBuf, PathBuf, Vec<u8>)>();
        let thread = std::thread::Builder::new()
            .name("sandblaster-cache".into())
            .spawn(move || {
                let mut dir_ok = false;
                for (tmp, path, bytes) in rx {
                    if !dir_ok {
                        dir_ok = std::fs::create_dir_all(&dir).is_ok();
                        if !dir_ok {
                            continue;
                        }
                    }
                    write_entry(&tmp, &path, &bytes);
                }
            })
            .ok()?;
        Some(Writes { tx, thread })
    }
}

/// Writes one entry aside, then renames it into place; `false` if either
/// step failed (the temporary file is then removed).
fn write_entry(tmp: &Path, path: &Path, bytes: &[u8]) -> bool {
    if std::fs::write(tmp, bytes).is_err() || std::fs::rename(tmp, path).is_err() {
        let _ = std::fs::remove_file(tmp);
        return false;
    }
    true
}

impl Drop for Cache {
    fn drop(&mut self) {
        if let Some(w) = self.writer.get_mut().take() {
            drop(w.tx);
            let _ = w.thread.join();
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CacheStats {
    pub hits: usize,
    pub misses: usize,
    pub stale: usize,
    pub stores: usize,
    /// Hits whose proof the kernel rejected (forged or corrupt entries).
    pub rejected: usize,
}

/// A hit the kernel rejected (must-reject R25): the lemma it was offered
/// for and the kernel's error.
#[derive(Clone, Debug)]
pub struct Rejected {
    pub lemma: String,
    /// The kernel error's kind (`TypeMismatch`, …), or `add_def` when the
    /// message names none.
    pub kind: String,
    pub error: String,
}

impl Cache {
    pub fn new(dir: &Path) -> Cache {
        Cache { dir: dir.to_path_buf(), hashes: RefCell::new(HashMap::new()), stats: RefCell::new(CacheStats::default()), rejected: RefCell::new(Vec::new()), inputs: 0, writer: RefCell::new(None), sync_writes: Cell::new(false) }
    }

    /// The same cache keyed also by the choice inputs' hash (see
    /// [`Cache::inputs`](Self)).
    pub fn with_inputs(mut self, inputs: u64) -> Cache {
        self.inputs = inputs;
        self
    }

    /// Records that the kernel rejected the hit under `key` (offered for
    /// `lemma`, refused with `error`) and removes the entry: the caller
    /// then builds the proof as on a miss and stores it afresh, so neither
    /// this build nor a later one emits anything a cold build would not.
    pub fn reject(&self, key: &str, lemma: &str, error: &str) {
        let _ = std::fs::remove_file(self.path(key));
        self.stats.borrow_mut().rejected += 1;
        let kind = error.split(':').next().filter(|k| !k.is_empty() && k.chars().all(|c| c.is_ascii_alphabetic())).unwrap_or("add_def").to_string();
        if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
            eprintln!("opt: cache entry {key} for {lemma} rejected by the kernel ({kind}); removed");
        }
        self.rejected.borrow_mut().push(Rejected { lemma: lemma.to_string(), kind, error: error.chars().take(300).collect() });
    }

    /// The hits rejected since the previous call (see [`Cache::reject`]),
    /// for the optimizer to report.
    pub fn take_rejected(&self) -> Vec<Rejected> {
        std::mem::take(&mut *self.rejected.borrow_mut())
    }

    /// The default location: `$SANDBLASTER_OPT_CACHE`, else
    /// `<target dir>/sandblaster/opt-cache` (`$CARGO_TARGET_DIR`, or the
    /// `target` directory above a build script's `OUT_DIR`); `None`
    /// outside a cargo build.
    pub fn default_dir() -> Option<PathBuf> {
        if let Some(d) = std::env::var_os("SANDBLASTER_OPT_CACHE") {
            return Some(PathBuf::from(d));
        }
        if let Some(t) = std::env::var_os("CARGO_TARGET_DIR") {
            return Some(PathBuf::from(t).join("sandblaster").join("opt-cache"));
        }
        // OUT_DIR = <target>/<profile>/build/<pkg>-<hash>/out
        let out = PathBuf::from(std::env::var_os("OUT_DIR")?);
        let build = out.ancestors().find(|a| a.file_name().is_some_and(|n| n == "build"))?;
        let target = build.parent()?.parent()?;
        Some(target.join("sandblaster").join("opt-cache"))
    }

    /// The key of the lemma `name : statement`: with the (Merkle) hashes of
    /// the globals the statement names (the residual and its source), so
    /// two crates with the same names (QMDB's N = 1 and N = 32 builds)
    /// keep their own entries.
    pub fn key(&self, env: &Env, name: &str, statement: &Tm) -> String {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        VERSION.hash(&mut h);
        self.inputs.hash(&mut h);
        name.hash(&mut h);
        encode(env, statement).hash(&mut h);
        let mut named: Vec<GlobalId> = Vec::new();
        crate::elab::tm::any_node(statement, &mut |n| {
            if let Term::Global(g) = n
                && !named.contains(g)
            {
                named.push(*g);
            }
            false
        });
        named.sort();
        for g in named {
            self.global_hash(env, g).hash(&mut h);
        }
        let k = format!("{:016x}", h.finish());
        if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
            eprintln!("opt: cache key {k} for {name}: {}", env.print_term(&[], statement).chars().take(300).collect::<String>());
        }
        k
    }

    fn path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.proof"))
    }

    /// The cached proof under `key`, if present and not stale.
    pub fn load(&self, env: &Env, key: &str) -> Option<Tm> {
        self.load_costed(env, key).map(|(t, _)| t)
    }

    /// [`Cache::load`] with the entry's [`Cost`] ([`Cache::store_lemma`];
    /// zero when not metered).
    pub fn load_costed(&self, env: &Env, key: &str) -> Option<(Tm, Cost)> {
        let Ok(bytes) = std::fs::read(self.path(key)) else {
            self.stats.borrow_mut().misses += 1;
            return None;
        };
        let r = (|| {
            let mut rd = Reader { b: &bytes, i: 0 };
            if rd.take(8)? != MAGIC {
                return None;
            }
            let cost = Cost { build: rd.u64()?, check: rd.u64()? };
            let ndeps = rd.u32()? as usize;
            for _ in 0..ndeps {
                let name = rd.str()?;
                let h = rd.u64()?;
                let g = env.lookup_global(&name)?;
                if self.global_hash(env, g) != h {
                    if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
                        eprintln!("opt: cache entry {key} stale: `{name}` changed");
                    }
                    return Some(None);
                }
            }
            Some(decode(env, &mut rd).map(|t| (t, cost)))
        })();
        match r {
            Some(Some(t)) => {
                self.stats.borrow_mut().hits += 1;
                Some(t)
            }
            Some(None) => {
                self.stats.borrow_mut().stale += 1;
                None
            }
            None => {
                self.stats.borrow_mut().misses += 1;
                None
            }
        }
    }

    /// Stores `proof` under `key` (best effort: an I/O error loses only
    /// the hint).
    /// [`Cache::store`] of the body of the committed lemma `g` (the term
    /// `proof` is its body): its content hash ([`Cache::global_hash`], which
    /// the next lemma of a chain needs, as it names `g`) is computed from
    /// the same encoding instead of a second one. `cost`: the metered steps
    /// the proof took to build and check, charged again on a hit
    /// ([`Cache::load_costed`]).
    pub fn store_lemma(&self, env: &Env, key: &str, proof: &Tm, g: GlobalId, cost: Cost) {
        let body_bytes = encode(env, proof);
        if !self.hashes.borrow().contains_key(&g)
            && env.global_body(g).is_some_and(|b| Rc::ptr_eq(&b, proof))
            && let Some(ty) = env.global_type(g)
        {
            // exactly `global_hash`'s computation, with the body's bytes reused
            self.hashes.borrow_mut().insert(g, 0);
            let mut h = std::collections::hash_map::DefaultHasher::new();
            let mut refs: Vec<GlobalId> = Vec::new();
            for (t, bytes) in [(&ty, None), (proof, Some(&body_bytes))] {
                match bytes {
                    Some(b) => b.hash(&mut h),
                    None => encode(env, t).hash(&mut h),
                }
                crate::elab::tm::any_node(t, &mut |n| {
                    if let Term::Global(r) | Term::Delta { def: r, .. } | Term::Unfold { def: r, .. } = n
                        && *r != g
                        && !refs.contains(r)
                    {
                        refs.push(*r);
                    }
                    false
                });
            }
            for r in refs {
                self.global_hash(env, r).hash(&mut h);
            }
            self.hashes.borrow_mut().insert(g, h.finish());
        }
        self.store_encoded(env, key, proof, Some(body_bytes), cost);
    }

    pub fn store(&self, env: &Env, key: &str, proof: &Tm) {
        self.store_encoded(env, key, proof, None, Cost::default());
    }

    fn store_encoded(&self, env: &Env, key: &str, proof: &Tm, body_bytes: Option<Vec<u8>>, cost: Cost) {
        let mut deps: Vec<GlobalId> = Vec::new();
        crate::elab::tm::any_node(proof, &mut |n| {
            if let Term::Global(g) | Term::Delta { def: g, .. } | Term::Unfold { def: g, .. } = n
                && !deps.contains(g)
            {
                deps.push(*g);
            }
            false
        });
        deps.sort();
        let mut w = Writer::default();
        w.b.extend_from_slice(MAGIC);
        w.u64(cost.build);
        w.u64(cost.check);
        w.u32(deps.len() as u32);
        for g in &deps {
            let Some(name) = env.global_name(*g) else { return };
            w.str(&name);
            w.u64(self.global_hash(env, *g));
        }
        match body_bytes {
            Some(b) => w.b.extend_from_slice(&b),
            None => encode_into(env, proof, &mut w),
        }
        // written aside, then renamed, by the background writer
        let tmp = self.dir.join(format!("{key}.{}.tmp", std::process::id()));
        let mut writer = self.writer.borrow_mut();
        if writer.is_none() && !self.sync_writes.get() {
            *writer = Writes::start(self.dir.clone());
            self.sync_writes.set(writer.is_none());
        }
        let stored = match writer.as_ref() {
            Some(w2) => w2.tx.send((tmp, self.path(key), w.b)).is_ok(),
            None => std::fs::create_dir_all(&self.dir).is_ok() && write_entry(&tmp, &self.path(key), &w.b),
        };
        if stored {
            self.stats.borrow_mut().stores += 1;
        }
    }

    /// A hash of `g`'s type and body and, recursively, of the globals they
    /// mention (a Merkle hash: a change anywhere below a proof's direct
    /// dependencies, e.g. in a callee conversion unfolds, changes it).
    fn global_hash(&self, env: &Env, g: GlobalId) -> u64 {
        if let Some(h) = self.hashes.borrow().get(&g) {
            return *h;
        }
        // a recursion's reference to itself (its stored body names it)
        self.hashes.borrow_mut().insert(g, 0);
        let mut h = std::collections::hash_map::DefaultHasher::new();
        let mut refs: Vec<GlobalId> = Vec::new();
        for t in [env.global_type(g), env.global_body(g)].into_iter().flatten() {
            encode(env, &t).hash(&mut h);
            crate::elab::tm::any_node(&t, &mut |n| {
                if let Term::Global(r) | Term::Delta { def: r, .. } | Term::Unfold { def: r, .. } = n
                    && *r != g
                    && !refs.contains(r)
                {
                    refs.push(*r);
                }
                false
            });
        }
        for r in refs {
            self.global_hash(env, r).hash(&mut h);
        }
        let v = h.finish();
        self.hashes.borrow_mut().insert(g, v);
        v
    }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Writer {
    b: Vec<u8>,
}

impl Writer {
    fn u8(&mut self, x: u8) {
        self.b.push(x);
    }
    fn u32(&mut self, x: u32) {
        self.b.extend_from_slice(&x.to_le_bytes());
    }
    fn u64(&mut self, x: u64) {
        self.b.extend_from_slice(&x.to_le_bytes());
    }
    fn str(&mut self, s: &str) {
        self.u32(s.len() as u32);
        self.b.extend_from_slice(s.as_bytes());
    }
    fn int(&mut self, n: &BigInt) {
        let bytes = n.to_signed_bytes_le();
        self.u32(bytes.len() as u32);
        self.b.extend_from_slice(&bytes);
    }
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let s = self.b.get(self.i..self.i + n)?;
        self.i += n;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn str(&mut self) -> Option<String> {
        let n = self.u32()? as usize;
        String::from_utf8(self.take(n)?.to_vec()).ok()
    }
    fn int(&mut self) -> Option<BigInt> {
        let n = self.u32()? as usize;
        Some(BigInt::from_signed_bytes_le(self.take(n)?))
    }
}

fn encode(env: &Env, t: &Tm) -> Vec<u8> {
    let mut w = Writer::default();
    encode_into(env, t, &mut w);
    w.b
}

fn width_code(w: Width) -> u8 {
    match w {
        Width::U8 => 0,
        Width::U16 => 1,
        Width::U32 => 2,
        Width::U64 => 3,
        Width::Usize => 4,
        Width::Int => 5,
    }
}

fn width_of(c: u8) -> Option<Width> {
    Some(match c {
        0 => Width::U8,
        1 => Width::U16,
        2 => Width::U32,
        3 => Width::U64,
        4 => Width::Usize,
        5 => Width::Int,
        _ => return None,
    })
}

fn rel_code(r: Rel) -> u8 {
    match r {
        Rel::Rel => 0,
        Rel::Irr => 1,
    }
}

fn rel_of(c: u8) -> Option<Rel> {
    match c {
        0 => Some(Rel::Rel),
        1 => Some(Rel::Irr),
        _ => None,
    }
}

/// `(code, width, second width)` of a primitive.
fn prim_code(op: PrimOp) -> (u8, u8, u8) {
    use PrimOp::*;
    let w = width_code;
    match op {
        WAdd(x) => (0, w(x), 0),
        WSub(x) => (1, w(x), 0),
        WMul(x) => (2, w(x), 0),
        WNeg(x) => (3, w(x), 0),
        And(x) => (4, w(x), 0),
        Or(x) => (5, w(x), 0),
        Xor(x) => (6, w(x), 0),
        Not(x) => (7, w(x), 0),
        WShl(x) => (8, w(x), 0),
        WShr(x) => (9, w(x), 0),
        Rotl(x) => (10, w(x), 0),
        Rotr(x) => (11, w(x), 0),
        Min(x) => (12, w(x), 0),
        Max(x) => (13, w(x), 0),
        SatAdd(x) => (14, w(x), 0),
        SatSub(x) => (15, w(x), 0),
        SatMul(x) => (16, w(x), 0),
        CountOnes(x) => (17, w(x), 0),
        LeadingZeros(x) => (18, w(x), 0),
        TrailingZeros(x) => (19, w(x), 0),
        SwapBytes(x) => (20, w(x), 0),
        Eq(x) => (21, w(x), 0),
        Ne(x) => (22, w(x), 0),
        Lt(x) => (23, w(x), 0),
        Le(x) => (24, w(x), 0),
        Gt(x) => (25, w(x), 0),
        Ge(x) => (26, w(x), 0),
        Cast { from, to } => (27, w(from), w(to)),
        IntToSat(x) => (28, w(x), 0),
        IAdd => (29, 0, 0),
        ISub => (30, 0, 0),
        IMul => (31, 0, 0),
        INeg => (32, 0, 0),
        IDiv => (33, 0, 0),
        IMod => (34, 0, 0),
        Add(x) => (35, w(x), 0),
        Sub(x) => (36, w(x), 0),
        Mul(x) => (37, w(x), 0),
        Div(x) => (38, w(x), 0),
        Rem(x) => (39, w(x), 0),
        Shl(x) => (40, w(x), 0),
        Shr(x) => (41, w(x), 0),
        OfInt(x) => (42, w(x), 0),
    }
}

fn prim_of(c: u8, a: u8, b: u8) -> Option<PrimOp> {
    use PrimOp::*;
    let x = width_of(a);
    Some(match c {
        0 => WAdd(x?),
        1 => WSub(x?),
        2 => WMul(x?),
        3 => WNeg(x?),
        4 => And(x?),
        5 => Or(x?),
        6 => Xor(x?),
        7 => Not(x?),
        8 => WShl(x?),
        9 => WShr(x?),
        10 => Rotl(x?),
        11 => Rotr(x?),
        12 => Min(x?),
        13 => Max(x?),
        14 => SatAdd(x?),
        15 => SatSub(x?),
        16 => SatMul(x?),
        17 => CountOnes(x?),
        18 => LeadingZeros(x?),
        19 => TrailingZeros(x?),
        20 => SwapBytes(x?),
        21 => Eq(x?),
        22 => Ne(x?),
        23 => Lt(x?),
        24 => Le(x?),
        25 => Gt(x?),
        26 => Ge(x?),
        27 => Cast { from: x?, to: width_of(b)? },
        28 => IntToSat(x?),
        29 => IAdd,
        30 => ISub,
        31 => IMul,
        32 => INeg,
        33 => IDiv,
        34 => IMod,
        35 => Add(x?),
        36 => Sub(x?),
        37 => Mul(x?),
        38 => Div(x?),
        39 => Rem(x?),
        40 => Shl(x?),
        41 => Shr(x?),
        42 => OfInt(x?),
        _ => return None,
    })
}

/// Post-order DAG encoding: the node count, then each node with its
/// children as indices of earlier nodes; the root is the last node.
fn encode_into(env: &Env, t: &Tm, w: &mut Writer) {
    let mut order: Vec<Tm> = Vec::new();
    let mut index: crate::auto::util::FxMap<*const Term, u32> = crate::auto::util::FxMap::default();
    // iterative post-order over the DAG
    let mut stack: Vec<(Tm, bool)> = vec![(t.clone(), false)];
    while let Some((x, done)) = stack.pop() {
        let k = Rc::as_ptr(&x);
        if index.contains_key(&k) {
            continue;
        }
        if done {
            index.insert(k, order.len() as u32);
            order.push(x);
            continue;
        }
        stack.push((x.clone(), true));
        for c in super::symex::children(&x).into_iter().rev() {
            if !index.contains_key(&Rc::as_ptr(&c)) {
                stack.push((c, false));
            }
        }
    }
    w.u32(order.len() as u32);
    let ix = |c: &Tm| index[&Rc::as_ptr(c)];
    let ind_name = |i: IndId| env.inductive_decl(i).map(|d| d.name.to_string()).unwrap_or_default();
    let gname = |g: GlobalId| env.global_name(g).unwrap_or_else(|| std::rc::Rc::from(""));
    for x in &order {
        use Term::*;
        match &**x {
            Var(Idx(i)) => {
                w.u8(0);
                w.u32(*i);
            }
            Global(g) => {
                w.u8(1);
                w.str(&gname(*g));
            }
            Sort(s) => {
                w.u8(2);
                w.u8(match s {
                    sandblaster_kernel::term::Sort::Type => 0,
                    sandblaster_kernel::term::Sort::Kind => 1,
                });
            }
            Pi { name, rel, dom, cod } | Lam { name, rel, dom, body: cod } => {
                w.u8(if matches!(&**x, Pi { .. }) { 3 } else { 4 });
                w.str(name);
                w.u8(rel_code(*rel));
                w.u32(ix(dom));
                w.u32(ix(cod));
            }
            App { rel, fun, arg } => {
                w.u8(5);
                w.u8(rel_code(*rel));
                w.u32(ix(fun));
                w.u32(ix(arg));
            }
            Let { name, rel, ty, val, body } => {
                w.u8(6);
                w.str(name);
                w.u8(rel_code(*rel));
                w.u32(ix(ty));
                w.u32(ix(val));
                w.u32(ix(body));
            }
            Sigma { name, snd_rel, fst, snd } => {
                w.u8(7);
                w.str(name);
                w.u8(rel_code(*snd_rel));
                w.u32(ix(fst));
                w.u32(ix(snd));
            }
            Pair { ty, fst, snd } => {
                w.u8(8);
                w.u32(ix(ty));
                w.u32(ix(fst));
                w.u32(ix(snd));
            }
            Fst(p) => {
                w.u8(9);
                w.u32(ix(p));
            }
            Snd(p) => {
                w.u8(10);
                w.u32(ix(p));
            }
            Eq { ty, lhs, rhs } => {
                w.u8(11);
                w.u32(ix(ty));
                w.u32(ix(lhs));
                w.u32(ix(rhs));
            }
            Refl { ty, val } => {
                w.u8(12);
                w.u32(ix(ty));
                w.u32(ix(val));
            }
            Transport { ty, lhs, rhs, eq, motive, val } => {
                w.u8(13);
                for c in [ty, lhs, rhs, eq, motive, val] {
                    w.u32(ix(c));
                }
            }
            Ind { ind, params } => {
                w.u8(14);
                w.str(&ind_name(*ind));
                w.u32(params.len() as u32);
                for p in params {
                    w.u32(ix(p));
                }
            }
            Ctor { ind, ctor, params, args } => {
                w.u8(15);
                w.str(&ind_name(*ind));
                w.u32(*ctor);
                w.u32(params.len() as u32);
                for p in params {
                    w.u32(ix(p));
                }
                w.u32(args.len() as u32);
                for a in args {
                    w.u32(ix(a));
                }
            }
            Match { ind, params, scrut, motive, arms } => {
                w.u8(16);
                w.str(&ind_name(*ind));
                w.u32(params.len() as u32);
                for p in params {
                    w.u32(ix(p));
                }
                w.u32(ix(scrut));
                w.u32(ix(motive));
                w.u32(arms.len() as u32);
                for a in arms {
                    w.u32(a.names.len() as u32);
                    for n in &a.names {
                        w.str(n);
                    }
                    w.u32(ix(&a.body));
                }
            }
            IntTy(wd) => {
                w.u8(17);
                w.u8(width_code(*wd));
            }
            Lit { w: wd, n } => {
                w.u8(18);
                w.u8(width_code(*wd));
                w.int(n);
            }
            Prim { op, args, proofs } => {
                w.u8(19);
                let (c, a, b) = prim_code(*op);
                w.u8(c);
                w.u8(a);
                w.u8(b);
                w.u32(args.len() as u32);
                for a in args {
                    w.u32(ix(a));
                }
                w.u32(proofs.len() as u32);
                for p in proofs {
                    w.u32(ix(p));
                }
            }
            Rec { args, proof } => {
                w.u8(20);
                w.u32(args.len() as u32);
                for a in args {
                    w.u32(ix(a));
                }
                match proof {
                    Some(p) => {
                        w.u8(1);
                        w.u32(ix(p));
                    }
                    None => w.u8(0),
                }
            }
            Delta { def, args } => {
                w.u8(21);
                w.str(&gname(*def));
                w.u32(args.len() as u32);
                for a in args {
                    w.u32(ix(a));
                }
            }
            Unfold { def, args, to_body, val } => {
                w.u8(22);
                w.str(&gname(*def));
                w.u32(args.len() as u32);
                for a in args {
                    w.u32(ix(a));
                }
                w.u8(*to_body as u8);
                w.u32(ix(val));
            }
            Linarith { hyps, goal, cert } => {
                w.u8(23);
                w.u32(hyps.len() as u32);
                for (p, s) in hyps {
                    w.u32(ix(p));
                    w.u32(ix(s));
                }
                w.u32(ix(goal));
                w.u32(cert.len() as u32);
                for r in cert {
                    w.int(&r.num);
                    w.int(&r.den);
                }
            }
            BvRefl { ty, lhs, rhs } => {
                w.u8(24);
                w.u32(ix(ty));
                w.u32(ix(lhs));
                w.u32(ix(rhs));
            }
            Absurd { ty, proof } => {
                w.u8(25);
                w.u32(ix(ty));
                w.u32(ix(proof));
            }
            Axiom { ax, args } => {
                w.u8(26);
                w.u32(ax.0);
                w.u32(args.len() as u32);
                for a in args {
                    w.u32(ix(a));
                }
            }
            Erased => w.u8(27),
        }
    }
}

fn decode(env: &Env, r: &mut Reader<'_>) -> Option<Tm> {
    let n = r.u32()? as usize;
    let mut nodes: Vec<Tm> = Vec::with_capacity(n.min(1 << 24));
    let mut globals: HashMap<String, GlobalId> = HashMap::new();
    let mut inds: HashMap<String, IndId> = HashMap::new();
    for _ in 0..n {
        let tag = r.u8()?;
        macro_rules! at {
            () => {{
                let i = r.u32()? as usize;
                nodes.get(i)?.clone()
            }};
        }
        macro_rules! global {
            () => {{
                let name = r.str()?;
                match globals.get(&name) {
                    Some(g) => *g,
                    None => {
                        let g = env.lookup_global(&name)?;
                        globals.insert(name, g);
                        g
                    }
                }
            }};
        }
        macro_rules! ind {
            () => {{
                let name = r.str()?;
                match inds.get(&name) {
                    Some(i) => *i,
                    None => {
                        let i = env.lookup_ind(&name)?;
                        inds.insert(name, i);
                        i
                    }
                }
            }};
        }
        macro_rules! list {
            () => {{
                let k = r.u32()? as usize;
                let mut v = Vec::with_capacity(k.min(1 << 16));
                for _ in 0..k {
                    v.push(at!());
                }
                v
            }};
        }
        let t: Term = match tag {
            0 => Term::Var(Idx(r.u32()?)),
            1 => Term::Global(global!()),
            2 => Term::Sort(match r.u8()? {
                0 => Sort::Type,
                1 => Sort::Kind,
                _ => return None,
            }),
            3 | 4 => {
                let name: Rc<str> = Rc::from(r.str()?.as_str());
                let rel = rel_of(r.u8()?)?;
                let dom = at!();
                let cod = at!();
                if tag == 3 { Term::Pi { name, rel, dom, cod } } else { Term::Lam { name, rel, dom, body: cod } }
            }
            5 => {
                let rel = rel_of(r.u8()?)?;
                let fun = at!();
                let arg = at!();
                Term::App { rel, fun, arg }
            }
            6 => {
                let name: Rc<str> = Rc::from(r.str()?.as_str());
                let rel = rel_of(r.u8()?)?;
                let ty = at!();
                let val = at!();
                let body = at!();
                Term::Let { name, rel, ty, val, body }
            }
            7 => {
                let name: Rc<str> = Rc::from(r.str()?.as_str());
                let snd_rel = rel_of(r.u8()?)?;
                let fst = at!();
                let snd = at!();
                Term::Sigma { name, snd_rel, fst, snd }
            }
            8 => {
                let ty = at!();
                let fst = at!();
                let snd = at!();
                Term::Pair { ty, fst, snd }
            }
            9 => Term::Fst(at!()),
            10 => Term::Snd(at!()),
            11 => {
                let ty = at!();
                let lhs = at!();
                let rhs = at!();
                Term::Eq { ty, lhs, rhs }
            }
            12 => {
                let ty = at!();
                let val = at!();
                Term::Refl { ty, val }
            }
            13 => {
                let ty = at!();
                let lhs = at!();
                let rhs = at!();
                let eq = at!();
                let motive = at!();
                let val = at!();
                Term::Transport { ty, lhs, rhs, eq, motive, val }
            }
            14 => {
                let ind = ind!();
                Term::Ind { ind, params: list!() }
            }
            15 => {
                let ind = ind!();
                let ctor = r.u32()?;
                let params = list!();
                let args = list!();
                Term::Ctor { ind, ctor, params, args }
            }
            16 => {
                let ind = ind!();
                let params = list!();
                let scrut = at!();
                let motive = at!();
                let k = r.u32()? as usize;
                let mut arms = Vec::with_capacity(k.min(1 << 16));
                for _ in 0..k {
                    let m = r.u32()? as usize;
                    let mut names = Vec::with_capacity(m.min(1 << 16));
                    for _ in 0..m {
                        names.push(Rc::from(r.str()?.as_str()));
                    }
                    arms.push(Arm { names, body: at!() });
                }
                Term::Match { ind, params, scrut, motive, arms }
            }
            17 => Term::IntTy(width_of(r.u8()?)?),
            18 => {
                let w = width_of(r.u8()?)?;
                Term::Lit { w, n: r.int()? }
            }
            19 => {
                let (c, a, b) = (r.u8()?, r.u8()?, r.u8()?);
                let op = prim_of(c, a, b)?;
                let args = list!();
                let proofs = list!();
                Term::Prim { op, args, proofs }
            }
            20 => {
                let args = list!();
                let proof = match r.u8()? {
                    0 => None,
                    1 => Some(at!()),
                    _ => return None,
                };
                Term::Rec { args, proof }
            }
            21 => {
                let def = global!();
                Term::Delta { def, args: list!() }
            }
            22 => {
                let def = global!();
                let args = list!();
                let to_body = r.u8()? != 0;
                let val = at!();
                Term::Unfold { def, args, to_body, val }
            }
            23 => {
                let k = r.u32()? as usize;
                let mut hyps = Vec::with_capacity(k.min(1 << 16));
                for _ in 0..k {
                    let p = at!();
                    let s = at!();
                    hyps.push((p, s));
                }
                let goal = at!();
                let m = r.u32()? as usize;
                let mut cert = Vec::with_capacity(m.min(1 << 16));
                for _ in 0..m {
                    let num = r.int()?;
                    let den = r.int()?;
                    cert.push(Rat { num, den });
                }
                Term::Linarith { hyps, goal, cert }
            }
            24 => {
                let ty = at!();
                let lhs = at!();
                let rhs = at!();
                Term::BvRefl { ty, lhs, rhs }
            }
            25 => {
                let ty = at!();
                let proof = at!();
                Term::Absurd { ty, proof }
            }
            26 => {
                let ax = AxiomId(r.u32()?);
                Term::Axiom { ax, args: list!() }
            }
            27 => Term::Erased,
            _ => return None,
        };
        nodes.push(Rc::new(t));
    }
    if r.i != r.b.len() {
        return None;
    }
    nodes.pop()
}
