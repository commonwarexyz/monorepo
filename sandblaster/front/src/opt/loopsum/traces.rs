//! Traces (optimizer design §7.3): the loop run on sample inputs.
//!
//! Inputs, at most [`MAX_SAMPLES`] per loop:
//!
//! * **profile inputs**: entry values recorded by `sandblaster profile` in the
//!   crate's checked-in `PROFILE.json` (`opt::cost::profile`);
//! * **seeded corners**: 0, 1, powers of two and their neighbours, the
//!   maximum, the boundaries of the call's `requires` (`2^62` for QMDB's
//!   leaf count), related pairs (`x < y`), and pseudo-random values — the
//!   seed is the hash of the loop's name, so the traces are deterministic.
//!
//! Samples that violate the call's `requires` are dropped (checked by kernel
//! evaluation). Each trace is run by the native interpreter of the classified
//! one-step paths, recording the state at every iteration and the exit;
//! the final result of every trace is also computed by the kernel (the loop
//! call evaluated closed) and must agree. Traces are untrusted and only
//! filter candidates.

use std::rc::Rc;

use num_traits::ToPrimitive;
use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{Lvl, Rel, Term, Width};
use sandblaster_kernel::value::{Budget, EnvEntry, VEnv, Value};

use super::classify::{CVal, Loop, eval_sval};
use super::expr::{self, Val};

/// At most this many inputs per loop (design §17).
pub const MAX_SAMPLES: usize = 256;

/// One trace.
#[derive(Clone, Debug)]
pub struct Trace {
    /// The dynamic entry values (the ghost inputs), in dynamic-parameter
    /// order.
    pub input: Vec<CVal>,
    /// The state at iterations `0..=exit`.
    pub states: Vec<Vec<CVal>>,
    /// The iteration at which the loop exits, and the exit path (an index
    /// into `Loop::exits`).
    pub exit_iter: u32,
    pub exit_path: usize,
    pub result: CVal,
}

/// The traces of a loop and the steps spent.
pub struct Traces {
    pub traces: Vec<Trace>,
    pub steps: u64,
}

/// A deterministic 64-bit generator (xorshift*), seeded by a string's hash.
pub struct Rng(u64);

impl Rng {
    pub fn seeded(s: &str) -> Rng {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in s.bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        Rng(h | 1)
    }
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    /// A value with a uniformly chosen bit length, masked to `w`.
    pub fn bitlen(&mut self, w: Width) -> u128 {
        let b = expr::bits(w).min(64);
        let len = (self.next() % (b as u64 + 1)) as u32;
        if len == 0 {
            return 0;
        }
        let v = self.next() as u128 & ((1u128 << len) - 1);
        (v | (1u128 << (len - 1))) & expr::mask(w)
    }
}

/// The corner values of a width (and `bound`-related ones).
fn corners(w: Width, bounds: &[u128]) -> Vec<u128> {
    let m = expr::mask(w);
    let b = expr::bits(w).min(64);
    let mut v = vec![0, 1, 2, 3, 5, 7, 8, 127, 128, 255, 256, m, m - 1, m >> 1, (m >> 1) + 1];
    for k in [5u32, 7, 16, 31, 32, 33, 61, 62, 63] {
        if k < b {
            let p = 1u128 << k;
            v.extend([p - 1, p, p + 1]);
        }
    }
    for &x in bounds {
        v.extend([x.saturating_sub(1), x, x + 1, x >> 1, x.saturating_sub(2)]);
    }
    v.retain(|x| *x <= m);
    v.sort();
    v.dedup();
    v
}

/// Literal bounds mentioned by the loop's `requires` (for corner samples).
fn requires_bounds(env: &Env, lp: &Loop) -> Vec<u128> {
    let tele = crate::opt::symex::telescope(env, lp.one.def).unwrap();
    let mut out = Vec::new();
    for (_, rel, dom) in &tele.binders {
        if *rel != Rel::Irr {
            continue;
        }
        crate::elab::tm::any_node(dom, &mut |n| {
            if let Term::Lit { n, .. } = n
                && let Some(x) = n.to_u128()
                && x > 16
            {
                out.push(x);
            }
            false
        });
        // global constants (e.g. `MAX_LEAVES`) evaluate to their literal
        crate::elab::tm::any_node(dom, &mut |n| {
            if let Term::Global(g) = n
                && env.global_arity(*g) == Some(0)
                && let Some(body) = env.global_body(*g)
                && let Term::Lit { n, .. } = &*body
                && let Some(x) = n.to_u128()
            {
                out.push(x);
            }
            false
        });
    }
    out.sort();
    out.dedup();
    out
}

/// Whether the call's `requires` hold at the dynamic values `dv` (kernel
/// evaluation of each `requires` binder's type).
pub fn requires_hold(env: &Env, lp: &Loop, dv: &[CVal]) -> bool {
    let tele = crate::opt::symex::telescope(env, lp.one.def).unwrap();
    let Some(state) = lp.entry_state(env, dv) else { return false };
    let mut venv: Vec<EnvEntry> = Vec::new();
    let mut b = Budget { steps: 2_000_000 };
    let bool_ind = env.bool_ind();
    for (i, (_, rel, dom)) in tele.binders.iter().enumerate() {
        match rel {
            Rel::Rel => {
                let v = match &lp.statics[i] {
                    Some(t) => match env.eval(&VEnv::default(), Lvl(0), t, &mut b) {
                        Ok(v) => v,
                        Err(_) => return false,
                    },
                    None => match cval_value(env, &state[i]) {
                        Some(v) => v,
                        None => return false,
                    },
                };
                venv.push(EnvEntry::Rel(v));
            }
            Rel::Irr => {
                let Ok(tv) = env.eval(&VEnv(Rc::new(venv.clone())), Lvl(0), dom, &mut b) else { return false };
                let ok = prop_holds(env, &tv, &mut b, 8);
                if !ok && std::env::var_os("SANDBLASTER_LOOPSUM_TRACE").is_some() {
                    let t = env.quote(Lvl(0), &tv, false);
                    eprintln!("[loopsum] requires fails at {dv:?}: {}", env.print_term(&[], &t).chars().take(400).collect::<String>());
                }
                if !ok {
                    return false;
                }
                let _ = bool_ind;
                venv.push(EnvEntry::Irr(sandblaster_kernel::value::Closure { env: VEnv::default(), body: Rc::new(Term::Erased) }));
            }
        }
    }
    true
}

/// Whether a closed proposition holds by evaluation: an equation whose
/// sides convert, or a conjunction (`Σ`) of such.
fn prop_holds(env: &Env, v: &sandblaster_kernel::value::V, b: &mut Budget, fuel: u32) -> bool {
    if fuel == 0 {
        return false;
    }
    match &**v {
        Value::Eq { lhs, rhs, .. } => env.conv(Lvl(0), lhs, rhs, b).unwrap_or(false),
        Value::Sigma { fst, snd, .. } => {
            if !prop_holds(env, fst, b, fuel - 1) {
                return false;
            }
            let dummy = EnvEntry::Irr(sandblaster_kernel::value::Closure { env: VEnv::default(), body: Rc::new(Term::Erased) });
            let mut es = (*snd.env.0).clone();
            es.push(dummy);
            match env.eval(&VEnv(Rc::new(es)), Lvl(0), &snd.body, b) {
                Ok(v2) => prop_holds(env, &v2, b, fuel - 1),
                Err(_) => false,
            }
        }
        _ => false,
    }
}

/// A kernel value for a concrete value (numbers and booleans; constructors
/// of the static arguments only).
pub fn cval_value(env: &Env, c: &CVal) -> Option<sandblaster_kernel::value::V> {
    Some(match c {
        CVal::N(Val::W(w, n)) => Rc::new(Value::Lit { w: *w, n: (*n).into() }),
        CVal::N(Val::B(b)) => Rc::new(Value::Ctor { ind: env.bool_ind(), ctor: *b as u32, params: vec![], args: vec![] }),
        CVal::N(Val::I(n)) => Rc::new(Value::Lit { w: Width::Int, n: (*n).into() }),
        CVal::Ctor { .. } => return None,
    })
}

/// The dynamic input samples of a loop: profile inputs first, then corners
/// and seeded random values, filtered by the call's `requires`.
pub fn samples(env: &Env, lp: &Loop, profile: &[Vec<u128>]) -> Result<Vec<Vec<CVal>>, String> {
    let dy = lp.dynamic();
    let widths: Vec<Width> = dy.iter().map(|i| lp.params[*i as usize].width.ok_or("a dynamic parameter that is not a machine integer")).collect::<Result<_, _>>()?;
    let name = env.global_name(lp.one.def).map(|s| s.to_string()).unwrap_or_default();
    let mut rng = Rng::seeded(&name);
    let bounds = requires_bounds(env, lp);
    // candidate streams, interleaved so that every kind is represented
    // within the sample budget
    let mut streams: Vec<Vec<Vec<u128>>> = Vec::new();
    streams.push(profile.iter().filter(|p| p.len() == widths.len()).cloned().collect());
    let cs: Vec<Vec<u128>> = widths.iter().map(|w| corners(*w, &bounds)).collect();
    // each position through its corners, the others at 0
    for (i, c) in cs.iter().enumerate() {
        let mut st = Vec::new();
        for &x in c {
            let mut v: Vec<u128> = widths.iter().map(|_| 0).collect();
            v[i] = x;
            st.push(v);
        }
        streams.push(st);
    }
    // pairs of positions: a corner and a related value (below, at, above,
    // half), both ways
    if widths.len() >= 2 {
        for i in 0..widths.len() {
            for k in 0..widths.len() {
                if i == k {
                    continue;
                }
                let mut st = Vec::new();
                for &x in &cs[i] {
                    for y in [x.saturating_sub(1), x >> 1, x.wrapping_add(1) & expr::mask(widths[k]), x & expr::mask(widths[k])] {
                        let mut v: Vec<u128> = widths.iter().map(|_| 0).collect();
                        v[i] = x;
                        v[k] = y & expr::mask(widths[k]);
                        st.push(v);
                    }
                }
                streams.push(st);
            }
        }
    }
    // seeded random values (uniform bit length), related pairs
    let mut st = Vec::new();
    for _ in 0..(3 * MAX_SAMPLES) {
        let mut v: Vec<u128> = widths.iter().map(|w| rng.bitlen(*w)).collect();
        if v.len() >= 2 {
            let r = rng.next() % 4;
            let (a, b) = (v[0], v[1]);
            match r {
                0 if b > 0 => v[0] = (rng.next() as u128) % b,
                1 if a > 0 => v[1] = (rng.next() as u128) % a,
                2 => v[0] = b.saturating_sub(1 + (rng.next() % 4) as u128),
                _ => {}
            }
        }
        st.push(v);
    }
    streams.push(st);
    let mut cands: Vec<Vec<u128>> = Vec::new();
    let longest = streams.iter().map(|s| s.len()).max().unwrap_or(0);
    for i in 0..longest {
        for s in &streams {
            if let Some(v) = s.get(i) {
                cands.push(v.clone());
            }
        }
    }
    let mut out: Vec<Vec<CVal>> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for c in cands {
        if out.len() >= MAX_SAMPLES {
            break;
        }
        let dv: Vec<CVal> = c.iter().zip(&widths).map(|(x, w)| CVal::N(Val::W(*w, *x & expr::mask(*w)))).collect();
        if !seen.insert(dv.clone()) {
            continue;
        }
        if requires_hold(env, lp, &dv) {
            out.push(dv);
        }
    }
    if out.len() < 16 {
        return Err(format!("only {} sample inputs satisfy the call's requires", out.len()));
    }
    Ok(out)
}

/// Runs the loop natively on each sample (see the module docs); the final
/// results are checked against the kernel's evaluation of the call on up to
/// `kernel_checks` samples.
pub fn run(env: &Env, lp: &Loop, samples: &[Vec<CVal>], kernel_checks: usize, budget: u64) -> Result<Traces, String> {
    let mut steps = 0u64;
    let mut traces = Vec::new();
    for (si, dv) in samples.iter().enumerate() {
        let mut st = lp.entry_state(env, dv).ok_or("an entry state")?;
        let mut states = vec![st.clone()];
        let mut exit = None;
        for jj in 0..=lp.k {
            let nums: Vec<u128> = st.iter().map(|c| c.num().unwrap_or(0)).collect();
            let holds = |gs: &[(expr::E, bool)]| gs.iter().all(|(g, b)| g.eval(&nums, None).and_then(|v| v.as_bool()) == Some(*b));
            let ex: Vec<usize> = lp.exits.iter().enumerate().filter(|(_, e)| holds(&e.guards)).map(|(i, _)| i).collect();
            let co: Vec<usize> = lp.cont.iter().enumerate().filter(|(_, c)| holds(&c.guards)).map(|(i, _)| i).collect();
            match (ex.len(), co.len()) {
                (1, 0) => {
                    let v = eval_sval(&lp.exits[ex[0]].value, &st).ok_or("an exit value that does not evaluate")?;
                    exit = Some((jj, ex[0], v));
                    break;
                }
                (0, 1) => {
                    let next: Vec<CVal> = lp.cont[co[0]].next.iter().map(|s| eval_sval(s, &st)).collect::<Option<_>>().ok_or("an update that does not evaluate")?;
                    st = next;
                    states.push(st.clone());
                }
                _ => return Err(format!("the native interpreter found {} exit and {} continuing paths at iteration {jj}", ex.len(), co.len())),
            }
        }
        let Some((exit_iter, exit_path, result)) = exit else { return Err("a trace that does not exit within K iterations".into()) };
        states.truncate(exit_iter as usize + 1);
        if si < kernel_checks {
            let (ok, s) = kernel_agrees(env, lp, dv, &result, budget)?;
            steps += s;
            if !ok {
                return Err(format!("the native trace disagrees with the kernel at input {dv:?}"));
            }
        }
        traces.push(Trace { input: dv.clone(), states, exit_iter, exit_path, result });
    }
    Ok(Traces { traces, steps })
}

/// Evaluates the loop call closed with the kernel and compares its result
/// with `result` (numbers compared exactly; constructors by their shape and
/// numeric fields).
fn kernel_agrees(env: &Env, lp: &Loop, dv: &[CVal], result: &CVal, budget: u64) -> Result<(bool, u64), String> {
    let tele = crate::opt::symex::telescope(env, lp.one.def).ok_or("no telescope")?;
    let state = lp.entry_state(env, dv).ok_or("an entry state")?;
    let mut args = Vec::new();
    let mut di = 0usize;
    for (i, (_, rel, _)) in tele.binders.iter().enumerate() {
        match rel {
            Rel::Rel => {
                let t = match &lp.statics[i] {
                    Some(t) => t.clone(),
                    None => {
                        let v = cval_value(env, &state[i]).ok_or("a dynamic value")?;
                        di += 1;
                        env.quote(Lvl(0), &v, false)
                    }
                };
                args.push((Rel::Rel, t));
            }
            Rel::Irr => args.push((Rel::Irr, Rc::new(Term::Erased))),
        }
    }
    let _ = di;
    let call = sandblaster_kernel::util::mk::apps(sandblaster_kernel::util::mk::global(lp.one.def), args);
    let mut b = Budget { steps: budget };
    let v = env.eval_opaque(&VEnv::default(), Lvl(0), &call, &|_| false, &mut b).map_err(|e| format!("kernel evaluation of the loop: {e:?}"))?;
    let t = env.quote(Lvl(0), &v, false);
    Ok((term_matches(env, &t, result), budget - b.steps))
}

fn term_matches(env: &Env, t: &sandblaster_kernel::term::Tm, c: &CVal) -> bool {
    match (&**t, c) {
        (Term::Lit { n, .. }, CVal::N(v)) => n.to_u128() == v.as_u128(),
        (Term::Ctor { ind, ctor, .. }, CVal::N(Val::B(b))) if *ind == env.bool_ind() => (*ctor == 1) == *b,
        (Term::Ctor { ind, ctor, args, .. }, CVal::Ctor { ind: i2, ctor: c2, args: a2 }) => {
            ind.0 == *i2 && ctor == c2 && args.len() == a2.len() && args.iter().zip(a2).all(|(x, y)| term_matches(env, x, y))
        }
        _ => false,
    }
}
