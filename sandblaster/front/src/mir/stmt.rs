//! The statement of a lifted function's theorem (`docs/mir-lift.md` §20.5,
//! `docs/checked-structuring.md` §3). TRUSTED: it decides what the theorem
//! says.
//!
//! ```text
//! L::thm::<f> : Π x̄ (.h̄ : pre). Σ (k : Int). Π (n : List(Unit)) (.hle : k ≤ len n).
//!     Eq(Option(Out), L::<f>::run n b0 (Some(init(x̄))), Some(erase(S_f x̄ .h̄)))
//! ```
//!
//! * `x̄ .h̄` is the telescope of `S_f`, the structured reading's definition.
//!   Its relevant parameters are the MIR instance's parameters, in order.
//!   Its preconditions `h̄` are the function's **declared contract** (the
//!   skeleton's and the attachments' clauses, never the reading of the
//!   body): the elaborator refuses a function read from MIR unless each of
//!   them is α-equal to the elaboration of the declared clause, which the
//!   lift carries apart (`hir::FnDef::declared`, `elab::items`), so an
//!   untrusted structurer cannot make the theorem vacuous.
//! * `init(x̄)`: slot `i` of a parameter holds `Some(erase(x_i))`; a `&mut`
//!   parameter's slot holds the code `(rc<j>, [])` of its cell, and the cell
//!   `Some(erase(x_i))` (the referent: state passing); an `Option<&mut T>`
//!   parameter's slot holds `None` or `Some((rc<j>, []))` as `x_i` is `None`
//!   or `Some`, and its cell `erase(x_i)`; every other local is `None`.
//! * `erase` is the identity on the types L and S share; a module type whose
//!   S declaration carries invariant proofs is L's mirror built from S's own
//!   projections of the relevant fields. S's result (its states in
//!   parameter order, then its return value) is erased component-wise into
//!   `Out` (the cells' final values, then the return place).
//!
//! **The panic statement** ([`statement_panic`], DESIGN.md §8.2 item 12),
//! for a *panic-explicit reading* `P` of an exec-only function that can
//! panic (`opt::panics`: `P x̄ : Option(R)`, `None` the panic outcome):
//!
//! ```text
//! Π x̄ (.h̄ : pre). Σ (k : Int). Π (n : List(Unit)) (.hle : k ≤ len n).
//!     Eq(Option(Out), L::<f>::run n b0 (Some(init(x̄))),
//!        match P x̄ with None => None | Some(y) => Some(erase(y)))
//! ```
//!
//! On the inputs where `P` returns a value it says what the plain statement
//! says. Where `P` is `None`, it says that the literal reading returns no
//! value: the run panics, or reaches what `L` reads as `None` for another
//! reason (undefined behaviour, an unmodeled construct, no fuel). The gate
//! (`gate::Ledger::accept_shipped_panic`) accepts it only for MIR whose
//! literal reading reads nothing but a panic as `None` there (no fault, no
//! loop, every block it reads as panicking checked to panic), so that `None`
//! means "panics"; it is never a theorem of a verified build.

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{Rel, Term};

use super::ir::{self, Ty};
use super::literal::{Gen, LFn};

/// The statement of one function's theorem.
#[derive(Clone, Debug)]
pub struct StmtSpec {
    /// `S_f`'s kernel name.
    pub s_global: String,
    /// `S_f`'s telescope: (name, relevance, type as core text over earlier names).
    pub params: Vec<(String, Rel, String)>,
    /// `S_f`'s result type (core text over the parameters).
    pub s_ret: String,
    pub l_run: String,
    pub l_st: String,
    pub l_blk: String,
    pub l_out: String,
    /// The initial slots (core text over the parameter names).
    pub init_slots: Vec<String>,
    /// `erase` of S's result `@Y@` (core text).
    pub erase_ret: String,
    /// The panic statement ([`statement_panic`]): S's result is
    /// `Option(s_ret)`, `None` the panic outcome.
    pub panic: bool,
}

impl StmtSpec {
    /// `run n b0 (Some init)`, `n` free.
    pub fn l_of(&self) -> String {
        format!("{} n {}::b0 (Some[{st}]({st}::st({})))", self.l_run, self.l_blk, self.init_slots.join(", "), st = self.l_st)
    }

    /// `λ (yy : R_S). erase(yy)`.
    pub fn erase_fn(&self) -> String {
        format!("fun (yy : {}) => {}", self.s_ret, self.erase_ret.replace("@Y@", "yy"))
    }

    /// `S_f x̄ .h̄`.
    pub fn app(&self) -> String {
        self.params.iter().fold(self.s_global.clone(), |a, (n, r, _)| format!("{a} {}{n}", if *r == Rel::Irr { "." } else { "" }))
    }

    /// `(x0 : T0) -> (.h : P) -> ..`.
    pub fn tele(&self) -> String {
        self.params.iter().map(|(n, r, t)| format!("({}{n} : {t}) -> ", if *r == Rel::Irr { "." } else { "" })).collect()
    }

    /// The trusted theorem: some fuel bound `k` after which the literal
    /// reading returns the structured reading's value (with more fuel too).
    pub fn theorem_ty(&self) -> String {
        self.eq_under(&format!("{}Sigma (k : Int), ((n : List(Unit)) -> (.hle : Eq(Bool, #le_int(k, seq::len Unit n), true)) -> ", self.tele()), ")")
    }

    /// The (untrusted) function lemma at an explicit fuel need: `Π x̄ (n)
    /// (.hle : need ≤ len n). Eq(..)`.
    pub fn lemma_ty(&self, need: &str) -> String {
        self.eq_under(&format!("{}(n : List(Unit)) -> (.hle : Eq(Bool, #le_int({need}, seq::len Unit n), true)) -> ", self.tele()), "")
    }

    /// S's result type (`Option(s_ret)` for the panic statement).
    pub fn s_full_ret(&self) -> String {
        if self.panic { format!("Option({})", self.s_ret) } else { self.s_ret.clone() }
    }

    /// The equation's right side for the structured value `s` (core text
    /// of type [`Self::s_full_ret`]): `Some(erase(s))`, or for the panic
    /// statement `match s with None => None | Some(yy) => Some(erase(yy))`.
    pub fn rhs_of(&self, s: &str) -> String {
        let out = &self.l_out;
        if self.panic {
            let er = self.erase_ret.replace("@Y@", "yy");
            format!("(match {s} : Option({}) as _ return Option({out}) with | None => None[{out}] | Some(yy) => Some[{out}]({er}) end)", self.s_ret)
        } else {
            format!("Some[{out}]({})", self.erase_ret.replace("@Y@", &format!("({s})")))
        }
    }

    fn eq_under(&self, pre: &str, post: &str) -> String {
        format!("{pre}Eq(Option({out}), {}, {}){post}", self.l_of(), self.rhs_of(&self.app()), out = self.l_out)
    }
}

/// The statement of `S_f`'s theorem against the literal reading `lf` of
/// its MIR instance `f` (also, untrusted, of a model lemma: a library
/// function's reading against the lift prelude's model, `u64::div_ceil`).
pub fn statement(env: &Env, g: &mut Gen<'_>, lf: &LFn, f: &ir::Fn, s_global: &str) -> Result<StmtSpec, String> {
    statement_as(env, g, lf, f, s_global, false)
}

/// The panic statement (module docs) of the panic-explicit reading
/// `s_global` (result `Option(R)`) against the literal reading `lf`.
pub fn statement_panic(env: &Env, g: &mut Gen<'_>, lf: &LFn, f: &ir::Fn, s_global: &str) -> Result<StmtSpec, String> {
    statement_as(env, g, lf, f, s_global, true)
}

fn statement_as(env: &Env, g: &mut Gen<'_>, lf: &LFn, f: &ir::Fn, s_global: &str, panic: bool) -> Result<StmtSpec, String> {
    let sg = env.lookup_global(s_global).ok_or_else(|| format!("no definition `{s_global}`"))?;
    let (mut cur, arity) = (env.global_type(sg).ok_or("no type")?, env.global_arity(sg).ok_or("no arity")?);
    let mut params: Vec<(String, Rel, String)> = Vec::new();
    let mut names: Vec<sandblaster_kernel::term::Name> = Vec::new();
    for i in 0..arity {
        let Term::Pi { rel, dom, cod, .. } = &*cur else { return Err(format!("`{s_global}`'s type has no binder {i}")) };
        params.push((format!("x{i}"), *rel, env.print_term(&names, dom)));
        names.push(std::rc::Rc::from(format!("x{i}").as_str()));
        cur = cod.clone();
    }
    // (the panic statement: S's result `Option(R)`, the statement about `R`)
    if panic {
        match &*cur {
            Term::Ind { ind, params: ps } if Some(*ind) == env.lookup_ind("Option") && ps.len() == 1 => cur = ps[0].clone(),
            _ => return Err(format!("`{s_global}` does not return an `Option` (a panic-explicit reading does)")),
        }
    }
    let s_ret = env.print_term(&names, &cur);
    let rel: Vec<String> = params.iter().filter(|p| p.1 == Rel::Rel).map(|p| p.0.clone()).collect();
    if rel.len() != f.argc {
        return Err(format!("`{s_global}` has {} parameters, its MIR instance `{}` {}", rel.len(), f.key, f.argc));
    }
    if params.iter().any(|p| p.2 == "Type") {
        return Err(format!("`{s_global}` is generic"));
    }
    let rc = format!("Tuple2(L::{}::Root, List(mir::Proj))", lf.id);
    let code = |j: usize| format!("tuple2[L::{id}::Root, List(mir::Proj)](L::{id}::Root::rc{j}, Nil[mir::Proj])", id = lf.id);
    let mut slots: Vec<String> = Vec::new();
    for (i, lt) in lf.local_tys.iter().enumerate() {
        let lt = lt.replace("@RC@", &rc);
        let cell = lf.cells.iter().position(|c| c.param == i && c.parent.is_none());
        slots.push(match (i, cell) {
            (0, _) => format!("None[{lt}]"),
            (i, Some(j)) if i <= f.argc && lf.cells[j].optional => {
                let st = s_ty(env, &params, &rel[i - 1]);
                format!("Some[{lt}](match {} : {st} as _ return {lt} with | None => None[{rc}] | Some(y) => Some[{rc}]({}) end)", rel[i - 1], code(j))
            }
            (i, Some(j)) if i <= f.argc => format!("Some[{lt}]({})", code(j)),
            (i, None) if i <= f.argc => format!("Some[{lt}]({})", erase(g, env, &f.locals[i].0, &rel[i - 1])?),
            _ => format!("None[{lt}]"),
        });
    }
    for c in &lf.cells {
        if c.parent.is_some() {
            return Err("a lifted function whose parameter's referent holds a reference".into());
        }
        let x = &rel[c.param - 1];
        let ct = c.ty.replace("@RC@", &rc);
        slots.push(if c.optional { erase_opt(g, env, &c.mir_ty, x, &ct, &s_ty(env, &params, x))? } else { format!("Some[{ct}]({})", erase(g, env, &c.mir_ty, x)?) });
    }
    // S's result (states.., return value) against `Out` (cells.., return place)
    let mut tys: Vec<(Ty, bool)> = lf.cells.iter().map(|c| (c.mir_ty.clone(), c.optional)).collect();
    if !matches!(f.locals[0].0, Ty::Unit) && !matches!(&f.locals[0].0, Ty::Tuple(v) if v.is_empty()) {
        tys.push((f.locals[0].0.clone(), false));
    }
    let outs = &lf.out_parts;
    let one = |g: &mut Gen<'_>, (t, opt): &(Ty, bool), y: &str, o: &str| -> Result<String, String> { if *opt { erase_opt_val(g, env, t, y, o) } else { erase(g, env, t, y) } };
    let erase_ret = match tys.len() {
        0 => "tt".to_string(),
        1 => one(g, &tys[0], "@Y@", &lf.out_ty)?,
        n => {
            let ys: Vec<String> = (0..n).map(|i| format!("y{i}")).collect();
            let es: Vec<String> = tys.iter().enumerate().map(|(i, t)| one(g, t, &ys[i], &outs[i])).collect::<Result<_, _>>()?;
            format!("(match @Y@ : @SRET@ as _ return {} with | tuple{n}({}) => tuple{n}[{}]({}) end)", lf.out_ty, ys.join(", "), outs.join(", "), es.join(", "))
        }
    };
    Ok(StmtSpec { s_global: s_global.to_string(), params, s_ret: s_ret.clone(), l_run: lf.run.clone(), l_st: lf.st.clone(), l_blk: lf.blk.clone(), l_out: lf.out_ty.clone(), init_slots: slots, erase_ret: erase_ret.replace("@SRET@", &s_ret), panic })
}

fn s_ty(_env: &Env, params: &[(String, Rel, String)], x: &str) -> String {
    params.iter().find(|p| p.0 == x).map(|p| p.2.clone()).unwrap_or_default()
}

/// core's types the structured reading models by a lift-prelude struct
/// (SEMANTICS.md §19.9, `front/lift/prelude.rs`): the MIR type's path and
/// its one type argument (`None`: any), S's struct, and for each of the
/// struct's fields, in order, the MIR field path of the value it models.
type Model = (&'static str, Option<&'static str>, &'static str, &'static [&'static [&'static str]]);
const MODELS: &[Model] = &[
    ("std::ops::RangeInclusive", Some("u32"), "crate::__lift::RangeInclusiveU32", &[&["start"], &["end"], &["exhausted"]]),
    ("std::ops::RangeInclusive", Some("u64"), "crate::__lift::RangeInclusiveU64", &[&["start"], &["end"], &["exhausted"]]),
    // `Once { inner: option::IntoIter { inner: option::Item { opt } } }`
    ("std::iter::Once", None, "crate::__lift::Once", &[&["inner", "inner", "opt"]]),
];

/// The L value of the MIR struct type `t` whose fields along the paths
/// `leaves` are the given L terms (a nested struct built field by field).
fn build_model(g: &mut Gen<'_>, t: &Ty, leaves: &[(&[&str], String)]) -> Result<String, String> {
    let Ty::Adt(k) = t else { return Err(format!("a model's field path through {t:?}")) };
    let d = g.m.adts.get(k).cloned().ok_or("no ADT")?;
    let [v] = d.variants.as_slice() else { return Err(format!("a model's field path through the enum `{k}`")) };
    let mut args = Vec::new();
    for (fname, fty) in &v.fields {
        let here: Vec<(&[&str], String)> = leaves.iter().filter(|(p, _)| p.first() == Some(&fname.as_str())).map(|(p, e)| (&p[1..], e.clone())).collect();
        args.push(match here.as_slice() {
            [([], e)] => e.clone(),
            [] => return Err(format!("the field `{fname}` of `{k}`, which its model does not hold")),
            _ => build_model(g, fty, &here)?,
        });
    }
    g.ctor(k, 0, &args)
}

/// `erase(x)` of a value of MIR type `t` (core text): S's value as L's.
pub fn erase(g: &mut Gen<'_>, env: &Env, t: &Ty, x: &str) -> Result<String, String> {
    Ok(match t {
        Ty::Ref(false, inner) => erase(g, env, inner, x)?,
        // a core type S models by a prelude struct: L's value built from S's
        // own projections of the struct's fields
        Ty::Adt(k)
            if let Some(d) = g.m.adts.get(k).cloned()
                && let Some((_, _, sname, paths)) = MODELS.iter().find(|(p, a, _, _)| d.path == *p && d.args.len() == 1 && a.is_none_or(|w| super::literal::width(&d.args[0]) == Some(w))) =>
        {
            let decl = env.lookup_ind(sname).and_then(|i| env.inductive_decl(i)).ok_or_else(|| format!("no S declaration `{sname}`"))?;
            let [c] = decl.ctors.as_slice() else { return Err(format!("`{sname}` is no struct")) };
            if c.fields.len() != paths.len() || c.fields.iter().any(|f| f.1 != Rel::Rel) {
                return Err(format!("`{sname}` has other fields than its model's table"));
            }
            // S's type (the struct at the MIR type argument, which L and S must share)
            let arg_l = g.ty(&d.args[0])?;
            if erase(g, env, &d.args[0], "z")? != "z" {
                return Err(format!("a model `{sname}` of a type L reads as a mirror"));
            }
            let sty = if decl.params.is_empty() { sname.to_string() } else { format!("{sname}({arg_l})") };
            let names: Vec<String> = (0..paths.len()).map(|i| format!("a{i}")).collect();
            let pat = format!("{}({})", c.name, names.join(", "));
            let mut leaves = Vec::new();
            for (i, path) in paths.iter().enumerate() {
                let fty = model_field_ty(g, t, path)?;
                let ftt = g.ty(&fty)?;
                leaves.push((*path, format!("(match {x} : {sty} as _ return {ftt} with | {pat} => {} end)", names[i])));
            }
            build_model(g, t, &leaves)?
        }
        Ty::Adt(k) => {
            let lt = g.adt(k)?;
            let d = g.m.adts.get(k).cloned().ok_or("no ADT")?;
            // S's declaration of a module type, when L reads it as a mirror
            let Some(sname) = g.k.names.kernel_adt(g.m, k).filter(|s| *s != lt.ty) else { return Ok(x.to_string()) };
            let decl = env.lookup_ind(&sname).and_then(|i| env.inductive_decl(i)).ok_or_else(|| format!("no S declaration `{sname}`"))?;
            let mut arms = Vec::new();
            for c in &decl.ctors {
                // a struct's one constructor is its one variant; an enum's by name
                let vi = if !d.is_enum && decl.ctors.len() == 1 && d.variants.len() == 1 { Some(0) } else { d.variants.iter().position(|v| v.name == *c.name) };
                let vi = vi.ok_or_else(|| format!("`{sname}::{}` is no variant", c.name))?;
                let mut pat = Vec::new();
                let mut rel = Vec::new();
                for (fi, fl) in c.fields.iter().enumerate() {
                    if fl.1 == Rel::Irr {
                        pat.push(format!(".p{fi}"));
                    } else {
                        rel.push((format!("a{fi}"), d.variants[vi].fields.get(rel.len()).ok_or("a field out of range")?.1.clone()));
                        pat.push(format!("a{fi}"));
                    }
                }
                if rel.len() != d.variants[vi].fields.len() {
                    return Err(format!("`{sname}::{}` has other fields than the MIR", c.name));
                }
                let cn = lt.kctors.iter().find(|kc| kc.1 == vi).map(|kc| kc.0.clone()).ok_or("no mirror constructor")?;
                let pat = format!("{}{}", c.name, if pat.is_empty() { String::new() } else { format!("({})", pat.join(", ")) });
                if decl.ctors.len() == 1 {
                    // a struct: the mirror of S's own projections of its relevant fields
                    let mut es = Vec::new();
                    for (a, ft) in &rel {
                        let fty = g.ty(ft)?;
                        es.push(erase(g, env, ft, &format!("(match {x} : {sname} as _ return {fty} with | {pat} => {a} end)"))?);
                    }
                    return Ok(if es.is_empty() { cn } else { format!("{cn}({})", es.join(", ")) });
                }
                let es: Vec<String> = rel.iter().map(|(a, ft)| erase(g, env, ft, a)).collect::<Result<_, _>>()?;
                arms.push(format!("| {pat} => {}", if es.is_empty() { cn } else { format!("{cn}({})", es.join(", ")) }));
            }
            format!("(match {x} : {sname} as _ return {} with {} end)", lt.ty, arms.join(" "))
        }
        _ => x.to_string(),
    })
}

/// The MIR type at a field path of the struct type `t`.
fn model_field_ty(g: &Gen<'_>, t: &Ty, path: &[&str]) -> Result<Ty, String> {
    let mut cur = t.clone();
    for f in path {
        let Ty::Adt(k) = &cur else { return Err(format!("a model's field path through {cur:?}")) };
        let d = g.m.adts.get(k).ok_or("no ADT")?;
        cur = d.variants.first().and_then(|v| v.fields.iter().find(|(n, _)| n == f)).map(|(_, t)| t.clone()).ok_or_else(|| format!("no field `{f}` in `{k}`"))?;
    }
    Ok(cur)
}

/// The initial cell of an `Option<&mut T>` parameter `x : Option(S_T)`: `erase` under the option.
fn erase_opt(g: &mut Gen<'_>, env: &Env, t: &Ty, x: &str, ct: &str, sty: &str) -> Result<String, String> {
    let e = erase(g, env, t, "y")?;
    Ok(if e == "y" { x.to_string() } else { format!("(match {x} : {sty} as _ return Option({ct}) with | None => None[{ct}] | Some(y) => Some[{ct}]({e}) end)") })
}

/// The final value of an optional cell (an `Option`) from S's state.
fn erase_opt_val(g: &mut Gen<'_>, env: &Env, t: &Ty, y: &str, out: &str) -> Result<String, String> {
    let e = erase(g, env, t, "z")?;
    let inner = out.strip_prefix("Option(").and_then(|s| s.strip_suffix(')')).unwrap_or(out);
    Ok(if e == "z" { y.to_string() } else { format!("(match {y} : {out} as _ return {out} with | None => None[{inner}] | Some(z) => Some[{inner}]({e}) end)") })
}
