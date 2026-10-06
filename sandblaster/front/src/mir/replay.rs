//! The encoding of the theorem gate's verdict-cache entries
//! (`mir::checked`): declarations as a DAG in post-order (shared subterms
//! once), globals and inductives by name, so an entry does not depend on the
//! numbering of the environment. Never trusted: [`replay_decls`] adds each
//! declaration through `add_def`, so the kernel checks it again, and the
//! trusted gate (`mir::gate`) checks every theorem's statement.

use std::collections::HashMap;
use std::rc::Rc;

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{Arm, AxiomId, BigInt, DefDecl, DefKind, GlobalId, Idx, IndId, PrimOp, Rat, Recursion, Rel, Sort, Term, Tm, Width};

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
    fn str(&mut self, s: &str) {
        self.u32(s.len() as u32);
        self.b.extend_from_slice(s.as_bytes());
    }
    /// A length-prefixed byte string.
    fn bytes(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.b.extend_from_slice(b);
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
    fn str(&mut self) -> Option<String> {
        let n = self.u32()? as usize;
        String::from_utf8(self.take(n)?.to_vec()).ok()
    }
    /// A term encoded by [`Writer::bytes`] of [`encode`].
    fn term(&mut self, env: &Env) -> Option<Tm> {
        let n = self.u32()? as usize;
        decode(env, &mut Reader { b: self.take(n)?, i: 0 })
    }
    fn int(&mut self) -> Option<BigInt> {
        let n = self.u32()? as usize;
        Some(BigInt::from_signed_bytes_le(self.take(n)?))
    }
}

/// Declarations as the theorem gate's verdict-cache entries hold them
/// (`mir::checked`): name, arity, recursion, and the DAG encodings of the
/// measure, the type and the body. Never trusted: [`replay_decls`] adds
/// each through `add_def`, so the kernel checks it again.
pub(crate) fn encode_decls(env: &Env, ds: &[DefDecl]) -> Vec<u8> {
    let mut w = Writer::default();
    w.u32(ds.len() as u32);
    for d in ds {
        w.str(&d.name);
        // the globals and inductives it names (to say which is missing)
        let mut names = std::collections::BTreeSet::new();
        for t in [&d.ty, &d.body].into_iter().chain(match &d.recursion {
            Recursion::Measure { measure } => Some(measure),
            _ => None,
        }) {
            crate::elab::tm::any_node(t, &mut |n| {
                match n {
                    Term::Global(g) | Term::Delta { def: g, .. } | Term::Unfold { def: g, .. } => names.insert(format!("g{}", env.global_name(*g).unwrap_or_default())),
                    Term::Ind { ind, .. } | Term::Ctor { ind, .. } | Term::Match { ind, .. } => names.insert(format!("i{}", env.inductive_decl(*ind).map(|d| d.name.to_string()).unwrap_or_default())),
                    _ => false,
                };
                false
            });
        }
        w.u32(names.len() as u32);
        for n in &names {
            w.str(n);
        }
        w.u32(d.arity);
        match &d.recursion {
            Recursion::None => w.u8(0),
            Recursion::Structural { param } => {
                w.u8(1);
                w.u32(*param);
            }
            Recursion::Measure { measure } => {
                w.u8(2);
                w.bytes(&encode(env, measure));
            }
        }
        w.bytes(&encode(env, &d.ty));
        w.bytes(&encode(env, &d.body));
    }
    w.b
}

/// Adds the declarations of [`encode_decls`] in order, as lemmas (each
/// decoded once the ones before it are defined, its globals by name).
pub(crate) fn replay_decls(env: &mut Env, b: &[u8]) -> Result<(), String> {
    let mut r = Reader { b, i: 0 };
    let bad = || "a malformed entry".to_string();
    for _ in 0..r.u32().ok_or_else(bad)? {
        let name = r.str().ok_or_else(bad)?;
        for _ in 0..r.u32().ok_or_else(bad)? {
            let n = r.str().ok_or_else(bad)?;
            let defined = match n.split_at(1.min(n.len())) {
                ("g", g) => env.lookup_global(g).is_some(),
                (_, i) => env.lookup_ind(i).is_some(),
            };
            if !defined {
                return Err(format!("`{name}` names `{}`, which is not defined", &n[1.min(n.len())..]));
            }
        }
        let arity = r.u32().ok_or_else(bad)?;
        let recursion = match r.u8().ok_or_else(bad)? {
            0 => Recursion::None,
            1 => Recursion::Structural { param: r.u32().ok_or_else(bad)? },
            2 => Recursion::Measure { measure: r.term(env).ok_or_else(bad)? },
            _ => return Err(bad()),
        };
        let ty = r.term(env).ok_or_else(bad)?;
        let body = r.term(env).ok_or_else(bad)?;
        let d = DefDecl { name: Rc::from(name.as_str()), kind: DefKind::Lemma, ty, body, recursion, arity, opaque: false };
        env.add_def(d, &mut sandblaster_kernel::value::Budget { steps: 40_000_000_000 }).map_err(|e| format!("the kernel rejected `{name}`: {}", e.to_string().chars().take(600).collect::<String>()))?;
    }
    Ok(())
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
        for c in children(&x).into_iter().rev() {
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

/// Direct subterms of a term (every position, relevant or not).
fn children(t: &Tm) -> Vec<Tm> {
    use Term::*;
    match &**t {
        Var(_) | Global(_) | Sort(_) | IntTy(_) | Lit { .. } | Erased => vec![],
        Pi { dom, cod, .. } => vec![dom.clone(), cod.clone()],
        Lam { dom, body, .. } => vec![dom.clone(), body.clone()],
        App { fun, arg, .. } => vec![fun.clone(), arg.clone()],
        Let { ty, val, body, .. } => vec![ty.clone(), val.clone(), body.clone()],
        Sigma { fst, snd, .. } => vec![fst.clone(), snd.clone()],
        Pair { ty, fst, snd } => vec![ty.clone(), fst.clone(), snd.clone()],
        Fst(p) | Snd(p) => vec![p.clone()],
        Eq { ty, lhs, rhs } => vec![ty.clone(), lhs.clone(), rhs.clone()],
        Refl { ty, val } => vec![ty.clone(), val.clone()],
        Transport { ty, lhs, rhs, eq, motive, val } => vec![ty.clone(), lhs.clone(), rhs.clone(), eq.clone(), motive.clone(), val.clone()],
        Ind { params, .. } => params.clone(),
        Ctor { params, args, .. } => params.iter().chain(args.iter()).cloned().collect(),
        Match { params, scrut, motive, arms, .. } => {
            let mut v: Vec<Tm> = params.clone();
            v.push(scrut.clone());
            v.push(motive.clone());
            v.extend(arms.iter().map(|a| a.body.clone()));
            v
        }
        Prim { args, proofs, .. } => args.iter().chain(proofs.iter()).cloned().collect(),
        Rec { args, proof } => args.iter().cloned().chain(proof.iter().cloned()).collect(),
        Delta { args, .. } => args.clone(),
        Unfold { args, val, .. } => {
            let mut v = args.clone();
            v.push(val.clone());
            v
        }
        Linarith { hyps, goal, .. } => {
            let mut v: Vec<Tm> = hyps.iter().flat_map(|(a, b)| [a.clone(), b.clone()]).collect();
            v.push(goal.clone());
            v
        }
        BvRefl { ty, lhs, rhs } => vec![ty.clone(), lhs.clone(), rhs.clone()],
        Absurd { ty, proof } => vec![ty.clone(), proof.clone()],
        Axiom { args, .. } => args.clone(),
    }
}
