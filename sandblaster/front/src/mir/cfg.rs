//! Control-flow facts of one MIR body (untrusted analyses that only steer
//! the shape of the reading; a wrong answer makes the reading fail or
//! refuse, never read a different program — the reading follows the edges
//! of the graph whatever these say, see `read.rs`).

use std::collections::{BTreeSet, HashSet};

use super::ir::{Fn, Operand, Place, Proj, Rvalue, Stmt, Term};

/// The normal successors of a block (unwind edges are not printed).
pub fn succs(t: &Term) -> Vec<usize> {
    match t {
        Term::Goto(b) => vec![*b],
        Term::Switch(_, arms, o) => {
            let mut v: Vec<usize> = arms.iter().map(|a| a.1).collect();
            v.push(*o);
            v
        }
        Term::Drop(_, _, b) | Term::Assert(_, _, _, b) => vec![*b],
        Term::Call(_, _, _, Some(b)) => vec![*b],
        _ => vec![],
    }
}

pub struct Cfg {
    pub n: usize,
    pub succ: Vec<Vec<usize>>,
    pub pred: Vec<Vec<usize>>,
    /// Blocks reachable from the entry.
    pub reach: Vec<bool>,
    /// `back[b]`: the targets of back edges out of `b`.
    pub back: Vec<Vec<usize>>,
    /// Loop headers (targets of back edges), in source order.
    pub headers: Vec<usize>,
    /// `body[h]`: the blocks of the natural loop of header `h`.
    pub body: Vec<BTreeSet<usize>>,
    /// Blocks that only return.
    pub ret_block: Vec<bool>,
    /// Immediate post-dominator in the forward graph (back edges removed,
    /// return and diverging blocks going to a virtual exit); `None`: the exit.
    pub ipdom: Vec<Option<usize>>,
    /// Locals live at the entry of each block.
    pub live_in: Vec<HashSet<usize>>,
}

fn place_uses(p: &Place, out: &mut HashSet<usize>) {
    out.insert(p.local);
    for pr in &p.proj {
        if let Proj::Index(l) = pr {
            out.insert(*l);
        }
    }
}

fn op_uses(o: &Operand, out: &mut HashSet<usize>) {
    if let Operand::Copy(p) | Operand::Move(p) = o {
        place_uses(p, out);
    }
}

fn rv_uses(r: &Rvalue, out: &mut HashSet<usize>) {
    match r {
        Rvalue::Use(o) | Rvalue::Un(_, o) | Rvalue::Cast(_, o, _) | Rvalue::Repeat(o, _) => op_uses(o, out),
        Rvalue::Bin(_, a, b) | Rvalue::Checked(_, a, b) => {
            op_uses(a, out);
            op_uses(b, out);
        }
        Rvalue::Ref(_, p) | Rvalue::Discr(p) | Rvalue::Len(p) => place_uses(p, out),
        Rvalue::Agg(_, ops) => ops.iter().for_each(|o| op_uses(o, out)),
        Rvalue::Unsupported(_) => {}
    }
}

/// Uses and kills of a block, in order: `(uses before any kill, kills)`.
fn block_use_def(f: &Fn, b: usize) -> (HashSet<usize>, HashSet<usize>) {
    let mut uses = HashSet::new();
    let mut kills = HashSet::new();
    let bl = &f.blocks[b];
    let add_uses = |u: HashSet<usize>, kills: &HashSet<usize>, uses: &mut HashSet<usize>| {
        for l in u {
            if !kills.contains(&l) {
                uses.insert(l);
            }
        }
    };
    for s in &bl.stmts {
        match s {
            Stmt::Assign(p, r, _) => {
                let mut u = HashSet::new();
                rv_uses(r, &mut u);
                if !p.proj.is_empty() {
                    place_uses(p, &mut u);
                }
                add_uses(u, &kills, &mut uses);
                if p.proj.is_empty() {
                    kills.insert(p.local);
                }
            }
            Stmt::Assume(o, _) => {
                let mut u = HashSet::new();
                op_uses(o, &mut u);
                add_uses(u, &kills, &mut uses);
            }
            Stmt::Unsupported(_) => {}
        }
    }
    let mut u = HashSet::new();
    match &bl.term {
        Term::Switch(o, _, _) | Term::Assert(o, _, _, _) => op_uses(o, &mut u),
        Term::Call(_, args, dest, _) => {
            args.iter().for_each(|a| op_uses(a, &mut u));
            if !dest.proj.is_empty() {
                place_uses(dest, &mut u);
            }
        }
        Term::Drop(p, _, _) => place_uses(p, &mut u),
        // the return place is read at a return
        Term::Return => {
            u.insert(0);
        }
        _ => {}
    }
    add_uses(u, &kills, &mut uses);
    if let Term::Call(_, _, dest, _) = &bl.term
        && dest.proj.is_empty()
    {
        kills.insert(dest.local);
    }
    (uses, kills)
}

impl Cfg {
    pub fn new(f: &Fn) -> Cfg {
        let n = f.blocks.len();
        let succ: Vec<Vec<usize>> = f.blocks.iter().map(|b| succs(&b.term)).collect();
        let mut pred = vec![vec![]; n];
        for (b, ss) in succ.iter().enumerate() {
            for &s in ss {
                pred[s].push(b);
            }
        }
        // reachability and DFS back edges (reducible graphs: a back edge
        // targets a block on the DFS stack)
        let mut reach = vec![false; n];
        let mut on_stack = vec![false; n];
        let mut back = vec![vec![]; n];
        fn dfs(b: usize, succ: &[Vec<usize>], reach: &mut [bool], on_stack: &mut [bool], back: &mut [Vec<usize>]) {
            reach[b] = true;
            on_stack[b] = true;
            for &s in &succ[b] {
                if on_stack[s] {
                    back[b].push(s);
                } else if !reach[s] {
                    dfs(s, succ, reach, on_stack, back);
                }
            }
            on_stack[b] = false;
        }
        if n > 0 {
            dfs(0, &succ, &mut reach, &mut on_stack, &mut back);
        }
        let mut hset: BTreeSet<usize> = BTreeSet::new();
        for bs in &back {
            hset.extend(bs.iter().copied());
        }
        // natural loops
        let mut body = vec![BTreeSet::new(); n];
        for h in &hset {
            let mut set = BTreeSet::new();
            set.insert(*h);
            let mut stack: Vec<usize> = (0..n).filter(|b| back[*b].contains(h)).collect();
            while let Some(b) = stack.pop() {
                if set.insert(b) {
                    for &p in &pred[b] {
                        if reach[p] {
                            stack.push(p);
                        }
                    }
                }
            }
            body[*h] = set;
        }
        // headers in source order (by the position of the header block)
        let mut headers: Vec<usize> = hset.into_iter().collect();
        let pos = |b: usize| -> (usize, usize) {
            let bl = &f.blocks[b];
            let l = bl.stmts.iter().find_map(|s| match s {
                Stmt::Assign(_, _, Some((_, l, c))) => Some((*l, *c)),
                _ => None,
            });
            l.or(bl.term_loc.as_ref().map(|(_, l, c)| (*l, *c))).unwrap_or((usize::MAX, b))
        };
        headers.sort_by_key(|b| pos(*b));
        let ret_block: Vec<bool> = f.blocks.iter().map(|b| b.stmts.is_empty() && matches!(b.term, Term::Return)).collect();
        // post-dominators on the forward graph with a virtual exit `n`
        let exit = n;
        let fsucc = |b: usize| -> Vec<usize> {
            let v: Vec<usize> = succ[b].iter().copied().filter(|s| !back[b].contains(s) && !ret_block[*s]).collect();
            if v.is_empty() { vec![exit] } else { v }
        };
        // iterative data flow: pdom[b] = {b} ∪ ⋂ pdom[s]
        let all: BTreeSet<usize> = (0..=n).collect();
        let mut pdom: Vec<BTreeSet<usize>> = (0..=n).map(|b| if b == exit { [exit].into_iter().collect() } else { all.clone() }).collect();
        let mut changed = true;
        while changed {
            changed = false;
            for b in (0..n).rev() {
                if !reach[b] {
                    continue;
                }
                let mut acc: Option<BTreeSet<usize>> = None;
                for s in fsucc(b) {
                    let ps = &pdom[s];
                    acc = Some(match acc {
                        None => ps.clone(),
                        Some(a) => a.intersection(ps).copied().collect(),
                    });
                }
                let mut nw = acc.unwrap_or_default();
                nw.insert(b);
                if nw != pdom[b] {
                    pdom[b] = nw;
                    changed = true;
                }
            }
        }
        let ipdom: Vec<Option<usize>> = (0..n)
            .map(|b| {
                if !reach[b] {
                    return None;
                }
                // the strict post-dominator nearest to b: the one whose own
                // post-dominator set contains all the others
                let strict: Vec<usize> = pdom[b].iter().copied().filter(|x| *x != b).collect();
                let best = strict.iter().copied().find(|c| strict.iter().all(|o| pdom[*c].contains(o)));
                best.filter(|c| *c != exit)
            })
            .collect();
        // liveness (backward, to a fixpoint)
        let ud: Vec<(HashSet<usize>, HashSet<usize>)> = (0..n).map(|b| block_use_def(f, b)).collect();
        let mut live_in: Vec<HashSet<usize>> = vec![HashSet::new(); n];
        let mut changed = true;
        while changed {
            changed = false;
            for b in (0..n).rev() {
                let mut out: HashSet<usize> = HashSet::new();
                for &s in &succ[b] {
                    out.extend(live_in[s].iter().copied());
                }
                let (u, k) = &ud[b];
                let mut inn: HashSet<usize> = u.clone();
                for l in out {
                    if !k.contains(&l) {
                        inn.insert(l);
                    }
                }
                if inn != live_in[b] {
                    live_in[b] = inn;
                    changed = true;
                }
            }
        }
        Cfg { n, succ, pred, reach, back, headers, body, ret_block, ipdom, live_in }
    }

    /// The loop (header) whose body contains `b` most tightly.
    pub fn innermost_loop(&self, b: usize) -> Option<usize> {
        self.headers.iter().copied().filter(|h| self.body[*h].contains(&b)).min_by_key(|h| self.body[*h].len())
    }
}
