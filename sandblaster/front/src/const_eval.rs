//! Front-end evaluation of integer constant expressions (DESIGN.md §3.1
//! "`const NAME: T = expr;`", §3.2 "`[T; N]` (N a literal or const)").
//!
//! Array lengths and intrinsic immediates must be known during surface type
//! checking, before the kernel runs. This evaluator handles the integer
//! fragment rustc's const evaluation accepts in such positions: literals,
//! paths to `const` items (recursively, with cycle detection), `uN::MAX`,
//! `uN::MIN`, `uN::BITS`, parentheses, `+ - * / % & | ^ << >>`, and `as`
//! casts between unsigned types. Every intermediate result is checked
//! against the width of the declared type of the constant (overflow, division
//! by zero and oversized shifts are errors, as in rustc's const evaluation).
//! The kernel evaluates constants again (authoritatively) in phase 2.

use std::cell::RefCell;
use std::collections::HashMap;

use crate::hir::{ItemId, ModId, UintTy};
use crate::resolve::{Def, Ext, ItemSrc, ItemTag, Ns, Resolver};
use crate::span::Span;

/// Evaluator with a per-crate memo.
pub struct ConstEval<'r> {
    res: &'r Resolver,
    memo: RefCell<HashMap<ItemId, Result<u128, String>>>,
    stack: RefCell<Vec<ItemId>>,
}

impl<'r> ConstEval<'r> {
    pub fn new(res: &'r Resolver) -> ConstEval<'r> {
        ConstEval { res, memo: RefCell::new(HashMap::new()), stack: RefCell::new(vec![]) }
    }

    /// Value of an integer `const` item.
    pub fn eval_item(&self, id: ItemId) -> Result<u128, String> {
        if let Some(v) = self.memo.borrow().get(&id) {
            return v.clone();
        }
        if self.stack.borrow().contains(&id) {
            return Err(format!("cycle in the definition of constant `{}`", self.res.items[id.0 as usize].name));
        }
        self.stack.borrow_mut().push(id);
        let it = &self.res.items[id.0 as usize];
        let r = match (&it.tag, &it.src) {
            (ItemTag::Const, ItemSrc::Const(c)) => {
                let width = uint_of_type(&c.ty);
                match width {
                    Some(w) => self.eval(it.module, &c.expr, Some(w)),
                    None => Err(format!("constant `{}` is not of an unsigned integer type", it.name)),
                }
            }
            _ => Err(format!("`{}` is not a constant", it.name)),
        };
        self.stack.borrow_mut().pop();
        self.memo.borrow_mut().insert(id, r.clone());
        r
    }

    /// Evaluates `e` in module `m`; `w` is the expected width (if known).
    pub fn eval(&self, m: ModId, e: &syn::Expr, w: Option<UintTy>) -> Result<u128, String> {
        let check = |v: u128, w: Option<UintTy>| -> Result<u128, String> {
            match w {
                Some(w) if v > w.max_value() => Err(format!("value {v} does not fit in `{}`", w.name())),
                _ => Ok(v),
            }
        };
        match e {
            syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(l), .. }) => {
                let v: u128 = l.base10_parse().map_err(|e| e.to_string())?;
                let lw = UintTy::from_name(l.suffix()).or(w);
                if !l.suffix().is_empty() && UintTy::from_name(l.suffix()).is_none() {
                    return Err(format!("literal suffix `{}` is not allowed here", l.suffix()));
                }
                check(v, lw)
            }
            syn::Expr::Paren(p) => self.eval(m, &p.expr, w),
            syn::Expr::Group(g) => self.eval(m, &g.expr, w),
            syn::Expr::Path(p) if p.qself.is_none() => {
                let segs: Vec<(String, Span)> = p.path.segments.iter().map(|s| (s.ident.to_string(), Span::DUMMY)).collect();
                if segs.len() == 2
                    && let Some(t) = UintTy::from_name(&segs[0].0) {
                        return match segs[1].0.as_str() {
                            "MAX" => Ok(t.max_value()),
                            "MIN" => Ok(0),
                            "BITS" => Ok(t.bits() as u128),
                            other => Err(format!("unsupported constant `{}::{other}`", t.name())),
                        };
                    }
                match self.res.resolve_path_defs(m, &segs, Ns::Value, p.path.leading_colon.is_some(), false) {
                    Ok(Def::Item(id)) if self.res.items[id.0 as usize].tag == ItemTag::Const => self.eval_item(id),
                    Ok(Def::Ext(Ext::IsizeMax)) => Ok(i64::MAX as u128),
                    Ok(_) => Err("only constants may appear in constant expressions".into()),
                    Err(d) => Err(d.msg),
                }
            }
            syn::Expr::Cast(c) => {
                let to = uint_of_type(&c.ty).ok_or("casts in constant expressions must target an unsigned type")?;
                let inner_w = match &*c.expr {
                    syn::Expr::Lit(_) => Some(to),
                    _ => None,
                };
                let v = self.eval(m, &c.expr, inner_w)?;
                Ok(v & to.max_value())
            }
            syn::Expr::Binary(b) => {
                use syn::BinOp::*;
                let shift = matches!(b.op, Shl(_) | Shr(_));
                let l = self.eval(m, &b.left, w)?;
                let r = self.eval(m, &b.right, if shift { None } else { w })?;
                let bits = w.map(|w| w.bits()).unwrap_or(128);
                let v = match b.op {
                    Add(_) => l.checked_add(r).ok_or("overflow")?,
                    Sub(_) => l.checked_sub(r).ok_or("attempt to subtract with overflow")?,
                    Mul(_) => l.checked_mul(r).ok_or("overflow")?,
                    Div(_) => l.checked_div(r).ok_or("attempt to divide by zero")?,
                    Rem(_) => l.checked_rem(r).ok_or("attempt to calculate the remainder with a divisor of zero")?,
                    BitAnd(_) => l & r,
                    BitOr(_) => l | r,
                    BitXor(_) => l ^ r,
                    Shl(_) => {
                        if r >= bits as u128 {
                            return Err("attempt to shift left with overflow".into());
                        }
                        (l << r) & w.map(|w| w.max_value()).unwrap_or(u128::MAX)
                    }
                    Shr(_) => {
                        if r >= bits as u128 {
                            return Err("attempt to shift right with overflow".into());
                        }
                        l >> r
                    }
                    _ => return Err("unsupported operator in constant expression".into()),
                };
                check(v, w).map_err(|_| "arithmetic overflow in constant expression".to_string())
            }
            // `a.div_ceil(b)` (SEMANTICS.md §19, lift.core)
            syn::Expr::MethodCall(mc) if mc.method == "div_ceil" && mc.args.len() == 1 && mc.turbofish.is_none() => {
                let l = self.eval(m, &mc.receiver, w)?;
                let r = self.eval(m, &mc.args[0], w)?;
                if r == 0 {
                    return Err("attempt to divide by zero".into());
                }
                check(l.div_ceil(r), w)
            }
            _ => Err("unsupported constant expression (use literals, constants and integer arithmetic)".into()),
        }
    }
}

/// The unsigned type named by a `syn` type, if any.
pub fn uint_of_type(t: &syn::Type) -> Option<UintTy> {
    match t {
        syn::Type::Path(p) if p.qself.is_none() && p.path.segments.len() == 1 => UintTy::from_name(&p.path.segments[0].ident.to_string()),
        syn::Type::Paren(p) => uint_of_type(&p.elem),
        syn::Type::Group(g) => uint_of_type(&g.elem),
        _ => None,
    }
}
