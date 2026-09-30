//! The prelude ("Base", DESIGN.md §6): trusted definitions written in core
//! text (`sandblaster/kernel/prelude/*.core`), embedded in the kernel,
//! loaded and checked by [`crate::api::Env::with_prelude`].
//!
//! The files may use one textual template form, expanded before parsing:
//!
//! ```text
//! %for W in u8 u16 u32 u64 usize
//! def[prelude] $w::wrapping_add : $W -> $W -> $W := fun (a : $W) (b : $W) => #wadd_$w(a, b)
//! %end
//! ```
//!
//! repeats the body once per listed width with `$w` (suffix, `u32`), `$W`
//! (type, `U32`), `$BITS` (`32`), `$BYTES` (`4`) and `$MAX` (`4294967295`)
//! substituted. After each file the prelude items with kernel-level meaning
//! (§5.7 list simplifications, §5.9 array eta) are registered by name; only
//! this loader registers them, and only from the embedded text.

use crate::api::{Env, KernelError, KernelErrorKind};
use crate::term::{DefKind, Width};
use crate::value::Budget;

/// The prelude files, in load order.
pub const FILES: &[(&str, &str)] = &[
    ("base.core", include_str!("../prelude/base.core")),
    ("list.core", include_str!("../prelude/list.core")),
    ("slice.core", include_str!("../prelude/slice.core")),
    ("int.core", include_str!("../prelude/int.core")),
    ("bytes.core", include_str!("../prelude/bytes.core")),
];

fn width_of(s: &str) -> Option<Width> {
    crate::prim::parse_width(s).filter(|w| *w != Width::Int)
}

/// Expand `%for W in ... %end` templates.
pub fn expand_templates(src: &str) -> Result<String, String> {
    let mut out = String::with_capacity(src.len());
    let mut lines = src.lines().enumerate();
    while let Some((i, line)) = lines.next() {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix("%for W in ") {
            let ws: Vec<Width> =
                rest.split_whitespace().map(|w| width_of(w).ok_or(format!("line {}: bad width `{w}`", i + 1))).collect::<Result<_, _>>()?;
            let mut body = Vec::new();
            loop {
                match lines.next() {
                    Some((_, l)) if l.trim_start().starts_with("%end") => break,
                    Some((_, l)) => body.push(l),
                    None => return Err(format!("line {}: unterminated %for", i + 1)),
                }
            }
            for w in ws {
                let bits = crate::prim::bits(w);
                for l in &body {
                    let l = l
                        .replace("$BITS", &bits.to_string())
                        .replace("$BYTES", &(bits / 8).to_string())
                        .replace("$MAX", &crate::prim::max_of(w).to_string())
                        .replace("$W", printer_width(w))
                        .replace("$w", crate::prim::width_suffix(w));
                    out.push_str(&l);
                    out.push('\n');
                }
            }
        } else if t.starts_with('%') {
            return Err(format!("line {}: unknown directive", i + 1));
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    Ok(out)
}

fn printer_width(w: Width) -> &'static str {
    match w {
        Width::U8 => "U8",
        Width::U16 => "U16",
        Width::U32 => "U32",
        Width::U64 => "U64",
        Width::Usize => "Usize",
        Width::Int => "Int",
    }
}

/// Register the prelude items with kernel-level meaning that are present,
/// after checking their shapes.
fn register_known(env: &mut Env) {
    let k = &mut env.known;
    if k.list.is_none()
        && let Some(l) = env.ind_names.get("List").copied()
    {
        let info = &env.inds[l.0 as usize];
        if info.ctors.len() == 2 && info.ctors[0].fields.is_empty() && info.ctors[1].fields.len() == 2 && info.params.len() == 1 {
            k.list = Some(l);
        }
    }
    let get = |n: &str, arity: u32| env.global_names.get(n).copied().filter(|g| env.defs[g.0 as usize].arity == arity);
    k.len = k.len.or(get("seq::len", 2));
    k.index = k.index.or(get("seq::index", 5));
    k.take = k.take.or(get("seq::take", 3));
    k.drop = k.drop.or(get("seq::drop", 3));
    for (i, n) in ["u16::from_le_bytes", "u32::from_le_bytes", "u64::from_le_bytes"].iter().enumerate() {
        if k.from_le[i].is_none() {
            k.from_le[i] = get(n, 1).filter(|g| env.defs[g.0 as usize].kind == DefKind::Intrinsic);
        }
    }
}

/// Load and check the embedded prelude into a fresh environment.
pub(crate) fn load() -> Result<Env, KernelError> {
    let mut env = Env::new();
    let mut b = Budget { steps: 2_000_000_000 };
    for (file, src) in FILES {
        let text = expand_templates(src).map_err(|m| KernelError { kind: KernelErrorKind::IllFormed, message: format!("{file}: {m}") })?;
        crate::syntax::load_with(&mut env, &text, &mut b, &mut register_known)
            .map_err(|e| KernelError { kind: e.kind, message: format!("{file}: {}", e.message) })?;
    }
    Ok(env)
}
