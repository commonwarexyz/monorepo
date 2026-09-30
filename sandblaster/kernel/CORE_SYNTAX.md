# sandblaster core text syntax

The textual syntax of the kernel's core terms (DESIGN.md §5.12). It is used by
the prelude (`prelude/*.core`), kernel tests, automation tests and
diagnostics. The parser (`src/syntax/parser.rs`) resolves named binders to de
Bruijn indices and names to globals/inductives/constructors of an `Env`; the
printer (`src/syntax/printer.rs`) produces text that parses back to the same
term (checked for every `Term` constructor and for the whole prelude in
`tests/syntax.rs`).

Entry points: `Env::parse_term(names, src)`, `Env::print_term(names, t)`,
`Env::load_core(src, budget)` (parse and check items one at a time),
`syntax::parser::parse_items(env, src)` (parse only), `Env::print_inductive`,
`Env::print_def_decl`.

## Lexical structure

* Identifiers: letters, digits, `_`, `'`; `::` joins path segments
  (`seq::len`, `u32::from_le_bytes`, `Option::Some`).
* `--` starts a comment that runs to the end of the line.
* Integer literals always carry a width suffix: `7u8`, `0xFFu32`,
  `1_000u64`, `3usize`, `42int`, `-5int` (negative only for `Int`). Machine
  literals must be in `[0, 2^w)` (checked by the kernel).
* Unsuffixed numbers appear only in certificates (`[1, -3/4]`), `@12` global
  references, and `arity = 2` / `structural 1`.
* Reserved words: `fun let if then else as return match with using end Sigma
  Type Kind U8 U16 U32 U64 Usize Int Eq refl transport pair fst snd rec delta
  unfold to_body from_body linarith bvrefl absurd axiom inductive def
  structural measure arity _`. (`opaque` and the definition kinds are
  recognized only inside a `def[...]` attribute list and remain usable as
  names.)

## Relevance markers

A leading `.` marks the irrelevant thing (DESIGN.md §5.3):

| form | meaning |
| --- | --- |
| `(.h : P) -> B`, `fun (.h : P) => b` | `Irr` Π / λ binder |
| `f .p` | irrelevant application (`App { rel: Irr }`) |
| `let .h : P = pf; body` | `Irr` let (a fact) |
| `Sigma (x : A), .B` | Σ whose second component is irrelevant |
| `| mk(x, .p) => …`, `mk(a, .pf)` | irrelevant constructor field / argument |
| `rec(a, .h; pf)`, `delta(g; a, .h)`, `axiom[n](a, .h)` | irrelevant parameters of the telescope |

Markers on constructor/`rec`/`delta`/`unfold`/`axiom` arguments are checked
against the declared relevance by the parser. Prim proof slots (after `;`),
`transport`'s equation and `absurd`'s proof are always irrelevant and carry no
marker.

Typing (phase 4, `AUDIT.md` §4): inside an irrelevant position, only the
`.`-bound variables of the *enclosing* context are usable as ordinary terms;
a `.`-binder written inside the position (`fun (.h : P) => …`, `let .h`, a
`.p` match field) is usable only in a further irrelevant position. `.B` in
`Sigma (x : A), .B` and `.p : P` fields must be propositions (`Eq`, `Empty`,
`Π` into / `Σ` of propositions, a single-constructor type of propositions).

## Terms

| Term constructor | syntax |
| --- | --- |
| `Var` | `x` (innermost binding of that name; `_` binders cannot be referenced) |
| `Global` | `seq::len`, or `@12` (by id) |
| `Sort` | `Type`, `Kind` |
| `Pi` | `(x : A) -> B`, `(.h : P) -> B`, `A -> B` (non-dependent, relevant); groups `(x : A) (y : B) -> C` |
| `Lam` | `fun (x : A) (.h : P) => body` |
| `App` | `f a .p b` (juxtaposition, left-associative) |
| `Let` | `let x : A = v; body`, `let .h : P = pf; body` |
| `Sigma` | `Sigma (x : A), B`, `Sigma (x : A), .B` |
| `Pair` | `pair(T, a, b)` (`T` is the Σ type) |
| `Fst`, `Snd` | `fst(p)`, `snd(p)` |
| `Eq`, `Refl` | `Eq(A, a, b)`, `refl(A, a)` |
| `Transport` | `transport(A, a, b, e, y. P, v)` |
| `Ind` | `Bool`, `List(T)`, `Tuple2(A, B)` |
| `Ctor` | `true`, `Nil[T]`, `Cons[T](h, t)`, `Some[U8](x)`; `Ind::Ctor` if the name is ambiguous |
| `Match` | `match s : D(ps) as y return P with \| C1(x, .h) => e1 \| C2 => e2 end` |
| `IntTy` | `U8 U16 U32 U64 Usize Int` |
| `Lit` | `255u8`, `-3int` |
| `Prim` | `#wadd_u32(a, b)`, `#add_u8(a, b; pf)`, `#of_int_u64(i; pf0, pf1)`, `#cast_u8_int(x)` |
| `Rec` | `rec(a, .h)`, `rec(a; decrease_proof)` |
| `Delta` | `delta(g; a, b)` |
| `Unfold` | `unfold(g; a; to_body; v)`, `unfold(g; a; from_body; v)` |
| `Linarith` | `linarith([pf0 : P0, pf1 : P1]; goal; [1, -3/4, 0])` — the certificate is a hint (phase 3): `[]` or a stale certificate is accepted when the kernel's own search finds one (for the stated hypotheses, then with the context's hypotheses); see `INTERFACE_CHANGES.md` |
| `BvRefl` | `bvrefl(T, a, b)` (equality modulo word algebra, DESIGN.md §9.8: accepted iff `a ≡ b` by conversion, or both sides — evaluated transparently: opaque definitions and intrinsics unfold — normalize to the same class in `bvnorm` and agree on every tripwire valuation) |
| `Absurd` | `absurd(T, pf)` |
| `Axiom` | `axiom[and_le_left_u32](a, b)`, `axiom[min_def_le_u8](a, b, .h)`, `axiom[count_ones_def_u64](a)` |
| `Erased` | `_` |

Match arms are written in constructor order and must name the constructor.
Primitive names are `<op>_<width>` (`wadd_u32`, `rotr_u64`, `lt_int`,
`count_ones_u8`, `sat_sub_usize`, `int_to_sat_u16`, `of_int_u32`), casts are
`cast_<from>_<to>`, and the `Int` operations are `iadd isub imul ineg idiv
imod`. Axiom names are `<schema>_<width>` (see `src/axioms.rs`).

### Derived forms (parser only)

Two abbreviations are expanded by the parser; the printer prints the
expansion.

* **Dependent match** (DESIGN.md §7.2): `match s : D(ps) as y return P using
  .e with | C(xs) => body … end` expands to

  ```text
  (match s : D(ps) as y return (.e : Eq(D(ps), s, y)) -> P with
   | C(xs) => fun (.e : Eq(D(ps), s, C[ps](xs))) => body … end) .refl(D(ps), s)
  ```

  so every arm receives the path equation as an irrelevant binder `e`.

* **Conditional**: `if c return R then a else b` is `match c : Bool as _
  return R with | false => b | true => a end`, and `if c as .h return R then a
  else b` is the dependent match on `c` with equation `h : Eq(Bool, c,
  true|false)` in each branch.

## Items

```text
inductive List (T : Type) { | Nil | Cons(head : T, tail : List(T)) }
inductive Tagged (A : Type) { | tag(x : A, .p : Eq(A, x, x)) }

def[prelude] seq::len : (T : Type) -> (l : List(T)) -> Int :=
  fun (T : Type) (l : List(T)) =>
    match l : List(T) as _ return Int with
    | Nil => 0int
    | Cons(h, t) => #iadd(1int, rec(T, t))
    end
  structural 1

def[spec] replicate : (n : Int) -> List(U8) :=
  fun (n : Int) =>
    if #le_int(n, 0int) as .c return List(U8) then Nil[U8] else
      Cons[U8](0u8, rec(#isub(n, 1int);
        pair(Sigma (_ : Eq(Bool, #le_int(0int, #isub(n, 1int)), true)), Eq(Bool, #lt_int(#isub(n, 1int), n), true),
             linarith([c : Eq(Bool, #le_int(n, 0int), false)]; Eq(Bool, #le_int(0int, #isub(n, 1int)), true); [1, 1]),
             linarith([]; Eq(Bool, #lt_int(#isub(n, 1int), n), true); [1]))))
  measure (n)

def[intrinsic, arity = 1] k : (x : U32) -> U32 -> U32 := fun (x : U32) => fun (y : U32) => x

-- An opaque definition (DESIGN.md §5.6): never unfolded by checking or
-- conversion; `delta(sha::compress_spec; s, b)` exposes its defining equation.
def[spec, opaque] sha::compress_spec : (s : Array U32 8usize) -> (b : Array U8 64usize) -> Array U32 8usize :=
  fun (s : Array U32 8usize) (b : Array U8 64usize) => sha::compress s b
```

* `def[<attrs>] <name> : <type> := <body> [structural <param> | measure
  (<term>)]`. The optional attribute list holds, comma-separated, in any
  order and at most once each: a **kind**, one of `exec spec lemma law
  loop_helper ensures prelude intrinsic` (default `prelude`); **`opaque`**
  (`DefDecl.opaque = true`; default transparent); **`arity = <n>`** (default:
  the number of leading λ binders of the body). The printer writes `def[<kind>`,
  then `, opaque` if set, then `, arity = <n>` if it differs from the default.
  `structural` takes a parameter name or its 0-based index; the `measure`
  term is in the scope of the first `arity` λ binder names of the body.
* **Opaque** definitions never unfold in the default (checking) mode of
  evaluation and conversion — not even intrinsics on closed arguments;
  `delta(g; args)` and `unfold(g; args; ..)` state their defining equation
  (one step: recursive calls of an opaque definition stay folded).
  `Env::eval_opaque`/`Env::conv_opaque` (optimizer) and
  `check_residual_equal` ignore the flag and fold exactly the caller's
  opaque set; `bvrefl` normalizes both sides transparently (phase 3), so it
  sees through opaque definitions (this is how a hardware variant is proven
  equal to a loop-containing, hence opaque, portable function).
* Inside a definition body, `rec(...)` refers to the definition itself
  (relevance markers checked against the type's Π binders). A definition
  cannot name itself as a global.
* Inductive field types are in the scope of the parameters and the previous
  fields; the inductive's own name may be used for direct recursive fields.

## Prelude templates

Prelude files (only) may repeat a block per width:

```text
%for W in u8 u16 u32 u64 usize
def[prelude] $w::wrapping_add : (a : $W) -> (b : $W) -> $W := fun (a : $W) (b : $W) => #wadd_$w(a, b)
%end
```

with `$w` (suffix `u32`), `$W` (type `U32`), `$BITS`, `$BYTES` and `$MAX`
substituted (`sandblaster_kernel::expand_templates`).

## Printing

* Binder names are kept unless they clash with a name in scope, a global,
  inductive or constructor name, or a keyword; then a numeric suffix is added
  (`x1`). Unused `_` binders print as `_`; `A -> B` is used for non-dependent
  relevant Π.
* Globals print by name when the name resolves back to them, otherwise as
  `@id`; constructors print unqualified when unambiguous.
* The printer never prints derived forms; `parse(print(t))` is `t` up to
  binder names.

## Examples

```text
-- Must-accept relevance example (DESIGN.md §5.3):
fun (G : (.h : Bool) -> Bool) => refl(Bool, G .true)
  : (G : (.h : Bool) -> Bool) -> Eq(Bool, G .true, G .false)

-- A slice element with its bound proof:
fun (s : Slice U8) (i : Usize) =>
  if #lt_usize(i, fst(s)) as .h return U8 then slice::index U8 s i .h else 0u8

-- A linear-arithmetic fact about a remainder (QMDB shift width):
fun (x : U64) =>
  linarith([]; Eq(Bool, #lt_u64(#rem_u64(x, 8u64; refl(Bool, true)), 8u64), true); [1, 0, 0, 0, 0, 0, 0, 0, 0, 1])
```
