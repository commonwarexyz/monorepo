# sandblaster elaboration semantics (normative)

This document is the **normative** meaning of the sandblaster exec subset and
of its ghost language: it says, construct by construct, which core term
(DESIGN.md §5) the elaborator (`sandblaster/front/src/elab/`) produces
for a checked HIR item. Because the kernel only checks core terms, this
translation is part of the trusted computing base (DESIGN.md §1.1): a wrong
rule here is a wrong program, however many proofs are checked. Every rule is
chosen so that the core term computes what `rustc` computes for the same
source, on every input on which rustc's program does not panic. Panics
(overflow, bounds, division by zero, `unreachable!`) do not exist in core;
each is an **obligation** that must be proven, so the verified program never
panics.

The rules are validated, not only trusted (DESIGN.md §10.3): every construct
has a differential test comparing kernel evaluation with the natively
compiled source (`sandblaster/front/tests/elab_constructs.rs`), and the
QMDB port is evaluated by the kernel on every fixture
(`tests/elab_qmdb.rs`).

Notation: `⟦T⟧` is the core type of a Rust type, `⟦e⟧` the core term of an
expression; `x :Irr A` is an irrelevant binder (erased at runtime, still
type-checked); `holds(b)` abbreviates `Eq(Bool, b, true)`. Core syntax is
the kernel's core text syntax (§5.12); `#op_w(..; p)` is a checked primitive
with proof slot `p`.

Contents: 1 Types · 2 Items · 3 Expressions · 4 Places and assignment ·
5 Blocks, `let`, SSA · 6 Branching (dependent matches, joins, CPS) ·
7 Patterns · 8 Loops · 9 Recursion · 10 Calls, `requires`, methods ·
11 Derived `PartialEq` · 12 `ensures` · 13 Ghost code (13.5 the
specification language: `Nat`, `Seq`, views, refinement, examples) ·
14 Obligations and facts · 15 Hardware · 16 Definitions added by the
elaborator · 17 Reference semantics · 18 Deviations and open points.

---------------------------------------------------------------------------

## 1. Types

| Rust | core `⟦T⟧` |
| --- | --- |
| `bool` | `Bool` (`false` = constructor 0, `true` = 1) |
| `u8`, `u16`, `u32`, `u64`, `usize` | `U8 … U64`, `Usize` (64-bit targets only) |
| `()` | `Unit` |
| `(A,)` / `(A, B, …)` | `Tuple1(⟦A⟧)` (§16) / prelude `TupleN(⟦A⟧, ⟦B⟧, …)` |
| `[T; N]` | `Array ⟦T⟧ N` = `Σ(l : List ⟦T⟧). .Eq(Int, len l, N)` |
| `&[T]` (and the place `[T]`) | `Slice ⟦T⟧` = `Σ(n : Usize). Σ(l : List ⟦T⟧). .SliceOk ⟦T⟧ n l`, where `SliceOk` is `len l = n ∧ n ≤ ISIZE_MAX` |
| `&T` | `⟦T⟧` (shared references are values; there is no `&mut` in the subset) |
| `Option<T>` | `Option(⟦T⟧)` (`None` = 0, `Some` = 1) |
| struct / enum `S<A…>` | an inductive named by the item path `crate::m::S`, parameters `A… : Type`; a struct has one constructor (named like the struct), an enum one per variant in declaration order; fields are relevant and named `f0, f1, …` in declaration order |
| type parameter `T` | a `T : Type` binder (the first binders of every definition that mentions it) |
| SIMD vectors (§9.2) | `Array(lane, lanes)` |
| `Int` (ghost) | `Int` |
| `Prop` (ghost) | `Type` |

The length proof of an array and the `SliceOk` proof of a slice are
irrelevant: two arrays with the same list are equal.

## 2. Items

Items are elaborated in dependency order (callees first; a law after
everything it mentions, a proof after its law). Each item becomes one or
more kernel definitions added to the environment **immediately**, so later
items see them.

* **`const C: T = e`** — `C : ⟦T⟧ := ⟦e⟧` (a `DefKind::Exec` definition
  with no parameters); its obligations are proven in the empty context.
* **exec `fn f<T…>(x: A…) -> R` with `requires P₁…Pₙ`** —

  ```text
  f : Π(T : Type)…. Π(x : ⟦A⟧)…. Π(h₁ :Irr ⟦P₁⟧)…. Π(hₙ :Irr ⟦Pₙ⟧). [Π(h_depth :Irr e ≤ C).] ⟦R⟧
  ```

  Each `requires` is a separate irrelevant binder, elaborated with the
  previous ones as facts (§13). `#[decreases(e, max = C)]` adds the
  irrelevant binder `h_depth : e ≤ C` (§9). The body is elaborated with the
  parameters bound (pattern parameters are destructured as by `let`, §7) and
  these facts in scope: each `requires`, and for every slice-typed
  parameter `s` the bound `len(s) ≤ ISIZE_MAX` (`slice::ok_bound`).
* A method (`impl` block function) is an ordinary function whose first
  parameter is the receiver; its kernel name is `crate::m::S::f`.
* **spec fn, lemma, law, proof** — §13.
* Hardware variants and intrinsic helpers — §15.

A definition whose elaboration fails (an unproven obligation, an
unsupported construct) is replaced by an **opaque placeholder** of the same
type so that its dependents can still be elaborated and reported; the build
fails anyway (the placeholder is never emitted).

## 3. Expressions

Arithmetic follows rustc's debug semantics, with every panic an
obligation (§14):

| Rust | core | obligation |
| --- | --- | --- |
| `a + b`, `a * b` (`uN`) | `#add_w(a, b; p)`, `#mul_w(a, b; p)` | `Overflow`: `a + b ≤ MAX` / `a · b ≤ MAX` (over `Int`) |
| `a - b` | `#sub_w(a, b; p)` | `Underflow`: `b ≤ a` |
| `a / b`, `a % b` | `#div_w(a, b; p)`, `#rem_w(a, b; p)` | `DivZero`: `b ≠ 0` |
| `a << s`, `a >> s` | `#shl_w(a, s'; p)`, `#shr_w(a, s'; p)` with `s' = s as u32` | `ShiftWidth`: `s < bits(w)`; for an amount wider than 32 bits, `s < bits(w)` is proven at the amount's own width (rustc panics on `s ≥ bits` even when `s mod 2³²` is small) |
| `&`, `|`, `^`, `!` (`uN`) | `#and_w`, `#or_w`, `#xor_w`, `#not_w` | — |
| `==`, `!=`, `<`, `<=`, `>`, `>=` (`uN`) | `#eq_w` … `#ge_w` (result `Bool`) | — |
| `+ - *` on `Int` (ghost) | `#iadd`, `#isub`, `#imul` (exact) | — |
| `/ %` on `Int` (ghost) | `let .h :Irr b ≠ 0 = p; #idiv(a, b)` / `#imod` (Euclidean) | `WellFormed`: `0 ≤ a`, `0 ≤ b`; `DivZero`: `b ≠ 0` (§13.5; `a.div_euclid(b)`, `a.rem_euclid(b)` for signed operands need only `b ≠ 0`) |
| `-x` on `Int` | `#ineg(x)` | — |
| `!b`, `a & b`, `a \| b`, `a ^ b`, `==`, `!=` on `bool` | `bool::not`, `bool::and`, `bool::or`, `bool::xor`, `bool::eq`, `bool::ne` (both operands evaluated) | — |
| `a && b`, `a \|\| b` | short circuit, §6: `if a { b } else { false }` / `if a { true } else { b }` | — |
| `==`/`!=` on other types | structural equality (§11): arrays `array::eq`, slices `seq::eq`, tuples/`Option` by components, user types `T::eq` | — |
| `x as uM` from `uN` | `#cast_N_M(x)` (identity if equal; widening exact; narrowing truncates mod 2^M) | — |
| `x as Int` | `#cast_N_int(x)` (exact) | — |
| `b as uN` (`bool`) | `bool::as_uN b` (`false ↦ 0`, `true ↦ 1`) | — |
| integer literal `7u32` | `7u32` (literals always carry their type) | — |
| `e.0`, `s.field` | projection by a `match` on the single constructor | — |
| `S { f: e, … }`, `S(e, …)`, `E::V(..)` | the constructor, fields in declaration order (`..base` is expanded by the front end) | — |
| `(a, b)`, `[a, b, c]`, `[v; N]` | `tupleN(..)`; an array literal is the list with its length proof (`WellFormed`, by evaluation); `[v; N]` is `array::repeat` | — |
| `&e`, `*e` | `⟦e⟧` (references are values) | — |
| unsizing `&[T; N] → &[T]` | `array::as_slice T N a .h` with `h : N ≤ ISIZE_MAX` (by evaluation) | `WellFormed` |
| `a[i]` (array) | `array::index T N a i .h` | `IndexBounds`: `i < N` |
| `s[i]` (slice) | `slice::index T s i .h` | `IndexBounds`: `i < len s` |
| `&s[a..b]`, `&s[a..]`, `&s[..b]` | `slice::range T s a b .h₀ .h₁` (and the one-sided forms via `slice::suffix` / `slice::prefix`) | `SliceRange`: `a ≤ b`, `b ≤ len s` |
| `unreachable!()` | `absurd(⟦T⟧, p)` | `Unreachable`: `Empty` from the facts |

Operands are evaluated left to right (the elaboration is in
continuation-passing style, so the order of `let`s is the order of
evaluation); since every exec expression is pure and total, the order is
observable only through which obligation is attributed to which span.

### 3.1 Proven arithmetic in generated code (E0; DESIGN.md §8.3)

In optimized (phase 3) output, every checked `+`, `-`, `*`, `<<`, `>>` on
`uN` — a primitive `#add_w`, `#sub_w`, `#mul_w`, `#shl_w`, `#shr_w` whose
proof slot the kernel checked — is printed as a call of a helper
`crate::__rt::chk::<op>_<w>(a, b)` (`<op>` one of `add sub mul shl shr`,
`<w>` one of `u8 u16 u32 u64 usize`). For a shift, `b` is the primitive's
amount `s' = s as u32`, printed `s as u32` when `s` is not a `u32`. A
checked compound assignment `P op= v` is printed
`P = { let tN__v: T = v; crate::__rt::chk::<op>_<w>(P, tN__v) };`
(`tN__v as u32` for a shift amount of another width).

* **Meaning** (canonical dialect, DESIGN.md §1.1 item 2). A helper call
  denotes the checked primitive. Generated mode lowers it to `a op b` at
  exactly the helper's operand types (`(uW, uW)`, or `(uW, u32)` for a
  shift): `#op_w(a, b; _)` with an `Erased` slot, operand order kept. The
  compound form lowers to `P op= v`. rustc evaluates it in the order of §4:
  `v`, then the value of `P` (whose indices are pure), then the operation and
  the store. The round trip then requires the operator, the width and the
  operands to match the optimized core at every slot. A wrong operator,
  width or operand order fails it (must-reject R19).
* **Execution.** The helpers are fixed templates in the glue module
  `mod __rt`, printed only with the helpers the code calls. Without
  `debug_assertions` a helper is `<uW>::wrapping_<op>(a, b)`; with them it is
  `a op b`, rustc's checked operator.
  * The kernel checked the slot's proposition for every printed occurrence,
    so the wrapping value is the exact value. The build computes the core's
    value, with no check to pay under `overflow-checks = true`.
  * A correspondence error could only produce a wrong value, never undefined
    behaviour.
  * A debug build keeps the checks (the DESIGN.md §10.3 oracle). For a shift
    amount wider than 32 bits it checks the primitive's slot
    `s as u32 < bits(w)`, which the proven full-width `s < bits(w)` implies.
* **Not printed through helpers:**
  * `/` and `%`, because rustc checks division by zero in every profile;
  * integer methods, which are total;
  * `const` initializers, which rustc evaluates at compile time;
  * phase 1 and phase 2 output.
* `__rt` is reserved: the front end rejects a module-level name `__rt` in
  the source.

## 4. Places and assignment

The subset has no `&mut`. Mutation is **SSA**: an assignment `x = e` binds
a new version of `x` (`let x' = ⟦e⟧`) and later uses of `x` refer to it.

* `x op= e` is `x = x op e` (with the obligations of `op`).
* `a[i] = v` is `a = array::set T N a i v .h` (`IndexBounds`); nested places
  (`a[i][j] = v`, `s.f[i] = v`, `s.f = v`) rebuild the path inside out:
  the inner array is read with `array::index`, updated, and stored back;
  a struct field update rebuilds the constructor with the other fields
  projected.
* `dst[a..b].copy_from_slice(src)` (array `dst`, `src` a slice or array) is
  `dst = array::copy_range T N dst a b src .h₀ .h₁ .h₂` (§16) with the
  `SliceRange` obligations `a ≤ b`, `b ≤ N` and `b − a = len src`,
  matching rustc's panics.

## 5. Blocks, `let`, SSA

`{ s₁; …; sₙ; e }` elaborates the statements in order, each passing its
continuation to the next; the block's value is `⟦e⟧` (or `()`).

* `let p = e;` — `⟦e⟧`, then `p` is matched irrefutably (§7). A simple
  binding `let x = e` is `let x : ⟦T⟧ = ⟦e⟧; …` unless `e` is itself a
  variable (then `x` aliases it). For a slice-typed binding the fact
  `len x ≤ ISIZE_MAX` is added.
* `let p = e else { diverge };` — a two-row match: `p ⇒ rest`,
  `_ ⇒ diverge` (the `else` block ends in `return`, §6).
* An expression statement `e;` evaluates `e` for its obligations and
  discards the value.
* `proof! { … }` — ghost statements (§13.3); they add facts, never values.

## 6. Branching

Every branch point is a **dependent match** (DESIGN.md §7.2):

```text
(match c as y return Π(e :Irr Eq(D, c, y)). A with
 | K₁ x… ⇒ λ(e :Irr Eq(D, c, K₁ x…)). ⟦branch₁⟧ …) .refl(D, c)
```

so each branch has its **path equation** as a fact (`e` is relevant in
proof mode, §13). `if c { a } else { b }` matches on `c : Bool` (arm
`false` = else branch). `&&`, `||` and `?` are expressed through `if`/
`match`. In ghost code (spec functions, contracts, proof statements) a
chain of one operator with five or more operands is elaborated right-nested
whatever its parse (`(((a && b) && c) && d) && e` as `a && (b && (c && (d
&& e)))`: the same value and order of evaluation), so
every test branches on an operand, never on the value of an inner chain.
Exec function bodies keep the source's nesting (their terms are what the
code generator prints).

Two shapes are used; both denote the same function because the
continuation is pure:

* **CPS**: the continuation (the rest of the enclosing computation) is
  elaborated inside every branch. Used when a branch contains `return` or
  `?` (the rest of the block moves into the non-returning branches; a
  `return e` is `⟦e⟧` as the value of the whole function body) and when
  the construct assigns locals of the enclosing scope (so the code after it
  sees each branch's values under that branch's path condition), up to 8
  nested duplications on one path.
* **Join**: otherwise (and beyond that bound), each branch ends in the
  *join value* — the branch value tupled with the new versions of the outer
  locals it assigns — and the match is bound once, `let j = match …;`, the
  tuple destructured, and the continuation elaborated once.

`e?` on `Option<T>` is `match e { Some(x) ⇒ x, None ⇒ return None }`
(CPS). `return e` in a function with `ensures` is still just the value
(§12).

## 7. Patterns

Matches compile to nested single-level core matches (a decision tree over
the columns of the pattern matrix) with **first-match** semantics:

* or-patterns are expanded into consecutive rows, left alternative first,
  nested or-patterns as a cross product (the normative expansion of §7.3,
  `canon::expand_or_arms`, shared with the printer);
* a guard `p if g ⇒ e` compiles to `if g { e } else { <the remaining rows> }`
  after the pattern matched — rustc's semantics, where the guard is tried
  for each alternative in order;
* constructor patterns (`Some(p)`, `E::V(..)`, `S { .. }`, tuples,
  `true`/`false`) match on the constructor; a single-constructor type is
  projected instead;
* integer literal and range patterns (`3`, `1..=9`, `..=4`) are
  comparisons (`#eq_w`, `#le_w`) in a chain of `if`s, in row order;
* array patterns `[a, b, c]` read the elements with `array::index`;
  slice patterns `[a, .., z]`, `[x, rest @ ..]` test the length with a chain
  `len = 0`, `len = 1`, …, `len ≥ K` (`K` the longest fixed prefix+suffix),
  read elements from the start or the end with `slice::index`, and bind the
  rest as a subslice (`slice::range` / `slice::suffix` / `slice::prefix`,
  an array rest as `slice::prefix_array`);
* bindings bind the matched value (by value; `ref`/`&` are erased); a
  binding with a subpattern binds and continues;
* a match that falls off the end is impossible: its last row's failure
  branch is `absurd` with an `Unreachable` obligation, provable from the
  path equations (the front end checked exhaustiveness).

## 8. Loops (normative desugaring, DESIGN.md §7.4)

A loop becomes a **helper definition** `f::loop#k` (numbered in source
order within `f`) and a call. Its parameters are, in order: the type
parameters of `f`; the loop variable `i` (for `for`); `done : Bool` (for
`a..=b`); the locals **mutated** in the loop; the locals **read** (including
those in the bounds). Its irrelevant `requires` are: the range facts
(`lo ≤ i`, `i < hi` or `i ≤ hi`), every fact in scope at the loop head that
mentions only the parameters (renamed), and the user invariants. It returns
the tuple of the mutated locals (`Tuple1` for one, `Unit` for none).

* `for i in a..b { B }` ≡ `if a < b { f::loop#k(a, M…, R…) } else { M… }`;
  the helper body is `B`, then `let i′ = i + 1` (checked: `Overflow`), the
  invariants at `i′` for `M′` as facts `h_next` (below), then `if i′ < b {
  rec(i′, M′…, R…) } else { M′… }`. Measure: `b − i` (as `Int`).
* `for i in a..=b { B }` ≡ `if a <= b { f::loop#k(a, false, M…, R…) } else
  { M… }`; the helper body is `if done { M… } else { B; if i < b {
  rec(i + 1, false, M′…) } else { rec(i, true, M′…) } }` — mirroring
  `RangeInclusive`, never computing `b + 1`. Measure `(b − i) + (done ? 0 :
  1)`. The invariants are required as `done = false → inv` (the final call
  with `done = true` runs no iteration); in the `done = false` branch they
  are facts.
* `while c { B }` with `proof! { decreases(e); }` ≡ `f::loop#k(M…, R…)`;
  body `if c { B; rec(M′…) } else { M… }`; measure `e`. A `while` without
  `decreases` is rejected by the front end.
* A read local defined by a `let` whose definition is proof-free (e.g.
  `let k = n.min(xs.len())`) contributes the fact `k = def` to the helper
  (its locals become read parameters too); mutated locals never do.
* `invariant(p)` (first statement of the loop body) is proven at the entry
  call (`InvariantEntry`), at every recursive call (`InvariantPreserve`)
  and at the exits (`InvariantExit`, in the post-loop lemma, §12); inside
  the body it is a fact. For `a..b` the invariants at `i + 1` are proven
  once, before the branch on `i + 1 < b` (`InvariantPreserve`, each on its
  own), and bound as facts `h_next` that the recursive call and the exit
  both use: together that is exactly preservation (`i + 1 < b`) and exit
  (`i + 1 = b`). An invariant whose statement or proof fails there (one
  that needs `i + 1 < b`) is proven at the recursive call instead, and its
  exit failure is reported as such.
* The measure must decrease at every recursive call (`Termination`,
  discharged by linear arithmetic from the loop facts).
* The bounds are evaluated once, before the loop (they are helper
  parameters); a bound that depends on a local mutated in the loop is
  rejected.
* **Nothing** is asserted after the loop about `a` and `b`. The
  invariants hold after the loop at the exit index (and `c` is false after
  `while`), by the post-loop lemma `f::loop#k::ensures` bound at the call
  site (§12).
* A function containing loops is an **opaque** definition (not unfolded by
  conversion; evaluation still runs it), which keeps the kernel from
  unfolding helpers during checking.

`return` and `?` inside loops are rejected by the front end.

## 9. Recursion (DESIGN.md §3.7, §5.6)

* A self-recursive function is a kernel definition with **measure
  recursion**: the recursive call is `rec(args; p)` where `p` proves that the
  measure decreases (`Termination`), as a pair `0 ≤ m(args) ∧ m(args) <
  m(params)` for `Int` measures.
* The measure is `#[decreases(e)]`, or inferred: a parameter `n` recursed on
  as `n − k` under a path condition implying `n ≥ k` (measure `n`), a
  slice parameter recursed on as a rest binding of a slice pattern (measure
  `len`), or a parameter of a recursive spec type recursed on as a field
  bound by a pattern (measure `T::size'`, §13.9). Otherwise the function is
  rejected ("add `#[decreases(e)]`"). An induction proof uses the same
  rules, or its `#[decreases(e)]` when it has one; `#[induction(n)]` on a
  `Nat` or `Int` parameter `n` without `#[decreases]` has the measure `n`.
* Tail recursion is printed as a loop by the code generator; its semantics
  is the same recursive definition.
* `#[decreases(e, max = C)]` (non-tail recursion, `C ≤ 4096`) adds
  `h_depth : e ≤ C` to the function type; every call from outside the
  function proves it (`StackDepth`), recursive calls carry it along.
* **Stack assumption (TCB).** The emitted code runs on a thread with at least
  2 MiB of stack (the Rust default for spawned threads); the validator
  (`validate::check_stack`) guarantees that every verified call tree uses at
  most 1 MiB under its conservative frame model (`depth × frame + max callee
  stack`, `frame = 2 × (parameters + result + locals + one temporary per
  expression) + 256 bytes`). Stack exhaustion is therefore outside the
  semantics only under that stated assumption (DESIGN.md §3.7).

## 10. Calls, `requires`, methods

* A call `g(a…)` to a user function applies `g` to the type arguments, the
  arguments, and one proof per `requires` of `g` instantiated with the
  arguments (`CalleeRequires(g)`), plus `h_depth` when `g` has
  `decreases(…, max)`. The obligation targets are obtained by **substitution
  into `g`'s type**, never by quoting values.
* Builtin methods (§3.4) map to prelude definitions (`u32::rotate_left`,
  `slice::split_at`, `option::unwrap_or`, …); `wrapping_*`, `saturating_*`,
  `checked_*`, `rotate_*`, `count_ones`, `leading_zeros`, `trailing_zeros`,
  `swap_bytes`, `to_be_bytes`/`to_le_bytes`/`from_be_bytes`/
  `from_le_bytes`, `min`, `max`, `is_power_of_two`, `abs_diff`, `len`,
  `is_empty`, `first`, `last`, `get`, `split_at`, `split_at_checked`,
  `split_first`, `split_last`, `split_first_chunk`, `first_chunk`,
  `as_chunks`, `as_slice`, `is_some`, `is_none`, `unwrap_or`. Methods with
  a precondition carry it as an obligation (`split_at`: `mid ≤ len`;
  `as_chunks::<N>`: `N > 0`, discharged by evaluation).
* **Method facts** (§3.4): after a call to `as_chunks::<N>`, the fact
  `len(rest) < N` (`fact::as_chunks_rest_lt`, §16) is added.
* A call to a function of the target semantics (§15) is an application of
  the corresponding core definition.

## 11. Derived `PartialEq` (DESIGN.md §7.7)

For a user type deriving `PartialEq`, `crate::m::S::eq : Π(A : Type)….
Π(eq_A : A → A → Bool)…. S → S → Bool` is defined structurally: for a
struct, the conjunction (`bool::and`) of the field equalities in declaration
order; for an enum, a nested match on both constructors — `false` for
different constructors, the field conjunction for equal ones. Field
equality is `#eq_w` for integers, `bool::eq`, `array::eq`/`seq::eq` with the
element equality, the component equalities for tuples and `Option`, and
`T::eq` (with its parameter equalities) for user types. `a == b` on such a
type is `S::eq A… eq_A… a b`.

For a non-generic type whose fields are integers, `bool`, integer arrays or
types with these lemmas, the elaborator also proves (checked lemmas,
untrusted):

```text
S::eq_sound    : Π(a b : S)(.h : Eq(Bool, S::eq a b, true)). Eq(S, a, b)
S::eq_complete : Π(a b : S)(.h : Eq(S, a, b)). Eq(Bool, S::eq a b, true)
```

(`eq_sound`: a double match on `a` and `b`; different constructors make
`h` `false = true`; equal ones split `h` with `bool::and_left/right`, apply
the field lemmas and rebuild the constructor by transports.
`eq_complete`: `S::eq a a = true` by a match on `a`, transported along
`h`.) They are registered for automation by name.

## 12. `ensures` (DESIGN.md §7.3)

For `#[ensures(|ret| Q)]` on `f`, the elaborator adds

```text
f::ensures : Π(T…)(x…)(h : P…). ⟦Q⟧[ret := f T… x… h…]
```

with **relevant** hypotheses (it is lemma-like and only used in irrelevant
positions; for `decreases(.., max)` the stack-depth hypothesis is included,
so the telescope matches `f`'s). It is proven by walking the body of `f`:
`let`s are mirrored, a join `let j = M; j` walks `M`, and every dependent
or plain `match` is mirrored by a match on the same scrutinee whose motive
is `Q[ret := the body's match on y]`, so that in each arm the goal computes
to `Q[ret := arm]`; at each tail value `v` the prover proves `Q[x, v]`
(`Ensures`) in that branch's context. For a recursive `f`, `f::ensures`
is measure-recursive with `f`'s measure: the proof starts with
`transport(…, sym(delta(f; x h)), …)`, and every call `f a…` in a tail
value gets the induction hypothesis `rec(a…; p) : Q[a…, f a…]` as an
irrelevant fact (its `Termination` obligation `p` proven in the branch).

At every call of a function with a checked `ensures`, the fact
`g::ensures T… a… p… : Q[a…, g a… p…]` is added after the call
(`CalleeEnsures`). A function containing loops is opaque (§8), so its
`ensures` proof also starts with the `delta` transport.

### 12.1 Post-loop lemmas (DESIGN.md §7.4)

A `for` loop with invariants, and every `while` loop, has a lemma about its
helper `H = f::loop#k` (§8). Its **post-state statement** `Post(v)` says
what holds of a result `v` of `H` (the mutated locals `M := v`):

* `for i in a..b`: the invariants at `i := b`;
* `for i in a..=b`: the invariants at `i := b + 1` — stated exactly over
  `Int` when they mention `i` only as `i as Int` and need no obligation
  (`(i as Int) := (b as Int) + 1`, also for `b = MAX`), otherwise under the
  premise `b < MAX` (`Π(hm : b < MAX). let i = b + 1; …`); invariants that
  do not mention `i` hold unconditionally;
* `while c`: the invariants and `¬c` at the exit state: `c = false` for a
  simple condition; `a = true → ¬b` for `a && b` (`b` runs only when `a`
  holds, so its operations are defined), `a = false ∧ ¬b` for `a || b`, `x
  = true` for `!x`; left out when the condition has another branching form
  or one of its partial operations is not provably defined there.

Only **propositions** in the kernel's sense are stated (their proofs carry
no information: equations, `Π`, `Σ` of propositions, `Unit`, `Empty`,
after unfolding `Not`, `And`, `Iff` and spec predicates), because the
lemma's statement is a squash (below). A disjunction `p ∨ q` is stated in
its implication form `p′ → q` (`p′` = `t = !c` when `p` is the boolean
equation `t = c`, as in `found == false || xs[pos] == key` ↦ `found ==
true → xs[pos] == key`; else `Not(p)`; nested for `p ∨ q ∨ r`); it is
proven as the disjunction and converted. Any other invariant (`exists`, an
opaque predicate) is not stated after the loop.

The conjuncts form a dependent conjunction; their partial operations are
obligations at the exit state — a failure is reported as `InvariantExit`
(the invariant must be defined after the last iteration), and an earlier
conjunct is a fact for them only when it is needed. `for` statements are
elaborated with the binders `z : W` (the index, printed `i_exit`), `ret`
and `hz : z = b`, so that `Post` at another index can be moved to `b` by a
transport along an equation (a `WellFormed` obligation).

```text
f::loop#k::ensures : Π(T…)(i)[(done)](M…)(R…)(h :Irr requires…)[(hd :Irr done = false)].
                       Squash(Post(H T… i [done] M… R… h…))
Squash(P) = Σ(_ : Unit) ×Irr P
```

The hypotheses are `H`'s own, irrelevant; `a..=b` adds `done = false`. The
squash carries the proof of `Post` in an irrelevant position, so every
conjunct is proven irrelevantly, with every fact usable (the hypotheses are
irrelevant). The lemma is proven by walking `H`'s body like `f::ensures`
(irrelevant `let`s are abstract in the walk: their proofs are never
unfolded), measure-recursively with `H`'s measure, after `transport(…,
sym(delta(H; …)), …)`:

* at an exit of `a..b` (after the iteration `i`, `¬(i + 1 < b)`),
  `Post(M′)` is proven at `i + 1` — each invariant an `InvariantExit`
  obligation, first from the proof the recursive call in the other branch
  uses (the fact `h_next`, §8: the obligation is recorded as proven by
  `reuse`), else by the prover with `hz : i + 1 = b` as a fact — and moved
  to `b`;
* at the exit of `while` (`c == false`), `Post(M)` directly
  (`InvariantExit`);
* the final call `H(i, true, M′)` of `a..=b` (in the branch `¬(i < b)`)
  unfolds to `M′` by `delta`; `Post(M′)` is proven at `i` and moved to
  `b`; the `done` branch contradicts `hd`;
* every other recursive call `H a…` is the induction hypothesis
  `rec(a… [refl]; p)` (its `Termination` obligations re-proven);
  `unreachable!()` keeps its proof of `Empty`.

A **generated** conjunct — `¬c` of `while`, the implication form of a
disjunction — that the prover cannot prove at the exit is left out and the
lemma built again, with a warning; it never fails the build. A written
conjunct that fails does.

At the call site, after the join `let loop = J` (named after the local when
the loop assigns one) and the destructuring of the mutated locals, the fact

```text
h_loop :Irr [a ≤ b →] Post(J)        (J: the join value, `loop` by definition)
```

is bound (`FactOrigin::Invariant`). The committed `let` states it about
`J` (the clone equality proofs of the optimizer rely on that, §18); the
elaboration context states the same, convertible, fact about the
destructured locals, `Post((x₁, …, xₙ))`, as an abstract binder: goals
after the loop read back the locals rather than `J`, and a later loop that
reads the locals gets the fact among its helper's requires (§8). It is
proven by mirroring `J` = `if a < b { H(a, …) } else { M }` into a squash
and opening it (`snd`, outside the match): the lemma applied to `H`'s
arguments in the `true` arm; in the `false` arm (the empty range) `Post(M)`
proven at `a` (each invariant an `InvariantExit` obligation, first from the
entry proof of the `true` arm, with `hz : a = b`) and moved to `b`. The
premise `a ≤ b` (inside the squash) is left out when `a` is the literal
`0` or `a ≤ b` holds by evaluation. For `while` the fact is `snd` of the
lemma applied to the call's arguments. A `for` loop without invariants has
no lemma. In generated mode (the round trip, DESIGN.md §8.3) the checked
lemma is recorded unchanged and no fact is bound.

`f::ensures` (§12) uses these irrelevant facts too: when the relevant proof
of a tail goal fails and the goal is a proposition built from equations
(e.g. a conjunction), it is proven irrelevantly and promoted.

Nothing comes for free: the lemma is kernel-checked and applied to the
entry proofs, so an invariant that fails at entry, preservation or exit
fails the build; if the helper or the lemma does not check, no fact is
bound.

## 13. Ghost code (DESIGN.md §4)

### 13.1 Propositions

In a proposition position (`requires`, `ensures`, `invariant`, `assert`, law
bodies, `-> Prop` spec functions):

| ghost | core |
| --- | --- |
| `a == b`, `a != b` | `Eq(⟦T⟧, a, b)`, `Not(Eq(⟦T⟧, a, b))` |
| `p && q` | dependent conjunction `Σ(h : ⟦p⟧). ⟦q⟧` (`h` is a fact while elaborating `q`) |
| `p \|\| q`, `!p`, `iff(p, q)` | `Or`, `Not`, `Iff` |
| `implies(p, q)` | `Π(h : ⟦p⟧). ⟦q⟧` |
| `forall(\|x: T\| p)`, `exists(\|x: T\| p)` | `Π(x : ⟦T⟧). ⟦p⟧`, `Exists ⟦T⟧ (λx. ⟦p⟧)` |
| a `bool` expression `b` | `Eq(Bool, ⟦b⟧, true)` |
| `if`/`match` in a proposition | a dependent match returning `Type` |

Operands are exec expressions (§3), so machine arithmetic in a proposition
has its own obligations (write `x as Int` for exact arithmetic). The
contract facts of a call in a proposition (the callee's `ensures` and
refinement, §10, §12) are available to those obligations but are not part
of the proposition: a statement never contains a lemma (§15 S3; a law about
`f` means the same for every implementation of `f`, §13.7).

### 13.2 Spec functions, lemmas, laws, proofs

* `#[spec] fn` — a definition like an exec function (`DefKind::Spec`); a
  `-> Prop` spec function returns a `Type`. A ghost `const` (a spec
  constant) is a `DefKind::Spec` definition too. (§13.5: `Nat` guards.)
* `#[lemma] fn` — `Π(params)(h : requires…). ensures` with **relevant**
  hypotheses; its body is a script (§13.4).
* `#[law] fn` — a claim; with an inline proof or a `#[proof]` item of the
  same name, the proof script is elaborated against the law's statement
  (`LawGoal`); a recursive call in the proof is the induction hypothesis
  (measure recursion). A law **without** a proof is an **open claim**: it is
  reported and the build fails.

### 13.3 `proof!` in exec code

`assert(p)` proves `p` (`Assert`) and adds it as a fact; `let`, `apply`
(lemma application: its `requires` become obligations, its `ensures` a
fact) and `show()` are allowed; facts are irrelevant lets.

### 13.4 Scripts

`assert`, `apply`/`lemma(args)`, `let`, `show`, `todo` (fails), `exact(t)`,
`bv()` (`BvRefl`), `witness(e…)`, `unfold(f)` (`Delta` + transport, or
the body substituted for a transparent `f`; then every irrelevant `let` of
the unfolded goal whose type and value mention only the script's context —
a callee's `h_ens`/`h_ref`, slice bounds — is hoisted out of the goal into a
fact of the script, its variable replaced by the fact: ζ, convertible),
`rewrite(h)`/`rewrite_rev(h)`, `match` (case analysis with the path
equation; the goal is refined by abstracting the scrutinee), `if`, `cases`.
At the end of a script the prover must close the remaining goal.

### 13.5 The specification language (DESIGN.md §4.1, §15; stage S1)

**Ghost types.** `Int` ↦ `IntTy(Int)`; `Nat` ↦ `IntTy(Int)` (below);
`Seq<T>` ↦ `List(⟦T⟧)` (the prelude list, unbounded: no `ISIZE_MAX`).

**`Nat`.** An `Int` whose bound `0 ≤ n` is established where a value is
built and assumed where one is bound:

| construction | core |
| --- | --- |
| an unsuffixed literal in ghost code (the default without an expectation) | the `Int` literal |
| `a + b`, `a * b`, `a / b`, `a % b` on `Nat` | `#iadd` … `#imod` (`/`, `%`: obligation `b ≠ 0`) |
| `a - b` on `Nat` | `let .h_nat : holds(#le_int(b, a)) = ⟨obligation⟩; #isub(a, b)` |
| `x as Nat`, `x : uN` | `#cast_w_int(x)` |
| `i as Nat`, `i : Int` | `let .h_nat : holds(#le_int(0, i)) = ⟨obligation⟩; i` |
| `n as Int`, the view `Nat ↦ Int` | `n` |
| `xs.len()`, `a.saturating_sub(b)`, `a.min(b)`, `a.max(b)` | `seq::len`, `if b ≤ a { a − b } else { 0 }`, … |

Every `Nat` built by ghost code therefore denotes a non-negative integer,
and every `Nat` a statement quantifies over is bounded by a hypothesis
(below). A
parameter of a **lemma, law or proof** of type `Nat` gets the relevant
hypothesis `h_natᵢ : holds(#le_int(0, xᵢ))` after the parameters (callers
prove it, like a `requires`). A **spec function** instead guards its body
per `Nat` parameter: `if 0 ≤ n { body } else { d }` with the default `d` of
its result type (`0`, `Nil`, the first constructor, `Unit` for `Prop`), so
the body has the fact `0 ≤ n` (for `n - 1` under `n != 0`, for measures)
while its kernel type has no hypothesis and calls carry no proofs (case
splits and rewrites over an argument keep well-typed motives). Because every
`Nat` argument is non-negative, the guard never changes a value.
Quantified `Nat`s: `forall(|n: Nat| p)` ↦ `Π(n : Int). Π(h : holds(0 ≤ n)).
⟦p⟧`, `exists(|n: Nat| p)` ↦ `Exists Int (λn. Σ(h : holds(0 ≤ n)). ⟦p⟧)`.
The `Nat` **components** of a parameter or quantified variable — the
fields of a struct and the components of a tuple, recursively — are guarded
(spec functions, a few levels deep) or hypotheses (`h_natᵢ_k`: lemmas, laws,
proofs, quantifiers) exactly like a `Nat` parameter (S2). They are not part
of the kernel type: a spec value carries no proof, so case analysis and
rewriting can generalize over its fields.

`Nat`s inside a **container** — the elements of a `Seq`, array or slice,
the payload of an `Option` or of an enum variant, at any depth — are bounded
by one well-formedness hypothesis per such component (`Elab::nat_bounds`):
`ghost::seq_all ⟦T⟧ (λv. wf_T v) l` for a sequence with list `l`
(§16: `seq_all T p Nil = Unit`, `seq_all T p (Cons(x, t)) = And (p x)
(seq_all T p t)`), `match o { None => Unit, Some(v) => wf_T v }`, `match e {
C_i(x̄) => wf(x̄) }`, where `wf_T v` is the `Σ` of `v`'s own bounds (`Unit`
for none). Quantified variables get them like `h_nat` (a `Π` for `forall`,
a `Σ` conjunct for `exists`), and so do the parameters of a **law** and its
proof: the kernel statement then quantifies over exactly the values the
source types allow, in every position (a `forall` in a `requires`, an
`exists` in an `ensures`). So do the parameters of a **lemma** whose
`requires`/`ensures` quantify over a type holding `Nat`s in a container
(the parameter can then be a witness or an instance of the quantifier);
callers prove them like a `requires`. Other lemmas' parameters get only the
plain bounds: without the well-formedness hypothesis the kernel statement
holds for every `Int` inside the container, which is stronger than the
source's reading (sound either way), so callers prove nothing more. A spec function's parameters are
not guarded inside containers: its value at a well-formed argument is the
source's value. A `Nat` inside a **recursive** type (an enum that contains
itself) has no finite well-formedness term: a quantified variable or law
parameter of such a type is an error (write `Int` and state the bound).

**Size limit.** Ghost `Int` values are exact up to the kernel's
implementation limit of 4096 bits (DESIGN.md §5.7): a value beyond it is
`EvalError::IntOverflow`, never a wrapped value. A proof that makes the
kernel compute such a value (`pow2(5000)` by evaluation) is not elaborated
and is reported as exceeding the limit.

**`Int` division and truncation.** `a / b`, `a % b` on `Int` are
`#idiv`/`#imod` with the obligations `0 ≤ a`, `0 ≤ b` (well-formed) and
`b ≠ 0` (then truncating and Euclidean division agree); `a.div_euclid(b)`,
`a.rem_euclid(b)` need only `b ≠ 0`. `x as uN` for `x : Int | Nat` is
`#of_int_w(#imod(x, 2^N))` — truncation mod `2^N`, exactly like exec `as`.

**`Seq<T>`** (`l : List(⟦T⟧)`):

| ghost | core |
| --- | --- |
| `xs.len()` | `seq::len T l` |
| `xs[i]` (`i : Nat`) | `seq::index T l i .p₀ .p₁` (obligations `0 ≤ i`, `i < len`) |
| `xs.get(i)` | `ghost::seq_get T l i` (`None` out of range) |
| `xs.take(n)`, `xs.skip(n)` | `seq::take T l n`, `seq::drop T l n` |
| `xs.chunks_exact::<N>()` | `seq::chunks T N .refl l` (the remainder dropped) |
| `xs.flatten()` | `ghost::arrays_flatten T N l` (`Seq<[T; N]>`), `ghost::seq_flatten T l` (`Seq<Seq<T>>`) |
| `xs.to_array::<N>()` | `pair(Array T N, l, ⟨obligation len l = N⟩)` |
| `Seq::repeat(x, n)`, `Seq::empty()`, `Seq::cons(x, xs)` | `seq::replicate T n x`, `Nil[T]`, `Cons[T](x, xs)` |
| `xs.append(ys)`, `xs.update(i, x)`, `xs.rev()` | `seq::append`, `seq::update`, `seq::rev` |
| `seq![a, ..xs, b]` | `Cons(a, append(xs, Cons(b, Nil)))` (right fold) |
| `b"abc"`, `hex!("61 62 63")` | the `[u8; N]` array literal |
| a pattern `[]`, `[p, ps.., rest @ ..]` | a match on `Nil` / `Cons(head, tail)`, `p` on the head, `[ps.., rest @ ..]` on the tail (prefix patterns only) |

`ghost::seq_get`, `ghost::seq_map`, `ghost::seq_flatten`,
`ghost::arrays_flatten` are the ghost-language library (§16).

**The view coercion** `α(from ↦ to)` (`Coercion::View`; ghost code only,
inserted by the typechecker where types differ and in the operands of
ghost `==`/comparisons): identity on equal types and through `&`; `Nat ↦
Int` identity; `uN ↦ Nat | Int` is `#cast_w_int`; `&[T] ↦ Seq<U>` is
`fst(snd(s))` mapped by `ghost::seq_map (λv. α v)` when `T ≠ U`; `[T; N] ↦
Seq<U>` is `fst(a)` (mapped); `Seq<T> ↦ Seq<U>` mapped; `Option`/tuples
componentwise by `match`/projections; a type with `#[view]` is `T::view x`
followed by the coercion of the view type (element-wise views of arrays are
rejected: view them as `Seq`).

**Views and representation relations.** `#[view(|s| e)]` on `T` is the
definition `T::view : Π(A..). T(A..) → ⟦typeof e⟧ := λs. ⟦e⟧`; the
structural `#[view(spec::U)]` is `λs. U(α(π₁ s), …)` field by field (by
name, through the field coercions). `#[represents(|s: &S, a: A| P)]` is
`S::represents : Π(A..). S → ⟦A⟧ → Type := λs a. ⟦P⟧`. All three are
`DefKind::Spec` definitions (spec items: spec closure applies).

**Refinement** (`f::refines`, `DefKind::Ensures`, obligations `refines`;
DESIGN.md §15.2): for `#[refines(s)]` on `f` with telescope `Π(T..)(x̄)(h̄ :
Req_f)[(h_depth)]`:

    f::refines : Π(T..)(x̄)(h̄ : Req_f x̄)[(h_depth)][(h_domain : P x̄)].
                   Eq(⟦V⟧, α_R(f x̄ h̄), s(ᾱ x̄; p̄))

`ᾱ x̄` are the positional coercions of the parameters (or the explicit
argument map, coerced by the typechecker), `V` the spec's result type,
`α_R` the result coercion, and `p̄` the proofs of `s`'s `Irr` binders
(`requires`) — obligations in the context of `Req_f` and the domain, never
hypotheses. Methods of a struct with `#[represents]` use the simulation form:
a constructor-like method proves `S::represents ret (s(ᾱ x̄))`; a method with
`self` has the extra hypotheses `(a : ⟦A⟧)(h_rep : S::represents self a)`
and proves `S::represents ret (s(a, ᾱ x̄'))` (`S → S`), `Σ(_ :
S::represents π₀ret π₀s(..)). Eq(⟦V⟧, α(π₁ret), π₁s(..))` (`S → (S, R)`),
or `Eq(⟦V⟧, α(ret), s(a, ᾱ x̄'))`. The proof walks `f`'s body like
`f::ensures` (§12; with the path equation `s = C(f̄)` of every projection
in scope, so hypotheses about the fields meet the field binders), with the
induction hypotheses of recursive calls (not in the domain and simulation
forms), or is the script of the `#[proof(refines = f)]` item. At every call
of `f` the lemma applied to the call's arguments is the fact `h_ref`
(binders past `f`'s own stay in its type); its instantiated statement is
re-certified (§14).

**Examples** (DESIGN.md §15.7). `#[example(e)]` on `X` is the lemma
`X::example#k : holds(⟦e⟧) := refl(Bool, true)` when checking-mode
conversion decides `⟦e⟧ ≡ true` (budget 5·10⁷ steps); otherwise
`Env::eval_closed(⟦e⟧)` (AUDIT.md §20) must return `true` within the
example budget (4·10⁹ steps): the verdict is the kernel's, and an
exhausted budget is an error. A vector record is `c(v̄; p̄)` for the checker
`c` applied to the record's values (`Nat`/`Int`/`uN` decimal or `0x`; bytes
hex; `bool`), `p̄` the proofs of `c`'s `requires` (obligations), decided the
same way (`c::example#fileJ#k`).



* **Facts** are context entries: irrelevant `let`s and irrelevant λ
  binders (the parameters' `requires`, path equations, invariants, carried
  loop facts, method facts, asserts). No extra machinery is needed for
  shifting or match refinement.
* An **obligation** is a goal (context, facts, target proposition) handed
  to the prover chain (DESIGN.md §8.1: the development prover, then
  `auto`); the returned term is re-checked by the kernel immediately and
  inserted in the proof slot. The kernel checks the whole definition again
  when it is added. An obligation whose target is closed by evaluation
  (both sides convert) gets `refl` directly.
* Kinds: `Overflow`, `Underflow`, `DivZero`, `ShiftWidth`, `IndexBounds`,
  `SliceRange`, `CalleeRequires(g)`, `Unreachable`, `InvariantEntry`,
  `InvariantPreserve`, `InvariantExit` (§12.1), `Termination`, `StackDepth`, `Ensures`, `LawGoal`,
  `Assert`, `VariantEquiv`, `WellFormed` (length proofs of literals, slice
  bounds of ghost sequences, range facts of loop helpers, the `Int`
  division and `to_array` side conditions), `Refines` (§13.5; the goals of
  `f::refines`), `TypeInvariant` and `ViewInjective` (§13.6).
* There is **no** way to skip an obligation: an unproven obligation is a
  build error with the goal, the facts and what the provers tried.

### 13.6 Types that carry invariants; ghost parameters (DESIGN.md §15.3; stage S2)

**Invariants.** `#[invariant(p)]` on `struct S<T..> { f̄ }` (several
attributes conjoined) is part of the kernel type: one trailing `Irr`
constructor field per conjunct,

    inductive S(T..) := S(f̄, inv₀ :Irr P₀(f̄), …, invₘ :Irr Pₘ(f̄))

where a conjunct is a top-level `&&`-part of an attribute. A part that
does not elaborate on its own (an obligation of its own needs an earlier
part: `self.w == self.hi - self.lo` after `self.lo <= self.hi`) takes the
earlier parts of its attribute as `Irr` hypotheses: `S::invariant#k :
Π(T..)(f̄)(h₀ :Irr P₀)…(h_{j-1} :Irr P_{j-1}). Bool` and the field `invₖ :Irr
holds(S::invariant#k T.. f̄ inv_{k-j} … inv_{k-1})` (field `k`'s type is a
term at depth `generics + fields + k`). Only if a part fails even with them is
the whole attribute one conjunct (with a `warning[invariant]` when the whole
then elaborates). A conjunct the front end can read as a `bool` expression
(`==` and comparisons on scalars, `&&`, `||`, `!`, `implies(p, q)` ≡ `!p ||
q`, `iff(p, q)` ≡ `p == q`, `if`, `match` and `if let` with `bool` arms) is
the definition `S::invariant#k : Π(T..)(f̄). Bool` and the field
`holds(S::invariant#k T.. f̄)`; any other proposition is `S::invariant#k : Π(T..)(f̄). Type` and the
field `S::invariant#k T.. f̄`, which must satisfy the kernel's `is_prop`
(checked first by the front end: `||` between propositions, a
proposition-valued `if`/`match`, a stuck predicate are `error[invariant]`).
`exists(..)` is encoded as `!!exists(..)` (a `warning[invariant]`). `self.f`
is the field binder; the invariant may mention the fields, type parameters,
constants and spec-closed globals (spec closure with constants allowed,
`error[spec-depends-on-impl]`), never `S` itself.

For every `Irr` field `k`: `S::holds#k : Π(T..)(s : S T..). Bool` (or
`Type`) is the conjunct at the projections `π s` (a dependent conjunct's
hypotheses are `S::inv#m T.. s`), and `S::inv#k : Π(T..)(s).
holds(S::holds#k T.. s)` (or `S::holds#k T.. s`) is proven by a match on `s`
promoting the `Irr` field (`eq::promote`). Facts use `S::holds#k` (their
types contain no `match`).

**Visibility.** A struct with an invariant, a representation relation or a
view has only private fields and at least one field (`S;`, `S {}`, `S()`
have a public constructor host code could use without the invariant):
`error[invariant]`. Ghost code (spec modules, contracts, `proof!`, lemmas,
laws, proof items) reads private fields and destructures private-field
structs anywhere in the crate; exec code and construction keep Rust's
privacy.

**Construction** (`TypeInvariant`). Every application of `S`'s constructor
supplies the `Irr` fields: struct literals, tuple-struct calls, `..base`
updates, SSA field assignments (`x.f = v` rebuilds `x`: the invariant can
be broken only in unpacked locals), the structural view onto a spec struct
with an invariant. The obligation's target is the field type instantiated
by substitution from the kernel declaration (`Elab::ctor_irr_proofs`), so
the round trip's generated mode builds the same constructor with `Erased`
proofs. A `¬¬∃` conjunct is proven as `λh. h p` from a proof `p` of the `∃`
when one is found. A derived default value (placeholders, `Nat` guards)
exists only when each `bool` conjunct evaluates to `true` at the default
fields.

**Facts** (`FactOrigin::TypeBound`): `S::inv#k T.. v` for a value `v : S`
at parameters (exec and spec functions, lemmas, laws, proofs), `let` and
pattern bindings, call results, projections `v.f` and projected patterns —
once per value term — as `let` binders around the rest of the computation.
In a *pure* context — a proposition elaborated as a type (contracts, loop
invariants, assertions, `-> Prop` bodies) or a value that must not bind
(place indices, loop bounds, measures) — a binder would change the type or
value being built, so there the facts of a projected value are *hints*: not
binders, but given to the prover in each proof slot like the ghost facts
below (`(λh_inv. p) (S::inv#k T.. v)`); the same proposition therefore
elaborates to the same type wherever it is stated. So that the obligations
using such an expression still see the facts, the invariant-typed paths
projected in a statement's place indices, a loop's bounds, invariants,
measure and condition, and a `proof!` block's steps are bound as `let`
facts before the statement; the parameters of a loop helper have their
facts as hints of every proof slot of the helper (its type is built before
any body binder). Projections take the field count from the kernel
declaration.

**Derived `PartialEq`** compares the relevant fields; `S::eq_sound` rebuilds
`C(x̄, p̄) = C(ȳ, q̄)` by transports of `Π(r̄ :Irr I(..)). Eq(S, C(x̄, p̄),
C(.., z, .., r̄))` (the `Irr` fields generalized) applied to `q̄`.

**Ghost parameters.** The `#[ghost]` parameters of an exec function (the last
ones) and the `requires` that mention them form one binder after the other
parameters:

    ghost : Σ(g₁ : T₁) … (gₙ : Tₙ). R₁ × … × Rₘ × Unit

`Irr` in the function (every type position is relevant, DESIGN.md §5.3, so a
requires over an irrelevant binder cannot be a separate binder), relevant in
`f::ensures` / `f::refines`. A ghost local is its projection; the ghost
requires, and every fact whose type mentions a ghost local, are not bound in
the body (they would be ill-typed) but given to the prover inside each proof
slot: the proof is `(λ(h₁ : F₁)…(hₖ : Fₖ). p) pf₁ … pfₖ`, placed in the
irrelevant slot where the bundle is usable. At a call, the arguments
`ghost!(e)` (a ghost expression; `e` in ghost code) and proofs of the
callee's ghost requires (`CalleeRequires`) are the bundle `pair(e₁, …
pair(p₁, … tt))`. The printer omits ghost parameters and arguments; the
round trip's lowered calls lack them and the bundle is `Erased`; `eval`
takes no value for them. In source, a call that leaves the ghost arguments
out is `error[ghost]` (naming the parameters and their `requires`). A loop
that mentions a ghost parameter, and a tail-recursive function with ghost
parameters, are not supported yet.

**Views** (DESIGN.md §15.2, §15.3). For `#[view(|s| e)]` on `T` the lemma
`T::view_inj : Π(T..)(a b)(h : Eq(V, T::view a, T::view b)). Eq(T, a, b)`
(`ViewInjective`) is attempted: a match on `a` and `b` (the arm binders named
`a.f`, `b.f`; the promoted `Irr` fields — the invariants of both values —
are hints); different constructors contradict `h` (`Empty` from the prover),
equal ones rebuild `a = b` from the field equations the prover derives from
`h`. A `#[proof(view_inj = T)] fn p(a: T, b: T) { steps }` item (structs)
replaces the attempt: its steps prove `T::view_inj_fields : Π(T..)(a b)(h :
Eq(V, T::view a, T::view b)). Σ(_ : Eq(F₀, π₀ a, π₀ b)) … Unit` (the
invariants of `a` and `b` are facts), whose projections are the field
equations; a failure is `error[view-injective]`, and exec functions over `T`
are elaborated after the item. Proven, the view counts as injective
(refinements through it determine and establish). Not proven, it is an
error for a type reachable from the root that is not `Abstract(T)`
(`error[view-injective]`, naming the first undetermined field) and otherwise
leaves no trace (the view is lossy). `Abstract(T)`
(`validate::abstract_reasons`): every field private, no exported constructor
(a public struct without fields or an enum has one), `PartialEq` not derived
unless the view is injective, `Debug` not derived, no boundary function
whose parameter or result type mentions a user type that contains `T` in its
fields (transitively), and every boundary function taking or returning `T`
(also inside `Option`, tuples, arrays, references) refines through `α_T`:
it carries `#[refines(s)]`, `s`'s signature mentions neither `T` nor a type
containing `T`, and an explicit argument map reads no field of a `T`. A
refinement through a lossy view of an `Abstract` type determines its
function but does not establish it; a simulation-form refinement determines
when its struct is `Abstract` and a constructor-like method's refinement
establishing the relation is checked. Each determining refinement records
why (`RefinesRecord::determined_by`: identity, an injective view and the
`view_inj` lemmas it uses, `Abstract(T)` for a lossy view, `Abstract(S)`
with the established relation), printed on the spec sheet and in the
report; an unproven refinement determines nothing. A struct with
`#[represents]` that is not `Abstract` is `error[invariant]`.

### 13.7 Computed sections and completeness (DESIGN.md §15.5; stage S3)

* **Candidates.** Every function host code can call (the root's `pub use`
  list, the `pub` methods of every type reachable from it through public
  signatures, and any other `pub` function reachable from the root), every
  exec function a law mentions (a law that did not verify included), every
  exec function an exported function's contract mentions, and every exec
  function the hypotheses of a candidate mention must be determined. "Mentions" is `Refs*` of the statement with every exec
  function in the stop set (direct occurrences and occurrences through spec
  function bodies). A checked refinement that its record says determines
  the function (S1/S2) takes it out of the candidates.
* **Sections** are the strongly connected components of "a hypothesis of
  `f` mentions `g`" over the remaining candidates, after the unions of
  `#[section(with = [..])]`, in the order of Tarjan's algorithm (a section
  after the sections it depends on). `P(R)`: exported members, members a
  law, a spec item, an example, any contract (a member's own included), or
  the code of an exec function outside `R` mentions, and members in the
  `requires` of a published member; a one-member section publishes it.
  `H(R)`: the laws mentioning a member (item order; a `#[definitional]` law
  is none), then per member its `ensures`, its (non-determining) refinement
  lemma and the `S::inv#k` of the structs of its signature; a law or contract
  mentioning a member that did not verify blocks the section. The views of
  `obs_eq` are the lossy views of `Abstract` result types.
* **Restatement.** A law hypothesis the kernel rejects in the type check (a
  proof slot that needed a member's definition) is elaborated again with the
  members as the `F'` binders and the earlier hypotheses as facts (and as
  hints instantiated at the law's parameters); the result is passed as the
  hypothesis' restatement, which the kernel accepts only if it equals its
  own abstraction in every relevant position.
* **Statement.** `Env::abstract_section(R, P(R), H(R), views, stop set)`,
  the stop set being the exec functions fully specified so far (determined
  by refinement, published members of earlier fully specified sections,
  exec constants). An exec global in the returned `deps` outside the stop set
  makes the section not well founded.
* **Lemma.** `p::complete : complete_p(R)` (`DefKind::Lemma`; its type is
  the returned term; measure recursion on `p`'s measure for the induction
  discharge). In a `#[proof(complete = p)]` item the item's parameters are
  `p`'s, the hypotheses, their real counterparts and their instances at the
  parameters are facts, and a call of a member denotes the hypothetical
  implementation `F'` the statement quantifies over (the real `p` is the
  right side of the goal).
* Until S5 a section that is not fully specified is recorded (report, sheet,
  lock), not an error.

### 13.8 Examples on constants, `Nat` indexes, record values, `#[opaque]` (stage S5)

* **`#[example(e)]` on a ghost constant** (a `const` of a ghost module) is
  a closed `bool` spec expression checked exactly like a function's
  example (§15.7): the lemma `C::example#k : holds(e)` by conversion, or
  the kernel's closed evaluator. It exercises nothing for coverage. An
  exec constant takes none.
* **A `Nat` index into an array** in ghost code, `a[i]` with `a : [T; N]`
  and `i : Nat`, is `seq::index T (fst a) i .p₀ .p₁` — the `Seq` indexing
  of the array's sequence, with the obligations `0 ≤ i` and `i < N`. A
  `usize` index (and a literal) is array indexing as in exec code.
* **Vector-file records** (§15.7): a JSON object is a struct value (its
  fields by name, case-insensitively; a missing or extra field is an
  error; the struct's invariant and the bounds of its `Nat` fields are
  obligations, like any construction), a JSON array a tuple (one entry per
  component) or a `Seq`, `null` is `None` and any other value `v` of an
  `Option<T>` is `Some(v)`. A vector-file record is decided by the
  kernel's closed evaluator first (it is a closed term over data), and by
  conversion only if that evaluator does not decide it.
* **`#[opaque]` on a spec function** makes its kernel definition opaque
  (`DefDecl.opaque`, §5.6): checking-mode evaluation and conversion keep
  its applications folded, and `unfold(f)` / `by_unfolding(f)` (`Delta`)
  expose its body. It changes no value (examples are decided by the closed
  evaluator, which unfolds it) and is not part of the specification's
  meaning. Use it for a hash (`sha256`) whose body must not be unrolled
  while proving facts about its callers.

### 13.9 Recursive spec types (stage S5)

* **Declaration.** An enum of a `#[spec]` module may have fields of exactly
  its own type (`enum Tree { Bytes(Seq<u8>), Cat(Tree, Tree), .. }`, with
  its type parameters in order). It is the inductive `crate::path::T` whose
  such fields are its recursive occurrences (§5.4). Every other cycle — a
  field `Seq<T>`, `Option<T>`, `(T, U)` or `[T; N]`, a cycle through
  another type, a struct, an exec type — is rejected, and so is
  `#[derive(PartialEq)]` on such a type (compare what its values stand for
  instead).
* **Size.** The elaborator adds `T::size' : Π(A..). T(A..) → Int`, one plus
  the sizes of the recursive fields, by structural recursion
  (`Recursion::Structural`), and the checked lemma `T::size'_pos : Π(A..).
  Π(t : T(A..)). holds(1 ≤ size'(t))`, which linear arithmetic adds for
  every `size'` atom. The names end in `'`, which no Rust item can.
* **Recursion.** A spec function whose recursive calls pass, at the
  position of a parameter `p : T(..)`, a variable bound to a recursive
  field of `p` by a pattern of the body — `match p { C(l, r) => .. }`, a
  `let`, or the component of `p` in a tuple match `match (p, q) { (C(l, _),
  D(m)) => .. }`, transitively — has the inferred measure `size'(p)` (§9).
  The decrease `size'(l) < size'(p)` follows from the path equation `p =
  C(l, r)`, the definition of `size'` and `size'_pos`.
* **Induction.** A lemma, law or proof with `#[induction(p)]` may apply its
  induction hypothesis `ih(..)` to such a field of `p` (measure `size'(p)`).
  A script `match (a, b) { (p₁, p₂) => .. }` on a tuple of distinct
  variables refines the goal and the facts in both variables, one matrix
  column per variable; a top-level or-pattern is one row per alternative.
  A `Seq` variable is refined too (`[]` is `Nil`, `[p, rest @ ..]` is
  `Cons(p, rest)`), and `ih` may take the rest binding of a `Seq`
  parameter.
* **Automation.** A boolean fact `g(.., C(..), ..) == b` about a recursive
  definition applied to a constructor of such a type is unfolded once
  through `g`'s defining equation (the kernel keeps it folded when `g`'s
  body inspects a recursive call, since `size'` of a symbolic tree is not a
  literal).

### 13.10 `pow2`, `log2`, `popcount` (stage S5)

The ghost prelude functions `pow2`, `log2` and `popcount` take an `Int`
(so a `Nat` argument coerces) and return a `Nat`. They are definitions of
the ghost-language library (§16):

| ghost | core | value |
| --- | --- | --- |
| `pow2(n)` | `ghost::pow2 n` | `2ⁿ`, and `1` for `n ≤ 0` (linear recursion on `n`) |
| `log2(n)` | `ghost::log2 n` | the position of the highest set bit, `⌊log₂ n⌋`, and `0` for `n < 2` (recursion by halving) |
| `popcount(n)` | `ghost::popcount n` | the number of set bits, and `0` for `n ≤ 0` (recursion by halving) |

They are ghost only (a call in exec code is an error); `unfold(pow2)` and
`by_unfolding(log2, ..)` name them. Their facts are the checked lemmas of
`lemmas/nat.core`, also available as `sandblaster::lemmas::nat::…`:
`pow2_pos` (`1 ≤ pow2(n)`), `log2_nonneg`, `popcount_nonneg` (for every
`n`), `popcount_le` (`popcount(n) ≤ n` for `n ≥ 0`), `pow2_succ` (`pow2(n +
1) = 2·pow2(n)` for `n ≥ 0`), `popcount_even` (`popcount(2n) =
popcount(n)` for `n ≥ 1`), `popcount_odd` (`popcount(2n + 1) = popcount(n)
+ 1` for `n ≥ 0`) and `log2_bounds` (`pow2(log2(n)) ≤ n < 2·pow2(log2(n))`
for `n ≥ 1`). Linear arithmetic adds the first four, and `log2_bounds` for
an atom `pow2(log2(n))`, whenever such an atom occurs and the lemma's
hypothesis follows from the problem.

### 13.11 `?` and `return` in spec functions (stage S5)

In a spec function (not one returning `Prop`) `?` and `return` are sugar,
removed by the type checker right after the body is typed, so every later
stage sees a pure expression. The rest of the function moves into the
branches that continue:

| source | desugared |
| --- | --- |
| `let p = e?; rest` | `match e { Some(p) => rest, None => None }` |
| a branch value `e?` | `match e { Some(x) => k(x), None => None }` (`k`: the rest of the function applied to the value) |
| `return v` | `v` (the rest of the function is dropped) |
| `if c { ..; return a; } rest` | `if c { ..; a } else { rest }` |
| `let p = match s { q₁ => return v, q₂ => w }; rest` | `match s { q₁ => v, q₂ => { let p = w; rest } }` (likewise `if` and blocks) |
| `let p = e else { ..; return v };` | `match e { p => rest, _ => { ..; v } }` |

`?` needs the function to return `Option`. An exit anywhere else — inside
an operand, a call argument, a condition, a scrutinee or a guard — is an
error (bind the value with a `let` first). The continuation is copied into
each branch that continues; the locals it binds are the same in each copy.

## 15. Hardware (DESIGN.md §9)

* Intrinsic calls elaborate to the definitions of the target semantics
  library `sandblaster/targets/core/<arch>.core` (loaded for the build
  target's architecture only), named `<arch>::<intrinsic>`. Const-generic
  immediates are passed first, as `U32` literals, each with an irrelevant
  range proof (by evaluation). Vector types are arrays of lanes.
* Load/store helpers (`sandblaster::arch::<arch>::…`) elaborate to the
  library's `<arch>::<helper>` definitions (or, where the library has
  none, to the intrinsic their template calls).
* A function with `#[implements(portable)]` is elaborated and checked like
  any exec function. The obligation `variant(x) = portable(x)`
  (`VariantEquiv`) is **deferred to phase 3**: variants are emitted but not
  dispatched to, so the portable function is what runs.

## 16. Definitions added by the elaborator

Loaded (and kernel-checked) before the crate, from
`sandblaster/front/src/elab/semantics.rs` and `facts.core`:

* `Tuple1(A)` — the one-element tuple (the prelude starts at two).
* `array::copy_range T N a lo hi s .h₀ .h₁ .h₂` — the array `a` with
  positions `lo..hi` replaced by the elements of the slice `s`, requiring
  `lo ≤ hi`, `hi ≤ N`, `hi − lo = len s`: `take(a, lo) ++ s ++ drop(a, hi)`
  with its length proof. This *definition* is part of the semantics of
  `copy_from_slice` (TCB); its length proof is checked.
* `fact::chunks_rest_c_lt`, `fact::as_chunks_rest_lt` — lemmas (checked,
  untrusted) stating that the remainder of `as_chunks::<N>` is shorter than
  `N`.
* The ghost-language library `elab/ghost.core` (§13.5; TCB item 6 of
  DESIGN.md §1.1): `ghost::seq_get T l i` (the element at `i`, `None` for
  `i < 0` or `i ≥ len l`), `ghost::seq_map A B f l`, `ghost::seq_flatten T
  l` (concatenation of a list of lists), `ghost::arrays_flatten T N l`
  (concatenation of the arrays' lists), `ghost::seq_all T p l` (every
  element satisfies `p`: the well-formedness of a sequence holding `Nat`s,
  §13.5), and `ghost::pow2`, `ghost::log2`, `ghost::popcount` (§13.10).

The automation's prelude lemmas (`sandblaster/front/lemmas/*.core`)
are loaded too; they are checked and untrusted.

Per crate (§13.6): `S::invariant#k` (spec), `S::holds#k` (spec) and
`S::inv#k` (lemma) for every struct with an invariant, `T::view_inj`
(lemma) for every closure view proven injective, and
`T::view_inj_fields` (lemma) for every `#[proof(view_inj = T)]` item.
Per section (§13.7): `p::complete` (lemma) for every published member whose
completeness statement is proven. Per recursive spec type (§13.9):
`T::size'` (spec, structural recursion) and `T::size'_pos` (lemma).
Per spec function `f` whose result has `Nat` in covariant positions (the
result, tuple and struct components, `Option` contents): `f::nat_range`
(lemma, `Π(x…)(h…). R[f x… h…]` with `R` the conjunction of `0 ≤ c` over
those components; an `Option` contributes `match v { None ⇒ (), Some(w) ⇒
R[w] }`), proven like an `ensures` (§12) and silently omitted when its
proof fails. The prover gets its instances for the applications of `f` in
a goal and its facts (irrelevant facts of the slot; closing statements:
facts of their view).

## 17. Reference semantics

The meaning of a verified program is the kernel's evaluation of its
definitions (`sandblaster eval <dir> <fn> <args-json>`; opaque definitions are
unfolded; irrelevant arguments are erased). The kernel's unfolding policy
for recursive definitions (§5.6) is made for conversion checking and keeps
non-tail recursion that inspects its own result folded; the reference
evaluator completes such applications on closed arguments by evaluating the
definition's body in the environment of the argument values and applying
the pending eliminators — exactly one kernel unfolding step, repeated. Values cross the boundary in
JSON (`elab::value`): numbers (or decimal/`0x` strings) for integers,
arrays (or `"0x…"` hex strings for bytes) for arrays and slices, `null` /
`{"Some": v}` for options, objects for structs.

## 18. Deviations and open points

* Ghost parameters (§13.6) are one `Irr` binder with the `requires` that
  mention them, after the other parameters (they must be written last):
  DESIGN.md §15.3 says "an `Irr` Π binder" per parameter, which the kernel's
  relevance rule (every type position is relevant) would leave unusable in
  any `requires`, `ensures` or fact.
* The bounds of `Nat` fields (§13.5) are guards and hypotheses at
  parameters, not `Irr` constructor fields: a proof inside a spec value
  blocks the case analysis and rewriting that refinement proofs rely on (the
  provers generalize a value without its proofs).
* `Abstract(T)` (§13.6) is stricter than DESIGN.md §15.3 states: a boundary
  function that exchanges a user type containing `T` breaks it (the
  containing type's view — identity or its own — shows `T`'s representation
  to the function's specification), and "refines through `α_T`" is checked
  on the specification's signature and argument map (a specification over
  `T` itself reads its hidden fields).
* A struct with an invariant, a representation relation or a view must
  have at least one (private) field (§13.6); DESIGN.md §15.3 states only
  "only private fields", which a struct without fields satisfies vacuously
  while its constructor is public.
* `f::natural` (DESIGN.md §15.2 "Generics") is not generated: a generic
  `f` refines its generic spec at the identity on its type parameters only,
  and a refinement never composes through a non-identity view at an
  instantiated type (at `T := u8` a call of `f` gets `f::refines` with `T`
  seen as itself). What it needs: (1) the statement `Π(A B : Type)(α : A →
  B)(x̄). map_Out(α)(f A x̄) = f B (map_In(α) x̄)`, with the functorial
  liftings `map_T(α)` of every type in the signature (`Seq`, slices,
  arrays, `Option`, tuples, and a derived `map` for every generic user
  type); (2) its proof by induction on `f`'s body, with commutation lemmas
  for every operation on values of the type parameter (length, indexing,
  `take`/`skip`, constructors and matches, moves) — an operation that
  observes a `T` value (derived `PartialEq` on `T`, a law-carrying trait's
  method) commutes only with an injective `α` and needs that as a
  hypothesis; (3) its use at call sites at instantiated types, to rewrite
  `α(f⟨A⟩ x̄)` into `f⟨B⟩(α x̄)` before the callee's refinement. The kernel
  needs nothing new (the statement is `Kind`-sorted, like a generic
  section's); the gap is the elaborator's lifting and the body walk.
  Generic sections (§13.7) are unaffected: they are stated and proven at the
  generic type directly.
* Computed sections (§13.7) take the refinement verdicts of S1/S2 as given
  ("determines" ⇒ fully specified, no section). DESIGN.md §15.5's
  "dependencies occur in `H(R)` only in `obs_eq`-respecting positions" is
  not checked; instead a dependency determined only up to the lossy view of
  an `Abstract` type (by its refinement, or in a section whose `obs_eq` used
  such a view) is not accepted: the depending section is not well founded
  (fail closed; exact dependencies — identity or injective views — are). A
  hypothesis whose proof slots do not re-check with the section abstracted
  is not re-proven (`SectionHyp::restated` is never passed): the section
  is reported as not stated, with a note to state the needed fact as an
  explicit hypothesis. Callee contract facts are no longer part of any
  statement (§13.1), so this arises only for a slot proven by unfolding a
  member.
* Evidence types (DESIGN.md §15.3) are surface items of kind `invariant`* Evidence types (DESIGN.md §15.3) are surface items of kind `invariant`
  (`invariant:S`): whether an invariant states a "certified property" is not
  decided syntactically, so rewriting an invariant into a spec function
  changes its statement, never its lock key; the spec functions it calls are
  its dependencies.

* Post-loop facts (§12.1) deviate from the letter of DESIGN.md §7.4 for
  `a..=b`: DESIGN states `Inv[i := b]` "at `done`", which describes the
  state after the last iteration with the index of that iteration (an
  off-by-one that no precise invariant satisfies). The facts use `i := b +
  1` instead: exact over `Int`, otherwise under `b < MAX`.
* The invariants must hold, and be defined, at the exit index (`i = b`):
  an invariant such as `i < n` or one indexing `xs[i]` fails
  `InvariantExit` (it was accepted before post-loop facts existed); the
  diagnostic explains the rule (drop the bound, or weaken it to `i <= b`).
* A post-loop fact whose loop may run zero times with `a > b` carries the
  premise `a ≤ b`, and `¬(a && b)` of a `while` is the implication `a =
  true → ¬b`: implications, which the development prover does not
  instantiate (`auto` does; a claim such as `i == 16 || i >= lim` that
  needs a case split on `a` is out of its reach, `implies(i < 16, i >=
  lim)` is not).
* A disjunctive invariant is available after the loop only in its
  implication form (§12.1), an `exists` invariant not at all: the lemma's
  statement is a squash, whose irrelevant component the kernel restricts
  to propositions.
* Optimizer clones (DESIGN.md §9.3): the clone equality proof relates the
  facts of a clone and its original modulo the renaming (`opt::mirror`).
  When it abstracts a `let` whose values differ (the join of a loop with
  several mutated locals), facts proven *from* a post-loop fact after that
  loop depend on the abstracted value, and the clone has no kernel-checked
  equality lemma — it relies on the renaming argument (an optimizer
  warning, an error with `SANDBLASTER_STRICT_OPT=1`), as for any such
  let-dependent fact.
* `eq_sound` / `eq_complete` are generated for non-generic types only.
* Inside the body of a recursive `f`, the recursive calls carry no `ensures`
  facts (they are available in `f::ensures` and at external call sites).
* `pow`, byte conversions of `u8`/`usize` and `split_last_chunk` are
  rejected as unsupported by the elaborator (`div_ceil` has a meaning,
  §19.4).
* `VariantEquiv` obligations are deferred (§15).

## 19. Lifted modules (`#[lift] mod m;`)

A lifted module is ordinary Rust copied verbatim from an existing crate.
The front end translates it at load time (`crate::lift`, before name
resolution) into the exec subset, and everything after that (types,
elaboration, obligations, kernel checking) is the ordinary pipeline. The
translation is **the meaning the toolchain gives to the copied file**, so it
is part of the trusted base like the rest of this document; the table in
`sandblaster/front/src/lift.rs` lists every rewrite. A construct the
lift does not know is an error, never a guess.

### 19.1 What each rewrite relies on

* **Sealed traits and monomorphization.** A trait declared in a private
  inline module with impls for concrete types has exactly those impls
  (rustc's coherence and privacy rules), so a generic item bounded by it
  means the finite set of its instances: `write::<T>` is `write__u16`,
  `write__u32`, ... A generic parameter with any other bound is rejected.
* **State passing.** `&mut self`, `&mut impl Buf` and `&mut impl BufMut`
  become a `mut` by-value parameter (a `mut self` receiver is accepted in
  lifted modules only) and an extra returned component. Sound because rustc
  already checked the exclusive borrow: nothing else observes the state
  during the call.
* **Buffers** are `Seq<u8>` (`crate::__lift_model`, ghost specs with
  examples): a `BufMut` is the bytes put so far, a `Buf` the bytes not yet
  read. Host assumption (TCB): the caller's buffer behaves as that sequence;
  a `BufMut` that panics on running out of capacity panics in host code.
* **`Result`** is the prelude enum `crate::__lift::Result` with core's
  variants; `e?`, `map`, `map_err`, `unwrap` become `match`es (`unwrap`'s
  panic is an `unreachable!()` obligation). `let x = a.checked_sub(b)
  .unwrap();` becomes `let x = a - b;` (both panic exactly when the
  operation overflows; the subtraction's obligation proves it does not).
* **Dropped items** are listed as warnings: `#[cfg(test)]` and
  `#[cfg(feature = ..)]` items, and the derives `PartialOrd`, `Ord`,
  `Hash` (rustc-derived and unused by the lifted code).

### 19.2 Attachments and declared gaps

Proof annotations never go into the copied file. A ghost `#[lift]` module
attaches them: `#[lift_attach(path)]` on a function whose body holds
`invariant(..)` (a type), `ensures(..)` and `at_start! { .. }` (a
function), or with `loop_nr = k` `invariant`/`decreases`/`ensures` and
`after_loop! { .. }` (the `k`-th loop). They are monomorphized with the
target and proven like any other contract. An attachment that matches no
lifted item is an error (its author relies on the contract it states).
Expression attributes of ghost instances (`#[example]`, `#[decreases]`)
are rewritten per instance like their bodies.

`#[lift(unverified = "u128, i16")]` on the declaration leaves the named
impl types' instances out of the verified module, with a warning per type;
they stay unchecked host code. Without it every instance is lifted (a
width the kernel lacks is then an error).

An attachment may also say `opaque();`: the lifted function is then opaque
in proofs (§5.6) — its callers see its `ensures` only, and a proof that
needs its body unfolds it by name.

`#[lift(host)]` on a declaration marks a **host model**: a module whose
items stand for items of the host crate that the lifted code names (for
`varint.rs`, `crate::Error`). It holds non-generic enums only; the proofs
use it, and module mode never emits it. Instead, the emitted module ends
with one `const _` item per variant, naming it through the lifted code's
own scope (`const _: Error = Error::EndOfBuffer;`,
`const _: fn(usize) -> Error = Error::InvalidVarint;`), so rustc checks in
the host that every variant the proofs construct exists with those
payload types. The same tail checks every `T::SIZE` the lift read as
`size_of::<T>()` (`const _: () = assert!(<u16 as FixedSize>::SIZE == 2usize);`).

### 19.3 Signed integers

The kernel has unsigned machine words only (§3). A lifted module reads an
`i16`/`i32`/`i64` as **its two's complement bits**: the type is the prelude
tuple struct `crate::__lift::I16(u16)` (`I32(u32)`, `I64(u64)`), a distinct
type, so an operation the lift does not translate does not type check —
never a silent unsigned reading. `i8`, `i128` and `isize` are not read
(they stay signed, which the front end refuses). The translation
(`FnRw::signed_rewrite`), for `x`, `y` of type `iN`:

| Rust | lifted | why it is the same |
| --- | --- | --- |
| `5iN`, `-5iN` | `IN(5uN)`, `IN((2^N − 5)uN)` | two's complement literals |
| `x << k` | `IN(x.0 << k)` | Rust's `<<` on `iN` is the bit shift; it panics exactly when `k ≥ N` (an obligation of `uN`'s `<<`); a signed `k` is its bits, so a negative amount is `≥ N` too |
| `x >> k` | `iN_shr(x, k as usize)` | arithmetic shift: `x.0 >> k` for a clear sign bit, `!((!x.0) >> k)` for a set one; `requires(k < N)`, Rust's panic |
| `x ^ y`, `x & y`, `x \| y`, `!x` | the same on `.0` | bitwise operations do not see the sign |
| `-x` | `iN_neg(x)` | `0` for `0`, else `2^N − x.0`; `requires(x.0 ≠ 2^(N−1))`, Rust's panic on `iN::MIN` |
| `x as uM`, `x as iM` (`M ≤ N`) | `x.0`, `(x.0 as uM)`, `IM(x.0 as uM)` | truncation of the bits |
| `u as iN` (`u` unsigned) | `IN(u as uN)` | zero extension or truncation of the bits |
| `x == y`, `x != y` | structural | equal bits, equal values |
| ghost `x as Int` | `int_of_iN(x)` | `x.0` below `2^(N−1)`, else `x.0 − 2^N` |
| ghost `e as iN` (`e` an integer) | `iN_of_int(e as Int)` | the `iN` congruent to `e` modulo `2^N`, as Rust's casts |

Refused (an error naming the operation): signed `+ − * / %`, comparisons,
compound assignment, widening casts from a signed type (sign extension),
methods on a signed receiver other than sealed-trait methods, and an exec
`as iN` of an operand the lift cannot type. `iN_shr`/`iN_neg` are exec
functions of the prelude (checked like any code); `int_of_iN`/`iN_of_int`
are opaque spec functions of the model with known-answer examples.
`tests/aug_int_toolchain.rs` compares the kernel's evaluation of lifted
signed code with rustc's on several thousand inputs (arithmetic shifts,
negation, ZigZag and its inverse, narrowing) and checks each refusal.

### 19.4 `div_ceil`

`uN::div_ceil(a, b)` is defined in `elab/lift.core` (trusted like the other
prelude definitions): `a / b`, plus one when `a % b ≠ 0`; a `DivZero`
obligation proves `b ≠ 0` at each call. The `+ 1` cannot wrap (then
`b ≥ 2`, so `a / b ≤ MAX / 2`). `tests/lift.rs` checks it against rustc on
edge values.


### 19.5 In place: a crate's own files (`#[lift(in_place, ..)]`)

A DSL root inside the host crate (commonware-storage:
`storage/sandblaster/mmr/mod.rs`) lifts the crate's own source files by
path, unchanged: `#[lift(in_place, ..)] #[path = "../../src/merkle/position.rs"]
pub mod position;`. The host's `build.rs` calls
`sandblaster::build::compile_lifted(root, name)`, which verifies the root and
writes a record (`<name>-verified.txt` in `OUT_DIR`, with a report and
timings) instead of emitting code: the host's files are the code rustc
compiles. The driver checks that every in-place file is under `src/`, that
the host module declaring it says `mod x;` without `#[path]` (so the file
verified is the file rustc compiles), and that the record's name is the
one asked for. Options:

| option | meaning |
| --- | --- |
| `children = "m, .."` | the source's out-of-line `mod m;` is lifted too, from its standard location (`m.rs` or `m/mod.rs`), with the same options; other out-of-line modules are host modules, listed |
| `instance = "Tr: path::S"` | §19.6 |
| `unverified_instances = "Tr: path::S2"` | the impls of the open trait `Tr` for `S2` are unchecked host code, listed |
| `unverified_impls = "Tr, .."` | impls of the named traits (last path segment matched) and a local declaration of such a trait are unchecked host code, listed |
| `unverified_fns = "T::m, .."` | the named methods are unchecked host code, listed (§19.9); a lifted caller of one does not load |

Before a module's specification lock is accepted, `build.rs` may call
`sandblaster::build::compile_lifted_pending_gates(root, name)` instead — a
development aid, to be removed before any landing (DESIGN.md §2.1): every
proof and law must still check (anything unproven fails the build), the
§15 gates run and their findings are counted in a cargo warning and in the
record `OUT_DIR/<name>-pending.txt`, which begins `NOT VERIFIED —
DEVELOPMENT BUILD: PROOFS CHECKED, §15 GATES PENDING` and carries no
verdict; `<name>-verified.txt` is replaced by a `NOT VERIFIED` stub, the
report's `status` says the same, and no verdict key is written or reused
(each build re-verifies). The build
script watches only paths that exist (a missing watched path, such as a
lock not yet written, would re-run it on every build; the root's directory
is watched, so a new lock is noticed).

Item macros whose path has two or more segments (`cfg_if::cfg_if! { .. }`)
declare host items (feature-gated modules) and are left out, listed.
`Debug`/`Display`/`Hash` impls are left out as in §19.1. An attachment's
`requires(..)` on a lifted function is its precondition: an obligation at
every lifted call, and a listed obligation of host callers in the record
(the panics the code documents, stated as contracts).

### 19.6 Open traits at a declared instance

A trait with impls outside a sealed module is open: the lift cannot know
its instances. `instance = "Tr: path::S"` reads every type parameter
bounded by `Tr` as `S`: the parameter is erased (`Position<F>` is
`Position`, `PhantomData<F>` is the prelude's unit `PhantomData`), `F::X`
and `<F as Tr>::X` are `S::X`, and `Tr`'s method calls through `F` are
calls of `S`'s impl, which is lifted like any code. What is verified is the
code **at `S`**; the record names the other instances
(`unverified_instances`), whose impls are dropped. Nothing is claimed about
them. Sound because the erased item, instantiated at `S`, is exactly what
rustc monomorphizes for `S`.

### 19.7 Templates: core's methods as checked prelude functions

A method of `Option`, `Result` or an unsigned integer that the kernel does
not define is read through a **template**: core's definition, transcribed
in `sandblaster/front/lift/combinators.rs` (plain Rust). `recv.m(args)`
becomes the body of the template `k_m` (`k` the receiver's kind:
`option`, `result`, `u64`, ..) with the receiver and arguments bound by
`let` in order (call by value), a closure argument inlined at its calls
(`f(x)` is the closure's body with its parameter bound to `x`), `panic!` an
`unreachable!()` obligation, and a `&str` message argument dropped (it
shapes the panic payload only; it must be a literal). The table is data,
not rewrite code: adding a method is adding its core definition. The
test `the_*_templates_agree_with_core` (`tests/lift_open.rs`) compiles the
file natively and compares every template with core's method on edge
inputs, panics included. Present: `expect`, `and_then`, `map`, `map_or`,
`ok_or`, `filter`, `or`, `is_some_and`, `unwrap_or_else` (Option);
`expect`, `unwrap`, `ok`, `is_ok`, `and_then` (Result); `checked_shl`,
`checked_shr`, `trailing_ones`, `leading_ones`, `cmp`, `partial_cmp`
(unsigned integers). `expect`/`unwrap` are written with `let .. else` so
the rest of the body sees the value as a fact.

A **local closure** `let f = |x: T| e;` is inlined at each call `f(a)`; a
capture that is re-bound or assigned while the closure lives is refused
(inlining would read another value). `array::from_fn` and closures passed
elsewhere are refused.

### 19.8 Operators, conversions and constants

An operator on a lifted struct is a call of its impl: `a + b` is
`S::add(a, b)` (`add__u64` for `Add<u64>`: impls are told apart by the
right operand's type), `a += b` is `S::add_assign`, `*a` is `S::deref(a)`
(`Deref`), `a < b` is `ord_lt(S::partial_cmp(a, &b))` with the prelude's
`Ordering` (an impl's `cmp` is lifted like any method), `==` with a
primitive on the right is `S::eq__u64`. `From`/`TryFrom` impls are
functions named by their source type. An impl's associated constant is the
module constant `S__C` (a `const fn S__C()` when its initializer calls a
function), `uN::MAX`/`MIN`/`BITS` are literals, `Self::X` of an impl's
associated type is the type. `#[derive(Default)]` is synthesized field by
field (a struct invariant then applies to it like to any constructor).
`const fn` is lifted as `fn`. An untyped integer literal takes its type
from its use (the other operand, the parameter, the `let` annotation).

### 19.9 Loops, iterators and assertions

`for x in e` steps an iterator by a state-passing `next`: a range of
`u32`/`u64` (`a..b`, `a..=b`: prelude structs with core's `next`),
`core::iter::once`, or a lifted struct with an `Iterator` impl. A
function returning `impl Iterator<Item = T>` returns its body's concrete
type (a range, `once(..)`, or `S::f(..)` with `f` returning `Self`), and
`for x in f(..)` over such a function steps that type. A `for` or
`while` whose body has `return`, `continue` or `break`, or whose
attachment has `ensures`, becomes a tail-recursive helper (`f__while0`,
`f__for0`) taking the locals it or its attachment uses, with body
`if cond { B; return f__while0(..) } else { exit }` (the test's outcome is
a fact of each branch); in a `&mut self` method the helper binds each of
`self`'s fields to a local (`let mut __self_a = self.a;`, so facts about
`self.a` carry over) — also inside macro arguments (`assert!(self.a >=
self.b)` reads the updated fields) — runs its `at_start!` steps after
those bindings, and rebuilds `self` where it leaves. A `for` names its iterator `iter` so
attachments can speak of it. Loop attachments: `invariant`, `decreases`,
`ensures` (helpers), `at_start! { .. }` (proof steps at the start of each
iteration: the helper's entry, or a proof block before a plain loop's
body), `at_end! { .. }`, `after_loop! { .. }`. Several attachments to one
item are merged (their statements concatenated in load order).

`assert!(c, ..)`, `debug_assert!(c, ..)` are `if !(c) { unreachable!() }`
(an obligation: the proof shows the assertion never fails, so it holds in
debug and release builds alike); `assert_eq!(a, b, ..)` and `assert_ne!`
compare with `==`; `panic!`, `todo!`, `unimplemented!`, `unreachable!(..)`
are `unreachable!()`.

**Proof support.** A lemma of a `#[bridges]` module is a rule of `auto`
(DESIGN.md §8.1): an unconditional equation rewrites; an inequality, or an
integer equation with hypotheses, joins the linear problems whose atoms
match its terms (its hypotheses discharged by `auto`). Hypotheses of an
implication fact (`implies(c, ..)` in a lemma's `ensures`) are used forward
when **one** hypothesis is literally a fact of the branch (for a new
implication fact, against the facts already present; for a new fact,
against the implications present) — write it in the form the code's test
leaves it (`(x == 0u64) == false`, `t > 1u64`, `(p < s) == false`); the
other hypotheses are proven by `auto`. A bridge lemma whose conclusion
and first hypothesis are test outcomes (`requires(t(a) == true);
ensures(u(a) == false)`, the hypothesis not an arithmetic comparison) is a
forward rule: the fact the first test leaves triggers it.

**Unreachable tails.** Where a function body ends in `absurd` (a branch
its own proof shows impossible: a `let .. else` whose else-branch is
refuted), its `ensures` is not an obligation there: the tail's own proof
closes any goal. A body that reaches the tail with a satisfiable context
still fails at the tail itself (the negative twin in
`tests/lift_open.rs`).

**Declared unchecked functions.** `#[lift(in_place, unverified_fns =
"T::m, ..")]` leaves the named methods out of the lifted module (they stay
host code, compiled by rustc as written, unchecked); each is listed in the
lift's diagnostics and the build record. A lifted item that calls one
does not load (the call has no definition), so the gap cannot hide inside
checked code.
