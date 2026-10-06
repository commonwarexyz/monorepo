# Writing sandblaster proofs — a guide for engineers

This guide explains how laws are proven and how to write or fix a proof. Its worked examples come
from the QMDB fixture's `LAWS.rs` and `PROOF.rs` (`sandblaster/fixtures/qmdb/sandblaster/`, removed
2026-10-05 and kept in the git history); the verified roots (`storage/sandblaster/mmr`,
`storage/sandblaster/verifier`, `codec/sandblaster/varint`) are today's examples of the same
techniques. The reference is DESIGN.md §4 (ghost language) and §8.1 (automation).

## 0. What laws are for

A law is a claim that a reviewer reads *instead of* the code. It is worth writing only if two things are true:
- it would fail on a wrong implementation;
- an engineer who has never opened the code would recognise it as a property they want.

The build checks that a law is proven. Only you can check that it is worth proving.

Ask four questions of every law:

1. **Would it fail if the code were wrong?** Picture the classic bug: a deleted check, a swapped argument, a limit that is too small. If the law still holds, it says nothing about that bug.
2. **Does it mention an internal function?** Then it is a contract of that function, not a guarantee of the crate. Write `#[refines(spec::…)]` on the function, or a `#[lemma]` in `PROOF.rs`. The build rejects the law with `error[law-mentions-internal]`.
3. **Is it one unfolding of a definition?** "If `verify` returns true, then `verify`'s body holds" is true of every `verify`. The build rejects it with `error[law-restates-impl]`.
4. **Does it cover both directions?** A verifier needs both "honest inputs are accepted" and "accepted inputs are honest". Either one alone is satisfied by a function that always returns `false`, or one that always returns `true`.

**Bad: restating the code.** This is from the old QMDB `LAWS.rs`:

```rust
#[spec]
pub(crate) fn Acceptance(root: Option<(Digest, &[u8])>, proof: Option<(Proof, &[u8])>, key: &[u8], value: &[u8]) -> Prop {
    exists(|trusted: Digest, decoded: Proof, k: Digest, v: Digest| {
        root == Some((trusted, &[])) && proof == Some((decoded, &[])) && key == &k[..] && value == &v[..]
            && verifier::active(&decoded)
            && verifier::reconstruct(&decoded, &k, &v) == Some(trusted)
    })
}

#[law]
fn verify_acceptance(root: &[u8], key: &[u8], value: &[u8], proof: &[u8]) {
    requires(verifier::verify(root, key, value, proof));
    ensures(Acceptance(codec::digest(root), verifier::parse(proof), key, value));
}
```

`Acceptance` is `verify`'s body, so this law holds for every `verify`. It holds for one whose `reconstruct` never hashes the activity chunk, which lets anyone prove a stale value current. It holds for one whose `active` reads the wrong bit. It took pages of proof and assures nothing.

**Good: a condensed guarantee.** This is from the new `LAWS.rs`:

```rust
/// Sound: if a proof verifies against a database's root, the update is current in the database
/// at the location the proof names, and the proof's sizes are the database's; or else the
/// proof's tree and the database's, walked together, contain a SHA-256 collision.
#[law]
#[reduces_to(collision_resistance)]
fn verified_updates_are_current(db: Db, key: Digest, value: Digest, p: Proof) {
    requires(db.well_formed() && verify(db.root(), key, value, encode(p)));
    ensures((db.is_current(p.location, update(key, value)) && p.leaves == db.leaves() && p.inactive == db.inactive)
        || collision(clash(p.tree(update(key, value)), db.tree())));
}
```

Why this one works:
- **It reads without the code.** Every term is a spec item written from the standard: `Db`, `verify`, `clash`.
- **The code is tied to the spec once**, by `#[refines(spec::proof::verify)]`.
- **It fails on real bugs.** With the graft deleted, a proof with a forged chunk verifies and no collision exists, so this law cannot be proven.
- **Its partner covers the other direction.** `current_updates_have_proofs` fails if any honest proof is rejected, for example because a cap is too small or the bit order is wrong.
- **It is in extraction form.** A law that relies on a hardness assumption is written so that when its claim fails, the proof computes the collision from the law's own inputs. A closed "some collision exists" is rejected, because pigeonhole proves it.

**Where other facts go:**

| Fact | Write it as |
| --- | --- |
| what an internal function computes | `#[refines(spec::f)]` on the function, with `spec::f` transcribed from the standard |
| a property only a proof needs (a bound, a regrouping, a partition) | a `#[lemma]` in `PROOF.rs` |
| a consequence of other laws | a lemma, or `#[corollary]` if readers need it spelled out |
| a known answer (a test vector, a production verdict) | `#[example]` or `#[examples(file = ..)]`: the only defence against a spec that is wrong the same way everywhere, which no law can see |

## 1. Laws, proofs, lemmas

| Item | Where | What it is |
| --- | --- | --- |
| `#[law]` | `LAWS.rs` | a **claim**: `requires(..)` hypotheses, one `ensures(..)` conclusion, no proof |
| `#[proof]` | `PROOF.rs` | the proof of the law with the **same name and parameters** |
| `#[lemma]` | anywhere ghost | a helper claim **with** its proof (its body after `requires`/`ensures`) |
| `#[spec]` | `spec/`, or proof-local in `PROOF.rs` | a definition used in statements (`spec::proof::verify`, `Db::root`; proof-local `honest`, the honest prover) |

`cargo build -p qmdb` runs the verifier: every law needs a proof, every step
is checked by the kernel, and the build prints `verified ... N obligation(s)
proven`. A law without a proof is an *open claim* and fails the build.

A proof body is a list of **steps**. Each step either transforms the goal
(`unfold`, `rewrite`, a case split) or adds a fact (`assert`, a lemma
application). A block ends with a **closing statement** that says *why* the
goal left there holds — by computation, by contradiction, by arithmetic, by
unfolding a definition, or by the automation's general reasoning — and the
build checks that reason, not just the goal (section 3). A block may also
end with a step whose result *is* the goal: a lemma whose conclusion is the
goal, a `by_cases(x)` split (the automation, "auto", closes each case), or
a `calc!` chain of the goal. When a block ends any other way (say after an
`apply(lemma)` whose conclusion still needs a step of arithmetic), auto
still closes it but the build **warns** until you write the closing
statement. If a check fails, the build fails with the goal and the facts it
had (section 5).

```rust
// LAWS.rs: the claim, over spec items only
#[law]
fn current_updates_have_proofs(db: Db, location: Nat, key: Digest, value: Digest) {
    requires(db.well_formed() && db.is_current(location, update(key, value)));
    ensures(exists(|p: Proof| p.location == location && verify(db.root(), key, value, encode(p))));
}

// PROOF.rs: the proof
#[proof]
fn current_updates_have_proofs(db: Db, location: Nat, key: Digest, value: Digest) {
    db_nonneg(db);                                          // facts: the Nat fields are >= 0
    well_formed_parts(db);                                  // the parts of `well_formed`
    current_parts_of(db, location, update(key, value));     // the parts of `is_current`
    honest_verifies(db, location, key, value);              // the honest proof verifies
    honest_numbers(db, location, db.log.len(), db.inactive);
    witness(honest(db, location, db.log.len(), db.inactive)); // closes the `exists`
}
```

Inside `PROOF.rs` a law's name stands for the law itself: calling
`equal_roots_agree(a, b)` uses that law as a lemma.

### Panic contracts: where the code panics

A lifted function whose documentation says when it panics states it in the
laws file, beside its other contracts (DESIGN.md §16.5):

```rust
/// `halve_capped` is half of `x`, and panics above 1000.
#[lift_attach(crate::a::halve_capped)]
fn halve_capped_contract() {
    panics_when(x > 1000u64);
    ensures(|ret: u64| ret == x / 2u64);
}
```

`panics_when(p)` says: where the function's `requires` hold, it panics if
and only if `p` holds. Its `ensures` hold where it does not panic, and the
spec sheet and the lock show `panics_when p` (only the laws file states
one: it is part of the locked contract). The build proves both directions
of rustc's MIR, with nothing for you to write:

* **Where `p` does not hold**, the function returns as its laws say. `!(p)`
  is its last precondition, so every `unreachable!()` the structured
  reading has where the MIR panics, and every operator that could
  overflow, must follow from it. If `p` misses a panic (it is *too
  narrow*), that obligation fails: the function is not elaborated, and the
  error names the panic's line. Callers in the module prove `!(p)` at
  their call, like any precondition, or state their own panic contract.
* **Where `p` holds**, the MIR panics (the panic theorem; the gate's
  `mir-theorems` note counts them). The walk follows the literal reading
  under `p` and splits each test `p` does not decide; a path that returns
  is refuted from `p` and the path's tests. If `p` covers an input where
  the code returns (it is *too wide*), the error is `the literal reading
  returns a value on a path where the panic condition holds` with the
  path's facts: pick `p` as the documentation states it. A path that loops
  forever, aborts or is undefined behaviour is never a panic.

State `p` as the documentation states it, in the laws' vocabulary:
`(size.0 as Int) > crate::laws::max_nodes()`, `(self.0 as Int) + (rhs as
Int) >= pow2(64)`, `x.is_none()`, a disjunction `height >= 64u32 ||
(pos.0 as Int) < pow2(height as Int)` (the walk splits it). The walk's
arithmetic is linear: it decides a panic condition that compares the
parameters with what the code compares them with. When the code computes
the test with operations the laws do not use (a shift by a variable
amount, `leading_zeros`, `count_ones`, wrapping arithmetic), give the walk
the panic condition in the code's own terms with a **panic lemma** in the
proof file:

```rust
/// `new`'s panic condition as its code tests it: above `MAX_NODES` the
/// size's top bit is set, so `start`, `u64::MAX >> leading_zeros`, is
/// `u64::MAX` (its `assert_ne!`).
#[lemma]
fn new_panics(size: Position) {
    requires((size.0 as Int) > crate::laws::max_nodes());
    ensures(size.0.leading_zeros() == 0u32 && (u64::MAX.wrapping_shr(size.0.leading_zeros()) == u64::MAX) == true);
    // ... its proof, as for any lemma
}

#[lift_attach(crate::merkle::mmr::iterator::PeakIterator::new)]
fn new_facts() {
    panic_lemma(crate::proof::new_panics);
}
```

The lemma's parameters are the function's, in order; each of its
`requires` must be one of the panic theorem's hypotheses as written (a
`requires` of the function, or its panic condition). The walk applies it
and uses its `ensures` as facts. Write them in the terms of the literal
reading: rustc's `a << s` is `a.wrapping_shl(s)` (MIR's `Shl` masks its
amount), a checked `a + b` that did not overflow is `a.wrapping_add(b)`,
and so on (`docs/mir-lift.md` §20.4); a fact that does not match the
code's term is simply not used. A lemma is a proof internal: it is never
locked, and a wrong one cannot make a wrong panic contract pass (its
`ensures` are proven).

A panic reached only after many steps (more than 48 split tests or loop
iterations on its path, the panic walk's bound; its fuel premise is 64) is
not proven yet: the error says the literal reading `does not reach a panic
within the walk's bound`.

**A domain, a panic, or both.** A function can have a `requires` and a
panic contract: `requires` is the domain (outside it nothing is
promised), `panics_when` splits the domain. Keep a documented condition as
a `requires` when the code does not simply panic outside it: when it
returns a wrong or meaningless value there (`chunk_peaks` past
`MAX_LEAVES`, where a shift drops high bits and it returns another
chunk's root), or when the documentation makes it the caller's guarantee
and the code's behaviour there is not to be relied on
(`location_to_position` above `MAX_LEAVES`). Say so in its doc comment.
A function whose code cannot panic on its domain needs no panic contract:
its theorem already says it returns there.

## 2. What auto does, and what it does not

Auto is proof search that has to produce a proof term, which the kernel then
checks. It:

* **evaluates** transparent functions. Exec functions are transparent. Codec
  readers (`parse`, `digest`), hashes and buffer builders are opaque: auto
  treats them as unknown functions and only knows that they are deterministic;
* uses the **facts** in scope: `requires` hypotheses, path equations from case
  splits, and conclusions of `assert` steps and lemma applications. It splits
  `&&`, uses constructor clashes (`None != Some(..)`) and rewrites with
  equations. Some facts are put in a more useful form:
  * `a != b` on integers (`requires(n != 0usize)`, `requires(h != g)`) is
    also the boolean fact `(a == b) == false`. It decides an unfolded
    `if a == b`, and for an unsigned `a != 0` it gives `0 < a`, so
    `n - 1` needs no extra step. Write `requires(n != 0usize)`, not
    `requires((n != 0usize) == true)`;
  * a fact `a && (b && (c && ..))` gives every conjunct, however long the
    chain;
  * a fact `a || b` and a fact `!b` give `a` (and `!a` gives `b`), without
    waiting for a case split;
  * a fact `!(a || b)` (a panic contract's no-panic clause) gives `!a` and
    `!b`, and a negated comparison `!(x < y)` is the fact `(x < y) ==
    false`, which linear arithmetic reads; a goal `!(a || b)` (a callee's
    no-panic clause at its call) is the two goals `!a` and `!b`;
  * a fact about a function at one argument proves the same statement at an
    argument that is equal by arithmetic: `r(y) == 4` and `y + 1 == x`
    give `r(x - 1) == 4`. You do not need a lemma that restates `r` at
    `x - 1`;
  * a fact `call == Some(v)` rewrites a goal that matches on `call`, also
    when the goal is a proposition (`match call { Some(w) => *w == v, None
    => false }`);
  * one link `requires(view(e) == s)` between an exec record `e` and a spec
    record `s` (with `view` building the spec record from `e`'s fields)
    gives every field equation; do not state the fields one by one. The
    narrow closers (`by_arithmetic()`, `by_unfolding(..)`) get these field
    equations too, but only what the record is made of: every field of a
    type's `#[view]`, and for any other function the fields its body copies
    from its arguments (a field, a cast of a field: `location: p.location
    as Nat`). A computed field (`a: x + 7`) is what the function computes:
    the narrow closers need `by_unfolding(mk)` for it;
  * a fact is **simplified with what the facts say**. A fact that matches on
    a test (`if b.len() < n { None } else { Some((b.take(n), b.skip(n))) }
    == Some((a, r))`, the body of a function unfolded in a fact) is decided
    by the value it equals: only the `else` arm can be `Some`, so the fact
    gives `b.len() >= n`, then `b.take(n) == a` and `b.skip(n) == r`. A
    test that other facts decide is taken the same way, and a variable that
    a fact fixes (`first == false`) is put in wherever the fact mentions it;
  * a fact about a recursive function of your crate applied to a
    constructor (`groups(seq![g, ..rest], first) == Some((x, r))`, in the
    `[g, rest @ ..]` case of a proof) is unfolded one step: the step's facts
    (`x == g as Nat - 128 + 128 * y` for the rest's `y`) need no one-step
    lemma;
* works on the **goal** the same way:
  * a variable that a fact defines (`b.take(n) == a`) is replaced by its
    definition when the goal is stuck, so `a.len() == n` uses what is known
    about `b.take(n)`;
  * a goal `C(a₁, ..) == C(b₁, ..)` with one constructor on both sides
    (`seq![g, ..rest] == seq![c, ..more]`, `Some(x) == Some(y)`) is the
    equations of its arguments, each proven on its own — through layers of
    different types (`Some((P(e), g)) == Some((P(x), g))` down to
    `e == x`, at most three), but one level of a recursive structure (a
    list's tail, a subtree, is one equation). So a contract may name the
    value it returns the way the code builds it, through its constructors
    (`ret.v == Some((Position::new(n as u64), g))`), instead of reading the
    value back field by field;
  * a contract that names a function known by its contract only (an
    opaque function, a constructor with a loop) has that function's
    contract as a fact in its proof, as a call in a body does;
  * a goal `p || q` whose side depends on a case (`first || x > 0` when a
    fact says `g != 0 || first`) is proven by splitting that case first;
  * a sequence whose length the facts fix at 0 is `seq![]` (`xs.len() == 0`
    gives `seq![..xs, x] == seq![x]`);
* decides **linear arithmetic** over integers (`+`, `-`, `*` by a constant,
  comparisons, `min`/`max`/`saturating_*` by case analysis, casts). It
  reasons over the integers, not just the rationals: when a fractional
  solution blocks the proof, it splits on an arithmetic atom (an integer
  cut: `x & 1 < 1` or `x & 1 >= 1`; `a != b` as `a < b` or `a > b`),
  within the step budget;
* does **bounded case splits** on stuck `bool`/enum values and enumerates
  small integer ranges (at most 64 values).

It does **not**:

* do induction. You write that with `#[induction(x)]` and `ih(..)`;
* guess which lemma to use. Your proof applies it (`apply(lemma)` finds the
  arguments);
* do nonlinear arithmetic beyond the monotonicity facts of a product below
  (`x * y` with two variables is otherwise unknown; no `x / pow2(e)` or
  `x % pow2(e)` for a variable `e`);
* look inside opaque functions;
* search without limit. Every goal has a step budget and a time limit, and
  running out counts as a failure.

### The built-in library

Auto also knows the following facts. You do not state or call them; each
is a kernel-checked lemma (no axioms), used when its side conditions follow
from the facts in scope by linear arithmetic.

* **Sequences** (`sandblaster::lemmas::seq::*`). `get`, `skip`, `take`, `++`
  and indexing simplify against each other: `xs.skip(k).get(i)` is
  `xs.get(i + k)`; `seq![..xs, ..ys].get(i)` is `xs.get(i)` below
  `xs.len()` and `ys.get(i - xs.len())` from there on (`skip`, `take` and
  `xs[i]` alike); `seq![x, ..t].skip(k)` is `t.skip(k - 1)` for `k > 0`;
  `xs.skip(k)` is empty and `xs.take(k)` is `xs` once `k >= xs.len()`;
  `xs.get(i)` is `Some(xs[i])` in range and `None` past the end;
  `seq![..xs.take(n), xs[n]]` is `xs` for `n + 1 == xs.len()` (the
  `[init @ .., last]` view). To call one by name, write the element type:
  `sandblaster::lemmas::seq::take_snoc::<u8>(xs, n);`.
* **Slices and their views.** With a fact `xs == ys` (the slice `xs` viewed
  as the sequence `ys`), auto knows `ys.len() == xs.len()`, and slice
  patterns (`[head, ..]`, `[.., last]`), `first()`, `last()`,
  `split_first()`, `split_last()`, `xs.get(i)` and `xs[i]` read the
  elements of `ys`; `&xs[k..]` is `ys.skip(k)`. `Some(a) == Some(b)` and
  `(a, b) == (c, d)` reduce to their components.
* **Arrays filled by ranges.** After `buf[..4].copy_from_slice(a);
  buf[4..].copy_from_slice(b);` the view of `buf` is `seq![..a, ..b]`.
* **Shifts.** For a shift amount `s` below the width (`u8` to `u64`),
  `x >> s` is `x / pow2(s)`. So `(b >> s) & 1 != 0` and
  `(b / pow2(s)) % 2 == 1` are the same test. A boolean equation between
  two comparisons is proved by trying both values of one side.
* **Division by a literal.** From `x == k * m + c` with `0 <= c < k` (a fact,
  or the shape of the dividend itself, as in `(a + 128 * y) % 128` with
  `a < 128`), auto derives `x / k == m` and `x % k == c`. Two divisions of
  equal values by the same literal are equal.
* **`pow2` and `popcount`.** Next to `1 <= pow2(n)`, auto uses
  `pow2(e + 1) == 2 * pow2(e)` (for `e >= 0`) and `pow2(a) <= pow2(b)` (for
  `a <= b`) for the `pow2` terms that occur in the goal and the facts, and
  `popcount(x) == x % 2 + popcount(x / 2)` for `x >= 0` when `x % 2` or
  `popcount(x / 2)` also occurs there (auto does not unroll `popcount`
  further on its own: for `popcount(x / 4)`, state the step you need).
* **Products of two unknowns.** For `a * b` with no literal factor, auto
  knows `0 <= a * b` when both factors are nonnegative, `b <= a * b` when
  `a >= 1` (and `a <= a * b` when `b >= 1`), and `a * b <= U * b`,
  `a * b <= a * V`, `a * b <= U * V` for literal bounds `a <= U`, `b <= V`.
  So `(c + 1) * pow2(g) <= pow2(62)` gives `pow2(g) <= pow2(62)`.
* **Exponents.** For a goal about the exponent of a power (`g <= 62`,
  `t + 1 < 64`: every variable of the goal inside the exponent of a
  `pow2(..)` in the facts), auto bounds the exponent through the power:
  when `pow2(g) <= U` follows from the facts for a number `U` they mention
  (directly, or through a product as above), it derives
  `g <= ⌊log₂ U⌋`.
* **Complements.** `!x` is `MAX - x` (`u64::MAX - x` for a `u64`), so
  facts about `(!n).trailing_zeros()` meet facts about `n`.
* **Trailing zeros and ones** are not built in beyond the bit library's
  per-step facts; for every count at once, call
  `crate::stdlib::bits::trailing_zeros_u64(x)` (`x` is `2^z` times an odd
  number) or `trailing_ones_u64(n)` (`n + 1` is `2^t` times an odd number),
  and the `u8`/`u16`/`u32`/`usize` versions.

Not covered yet: division or remainder by `pow2(e)` for a variable `e` (the
kernel has no rule for a division by a non-literal divisor, so write such
geometry with `/ 2` and `% 2`), left shifts and `usize` shifts by a variable
amount.

## 3. The statements

### Closing statements — say *why* the goal holds

The last statement of a block names the reason the remaining goal holds.
The build checks the **reason**: a closing statement fails when the goal
needs more than it claims, even if auto could prove the goal some other
way. So a reader can trust the one word at the end of each case.

| Statement | What it claims (and what the build checks) | Typical use |
| --- | --- | --- |
| `by_computation();` | the goal evaluates to `true`: evaluation only, no search. The only facts it uses are the ones that fix a variable to a value (`x == 3`, `o == None`): the value is put in for the variable first | a case whose result the code fixes: `None => by_computation()` |
| `by_contradiction();` | the facts of this case contradict each other, so it cannot happen. The prover must derive the contradiction from the facts alone; the goal is not used | impossible arms of a `match` or `by_cases` |
| `by_arithmetic();` | arithmetic and equality reasoning on the facts. Every function of the crate (with or without parameters) is **unknown**: only what the facts say about it counts. Two kinds of fact come with the code rather than from the facts in scope, and are used too: the Nat range `0 <= f(x)` of a spec function's `Nat` results, and the field equations of a view link `s == view(e)` (every field of a type's `#[view]`; for another function only the fields it copies from its arguments; see "What the narrow closers see"). The built-in operations are not unknown: their built-in rules are used (see "What arithmetic includes" below: `Seq` and slice operations, `pow2`/`log2`/`popcount` on literals). No case analysis on program values (`bool`/`Option`/enum scrutinees, matches). Integer reasoning is complete linear *integer* arithmetic: it may split internally on arithmetic atoms (integer cuts `a < c` or `a >= c`; `a != b` as `a < b` or `a > b`). That is arithmetic, not case analysis | bounds and inequalities that follow from the hypotheses |
| `by_unfolding(f, g);` | like `by_arithmetic()`, after unfolding **exactly** `f` and `g`, in the goal and in the facts (see below). What they call stays unknown: if the step needs it too, name it as well | a step that depends on what `f` computes |
| `follows();` | the goal follows from the facts in scope by auto's general reasoning: arithmetic, unfolding transparent functions, bounded case splits, prelude lemmas | when no narrower reason applies |

**Which closer to use.**

| The step holds because ... | Write |
| --- | --- |
| the code computes the answer (no facts needed) | `by_computation();` |
| this case cannot happen (its facts contradict each other) | `by_contradiction();` |
| of arithmetic and equalities on the facts | `by_arithmetic();` |
| of what `f` computes (plus arithmetic) | `by_unfolding(f);` |
| none of the above, or it needs a case split on a program value or a prelude lemma | `follows();` |

Try them in the order of the table: the first one the build accepts is the
most informative. `by_arithmetic()`'s error names the functions it treated
as unknown, which is the list to choose from for `by_unfolding(..)`.
`follows()` is the fallback, not the default.

**`follows()` is checked too.** It fails the build when the goal cannot be
derived from the facts in scope: every proof auto finds is re-checked by
the kernel, so a goal that does not follow can never pass. The search is
bounded, so it can also fail on a step that is true but too big: then add
an intermediate step (an `assert`, a lemma, a `calc!` link) and try again.
The search is deterministic: the same proof gives the same result on every
build and every machine.

All of them must be the last statement of their block. An **empty** proof
body, case arm or branch (or an `if` without `else`) still works (auto
closes it, as with `follows()`), but produces a warning; so does a block
that ends after other statements without a closing statement, unless what
is left is closed by evaluation (`a == a`) or is exactly a fact in scope
(for example the conclusion of the lemma just applied). `by_auto()`, the
former catch-all, is an error that lists these statements, and
`follows_from_facts()` is an error that says to write `follows()`.

**What the narrow closers see.** `by_arithmetic()` and `by_unfolding(..)`
work on the facts in scope, with these rules:

* **Facts are unfolded too.** `by_unfolding(f)` unfolds `f` once in every
  fact that calls it, not just in the goal. For a recursive `f` the fact
  gets one step of the definition (the recursive calls in the body stay as
  they are), and the tests the body makes on its arguments (`n == 0`, a
  `Nat` parameter's `0 <= n`) are decided from the other facts when linear
  arithmetic settles them. So a one-step equation of a recursive function
  needs no helper lemma:

  ```rust
  #[spec] #[decreases(n)] fn r(n: Nat) -> Nat { if n == 0 { 0 } else { r(n - 1) + 2 } }
  #[lemma] fn step(n: Nat) {
      requires(n >= 1 && r(n) == 7);
      ensures(r(n - 1) == 5);
      by_unfolding(r);  // r(n) == r(n - 1) + 2 because n != 0
  }
  ```

  `by_arithmetic()` unfolds nothing: the same step fails with it.
* **A `let` is its value.** `let z = x + 1;` names `x + 1`; the closers see
  through the name, so `r(z)` and `r(x + 1)` are the same term.
* **`Nat` values are non-negative.** A spec function whose result is a
  `Nat` (or holds `Nat`s: tuple and struct fields, the contents of an
  `Option`) comes with the fact `0 <= f(x)` for each of them, wherever the
  function is called. The build proves this once per function, like an
  `ensures`, by induction for a recursive function (its recursive calls,
  also those bound by a `let`, give the induction hypotheses). The proof
  does not always go through: when the body takes a `Nat` out of something
  whose contents carry no bound (a parameter of type `Option<(Nat, ..)>`,
  an element of a `Seq<Nat>`), the function has no such fact. A failing
  step about such a function says so (`f has no automatic Nat range
  fact`) and names where the range proof stopped; state the bound you
  need as a lemma. With the fact, a `Nat` bound by a pattern (`Some((y,
  rest)) = grp(b)`) or read from a field (`mk(x).a`) can be passed to a
  `Nat` parameter, and the `0 <= n` guard of a `Nat`-parameter helper is
  decided. The fact is the range only: it says nothing about upper
  bounds. A goal that is itself a `match` on a call of a recursive spec
  function (`ensures(match cnt(n) { Some(k) => k >= 0, None => true })`)
  is not split by auto, with or without a range: write the `match` in the
  proof (`match cnt(n) { Some(k) => follows(), None => follows() }`).

What "arithmetic" includes: linear arithmetic over integers (`+`, `-`,
`*` by a constant, comparisons), the built-in facts about `min`/`max`,
`saturating_*`, shifts, masks, casts and `count_ones`, the built-in rules
of the ghost `Seq` and of slices and arrays (the rewrite rules of the
built-in theory: lengths, `&s[0..]` is `s`, `xs.skip(1).get(0) ==
xs.get(1)`, `get`/`index` over `take`/`skip`/`append`, chunking and
flattening), evaluation of the built-in functions on literal arguments
(`pow2(3)` is `8`, also after a fact fixes the argument: `e == 3`),
equations among the facts, splitting `a && b` facts, constructor clashes
(`None != Some(..)`) and congruence (`x == y` gives `f(x) == f(y)` for any
`f`). It does not include instantiating a `forall` fact or a lemma of the
crate: that is `follows()` (or `apply`).

```rust
// before: every case ended in the same `by_auto()`
match root {
    None => by_auto(),
    Some(_) => apply(inactive_decoded_rejected),
}
// after (inactive_parsed): with no root, `verify_parsed` returns `false` outright
match root {
    // no root: rejected before the proof is looked at
    None => by_computation(),
    Some(_) => apply(inactive_decoded_rejected),
}
```

```rust
// root_matches_sound: requires(verifier::root_matches(&root, candidate))
match candidate {
    // `root_matches(_, None)` is false: this case cannot happen
    None => by_contradiction(),
    // a found root matches when its bytes are equal
    Some(_) => apply(digest_equal_sound),
}
```

```rust
// before
#[proof]
fn bag_prefix_order(n: usize, head: Digest, tail: &[Digest], acc: Digest) {
    // one step of `bag_prefix` on `cons(head, tail)`: `n + 1 != 0`, `(n + 1) - 1 == n`
    by_auto();
}
// after: the step depends on the definition of `bag_prefix` and nothing
// else; `fold`, which it calls, stays unknown (both sides call it with the
// same arguments)
#[proof]
fn bag_prefix_order(n: usize, head: Digest, tail: &[Digest], acc: Digest) {
    // one step of `bag_prefix` on `cons(head, tail)`: `n + 1 != 0`, `(n + 1) - 1 == n`;
    // both sides then call `bag_prefix` on `tail` with the same `fold(acc, head)`
    by_unfolding(merkle::bag_prefix);
}
```

```rust
// bag_prefix_partition, case `xs == []`: the base case of `bag_prefix` calls
// `fold_back_join` and `fold_back`, and the step needs what they return
[] => by_unfolding(merkle::bag_prefix),  // fails: `fold_back_join`, `fold_back` are unknown
// after
// `bag_prefix(0, [], acc)` is `fold_back_join(acc, fold_back([]))`, which is
// `Some(acc)`: both sides continue with `bag_prefix(n, ys, acc)`
[] => by_unfolding(merkle::bag_prefix, merkle::fold_back, merkle::fold_back_join),
```

```rust
// before: the arm ended with the lemma; auto found the contradiction silently
None => key_chunk_none(root, key, value, proof),
// after: the lemma says a short key rejects, but the input was accepted
None => {
    key_chunk_none(root, key, value, proof);
    by_contradiction();
}
```

```rust
#[spec] fn twice(x: u8) -> Int { 2 * (x as Int) }
#[lemma] fn a(x: u8) { requires(twice(x) <= 100); ensures(twice(x) + 1 <= 101); by_arithmetic(); }  // ok: `twice` stays unknown
#[lemma] fn b(x: u8) { ensures(twice(x) <= 510); by_arithmetic(); }  // fails: needs what `twice` computes
#[lemma] fn c(x: u8) { ensures(twice(x) <= 510); by_unfolding(twice); }  // ok
```
```text
error[obligation]: unproven obligation [ensures] in `crate::b`
  = note: `by_arithmetic()`: the goal does not follow from the facts in scope by arithmetic and equality reasoning alone (the crate's functions are unknown, no case analysis on program values)
  = note: treated as unknown functions: `twice` — if the step depends on what they compute, name them: `by_unfolding(twice)`
  = note: if the step needs a case split on a program value, split with `by_cases(..)` or write `follows()`; if a quantified fact or a lemma is needed, apply it first; `by_computation()` if the goal holds by evaluation alone
  | goal: Eq(Bool, #le_int(crate::twice x, 510int), true)
```

`by_contradiction()` fails when the facts are consistent, even if the goal
is true:

```rust
#[lemma] fn l(a: u8) { requires(a > 10); ensures(a > 5); by_contradiction(); }
```
```text
error[obligation]: unproven obligation [ensures] in `crate::l`
  = note: `by_contradiction()`: the facts in scope must contradict each other on their own; the goal is not used
  = note: the goal (not used): Eq(Bool, #gt_u8(a, 5u8), true)
  = note: if the case is possible, the goal needs a proof of its own: `by_arithmetic()`, `follows()` or more steps
  | goal: Empty
  |   fact: Eq(Bool, #gt_u8(a, 10u8), true)
```

### `by_cases(x);` — split on every value, auto closes each case

`by_cases` takes a `bool`, an `Option` or an enum (several values nest:
`by_cases(a, b)`), or an integer with its range: `by_cases(k, lo..hi)`, or
`by_cases(k in lo..hi)` inside `proof! { .. }`. The statements **after** a
`by_cases` run in every case. Use `match` when a case needs steps of its own.

```rust
// before (reconstruction_gate)
    if ok {
    } else {
    }

// after
    // with `ok == false` the reconstruction returns `None`, not `Some(root)`
    by_cases(ok);
```

```rust
// before (inputs_accepted): four nested empty `if`s
    if a { if b { if c { if d {} else {} } else {} } else {} } else {}
// after
    // a failed length check rejects
    by_cases(a, b, c, d);

// before (no_proof)
    match root { None => {} Some(_) => {} }
// after
    // with or without a root, a missing proof rejects
    by_cases(root);
```

`cases(k, lo..hi, { steps })` (the older integer form) still works.

### `by_computation();` in detail — the goal holds by evaluation alone

The goal must be an equation (or a `bool`) whose two sides **evaluate to the
same value**. No search runs. The only facts it uses are the ones that fix a
variable to a literal or a constructor (`e == 0`, `x == 3`, `o == None`): the
variable is replaced by its value before the sides are evaluated. Bounds
(`e <= 0 && e >= 0`) do not count; that is `by_arithmetic()`. Use it to
document that a step is a plain computation. If it fails, the error shows
both evaluated sides:

```rust
#[lemma] fn get_some(v: u8) { ensures(get(Some(v)) == v); by_computation(); }  // ok
#[lemma] fn p0(e: Int) { requires(e == 0); ensures(pow2(e) == 1); by_computation(); }  // ok: `e` is 0
#[lemma] fn l(a: u8, b: u8) { requires(a < b); ensures(a <= b); by_computation(); }
```
```text
error[obligation]: unproven obligation [ensures] in `crate::l`
  = note: tried: `by_computation()`: evaluation only, no proof search
  = note: left side evaluates to: #le_u8(a, b)
  = note: right side evaluates to: true
  = note: the evaluated sides differ: the goal needs facts or reasoning beyond evaluation (`by_arithmetic()`, `by_unfolding(..)`, `follows()` or more steps)
```

(Here `by_arithmetic()` is the right closer: `a <= b` follows from `a < b`.)

### `apply(lemma);` — use a lemma without writing its arguments

`apply` reads the arguments off the facts in scope. It matches each
`requires` of the lemma against the facts, and its `ensures` against the goal,
unfolding transparent functions on the way (`verify` into `verify_inputs(..)`,
`reconstruct_shape` into `reconstruct_checked(..)`). The lemma's hypotheses
are then proven as for an explicit call, and its conclusion becomes a fact
(`let h = apply(lemma);` names it). A fact that states a hypothesis by cases
(a `match` or `if` in a statement, such as a `use_hyp(..)` instance) serves
a lemma's `requires` as it is. If no instantiation fits, or two different
ones fit equally well, the build fails and lists the requires, the facts and
the candidates. In that case, call the lemma explicitly: `lemma(a, b, ..);`.

```rust
// before (merkle_digest_count): the gate lemma's 14 arguments, re-typed
            reconstruction_gate(
                inactive as u64 <= selected.before as u64 + selected.after as u64 + 1
                    && digests.len() as u64 == required_digests(selected, inactive),
                leaves,
                inactive,
                selected.before.min(inactive),
                (selected.before as u64).saturating_sub(selected.before.min(inactive) as u64)
                    + (selected.before.min(inactive) != 0) as u64,
                ... // 9 more lines
            );
            witness(selected);

// after
            // the reconstruction succeeded, so its count check passed ...
            apply(reconstruction_gate);
            // ... which is `ShapeCount` for the selected shape
            witness(selected);
```

Explicit calls are still the right choice when a fact cannot determine the
arguments, for example `chunk_exact(key, *k)`: both `key` and `value` would
match, so `apply` would be ambiguous.

### `#[induction(x)]` and `ih(args);` — proofs by induction

Mark the proof with the parameter it recurses on. `ih(args)` applies the
induction hypothesis, meaning the same claim for smaller arguments. The front
end checks that every `ih` passes a structurally smaller `x`: the rest of a
`match x { [head, tail @ ..] => .. }` for slices, or `x - k` (literal `k >= 1`)
for unsigned integers. On a `Nat` or `Int` parameter, `#[induction(n)]` makes
`n` the measure (as `#[decreases(n)]` would): every `ih(..)` must pass a
smaller, non-negative value, which the build proves at the call. The kernel
checks termination. `ih` without `#[induction]` is an error. A recursive call
by the proof's own name still works.

### Function values in ghost code — one law for every fold

Spec functions, lemmas, laws and proofs may take function parameters, written
`f: fn(A, T) -> A` (DESIGN.md §13.2's `spec_fn`), call them (`f(a, x)`), and
pass lambdas `|a: A, x: T| e`, spec functions by name (`join`) or tuple
constructors of non-generic types (`Tree::Pruned`). They are the kernel's `Π`,
`λ` and application, and never reach exec code: exec code rejects closures and
function types, and a function value is never stored in data, returned, or used
as a type argument. A function type never mentions `Nat` or `Prop` (write
`Int`, `bool`): no bound travels with a function value.

`crate::stdlib::folds` states the list laws once, for every function:
`fold_left_append(xs, ys, a, f)`, `map_take_skip(xs, j, f)`,
`all2_take_skip(xs, ys, j, r)`, `fold_left_rel(..)`, `fold_left_inj(..)`, and so
on. A law about one step of a fold takes the step as a `forall` premise, which
auto discharges at the call, or which a lemma whose `ensures` is a `forall`
puts in scope first:

```rust
/// Fold steps agree exactly when their parts do.
#[lemma]
fn join_agree() {
    ensures(forall(|a: Tree, b: Tree, x: Tree, y: Tree| implies(agree(a, b) && agree(x, y), agree(join(a, x), join(b, y))))
        && forall(|a: Tree, b: Tree, x: Tree, y: Tree| implies(agree(join(a, x), join(b, y)), agree(a, b) && agree(x, y))));
    follows();
}
// … then, for two agreeing lists:
join_agree();
fold_left_rel(xs, ys, x, y, join, join, agree, agree);
```

A `forall` conclusion is the fact itself: applying such a lemma does not demand
its bound variables. Facts from the library mention `all(xs, p)` or
`all2(xs, ys, r)` directly; a restricted closer (`by_unfolding(..)`) that must
see through a local wrapper such as `hashes(xs)` names it.

### `calc! { .. }` — a chain of equalities (or `<=`, `<`)

```rust
calc! {
    e0
        == e1 by { steps };   // each link proven by its block (ending in a closing statement) ...
        == e2;                // ... or without `by` when evaluation or a fact gives it
        <= e3 by { steps };   // `<=` / `<` links for integers
}
```

A link without `by` that needs more than evaluation or a fact still
passes if auto proves it, with a warning: write `by { follows(); }` (or a
narrower closer).

The chain proves `e0 R en` (`<` if any link is `<`, else `<=` if any link is
`<=`, else `==`). If `calc!` is the last statement of a block, `e0 R en` must
be the goal. Otherwise it becomes a fact. A wrong link fails **at that link**.

A chain may start with links between exec values and continue with a link
from an exec value to a spec value (a view equality, `exec_value ==
spec_value`): the exec part is carried through the view, and the chain
proves `exec_first == spec_last`.

```rust
calc! {
    crate::exec::wrap2(xs)
        == crate::exec::wrap(xs) by { by_unfolding(crate::exec::wrap2); };  // exec == exec
        == swrap(ys) by { direct(xs, ys); };                                  // exec == spec
}
```

```rust
// before (bag_prefix_partition): asserts, lemma calls and a recursive call
        [head, tail @ ..] => {
            bag_prefix_order(tail.len() + n, *head, seq::append(tail, ys), acc);
            bag_prefix_order(tail.len(), *head, tail, acc);
            bag_prefix_partition(tail, ys, n, merkle::fold(&acc, head));
            assert(merkle::bag_prefix(xs.len() + n, seq::append(xs, ys), acc)
                == merkle::bag_prefix(tail.len() + n + 1, seq::cons(*head, seq::append(tail, ys)), acc));
            assert(merkle::bag_prefix(xs.len(), xs, acc) == merkle::bag_prefix(tail.len() + 1, seq::cons(*head, tail), acc));
        }

// after (with #[induction(xs)] on the proof)
        [head, tail @ ..] => {
            let folded = merkle::fold(&acc, head);
            calc! {
                merkle::bag_prefix(xs.len() + n, seq::append(xs, ys), acc)
                    // `xs` is `head` followed by `tail`
                    == merkle::bag_prefix(tail.len() + n + 1, seq::cons(*head, seq::append(tail, ys)), acc) by { follows(); };
                    // one bagging step folds `head` into the accumulator
                    == merkle::bag_prefix(tail.len() + n, seq::append(tail, ys), folded) by { apply(bag_prefix_order); };
                    // the law for `tail`
                    == match merkle::bag_prefix(tail.len(), tail, folded) { .. } by { ih(tail, ys, n, folded); };
                    // the same bagging step, backwards, on the left prefix
                    == match merkle::bag_prefix(xs.len(), xs, acc) { .. } by { .. };
            }
        }
```

### The other statements

| Statement | Use it to |
| --- | --- |
| `assert(p);` / `assert(p, { steps });` | prove an intermediate fact (by auto, or by the steps) |
| `lemma(args);` / `let h = lemma(args);` | apply a lemma with explicit arguments (its `requires` are proven at the call; an `ensures(implies(a, b))` becomes the fact `a -> b`, and `a` is not demanded) |
| `match e { pat => { steps } .. }` | split by cases when a case needs its own steps; on a variable the goal is refined, on an expression its occurrences in the goal are replaced by the pattern (also where the goal names the expression's parts with a `let`, as the unfolded body of an exec function does). A match on a slice (`[head, tail @ ..]`, `[init @ .., last]`) keeps the goal: its bindings (`tail` is `&xs[1..]`, `last` is `xs[xs.len() - 1]`) and its length tests are the facts of each case. After `unfold(f)`, the facts of `f`'s body that the case exposes (a callee's `ensures` or `refines` on the pattern's variables) become facts of the case |
| `if c { .. } else { .. }` | the same, on a `bool` |
| `witness(e, ..);` | prove an `exists(..)` goal with the given values |
| `unfold(f);` | replace the calls of `f` written in the goal by its body — in every conjunct of a `&&` goal and on both sides of `||`, but not in the arms of a boolean `&&` or `if`, and not the calls the body brings in, also where the goal writes the same call elsewhere: in `f(s) == match f(left(s)).3 { .. }` the right side's `f(left(s))` stays folded, since unfolding it would unfold the body's copy with it (the other calls stay as they are; with no such call the goal is unchanged and the build warns). A call that sits only in an arm of a match of the goal (the unfolded body of an exec function calls `byte(xs)` in the arm of its `fuel == 0` test) is unfolded there. The facts of the unfolded body that depend only on the proof's context — a callee's `ensures` and `refines` at its call, slice bounds — become facts of the proof |
| `rewrite(a == b);` / `rewrite(lemma(..));` / `rewrite_rev(..)` | replace `a` by `b` in the goal (the equation is proven first) |
| `exact(term);` | close the goal with a proof term |
| `bv();` | close a machine-word equation (DESIGN.md §9.8). An equation with a shift by a variable amount, `/` or `%` that word algebra does not decide goes to linear arithmetic with the built-in shift and `pow2` rules. That step uses only the facts that bound the shift amounts and `pow2` exponents (`requires(s < 8)`, for an `s` the goal uses only as an amount: a variable that is also shifted, divided or compared is a value, and facts about it are not used) and the ranges that come with a type (`0 <= x` of a `Nat`), so `bv()` still claims a word identity: `requires(x == 10); ensures(x / 2 == 5); bv();` fails and says to write `by_arithmetic()`, and so does a step that needs a type's `#[invariant]` |
| `let x = e;` | name a value: the closers see through the name (`x` is `e`). Before `requires`/`ensures` it abbreviates the contract: `let t = peak_of(n, i); requires(t.height > 0); ensures(..t..);` |
| `show();` | print the goal and the facts (a warning) |
| `todo();` | leave the goal open (the build fails and prints it) |

`rewrite(a == b)` also works when the side being replaced is a variable
(`rewrite_rev(tagged(b[1]) == b)` replaces the array `b` by its encoding).

In a `proof! { .. }` block of exec code, a lemma of `PROOF.rs` is named by
its path (`crate::proof::sum4_le(&first);`). It does not need to be
`pub(crate)`: ghost code is never compiled by rustc.

Long `&&` / `||` chains (five or more operands) in spec functions,
contracts and proofs are fine in either nesting: `a && b && c && d && e`
(which parses left-nested) is elaborated right-nested, with the same meaning
and order of evaluation, so unfolding the function does not blow up.

### Refinement by lockstep: `#[model]`, `by_lockstep()`, bridges

When exec code and the specification compute differently (a scan against a bit recursion, `u64`
and slices against `Nat` and `Seq`), write a **model**: the code again, over numbers and
sequences, in a ghost module declared `#[cfg(sandblaster)] #[model] mod model;`. Its functions are
spec functions; it is proof text (not on the specification surface), and it may not call exec
code. Each exec function gets `#[refines(crate::model::f)]` and needs no proof: the refinement
walk meets the code's body and the model's body **in lockstep**. The model's tests are split with
their path equations (an arm that contradicts the code's tests is closed at once), `let`-bound
choices of either side (`let child = if left { .. } else { .. };`) are walked through their values,
calls meet calls argument by argument (a callee's own refinement, an induction hypothesis for a
recursive call), constructors field by field, and what is left — `(p + 2w).saturating_sub(2)`
against `sat_sub(p + 2w, 2)`, `x.count_ones()` against `popcount(x)` — goes to the prover. The
proof is an ordinary term the kernel checks; a struct viewed by `#[view(crate::model::S)]` maps
onto the model's record field by field.

```rust
// merkle.rs: the code keeps its natural shape
#[refines(crate::model::path)]
pub(crate) fn path(height: u32, position: u64, width: u64, index: u64, ..) -> Option<Digest> {
    if height == 0 { return Some(leaf_digest(position, operation)); }
    let left = index < width / 2;
    let sibling = list_get(siblings, if left { (height - 1) as usize } else { 0 });
    let child = if left { path(height - 1, ..) } else { path(height - 1, ..) };
    path_node(left, width, position, chunk, sibling, child)
}
// MODEL.rs: the same, over numbers
pub fn path(height: Nat, position: Nat, width: Nat, index: Nat, ..) -> Option<Digest> { .. }
```

What remains is the model against the spec, over numbers, where `by_lockstep();` closes a step:
the goal `f(ā) == R` holds by one step of `f` (its body walked, each outcome met with `R` the same
way). A lockstep has a fixed step budget (deterministic). When it fails, the refinement error says
where code and model differ: the branch conditions, the argument or field, and the equation left
(`lockstep with `crate::model::f`: … code and target differ at: …`).

The standard library's `bridges` module (declared `#[bridges]`) holds the checked equations between
the code's machine operations and the model's (`count_ones` and `popcount`, `first()` and `get(0)`,
`split_at_checked` and `take`/`skip`); each is a rule of `auto`, so the lockstep's leftover
equations use them without being named.

## 4. Reading the QMDB proofs

The QMDB fixture's `PROOF.rs` (in the git history) opened with a table of its parts. Two kinds of
proof live there:

* **Refinements (R1–R12)** tie each piece of code to a spec function:
  `shape_finds` (R7) says `merkle::shape(n, i)` is the spec's `peak_of`,
  `path_root` (R8) that `merkle::path` computes the root of the spec's path
  tree, and so on up to R12, `verify` and `verify_fixed` against
  `spec::proof::verify`. They go by induction over step lemmas: one lemma
  per iteration of the code's recursion, stated with plain variables.
* **Laws** are proven about the spec only, never about the code. Soundness
  and uniqueness follow one shape: the proof decodes to itself
  (`verify_encode`), its tree *fits* the other tree (`proof_fits_db`,
  `proof_fits_proof`) and has the same root, so the tree law
  `equal_roots_agree` gives agreement or a collision, and agreement pins
  every field (`proof_agrees_db`, `proof_agrees_proof`). Completeness gives
  a witness: the proof-local spec `honest(db, i, n, k)` builds the proof an
  honest database would send.

Patterns you will see, and why:

* **Wrapper lemmas and specs with variable parameters.** The prover does
  not decide the `0 <= n` guard of a `Nat` parameter when the argument is a
  compound term. So proofs pass sizes as parameters (`honest(db, i, n, k)`
  with `n == db.log.len()`) and call a nonnegativity lemma first
  (`db_nonneg(db)`, `proof_nonneg(p)`).
* **Opaque helpers.** Array values expand into one term per byte. Helpers
  such as `grafted` and `zero_chunk` are `#[opaque]` in the proofs, with an
  `_is` lemma that reveals the body where it is needed.
* **Division facts.** `by_arithmetic` knows `/` and `%` only by a literal.
  For the chunk size `C` the proofs state the quotient and remainder facts
  once (`divmod_c`, `divmod_8`) and use them by `by_contradiction()`.
* **A disjunction is closed by a helper lemma.** For `a || b` with a large
  `a`, auto tries `a` first and can run out of budget. The laws end with a
  call such as `sound_collide(db, op, q, u)` whose conclusion is the whole
  disjunction.
* **Case analysis in its own lemma.** An `if` or `match` step splits the
  rest of the block, so statements after it are unreachable. A case
  analysis that should produce one fact goes into its own lemma
  (`honest_partial_or`).

## 5. When a proof fails

A failing step reports an **unproven obligation**. It shows the goal as auto
saw it, the facts in scope, and what was tried:

```text
error[obligation]: unproven obligation [assert] in `crate::chain`
   |
16 |             == 2 * (y as Int) + 2;
   |             ^^^^^^^^^^^^^^^^^^^^^
  = note: tried: basic: linarith over 1 hypothesis(es): no certificate
  | goal: Eq(Int, #iadd(crate::double y, 1int), #iadd(#imul(2int, #cast_u8_int(y)), 2int))
  |   fact: Eq(U8, x, y)
```

How to debug:

1. **Look at the goal and the facts.** Put `show();` before the failing point
   to print them as a warning without failing (`todo();` fails and prints
   them). `Eq(Bool, e, true)` is how a `bool` claim `e` is shown; `#le_u8`,
   `#iadd` are the machine and integer operations.
2. **Is a fact missing?** Add it with `assert(..)`, or apply the lemma that
   provides it. The `stuck:` notes list subterms auto could not evaluate.
   These are usually calls of opaque functions or matches on unknown values,
   and a `match`/`by_cases` on them or a `rewrite` with a hypothesis unblocks
   them.
3. **Does the step need a split?** If the goal mentions a `bool`/`Option`
   that auto did not split on, add `by_cases(..)`.
4. **Does the closer claim too little?** `by_computation()` shows both
   evaluated sides: if they differ by arithmetic or by a fact, write
   `by_arithmetic()`. `by_arithmetic()` lists the functions it treated as
   unknown: if the step depends on what they compute, name them in
   `by_unfolding(..)`. `by_contradiction()` shows the goal it did not use:
   if the case is possible, it needs a proof of its own. If the step needs a
   case split on a `bool`/`Option`/enum value, add `by_cases(..)`, or fall
   back to `follows()`. (Splits on arithmetic atoms, such as `a != b` into
   `a < b` or `a > b`, are part of `by_arithmetic()` and need no script.)
5. **Split a big step.** Turn one leap into a `calc!` chain or a few
   `assert`s. The first link that fails is the step to fix.
6. **`apply` errors** list the lemma's requires (with how many facts matched
   each), the facts in scope and, for ambiguity, the candidate
   instantiations. Pass the arguments explicitly, or add the fact that pins
   them down.
7. Tracing: `SANDBLASTER_TRACE_OBL=1` prints every obligation with the prover
   that proved it and the time taken. `SANDBLASTER_TRACE_APPLY=1` prints where
   `apply`'s matching failed. `sandblaster check <crate>` runs the same
   pipeline as the build (the proofs, then every §15 gate) and prints a
   summary.

### Reading the gate errors

A crate whose proofs check still has no verdict until it passes the five
§15 gates (DESIGN.md §15.8). `sandblaster check` prints one line per gate:

```text
gate boundary: passed
gate examples: passed (20 example(s) and vector record(s) checked)
gate sections: passed (0 section(s))
gate law-rules: passed
gate lock: 1 error(s), 0 warning(s) (missing (31 surface item(s) not locked))
status: NOT VERIFIED
```

Fix them in that order; the errors above the summary say what each wants.

| Gate | Typical error | What to do |
| --- | --- | --- |
| boundary | `error[boundary]: pub mod … is not allowed at the DSL root`, `` `pub` item `f` declared at the DSL root `` | make modules private and re-export the API from the root with `pub use m::{..};` |
| examples | `spec function … is not exercised by any example`, `no example of … has the outcome …`, `error[spec-depends-on-impl]` | add known answers (from the standard or an independent implementation, never from the spec) that reach the function and show each outcome; a spec may not call the code |
| sections | `… is not determined by the specification: complete_p(R) is unproven for the section {…}` with the stuck goal | a `#[refines]` that determines the function, or the missing law (§6), or a `#[proof(complete = f)]` item |
| law-rules | `error[law-mentions-internal]`, `error[law-restates-impl]`, `error[law-undocumented]` … | laws speak about spec functions and exported functions only, state something the definitions do not already say, and start with a sentence that states the guarantee (§0) |
| lock | `error[spec-lock]: no SPEC.lock`, `` `law:…` changed (weakened) `` | review the spec sheet (`sandblaster spec`), then `sandblaster spec --accept` (it runs every other gate first and writes the root's lock only if they pass) |

Spec mutation is not a gate (2026-10-05): run `sandblaster mutate <crate>`
when writing or reviewing laws (§6). It is the slow check (about a minute
for the SHA-256 sample's 1526 spec mutants, hours for a library-sized
vocabulary such as the verifier's SHA-256); its per-mutant verdicts are
cached, so a re-run after an edit is quick. Set
`SANDBLASTER_TRACE_MUTATION=1` to see its progress.

### Stage runs and crate verdicts (for toolchain authors)

Only the crate path, `driver::build_crate`, makes a crate verdict. The
toolchain's own steps — `driver::stage::verify`, `verify_checked`,
`eval_json`, `spec_run`, `conform_in_place` — skip the gates. Their
reports say `PROOFS CHECKED (stage run, …)`, never `VERIFIED`. Use them in
toolchain tests of the elaborator; any test of what a *crate* gets must go
through `build_crate` (or the build entry points `build_module` and
`build_lifted`, or the CLI) with a fully specified test crate and the lock
its own gates accepted (`tests/gated_util.rs`).

## 6. When the specification does not pin the code down

The spec-mutation tool, `sandblaster mutate <crate>` (DESIGN.md §15.7; on
demand, never part of a build), mutates the specification — the spec
functions of the review surface, what the laws file's statements use — and
reports each spec mutant that survives every example and law with a
distinguishing input (exit 1). A proof helper (a spec
function only proofs use, such as one of `PROOF.rs`) is not mutated: no
locked statement depends on its definition (DESIGN.md §15.9), and the
report lists it. `sandblaster coverage <crate>`
(DESIGN.md §15.9, §15.10) runs the same gates, then an exploration run that
also mutates the code, re-verifies each mutant, and reports per function
what killed its mutants. Neither ever makes anything pass: the findings are
reasons to add a law or an example.

* **`error[spec-incomplete]`** — a mutant of `f` satisfies every law,
  contract and example, yet returns something else on the printed input.
  The laws do not determine `f`. Typical fixes: the missing direction of a
  soundness law (a `verify` that "only accepts good tags" also needs "accepts
  every good tag", or `λ_. false` passes), or the canonicity law of a
  decoder (a round trip alone lets the decoder accept non-canonical
  encodings). The diff shows the mutant (parenthesized where the edit
  changes how the line parses); the input is shrunk, a compound output
  says where it differs, and the input is a test case for the law you add.
  When the error is at a helper `h` rather than at the function the
  difference was seen at, `f`'s completeness is proven only relative to
  `h`: specify `h` (a refinement, or laws that determine it).
* **`error[spec-mutant-survived]`** — a mutant of a spec function survives
  every example and law. The note prints the example to add,
  `#[example(pos(1) == <expected>)]`; fill in `<expected>` from an
  independent source (the standard, Commonware), never from the spec
  itself. For a helper the standard has no answers for, a second note
  names the nearest spec function with known answers (a refinement target,
  or one with examples) where the mutant differs too. A spec that is wrong
  the same way on both sides of every law can only be caught this way.
* **`warning[law-insensitive]`** — a law holds for every mutant of the spec
  functions it uses: it says nothing about their definitions (LR8).
* **Verdicts.** *Killed by the specification*: an `ensures`, an invariant or
  an example fails, or a law or a determining refinement has a definite
  counterexample (printed). *Killed by proofs*: a law or refinement proof
  fails but no counterexample was found — the law may still hold for the
  mutant, so it does not count for the specification. *Killed by safety*
  (an overflow, an index out of bounds, an ill-formed spec) and *killed by
  budget* are listed separately and are never the specification's kills;
  budget kills are left out of the kill rates. **Possibly equivalent**
  mutants (such as `x * 1` → `x / 1`) are listed, never errors. A constant
  that is also an array length is not mutated (listed as such).
  `error[mutation-incomplete]` says the run was capped (`--mutants-max`,
  `SANDBLASTER_MUTANTS_MAX`, `SANDBLASTER_MUTANTS_PER_ITEM`), stopped for time
  (`--time-budget`) or memory, or has mutants killed only by budget: nothing
  is claimed about those. Those caps shape only `sandblaster coverage`'s
  exploration run; the build's gate always runs every spec mutant of the
  review surface, and
  `coverage` exits 0 only when the crate has a verdict. An exploration run
  prints a progress line per batch.
