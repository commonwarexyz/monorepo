# H2 probe log

The infrastructural fixes to the probe (RULE.md, preamble), in order. Each one applies to every candidate alike.

- 2026-10-02T17:53:03Z: RULE.md written before enumeration; its SHA-256 then was `771ad22c63b364c5e28a4449e1c42cc61b1bcea88e7313eb07a3f30413fa48c8`.
- 2026-10-02T17:56:40Z: the generated root resolved `mir` and `#[path]` against `<module path minus its last segment>/` instead of the directory of the declaring file (`bitmap/roaring.rs` lives in `bitmap/`), so the reader could not find any nested host file. Fixed in `gen_root`. Found on rank 1; every probe row is re-run from scratch after this fix.
- 2026-10-02T17:59:28Z: the generated root re-exported the item with `pub use` even when the item is private, which the front end refuses (`error[privacy]`, rank 11). It now re-exports only an item declared plain `pub` (a `pub struct/enum/union/type` for a method's type). Every probe row is re-run from scratch after this fix.
- 2026-10-02T18:19:39Z: the probe ran on all 281 candidates in seeded order (ranks 1-281, no gap; about 30 minutes). One passed: rank 145, `commonware-utils::rng::mix64` (sample s01). The rest failed:
  - 186 at size (rustc's optimized MIR: no loop and fewer than 10 statements);
  - 85 at the reader;
  - 8 at extraction (5 had no MIR root; 3 hit a panic of the mirx driver inside rustc_public);
  - 1 at exec-only elaboration (`Unproven`).

  The shortfall is 39. RULE.md §4 says H2 is then every candidate that passed, and that this stage does not widen the rule. A widened rule must be a new, versioned rule with new files beside these (G6 freezes these as recorded), decided by the coordinator. The accepted set is exhausted, so this rule has no replacement candidate for protocol item 3.
