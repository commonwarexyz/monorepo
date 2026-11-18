# Intents: the glue DKG fuzz harness (decisions of 2026-11-18)

This file records the decisions taken on the DKG fuzz harness after PRs #5708 and #5728. The harness
and its `SPEC.md` existed before this file, so it starts here; earlier decisions are recorded in
`SPEC.md` itself (for example the withdrawal of I7, "Choices made", item 4).

## Decisions

1. **The spec after PRs #5708 and #5728 is accepted**: the text fixes from #5708, the Future work
   section, the house shape, and the requirement grammar.
2. **R30, unmeasured invariants are reported**: every run reports, per invariant, how many records
   its check judged; zero is reported as unmeasured with its reason, never as passing, and never
   fails the run.
3. **Emission of the R30 reports** ("Compact aggregate always"): every fuzz process always writes a
   short per-invariant aggregate, at intervals and at its end; each run's full report is written
   only when `GLUE_FUZZ_LOG` is set.
4. **The bounded-exposure invariant is not prototyped now**: it stays a next step in Future work,
   section 12.2.
5. **The accepted improvements are built into the harness**, with acceptance tests written from the
   spec.
6. **I6 on `dkg_bootstrap`** ("A: exclude I6 on bootstrap"): no input of `dkg_bootstrap` is known to
   fail a ceremony (4,330 runs, none failed; likely unreachable in that target's model, not proven),
   so verification step 7 excludes I6 on `dkg_bootstrap`; that target's regression suite shows I6
   reported as unmeasured with its reason, and I6 keeps its negative control there.
7. **The end-of-process write keeps its one `atexit` call** ("Keep it, skip Miri"): Miri cannot call
   `atexit`, so that one unsafe call has no Miri test; tests with real processes show its behaviour.

## Left to the spec

- The count units, the fixed reasons and the per-target set of section 8.1, and the report surface
  of section 5.4, are the spec's precision of R30 (Choices made, items 25 to 28).
