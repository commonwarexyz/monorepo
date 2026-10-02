# sandblaster optimizer v3: implementation plan

This plan implements `docs/optimizer-design.md`, cited here as "design §n". The
proposed normative text for DESIGN.md §8.2 is in design Appendix A. The plan
has milestones O1–O20. Each milestone lists:

- scope;
- the files it owns;
- its dependencies;
- acceptance tests;
- budgets;
- risks;
- a rough effort estimate for one engineer.

The effort estimates are indicative; the order and the gates are what matter.

---

## 0. Conventions and constraints

### 0.1 Roles (file owners)

| Role | Owns |
| --- | --- |
| **Kernel owner** | `sandblaster/kernel/**` (TCB), `AUDIT.md`, `INTERFACE_CHANGES.md`, prelude core text |
| **Automation owner** | `sandblaster/front/src/auto/**`, `sandblaster/front/lemmas/**` |
| **Optimizer owners** | `sandblaster/front/src/opt/**`, split by area: driver (`opt/drive`, `opt/proof`, `opt/summary.rs`, `opt/residual.rs`), loops (`opt/loopsum`), sequences (`opt/seqsum`), algebra (`opt/alg`), cost and selection (`opt/egraph`, `opt/cost`), parallelism (`opt/par`) |
| **Printer owner** | `sandblaster/front/src/{canon,roundtrip}.rs` |
| **Targets owner** | `sandblaster/targets/**`, `sandblaster/front/src/{intrinsics,target}.rs`, `tools/host-kit/**` |
| **Front-end owner** | the S0-owned files, after the merge (§0.2) |
| **Port owners** | QMDB bench (`qmdb/bench/**`); Reed–Solomon, curve25519 and BLS/VROOM port crates |

### 0.2 The S0 constraint

The DESIGN §15 S0 work is changing these files in an isolated copy, which will
be merged back:

- `sandblaster/front/src/{hir,resolve,loader,validate,prover,visit}.rs`
- `typeck/**`
- `elab/{mod,obl,order,loops,ensures}.rs`

Rules until the merge:

- **O1–O11 and O13 do not modify these files.** They use only the existing
  public APIs: `ProverChain`, the `hir::*` types, `hir::Recursion`,
  `elab::generated::resume`, and the `Prover::prove` entry point (the latter
  only with existing obligation kinds). No new `ObligationKind` is added. The
  optimizer builds lemma terms itself and calls `Env::add_def` and `auto`
  directly.
- Any change these milestones would need in an S0-owned file goes into a queue
  of post-merge patches, owned by the front-end owner and landed in O12.
  Examples: `#[specialize(loop_free)]` parsing, a HIR field for `#[rewrite]`
  laws.
- O12 and O16 (the language extensions) start only after the S0 merge.
- O14's algorithm selection through `#[refines]` also needs the §15 S1 stage.
  O19's representation choice needs §15 S1–S2.

### 0.3 Measurement protocol (all performance acceptance)

1. **Differential check first.** Every candidate and every emitted build is
   checked against the generated or oracle outputs before anything is timed.
2. **Same-binary A/B.** Subjects are interleaved in one binary, with ≥ 3 rounds
   in rotating order. The load average is recorded, and the reported value is
   the median of per-round medians. Deltas are compared within a run, never
   across runs.
3. **Emitted code only.** The numbers in design §1 and §12 are for hand-written
   candidates. They are targets, not results. A gate passes only when the
   **emitted** code meets it.
4. **Where numbers come from.** aarch64 numbers are taken on this M5 Pro. x86
   numbers are compile-only (asm checks) until the host kit (O9/O20) runs;
   before then an x86 target is a hypothesis.
5. **Resource limits.**
   - Every cargo build, test or bench goes through the machine-wide admission
     wrapper, with `-j` capped.
   - `sandblaster-memguard` stays linked, with `SANDBLASTER_MEM_LIMIT_GB` set.
   - `SANDBLASTER_OPT_JOBS` is at most 2 (default 1).
   - No workspace-wide test suite runs as the first check; use narrow test
     invocations.

### 0.4 Global gates

Each gate is introduced by the milestone named in the last column. From then
on it is enforced on every merge.

| Gate | Requirement | From |
| --- | --- | --- |
| G1 determinism | QMDB N=1 and N=32 builds three times: `sandblaster.rs` and the report are byte-identical | O1 |
| G2 strict | the test suite runs with `SANDBLASTER_STRICT_OPT=1`; the QMDB and corpus builds have no optimizer warnings | O1 |
| G3 round trip | every printed item is α-equivalent to its core definition | existing |
| G4 must-reject | every must-reject test introduced so far passes (design §20) | O1 |
| G5 kernel budget | kernel ≤ 10,000 non-blank non-comment lines (the `AUDIT.md` method; 9,808 today) | O3 |
| G6 zero source change | `git diff --exit-code sandblaster/fixtures/qmdb/sandblaster` is empty in every optimizer acceptance run; the corpus DSL is frozen after O1 except for additions | O1 |
| G7 x86 compile | every x86 variant set builds for `x86_64-unknown-linux-gnu` and `x86_64-apple-darwin`; `tools/asmcheck` assertions pass | O1 |
| G8 ARM validation | new NEON/SHA models validated on this M5 (≥ 10^7 random inputs plus corners); ARM benchmarks recorded | O10 |
| G9 budgets | optimizer time and peak-RSS delta on the QMDB build stay within the milestone's budget; cold ≤ 2× the O1 baseline (hard); warm ≤ 1.15× | O4 |
| G10 parity | functions that are not intentionally improved keep byte-identical output (today's 51 specialized functions, at O1) | O1 |

---

## 1. Dependency graph

```
                 ┌──────────── O9 host kit v1 ───────────────────────────┐
                 │                                                       ▼
O1 harness ─┬─ O2 E0 printing                                         O20 AVX-512 rounds
            ├─ O3 K1 + bits + obligation prototype ──(D1)──┐             ▲
            └─ O4 Σ1 driver core ── O5 summaries ──┬── O6 Σ2 loops ──┐   │
                                                   └── O7 Σ3 seqs ◄──┘   │   ← QMDB regression gate
                                                         │               │
                          O8 selection/cost/variant sets ◄┘ (D2)─────────┤
                                     │                                   │
                          O10 models + lane functor ─── O11 parallel I ──┤
                                     │                        │          │
  [S0 merge] ── O12 language ext. I ─┼──── O13 parallel II (threads)     │
                     │               │                                   │
                     └──── O14 Σ4 algebra (D3) [§15 S1 for refines] ─────┤
                                     │                                   │
                     O15 Reed–Solomon R0…R5 (R0 from O1) ────────────────┤
  [S0 + §15.13] ─ O16 language ext. II (Secret, Vec, traits)             │
                                     │                                   │
                          O18 representation regions (D5)                │
                                     │                                   │
                     O17 curve25519 C1…C6 ── O19 BLS12-381/VROOM A…E ─────┘
```

**Critical path to the QMDB regression gate:** O1 → O4 → O5 → O6 → O7, with O3
running in parallel. The estimate is 17–26 weeks for the driver, loop and
sequence work, plus about 3 weeks of O3 alongside.

**Tracks that can start at once:** O2, O3, O9 (portable parts), and the O15 R0
oracle.

---

## 2. Milestones

### O1. Harness, corpus, baselines, gates (1–2 weeks)

Owners: optimizer (driver) + QMDB bench.

**Scope.** Do this first. The scratch artifacts live in `/private/tmp/...` and
are ephemeral.

1. **Corpus import.**
   - Import `$O/corpus` into `sandblaster/front/tests/opt_corpus/`:
     the DSL programs P1–P14 plus a `corpus.toml` manifest listing program,
     expected route, expected rung, target ratio to ideal, and control flag.
   - Import the native harness into `bench/opt-corpus/`:
     - checks first (400k integers, 1M+ varints, folds, tables, scans);
     - generated vs ideal;
     - aarch64 and x86_64 builds.
2. **New corpus programs** (subset-expressible today):
   - P15: threaded-cursor tree DFS;
   - P16: a batch of K equal-shape 20-deep hash paths;
   - P17: GF(2^16) multiply by a constant over 64-byte lo/hi blocks;
   - P18: u64 carry chain;
   - P20: sparse / constant-operand multiply.

   P19 (16-term dot product mod p) is added when u128 lands in O12. Each program
   gets an `ideal/` counterpart and a must-reject variant.
3. **QMDB A/B harness.** Import `$O/micro` into `qmdb/bench` as a same-binary A/B
   mode with three subjects:
   - pre-H1, frozen under `qmdb/bench/baselines/`;
   - H2, frozen from the H2 file with SHA-256 `886dd65d…`;
   - the current emitted build.

   Import its checks too: shape 2.18M cases, varints 3.26M, parse 6.4k,
   finish 40k, verify 1.9k.
4. **Stuck-reason test.** Turn `tests/opt_explore.rs` into a non-ignored test
   that asserts today's stuck reasons. Each later milestone then updates
   expected outcomes deliberately.
5. **Report schema.** Add `link`, `rung`, `candidates[{rung, cost per set,
   chosen, reason}]`, `budgets_used` and `facts_exported`.
6. **Test hooks.** Add `OptTestHooks` (`cfg(test)` only), which injects
   candidates, proofs, rules, executors and cache entries. Add
   `tests/opt_reject.rs` with R25, R26 and R27 against today's paths.
7. **Tools.** Add `tools/asmcheck/`, built from `$O/sfn.py`, `$O/dis.sh` and
   `$O/x86asm.sh`. It covers aarch64 plus the x86 targets x86-64, v3, v4,
   znver4 and sapphirerapids.
8. **Gates.** Wire up G1, G2, G4, G6, G7 and G10.

**Files:**
- `sandblaster/front/tests/{opt_corpus/**, opt_explore.rs, opt_reject.rs}`
- `bench/opt-corpus/**`
- `qmdb/bench/**`
- `tools/asmcheck/**`
- `opt/mod.rs` (report structs only)
- `driver.rs` (report emission)

**Dependencies:** none.

**Acceptance:**
- Baselines are reproduced within ±3% of the recorded values:
  - H2 N=1 `verify` 309.8 ns, pre-H1 284.0 ns;
  - `shape` 24.8 / 46.0 / 61.5 ns;
  - `reconstruct_finish` 89.2 ns;
  - `parse` 6.46 ns;
  - the corpus generated/ideal ratios of design §2.3.
- G1 and G10 hold: 51/111 specialized, byte-identical.
- The stuck-reason test matches `explore.txt`.

**Budgets:** no optimizer behaviour change. The harness runs in ≤ 10 minutes
under the admission wrapper.

**Risks:** machine noise. Mitigation: interleaving, recorded load, medians.

### O2. Checked-arithmetic printing (E0) (1–2 weeks)

Owner: printer.

**Scope:**
- Add the `crate::__rt::chk::{add,sub,mul,shl,shr}_{u8,u16,u32,u64,usize}`
  templates. Each is `#[inline(always)]`: `wrapping_*` under
  `not(debug_assertions)`, the checked operator under `debug_assertions`.
- The printer emits them for every checked primitive whose proof slot exists.
- In generated mode, `roundtrip.rs` lowers exactly those paths, with their
  operand order and width, to the checked primitive with an `Erased` slot.
- `#[inline]` on residual helpers. It is semantics-free and ignored by the
  round trip; it is needed from O4 on.
- Golden updates.

**Files:** `canon.rs`, `roundtrip.rs`,
`tests/{canon_golden.rs, canon_golden_opt.rs, roundtrip_mutations.rs, redteam_fidelity.rs}`.

**Dependencies:** O1.

**Acceptance:**
- QMDB round trip is clean. QMDB timing is unchanged within noise under the
  oracle's `bench-release` profile (no overflow checks).
- Under an `overflow-checks = true` profile (Commonware's release profile):
  - P18 is ≥ 1.5× faster (curve25519's F::mul measured 1.9× for the same
    change, *(third-party code)*: Commonware's F::mul with overflow checks
    on vs off; the emitted P18 gain is 1.43–1.57×);
  - QMDB N=32 `verify` is no slower than under `bench-release` + 2%.
- A debug build still traps an injected overflow (the DESIGN §10.3 oracle is
  intact).
- **Must-reject R19:** swapped operands, wrong width or wrong operator in a
  printed helper fail the round trip.

**Budgets:** printer time ≤ +2%.

**Risks:** printed code becomes less readable. Mitigation: the helper names read
as the operation, and `SEMANTICS.md` gains one entry.

### O3. K1 bit-count axioms, bits library, integer cuts, and the Σ2 obligation prototype (2–3 weeks)

Owners: kernel (axioms) and automation.

**Scope:**
- **Kernel.**
  - Add `count_ones_def`, `leading_zeros_def` and `trailing_zeros_def` to
    `axioms.rs`, per width, stated in `Int` (design §11.4).
  - Retire `count_ones_le`, `leading_zeros_le/lt` and `trailing_zeros_le/lt`.
    They become checked lemmas.
  - Tests: exhaustive over U8/U16; at U32/U64/Usize, 10^7 random values plus
    single-bit, prefix and suffix patterns; mutation tests.
  - Update `AUDIT.md` and `INTERFACE_CHANGES.md` (additive schemas).
- **Library.** A generator for `sandblaster/front/lemmas/bits.core`
  (design §11.4), and auto step 7 switched to the retired bounds as lemmas.
- **Automation.**
  - The **integer-cut** tactic: a Bool split on `lt(atom, c)`
    (`auto/{cases,arith}.rs`).
  - **Fact normalization:** `ne … true` and `eq … false` become on-demand splits
    (`auto/facts.rs`).
- **Prototype.** `tests/opt_obligations_shape.rs` generates the statements of
  `lemma_0 … lemma_63` for `shape_go`, and the corresponding lemmas for corpus
  P4 `find_block`, from design §12.1. It proves them with auto plus the library
  through a hand-rolled builder and records step counts per obligation class.

**Files:**
- `sandblaster/kernel/src/axioms.rs`, `sandblaster/kernel/tests/axioms.rs`,
  `sandblaster/kernel/{AUDIT,INTERFACE_CHANGES}.md`
- `sandblaster/front/lemmas/bits.core`
- `auto/{cases,arith,facts,lemmas}.rs`
- `sandblaster/front/tests/opt_obligations_shape.rs`

**Dependencies:** none (runs in parallel with O1, O2 and O4).

**Acceptance:**
- G5: kernel ≤ 9,850 lines, a net increase of ≤ 42.
- All schema tests pass, and R20's mutations fail as required.
- **D1:**
  - Every `lemma_k` for `shape_go` and P4 closes, each ≤ 5·10^6 steps and
    ≤ 5·10^8 in total per loop.
  - If some class fails, O6 ships rung 2 (early exit) and rung 3 for `shape`
    first. A reflective bit-blasting checker (prelude, 0 TCB) is opened as a
    follow-up. Neither path adds kernel code.

**Budgets:** prototype RSS ≤ 256 MiB.

**Risks:** integer-cut completeness on quotient atoms. Mitigation: the prototype
shows which classes close before Σ2 is built.

### O4. Σ1 driver core and lemma admission (4–6 weeks)

Owners: optimizer (driver) + printer.

**Scope** (design §6, §11):
- **Driver.** `opt/drive/{mod,config,step,tree,process,facts}.rs`, with:
  - struct/tuple entry η (`opt/symex.rs`);
  - static-measure and static-structure unrolling;
  - the steps Reuse, Prune, Refine, Merge (non-secret), Split and Word (with the
    `BvRefl` cap);
  - fact normalization.
- **Residual language** (`opt/residual.rs`):
  - new nodes: `If`, `Match`, `SelfCall`, `HelperCall`, `SubSlice`, symbolic
    `ElemRead`, `Enum`, `WrapPrim`;
  - scoped emission;
  - proof-aware placement of partial operations;
  - `Recursion` kept.
- **Proof builder.** `opt/proof/{mod,build,steps}.rs`, which generalizes
  `mirror.rs`; mirror's clone proofs move behind the same API.
- **Admission.**
  - `summarize_one` replaces `specialize_one`, with tier 0 kept verbatim.
  - `Link::Lemma` commit.
  - The print view and the round trip handle lemma-admitted residuals.
- **Clones without `clone_equiv`** become an error once QMDB has zero such
  clones (checked in this milestone).

**Files:** `opt/drive/**`, `opt/proof/**`, `opt/{residual,symex,mod,mirror,multiversion}.rs`,
`canon.rs`, `roundtrip.rs`, tests.

**Dependencies:** O1. O3's integer-cut and fact normalization are used once
they land; plain linarith pruning works before.

**Acceptance:**
- **QMDB:**
  - `uint64`, `uint`, `byte`, `digest`, `sha256::equal`, `active` and
    `verifier::reconstruct` report `Specialized`.
  - `sha256::equal` is branch-free: `eq8_word` lemma, asm check.
  - Nothing regresses: N=1 ≤ H2 + 1%, and no N=32 workload is more than 1%
    slower than H2.
- **Corpus:** P5 and P12 do not regress.
- **Must-reject:** R1, R3, R4, R11, R12, R13, R14, R15, R24.
- G1–G4 and G6 hold.

**Budgets (G9):**
- QMDB optimizer time ≤ 1.2× the O1 baseline;
- peak-RSS delta ≤ 256 MiB;
- driver steps ≤ 5·10^7 per function.

**Risks:**
- Alignment between the elaborated residual core and the process graph, and
  dependent motives. Mitigation: each step kind is unit-tested on small
  residuals, and the kernel judges every step, so a bug costs only a fallback.
- `abstract_occurrences` performance.

### O5. Compositional summaries (4–6 weeks)

Owner: optimizer (driver).

**Scope:**
- `opt/summary.rs`.
- Callee summaries at call sites: keep, inline through the link, or
  instantiate the tree.
- Case-of-case.
- Fact-lemma export and import.
- Polyvariant specialization (`opt/drive/callsite.rs`).
- The whistle, generalization and Houdini carried invariants
  (`opt/drive/{whistle,generalize,houdini}.rs`).
- Folding under the same-global rule.
- Bound invariants (P10).
- The hints-only cache (`opt/cache.rs`, under `target/sandblaster/opt-cache/`,
  not checked in).

**Files:** `opt/summary.rs`, `opt/drive/**`, `opt/cache.rs`, `opt/mod.rs`, tests.

**Dependencies:** O4.

**Acceptance:**
- **QMDB:**
  - The 10th varint byte is never inspected in `location` (report plus
    emitted-code check).
  - `location` and `parse` are `Specialized`.
  - **`parse` ≤ 1.7 ns** (H2 6.46, pre-H1 3.94, measured candidate 1.46).
  - N=1 `verify` ≤ H2.
- **Corpus:**
  - P5b ≥ 2.5× (4 × 1-byte fields);
  - P10 ≥ 3.0× (16 words) and ≥ 4.0× (4096 words);
  - P20 ≥ 1.4× (constant-operand specialization).
- **Must-reject:** R2, R10, R25.
- **Cache:** a warm build is ≤ 1.15× the cold baseline, and a forged entry is
  rejected.

**Budgets (G9):** optimizer time ≤ 1.3×; RSS delta ≤ 384 MiB.

**Risks:**
- The whistle fires too early and loses facts. Mitigation: Houdini recovers
  them; the report names generalization points.
- Specialization blow-up. Mitigation: caps of 8 per callee and 64 per crate.

### O6. Σ2 loop summaries (5–7 weeks)

Owner: optimizer (loops).

**Scope** (design §7):
- `opt/loopsum/{onestep,classify,traces,synth,guards,invariant,lemmas,rungs}.rs`:
  - one-iteration symbolic execution;
  - recurrence classes;
  - traces (profile and seeded corners);
  - enumerative synthesis with guard trees;
  - K+1 per-literal lemmas, and the recursive enumeration lemma for symbolic
    fuel;
  - fallback rungs: early exit, idle skip, set-bit iteration.
- Export of closed-form facts: `height ≤ 62`, `before + after ≤ 61`,
  `index < width`.
- `sandblaster profile` subcommand (`sandblaster/cli`) and a `PROFILE.json`
  reader. The QMDB profile comes from `qmdb/fixtures` and `qmdb/fixtures-n32`.
- `#[specialize(loop_free)]` parsing is S0-owned and is queued for O12. Until
  then the acceptance test asserts `rung = ClosedForm` in the report.

**Files:** `opt/loopsum/**`, `opt/cost/profile.rs` (reader), `sandblaster/cli/src/main.rs`
(profile subcommand), `qmdb/PROFILE.json` (generated data, not source), tests.

**Dependencies:** O3 (D1), O5.

**Acceptance:**
- **`shape` ≤ 2.6 ns** at N=1 fixtures, N=32 fixtures and uniform leaves < 2^62
  (from 24.8 / 46.0 / 61.5). Emitted code, same-binary A/B, `rung = ClosedForm`.
- With synthesis disabled through a hook, the early-exit rung is emitted and
  proven, at ≤ 2.6 ns for N=1.
- The `reconstruct_checked` specialization has no `nb + na ≥ 62` check and no
  `height > MAX_HEIGHT` check (driven by the exported facts).
- **N=1 `verify` ≤ 292 ns** (the S candidate alone measured 290.5).
- **Corpus:** P1, P2, P4, P6, P11 and P13 are within 1.25× of ideal on aarch64.
- **Must-reject:** R6, R7, R8.
- **Law.** The summary lemma of `shape_go` is exported under a stable name. The
  deferred law `shape_closed_form` can then be discharged by it, once stated in
  a separate `LAWS.rs` change. That change is not part of this milestone's G6
  run.

**Budgets:**
- per loop ≤ 5·10^8 steps;
- optimizer time ≤ 1.5×;
- RSS delta ≤ 512 MiB.

**Risks:**
- D1 outcome.
- Synthesis misses on corpus programs. Mitigation: each program has an
  expected-rung entry, and a miss degrades to a certified rung.

**Status (built, merged into main on 2026-09-25, validated on 2026-09-26).**
O6 is done except for one acceptance item: the `nb + na ≥ 62` check is still
emitted. Details and the history are in `docs/opt-o6-o7-reports.md`. Numbers
are from the final validation (same-binary A/B, 7 rounds, load 3.95–4.31) unless
noted.

| Item | Outcome |
| --- | --- |
| `shape` ≤ 2.6 ns, `rung = ClosedForm` | **Met:** 2.41 / 2.41 / 2.40 ns (N=1 fixtures / N=32 fixtures / uniform). `opt_qmdb` asserts the rung, the lemma link and the summary lemma in both real builds |
| Synthesis off: early exit emitted and proven, ≤ 2.6 ns at N=1 | **Met** in the O6 tree: 2.54 ns (verifier 2.40 ns). This is test-only output and was not re-measured after the merge |
| No `height > MAX_HEIGHT` check | **Met on the verify path.** `merkle::reconstruct__portable` and `__sha2` are driven through `reconstruct_shape` and `reconstruct_checked`, and the fact `height ≤ 62` prunes the check (`opt_qmdb` asserts it). The clones behind the public `reconstruct_checked` and `reconstruct_shape` entry points still have it; the verify path no longer calls them |
| No `nb + na ≥ 62` check | **Not met.** The check tests lengths of `list_take` slices whose counts come from saturating subtraction, `min` and bool-to-int casts; linear arithmetic over `shape`'s facts does not decide it, so neither the unfolding trial nor guard specialization removes it (design §6.4) |
| N=1 `verify` ≤ 292 ns | **Met:** 0.869 of H2 in the same binary, 269.2 ns scaled to H2's recorded 309.8 (273.1 ns raw) |
| Corpus P1, P2, P4, P6, P11, P13 within 1.25× of ideal | **Met** before the merge (development set: measured on the program the feature was built for): P13 went from 12.9× to 1.00× in the O6 fix; P1–P11 were 0.97–1.03× in the verifier's run. Not re-run after the merge |
| Must-reject R6, R7, R8 | **Met**, plus R28 (misstated enumeration arm) and R29 (wrong set-bit step). `opt_reject` 33/33 |
| Summary lemma under a stable name | **Met:** `crate::merkle::shape_go::summary` |
| Budgets | **Met:** `shape`'s loop summary took 11,063,271 steps (limit 5·10^8); G9 optimizer time 1.418× (N=32) and 1.434× (N=1) (limit 1.5×); peak RSS +193 / +184 MiB (limit 512 MiB) |

Scope as built: one-iteration symbolic execution, recurrence classes
(including `MaskedCount` for P13), traces from `PROFILE.json` and seeded
corners, templates then enumerative synthesis with depth-one guard trees,
K+1 per-literal lemmas, the symbolic-fuel enumeration lemma, the early-exit
rung with an idle skip at entry, the set-bit rung, five exported facts for
`shape`, guard specialization, and `sandblaster profile`. Not built or open:
idle skips after the entry; guard-tree witnesses (`ite`) cannot be pinned,
so they always fall to the early exit; choosing between rungs by cost
(O8); `#[specialize(loop_free)]` (O12).

### O7. Σ3 sequence summaries: the QMDB regression gate (4–5 weeks)

Owner: optimizer (sequences).

**Scope** (design §8):
- `opt/seqsum/{segments,drive,templates,demand}.rs`:
  - segment normal form;
  - general consumer driving over segments;
  - SP1/SP2 fast templates;
  - demand, forwarding and known-zero propagation.
- `lemmas/seq.core`:
  - clamped-`Int` take/drop/append/update/replicate/`copy_range` lemmas;
  - `slice::ext`;
  - `foldl_append` and `foldr_append`;
  - `index_scanl`.
- Dead-helper elimination in the print view.

**Files:** `opt/seqsum/**`, `sandblaster/front/lemmas/seq.core`, `opt/mod.rs` (print view), tests.

**Dependencies:** O5; O6 for the combined gate.

**Acceptance:**
- **`reconstruct_finish` ≤ 74 ns** (from 89.2).
  - aarch64 asm: no `bzero`/`memset`/`memcpy` call and no ~2000-byte frame.
  - x86 compile-only asm: no 62 × ymm (v4, SPR) or 31 × zmm (znver4) zeroing
    stores, and no `memcpy@GOTPCREL`.
- **QMDB regression gate:**
  - **N=1 `verify` ≤ 275 ns**, same-binary A/B against H2 (309.8) and pre-H1
    (284.0);
  - `shape`, `uint64`, `location`, `parse` and `reconstruct_finish` all report
    `Specialized { link: Lemma }`.
- **N=32** (the oracle `bench-release` table):
  - no production or deep workload is more than 1% slower than H2;
  - generated/Commonware stays ≤ 0.77 on every workload (a development-set
    regression check, **not** an optimizer acceptance criterion: it compares
    the QMDB port, a different fixed-shape program with hand-written hash
    variants, with Commonware's generic verifier);
  - the geometric mean vs hand-written stays ≤ 0.95 (production) and ≤ 0.96
    (deep);
  - deep workloads are at least 3% faster than H2 on geometric mean.
- G6 holds (zero QMDB source change). All QMDB laws and obligations still pass.
- **Corpus:** P7 ≥ 8× (segments 0–3) and ≥ 2× (0–60 words); P8 ≥ 1.1×.
- **Must-reject:** R5, R9.

**Budgets:** cold optimizer time ≤ 1.5× the O1 baseline (G9 hard gate 2×); RSS
delta ≤ 512 MiB.

**Risks:** printing details erase gains, e.g. a helper not inlined. Mitigation:
asm checks and `#[inline]` hints; the emitted code is measured.

**Status (built, merged into main on 2026-09-25, validated on 2026-09-26).**
The QMDB regression gate passes: N=1 `verify` and `reconstruct_finish` are
under their limits (`reconstruct_finish` by a small margin), and every N=32
item holds except "deep workloads ≥ 3% faster". Corpus P8 and the SP1/SP2
templates are not done. Details and the history are in
`docs/opt-o6-o7-reports.md`. N=1 numbers are from the final validation
(same-binary A/B, 7 rounds, load 3.95–4.31); a reading counts as its ratio to
H2 in the same binary times H2's recorded value.

| Item | Outcome |
| --- | --- |
| `reconstruct_finish` ≤ 74 ns (ratio ≤ 0.8294 of H2's 89.22) | **Met, with a small margin:** 0.8235 of H2 in the same binary, 73.5 ns scaled (70.1 ns raw); earlier readings 72.7–73.6 ns. Any change to `reconstruct_finish` or `root__sha2__seg0` must be measured again |
| aarch64 asm: no `bzero`/`memset`/`memcpy`, no ~2 KB frame | **Met:** `reconstruct_finish__sha2` has a 480-byte frame and calls only `fold__sha2` and `root_seal__sha2`; asmcheck in G7 |
| x86 asm: no 62 × ymm / 31 × zmm zeroing, no `memcpy@GOTPCREL` | **Met:** asmcheck in G7 (145/145) |
| N=1 `verify` ≤ 275 ns (ratio ≤ 0.8877 of H2's 309.8) | **Met:** 0.869 of H2 in the same binary, 269.2 ns scaled (273.1 ns raw); 0.944 of pre-H1 in the same run |
| `shape`, `uint64`, `location`, `parse`, `reconstruct_finish` report `Specialized { link: Lemma }` | **Met** in both instances; 80/111 functions specialized |
| N=32: no workload more than 1% slower than H2 | **Met** in a same-binary aligned A/B of the current emission (vMeasure, 9 rounds): worst workload 0.9913 of H2, A/A noise within 0.50% |
| N=32: generated/Commonware ≤ 0.77 on every workload (development-set regression check, not an optimizer criterion: the port vs a different program) | **Met:** largest ratio 0.748 (oracle table on the final emission, 3 rounds); geometric means 0.671 (production) and 0.715 (deep) |
| N=32: geometric mean vs hand-written ≤ 0.95 (production), ≤ 0.96 (deep) | **Met:** 0.900 (production) and 0.939 (deep), same table |
| N=32: deep workloads ≥ 3% faster than H2 (geometric mean) | **Not met:** 0.981 of H2 (production 0.950), in the same aligned A/B |
| G6; QMDB laws and obligations | **Met:** G6 passes; the strict verified builds prove every law and obligation (887 obligations proven, 141 definitions kernel-checked, in each instance) |
| Corpus P7 ≥ 8× (0–3 words), ≥ 2× (0–60 words) | **Met** before the merge (development set: measured on the program the feature was built for): 8.80× and 2.18× (verifier 9.41× and 2.10×). Not re-run after the merge |
| Corpus P8 ≥ 1.1× | **Not met:** the code is the same as O1's. It needs a summary of the loop that builds the table plus a synthesized fold helper; `index_scanl` is ready in `seq.core` |
| Must-reject R5, R9 | **Met**; `opt_reject` 33/33 |
| Budgets: cold time ≤ 1.5×, RSS ≤ 512 MiB | **Met:** G9 1.418× (N=32) and 1.434× (N=1) of the O2 baseline, peak RSS +193 / +184 MiB |

Scope as built: the segment normal form (`Seg`/`Elem`/`Rep`), consumer
driving through per-shape helpers `f__seg<k>` (instead of
`StaticArg::Segs`), demand splits, forwarding, dropping unread pieces,
`lemmas/seq.core` (53 lemmas plus `seq::{foldl, foldr, scanl}`, including
`slice::ext`, `foldl_append`, `foldr_append` and `index_scanl`), and
dead-helper elimination in the print view. Not built: the SP1/SP2 templates
(a helper's loop already runs exactly the consumer's tests, so they would
only save helper code), known-zero propagation, and the scan demand P8
needs.

### O8. Selection, cost model, variant sets (3–4 weeks)

Owners: optimizer (cost) + targets.

**Scope** (design §10, §13.1–13.2):
- **Aegraph.** `opt/egraph/{aeg,rules,extract,explain}.rs`, over straight-line
  regions only:
  - `bvnorm::classify` batching;
  - `cong_irr` lemmas (`lemmas/cong.core`);
  - memoized explanations.
- **Cost model.** `opt/cost/{model,tables,tuning}.rs`:
  - M5 tables from measurements;
  - x86 tables for v1, v3-scalar and v4 (SPR, Zen 4, Zen 5), seeded and marked
    as hypotheses;
  - critical-path weighting;
  - multi-result top-3 with ≤ 2 retries;
  - the 3% gate.
- **Feature-only variant sets** in `multiversion.rs`: x86 `v3-scalar`;
  aarch64 `cssc` if D2 allows.
  - The dispatch glue gains the **known-answer self-test**.
  - `pext` is tied to v4.
- **Tuning evidence.** Format `evidence/tuning-<arch>-<uarch>.json`, with the
  aarch64 M5 file produced by local calibration from the `$O/par` tables.
- **Rulegen v0.** `sandblaster/rulegen` (offline tool) produces the first
  library, `lemmas/rules/*.core`, which is re-checked every build.

**Files:** `opt/egraph/**`, `opt/cost/**`, `opt/multiversion.rs`, `opt/mod.rs` (dispatch glue),
`sandblaster/targets/evidence/tuning-*.json`, `sandblaster/rulegen/**`,
`sandblaster/front/lemmas/{cong.core, rules/**}`.

**Dependencies:** O6, O7.

**Acceptance:**
- **Corpus:** P3 → `count_ones` (≥ 8×). The controls P9 and P14 are within 2%.
- **x86 asm checks:**
  - `shape` in the v3-scalar and v4 clones contains `lzcnt`, `popcnt` and
    `bzhi` or `shlx`;
  - the P1, P2, P4, P6, P11 and P13 clones contain `lzcnt`/`tzcnt`/`popcnt`.
- **Cost model: regression checks on three development-set decisions**
  (accuracy is to be measured on the held-out decision set):
  - NEON SHA lanes are rejected;
  - SWAR varint is rejected;
  - a regression check on the development profile: with the QMDB profile,
    the closed form beats set-bit iteration at N=32.
- **Must-reject:** R21.
- **Determinism:** `PROFILE.json` and the tuning hash are the only inputs that
  change choices (G1 variant test).
- The QMDB gate of O7 is maintained.
- **D2:** if `cssc` is accepted by rustc 1.98, the aarch64 clone gives
  `shape` ≤ 2.3 ns.

**Budgets:** aegraph ≤ 10^4 e-nodes and 8 rounds; optimizer time ≤ 1.5×.

**Risks:**
- Unvalidated x86 costs. Mitigation: O9/O20 tuning evidence.
- Rulegen search cost. Mitigation: offline only.

**Status (built in `o8-tree`, validated on 2026-09-26; not yet merged).**
Every acceptance item is met except D2, which does not apply (rustc 1.98.1
rejects `cssc`). The fixer pass made the known-answer self-test execute its
instructions in release builds (R21 now simulates the fault in the machine
code) and made a failing rule library a reported, sticky failure; running the
`v4` clones on a host remains open (table). Details, commands and the history are in
`docs/opt-o8-reports.md`. Load average 3.1–5.0 during the measurements, with
other agents running.

| Item | Outcome |
| --- | --- |
| Corpus P3 → `count_ones` ≥ 8× | **Met** (development set: measured on the program the feature was built for): 8.710× (default layout) and 8.698× (aligned), judged 8.698×, current/ideal 1.00; the aegraph rewrites the 64-step sum by `rules::count_ones_sum_u64_u32` (rung `Rewritten`, kernel-checked lemma link) |
| Controls P9, P14 within 2% | **Met through identical machine code:** both compile to the same machine code as the O1 emission (`samecode.py`); the measured per-layout ratios on that code are placement noise (P9 at 16 words: 1.161 and 1.157 default, 0.879 aligned in the verifier's rerun), so they are not the evidence |
| x86 asm: `shape` v3-scalar and v4 clones have `lzcnt`, `popcnt`, `bzhi`/`shlx` | **Met:** `lzcnt`, 2 `popcnt`, `shlx` (and 3 `shrx`) in both clones at the x86-64 baseline level, both instances; the portable `shape` has `bsr` |
| x86 asm: P1, P2, P4, P6, P11, P13 clones have `lzcnt`/`tzcnt`/`popcnt` | **Met** for the `v3_scalar` and `v4` clones (P3's too); G7 asmcheck 166/166 |
| Cost model: NEON SHA lanes rejected | **Met:** lanes 302.9 vs SHA2 150.0 cycles per block (M5 tables); measured 98.3 vs 30.5 ns/msg |
| Cost model: SWAR varint rejected | **Met:** SWAR 5.890 vs unrolled 4.289 cycles; the measured rows agree (SWAR slower at 5 and 9 bytes, parity at 1–2) |
| Cost model: closed form beats set-bit at N = 32 with the QMDB profile (a regression check on the development profile) | **Met:** closed form 8.534, set-bit 87.821, early exit 265.423 cycles on the N = 32 samples (8.534 / 78.489 / 269.199 with both corpora, as a build merges them); the rungs are now ordered by cost |
| Must-reject R21 | **Met (after the fixer's change):** the release binary with forced detection and every `lzcnt`/`tzcnt` patched to `bsr`/`bsf` runs under Rosetta 2: the patched clone alone is wrong (`bit_len(1)` = 64), the self-test fails and the portable code runs; the unpatched binary runs the clone; `opt_reject` 34/34. The self-test's checks go through `black_box` (as first built, LLVM folded them and a `bsr` CPU passed) and G7 asserts its instructions |
| Determinism | **Met:** G1 byte-identical (three builds per instance, cold and warm); a changed tuning file changes the P3 choice and the cache key (`opt_egraph`), identical inputs give identical output |
| O7 QMDB gate | **Met:** the aarch64 emission is the O7 emission plus the self-test glue, compiled out on Apple (G10: 125/173 identical, `has_sha2` listed); N = 1 `verify` 0.872 of H2 (270.1 ns scaled), `reconstruct_finish` 0.8286 (73.9 ns scaled, 0.1% margin), `shape` 2.41/2.39/2.39 ns; N = 32 same-binary (aligned, 7 rounds): worst workload 0.9917 of H2, A/A within 0.63% |
| `v4` clones executed | **Open, now fail closed (headroom, docs/opt-headroom-reports.md):** no host has run the `v4` clones, so the optimizer no longer generates or dispatches `v4` (nor any feature-only set): a feature-only set needs a passing host run of its clones on a CPU that reports all its features (`sets` in `evidence/x86_64.json`). The host kit's `sets` stage produces those runs (QMDB fixtures N = 1 and N = 32, and a `shape` differential); run it on the Zen 5 host and merge the record. The `v3_scalar` clones passed forced-dispatch fixture runs under Rosetta 2 (N = 1: 32 fixtures, N = 32: 490, re-run by the harness), recorded as diagnostics because Rosetta 2 does not report LZCNT/BMI1/BMI2 |
| D2 (`cssc`, `shape` ≤ 2.3 ns) | **Does not apply:** `#[target_feature(enable = "cssc")]` is E0658 in rustc 1.98.1; revisit with a newer rustc |
| Budgets | **Met:** G9 1.435× (N = 32) and 1.422× (N = 1), peak RSS +203 / +172 MiB; reproduced by the verifier at 1.42–1.46× and by the fixer at 1.45–1.50× (medians 1.474/1.455 and 1.496/1.449; the current tree's absolute times were unchanged, 6626–6693 ms N = 32, while the pinned baseline ran faster under load), so almost no time headroom is left for later milestones; aegraph ≤ 10^4 e-nodes, 8 rounds (P3: 321 e-nodes, one round) |

Scope as built: the cost model (`opt/cost/{tables,tuning,model}.rs`: M5 and
Zen 5 measured, SPR and Zen 4 hypotheses; critical-path weighting; the 3%
gate; top 3 with two retries), the tuning evidence (`tuning-aarch64-m5.json`
by local calibration, `tuning-x86_64-zen5.json` from host round 0) and its
hash in the cache key, the aegraph (`opt/egraph/`, `bvnorm::classify`
batching, memoized explanations, `cong_irr` lemmas), rulegen v0
(`sandblaster/rulegen`, `lemmas/rules/bitsum.core`,
`lemmas/cong.core`), the feature-only sets (`v3_scalar`, `v4`, SHA-NI
combined with `v3_scalar`) with the known-answer self-test in the dispatch
glue, and rungs ordered by cost. Not built: `pext` candidates (no rule or
lowering proposes one yet; `pext` is priced as microcode outside `v4` and
tested only in `v4`'s self-test), EVEX-256 twins, code-size charges,
per-branch profile probabilities (½ without a profile), and rulegen's
enumeration beyond the bit-sum template and its mining mode.

### O9. AVX-512 host-validation kit v1 (2–3 weeks; can start after O1)

Owner: targets.

**Scope** (design §19):
- `tools/host-kit/run.sh` merges the scratch kits `$O/par`, `$O/corpus`,
  `$O/rs/{rsbench,gfniasm}`, `$O/curve25519/bench` and `$O/bls/harness`.
- `sandblaster-targets-evidence` is extended for:
  - the existing x86 models (SSE/SSSE3/SHA-NI);
  - known-answer tests for BMI1/BMI2/LZCNT/POPCNT.
- Evidence entries are keyed by model hash × CPUID family/model/stepping plus
  microcode.
- It also produces:
  - the tuning-evidence JSON;
  - the QMDB x86 same-binary A/B (portable vs `__shani`);
  - the corpus under `native`, `x86-64-v4` and `x86-64`;
  - parallel calibration: Linux futex θ_enter and o_fork, SHA-NI k_sat, x16 b*,
    512 vs 256 bit.
- Runs are capped (`-j 4`, one benchmark at a time) and need crates.io access.

**Files:** `tools/host-kit/**`, `sandblaster/targets/src/{evidence.rs,bin/**}`.

**Dependencies:** O1. It uses O8's tuning format once that exists.

**Acceptance:**
- **On this Mac:** the kit builds for `x86_64-unknown-linux-gnu`; its portable
  self-test passes under Rosetta; a dry run produces a schema-valid report.
- **On an AVX-512 host (first run):**
  - SHA-NI evidence is recorded, and `verify__shani` dispatch is enabled in a
    test build;
  - the known-answer tests pass;
  - each design §19 hypothesis is marked confirmed or refuted in the results
    file.

**Risks:** host access. Mitigation: the kit is self-contained; running it is
O20.

### O10. Target models and the lane functor (5–6 weeks)

Owners: targets + optimizer (parallelism).

**Scope** (design §13.3–13.5):
- **Model groups:**
  - AVX-512F/BW/VL, IFMA, GFNI, VBMI/VBMI2, VPOPCNTDQ/CD, VAES/VPCLMULQDQ,
    BMI2 `pext`/`pdep`;
  - NEON u8/u64/u32×2, SHA3 and SHA512.

  Each model comes with core text, consistency tests, `hw/x86_64.rs` detection
  and registration in `intrinsics.rs`.
- **Lanewise lemmas** per model: `lemmas/lanes/*.core`, generated.
- **Lane functor Φ** (`opt/par/lift.rs`).
- **SHA-256 kernels** lifted and proven:
  - x16 and x8 (AVX-512, AVX2);
  - x4 (NEON);
  - a shape-specialized x16 with a constant second block.
- **SIMD search lowering** (P12): NEON `vcltq` + `shrn` + `ctz`; AVX-512BW
  compare-to-mask + `tzcnt`.
- **SIMD `seq::eq` candidate.**

**Files:** `sandblaster/targets/{src/x86_64/**, src/aarch64/**, core/**, src/registry.rs, src/hw/**, MODELS.md}`,
`sandblaster/front/src/intrinsics.rs`, `opt/par/lift.rs`,
`sandblaster/front/lemmas/lanes/**`, `sandblaster/targets/evidence/aarch64.json`.

**Dependencies:** O8.

**Acceptance:**
- **G8:** every new NEON model is validated on the M5.
- **x16 SHA-256** `VariantEquiv` via the lane functor:
  - checks within ≤ 2·10^9 steps and ≤ 1 GiB peak;
  - compiles for x86_64;
  - is not dispatched (the evidence gate holds).
- **NEON x4 SHA** is proven, then rejected by the M5 cost model (report).
- **P12:** ≥ 1.8× at 16 B and ≥ 6× at 256 B on aarch64.
- **Must-reject:** R16, R26.

**Budgets:** model consistency suite ≤ 10 minutes; each lane proof ≤ 1 GiB.

**Risks:**
- Transcription errors. Mitigation: hardware evidence from O20 before dispatch.
- LLVM pessimizes emitted intrinsics. Mitigation: measure; trusted asm templates
  only where measured necessary (a DESIGN §9.2 extension).

**Status (built in `o10-tree`, validated on 2026-09-26; not yet merged).**
Every acceptance item is met. The x86 model groups that no O10 lowering
uses, the AVX-512BW search and an emission path for a chosen `seq::eq`
candidate were not built (table). Details, commands and numbers are in
`docs/opt-o10-reports.md`. Load average 4.5–7.3 during the measurements,
with other agents running.

| Item | Outcome |
| --- | --- |
| G8: new NEON models validated on the M5 | **Met:** 27 NEON u8/u64/u32×2 and 8 SHA3/SHA512 models, 10⁷ random cases each + corners + every immediate, 0 mismatches; kernel cross-check passes; `evidence/aarch64.json` regenerated natively (58 models) |
| x16 SHA-256 `VariantEquiv` via the lane functor | **Met:** 27.2 M steps, +183 MiB peak (budgets 2·10⁹ and 1 GiB); compiles for `x86_64-unknown-linux-gnu` and `x86_64-apple-darwin` (G7, `vpternlogd`/`vprold` in the asm); chosen by the Zen 5 tables (1738 vs 2437 cycles) and **not dispatched**: no host has run the kernel (lane evidence gate) |
| x8 (AVX2) | **Met:** 14.1 M steps, +96 MiB; compiles for both triples; not dispatched |
| NEON x4 SHA proven, then rejected by the M5 cost model | **Met:** 3.2 M steps, +44 MiB; 2484 vs 378 cycles for the SHA2 variant |
| Shape-specialized x16 with a constant second block | **Met:** `hash64_x16`: 51.8 M steps, +264 MiB; not dispatched |
| P12 ≥ 1.8× at 16 B and ≥ 6× at 256 B on aarch64 | **Met** (development set: measured on the program the feature was built for): judged 2.555× and 6.643× (default and aligned layouts; the NEON search variant, `opt/par/search.rs`) |
| SIMD `seq::eq` candidate | **Met:** generated, proven equal to the word form (`seqeq::neon_word_<n>`), rejected by the M5 tables (16 B: 22.2 vs 12.0 cycles; 32 B: 38.0 vs 21.4) |
| Must-reject R16, R26 | **Met:** `opt_reject` 37/37 (R16: lanes 3/4 swapped, `lane_equiv` rejected; R26: a lane kernel without its host run, and a NEON variant with withheld model evidence) |
| Budgets | **Met:** model consistency suite 133 s of test time; each lane proof ≤ 264 MiB |
| Gates | **Met:** G1, G2, G4, G6, G7 (asmcheck 179/179), G9 (1.255× / 1.152×, +190 / +180 MiB), G10 (125/173 identical, 80/111 specialized) |
| QMDB | **Met:** emission byte-identical to O8's; 7-round A/B: verify 270.2 ns scaled (0.872 of H2), `shape` 2.42 ns, `reconstruct_finish` 73.8 ns scaled (0.827). `reconstruct_finish` is at its limit (0.777–0.831 of H2 across four runs, limit ≈ 0.829), and `shape` needs a quiet machine; the fixer's emission is identical, so this verdict carries forward |
| x86 groups: byte compare-to-mask, `setzero`, `set_epi64`, `min_epu64`, `permutex2var_epi32`, `maskz_compress_epi8`, `lzcnt_epi64`, VAES/VPCLMULQDQ, BMI2 | **Not built:** no O10 lowering needs them, and they cannot be validated on this Mac; the next Zen 5 host round would add them |
| AVX-512BW search (compare-to-mask + `tzcnt`) | **Not built:** needs the byte compare-to-mask models |
| Lane kernels dispatched on x86 | **Open:** needs a host run of each kernel (host kit stage `lanes`, `tests/host_lanes.rs`; a Rosetta 2 diagnostic of the AVX2 kernel ran 20,000 inputs with no mismatch, not recorded) |
| Lane evidence names the emitted code (fixer) | **Met:** the record name hashes the printed kernel, the helpers it calls and `rustc -V` (`opt::par::lane_fingerprint`); the round trip holds every printed kernel to it; a changed helper template renames the record (R26, `opt_reject` 38/38) |
| NEON lane kernel host run (fixer) | **Met:** the `lanes` stage runs on aarch64; `lanes:neon_x4:5222…d838` recorded natively on the M5 (10⁶ inputs, 0 mismatches); still rejected by the M5 cost model |

Scope as built: the NEON models and their evidence; the lane functor
(`opt/par/{tiles,cquote,lift,sites}.rs`) with staged congruence proofs and
the generated libraries `lemmas/lanes/*.core`; the lane evidence gate
(`lanes:<target>:<hash>` set records) and the host kit's `lanes` stage; the
SIMD search lowering and its lemma library (`opt/par/search.rs`: every
unsigned byte test against a literal, any result type); the `seq::eq`
candidate (`opt/par/seqeq.rs`). Not built beyond the table: masked lane
tails, `u64` lanes, cross-lane shuffles in lifted code, and other search
skeleton spellings.

### O11. Parallelism I: fusion, lanes, state decoupling (no threads) (3–4 weeks)

Owner: optimizer (parallelism).

**Scope** (design §14.2–14.3):
- `opt/par/{sites,decide,fuse}.rs`: Σ5 skeletons (antichain, map, reduce,
  search, tree, AffineGF2).
- Decision procedure for ILP and lanes, with the tail policy (masked gang, or
  NEON padding with the padding lemma).
- State decoupling for cursor-threaded recursions (Σ2 on the index effect).
- Decision records in the report.
- Equal-input memoization is designed here and implemented after L6 (O16).

**Files:** `opt/par/**`, `sandblaster/front/lemmas/par.core` (tiling, padding, homomorphism lemmas).

**Dependencies:** O10.

**Acceptance:**
- **P16** (K equal-shape 20-deep paths): ≥ 1.25× on the M5 from interleaving
  (measured candidate 1.28–1.30× at K ≥ 2).
- **x86 v4:** x16 lanes are chosen for ≥ 7 active lanes (report); the path is
  compile-only.
- **P15** single-threaded ≥ 1.15× (measured candidate 1.19–1.23× at ≥ 16
  leaves).
- **QMDB** single `verify`: the report shows no lanes or threads chosen, and
  there is no regression.
- **Must-reject:** R17.

**Budgets:** optimizer time ≤ 1.6×.

**Risks:** code growth from fused kernels. Mitigation: the code-size term and
the 3% gate.

### O12. Language extensions I, after the S0 merge (6–8 weeks)

Owner: front-end, with printer, kernel (prelude) and automation.

**Scope** (design §16):
- **L1:** `&mut [T]` as linear values, with `fill`, `copy_from_slice`,
  `copy_within`, `chunks_exact_mut` and `split_at_mut`.
- **L2:** `u128` and `mul_wide_u64` as prelude operations over `Int`.
  - This is TCB item 3 (prelude definitions), about 40 lines of core text, and
    needs kernel-owner review.
  - It makes no `Width` change and no kernel code change.
- **L3:** `#[memo]` tables.
- **L4:** whitelist additions (`next_power_of_two`, `next_multiple_of`,
  `is_multiple_of`, `.rev()` ranges), and the `(u16, bool)` convention for signed
  digits.
- **Queued optimizer patches:** `#[specialize(loop_free)]`, a HIR field for
  `#[rewrite]` laws.
- A per-construct differential corpus (DESIGN §10.3) for each new construct.

**Files:** the S0-owned files, `builtins.rs`, `elab/semantics.rs`,
`sandblaster/kernel/prelude/*.core` (L2), `canon.rs`, `roundtrip.rs`,
`SEMANTICS.md`.

**Dependencies:** the S0 merge; O4.

**Acceptance:**
- The differential corpus passes for every construct.
- Round trip is clean.
- P19 (16-term dot product mod p) is added to the corpus.
- The Reed–Solomon R2 work is unblocked.
- `#[specialize(loop_free)]` on `shape` holds in the QMDB test configuration.
- G5 is unchanged, since there is no kernel code change.

**Risks:** S0 merge conflicts. Mitigation: the queue of patches; no optimizer
milestone touches these files.

### O13. Parallelism II: threads (4–6 weeks)

Owners: optimizer (parallelism) + printer.

**Scope** (design §14.4–14.5):
- **Combinators** in `lemmas/par.core`: `par::choose` (with its `Eq` argument),
  `par::map_tiles`, `par::join`, `par::reduce`.
- **Templates** in `__rt::par`:
  - tile-index validation, with serial recompute on mismatch;
  - sequential combine in index order;
  - leftmost error.
- **`__rt::Exec`:**
  - a blanket `impl<S: commonware_parallel::Strategy>` under the `commonware`
    cfg;
  - `Serial`;
  - `Scoped { threads }`.
- **Entry points.** Opt-in `f_with<E: __rt::Exec>` entry points
  (`[opt] exec_entry_points = true`) and executor-carrying clones
  (`opt/par/{twins,emit}.rs`).
- **Guards** `n ≥ n*`.
- **Subtree splitting.**
- **Round trip:** lowering of templates and of the `&E` parameter.
- **DESIGN §1.1 assumption:** worker stacks ≥ 2 MiB.

Trees and reductions do not need L1. Symbolic-size outputs do.

**Files:** `opt/par/**`, `canon.rs`, `roundtrip.rs`, `sandblaster/front/lemmas/par.core`, tests.
The tests use `commonware_parallel` as a dev-dependency, as a path dependency
pinned to `86b7ee8674`.

**Dependencies:** O11, and O12 (L1) for in-place outputs.

**Acceptance** (M5, emitted code):
- automatic subtree-parallel BMT/MMR build: ≥ 2.5× at 2^12 leaves and ≥ 6× at
  2^16 (measured *(hand-written candidates)* 2.9× and 7.1×);
- batch 20-deep paths: ≥ 5.5× at K=1024 and ≥ 7× at K=4096 (measured candidates
  6.0× and 8.1×);
- outputs are identical under `Sequential`, Rayon(4), Rayon(12) and `Scoped`
  over the corpus and QMDB fixtures;
- QMDB single `verify` has no executor call, and `f_with` is not generated
  unless opted in;
- **zero overhead:** a hand-written level-synchronous Commonware-style
  merkleize on the same executor is not faster than the emitted code at any
  size ≥ 512 pairs;
- **Must-reject:** R17, R18.

**Budgets:** templates ≤ 150 lines of trusted glue.

**Risks:**
- macOS wake-up latency dominates the thresholds. Mitigation: a runtime guard
  plus the adaptive policy; Linux θ comes from O20.

### O14. Σ4 algebra (6–8 weeks, plus a proof library)

Owner: optimizer (algebra).

**Scope** (design §9):
- `opt/alg/{gf2,ring,sched,select}.rs`.
- `lemmas/{gf2,ring}.core`: `gf2_linear_ext`, `mul_linear`, and reflective
  RingRefl.
- Table and affine synthesis for constant GF(2) maps.
- Runtime-multiplier staging, with `lut(c)` built from the basis products.
- E1 and E2.
- Exact reduction batching and scheduling (plain-equality only).
- Formula selection in the aegraph.
- `#[rewrite]` consumption (needs O12's HIR field).
- Algorithm selection through `#[refines]` (needs §15 S1).
- P14 closed form.

**Files:** `opt/alg/**`, `sandblaster/front/lemmas/{gf2,ring}.core`, tests.

**Dependencies:** O8, O10 (u8 models), O12 (u128, `#[rewrite]`); §15 S1 for the
refinement-based selection.

**Acceptance:**
- **P17:** from portable source, the emitted NEON TBL kernel is ≥ 31 GiB/s
  (Commonware `Neon::mul` 32–33; LLVM on portable source 1.8).
  - The GFNI variant is proven and compile-only, with ≤ 4 vector ALU ops per
    64 B (asm).
  - It agrees with the reference for all 65536 multipliers on the models
    (local test).
- **P14** does not regress (it is a control; the closed form is taken only if
  cheaper).
- **E1/E2** on P18 and P19: bit-identical results, and P19 ≥ 1.2×.
- **Refinement-based selection:** a corpus pair of implementations refining one
  spec is replaced by the cheaper one (report).
- **D3:** reflective RingRefl proves the Fp12 flattened-multiplication identity
  in ≤ 2·10^8 steps.
  - If not, a TCB design note weighs a native RingRefl against the budget:
    move bvnorm to a reflective prelude checker, or raise the budget with owner
    sign-off.
  - Nothing is added to the kernel silently.

**Risks:**
- Proof volume for field libraries. Mitigation: prefer `bv()` routes for fixed
  parameters, as in RS R1.

### O15. Reed–Solomon port (R0–R5; R0 can start after O1)

Owner: RS port. The monorepo pin is `6e15fe7c`; HEAD `86b7ee86` is identical for
these paths.

**Kernel scope.** The RS report asked for K1 (packed arrays), K2 (exhaustive
certificates), K3 and K5 (bvnorm rules). None of them are needed:
- GF lowering uses `gf2_linear_ext` plus enumeration;
- constant tables are synthesized by Σ4;
- memo tables are proven through builder-induction lemmas.

| Stage | Scope | Dependencies | Acceptance |
| --- | --- | --- | --- |
| R0 oracle + harness | `rs/oracle` pinned; (k, m, shard_bytes ∈ {2, 62, 64, 66, 1024, 8190, 8194, …}, both rates, erasure patterns including worst cases and invalid indices) grid; upstream vectors; interpolation-spec oracle (`$O/rs/spec.rs`); `ReedSolomon<Sha256>` corpora; `rsbench` baseline | O1 | reproduces Commonware's vectors; 0 disagreements |
| R1 GF core + fixed-parameter block encoders (4/6, 7/13) | `spec::gf16`, `spec::rs`; `encode_block_*` over `[[u8;64]; k]`; `#[refines]` by `bv()`; NEON TBL and AVX-512 GFNI variants derived by Σ4 | O5, O10, O14 (gf2 part) | byte-identical on 10^6 random blocks; ≤ 167 ns per 7/13 × 64 B block (Commonware); NEON validated locally; GFNI proven, compile-only |
| R2 language and library | L1, L3, L4, 2-D shard view; GF(2)[x] library (`gf_field`, `mul_linear`, `twiddle` via linear extensionality + evaluation) | O12, O14 | library laws kernel-checked; table builders proven by builder induction |
| R3 general encode (both rates) | radix-2 source (layer fusion measured ±1.8%); LCH FFT theorem; staging, unswitching on the `GF_MODULUS` sentinel, known-zero skipping (automatic `truncated_size`) | R2, O7 | byte-identical over the R0 grid; ≥ 0.98× Commonware Neon on every engine row; kernel ≥ 31 GiB/s |
| R4 decode | matrix decode and FFT decode, selected through refinement; direct locator evaluation for high rate | R3, §15 S1 | byte-identical incl. every error case; ≥ 1.8× Commonware at n ≤ 50, ≥ 0.98× everywhere; 32/32 high-rate decode ≤ 20 µs (Commonware 253 µs) |
| R5 coding scheme | prepare/check/decode, BMT, laws `decode_sound`/`decode_unique`/`canonical`; automatic stripes (O13); multi-stream shard hashing | R4, O13 | `Chunk` conformance hash `45545e4d…`; byte-identical roots/chunks; fuzz target passes; Sequential ≥ 1.15× encode and ≥ 1.5× decode at 1–8 MiB, n=20/100; Rayon(8) ≥ 1.0×; aarch64 shard hashing ≥ 1.25× |

AVX-512 host targets, measured in O20:
- GFNI kernel ≥ 2× Commonware AVX2;
- encode/decode ≥ 1.5×;
- scheme ≥ 1.0× (Commonware already uses x16 SHA there).

### O16. Language extensions II (after S0; §15.13 staging) (8–12 weeks)

Owner: front-end, with printer and automation.

**Scope:**
- **L5 `Secret<T>` MVP:**
  - structural taint over structs of limbs;
  - `ct_select`/`cswap` templates with an optimization barrier;
  - a post-optimization constant-time core check;
  - DIT glue on aarch64.
- **L6:** `Vec`/`Seq` collections (DESIGN §13.2).
- **L7:** static traits over the coordinate field (DESIGN §14.3).
- **Library:**
  - SHA-512 (portable FIPS 180-4) and multi-part hashing;
  - a FEAT_SHA512 aarch64 variant, validated locally;
  - an AVX-512 8-lane multi-buffer variant, compile-only.
- **Equal-input memoization** over `Seq` (sort, unique, lookup), for batch
  APIs.

**Files:** the S0-owned files, `canon.rs`, `roundtrip.rs`, `opt/drive/**` (secret rules),
`sandblaster/targets/**` (SHA-512 models).

**Dependencies:** the S0 merge, and §15 staging for `Secret`.

**Acceptance:**
- The constant-time check is green on an X25519-ladder corpus kernel.
- **Must-reject:** R23.
- `Vec` passes the differential corpus.
- SHA-512 matches FIPS vectors, and the FEAT_SHA512 variant is validated on
  the M5.
- A multi-proof corpus program with memoization does ≈ 30% fewer hashes at
  K = 1024, h = 30, with identical verdicts.

### O17. curve25519 port (C1–C6)

Owner: curve25519 port. The monorepo pin is `6e15fe7c` (identical at
`86b7ee86`). All targets use Commonware's `overflow-checks = true` profile.

| Stage | Scope | Dependencies | Acceptance |
| --- | --- | --- | --- |
| C1 field GF(2^255−19) | portable radix-2^51 source written like Commonware's; `spec::field`; E0 (O2), E1/E2 (O14), constant specialization (O5) | O2, O5, O12 (u128), O14 | refines `spec::field`; differential ≥ 10^6 vs Commonware `F` (random, `MASK_52` limbs, encodings ≥ p); mul ≤ 8.2 ns latency, square ≤ 6.8 ns, invert ≤ 2.0 µs |
| C2 X25519 | constant-time ladder over `Secret` limbs | C1, O16 (L5) | RFC 7748 vectors (+ iterated ×1/×1000 natively); Wycheproof 518; low-order rejection; bit-identical to Commonware and x25519-dalek; constant-time check green; **≤ 18.5 µs** (Commonware 33.5–33.9) |
| C3 Edwards group, scalars mod L | extended coordinates, ZIP215 decompress/compress, Barrett, recoding; completeness (d non-square by closed evaluation) | C1, O16 | ZIP215 196 cases; property tests vs Commonware via canonical bytes; decompress ≤ 2.1 µs; point add ≤ 84 ns |
| C4 Ed25519 single sign/verify | Straus + wNAF + basepoint table written in source; later selection through refinement | C3, O16 (SHA-512), O14 | RFC 8032 ×5; ZIP215; Wycheproof 151; differential vs ed25519-consensus; verify ≤ 23 µs (Commonware 73.5); sign ≤ 9.6 µs (Commonware 51) |
| C5 batch verification | Pippenger + Straus by n (selection); lanes; threads (O13) | C4, O13, O16 (Vec) | Commonware batch tests incl. Sequential/Rayon agreement; n ≥ 1024 at or below Commonware per signature; n=1 ≤ 25 µs; n=8 ≤ 15 µs/sig |
| C6 AVX-512 | IFMA field and point kernels as representation-region helpers | O18, O10 | static parity: `mul_field` ≤ 148 instructions with 26/25 IFMA; `add_points` ≤ 1604; host timings in O20 |

### O18. Representation regions (3–4 weeks)

Owner: optimizer (algebra).

**Scope** (design §9.5):
- `opt/alg/region.rs`: builder for simulation lemmas, and composition at the
  boundary.
- Lazy-reduction placement.
- Helpers for the NEON 26/25-bit digit layout and the IFMA 52-bit layout.
- The DESIGN §15.2 wording note.
- **D5:** red-team before landing.

**Files:** `opt/alg/region.rs`, tests.

**Dependencies:** O14, C1/C2.

**Acceptance:**
- An X25519 region with lazy reduction is bit-identical at the boundary and
  ≥ 5% faster than C2 (stretch: 15 µs).
- The NEON field-kernel region helper is validated locally.
- The IFMA kernels reach static parity (C6).
- **Must-reject:** R22.
- The red team finds no way for a representation-dependent value to reach a
  replaced function.

### O19. BLS12-381 / VROOM port (Stages A–E)

Owner: BLS port. Based on PR #4811 at `5a68b8f417`; production baseline
`6e15fe7c`.

**Representation choice.** RNS on IFMA vs six-limb Montgomery on aarch64 is made
by **selection through refinement between author-supplied implementations**. It
is not synthesized. Data refinement exists only inside regions (O18).

| Stage | Scope | Dependencies | Acceptance |
| --- | --- | --- | --- |
| A residue core + Fp | lane ops (`madd`, `prepare`, `reduce`, `change_base`, `expand`) over `[u64; 8]`; parameter bounds as kernel lemmas (moves `parameters.py --check` into the kernel); CRT view; AVX-512 variants proven; six-limb Montgomery on ARM refining the same spec | O10 (IFMA), O12, O14, §15 S1–S2 | ≥ 10^6 random + boundary vs bigint oracle; lane-exact vs the PR's `Portable` (and IFMA on the host); canonical vs blst; portable Fp mul ≤ 70.5 ns, 16-term dot ≤ 141 ns; ARM Montgomery ≤ 1.05× blst (≤ 20.8 ns latency, ≤ 16.2 ns throughput); ≤ 40 IFMA per closed multiply (static) |
| B tower + group, written naively | naive Karatsuba tower and naive RCB formulas; delayed reduction and formula selection are automatic | A, O14 | 10^5 random points incl. P = Q, P = −Q, identity, byte-equal with blst and the PR; IFMA static ≤ 948 IFMA / 2312 instructions per Fp12 mul, ≤ 406 IFMA per G1 mixed bucket add; ARM G1 add ≤ 363 ns, double ≤ 165 ns, Fp12 mul ≤ 1.0 µs |
| C scalar multiplication, MSM, threads | GLV/GLS with `Secret`; Pippenger with `Vec` buckets; Booth recoding proven; tiles | B, O13, O16 | byte-equal with blst at the PR's fixture sizes; ARM MSM of 256 points ≤ 2.51 ms, constant-time G1 mul ≤ 46 µs; ≥ 80% thread efficiency at 6 threads for 100k points |
| D pairing, hash to curve, signatures, batch verify | RFC 9380 vectors; consensus-spec vectors | C | ARM pairing ≤ 285 µs, hash_to_G1 ≤ 29.2 µs, hash_to_G2 ≤ 88.3 µs, verify ≤ 0.50 ms; IFMA (host) pairing ≤ 102.5 µs for 1 pair, ≤ 474.1 µs for 16 |
| E subgroup checks, recovery, Banderwagon | k-path moduli (anti-overfitting to `no_k`); statistical assumption for the batch subgroup bound | D | the PR's graph tests; IFMA G1 membership at 100k ≤ 0.132 s, G2 ≤ 0.325 s; the curve25519 cross-check picks radix 2^51 |

### O20. AVX-512 validation rounds and dispatch enablement (recurring, 1–2 weeks per round)

Owner: targets.

**Rounds:**
1. after O8/O9: SHA-NI, feature-only sets, corpus, QMDB x86 A/B;
2. after O10/O13: AVX-512 models, x16 SHA, SIMD search, thread thresholds;
3. after O15 R1/R3: GFNI;
4. after O17/O19: IFMA.

**Each round:**
- run the kit on at least two microarchitectures (one Intel SPR/ICX, one AMD
  Zen 4/5);
- check in evidence and tuning JSON;
- enable dispatch only for evidenced models;
- record the x86 acceptance numbers;
- update the hypotheses in design §19.

**Acceptance per round:**
- all differential tests pass;
- a dispatched variant is never slower than the next-best set on that
  microarchitecture (≥ 3 builds, min/median reported);
- QMDB N=1/N=32 x86 A/B tables are published.

**Expected first-round results (hypotheses):**
- `verify__shani` dominates on x86;
- the closed-form `shape` gains more than it does on the M5;
- the 2 KiB zeroing costs 10–20 ns.

---

## 3. Decision points

| Id | When | Question | If no |
| --- | --- | --- | --- |
| D1 | end of O3 | do the per-literal obligations of `shape_go`/P4 close with auto + K1 + integer cuts? | O6 ships early exit and set-bit rungs first; open a reflective bit-blasting checker (prelude, 0 TCB) |
| D2 | O8 | does rustc 1.98 accept `cssc` in `#[target_feature]`? | NEON `cnt` lowering; revisit with a newer rustc |
| D3 | O14 | does reflective RingRefl check the Fp12 identity in ≤ 2·10^8 steps? | TCB design note (options: reflective bvnorm to free budget, or an owner-approved budget change); never a silent kernel addition |
| D4 | O9/O20 | do the x86 hypotheses hold? | tuning evidence re-derives choices automatically (tuning hash in the determinism key); design §19 updated |
| D5 | O18 | does the red team break the representation-region discipline? | regions stay disabled; curve25519/BLS keep source representations; C6/Stage B IFMA targets are deferred |

---

## 4. Target summary

Every target below is measured on the development set (QMDB, the corpus,
the programs the features were built for). They are regression gates: on
their own they cannot justify a new feature, and none is evidence that the
optimizer is general or beats rustc. The held-out evaluation
(`sandblaster/bench/heldout/REPORT.md`, first run 2026-10-02) found the
optimizer changes 0 of 31 held-out functions (optimizer-only geomean 1.02
default layout, 1.005 aligned, vs rustc on the same source): no held-out loop
reaches the optimizer (the MIR reader and exec-only elaboration refuse 28 of
31). Repeat it at every milestone and publish it next to these targets.

### 4.1 QMDB (zero source changes; same-binary A/B on emitted code)

| Milestone | `shape` N=1 / N=32 / uniform | `reconstruct_finish` | `parse` | N=1 `verify` | N=32 |
| --- | --- | ---: | ---: | ---: | --- |
| baseline H2 | 24.8 / 46.0 / 61.5 ns | 89.2 ns | 6.46 ns | 309.8 ns | — |
| O5 | – | – | **≤ 1.7 ns** | ≤ H2 | no workload > H2 + 1% |
| O6 | **≤ 2.6 ns each** | – | – | ≤ 292 ns | – |
| O7 (regression gate) | – | **≤ 74 ns** | – | **≤ 275 ns** (pre-H1 284.0) | no workload > H2 + 1%; ≤ 0.77× Commonware (development-set regression only, not an optimizer criterion); ≤ 0.95/0.96× hand-written; deep ≥ 3% faster |
| O8 | aarch64 `cssc`: ≤ 2.3 ns (if D2) | – | – | maintained | maintained |
| O20 | x86: record | x86: record | x86: record | x86 A/B published | x86 A/B published |

### 4.2 Corpus (aarch64, emitted code vs `ideal/`)

| Programs | Milestone | Target |
| --- | --- | --- |
| P5b, P10, P20 | O5 | P5b ≥ 2.5×; P10 ≥ 3× / 4×; P20 ≥ 1.4× |
| P1, P2, P4, P6, P11, P13 | O6 | within 1.25× of ideal |
| P7, P8 | O7 | P7 ≥ 8× / 2×; P8 ≥ 1.1× |
| P3; controls P9, P14 | O8 | P3 ≥ 8×; controls within 2% |
| P12 | O10 | ≥ 1.8× / 6× |
| P15, P16 | O11 | ≥ 1.15×; ≥ 1.25× |
| P17, P18, P19 | O2 / O14 | P18 ≥ 1.5× under overflow checks; P17 ≥ 31 GiB/s; P19 ≥ 1.2× |

### 4.3 Must-reject tests by milestone (design §20)

| Milestone | Tests |
| --- | --- |
| O1 | R25, R26, R27 |
| O2 | R19 |
| O3 | R20 |
| O4 | R1, R3, R4, R11, R12, R13, R14, R15, R24 |
| O5 | R2, R10 |
| O6 | R6, R7, R8 |
| O7 | R5, R9 |
| O8 | R21 |
| O10 | R16 |
| O11 | R17 |
| O13 | R18 |
| O16 | R23 |
| O18 | R22 |

---

## 5. Risk register

| Risk | Milestone | Likelihood / impact | Mitigation |
| --- | --- | --- | --- |
| Per-literal obligations do not close | O3/O6 | medium / high (N=32 loses ≈ 11 ns per verify) | D1 prototype first; the early-exit + idle-skip rung (measured candidate 2.43 / 13.8 / 2.48 ns vs 2.33 / 2.26 / 2.30 for the closed form) keeps the N=1 gate reachable; the closed form follows once the failing obligation class is fixed |
| Kernel budget (≈ 190 lines of headroom) | O3, O14 | low / high | K1 net ≈ +40; retire bound schemas; everything else in the prelude or reflective; G5 |
| Scope (≈ 30k untrusted lines) | all | high / medium | every milestone ships independently behind the fallback; QMDB gate by O7 |
| Proof-memory blow-up | O4, O10 | medium / high (host OOM) | `BvRefl` entry cap; lane functor; per-lemma steps; memguard; ≤ 1 GiB per lane proof |
| Printing erases gains | O5–O7 | medium / medium | measure emitted code; asm checks; `#[inline]` hints |
| x86 cost errors | O8+ | high / medium | profiles, tuning evidence, multi-result extraction, host rounds |
| S0 merge conflicts | O12, O16 | medium / medium | no optimizer milestone touches S0 files; queued patches |
| Reflective RingRefl speed | O14, O17, O19 | medium / high for BLS | D3 with a design note; stay on `bv()` routes for fixed parameters |
| Representation regions unsound in practice | O18 | low / high | helpers only; plain equality at boundaries; red team (D5) |
| Build time on the shared machine | all | medium / medium | single-threaded optimizer, hints cache, step budgets, cold ≤ 1.5× target |
| Host access for AVX-512 | O9, O20 | medium / medium | compile-only proofs and asm checks now; dispatch fails closed |
