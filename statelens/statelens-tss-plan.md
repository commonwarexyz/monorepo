# Target-State Synthesis for StateLens: PRD/SPEC update (stage 1), then implementation (stage 2)

## Context

StateLens (`statelens/`, after arXiv 2609.24550) instruments commonware's monorepo simplex/marshal/qmdb with assertions
and state probes and builds a `*_statelens` variant of every existing fuzz target. Variants inherit
drivers that sample states at random, so deep multi-step states (the ones tests, PRs and bug
reports describe) are rarely reached. The marshal scenario method
(`consensus/fuzz/marshal/src/scenarios/`, `specs/SPEC.md`) reaches 6 such states, but statically:
hand-written prefixes behind a closed enum, prefix fully fixed, a miss panics, no probe
verification, no refinement, marshal standard tests only.

Target-State Synthesis (TSS) is the dynamic LLM-assisted version on top of an instrumented checkout: a target
protocol state is extracted (Phase 1) from a test, issue/PR, comment, report or text into a reviewed card;
after a campaign, an agent writes a dedicated state-reaching fuzz target (scaffold) per card and
base that fixes the essential setup and history and exposes uncertain parameters, timings and orderings to
libFuzzer; the probes the campaign already installed, together with harness observables, witness
which stages were reached, and that verdict drives up to 3 refinements. The probes stay part of the
instrumented SUT and serve every scaffold.

Paper: arXiv 2609.23889v2 is "SyzHarness" (Linux kernel; patch -> Syzkaller pseudo-syscall; v3
exists with errata). It never says "Target-State Synthesis" or "semantic probe". Mapping used in the
docs: trigger scaffold -> fixed setup + History; uncertain bug-critical knobs -> Knobs; isolated
config -> dedicated target; T_file/T_func/T_line -> witnessed stages; <=5 feedback iterations
-> <=3 refinements on replays; main() sanity run -> canonical empty input; patch-differential
validation -> control run. Its main failure mode (14/20: code reached, semantic precondition not)
is what StateLens probes close.

User decisions, binding:
1. Verification uses existing probes only (invariant + beacon probes the campaign installed, plus
   harness-side observables). No new SUT instrumentation step: synthesis adds no probes,
   assertions or ghost state. (A read side in the runtime *template* is allowed: it is
   materialized by every campaign.)
2. We only use this method for simplex and marshal profiles; qmdb refused.
3. Every scaffold that passes the safety vetoes and builds is fuzzed; the verdict is only reported.
4. An input that misses a stage continues into the base driver's free-running phase.
5. Synthesis edits follow the edit contract below (the Assumptions section, made authoritative).
6. Shape A (pinned base input, stages read after the run) preferred; Shape B (online prefix) allowed.
7. Existing variant `run` lines keep their flags (separate follow-up); scaffold lines carry none.
8. The card is the record of its source; raw inputs are not archived (see D60, "Where inputs
   live").
Standing preferences: keep the tooling simple; same input type, `run` recipe and libFuzzer flags
as ordinary fuzzing; no seed corpora; fix the method, never a campaign checkout.

Design source: judge-panel workflow (3 designers, merge, 2 critics, final), checked against HEAD
`37e01e1036`, trimmed for simplicity, then revised for the review of 2026-10-07 (witness
soundness, handoff vs recovery, crash attribution, one edit contract).

## Assumptions
Scaffold synthesis operates on a disposable copy of the repository, following the same assumption as StateLens. The generator may modify source code when necessary to expose state, make existing functionality callable, add fuzz-only accessors or wrappers, or support scaffold execution and verification.
Such modifications must not change the production behavior or protocol semantics of the system under test.
Allowed examples include:
widening visibility of existing functions, fields, or types;
adding fuzz-only getters or read-side accessors;
adding re-exports;
adding wrappers around existing operations;
adding campaign/runtime observation code;
adding compile-time fuzz-only hooks that expose existing behavior;
restructuring code only where the transformation is demonstrably semantics-preserving.
The generator must not modify production consensus logic, including:

state-transition rules;

branch conditions or protocol predicates;

ordering of protocol operations;

certificate or vote validation rules;

message handling semantics;

timeout behavior;

persistence/recovery semantics;

error handling that affects execution;

state mutations used by the production implementation.

The principle is:

Allowed:
change how existing behavior is exposed or observed

Forbidden:
change what the protocol does

Because synthesis runs on a disposable copy, generated modifications do not need to be suitable for upstream production code. They only need to preserve the behavior of the production logic being fuzzed.

## Edit contract (authoritative; PRD R-TS-SYN-3, SPEC 18.6.1)

The Assumptions section above is the one contract for every synthesis edit. Every other part of
this plan, the PRD, the SPEC, prompt `synthesize.md`, the synthesis scope check, the restore rules
and the acceptance criteria refer to R-TS-SYN-3 instead of restating allowed edits.

- Where: the profile roots (the SUT: `consensus/src/simplex/`, plus `consensus/src/marshal/` for
  marshal) and the profile's fuzz package (`consensus/fuzz/{simplex,marshal}/`, which reaches
  `consensus/fuzz/core/` only through its own `src/`). Any other path is out of scope.
- "Observation code" means read-only code the scaffold calls (getters, accessors, witness helpers).
  It never adds counter features, assertions or ghost state (decision 1); those come only from the
  campaign.
- Mechanical guards (the only part a script enforces; semantics is enforced by the prompt, the
  test gate and human review of the diff):
  1. scope: a change outside the paths above is exit 2 and the card's edits are restored;
  2. no dependency change in any `Cargo.toml`; the package manifest, `target_states/mod.rs` and the
     `lib.rs` declaration line are script-owned (agent edits to them are restored, with feedback);
  3. instrumentation integrity: no `sl_probe!`/`sl_assert!`/`sl_implies!` call added, removed or
     changed; `statelens.rs` byte-identical to its state when synthesis started (the witness
     checks rely on its trace, so observation code lives elsewhere); no
     `with_ghost`/`with_global`/`record`/`note`/`watch`/read-API call added under the profile
     roots; no `[statelens-reach]` or `[statelens-scaffold]` literal outside
     `target_states/mod.rs` (veto, with feedback);
  4. marker: every changed hunk outside the card's module and thin target carries
     `// [statelens] tss:TS-NNNN` (missing: annotation `unmarked edit`, for review);
  5. test gate: when the kept version of a card changed any file under the profile roots, the
     script reruns the test gate; a failure restores the card's edits and records GATE FAILED;
  6. restore: on NOT BUILT or GATE FAILED the card's edits are restored on every path; `just clean`
     restores the profile roots, the fuzz packages' `src/` and manifests, and deletes
     `target_states/` and the thin targets.
- Alignment: prompt `synthesize.md` quotes R-TS-SYN-3 and guards 1-6; the synthesis scope check
  implements guards 1-3 and 4 as an annotation; AC-24/AC-25 test each guard with stub agents.

## Design (decisions D59-D68, SPEC section 18.2)

**D59 Registry.** `statelens/target-states/{simplex,marshal}/TS-NNNN.md` plus git-ignored
`target-states.local/<sub>/` (kb and out-of-repo sources). One global `TS` counter; every card
active; no status field (D1). Front matter = the five invariant keys; `source_kind` adds `test`,
`text`. Sections, in order: Statement (one "While ..., the replica ..." sentence, honest replicas,
no Rust identifiers, R-REG-4), Rationale, Evidence (pinned `path:line@commit`, ranges <= ~40
lines), History, Knobs (`| Knob | Event | Domain | Source value |` or "None."; >= 2 values per
domain), optional Observation hints, generated Source excerpts. History: `E1.`..`En.`; each event
starts with its actor (`harness` or a replica name) and names the entities it involves (replicas,
views, payloads, parents, certificates, incarnations) with short names (R, v, d, p1).
E1..E(n-1) each have one indented `Check` line (the event happened), En has one `Holds` line (the
target state holds at handoff). Each line starts with the entities it binds, in parentheses; an
entity shared with an earlier event is written `v as E1`, and a name without `as` is existential
("for some v"): `Check (R, v as E1, d as E4): R holds a notarization of d for v.` Optional
`Order:` line. Cards never name probe labels (labels change per campaign). New lint rules 12
(History shape: numbering, actors, one `Check` per event before En and one `Holds` for En, entity
lists, every `as Ek` names an earlier event that binds that entity, `Order:` names defined events)
and 13 (Knobs shape); `just check-invariants` lints cards too.
Reuses `FILE_NAMES`, `registry_files`, `lint_file`, `with_excerpts`; `next_invariant_id` becomes
`next_id(prefix)`.

**D60 Phase 1.** `just extract-states [--registry simplex|marshal] [--number N] <kind> <source>...`
= `statelens.py extract --states`: one prompt `prompts/state-analyst.md` (+ the existing
`subsystems/<registry>-analyst.md`), same post-checks as `cmd_extract`. Kinds: existing ones plus
`test` (`path:line[-end]` under the registry's source root or its fuzz package; reads the test,
its helpers and the code it drives; outcome asserts dropped; incidental choices become knobs per
scenario-SPEC S7; direct mailbox injections become the protocol event that produces the same input)
and `text` (a file, or a literal written to `extract/` for the agent to read; `source_ref` is
`text: <title>` or the original path, never `extract/`; Evidence quotes the passages that define the
History verbatim, <= ~40 lines, and summarizes the rest; every event confirmed against code or
dropped). With `--states`, a `kb` source may also be one finding id (resolved as `kb show` does).
An `issue` source's `source_ref` is the URL plus the merge commit, or the head commit of an
unmerged PR (re-extract after the merge to pin its tests); Evidence pins the code the History runs
against (normally HEAD), and for a fix PR the target state is the precondition the bug needed, not
the bad outcome.

Routing by disclosure, not location: `kb`, `text`, any source path outside the repository, and any
extraction run with `--local` (a private advisory, a private repository) write to
`target-states.local/<sub>/`; public URLs and in-repo paths write to `target-states/<sub>/`.
Sharing a local card is a manual rewrite without private detail and a move (as D55). Campaigns and
synthesis run in a fresh clone, which has no git-ignored files: the README says to copy
`target-states.local/` (like `invariants.local/`) into it, and `synthesize` prints
`cards: <n> tracked, <m> local`.

Where inputs live (decision 8): synthesis reads only the card and the current code, so the card
carries everything essential; no raw input is archived.
| Input | Kept as | Where |
|---|---|---|
| public GitHub PR / issue | URL + merge (or head) commit in `source_ref`; body, comments, diff fetched live at extraction; Evidence quotes the decisive sentences and pins the code | card, committed; prompt/log in `statelens/extract/` (git-ignored) |
| test, code comment | pinned `path:line@commit`; cited lines copied into generated `## Source excerpts` | card, committed |
| text description | the defining passages quoted verbatim in Evidence | card in `target-states.local/` (moved by hand to share); temp copy in `statelens/extract/` (git-ignored) |
| bug report (KB finding), private advisory or issue | stays where it lives (`STATELENS_KB`, R-KB-6) | card in `target-states.local/<sub>/` |
| paper, design document | URL or path; paper text cached in `statelens/extract/papers/` | card committed, or `.local` when private |

**D61 Runtime read side** (template `statelens/runtime/statelens.rs`, new SPEC 9.6, App A). A
per-input, ordered trace of guarded probe hits, off by default:
`pub struct Seen { label, site, me: Option<u32>, a, b, seq, run }` where `site` is the call site
(`concat!(file!(), ":", line!(), ":", column!())`, a `&'static str`, so repeated labels and repeated
invariant ids stay distinguishable) and `run` numbers the runtime instance within the input. The
fresh-run hook becomes `fresh_run()`: forget ghost state, then `RUN += 1`; `reset()` sets `RUN = 0`
and registers the hook, so the first runtime of every input has `run = 1` in replays and in fuzzing
alike. A checkpoint resume (`Runner::from(Checkpoint)` skips the hook) and every engine restart
inside one runtime are incarnation boundaries the scaffold marks through the helper's
`restart(replicas) -> u64`; in Shape A a base that restarts replicas gets a marked hook (edit
contract); a relation across a boundary is accepted only if the card names both incarnations, and
without marks every cross-stage relation on a restarted replica is `unverifiable (incarnations
unmarked)`. `Seen` is `#[non_exhaustive]` with no public constructor. API: `watch()`, `unwatch()`,
`mark() -> u64`, `seen(label, site, since, f) -> Option<Seen>` (earliest match at or after `since`,
in the current `run` unless asked otherwise; `site` optional, found at runtime with `sites(label)`,
never a hard-coded literal, because synthesis edits move lines), `observations(since)`,
`TRACE_CAP = 1 << 20` (a stage evaluated past an overflow is `unverifiable (trace truncated)`), hidden
`note()`. `sl_probe!`/`sl_implies!` call `note` after `record`, inside the guard (Byzantine replicas
are never observed; reach replays run with `STATELENS_BYZANTINE` unset). `reset()` clears the
trace; the fresh-run hook does not. Not watching costs one TLS check per hit; no I/O, locks or
awaits (R-INS-3). Instrumentation never calls it (prompt 13.7 line; guard 3). Placed before the
`// [statelens] consensus only:` cut; no `simplex::` paths in doc comments (qmdb copy test).

**D62 Synthesis step.** `just synthesize [--profile simplex|marshal] [--match GLOB]... [--redo]`
on a checkout a campaign of the same profile instrumented: `meta.json` names the profile, `base`
== HEAD, no `FALSE-` ids, `summary.txt` READY or PANIC (tests), runtime contains `pub fn watch(`,
`plan.md` exists. Never instruments (no probes, assertions or ghost state); edits follow the edit
contract (R-TS-SYN-3, guards 1-6). Phase 2 permissions (D4); qmdb refused. A second agent role with
its own scope (amends R-INS-7). Pairs (card, base) run sequentially (one crate); each pair's diff
is saved to `campaign/reach/TS-NNNN_<base>.diff`.

**D63 Scaffolds are written, not derived** (exception to D5, D24, D57, B.1, G4/G7, marshal
non-goal PRD:95). Per pair (card, base), one scaffold per selected base, the agent choosing no base
(Pair synthesis, below): module `<pkg>/src/target_states/tsNNNN_<base>.rs`; `target_states/mod.rs` =
helper template `statelens/runtime/target_states.rs` + `pub mod` lines (script-owned); one anchored
line in `<pkg>/src/lib.rs` (simplex after `pub mod state_cov;`, marshal after `pub mod scenarios;`
under `#[cfg(feature = "mocks")]`, verified); thin target `fuzz_targets/<base>_tsNNNN_statelens.rs`
(new App B.6: `reset(); tsNNNN_<base>::fuzz::<..>(input); clear_compromised();`, base's closure
type);
`[[bin]]` = base's block renamed (`variant_bin_block` + `name=`). A child module of the crate root
sees the private drivers (`run_standard_once` etc.); anything else is exposed under the edit
contract. Mallory (`fuzz_mutator!`) bases excluded. D15 cert_mock checks and the guard rule apply.
Naming keeps the `<profile>_` prefix and `_statelens` suffix, so `just run`, the 7.1 refusal glob,
`clean` and `select_targets` keep working.

**D64 Knobs.** The first K <= 16 bytes of the base input's own `raw_bytes`, zero-padded; the rest
stays (non-empty if it was). Knob = `domain[byte % len]`, `domain[0]` = source value, so the empty
input is the canonical input (the source history). Fields History fixes are pinned; dependent
fields reset as the base decoder would. Same input type, recipe, flags; no corpus.

**D65 Stages and witnesses.** One stage per History event, named by event number. The scaffold
binds the card's entities to concrete values (the views, payloads and replicas it chose or
observed) and records, per stage, one witness that establishes the whole `Check`/`Holds` line,
including its relations to earlier events. Witness kinds:
- `exact`: a harness observable keyed by the bound entities (reporter maps keyed by view/digest,
  resolver and buffer recorders, fuzz-package recording wrappers, network intercept records, a
  side-effect-free local query); a query that subscribes, hints, fetches or verifies is not a
  witness (it would create or satisfy the state it checks). An exact observable establishes an
  order only if each entry carries the trace seq at which it was recorded (recording wrappers call
  `mark()`); a map read after the run establishes presence only;
- `intrinsic`: one probe observation at a site whose `a` and `b` are computed from one receiver. It
  binds the replica (`me`) and the relation among that object's fields at that instant, and no view,
  digest or other identity, so it witnesses only a line whose non-replica entities are all
  existential. Example from the retained simplex campaign: at `voter.round.set_certify_handle`,
  decision code 1 (Nullify, set by the replica's own `construct_nullify` or a replayed nullify)
  witnesses "R queued certification for some view in which R had already built or restored its own
  nullify vote"; it witnesses neither a nullification certificate nor the v of an earlier event,
  and a nullification observed at one site followed by a certification observed at another
  witnesses nothing;
- `construction`: a harness action the scaffold performed itself and that cannot fail silently (a
  pinned elector, a certificate it built); only for events whose actor is `harness`, never for En.
A probe observation whose subject is not fixed by its own site is not a witness. A stage whose
entities or relations no available witness binds is `unverifiable` (not a miss).

Witness records make this checkable. A stage is held only through the helper `held(k, witness)`,
which prints the record; the scaffold never prints `[statelens-reach]` itself (veto on the literal
outside `target_states/mod.rs`), and guard 3 keeps `statelens.rs` byte-identical to its state when
synthesis started. Each record carries `bind=` (every entity of the line with its value and the
stage that bound it, e.g. `R=2@E1 v=5@E1`), and for a probe witness `obs=<run>:<seq>:<me>:<label>@
<site>:<a>:<b>`, for an exact witness the observable, its key, the value read and the read mark,
for a construction witness the action. The script recomputes, and downgrades a held stage to
`unverifiable` with `witness rejected: <rule>` when: an `as Ek` entity's value differs from the
value bound at Ek; the line's entity list is not covered by `bind=`; seq or mark order contradicts
the History or `Order:`; `run` differs from E1's without a marked boundary; `me` is not the bound
replica; an intrinsic witness cites more than one observation or binds a non-existential,
non-replica entity; a construction witness is used for En or for an event whose actor is not
`harness`. A held stage adds
the feature `(site_hash("TS-NNNN"), k, 0)` via the existing pub `record`. The first miss closes the
scripted prefix; the input continues into the base's free-running phase and every oracle
(decision 4).

Handoff and recovery are separate. Shape B: `set_compromised` first; drive E1..E(n-1) online with
polling in simulated time, each stage with a simulated-time deadline (passing it is a miss, never
a wait; every await on a SUT reply is raced against it; no unwrap/expect on SUT replies, the helper
turns a dropped reply into a miss); then the handoff check: En's `Holds:` is witnessed in a window
that ends at the handoff instant, and for a state defined by pending work or a withheld delivery an
`exact` observable shows the operation still pending at that instant (scenario-SPEC S3: the
defining state is present at handoff); then handoff: the continuation starts with every fault the
prefix opened still in place (a crashed replica down, a partition, a held message). Recovery is
part of the continuation and never precedes handoff: every fault the prefix opened is released no
later than the base's first heal (GST), and the base's liveness measurement starts after both.
Network cuts go through the base's own fault input (pinned partition fields, so the base installs
and heals them) or are composed with the base's current cut; the scaffold never heals the network
on its own. Crashed replicas and withheld messages are released at handoff + d, with d a knob in
[0, base fault phase) (marshal scenario runner 12 s, core `FAULT_PHASE` 30 s); a base with no GST
releases before its liveness wait starts. The runtime deadline is the base's
`fuzz_runtime_timeout(..)` plus the stage deadlines plus the largest release delay. If En does not
hold at handoff, En is missed (even if it held earlier) and the continuation still runs. A marshal
prefix that leaves too little height headroom before the epoch ceiling is annotated `liveness
unmeasurable`. Shape A: no scaffold-imposed cleanup; the base's own schedule runs; the implicit
handoff is En's witness, which counts only if the trace has a later guarded observation of an
honest replica in the same `run` (otherwise En is `unverifiable (no continuation)`).
Oracles are never removed or weakened; progress targets are re-based on the handoff. No
fabrication (scenario SPEC I5: votes only on the signer's channel; injections listed in the module
header with the INV ids whose ghost history they bypass). A missing capability is reported as
`cannot: <capability>` and `//! Missing:`, never approximated.

**D66 Reach check (replays, not fuzzing; carve-out from D23, R-P3-1, PRD non-goal
"Automating Phase 3").** The built binary runs one empty file in individual-file mode from
`campaign/reach/TS-NNNN/` with `STATELENS_REACH=1` (no corpus, no flags), printing
`[statelens-reach] TS-NNNN E3/7 held|missed|unverifiable|withheld <witness record>`,
`handoff holds|lost`, the trace after a miss (<= 64 lines, with sites), `reach k/n control=c`,
`done`. Plus one control run and a final canonical rerun for determinism. The control: the module
header names the withheld event Ek (a `harness` action, k < n); `STATELENS_REACH_CONTROL=1` is read
only through the helper's `control()`; the control run prints its own stage lines with Ek
`withheld`. It is vacuous when a stage before Ek misses or binds different values than the
canonical run. `Control: n/a` is allowed only when every witness is `exact` or `construction`.
Verdicts:
- REACHED n/n: every stage held and no witness rejected, En holds at handoff, and the control is
  non-vacuous and misses En for the bound entities (or is `n/a` as allowed above);
- UNVERIFIED k/n: no stage missed, but a stage is `unverifiable` or a witness was rejected; or the
  control is vacuous; or the control reaches En for the bound entities (`weak`); or `n/a` is
  declared with a probe witness;
- PARTIAL k/n (first miss at stage k+1), UNREACHED 0/n, NO REPORT;
- CRASH (finding candidate), with the phase (prefix, continuation) and the location as context;
- SCAFFOLD ERROR (an explicitly identified scaffold error, below);
- NOT BUILT, GATE FAILED.
Crash attribution: every failure in a replay, in any phase (panic, `[statelens][INV-...]` or
`[statelens][BYZANTINE]` message, harness oracle failure, sanitizer report, oom, leak, runtime
timeout or stall, wall-clock timeout), is preserved (crash file, log, replay line and the scaffold
version, in `campaign/reach/TS-NNNN/attempt-<a>/`) and is a finding candidate. Where it happened is
diagnostic context only: the report gives the panic location (libfuzzer-sys chains the default
hook, which prints `panicked at <file>:<line>:<col>`; `violation()` is `#[track_caller]`, so
invariant panics name the SUT line) or the first non-std frame of a sanitizer stack, and whether
that line belongs to the card's diff, but a line the diff added or moved does not make the failure
the scaffold's (a restructured production assertion, or an accessor that exposes earlier
corruption, fails for the SUT's reasons). The only failure attributed to the scaffold is one the
helper raises itself with `[statelens-scaffold] <reason>`, and the helper raises it only for
conditions that depend on the scaffold's own code and knob bytes, never on SUT output: helper API
misuse (a stage held twice or out of order, an unknown event number, a mark used after
`unwatch`), an empty or inconsistent knob domain, a stage-deadline budget that exceeds the runtime
deadline (checked before any engine starts). Scaffold code never panics otherwise: no
unwrap/expect/index panics on SUT data (a miss instead), and a `[statelens-scaffold]` literal outside
`target_states/mod.rs` is vetoed. Such a failure is SCAFFOLD ERROR. The helper's chained panic
hook prints the stage lines evaluated over the trace so far and the phase before libFuzzer aborts,
so a crash in either shape reports its stages. The replay's own timeout exceeds libFuzzer's default
`-timeout` (1200 s); a kill by it is classed `timeout`. Annotations: `nondeterministic`, unbound
labels, missing capabilities, `unmarked edit`, `liveness unmeasurable`, `location in TS-NNNN diff`.
Vetoes (build-blocking): scope, thin-target shape, cert_mock, guard, edit-contract guards 1-3.

**D67 Refinement.** Up to 3 further agent attempts per card (`REPAIR_ATTEMPTS`) with feedback
modeled on SyzHarness's hierarchy, made semantic: E1 miss -> setup/base/shape; middle Ek miss ->
event content/recipient/order (compare trace a/b and sites with expected); En miss or `handoff
lost` -> knob domains, timing, what keeps the state pending; `unverifiable` or `witness rejected`
-> a witness that binds the relation (an intrinsic site for an existential line, otherwise an
exact observable keyed by the bound entities, with seq stamps when order matters); `weak` with
bound witnesses -> withhold the event whose absence prevents En for these entities, or report that
the History is not causal; vacuous control -> withhold a later harness action; SCAFFOLD ERROR ->
the named reason. Automatic repair covers only these explicitly identified scaffold errors and
the non-crash outcomes above (build, veto, NO REPORT, misses, unverifiable). Any CRASH (finding
candidate) stops refinement for that card: that version is kept and built for fuzzing (the console
says it crashes on its canonical input, so `just run` reproduces it at once), never replaced by
one that avoids the failure, and humans triage it; if triage shows a scaffold fault, the operator
reruns that card with `--redo`. Otherwise the best built version (REACHED > UNVERIFIED > PARTIAL >
UNREACHED > NO REPORT > SCAFFOLD ERROR; then most stages held; then later) is kept and rebuilt;
none built -> files restored, NOT BUILT. `--redo` moves
`reach/TS-NNNN/` to `reach/TS-NNNN.<stamp>/`, so preserved crashes are never deleted. Not PRD:83's iterative state discovery (no frontier). Outputs in
git-ignored `campaign/`: `reach/TS-NNNN.md` (verdict, per-stage witness kind and detail, handoff,
attempts, crash attribution, labels and sites read, run/replay lines), `reach/TS-NNNN.diff`,
prompts and logs.

**D68 `just fuzz <simplex|marshal> --state-reaching`.** Campaign (unless `--skip-campaign`) ->
`synthesize` -> fuzz the scaffolds only, through the existing sequential/`--parallel`/`--tmux`
branches (session `statelens-<profile>-reach`). `--state-targets` selects card ids (`TS-0003`)
and `--fuzz-targets` candidate bases, by variant or scaffold name; both repeatable, both
forwarded as `--match`, a pattern of the other flag's form refused, `--state-targets` only with
`--state-reaching`; one scaffold per selected card and base, every candidate base without
`--fuzz-targets`. Unknown `--x` flags are refused (today
`--state-reaching` falls to `*) break` at justfile:63 and leaks to libFuzzer). A single target
or qmdb with `--state-reaching` is refused. Example: `just fuzz simplex --parallel --tmux
--state-reaching --state-targets TS-0004 --fuzz-targets "simplex_cert_*"` -> campaign, synthesis
of TS-0004 on each `simplex_cert_*` base, one tmux window per scaffold running
`just run <scaffold>` with no added arguments.

Initial cards (stage 2): TS-0001 hand-written from PR #4317 (marshal, merged 85f85284d7; the
worked example in SPEC 18.3, rewritten with entities, relations and a `Holds:` line), TS-0002
`test consensus/src/marshal/standard/mod.rs:7027`, TS-0003 `test consensus/src/simplex/mod.rs:3260`
(`all_crash_after_nullify`), TS-0004 `text` simplex smoke card (R votes nullify in v; a
notarization for v reaches R; R dispatches certification for the same v; expected REACHED with an
`exact` En witness: a fuzz-package recording wrapper around R's automaton, certify requests keyed
by round and seq-stamped, read with R's reporter `nullifies[v]`; an intrinsic observation at
`voter.round.set_certify_handle`, if the campaign has that beacon, is reported as corroboration
only).

## Stage 1: document changes (this task's first deliverable)

Edit only `statelens/docs/PRD.md` and `statelens/docs/SPEC.md`. Follow their conventions:
present-tense, `R-<AREA>-n` paragraphs, `AC-n`, ASCII only, cross-refs in parentheses.

### PRD.md
- New `## 11. Target-State Synthesis` after 10.6 (old 11 Risks -> 12, old 12 Specification -> 13;
  nothing cites them by number): 11.1 Overview; 11.2 Background (random sampling, static marshal
  scenarios as precedent, SyzHarness mapping table, why probes); 11.3 Requirements in groups:
  Registry R-TS-REG-1..4, Phase 1 R-TS-P1-1..3, Synthesis R-TS-SYN-1..7 (R-TS-SYN-3 = the edit
  contract), Scaffold R-TS-SC-1..7 (incl. witnesses, handoff and recovery), Feedback R-TS-FB-1..2,
  Phase 3 R-TS-P3-1..2, Non-functional R-TS-NF-1..3; 11.4 Fuzz harness (ASCII flows for Shape A
  and B showing handoff before recovery, table of initial cards); 11.5 Acceptance criteria
  AC-22..AC-28 (registry+extraction; read side; simplex synthesis; marshal synthesis; stage
  semantics incl. witness kinds, handoff, determinism, control and crash attribution; recipe incl.
  the user's exact command and refusals; clean and guard); 11.6 Risks.
- Amend: header (Reference row SyzHarness arXiv 2609.23889); 1 Summary; 2.2 (item 4); 3.1 (G11
  registry+extraction, G12 witnessed state-reaching targets); 3.2 non-goals at L81, L83, L85, L87,
  L89, L95 plus new non-goals (synthesis adding probes, assertions or ghost state, or changing what
  the protocol does; archiving raw source inputs; gating fuzzing on a verdict; qmdb target states;
  an LLM in the fuzz loop); 4 Roles (synthesizer); 5 Terminology (Target state, Card, History,
  Entity, Knob, Scaffold, Shape A/B, Base target, Stage, Witness and its kinds, Canonical input,
  Handoff, Recovery, Control run, Reach verdict, Finding candidate, Edit contract; Source kind adds
  `test`/`text`; StateLens variant notes scaffolds are written); 6.1/6.2 diagram; 7.1 layout;
  R-REG-2 (add `kb` - existing defect); R-P1-3; R-P2-1; R-P2-4 (applies to scaffolds, precedes
  R-TS-SYN-6); R-P2-5 (new recipes, `--state-reaching`, `--fuzz-targets` and `--state-targets`,
  unknown flags refused, `--tmux` implies `--parallel` - existing defect); R-P3-1 (reach replays
  carve-out); R-P3-2 (a replay failure is a finding candidate); R-P3-4; R-INS-3; R-INS-5; R-INS-7
  (synthesizer scope, R-TS-SYN-3); R-FB-1;
  R-OR-1 (stage checks and verdicts are not oracles); R-ART-2; R-AG-3; R-NF-1 (synthesis edits
  included); R-NF-3 (baseline = base's variant); Risks (new rows; fix stale semantic-search row);
  Specification ("SPEC chapter 18", "AC-1 to AC-28").
- Fix the stale cross-references in sections being edited (L395 7.7->7.6, L397 7.11->7.10, L409,
  L479, missing `---` before ch.8).

### SPEC.md
- New chapter 18 after 17.6, before Appendix A: 18.1 What was verified (visibility facts, input
  types pass the empty input, anchors, ignored dirs, libFuzzer abort hook); 18.2 Decisions
  D59-D68 (note at SPEC:169-170); 18.3 Registry, lint rules 12-13, `templates/target-state.md`
  verbatim, TS-0001 example; 18.4 Phase 1 deltas; 18.5 Read side (-> 9.6); 18.6 Synthesis (18.6.1
  edit contract and guards 1-6; preconditions, selection/skip/`--redo`, snapshots and restore,
  per-card loop, build, test-gate rerun, best version, outputs, console, exit codes 0/1/2/3,
  clean); 18.7 Scaffold contract (common rules, witness kinds and binding, handoff and recovery,
  Shape A/B, simplex and marshal parts, B.6); 18.8 Reach check (inputs, line format and regex,
  verdicts, crash attribution, annotations, feedback table); 18.9 Running (`--state-reaching`,
  `targets --state-reaching`, replay with `STATELENS_REACH=1`, coverage); 18.10 Acceptance
  procedures AC-22..AC-28; 18.11 Known limitations (coarse probes bind few identities, so many
  stages need exact observables or end `unverifiable`; Shape A crashes give no stage lines).
- Amend: 1.2 pointer; 2 (D14 row note; pointer note); 3 layout (`target-states/`,
  `target-states.local/` + `.gitignore`, `templates/target-state.md`, `runtime/target_states.rs`,
  4 new prompts, `synthesize` in scripts line); 4.1/4.6 (TS counter, rules 12-13); 5.1 (env-only
  `STATELENS_REACH`, `STATELENS_REACH_CONTROL`; no config keys); 5.3 justfile (described in stage
  1, verbatim synced in stage 2); 5.4 (`extract --states`, `targets --state-reaching`,
  `synthesize`, `coverage`, `clean` scope incl. fuzz `src/` dirs; fix `--stop-after` to list
  `index`); 5.5 (`PROFILES[...]["scaffold"]`); 5.9 (new test classes); 6.1; 7.1 (refusal covers
  `<pkg>/src/target_states/`; read-API scan); 9.2, 9.5, new 9.6 (incl. `site`, `run`); 12
  (synthesizer = Phase 2 invocation); 13.7 (one line); 14, 15, 16 pointers; App B.1/B.2 + new
  B.6; App D README outline; new App H (`runtime/target_states.rs`).
- Verbatim blocks for files that do not exist yet (prompts 13.20-13.23 `state-analyst.md`,
  `synthesize.md`, `subsystems/{simplex,marshal}-synthesize.md`; App A runtime; App H; 5.3
  justfile; 5.1 config) are added in stage 2 as each file lands, so `just check-prompts` stays green
  after stage 1. Stage 1 specifies their content and behavior in chapter 18.

## Stage 2: implementation order (after the docs are approved)

1. Runtime read side in `statelens/runtime/statelens.rs` (`#[non_exhaustive] Seen` with `site`
   and `run`, `fresh_run()` hook with the run counter, `reset()` zeroing it, `seen` with site and
   run filters, `sites(label)`) + self-tests (no `reset()` in them) + `check_scope` scan + 13.7
   line; sync App A, 9.6, test counts.
2. Registry in `statelens/scripts/statelens.py` (`FILE_NAMES`, per-prefix sections, rules 12-13
   with actors, `Check`/`Holds` entity lists and `as Ek` references, `SOURCE_KINDS`, `next_id`),
   `templates/target-state.md`, `.gitkeep`s, `.gitignore`; commit TS-0001.
3. Extraction (`--states` mode record over `cmd_extract`, `test`/`text`, `--local` and routing by
   disclosure, `kb` finding ids, the worktree check allowing `target-states/` and
   `target-states.local/`), `prompts/state-analyst.md` (entities and relations in every Check),
   `extract-states` recipe; extract and review TS-0002..0004 (TS-0004, from `text`, is moved
   from `.local` by hand).
4. Helper template `statelens/runtime/target_states.rs` (Knobs, Stages, `held(k, witness)` and
   witness records, `restart()`, handoff check, recovery scheduling, `control()`, the
   `[statelens-scaffold]` checks on scaffold-only conditions, chained panic hook, reach lines);
   compile it in a scratch checkout of both packages. The script side of step
   6 recomputes every witness rejection rule from the records.
5. Script plumbing: `PROFILES["scaffold"]`, `select_scaffolds`, `targets --state-reaching`,
   coverage `known`, clean scope, 7.1 refusal, `variant_bin_block(name=)`, `run_logged` timeout.
6. `synthesize`: preconditions, anchor, `mod.rs`, snapshots/try-finally, per-pair loop (one
   transaction per card and base), edit contract guards 1-6, manifest, build, reach check, verdicts
   and crash attribution (preserve every failure), refinement stop on finding candidates, best
   version, test-gate rerun, per-pair diff, reports.
7. Prompts `synthesize.md` (quotes R-TS-SYN-3; witness, handoff and recovery rules),
   `subsystems/{simplex,marshal}-synthesize.md`; add 13.20-13.23 blocks.
8. justfile: recipes, `--state-reaching`, `--state-targets` and `--fuzz-targets`, unknown-flag
   refusal, session name; sync SPEC 5.3.
9. README (App D), including copying `target-states.local/` and `invariants.local/` into the
   campaign clone.
10. Acceptance AC-22..AC-28 on fresh clones / scratch worktrees (campaigns run Phase 2 agents with
    full permissions).
Reuse throughout: `compose`/`render`, `agent_command`, `run_logged`, `worktree_state`,
`find_anchor`/`insert_lines`, `variant_bin_block`/`bin_blocks`, `check_simplex_cert_mock`/
`check_marshal_cert_mock`, `select_targets`, `first_panic`, `coverage_binary`, marshal
`FuzzScenarioStandardHarness`/`ScenarioHandoff`/`finish`/journal seeding, simplex runners and
reporters, chaos-twins gate pattern.

## Verification

Stage 1 (docs):
- `cd statelens && just check-prompts && just check-invariants` (both unchanged, must pass).
- ASCII: `LC_ALL=C grep -nP '[^\x00-\x7F]' statelens/docs/PRD.md statelens/docs/SPEC.md` is empty.
- Consistency greps: every `R-TS-*`, `D59`-`D68`, `AC-22`-`AC-28` defined once and every reference
  resolves; chapter renumbering leaves no stale "chapter 11/12" or "AC-1 to AC-20"; no text outside
  R-TS-SYN-3 restates allowed edits.
- An adversarial review pass (subagents) of the edited PRD/SPEC against this plan and the binding
  decisions; findings fixed before hand-back.

Stage 2 (code), per step: `just check-scripts`; runtime self-tests through
`just campaign --stop-after materialize` plus the gate filter in a scratch `git worktree`;
stub-agent synthesis runs (stub `claude` on PATH) for each edit-contract guard (an edit outside
scope: exit 2 and restore; a manifest dependency: restored; an added `sl_probe!`: vetoed; a marked
SUT accessor: gate reruns, GATE FAILED restores it; an unmarked hunk: annotated), for NOT BUILT and
exit codes, and for verdicts (one stub per witness rejection rule - an `as Ek` value mismatch, an
uncovered entity, an order contradiction, a foreign `run`, a wrong `me`, a two-observation
intrinsic witness, a construction witness for En - each expecting UNVERIFIED with `witness
rejected`; a vacuous control and a `weak` control: UNVERIFIED; `n/a` with a probe witness:
UNVERIFIED; a scaffold printing `[statelens-reach]` itself: vetoed;
a scaffold panicking with an INV message in its prefix: CRASH (finding candidate), refinement
stops, crash file preserved; a panic on a line the card's diff added or moved: CRASH (finding
candidate) with `location in TS-NNNN diff`, refinement stops; a sanitizer report in an added
accessor: the same; a helper `[statelens-scaffold]` error for a stage held twice: SCAFFOLD ERROR,
refined; a scaffold printing `[statelens-scaffold]` itself: vetoed); then real
acceptance: simplex campaign + `just fuzz simplex --tmux --state-reaching --state-targets TS-0004
--fuzz-targets "simplex_cert_*" --skip-campaign` (AC-24, 26, 27), marshal campaign with
TS-0001/TS-0002 (AC-25, including a pending-state handoff check), AC-22, AC-23, AC-28.

## Revisions made while writing stage 1

The adversarial review of the written PRD/SPEC tightened these points; the documents follow them
and they override the text above where they differ. Status after the user's review of 2026-10-07:
1. CONFIRMED. Scaffold errors are only the helper's pre-engine checks (more than 16 knobs, an empty
   or single-value knob domain, a stage-deadline budget over the runtime deadline), with the panic
   location inside `target_states/mod.rs`. Helper misuse after engines start (a stage held twice,
   out of order, unknown event number) has no effect, because the SUT can drive it. AC-26's
   SCAFFOLD ERROR stub is an empty knob domain.
2. CONFIRMED. The helper decides `handoff holds|lost`. The essential check is a fresh,
   uninterrupted read of En's witness at the handoff (the helper takes the read and the handoff
   mark in one call, with no await between); in addition, no probe observation may lie between
   `read=` and `mark=`. The script rechecks both. Nothing in the prefix may complete or cancel the
   pending work before the handoff.
3. REVISED (event sequence). Order needs positions: a stage that History or `Order:` requires to
   follow an earlier one must carry a position; presence-only evidence makes it `unverifiable (no
   position)`. Positions come from ONE per-input event sequence: every guarded probe observation
   and every helper event (exact read, exact entry recorded by a recording wrapper, construction
   action, restart boundary, handoff mark) advances it, through `tick()` in the read side, so
   positions are unique and strictly ordered and two harness actions with no probe between them
   are still ordered; order checks are strict. `tick()` is callable only from `target_states/`
   (guard 3 bans it elsewhere). TS-0004 uses seq-stamped evidence for R's nullify vote too.
   Construction witnesses: only for events whose actor is `harness`, never En, and they prove
   only the harness action; the action takes its own tick.
4. REVISED (unique incarnations). `restart()` takes a tick s and the incarnation it begins is
   `inc<s>`, unique even for back-to-back restarts with no probe between them. The scaffold marks
   every restart it drives and adds a marked hook to a Shape A base that restarts replicas
   (prompt rule); a relation across a marked restart must name the incarnation; an unmarked
   restart cannot be detected by the script (annotation `relation across restart`; known
   limitation). The subsystem rules name the known restart sites (simplex
   `chaos::runner::restart_durable`, `chaos::twins::restart_honest`; marshal `StoreOp::Restart`)
   as guidance. Acceptance adds ordered actions and repeated restarts with no intervening probes.
5. CONFIRMED. Control run: a miss does not end the control prefix; vacuous when the withheld Ek
   is not a `harness` event before En, there is no `withheld` line, or En has no line;
   `Control: n/a` only for a card with no `harness` event before En and only exact/construction
   witnesses; a missing `Control:` line is `control missing` (UNVERIFIED).
6. REVISED (immutable baseline). Guards 1-3 are evaluated on the cumulative difference between
   the tree and an immutable baseline B taken once when `synthesize` starts (never against the
   per-attempt snapshot): after every attempt, on the kept version before it is built for
   fuzzing, and over the whole tree when synthesis finishes. A guard-3 violation therefore vetoes
   every later attempt that still contains it; only versions that pass against B can be kept;
   a failing final check restores the card to S0 (NOT BUILT). Guard contents: guard 1 exempts
   `Cargo.lock`; guard 2 covers `Cargo.lock`, compares script-owned files with what the script
   wrote, and a violating version is not built; guard 3 also bans runtime write calls
   (`with_ghost`, `with_global`, `record`, `note`, `tick`, `violation`, `reset`,
   `clear_compromised`) outside `target_states/` and under the profile roots, and compares
   `sl_*` calls per file as a multiset; guard 5 counts only a test that passed in the campaign's
   own gate; guard 6 and `just clean` restore the whole fuzz packages except their git-ignored
   `corpus/`, `artifacts/`, `coverage/`. Acceptance adds a two-attempt case whose second attempt
   leaves the rejected edit untouched (vetoed again, NOT BUILT, assertion restored).
7. CONFIRMED. The synthesizer agent builds but never runs its scaffold or the fuzzer; files that
   appear during an attempt are moved to `attempt-<a>/swept/`, never deleted, and a
   crash/oom/timeout/leak file among them is a finding candidate. A GATE FAILED card whose kept
   version crashed still reports that finding candidate.
Details settled in the documents (second review round, 2026-10-07):
- Baseline B is taken once per campaign (first synthesis after a campaign), stored in
  `campaign/reach/baseline/` with what the script last wrote to its own files, and reused by every
  later synthesis and `--redo`; every run checks guards 1-3 against it before any card (exit 2 on
  a breach, e.g. one a killed run left behind); an interrupted card restores its S0; the final
  check reverse-applies card diffs in reverse order and writes untouched failing files back from B.
- Guard 3 also requires every non-blank line `campaign/instrumentation.diff` added to still be in
  its file (per-file multiset), so ghost updates, `// [statelens]` fields and the fuzz-package
  runner hooks cannot be removed; the runtime module declaration and its attributes stay as in B,
  with no `#[path]` added; no added `set_compromised` outside `target_states/`; the thin-target
  exemption covers every scaffold thin target of the exact B.6 shape. Guard 5 also counts a gate
  test that no longer runs.
- Positions: both stages of an ordered pair need a position (presence-only evidence on either side
  is `unverifiable (no position)`). Exact-entry positions come only from the helper's
  `stamp(observable, key, value)`, which ticks and prints an `entry` line the script matches;
  `tick()` is callable only from `target_states/mod.rs`. Construction witnesses come only from
  `Witness::act(bind, action, perform)` (tick taken right before the action; in Shape A only for
  actions before the base entry). The incarnation rule is per replica. `held` moves `since()` to
  the stage's position + 1. `reset()` calls a private `clear_trace()`, which the self-tests use.

8. PENDING. Shape A crash lines: stages the panic hook cannot evaluate print `unverifiable
   (crashed)`; the phase of a non-panic failure in Shape A may be unknown (known limitation).

## Implementation review fixes (2026-10-07)

A review of the uncommitted implementation found four high findings; each is fixed, with a
regression test, and the PRD and SPEC follow the fixes.
1. Truncated traces. `truncated()` now returns the position of the first observation the trace
   dropped at `TRACE_CAP` (`Option<u64>`; `watch`, `unwatch` and `clear_trace` reset it). The
   helper prints `truncated seq=<s>` once; a stage whose witness is read at or after `s`, and En
   when `s` is at or before the handoff mark, is `unverifiable (trace truncated)` with no feature,
   and the handoff is lost. The script parses the line (`REACH_LINE` gains
   `|truncated seq=(\d+)`) and downgrades a held line with `read=` >= `s`, and En under
   `handoff holds` with `mark=` >= `s`, so such a replay is never REACHED. Helper self-tests in
   `imp::tests`; a runtime-to-parser regression replays captured lines (PRD R-TS-SC-3, R-TS-FB-1;
   SPEC 9.6, 18.7, 18.8, AC-23, AC-26, 18.11).
2. Test gate fails closed. Every nextest command forces its rendering (`--color never
   --message-format human --status-level pass --final-status-level fail --success-output never
   --failure-output immediate`), and `nextest_run` validates a run against nextest's own summary
   line and the exit code. The baseline keeps a validated test inventory,
   `campaign/reach/baseline/tests.json`, from the campaign's `test.log` or one gate run on the
   tree as the campaign left it (exit 2 when neither validates). Guard 5 fails on unusable output,
   on a build failure and on any failing or vanished test the inventory does not record as
   failing (PRD R-TS-SYN-3 guard 5; SPEC 7.7, 8.3, 17.3, 18.6.1 guard 5, 18.6.2, AC-24).
3. Interrupts keep failures. A built version is kept (`version.diff` and `version/`, a copy of
   every file it created or changed) before its first replay, and a stray failure's version right
   after the sweep. On an interrupt or any other error, synthesis first preserves the attempt
   (sweep, stray version, `attempt-<a>/interrupted.txt` with the step and each finished replay's
   exit code and `run`/`replay` lines), then restores S0 (PRD R-TS-SYN-3 guard 6, R-TS-SYN-6;
   SPEC 18.6.1 guard 6, 18.6.2 Per card, step 2.7 and Outputs, 18.8, AC-26).
4. Revalidation of earlier cards. A kept version that changes a file other than its module, thin
   target, the manifest and `Cargo.lock` rebuilds and replays every other kept scaffold in
   `TS-MMMM/after-TS-NNNN/`; the first that no longer builds, stands worse than its report or
   gains or loses a crash rolls the card back to `NOT BUILT (breaks TS-MMMM)`, otherwise the
   earlier reports take their new verdicts. The last check also builds every scaffold, exit 2 on
   a failure (PRD R-TS-SYN-1, R-TS-SYN-6; SPEC 18.6.2 Finish, Last check, Exit codes, Outputs,
   18.8, AC-24, 18.11).
Not changed: README (its NOT BUILT row and exit code 2 could name the revalidation and the last
check's build) and `prompts/synthesize.md`, which could tell the agent that breaking another
card's scaffold restores its own edits.

## Medium findings triage (2026-10-08)

The review's medium findings 5 to 20 and three defects of the E2E smoke run (E1 to E3) were
checked against the tree after the high fixes, then fixed with a regression test each where code
changed; the PRD, the SPEC (section 5.3 and Appendix H resynced, prompt copies refreshed with
`just check-prompts --write`, the 18.3 example synced with TS-0001) and README follow.

| Finding | Verdict | What was wrong (or why not) | Fix |
|---|---|---|---|
| 5 | Valid | `Stages::unverifiable(n, ..)` recorded nothing for `En`, so the handoff made it `missed not held at handoff`: PARTIAL, the reason lost, the wrong feedback row. | `unverifiable` records stage n (`last = true`); called before `Stages::handoff`, which then calls no `read` and prints `handoff lost`; the script already gives UNVERIFIED. Helper self-test; SPEC 18.7, AC-23, Appendix H; prompt. |
| 6 | Valid | `control_status` ignored the control replay's `reach`, `done` and parser problems, so a control that returned before the oracles, the only replay of the lost-handoff path, still certified REACHED. SPEC 18.8 had the same gap. | An incomplete control (no `reach` or `done` line, lines of another card or `n`) is vacuous; the control feedback asks to drive the base's oracles too. Tests; SPEC 18.7, 18.8, PRD R-TS-SYN-5, prompt. |
| 7 | Valid | The incarnation rule was skipped for a held record without a position, so `inc99` with no `restart` line gave REACHED 1/1. | Such a record still gets the existence check, `witness rejected: incarnation`. Test; SPEC 18.7 rule clarified. |
| 8 | Partly valid | The log-truncation trigger was fixed by high fix 2 (`tests.json`), and `written/` and `state.json` are rewritten on every script write. Still valid: B's copies, `tests.json` (and the `test.log` fallback) and `instrumentation.diff` that an agent rewrote were trusted by the next synthesis, which failed closed or let guards 3 and 5 pass a matching edit. | `Synthesis.seal()`, in a `finally` after every agent run and when the synthesis ends (the agent's scaffolds run in the replays and the gate after its last run), writes back B's files, `written/`, `tests.json` and `instrumentation.diff` with a warning, and `state.json`; a baseline without `tests.json` exits 2. Tests; SPEC 18.6.1, 18.6.2, 18.11, PRD R-TS-SYN-3, README. |
| 9 | Already fixed | High fix 3 keeps a stray failure's version right after the sweep, before guard 2 restores the script's files; the reviewer's fixture passes. | None in code; PRD R-TS-SYN-7 now lists that version among the outputs. |
| 10 | Valid | `--redo`, and the move of an attempt directory left without a report, renamed the outputs but not the paths in the report, `replay.txt` and `interrupted.txt`, which then named missing files or the replacement's. | `Synthesis.archive` moves and rewrites `/reach/TS-NNNN/` to `/reach/TS-NNNN.<stamp>/`. A revalidation directory that exists, which an archived report may name, stays, and the new replays go to `<tag>.<stamp>/`, which the `Replays` line names. Tests; SPEC 18.6.2 `--redo` and Finish, 18.11 (an archived `run` line names the scaffold, so apply `version.diff` first). |
| 11 | Valid | `--redo` left `<package>/artifacts/<scaffold>/` beside the replacement version, where an old crash looks like a new one. PRD R-TS-SYN-2 required the move; the SPEC did not. | `--redo` moves it to `TS-NNNN.<stamp>/artifacts/<scaffold>/`; the corpus stays. Test; SPEC 18.6.2. |
| 12 | Valid | `fuzz_binary` ignored `CARGO_TARGET_DIR`: every card NOT BUILT, or a stale binary in the default directory replayed. | With the variable set, only `$CARGO_TARGET_DIR` (relative to the checkout) is checked, else the two defaults. Tests; SPEC 18.8. |
| 13 | Valid, other trigger | Clean never deleted git-ignored files under `target_states/` (a `target/` module, `.DS_Store`, scratch of a failed or killed attempt), exited 0, and the next campaign refused the checkout. A Ctrl-C does not leave them. | `clean_plan` adds the ignored files under `scaffold_dirs()`, shown as `delete` lines; a `target_states/` left is a difference, exit 1, also when it holds no file and nothing else is left to undo. Tests; SPEC 5.4, 18.6.1 guard 6, 18.6.2 Clean. |
| 14 | Valid | A miss's trace lines and the handoff's `next=` cloned the trace suffix, 64 MiB at `TRACE_CAP`, also with `STATELENS_REACH` unset. | Both run only under `reach()`; no new runtime API. Helper self-test; SPEC 18.7, AC-23, Appendix H. |
| 15 | Valid | The prompt and SPEC pinned fields before `Stages::new`, so a pin witnessed by `Witness::act` took position 0 and its ordered stage was `unverifiable (no position)`. | Order: split and pick the knobs, `Stages::new` and `Stages::budget`, then the pins. Prompt and helper doc; SPEC 18.7 (shapes, naming, table), Appendix H; PRD R-TS-SC-2 and the 11.4 diagrams. |
| 16 | Valid | The re-base rule (`required_containers`, `fuzz_runtime_timeout`) fits only the simplex bounded drivers: no marshal base has a runtime deadline or that progress field, and Shape A cannot re-base an oracle that runs inside its entry. The 12 s fault phase was the scenario-prefix runner's only. | Per-base progress and deadline rules in the subsystem prompts, each in the base's own measure counted from the handoff (simplex: standard and audited drivers, Twins campaign, Twins mutator without one, Chaos, ByzzFuzz and Chaos-Twins from their heal); `Duration::MAX` for a base without a deadline; Shape A keeps its oracles, else Shape B. SPEC 18.7, PRD R-TS-SC-4 and R-TS-SC-5. |
| 17 | Valid | `rounds` and `case_selector` do not pin the marshal Twins case: `raw_bytes` seeds the sampled case list that `case_selector` only indexes. | No field pins the case: Shape B, or a marked constructor for `Scenario` and `RoundScenario`, whose fields are private. Marshal prompt; SPEC 18.7. |
| 18 | Valid | TS-0001's E5 did not bind `p1`, nor TS-0002's E4 `B`; and TS-0001's "E6 first" knob value cannot make R's nullify vote come from the rejection, which the voter drops as stale. | The cards bind `p1 as E2` and `B as E1`, and the knob row says R votes on a timeout. Test; SPEC 18.3 example. |
| 19 | Valid, location corrected | The blanket no-panic rule conflicted with copying drivers and keeping oracles verbatim; `run_standard_once` is simplex's, and marshal runners panic too. A miss after the handoff records nothing. | The rule covers only the prefix and witness code a scaffold adds; copied code and oracles keep their panics. Prompt; SPEC 18.7, PRD R-TS-SC-7. |
| 20 | Partly valid | High fix 4's last check turned the reviewer's exit 0 into exit 2, but a killed synthesis still left the card's edits in the next run's `S0`, out of reach of the restores, the diff, guard 5 and `--redo`, and could hand over a NOT BUILT card's scaffold. | `reach/pending/` keeps `S0` until the card ends; the next run's `recover()` restores it before the guards, exit 2 when unreadable. Tests; SPEC 18.6.1 guard 6, 18.6.2, 18.11, PRD R-TS-SYN-3. |
| E1 | Valid | PARTIAL's k was the stages before the first miss, so a version that held nothing outranked one that held `E1`, against "the most stages held"; SPEC 18.8 and PRD R-TS-SYN-6 defined it that way. | k counts the stages held before the miss, and the earlier stages that did not hold are reasons. Test; SPEC 18.8, PRD R-TS-SYN-6, README. |
| E2 | Valid | A `cannot:` miss got the positional fix (setup, event or timing), which cannot add a capability. | A `cannot` feedback row for a miss at any stage. Test; SPEC 18.8, PRD R-TS-SYN-7, prompt, README. |
| E3 | Valid | The sequential `fuzz` branch warned "no -max_total_time" when `-runs=N` bounds the run. | `-runs=[0-9]*` also silences it. Test; justfile, SPEC 5.3, PRD R-P2-5. |

Evidence: `just check-scripts` passes (421 tests). The reviewer's fixtures pass where they still
apply; three fail for reasons outside these findings: `test_truncated_trace_cannot_be_reached`
runs a binary built against the helper before high fix 1, the cross-card build-count test
predates high fix 4's last check, and `tss-r3-abandoned-scaffold.py` builds a kill state without
the `pending/` the fixed script always writes (adapted, it gives exit 3 with nothing left).

## Round-2 findings triage (2026-10-08)

The round-2 review (`statelens-code-review-target-state-round-2.md`) found 1 high, 10 medium
and 2 low findings. Finding 1 was fixed before this triage (its status line in the report).
Findings 2 to 13 were triaged against the current tree, every reviewer fixture rerun from a copy
pointed at it, then fixed with a regression test each where code changed; the PRD, the SPEC (the
section 13 copy of `simplex-synthesize.md` refreshed with `just check-prompts --write`; section
5.3 and Appendices A and H unchanged, since the justfile and the Rust files did not change) and
README follow. `just check-scripts` passes (450 tests).

| Finding | Verdict | What was wrong (or why not) | Fix |
|---|---|---|---|
| 2 | Valid (high) | `Synthesis.shared_paths` exempted the card's own module, so a `--redo` or a kept version that changed a helper a sibling module uses (`super::ts0004::limit()`) revalidated nothing and left the sibling's REACHED standing on a tree where it is false. The modules are `pub mod` siblings of one crate, so no token scan can prove independence; only the thin-target exemption is sound. Two corrections to the report: with the exemption gone the SPEC's rollback rule makes A `NOT BUILT (breaks TS-0005)` (exit 3) rather than keeping A and restating B, and removals were already covered, since a card's diff creates its module. | `own = {manifest, mod.rs, Cargo.lock}`, the thin-target regex kept: every card with other standing scaffolds revalidates them all, every undo owes one, and the console line names the paths. 13 expectations updated, a sibling-helper regression test. SPEC 18.6.2 (`--redo`, Finish, Last check, Outputs), AC-24, 18.11; PRD R-TS-SYN-1, AC-24; README. |
| 3 | Valid | After a `--redo` left a scaffold `NOT BUILT (no longer builds)` (exit 2), the next unchanged run skipped every card, `run_cards` skipped `last_build` (`if outcomes:`), printed run lines for the unbuildable scaffold and exited 0; `test_a_redo_that_breaks_a_kept_scaffold_records_it_not_built` asserted that. | `last_build()` on every run: N incremental builds when nothing changed, exit 2 until a `--redo` or a later card makes the scaffold build. `test_the_last_check_builds_every_scaffold` is the no-card scenario. SPEC 18.6.2 Last check. |
| 4 | Valid | `control_status` checked Ek, the stages before it and En, but no stage between them: a second withheld or absent later event, which can explain En's miss by itself, still certified REACHED. Stages before Ek were already vacuous (`binds other values`), so only the after-Ek gap was open; the prompts already require driving every later event. | A loop over the stages after Ek: `vacuous`, `E{j} has no line in the control run` or `E{j} is withheld in the control run too`; a later `missed` stays an outcome. Test. SPEC 18.8, PRD R-TS-SYN-5. |
| 5 | Valid | The weak check compared `stage_values` by equality, so an entity the control's En witness left out of `bind=` or bound to `?` counted as another value: control `ok`, REACHED 4/4. The tolerated witness rejection is by design; the defect was unknown read as different. | `apart` is true only when an entity both witnesses bind to a value differs; the control is `weak` (existing feedback), not a new status; `d=cd` stays REACHED. Test. SPEC 18.8, PRD R-TS-SYN-6. Refix (below): a bind the control witness's own key or `as` source contradicts counts as unbound too. |
| 6 | Partly valid (low) | `first_run` cut at the first `done`, so libFuzzer's leak-check rerun could complete an incomplete first run (NO REPORT read as REACHED) and a second-run panic lost its `phase prefix` (phase `continuation`). Not valid: the completion case needs run-dependent scaffold behavior, which the fixture supplies; `replay.log` already keeps the raw output; no helper or grammar change is needed, since `Stages::new` prints `phase prefix` first and the hook reprints the phase only after `panic`. | `first_run` keeps one run of the input: a run opens at `phase prefix` unless a `panic` of its run precedes it, and the run kept is the one that panicked, else the first. Tests. SPEC 18.8. |
| 7 | Valid | `run_logged` gave a command its own process group, and killed it, only with a `timeout`, so an interrupted agent, with a cargo it started, outlived the restore of S0 and could write into the restored tree or the kept version; a supervisor's `kill -INT` left it running for good. For timed replays only the reap was missing. | `start_new_session=True` always; on any exception `kill()` then `process.wait()` before it propagates; `SIGTERM` and `SIGHUP` mapped to `KeyboardInterrupt` under `__main__`, since the new session would otherwise orphan the agent. Test. SPEC 18.6.1 guard 6, 18.6.2 Per card, 18.11; PRD R-TS-SYN-3 guard 6; README. |
| 8 | Valid | The timer's `kill` ran `killpg` only while the leader was alive; a descendant holding stdout after the leader exited blocked the read past the deadline, and the command returned the leader's code. Only the scaffold binary is timed, so no protocol replay is known to hit it; the runner's contract was wrong. | The `poll()` guard dropped: the callback always sets `killed` and `killpg`s under `suppress(OSError)`. Test. SPEC 18.8. |
| 9 | Valid | The simplex prompt and both SPEC copies said the standard and audited drivers wait until every reporter reaches `input.required_containers`, with no predicate; they wait only under `should_bound_standard_liveness` (`Connected` partition, valid configuration, `BlockFilterChoice::None`) and otherwise sleep `MAX_SLEEP_DURATION`, FaultyNet never waits, and the audited loop skips the omission victim and checks its recovery drain instead. A literal Shape B adds a wait that ends in `panic!("runtime timeout")`: false finding candidates, no missed bug. | The `Progress and deadline` bullet carries the predicate, the FaultyNet case and the victim's drain check; `just check-prompts --write` for the section 13 copy; the 18.7 paraphrase hand-edited. No code or test change. |
| 10 | Valid | `restate` rewrote only the `Verdict` line and appended the section, so a CRASH that moved from the canonical to the control replay (accepted by `stands_worse`), or one an undo revalidation gained, kept a `## Run and replay` block without `STATELENS_REACH_CONTROL=1` that named the old crash file. | `crash_text` factored out of `write_report` and added to the section; the block rewritten from the latest check through `REPORT_RUN_BLOCK`, the placeholder when it has no failure. Tests. SPEC 18.6.2 Finish, Outputs; PRD R-TS-SYN-7. |
| 11 | Valid (low) | `run_lines` interpolated the checkout and crash paths unquoted, so a checkout with a space failed at `cd`. `shlex.join` does not apply, and quoting the whole placeholder would change its documented form; `Campaign.handover` has the same defect, scoped out by the reviewer. | `shlex.quote` on the checkout, the crash file and the artifacts directory, the `/<crash file>` placeholder left unquoted; a space-free checkout renders as before. Tests (`HandoverLines`). SPEC 18.6.2 Console. |
| 12 | Valid (low) | `check_test_sources` accepted an untracked or merely staged test under the roots; the card must cite it at `{{COMMIT}}`, so lint rule 10 rejected it after a wasted agent attempt (exit 3 instead of 1). `unpinnable` is right as it stands (tracked files that differ from HEAD); `comment` sources have the same gap, not raised. | Preflight: `git_file(repo, "HEAD", relative) is None` exits 1 ("commit the file first, or give the test as a `text` source"), before the agent. Test. SPEC 18.4, PRD R-TS-P1-2. |
| 13 | Valid | `Synthesis.write` tested `is_file()` and `write_bytes` followed a link, so an edit that replaced an in-scope file by a link to an unchanged sibling made `restore` write the snapshot into the sibling and keep the link; guard 1 sees the typechange only after the restore. A link-replaced directory is caught by guard 1, but the rollback still wrote through it; a dangling link survives a restore, harmless. | `write` warns and returns when the path's parent resolves elsewhere, unlinks a link at the path before writing or deleting, and prunes the parent. Tests (`RestoreLinks`). SPEC 18.6.2 step 1, 18.11 (the dangling link). |

Residuals, noted and not fixed: `Campaign.handover` quoting (finding 11); `comment` sources with
the HEAD gap of finding 12; the sub-millisecond window between a command's exit and the timer's
cancel can still mark it killed (finding 8, pre-existing); a scaffold recorded `NOT BUILT (no
longer builds)` is not replayed when a later card makes it build again (finding 2, SPEC 18.11).

Refix after adversarial verification (2026-10-08). Two verifiers reran every reviewer fixture
against the fixed tree, with variants of their own, and found all of findings 2 to 13 fixed. One
residual of finding 5 was a defect of the same class and is fixed: `control_status` compared the
control's En bind even where the witness's own evidence contradicted it, so a control that read
the canonical's `certify[..,d=ab]` but bound `d=cd` (detail `witness rejected: as`, which masks
the `evidence` rule), or bound `R=2` where its E1 bound `R=1`, was `ok` and REACHED 4/4. Now an
entity whose control value its key pairs, or the control stage its `as Ej` cites, name
differently counts as unbound, and the control is weak; `d=cd` confirmed by the key stays
REACHED (`test_a_control_bind_its_own_evidence_contradicts_tells_nothing_apart`; SPEC 18.8, PRD
R-TS-SYN-6). A bind nothing confirms or contradicts is still compared: an entity cited `as` the
withheld stage whose key does not name it, which for an `exact` or `construction` witness the
canonical's `evidence` rule rules out, since the same code prints both runs' keys; `intrinsic`
witnesses and incarnation values remain. SPEC 18.11 now also names a symbolic link to a
directory as one that `restore` leaves in place (finding 13; `scope_files` lists only files).
Not applied: a `returncode` guard in the timer's `kill` (finding 8), since the check in the
timer's thread and the reap in the caller's still race, so it narrows the window noted above
without closing it, and the group id it would protect is reused only by a new session leader
within microseconds.

## Pair synthesis (2026-10-08)

The user's decision, binding: with `--state-reaching`, a card gets one scaffold per matching base,
not one scaffold on a base the agent chooses. The unit of synthesis is the pair (card, base). TS-0004
with `--fuzz-targets "simplex_cert_mock_twins_*"` yields eight scaffolds, the four
`simplex_cert_mock_twins_campaign*` and the four `simplex_cert_mock_twins_mutator*` bases, each with
its own agent synthesis (attempts, feedback), build, replays, verdict, report and tmux window;
without `--fuzz-targets` every candidate base of the profile is used, 20 for simplex (21 targets
less Mallory) and 13 for marshal at HEAD. The agent chooses no base: `prompts/synthesize.md` gets
the one base of the pair (`BASE_TARGET`, `BASE_DETAILS`, `SCAFFOLD`, `BUILD` with the real name;
`BASES` and `TARGET_RULE` are gone). Each pair is a card-sized transaction of the existing shape, so
the baseline, guards 1-6, the pending snapshot, the rollback, the durable revalidation record and
the cross-scaffold revalidation apply unchanged per pair; a kept pair revalidates every other
standing scaffold, the card's other pairs included, and one that breaks a sibling is rolled back as
before. The cost (20 x (S - 1) revalidation builds for a card on every simplex base) is accepted and
recorded in SPEC 18.11; `--fuzz-targets` and `<base>_tsNNNN` patterns bound it.

Naming, applied everywhere (SPEC 18.6.2 and 18.7, PRD R-TS-SYN-2):

| Thing | Per card (before) | Per pair (now) |
|---|---|---|
| Pair key: reports, attempt and revalidation directories, `revalidation.json` keys, `pending/state.json` (`"pair"`), prompt and log names | `TS-0004` | `TS-0004_<base>` |
| Module | `target_states/ts0004.rs` | `target_states/ts0004_<base>.rs` |
| Thin target and scaffold | `<base>_ts0004_statelens` | unchanged, already carries the base |
| Report title | `# TS-0004: <title>` | `# TS-0004 on <base>: <title>` |
| Skip line | `TS-0004 was synthesized as/on/without ...` | `TS-0004 on <base> was synthesized as <scaffold>; use --redo`, or `... without a scaffold; use --redo` |
| Console verdict line | `<scaffold \| no scaffold>` | `<scaffold \| no scaffold on <base>>`; summary `<k> pair(s), <s> scaffold(s)` |
| Rollback verdict | `NOT BUILT (breaks TS-MMMM)` | `NOT BUILT (breaks TS-MMMM_<b>)` |
| Revalidation headings and directories | `after-TS-NNNN`, `without-TS-NNNN` | `after-TS-NNNN_<base>`, `without-TS-NNNN_<base>`; `after-redo`, `after-last-check`, `after-rollback` unchanged |
| `[[bin]]` block removed by an undo | by `*_ts0004_statelens` | by the scaffold's exact name, so a sibling's block survives |
| Marker, `strays` glob, replay line prefix | `tss:TS-0004`, `*_ts0004_statelens`, `[statelens-reach] TS-0004` | unchanged, per card |

Vetoes gained per pair: no thin target for the pair's base, a new thin target of the card on another
base, a header naming another base than the pair's. The skip rule, `--redo` and `targets
--state-reaching` are per pair; the handover prints one `run` line per scaffold; the `fuzz` recipe
needed no logic change beyond counting scaffolds in its messages, since it already ran one window
or run per listed scaffold. AC-24 and AC-25 pin each card to the base family of PRD 11.4 with
`<base>_tsNNNN` patterns and add a card on two bases; AC-27 adds the one-window
(`--fuzz-targets simplex_cert_mock`) and eight-window (twins) cases. Round-2 finding 14 is
superseded: the twins example lists the eight scaffolds, `<base>_ts0004_statelens` for each
`simplex_cert_mock_twins_*` base, and the name is no longer a prediction of the agent's choice
(SPEC 18.9, `FuzzRecipe.test_an_invariant_list_goes_to_the_campaign`).

## Revisions: differential test of the primitives (2026-10-08)

The user's decision, binding: "this is just testing; you do not need to instrument the
codebase or launch a campaign"; import the runtime module rather than copy it; a test-only
module under `statelens/` may import the marshal scenario primitives and ours; and
`consensus/fuzz/marshal` may change only for visibility. The question answered: do the helper
primitives, and a prefix written by the scaffold rules, reach the state a human-written prefix
of the same source test reaches, and does the reach check say so?

1. Visibility (`consensus/fuzz/marshal/src`, uncommitted): the modules `scenarios::{environment,
   harness, input, recording_resolver, scenarios}`, `marshal::end_to_end::{app, twins}` and
   `twins::stack`, the `Scenario` trait and `drive`, `FuzzScenarioStandardHarness` with its
   verbs and `finish`, `ScenarioHandoff` and its types, the recorders with `RecordingResolver`'s
   two injection fields, the setup pieces of `app` and `twins::stack` and the input types go
   from `pub(crate)` to `pub`. Every changed line is the keyword, plus three rustfmt reflows and
   two `#[allow]`s (`async_fn_in_trait`, `clippy::new_without_default`). `scenarios::runner`
   stays `pub(crate)`; its SETUP block is copied verbatim into the test crate. Clippy
   `-D warnings` on all targets, rustfmt and nextest (80/80) pass. Nothing under `consensus/src`
   changes. PRD R-LAYOUT-3 and SPEC section 3 record the exception.
2. The crate `statelens/differential/` (empty `[workspace]` table; the shim is a member of it
   as a path dependency under it): the shim compiles `runtime/{statelens,target_states}.rs`
   byte-identical by `#[path]`, with `extern crate self as commonware_consensus` and
   `as commonware_runtime` and a local `deterministic::STATELENS_FRESH_RUN`; no `sed` copy was
   needed, since the runtime's Simplex-only tail is `#[cfg(test)]` and compiled out in a
   dependency. Seven cards TS-9001 to TS-9007 over the six source tests (TS-9003 Deferred and
   TS-9004 Inline split the height-lie test), one module per card with the SPEC 18.7 header, a
   verbatim setup with stamping wrappers on both sides, and a digest wider than `finish`
   (resolver, buffer, blocks, finalizations, acks, every node's durable storage through
   `Context::scan`, `logical_blob` and `storage_audit`, settled first). 24 positive tests, 6
   negatives. PRD R-LAYOUT-2, SPEC D13 and section 3 record the exception; SPEC 18.10.1 has
   the procedure and the expected table, and the README a section.
3. `scripts/differential.sh`: worktree, rsync, fuzz-package checks, build, every test twice
   (canonical with `STATELENS_REACH=1`, control with `STATELENS_REACH_CONTROL=1`) in its own
   process, `statelens.py reach-verdict` (a new command over the existing `card_history`,
   `first_run` and `reach_verdict`; `ReachVerdictCommand` tests it), the table, cleanup.
   Result at `392b116687`: `differential: PASSED (+180s)`, all 24 positives equal and REACHED
   n/n with no annotation or rejected witness, all 6 negatives caught.
4. Verification found, and the refix closed: the script skipped the control replay for `neg_*`
   tests, so a wrong prefix could never be REACHED and the `NOT CAUGHT` branch was dead (now
   every test gets the control); a notarization reported to another node and an armed,
   unconsumed delivery were invisible to the digest (now read from durable storage and from
   the resolver's injection fields; two new negatives, each caught by the digest alone while
   the validator says REACHED); acknowledgements were only a settle precondition (now a digest
   line, and an unsettled cluster panics). Not narrowed: items that widened with their modules
   because they sit in now-pub signatures, and the harness verb set.
5. What it establishes and does not (SPEC 18.10.1 and 18.11, PRD 11.2 and 11.6): primitive and
   reconstruction fidelity against a human-written definition of the same state, and the
   validator's acceptance; nothing about agent output, probes (`intrinsic` witnesses) or
   fuzzing, and settled states only, so an event in flight at the handoff is not told apart.

## Differential review triage (2026-10-08)

The review of the differential test (`statelens-code-review-target-state-differential.md`)
found 4 medium and 2 low findings, no critical or high. Each was triaged against the current
tree before any fix (the reviewer's fixtures of findings 4 to 6 rerun against the tree; the
script findings reproduced on a verbatim copy of the script in a scratch repository with
`cargo`/`rustfmt` stubs and the real validator, under bash 5.3 and 3.2), then fixed; the docs
follow. The differential run was repeated through the script after the
fixes, with the fuzz package's checks skipped since that package did not change: the same 30
rows, `differential: PASSED`. Not changed: `statelens/scripts/statelens.py` and its tests. The
review report's status lines, left open here, were closed by the verifier round below.

| Finding | Verdict | What was wrong (or why not) | Fix |
|---|---|---|---|
| 1 | Valid | The `neg_*` branch of `differential.sh` failed only on equal digests plus an unannotated REACHED, so a negative whose replay crashed (exit 101 or 127, no digest line), printed no digest, got `NO REPORT` or `CRASH`, or hit a validator traceback or abort counted as caught: five such negatives, `differential: PASSED`, exit 0. The validator's exit code cannot discriminate (1 for every verdict but REACHED and for an abort), so the fix checks the verdict's shape; the exposure is negatives only, since the positive branch already requires exit 0, a digest and REACHED. SPEC 18.10.1 step 6 and the README stated the same weak criterion. | `VERDICT_SHAPE` (`REACHED|UNVERIFIED|PARTIAL|UNREACHED k/n`, annotated or not); a negative with a non-zero exit, a digest line other than `true`/`false` or an unshaped verdict is `(ERROR)` and fails the run; `(NOT CAUGHT)` as before. The expected table has no negative that crashes, so nothing is lost. SPEC 18.10.1 steps 6, Negative controls, 18.1, AC-25; PRD AC-25; differential README. |
| 2 | Valid | `tests=$(cargo ... --list \| sed ...)` was never compared with the 30 names: an empty listing, one that lost tests (every negative included) or nested names (`tests::nested::x`) ran fewer or zero replays and exited 0 (bash 5.3 printed PASSED; bash 3.2 died on the empty `rows[@]` under `set -u` yet still exited 0, the EXIT trap's `git worktree prune` masking the status). A failing `--list` was already caught by `pipefail` (exit 101), as the reviewer said. | `EXPECTED_TESTS` (the 30 names of `src/tests.rs`) and a sorted `diff` against the listing into `logs/tests.diff`; any difference prints the diff and exits 2 before any replay. `printf '%s\n' ${rows[@]+"${rows[@]}"}` for bash 3.2. SPEC 18.10.1 step 4, AC-25; PRD AC-25; differential README (Layout, How to run). |
| 3 | Valid | `WT=<scratch>/wt-diff` and `LOGS=<scratch>/differential-logs` were fixed per scratch; startup deleted the old logs and ran `cleanup` whenever `$WT` existed, and `cleanup` fell back to `rm -rf "$WT"` with no ownership check. Reproduced: a second concurrent run removed the first's live worktree at startup (and the first's trap later the second's); an unrelated directory at `<scratch>/wt-diff` was deleted by the fallback. Confined to that scratch child; the checkout was never touched. | `RUN=$(mktemp -d "$SCRATCH/run.XXXXXX")`, `WT=$RUN/wt-diff`, `LOGS=$RUN/logs`; the startup cleanup and log deletion are gone; `cleanup` unchanged, now inside the run's own directory; the header documents the exit codes and the default `$TMPDIR/statelens-differential`. Two concurrent runs pass with 30 rows each, zero worktree registrations left. SPEC 18.10.1 procedure, step 1, 4, 6, AC-25; differential README. |
| 4 | Valid | `ts9005.rs` stamped `verify=pending` unconditionally right after `wrapper_verify` returned and E2 read that string back; nothing touched the receiver before E5. So the E2 Check "B's verification of d at v is pending" was asserted by the prefix, not observed, and a receiver already holding a verdict held E2; the digest cannot notice, since both sides run the same system. The rule is SPEC 18.7's `exact` definition (a harness observable, a wrapper's stamped entry or a side-effect-free local query), not scenario S3 as the reviewer wrote; neither the reference drive nor the source test checks pending-ness, so the claim is the card's own and only the prefix can establish it. Not a `cannot:`. | The unconditional stamp removed; `e2_recorded` returns the `subscription` and `fetch_count` entries; after the poll, one `try_recv` on the held receiver: `Err(Empty)` stamps `pending` then and holds E2 with three items; `Ok(v)` or `Closed` records the verdict or `dropped`, drops the receiver and misses E2 ("the verification of d did not stay pending"). Positions unchanged (`neg_ts9005_swapped_arm_verify` still `witness rejected: order`). Module comment; SPEC 18.10.1 "The test"; differential README Limitations. |
| 5 | Valid | `waiting` in `ts9006.rs` built E2's and E4's witness with `replica_nonzero("subscription", ",m=..")`, so a count raised from 1 to 2 after E3's drop still held E4, against the card's E4 Holds line, the module comment ("unchanged") and the reference's `assert_eq!` on `buffer_subscription_count`. One correction to the report: the digest cannot catch such a regression ("or the exact total in the digest"), since both sides print the same total; only side A's reference assertion can. | `waiting(.., count: Option<&str>)`: `None` keeps nonzero (E2), `Some(count)` requires `replica_exact` (E4); after E2 is held, `registered` captures the observed value and the handoff closure requires it (`registered.as_deref()?`), so the control run misses E4 by construction. Optional total-count item not taken. SPEC 18.10.1 "The test" and "What it establishes"; differential README. |
| 6 | Partly valid | The seven cards are documented as cards in the 18.3 grammar; no document claimed lint-cleanliness or discovery. Explicit lint gave 14 problems: rule 11 on all seven (no generated `## Source excerpts`), a card defect; rule 1 on all seven, because `differential/cards/` is not a card tree, the documented, intentional location (the `9NNN` ids stay out of the counter), so a lint-support gap, not a card defect. Rules 2 to 10, 12 and 13 pass; all 15 pinned citations resolve at `392b116687`. Moving the cards into `target-states/marshal/` is not an option (they would become synthesis cards and raise the counter). | `statelens.py excerpts` on the seven cards (`excerpts --check`: 0 of 7 out of date); explicit lint now reports 7 problems, all rule 1. Not taken: the rule-1 fixture location in `statelens.py` and a lint step in the script (follow-up). SPEC 18.10.1 "Scenarios covered" and the differential README now say exactly that: outside the card trees, linted only when named, location reported and nothing else. |

Follow-ups of this triage: `statelens.py lint` could accept `differential/cards/TS-NNNN.md` as a
named marshal-card location (never discovered or counted) with a test, and `differential.sh`
could lint the cards in the worktree before the builds; TS-9006 could add the `subscriptions`
total as a fifth E4 item; the scenarios.rs citations (70 to 131 lines) exceed the 18.3 guidance
of about 40 lines, unchecked by lint.

## Verifier leftovers of the triage (2026-10-08)

The verification of the six fixes, from a shared scratch clone through its own copy of the
script (baseline from scratch with the fuzz checks, a validator traceback on a negative, one
test deleted, two concurrent runs, the wrong prefixes of findings 4 and 5, the full card lint),
upheld every verdict (1 to 5 valid, 6 partly valid) and left five items, A to E, each checked
against the tree before any change:

| Item | Verdict | What was wrong (or why not) | Fix |
|---|---|---|---|
| A | Valid | `statelens/README.md`'s differential section still described the pre-fix script: a worktree "under `DIFFERENTIAL_SCRATCH` (`$TMPDIR` by default)", logs in `<scratch>/differential-logs/`, negatives that "must be caught" without the replay condition of finding 1. | The section names `<scratch>/run.XXXXXX/wt-diff` and `logs/` (the path is printed), the default `$TMPDIR/statelens-differential`, and "caught, by the digest or by the validator's verdict of a replay that ran to its digest line". |
| B | Valid | The review report's six findings read `Status: OPEN` after the fixes, against the convention that a fixed finding is marked FIXED with a note; finding 5's "or the exact total in the digest" was wrong for a regression of the system under test, which both sides run, so both digests carry it and only side A's reference assertion sees it (a wrong prefix's extra wait is a different thing, and the digest did catch that one). | Table and sections set to FIXED (6: FIXED, partly valid) with a note each, finding 5's sentence corrected to "on side A", finding 6's note as the triage wrote it. |
| C | Valid | `(NOT CAUGHT)` matched only an unannotated REACHED, so a negative with equal digests and `REACHED k/n (weak)`, or any other annotation (`nondeterministic`, `control n/a`, `control missing`, `unbound label`, `missing:`, `stray failure`, `relation across restart`, `location in .. diff`; `reach_verdict` and `verdict_text`, all informational, none a rejected witness), would have counted as caught. Latent: no current negative yields an annotated REACHED. | The match is the REACHED prefix, annotated or not; the positive branch still requires an unannotated REACHED. SPEC 18.10.1 step 6; differential README. |
| D | Valid | `ts9006.rs` stamped `verify=pending` at the E1 call and E2 read it back (gated on `try_recv`, so E2 itself was sound), against the general clause of SPEC 18.10.1 that a pending reply is stamped only at its stage. | The stamp moved into E2's `Empty` branch as in TS-9005: `waiting` returns the three recorded parts, the verify entry is the stage's own (E2 stamps `pending`, E3 `dropped` as it drops the receiver), E4 requires the `dropped` entry with E2's count. SPEC 18.10.1 "The test"; differential README Limitations; the module comment. |
| E | Info | `statelens/tss-reach-check-explained.md`, untracked, appeared in the checkout during the verification. | None; not part of this change, left in place. |

The procedure was rerun once after these fixes, the fuzz package's checks included (clippy,
rustfmt, nextest 80/80; the 30 listed tests are the 30 expected): the same 30 rows as the
expected table of SPEC 18.10.1, `differential: PASSED (+187s)`, exit 0; TS-9006's E2 now reads
`verify=pending` stamped after the `subscription` entry, and its control run misses E2; the
worktree and its target directory were gone afterwards. `just check-scripts`, `just
check-prompts` and `just check-invariants` pass; the seven cards, linted by name, still report
their location (rule 1) and nothing else, with `excerpts --check` at 0 of 7 out of date.

## Follow-ups (not in this change)
- Variant `run` lines print `-- -rss_limit_mb=4000 -print_final_stats=1` (statelens.py:5650),
  against the no-flags preference.
- SPEC 8.1/AC-9 say 12 marshal targets; there are 13.
- `prompts/synthesize.md` finds an intrinsic `En` witness with `observations`, which copies the
  trace suffix on every input (about 3 ms at `TRACE_CAP`); `seen` with a closure that keeps the
  last match would not copy it.
- `coverage_binary` still looks only in the default target directories, not in
  `CARGO_TARGET_DIR` (finding 12).
