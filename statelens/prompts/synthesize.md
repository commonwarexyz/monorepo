# StateLens synthesizer: write a state-reaching fuzz target

You are writing a scaffold: a dedicated fuzz target that drives the History of one
target-state card on an existing fuzz target of this repository, its base, witnesses each of
its events with the probes a StateLens campaign installed and with harness observables, hands
off at the target state, and lets the fuzzer and the base's oracles run on from there.

## Where you are

- This checkout is a throwaway clone at commit `{{BASE}}`, instrumented in place by a
  StateLens campaign. Your changes are never merged; a human reviews the pair's diff. The
  repository conventions in AGENTS.md and CLAUDE.md about public API stability, documentation,
  benchmarks, dependencies, commits and pull requests do not apply here. The rules in this
  prompt take precedence.
- Do not commit. Do not run the tests, the scaffold, any fuzz target or the fuzzer: build
  only (section Building). The script replays your scaffold itself.
- Read `{{RUNTIME}}`, the runtime module of the campaign, `{{RUNTIME_MODULE}}`: its probes,
  and its read side (`seen`, `sites`, `observations`, `truncated`, `mark` and the `Seen`
  type, whose fields you read through its getters, such as `s.a()`), which a scaffold uses
  to ask which probes fired during its input. From the fuzz package it is
  `commonware_consensus::simplex::statelens`.
- Read `{{FUZZ_PACKAGE}}/src/target_states/mod.rs`, the helper the script wrote, for the
  exact signatures of the items this prompt names, and `{{PLAN}}`, the campaign's plan, for
  what each probe records (its beacon table) and which invariants are bound where.
- The probe labels and `sl_implies!` invariant IDs of this campaign, with where each is,
  from one scan. Lines move as you edit, so a scaffold looks a site up at run time with
  `sites(label)` and never writes one as a literal:

{{LABELS}}

## Task: card {{CARD_ID}}, attempt {{ATTEMPT}} (attempts run from 0 to 3)

The card, with its {{STAGES}} History events; its Source excerpts show the code it was
written against:

===== {{CARD_ID}} =====
{{CARD}}
===== end of {{CARD_ID}} =====

Write:

- the module `{{MODULE}}`, which holds everything the scaffold needs: its `fuzz` entry, its
  stages, and any recording wrapper;
- the thin target `{{FUZZ_PACKAGE}}/fuzz_targets/{{SCAFFOLD}}.rs`, on the base
  `{{BASE_TARGET}}` described below; exactly one thin target for this card on this base,
  and none on another base;
- any edit under the edit contract below that the scaffold needs elsewhere, each marked.

The script owns the package manifest, `Cargo.lock`, `target_states/mod.rs` (the helper,
followed by one `pub mod` line per module, yours included) and the line of the package's
`src/lib.rs` that declares `target_states`. It adds your scaffold's `[[bin]]` block, the
base's block with `name` and `path` renamed, after your attempt.

The base, `{{BASE_TARGET}}`: its name, the `fuzz_target!` closure header and entry call,
`required-features`, input type, and whether its runner is hooked:

{{BASE_DETAILS}}

## Edit contract

This is requirement R-TS-SYN-3, the one contract for every edit a synthesis makes:

> Scaffold synthesis operates on a disposable copy of the repository, following the same
> assumption as StateLens. The generator may modify source code when necessary to expose
> state, make existing functionality callable, add fuzz-only accessors or wrappers, or support
> scaffold execution and verification. Such modifications must not change the production
> behavior or protocol semantics of the system under test.
>
> Allowed examples include:
> - widening visibility of existing functions, fields, or types;
> - adding fuzz-only getters or read-side accessors;
> - adding re-exports;
> - adding wrappers around existing operations;
> - adding campaign/runtime observation code;
> - adding compile-time fuzz-only hooks that expose existing behavior;
> - restructuring code only where the transformation is demonstrably semantics-preserving.
>
> The generator must not modify production consensus logic, including:
> - state-transition rules;
> - branch conditions or protocol predicates;
> - ordering of protocol operations;
> - certificate or vote validation rules;
> - message handling semantics;
> - timeout behavior;
> - persistence/recovery semantics;
> - error handling that affects execution;
> - state mutations used by the production implementation.
>
> The principle is:
> - Allowed: change how existing behavior is exposed or observed
> - Forbidden: change what the protocol does
>
> Because synthesis runs on a disposable copy, generated modifications do not need to be
> suitable for upstream production code. They only need to preserve the behavior of the
> production logic being fuzzed.

How it applies here:

- Where: the paths the subsystem rules below name, which are the system under test and the
  profile's fuzz package. The fuzz package reaches `consensus/fuzz/core/` only through its
  own `src/`. Any other path is out of scope.
- Observation code is read-only code the scaffold calls: getters, accessors, recording
  wrappers, witness helpers. It never adds a counter feature, an assertion or ghost state;
  those come only from the campaign. Synthesis never instruments.

The script checks every attempt against the tree as the campaign left it, so a change an
earlier attempt made counts as if you made it now:

1. Scope: a change outside those paths, other than to `Cargo.lock`, stops the synthesis and
   restores the pair's edits; the operator then needs a fresh clone.
2. Manifests: no dependency change in any `Cargo.toml`. An edit to a file the script owns is
   restored, and your version is not built.
3. Instrumentation integrity: every `sl_probe!`, `sl_assert!` and `sl_implies!` call stays
   as it is (moving one within its file is fine); every line the campaign's instrumentation
   added stays, so no ghost update, `// [statelens]` field or runner hook is removed or
   changed; the runtime module stays byte-identical, and its declaration and the attributes
   above it stay, with no `#[path]` attribute added; no call of `with_ghost`, `with_global`,
   `record`, `note`, `violation`, `reset` or `clear_compromised` is added outside the helper
   and the thin targets; no `set_compromised` outside `target_states/`; no `tick`, `watch` or
   `unwatch` outside the helper; no call of the read side in the system under test; no `[statelens-reach]` or
   `[statelens-scaffold]` literal outside the helper; outside the helper, no print macro
   (`print!`, `println!`, `eprint!`, `eprintln!`), `stdout()` or `stderr()`, `from_raw_fd`,
   panic hook (`set_hook`, `take_hook`), `include!`, `include_str!`, `include_bytes!` or
   `#[path]` attribute, also in code you copy from elsewhere; and no Rust file in a path git
   ignores, such as a module or directory named `target`, which the repository ignores. A
   breach is not built, and it stays a breach in every later attempt until you revert it.
4. Marker: every changed hunk outside your module and thin target carries the comment
   `// [statelens] tss:{{CARD_ID}}`. An unmarked hunk is reported for review, and so is a
   hunk that changes or neighbors an `sl_*!` call or a line the campaign added.
5. Test gate: when the kept version changed the system under test, the campaign's tests run
   again; a test that passed in the campaign and now fails or no longer runs restores the
   pair's edits and records GATE FAILED.
6. Restore: a pair with no version built, or GATE FAILED, has its edits restored.

## Shapes

Pick one and record it in the module header.

- Shape A, pinned input, preferred where it fits: the base input's fields fix every event
  before `En`. `fuzz` splits and picks the knobs, opens the stages and checks the budget,
  pins those fields, resets the fields that depend on them, calls the base's entry by path
  with its generics, then evaluates `E1` to `E(n-1)` over the trace and the harness
  observables, calls `Stages::handoff` with the evaluation of `En`, and last `Stages::done`.
  The base's own schedule runs, no driver code is copied, and its oracles are untouched.
  Register the evaluation with `Stages::on_panic`, so a crash still reports what the trace
  shows.
- Shape B, online prefix, where Shape A cannot express the History: `fuzz` splits and picks
  the knobs, opens the stages and checks the budget, calls `set_compromised`, pins the
  fields, sets the base up, drives `E1` to `E(n-1)` online, calls `Stages::handoff` with a
  read of `En`'s witness, hands off to the base's free-running phase and oracles, and calls
  `Stages::done` after the last oracle. Call the base's setup by path; where only a
  monolithic driver can host the prefix, copy that driver verbatim into the module and cite
  it as `path::item@{{BASE}}`.

`pub fn fuzz` takes the base's input type and the generic parameters of the base's entry, in
order. The module opens with this header, which the script reads:

```rust
//! {{CARD_ID}} on {{BASE_TARGET}}
//! Shape: A | B
//! Knobs: raw_bytes[0..k]: [0] <knob>, [1] <knob>, ...
//! Stages: E1 <witness kind and what it reads>; E2 ...; ...
//! Control: withholds Ek | n/a
//! Injections: <each injection, with the INV ids whose ghost history it bypasses> | none
//! Missing: <each missing capability> | none
```

The thin target is the base's file with two changes: the `use` lines name your module
instead of the base's entry, and the body of its one `fuzz_target!`, whose closure parameter
stays the base's, is exactly these three statements:

```rust
    fuzz_target!(|input: <the base's input type>| {
        commonware_consensus::simplex::statelens::reset();
        <module>::fuzz::<the base entry's generic arguments>(input);
        commonware_consensus::simplex::statelens::clear_compromised();
    });
```

The first generic argument names the `cert_mock` scheme, as in the base, and the module names
no Simplex type with another scheme.

## Knobs

- The card's Knobs table lists them. `Knobs::split` takes the first K <= 16 bytes of the base
  input's own `raw_bytes`, zero-padded, as the first statement of `fuzz`; `Knobs::pick`
  takes the next one as `domain[byte % domain.len()]`, with the source value at index 0, so
  the empty input, the canonical input, replays the source's History.
- Each knob decodes to a valid value by construction: derive a view so that the required
  leader leads it, rather than hoping. An ordering knob indexes the orders `Order:` allows,
  the source order first.
- Pick every knob before any engine starts, then call `Stages::new("{{CARD_ID}}", {{STAGES}})`
  and `Stages::budget`, which takes the knobs, so none is picked later. Do both before you pin
  a field or perform any other action: until `Stages::new` nothing watches, so `Witness::act`
  takes position 0 and its stage has no position. The input type, the run recipe and the
  libFuzzer flags stay the base's; there is no seed corpus.
- Then pin the fields the History fixes, through `Witness::act` when a stage witnesses the
  pin, and reset the fields that depend on them as the base's decoder sets them under the pin
  (the subsystem rules name them).
- `Knobs::split`, `Knobs::pick` and `Stages::budget` raise the only errors attributed to a
  scaffold, before any engine starts: more than 16 knobs, more picked than split, a domain
  with fewer than two values, a prefix budget over the runtime deadline.

## Stages and witnesses

One stage per History event, `E1` to `En`, evaluated in the order you drive them. Bind the
card's entities to the concrete values you chose or observed, and record for each stage one
witness that establishes its whole `Check` or `Holds` line, its relations to earlier events
included. The kinds:

- `exact`: harness observables, one per part of the line, each keyed by the bound entities:
  a reporter map keyed by view or digest, a resolver or buffer recorder, a recording wrapper
  in your module, a network intercept record, or a local query without side effects. A query
  that subscribes, hints, fetches or verifies is not a witness: it would create or satisfy
  the state it checks. A map read after the run shows presence only; an entry carries a
  position only when a recording wrapper stamped it with `stamp` as it recorded it. A
  recording wrapper records synchronously and forwards every call and reply unchanged and at
  once: no await, delay, spawn, drop or reordering of its own.
- `intrinsic`: one probe observation, found with `seen` and a label from the list above, at a
  site whose two values come from one receiver. It identifies the replica `me` and the
  relation among that object's fields at that instant, and no view, digest or other
  identity, so it witnesses only a line whose entities other than one replica are all
  existential, and binds those to `?`. Two
  observations at different sites witness nothing together, and an observation whose
  subject its own site does not fix is no witness.
- `construction`: a harness action you performed through `Witness::act` or
  `Witness::act_async`, which take the action's position right before they perform it, and
  that cannot fail silently, such as a pinned elector or a certificate you built. It proves
  only that the action happened, never what a replica did with it, and only for an event
  whose actor is `harness`, never for `En`; in Shape A, only for an action before the base's
  entry is called. `act_async` takes a closure that makes the future: pass the call itself,
  never a future you made earlier, because some mailbox methods act when called, not when
  awaited.

A stage that no available witness binds is `unverifiable` with its reason, never held, and
never approximated; for `En`, record it with `Stages::unverifiable` before you call
`Stages::handoff`. Record stages only through the helper: `Stages::held(k, witness)` for
`E1` to `E(n-1)`, `Stages::missed`, `Stages::unverifiable` and `Stages::withheld`, and
`Stages::handoff` for `En`. Read the trace from `Stages::since()`. Never print anything:
the helper prints every line the script reads.

A witness record is checked again by the script, which downgrades a held stage to
`unverifiable` (`witness rejected: <rule>`) when:

- `as`: an `x as Ek` value differs from the value `Ek` bound, or is `?`;
- `bind`: an entity of the line is missing from the binding, written `name=value@Ek,...`;
- `evidence`: an `exact` or `construction` witness does not name every entity of the line
  with its bound value in its keys, written `name=value,...`, or an `exact` item's stamp is
  not that of an entry line with the same observable, key and value;
- `order`: a stage's position is not greater than that of an earlier stage it must follow,
  by the numbered order less the pairs `Order:` frees;
- `run`: a probe observation's runtime instance differs from that of an earlier stage's
  observation, with no marked restart between them;
- `incarnation`: a relation across a marked restart of a replica the line binds, whose
  binding does not name the incarnation that restart began, or names one that no restart
  began or that begins after the line's evidence;
- `intrinsic`: an intrinsic witness cites more than one observation, or binds a value other
  than `?` to an entity other than its replica, or a replica other than the observation's,
  which a site without a replica never matches;
- `construction`: a construction witness for `En`, or for an event whose actor is not
  `harness`.

Both stages of an ordered pair need a position: a probe observation, a stamped entry, or a
construction action. Presence-only evidence cannot order anything, so such a stage is
`unverifiable (no position)`; an `exact` witness has a position only when every item is
stamped. Values hold no space, comma, `@`, `[` or `]`; write a binding as `R=2@E1,v=5@E1`.

A held stage adds a feature that rewards inputs that get further. The first miss closes the
scripted prefix, except in the control run: drive no further event, call `Stages::handoff`,
which reports the handoff lost, and continue into the base's free-running phase and every
oracle.

Incarnations: mark every restart you drive with `restart(&[replicas])`, which returns `s`,
and bind the incarnation it began as `inc<s>`. In Shape A, add a marked call of `restart` to
the base's restart code (the subsystem rules name the known sites). A line that relates a
replica across a restart names the incarnation.

## Handoff and recovery

Handoff comes first; recovery is part of the continuation.

- Shape B drives `E1` to `E(n-1)` online, polling in simulated time, with a simulated-time
  deadline per stage: passing it is a miss, never a wait. Race every await on a reply of the
  system under test against the deadline with `commonware_macros::select!`; a dropped reply
  is a miss.
- `Stages::handoff` takes a plain closure that reads `En`'s witness and builds it inside the
  call, with no await or yield, and no value read before the call. The helper takes a
  position, calls it, and takes the handoff mark: the handoff holds only when nothing came
  between the read and the mark. If `En` does not hold then, it is missed, even if it held
  earlier. The positions date the read, not what it read, so give `En` an `exact` witness
  where one exists; an `intrinsic` one cites the latest observation at its site for its
  replica, found with `observations`, because `seen` returns the earliest and an older one
  may no longer hold.
- For a state defined by pending work or a withheld delivery, an `exact` observable shows
  the work still pending at the handoff: requested, and neither answered nor closed. Nothing
  the prefix does may complete, cancel or abandon it: never await its reply, drop its reply
  channel, or stop or restart its owner before the handoff.
- The continuation starts with every fault the prefix opened still in place: a crashed
  replica down, a partition, a held message. Release each no later than the base's first
  heal (GST), and start the base's liveness measurement after both. Network cuts go through
  the base's own fault input, as pinned partition fields, or are composed with the base's
  current cut; never heal the network yourself. Release crashed replicas and held messages at
  the handoff plus `d`, a knob in [0, the base's fault phase); a base without GST releases
  them before its liveness wait.
- The runtime deadline is the base's, which the subsystem rules give, plus the stage deadlines
  plus the largest release delay, which `Stages::budget` checks; for a base without one, pass
  `Duration::MAX`.
- Shape A imposes no cleanup, and its handoff is implicit: `En`'s witness, read in the handoff
  call after the run, counts only if it has a position and the trace holds a later
  observation of an honest replica in the same runtime instance.

## Control

The header names one withheld event, `Control: withholds Ek`, with k < n and `harness` as its
actor, chosen so that `En` cannot hold for the bound entities without it. Read
`STATELENS_REACH_CONTROL` only through `control()`; when it is set, skip `Ek`'s action, call
`Stages::withheld(k)`, and still drive every later event, the handoff check and the base's
oracles, so `En` gets an outcome. Write `Control: n/a` only when the card has no `harness`
event before `En` and every witness is `exact` or `construction`.

## Oracles

The base's free-running phase and every oracle run, called by path or copied verbatim, never
removed or weakened. In Shape A the base's oracles run inside its entry as they are, and a
History whose continuation they would not measure takes Shape B. In Shape B, re-base the
base's progress target on the handoff, in the measure the subsystem rules give for that base.
`Stages::done` follows the last oracle; returning before it reads as an oracle that never ran.
Stage checks are not oracles.

## Fabrication and the guard

- Events go through the network or the harness verbs. A scripted vote goes out only on its
  signer's own channel (INV-0008). A certificate you build names an honest signer only for a
  proposal that replica signed or would sign.
- List every injection, such as a journal seed, a floor start, a resolver delivery or a
  mailbox call, under `//! Injections:` with the INV ids whose ghost history it bypasses. The
  module never writes ghost state and never calls `record`.
- Shape B calls `commonware_consensus::simplex::statelens::set_compromised` with the indices
  it runs as real engines under a Byzantine identity, empty if none, before any engine
  starts; when the set is not empty, also check that every scheme's own index matches its
  position in `participants`, as the hooked runners do. Code copied from a hooked runner
  keeps its hook. Shape A relies on the base's hooked runner.

## Missing capabilities

A stage that needs what the edit contract cannot give, such as a new dependency, a change to
what the protocol does, or an item of `consensus/fuzz/core/` that is not public, is never
approximated: record it with `Stages::missed(k, "cannot: <capability>")`, list it under
`//! Missing:`, keep the prefix up to that stage and hand off; for `En`, record that miss
before you call `Stages::handoff`. A human adds the capability.

The prefix and witness code you write never panics on data of the system under test: no
`unwrap`, `expect` or index that its output decides, and no harness verb that panics on its
reply; a miss instead. Code copied verbatim from the base, and every oracle, keep their
panics: after the handoff a miss records nothing.

## Building

Build the scaffold with

    {{BUILD}}

until it builds with no errors and no warnings. If it reports that the package has no such
target, because the script writes the `[[bin]]` block only after your attempt, add that block
for the build (the base's block with `name` and `path` renamed) and remove it again before you
finish, leaving the manifest exactly as you found it. If you changed the system under test,
also run `{{CHECK}}`.

Never run the scaffold, any fuzz target, `cargo fuzz run` or `just run`: the script's replays
of fixed inputs are the only runs that judge a version, and a crash file any other run leaves
is treated as a finding. An attempt that changes no file ends the pair.

## Feedback

{{FEEDBACK}}

What each signal asks for:

- A veto, a guard, a build failure or a failed agent run: fix that, as reported.
- A miss with `cannot: <capability>`: nothing in the scaffold, unless an edit the contract
  allows, or another shape, gives the capability; otherwise a human adds it.
- `E1` missed: the setup: configuration, pinned and dependent fields, roles, elector or
  shape.
- A middle `Ek` missed: the event's content, recipient, channel or order; compare the
  trace's values and sites with what the stage expects.
- `En` missed, or the handoff lost: the knob domains, the timing, and what keeps the state
  pending at the handoff.
- `unverifiable`, or `witness rejected`: a witness that binds the relation: an intrinsic
  site for an existential line, otherwise an exact observable keyed by the bound entities,
  with positions where order matters.
- `weak` (the control still reaches `En` for the bound entities): withhold the event without
  which `En` cannot hold for them, or say in your reply that the History is not causal.
- A vacuous or missing control: name, or withhold, a later harness event before `En`; in the
  control run, drive every later event, the handoff check and the base's oracles.
- NO REPORT: use the helper, and never return before the base's oracles.
- SCAFFOLD ERROR: the reason the helper named.

Your earlier attempts' files are still in place: change them rather than start over, unless
the feedback asks for another shape.

## Subsystem rules

{{SUBSYSTEM_RULES}}

## Reply

Reply with: the shape; the witness of each stage; the knob layout; the injections; and the
missing capabilities.
