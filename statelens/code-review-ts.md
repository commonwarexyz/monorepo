# StateLens target-state reachability review

Reviewed on 2026-10-21 against the working tree at
`9bceaefe9af432c15e15ebbc11cf14413170c932`.

Scope: target-state selection, the synthesis prompt and edit contract, witnesses,
reach verdicts, and the trusted Simplex/marshal continuation. Particular attention
was given to `target-states.local/marshal/TS-0019.md` and `TS-0021.md`. This is a
static implementation review with isolated Python diagnostic checks, not a replay
of either failed generated scaffold.

## Assessment

There are concrete reachability blockers more consequential than the length of
the TS descriptions. TS-0019 contains configuration requirements its otherwise
appropriate bases cannot implement. Both cards require observations of internal
state that the supplied witness and continuation APIs do not provide. Default
selection also schedules incompatible card/base pairs, and synthesis receives no
feedback from exploring alternative fuzz inputs.

The findings below are high severity for StateLens's ability to construct and
verify these states. No critical Rust consensus defect was established. Some
findings are contradictions or omissions in the intended synthesis contract,
rather than implementation code violating that contract.

The earlier failed synthesis logs were removed. Therefore this review cannot
identify which blocker consumed the reported four hours, or establish that every
possible implementation of either protocol state is unreachable.

## Current campaign evidence

At inspection, `campaign/meta.json:6` named the `simplex` profile, and line 10 set
`bare: true`. The campaign had build logs, but no `summary.txt`, `reach/` reports,
or synthesis prompts. The completed build logs inspected reported successful
builds; there was no failed synthesis to analyze there.

Two implications matter:

- This campaign selects Simplex cards. TS-0019 and TS-0021 are in the marshal
  registry and will not be selected by a Simplex synthesis. Registry selection
  uses the profile's directory in `scripts/statelens.py:6479`; synthesis also
  rejects a profile that differs from the campaign's metadata.
- A bare campaign installs no beacons or invariant instrumentation. The current
  `campaign/plan.md` explicitly states that no witness can be intrinsic. This
  leaves internal-state targets dependent on the exact observation API described
  in finding 1.

These are observations about the current run, not proof that the deleted run had
the same configuration. The running campaign was not changed or interrupted.

## 1. MUST FIX - High: required internal-state witnesses have no supplied observation path

**Status: FIXED, with a harness branch to merge.** (a) Branch `denis/tss-observation-reads`
of the fuzzing repository (off `fuzzing` 082a6a420, `consensus/fuzz/**` only) adds keyed
read-only observations: `MarshalReads::cached` and `PrefixContext::cached_block(replica,
digest)`, through the buffered broadcast mailbox's `get` on standard bases and the shard
engine's `get_by_digest` on coding bases, neither of which opens a wait or changes what the
cache holds; and a coding automaton log, `PrefixContext::coded_automaton::<D>(replica)`
(`AutomatonEvent<D = Sha256Digest>` made digest-generic), with certify requests and their
outcomes. Runs without a prefix are unchanged (the wrapper only forwards without a tap).
Core, marshal and simplex fuzz tests pass (176 and 360), clippy is clean. The reads are
asynchronous, so they witness stages before the handoff; `En` stays log-observable, and
TS-0019 and TS-0021 were restructured so their last stage holds what the logs show. (b) A
version that declares a missing capability ends its pair; cards declare `cache-reads` and
`coding-certification` in `needs`, which a checkout offers only when its harness has the
reads, so the cards are classified unsupported until the branch is merged. The binding
checks are unchanged.

Relevant locations:

- `scripts/statelens.py:6838`: an `x as Ek` binding cannot be `?` and must match
  the earlier event's value.
- `scripts/statelens.py:6864`: an intrinsic witness can identify at most one
  concrete entity, the observed replica. It cannot bind a concrete view, digest,
  height, or another replica.
- `scripts/statelens.py:6874`: construction cannot witness the final event.
- `prompts/synthesize.md:113`: synthesis cannot add ghost state or instrumentation.
- `scripts/statelens.py:9943`: the trusted harness is protected against edits.
- `../consensus/fuzz/core/src/continuation.rs:381`: `MarshalReads` exposes only
  finalized block digests and the processed height.
- `../consensus/fuzz/core/src/continuation.rs:2948`: coding automaton logs are not
  recorded; reading one cuts the trace.

TS-0019's E8 requires current cache absence for the particular digest `d` on `R`,
its delivery provenance, and certification still pending for the particular view
`v`. TS-0021's E9 requires current shard-cache membership for `x` at `v`, after
rejection and subsequent processed progress. Its E6 also requires evidence of a
failed certification, not merely a nullify vote that could have another cause.

These are concrete relations to earlier events, not existential observations.
An otherwise ideal campaign beacon at the exact state cannot witness them under
the intrinsic schema: supplying the real entities yields `witness rejected:
intrinsic`; replacing referenced entities with `?` yields `witness rejected: as`.

The exact recorders do not close the gap. A message delivery does not establish
that the component accepted it or currently retains the corresponding cache
entry. Finalized and processed queries do not expose shard-cache membership or a
certification result. Standard automaton logs can help with pending
certification, but do not provide a current broadcast-cache snapshot. Coding
automaton logs are unavailable altogether.

Adding a getter to an actor does not by itself give the prefix access to the
running actor: the harness owns and starts it, and the supplied context carries
no handle for these reads. The final handoff also requires synchronous evidence;
an earlier asynchronous answer alone does not establish that a mutable entry
still exists at handoff.

**Why it matters:** the protocol state can occur while the framework remains
unable to certify that it occurred. More code generation or additional coarse
beacons cannot repair that missing observation contract. `UNVERIFIED` must not be
interpreted as proof of protocol unreachability.

**Suggested fixes:**

a) Add a target-state observation preparation step before freezing the trusted
harness. Supply read-only, identity-preserving observations keyed by replica,
round and digest, including coding certification results and synchronous current
cache membership. Preserve the existing restrictions on changing protocol
semantics.

b) Until those capabilities exist, preflight every History event against the
available observation API and report an unsupported observation before invoking
the synthesizer. Keep the entity-binding checks; weakening them would create
false reachability reports.

## 2. MUST FIX - High: TS-0019 requests leader and adapter choices its bases cannot supply

**Status: FIXED.** TS-0019 lost its adapter knob (the bases with B's marshal channels run deferred) and names v as "the first view B leads after p" instead of a pinned elector; it now says `needs: [byzantine-marshal]`. The same pinned-elector rows were rewritten in TS-0001, TS-0005, TS-0007, TS-0011 and TS-0018. The state-analyst prompt and the subsystem Context now say that a leader-dependent view is named by its leader and a configuration takes only values the bases run (with each base's leader schedule); the synthesis prompt treats a configuration, elector or leader the base does not run as `cannot:` and takes card view numbers from `cx.leader(view)`.

Relevant locations:

- `target-states.local/marshal/TS-0019.md:100`: the adapter knob's source value
  is `Inline`.
- `target-states.local/marshal/TS-0019.md:101`: `(p, v)` is restricted to
  `(0, 1)`, `(2, 3)`, `(5, 6)`, with the elector supposedly pinned so B leads v.
- `../consensus/src/simplex/elector.rs:410`: the rotating leader is selected by
  `(epoch + term_index) % committee_size`, using the identity permutation when
  no shuffle seed is configured.
- `../consensus/fuzz/marshal/src/marshal/end_to_end/runner.rs:403`: standard
  disrupter and poison bases force term length one.
- `../consensus/fuzz/marshal/src/marshal/end_to_end/runner.rs:588`: these
  standard bases construct `DeferredMarshal` explicitly.
- `../consensus/fuzz/core/src/continuation.rs:720`: `Pins` offers neither an
  adapter selector nor an elector override.

On the ordinary standard disrupter and poison bases, B is participant 0 and the
epoch is 0. Therefore B leads views 4, 8, 12, and so on. The card's allowed views
1, 3 and 6 elect participants 1, 3 and 2 respectively. None satisfies E1.

The synthesis prompt tells the agent to derive a view that the required leader
leads, while this card restricts the view domain to values that do not work. The
agent must violate the card or fail the stage. It cannot solve this by pinning an
elector: the trusted prefix API has no such capability.

There is a separate canonical-input conflict. The empty input must select the
source adapter, `Inline`, but the standard bases with usable marshal injection
channels run `Deferred`. The special block-dissemination base can give B view 1,
but it also runs Deferred. Inline Twins bases exist, but the prefix has no B
marshal channels on Twins, so it cannot perform the card's block sends and
eviction sequence.

**Why it matters:** these are unsatisfiable card/base requirements before the
cache race is considered. Longer synthesis does not make the missing pins exist.

**Suggested fixes:**

a) Describe the attack view symbolically as a future B-led view, derive its parent
from actual chain progress, and choose an adapter the selected base supports.
For a Deferred base, use Deferred as the canonical adapter. Treat a fixed source
view number as incidental when the state depends on leadership and ordering.

b) If literal views and both adapters are required, add explicit trusted setup
capabilities for those choices, then verify that the honest engines and the
prefix's leader lookup use the same configuration.

## 3. MUST FIX - High: selection spends synthesis attempts on incompatible bases

**Status: FIXED.** Selection intersects card requirements with base capabilities before any agent work: a marshal card scoped to one stack (`standard` or `coding`) runs only on that stack's bases, and a new optional card key `needs` (`byzantine-marshal`, `first-term`) excludes bases that do not offer it (Twins for B's marshal channels; all but `simplex_cert_mock_byzantine_first_leader` and the marshal block dissemination base for the first term). Excluded pairs print as `unsupported` and are never synthesized; a selection with none left exits 1. Lint checks `needs` values per registry. Tests: `ScaffoldSelection.test_a_card_runs_only_on_bases_that_offer_its_stack_and_needs`, `TargetStateLint.test_a_card_names_what_it_needs_of_its_base`.

Relevant locations:

- `scripts/statelens.py:6501`: base selection considers name patterns, not the
  card's required stack or capabilities.
- `scripts/statelens.py:6517`: each selected card yields a pair for every chosen
  base.
- `scripts/statelens.py:11651`: `refuse_bases` checks only whether a trusted
  continuation adapter exists.
- `prompts/subsystems/marshal-synthesize.md:61`: Twins prefixes have no B marshal
  channels and cannot use the honest marshal gates.
- `scripts/statelens.py:10869`: each remaining pair can consume four agent
  attempts.

With only the two card IDs selected and no base restriction, the current code
keeps nine supported bases per card after refusing bases without adapters:

| Card | Wrong stack still selected | Additional incompatible Twins base(s) | Pairs left after those exclusions |
|---|---|---|---|
| TS-0019, standard block cache | 3 coding bases | 3 standard Twins bases without B marshal injection | 3 |
| TS-0021, coding reconstruction cache | 6 standard bases | 1 coding Twins base without B marshal injection | 2 |

Thus 13 of 18 pairs cannot express these Histories through the supplied prefix
capabilities, independently of the witness problem. The three remaining TS-0019
bases also have the canonical configuration conflicts in finding 2.

**Why it matters:** up to 52 agent attempts can be scheduled for those 13
incompatible pairs. With the current alphabetical ordering, TS-0019 starts on
coding bases. This can spend substantial time before reaching a suitable stack.
This finding is conditional on selecting all bases; an explicitly restricted run
does not incur every incompatible pair.

**Suggested fixes:**

a) Associate each base with machine-readable capabilities: stack, adapter,
Byzantine marshal injection, marshal gates, available recorders and setup pins.
Associate cards with their requirements and intersect them before agent work.

b) As an immediate operational measure, restrict TS-0021 to a coding disrupter or
coding poison base. For TS-0019, first correct its configuration requirements,
then restrict it to a standard base with marshal injection. Report incompatible
pairs as unsupported rather than spending repair attempts on them.

## 4. MUST FIX - High: refinement never explores the parameters it delegates to fuzzing

**Status: FIXED, with a deliberate simplification.** (a) When the canonical replay misses a stage, the reach check replays up to `STATELENS_REACH_INPUTS` (64) other inputs of seeded random bytes (sha256 counter mode, so deterministic), which vary every knob and unpinned base field; the input that held the most stages is replayed as the control too, and its verdict, path and the knob indices it picked (a new helper line `knobs <i>,...`) go to the next attempt's feedback, the console and the report. A failing search input is kept as a stray failure and makes the attempt a CRASH (finding candidate), which ends refinement. The verdict stays the canonical replay's, so revalidation, final replays and run lines are unchanged; the search is bounded random sampling, not coverage-guided fuzzing. (b) An agent run is stopped after `STATELENS_AGENT_TIMEOUT` (3600 s) with a veto and a log line. Tests: four new `Synthesize` tests.

Relevant locations:

- `prompts/synthesize.md:21`: the synthesis agent may build, but cannot run the
  scaffold, tests or fuzzer.
- `scripts/statelens.py:10561`: `replay` always rewrites the canonical input to
  zero bytes and executes only that input.
- `scripts/statelens.py:10665`: canonical and control replays feed the reach
  verdict and the next repair attempt.
- `scripts/statelens.py:10419`: the agent invocation supplies no timeout to
  `run_logged`.

The agent generates parameterized code, but every synthesis-time execution uses
the same empty input. The control changes an environment variable; it does not
search the knob space. Final replays also use the empty input. No intermediate
fuzzing phase supplies a successful alternative input or deeper reach evidence
to the repair loop.

This differs materially from the paper's refinement loop. Section IV-D describes
fuzzing each generated harness and then using hierarchical reachability feedback
to revise it. The paper does not establish that StateLens's replacement with
fixed-input replay is sufficient for these consensus states.

Source: [SyzHarness, sections IV-D1 through IV-D4](https://arxiv.org/html/2609.23889v2#S4.SS4).

**Why it matters:** for the transient-cache target especially, the setup can be
structurally correct while the default schedule misses the final pending-work
window. The repair loop then sees only that one miss and asks the model to change
code instead of discovering a better input. This does not itself make the
protocol state impossible, and partial scaffolds can still be retained and
fuzzed later; it makes synthesis-time feedback incomplete.

The unbounded agent call also means four hours can elapse inside one synthesis
attempt without reaching the script's replay/feedback step. The four-attempt
limit does not bound the duration of an individual attempt. Without the removed
logs, that remains a possible explanation of elapsed time, not a diagnosis of
the earlier run.

**Suggested fixes:**

a) After a prefix builds, run a bounded search over its permitted parameters and
runtime seeds. Keep inputs with deeper valid stage evidence, replay a selected
input deterministically, and run the control with that same input. Preserve
canonical replay as a separate check rather than the only source of feedback.

b) Bound agent attempts and provide an explicit build-to-execution checkpoint so
runtime evidence reaches the repair process promptly. For timing-dependent
targets, expose the relevant allowed schedule choices to the search.

## Validation and limits

The following existing checks passed:

```sh
cd statelens/scripts
python3 -B -m unittest \
  test_statelens.ReachCheck \
  test_statelens.ScaffoldSelection \
  test_statelens.SynthesisPromptRules
```

Result: **54 tests passed**. These verify the current behavior; they do not
establish that the two actual cards have a supported construction and witness
path.

Five additional isolated diagnostic tests were written outside the checkout at
`/private/tmp/statelens-review.vUstlR/test_review_regressions.py`. Each fails an
assertion for the missing behavior it examines:

1. TS-0019 selects coding bases.
2. TS-0021 selects standard bases.
3. The real witness validator rejects an ideal intrinsic observation with the
   final bound entities of either actual card.
4. Canonical, control and final replay invocations all use `b""`.
5. TS-0019's view domain contains no B-led view under the ordinary rotating
   base's leader arithmetic.

The selection and validator tests call the actual Python implementation. The
replay test mocks subprocess execution to inspect which input is passed; it does
not demonstrate a real scaffold reaching under another input. The leader test
evaluates the arithmetic from the Rust elector against the actual card domain;
it is not a Rust consensus execution. These diagnostics establish the listed
boundaries, not that a particular deleted scaffold failed for any one of them.

No fuzzer, consensus simulation, Rust build, or campaign mutation was performed
for this review. The only repository file added by the review is this report.

## Recommended order

Resolve card/base compatibility and the exact observation path before spending
another synthesis budget on these cards. Correct TS-0019's configuration domain,
provide keyed state observations for both cards, then add bounded parameter
search to the refinement loop. Shortening evidence excerpts may reduce prompt
cost, but it cannot resolve these capability and configuration contradictions.

## Follow-up: TS file structure and information sufficiency

The follow-up examined the Statements, Histories and Knobs of all 18 tracked and
local cards, the extraction prompt, the template, and the History/Knobs parser.
It also inspected selected rationale, evidence and implementation code where
needed to distinguish contradictory instructions from legitimate variations.

The cards provide substantial background about why the states matter. Several
do not provide an unambiguous construction contract. Adding more historical
explanation would not supply the missing decisions: which variant is canonical,
which constraints are fixed, which observations establish completion, and which
conditions must remain true until handoff.

This extends the review to specification ambiguities as requested. The following
findings distinguish a literal contradiction from a missing definition or a
format limitation.

## 5. MUST FIX - High: TS-0020 E4 simultaneously requires and forbids a certificate

**Status: FIXED.** E4 now reads "holds a nullification of t ..., and holds no notarization or finalization of any view of T and no notarize vote for any view of T". The state-analyst prompt adds the review rule: check every possession requirement against every exclusion on the same replica, object and time. TS-0020 also says `needs: [first-term]`, since its History has B lead the first term after genesis.

`target-states.local/simplex/TS-0020.md:93` requires A to hold a nullification of
view t, then says A "holds no notarize vote or certificate of any view of T".
E1 establishes that t belongs to T. A nullification of t is a certificate for a
view of T. Both clauses cannot hold at the same time under the protocol's normal
terminology.

This affects the canonical construction as well as variations: E4 is part of
every History ordering. An agent must either fail E4 or silently reinterpret
"certificate" to exclude the very nullification the check requires.

**Suggested fixes:**

a) State the actual exclusion, for example: A holds the nullification of t but no
notarization or finalization of any view in T, and no notarize votes for those
views. Confirm that those are the intended restrictions before editing the card.

b) Add a card review rule that every positive possession requirement is checked
against all negative requirements on the same object, replica and time interval.
This is a semantic review, not just a Markdown lint.

## 6. SHOULD FIX - High: TS-0021 does not define a unique canonical construction

**Status: FIXED.** Shard recipients default to `R and S`; the repeated-attack knob is removed (the canonical construction has no prior attack); the view gap is `w - v` with values 1, 2 and 5, each giving w an honest leader; E6 accepts either rejection of the claimed height (outside the parent's epoch, or not one above the parent's height) and its Check is that the certify request returned false. Lint rule 13 now requires each Domain to start with its Source value, spelled the same, as the one default; seven other rows across TS-0001, 0005, 0007, 0011, 0015, 0017 and 0020 were respelled to comply.

The Knobs table in `target-states.local/marshal/TS-0021.md:94` mixes enumerated
choices, descriptions of those choices, and historical source observations:

| Field | Present wording | Missing decision |
|---|---|---|
| Shard recipients | Domain: R and S; S and T. Source: "two honest" | Which pair does byte zero select? Both choices satisfy the source wording. |
| Prior B-led attack views | Domain: 3, 0, 1. Source: "every one" | How many prior attacks does the canonical input perform, and before which selected p? |
| Gap to w | "views between v and w": 1, 2, 5 | Is the number `w - v` or `w - v - 1`? Which choices also give w an honest leader? |
| Repeated attacks | B "also plays E3-E7" before E2 | How are v, x, m and the parent rebound for each iteration, and which results are retained? |

The synthesis contract makes byte zero select the source value at domain index
zero. "Two honest" and "every one" do not determine those selections. Silently
taking the first listed alternative is an implementation choice, not information
the source-value cells supply. The repeat count also affects the chain prefix,
the finite coding record window, and the setup budget.

There is an additional ambiguity about rejection. E6 describes finding a
noncontiguous height. The source value `u64::MAX`, under the current fixed
20-height epoch configuration, fails epoch membership before reaching the
contiguous-height check in
`../consensus/src/marshal/coding/validation.rs:94`. E6's Check requires only a
failed certification. A generator following the event description can therefore
target a different validation path than one following only the Check.

**Suggested fixes:**

a) Give every alternative a stable identifier and name one exact default. Define
derived values with equations and constraints, including the meaning of the view
gap. Give a repeated prelude its own bindings and an explicit stopping condition.
If the number of prior attacks is incidental, begin with a clearly specified
zero-attack prelude rather than leaving it to interpretation.

b) Decide whether the target needs any certification rejection, or specifically
the height-contiguity rejection. For the latter, constrain the candidate height
to the parent's epoch while making it noncontiguous. For the former, say that
epoch rejection is permitted. Do not infer the desired rejection path from a
historical bug description.

## 7. SHOULD FIX - High: the format conflates construction variants, mutations and stage outcomes

**Status: FIXED.** TS-0001's "E6 first" variant and its `Order:` line are removed (the SPEC 18.3 copy is synced); TS-0018's elector claim now says participant 0 leads index 0 modulo 4 terms, and its term-length row states the joint constraint. The state-analyst rules now require every knob value to keep every Check and Holds line true as written (a choice that changes a required outcome is another card), dependent choices to be one knob or a stated constraint, and timing domains to stay inside the feasible window (the rule to straddle a timeout is gone).

`templates/target-state.md:22` supplies one History and one Knobs table, with no
field describing how a knob changes a stage's required outcome. Meanwhile,
`prompts/state-analyst.md:85` requires each knob value to keep the History
possible, but line 89 requires timing domains to straddle a relevant timeout.
Crossing such a timeout can change whether work remains pending or whether the
replica exits the required view. The format needs to distinguish alternative
valid constructions from inputs intentionally allowed to miss the target.

The model card illustrates the problem. In `target-states/marshal/TS-0001.md:50`,
E5 requires R to reject the proposal and its verification to fail. The ordering
knob at line 66 also permits E6 first, with verification pending, followed by a
dropped stale rejection and a nullify vote on a timeout. A negative application
answer, a negative answer applied by consensus, and a stale answer discarded by
consensus are different observables. The card does not specify which meaning of
"failed" applies in that variant. Reversing two events alone does not resolve
that difference.

This is especially consequential because `prompts/state-analyst.md:130` tells
every extractor to use TS-0001 as its model.

Other coupled choices have the same format problem. For example,
`target-states/simplex/TS-0018.md:189` makes a view choice depend on a particular
elector and term length, while line 191 varies term length separately. The card
does not define a joint domain or a constraint that prevents incompatible
combinations. Its claim about participant 0 leading indices 3 modulo 4 also
disagrees with the current plain epoch-0 round-robin implementation, which
selects participant 0 at indices 0 modulo 4.

**Suggested fixes:**

a) Keep the History's required outcomes fixed across all choices advertised as
valid constructions. Split variants with different required outcomes into
separate cards, or give them explicit conditional predicates and witnesses.

b) Label mutations that are intentionally allowed to miss the target, separately
from setup choices guaranteed to preserve its feasibility. Define dependent
choices jointly or provide constraints; do not imply that every row is freely
combinable. Clarify TS-0001 before using it as the extraction exemplar.

## 8. SHOULD FIX - Medium: the template omits definitions needed to turn prose into witnesses

**Status: FIXED, by rules rather than new sections.** The state-analyst prompt now requires each line to name its milestone (sent, received, accepted, cached, stored, durable; requested and neither answered, closed nor canceled), the identity an entity is, how long a restriction lasts, an exclusion's transport and whether it bounds sends or receipt, and setup stated in an event; the Holds line must be observable from the harness's logs at the handoff. Lint rule 12 rejects an event with no action and a Check or Holds line that states nothing. The synthesis prompt carries the card without its generated Source excerpts and names the card's path for reading them. The proposed eight-part authoring structure was not adopted, to keep the format and the 18 cards stable.

The following distinctions materially affect scaffold behavior, but the format
has no required place for them:

- Entity types and identities: a view is not a height, and a coding block digest
  is not its coding commitment. TS-0021 calls x a block while using it across
  proposal signing, reconstruction and cache membership. Define which identity
  each operation binds and how the identities relate.
- Observation boundary: "sent", "received", "accepted", "cached", "stored"
  and "durable" are different milestones. TS-0019 E7 needs actual cache
  insertion, not an enqueued send. E8 needs actual eviction, not merely ten
  filler sends.
- Work ownership: "outstanding" should identify the request and owner and mean
  requested, not completed, not closed and not canceled, rather than just "a
  request was logged earlier". The synthesis prompt defines this more precisely
  than the card template does.
- Temporal scope: TS-0019 E8 says B withholds the block and its votes "from then
  on". Does that last until handoff, through the release delay, or throughout the
  continuation? The trusted continuation resumes the base's adversary at release.
  A card should specify the interval over which its restrictions apply.
- Background traffic: TS-0019 requires that no honest replica sent R the block.
  The construction must cover both broadcast and backfill responses. A card can
  state that exclusion without specifying a particular implementation of the
  gates, but should make its transport and time scope explicit. A receiver gate
  proves nondelivery, not that the peer never sent the block. Decide whether the
  intended condition excludes sends or only excludes receipt by R.
- Setup versus the target: a finalized starting floor, extra stored blocks,
  particular leaders, and epoch membership should be stated as explicit setup
  requirements with a feasible construction route. They should not be hidden in
  a compound E1 or left only in non-binding Observation hints.

The current parser cannot establish that these definitions exist. Its
`HistoryEvent` at `scripts/statelens.py:1260` retains only the actor and entity
references. It does not retain the action or predicate prose. The Knobs linter
at line 1426 checks table shape and event numbers, but not unique defaults,
membership in a domain, cross-knob constraints or feasibility.

All 18 actual cards pass those History/Knobs structural checks. As a diagnostic,
replacing TS-0021 with nine events having no action descriptions and no Check or
Holds predicates also passes them. Thus "lint clean" does not mean sufficient
or unambiguous, and the reach validator's binding checks should not be described
as semantic verification of the prose.

**Suggested fixes:**

a) Add required setup, typed entities, explicit handoff predicates, temporal
restrictions and witness requirements to the authoring contract. Keep ordinary
Rust API syntax and incidental scheduling choices out of that contract.

b) Reject empty predicates and non-unique defaults mechanically. Require a
semantic review of each valid variant and its observation route before
synthesis. If machine checking of predicate meaning is required, retain a small
structured predicate representation instead of only actor/entity names.

### Length: measured cost, without attributing the four-hour failure to it

Most card length is generated evidence, not the active construction description:

| Card(s) | Total lines | Lines before Source excerpts | Generated excerpt section |
|---|---:|---:|---:|
| TS-0019 | 377 | 114 | 263, about 70% |
| TS-0021 | 317 | 107 | 210, about 66% |
| TS-0018 | 1,276 | 222 | 1,054, about 83% |
| All 18 cards | 7,558 | 1,985 | 5,573, about 74% |

These are line counts, not token measurements. The synthesis prompt embeds the
entire card on every attempt (`scripts/statelens.py:10397`), including the
historical excerpts. Their size therefore increases the context supplied to the
agent. No timing or context-utilization experiment was run, so this review does
not claim they caused a particular slowdown or exhausted a context window.

Keep pinned evidence available for provenance and targeted code reading, but
make the active contract concise and authoritative. Supply decisive excerpts
initially and retrieve the rest when needed. In particular, 107-114 lines of
active content in TS-0019 and TS-0021 is not by itself evidence of excessive
complexity. Contradictory or undefined instructions within that content are the
more direct problem.

### Proposed authoring structure

This is a proposed format change, not a file that the current strict section and
front-matter parser would accept unchanged:

1. **Target:** one precise state at handoff, with its historical preconditions.
2. **Requirements and setup:** protocol variant, committee, epoch constraints,
   required controls and read capabilities; symbolic leadership constraints.
3. **Entities:** typed names, role distinctions and full proposal identities.
4. **Required sequence:** essential causal edges, separating an action's issue
   from the system's completion of it. Avoid incidental literal view numbers.
5. **Handoff predicate:** an explicit conjunction, plus historical facts that
   must already have been witnessed. State what must remain pending or absent.
6. **Choices:** exact canonical values, valid alternatives, dependent domains,
   and separately identified mutations that may miss the target.
7. **Witness requirements:** the exact relation each check must observe and
   whether the current harness exposes it. Observation is a prerequisite to
   synthesis, not a guess postponed until code generation.
8. **Evidence appendix:** source rationale and pinned excerpts, read on demand.

For TS-0019, the handoff contract could explicitly separate these requirements:

```text
Current at handoff:
  R accepted a valid notarization for (epoch e, view v, digest d).
  R's broadcast cache contains no block with digest d.
  R's certification request for (e, v, d) exists and is neither
  completed, closed nor canceled.

Established earlier in this execution:
  B is the elected leader of (e, v).
  P and Q supplied their own notarize votes for the same full proposal.
  R's cache accepted d from B, then evicted d after distinct filler blocks.
  No honest peer sent d to R by broadcast or backfill before handoff.

Scope of withholding:
  Explicitly state whether the restriction ends at handoff or at release.
```

This clarifies what must be proved without supplying the scaffold's Rust code.
It still requires the missing observation capabilities from finding 1.

### Follow-up validation

The existing `test_statelens.TargetStateLint` suite passed: **14 tests**. Direct
History/Knobs checks also passed for all 18 cards; these checks did not run
citation/excerpt validation or establish semantic feasibility.

Additional static diagnostic tests are at
`/private/tmp/statelens-review.vUstlR/test_ts_contract.py`. Three expected failures
expose the literal TS-0020 contradiction, ambiguous TS-0021 source selections,
and acceptance of empty action/predicate text. A positive control confirms that
TS-0007's prohibition is on notarize votes: its nullify-vote timing variation
does not by itself contradict that prohibition. These are content and parser
checks, not consensus executions or reproductions of the removed campaign.

The TS files, template, prompts and running campaign were left unchanged. Only
this review document was extended.

## Re-review of the fixes (2026-10-21)

1. MUST FIX - High: the observation blocker remains open.
   **Status: FIXED, with the harness branch of finding 1 to merge.** The keyed reads exist on
   branch `denis/tss-observation-reads`: `cached_block` (block-cache membership) and
   `coded_automaton` (coding certification answers), used as `exact` witnesses stamped at the
   answer for stages before the handoff, never `intrinsic` ones. Until a checkout has them,
   TS-0019 (`needs: [byzantine-marshal, cache-reads]`) and TS-0021 (`needs:
   [byzantine-marshal, cache-reads, coding-certification]`) are classified unsupported by
   selection, which reads the checkout's `continuation.rs`. The binding checks are unchanged.
2. SHOULD FIX - High: TS-0019 still contains impossible knob alternatives.
   **Status: FIXED.** v is anchored independently, "the first view B leads; the second; the
   third", and E1 derives p as v - 1.
3. MUST FIX - High: input search misclassifies scaffold errors as findings.
   **Status: FIXED.** A failing search replay is classified as a canonical or control replay
   is: a SCAFFOLD ERROR goes to the next attempt's feedback ("ended in a scaffold error:
   <reason>") and refinement continues; only anything else is a finding candidate. Test:
   `Synthesize.test_a_searched_scaffold_error_is_fed_back_and_refinement_goes_on`.
4. SHOULD FIX - Medium: searched control crashes get an incorrect reproducer.
   **Status: FIXED.** The search failure keeps its mode with its input; the report's note
   says it failed in its control replay, and the replay line sets
   `STATELENS_REACH_CONTROL=1`. Test:
   `Synthesize.test_a_searched_control_failure_reproduces_with_the_control_switch`.
5. SHOULD FIX - High: search feedback gives contradictory and unjustified repair instructions.
   **Status: FIXED.** The feedback keeps the card's domains, source value first: a better
   input whose knobs picked the source values points at unpinned base fields, one that picked
   other values leaves the choice of another source value to the card's review, and the
   empty input must reach with the pins and timing the scaffold controls. A search that found
   no better input is reported as inconclusive. The synthesis prompt says the same.
