### Marshal (`consensus/src/marshal/`, `consensus/fuzz/marshal/`)

- Paths you may change: `consensus/src/simplex/` and `consensus/src/marshal/`, the system
  under test, whose tests the script reruns when you change it, and the fuzz package
  `consensus/fuzz/marshal/`.
- Shape A first: `marshal_e2e_standard_deferred_cert_mock_scenarios`, whose
  `NotarizationBlockSplitScenarioInput` fixes a scripted `template` and its pre-GST
  `actions`, with the wedge's real Byzantine engine behind the runner's hook. The
  `*_twins_split_header` targets draw their Twins case from the stream `raw_bytes` seeds:
  `run_twins_with_backend` samples `twins::cases` from it and `case_selector` only indexes
  that sample, so no field pins the case, and a History about it takes Shape B; a fixed case
  needs a marked constructor for the private fields of `mocks::twins::Scenario` and
  `RoundScenario`, which only `cases` builds.
- Shape B uses, without an edit, the `pub(crate)` items of `scenarios`: the harness
  `FuzzScenarioStandardHarness`, its verbs and `finish`, `RecordingBuffer`,
  `ScenarioHandoff`, `RecordingResolver` and `init_injectable`; and
  `marshal::end_to_end::twins`. With a marked visibility edit: `scenarios::runner::run`,
  whose journal seeding before the engines start is how Simplex engines start from a
  reconstructed state, and the private modules `scenarios::{adversary, elector, strategy}`
  and `end_to_end::{input, runner, scenario}`.
- The scenario-prefix runner starts no engine during its prefix, so a History whose events
  need running engines, such as TS-0001's, takes an end-to-end base.
- Known restart site, which gets a marked call of `restart` when a scaffold runs it: the
  `StoreOp::Restart` arm of `marshal::store` (`marshal_actor_standard_store_cert_mock`),
  which restarts the marshal actor. The list is guidance, not a complete one.
- Of the scenario SPEC, `consensus/fuzz/marshal/src/scenarios/specs/SPEC.md`, rules S1, S2,
  S4, S7, I1 to I3 and I5 apply; S3 becomes the handoff check; S5 and R9 become `cannot:`;
  S0 and S6 do not apply, because the card and the module header cite the source, and I4
  does not, because the edit contract allows marked edits. Add no `ScenarioKind` variant.
- Only the victim, `Node::B`, has an injectable resolver, with one armed delivery at a time,
  and in `N4F1C3` node 0 has no marshal. The harness verbs that panic when the system under
  test does not answer (`await_wrapper` after 5 s, `verified` and `certified` on a write that
  is not durable) and the polls of the existing scenario prefixes, bounded to 64 rounds, are
  not used where a reply of the system under test decides: race the reply against the stage
  deadline instead.
- The fault phase is 12 s in the scenario-prefix runner and `FAULT_PHASE`, 30 s, in the
  end-to-end disrupter runner, so a release delay is a knob below the base's. Heights stop at
  the epoch ceiling (`BLOCKS_PER_EPOCH`): leave enough height below it after the handoff for
  the liveness measurement.
- Progress and deadline: no marshal base sets a runtime deadline, so `Stages::budget` takes
  `Duration::MAX`. Each base measures finalized heights against its own baseline, which a
  Shape B continuation counts from the handoff: the scenarios target, one block past each
  correct node's height at GST (`check_scenario_progress`); Twins, `input.trailing_blocks`
  blocks of views after the prefix (`wait_for_liveness`); the scenario-prefix runner, one
  block past each honest node's height at its heal, `input.required_containers` only ending
  the fault phase early; the disrupter and poison targets (`run_liveness_phases`),
  `input.required_containers`, or after a fault phase that ends without it, the larger of
  that and one block past each honest node's height at the heal; the store target checks no
  liveness.
- The scheme: every type argument of the thin target's call names a Simplex type with the
  `cert_mock` certificate scheme, such as `SimplexCertificateMock`, as the base does.
