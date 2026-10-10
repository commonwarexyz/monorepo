### Simplex (`consensus/src/simplex/`, `consensus/fuzz/simplex/`)

- Paths you may change: `consensus/src/simplex/`, the system under test, whose tests the
  script reruns when you change it, and the fuzz package `consensus/fuzz/simplex/`.
- Bases: every `simplex_*` target but Mallory, whose custom mutator a scaffold cannot reuse.
  Shape A fits a History that the fields of `FuzzInput` fix: the partition, the
  configuration, the certify choice and the block filter. The Chaos, ByzzFuzz and Twins
  schedules are drawn from the random stream that `raw_bytes` seeds, so no field pins them,
  and a History about them takes Shape B. The `_state_cov` and `_hb` targets add coverage
  tables, which cost throughput.
- Dependent fields of `FuzzInput`, reset as its decoder sets them when you pin what they
  depend on: `degraded_network` depends on `partition` and `configuration`, `certify` on
  `configuration`, `block_filter` on `configuration` and on the fault bound drawn from
  `required_containers`, the fault rounds of `strategy` on `required_containers`, and
  `optimistic_views` on `term_length`.
- Usable without an edit, because a module under `crate::target_states` sees the private
  items of the crate root: `run_standard_once`, `run_audited_standard_once_with`,
  `run_twins`, `MockTwinsBackend`, `configure_block_filter`, `spawn_disrupter_with_relay`
  and `install_chaos_panic_hook`, and `chaos::runner::run`. Also the public items of
  `consensus/fuzz/core`, among them `setup_network`, `bounded_fuzz_runtime_config`,
  `fuzz_runtime_timeout`, `spawn_filtered_honest_validator`, `run_twins_with_backend`, which
  is hooked, and the partition helpers `apply_partition`, `link_peers` and
  `scheduled_partition`; and the mock reporter's maps keyed by view (`leaders`,
  `notarizations`, `nullifies`, `nullifications`, `certifications`, `finalizations`), read
  after the run for presence, or through a recording wrapper for order.
- With a marked edit: `chaos::runner::{run_with, restart_durable, enact, check_safety}` and
  the internals of `chaos::twins`; under `consensus/src/simplex/`, an accessor such as one
  for the private fields of `mocks::twins::RoundScenario`, which only `cases` builds.
- Known restart sites, which get a marked call of `restart` when a scaffold runs them:
  `chaos::runner::restart_durable` (Chaos) and `chaos::twins::restart_honest`
  (Chaos-Twins). The list is guidance, not a complete one.
- `start_validator_engine` in `consensus/fuzz/core` is private and starts every engine from
  `Floor::Genesis`; a History that needs another floor copies it into the module with the
  floor as a parameter.
- The Chaos-Twins runner's gate is the pattern for a stage: wait for a replica's own state
  before acting, and do not act in the wrong state.
- The fault phase of `consensus/fuzz/core` is `FAULT_PHASE`, 30 s, so a release delay is a
  knob in [0 s, 30 s).
- Progress and deadline: `run_standard_once`, `run_audited_standard_once_with` and `run_twins`
  run under `bounded_fuzz_runtime_config`, whose deadline is
  `fuzz_runtime_timeout(input.required_containers, <prefix views>)`, with 0 prefix views, or
  `twins_prefix_views(..)` for `run_twins`; the Chaos, Chaos-Twins and ByzzFuzz runners set
  none. Each base keeps its own liveness measure, which a Shape B continuation counts from the
  handoff, and keeps the base's condition for measuring at all: `run_standard_once` and
  `run_audited_standard_once_with` wait only when `should_bound_standard_liveness(&input)`
  holds, that is a `Connected` partition (`Static` and `Adaptive` fail it), a valid
  configuration and `BlockFilterChoice::None`; otherwise they sleep `MAX_SLEEP_DURATION` and
  assert no liveness, so FaultyNet, whose partition `fuzz` always sets to `Adaptive`, never
  waits. Where they wait, every reporter's latest finalized view must reach
  `input.required_containers`, so the target is the latest finalized view at the handoff plus
  `input.required_containers`; the audited driver leaves the notarize-omission victim out of
  that wait and instead checks after the invariants that its pending finalize recoveries drain
  (`unresolved_finalize_recoveries`, one `MAX_SLEEP_DURATION` sleep,
  `check_finalize_recoveries_drained`), a check the continuation keeps; the Twins campaign
  counts `input.required_containers` finalizations of views after the Twins prefix
  (`observe_liveness`), so count only views after the handoff as well; the Twins mutator checks
  no liveness, so add none; Chaos, ByzzFuzz and Chaos-Twins measure from their own heal or
  recovery, which follows the handoff, so their targets stay as they are: the larger of
  `input.required_containers` and one view past the finalized view at the heal (Chaos: the
  highest, `liveness_target`; ByzzFuzz: each node's own, `reach_gst_and_check_liveness`), and
  for Chaos-Twins one view past the highest at its recovery.
- The scheme: the thin target names `SimplexCertificateMock` or another `cert_mock`
  instantiation of `consensus/fuzz/core`, as the base does.
- Missing, reported as `cannot:`: journal seeding, because the package has no
  `commonware-storage` dependency and no dependency may be added.
