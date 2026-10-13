### Simplex (`consensus/src/simplex/`, `consensus/fuzz/simplex/`)

- Paths you may change: `consensus/src/simplex/`, the system under test, whose tests the
  script reruns when you change it, and in the fuzz package `consensus/fuzz/simplex/` only
  your module under `src/target_states/`.
- Bases with a trusted continuation, and B at the release: the Standard family
  (`simplex_cert_mock`, `_state_cov`, `_hb`, `_hb_state_cov`, `_faulty_net`,
  `_byzantine_first_leader`, `_audit`), whose B is participant 0 under N4F1C3, with one
  Disrupter from the release, and none under N4F0C4; and the Twins bases
  (`simplex_cert_mock_twins_campaign` and `_twins_mutator`, each also `_audit`, `_hb` and
  `_state_cov`, and `simplex_cert_mock_shuffled_twins_mutator`), whose B is the compromised
  participant the base's Twins case picks, under N4F1C3 always, with the twin pair from the
  release: a primary and a secondary engine for the campaign, a primary engine and a
  Disrupter for the mutator. The script refuses every other base. The `_state_cov` and
  `_hb` targets add coverage tables, which cost throughput.
- Pins, through `Pins`: `term_length`, which cuts a lookahead the decoder would not draw for
  it; `lookahead`, at most the term length plus two; and `configuration`, N4F1C3 or N4F0C4
  (N4F1C3 only under Twins), which resets the certify choice, the degraded network and the
  block filter as the decoder draws them. Pin N4F0C4 only for a History of four honest
  replicas: the base then runs no Byzantine actor.
- Leaders: the runner builds every honest engine with the base's elector, so a Twins base's
  scripted rounds choose the leaders of the views up to `cx.scripted_views()` during the
  prefix, and its split applies from the release. Derive a view from `cx.leader(view)` so
  that the leader the History needs leads it, rather than assuming round robin.
- The base's links: the Standard drivers link every pair at 10 ms (a static partition cuts
  some pairs; a degraded network slows the last participant's), the Twins drivers at
  500 ms +- 500 ms. Change one only with `cx.set_link`, which the release reverts. The base's
  network faults (an adaptive partition schedule, a dropped block) and the Disrupter's
  faulty views start at the release, re-based on the highest view finalized then.
- Restarts: `cx.crash` and `cx.restart` stop a replica and bring it back from its journal on
  its partition, with its reporter, behind its gate and recorders; mark each with
  `restart(&[replica])` and bind the incarnation it began. The release restarts a replica
  still down.
- The fault phase of `consensus/fuzz/core` is `FAULT_PHASE`, 30 s, so a release delay is a
  knob in [0 s, 30 s).
- The prefix budget is cut to `MAX_PREFIX_BUDGET`, 60 s: keep the stage deadlines, setup
  included, within it.
- After the release every base runs its faults and B's actors for `MAX_SLEEP_DURATION`, 15 s
  of simulated time, and then its safety oracles; it never waits for finalizations.
- The scheme: the module names only `cert_mock` instantiations of `consensus/fuzz/core`, such
  as `SimplexCertificateMock`, as the base does.
- Missing, reported as `cannot:`: journal seeding, because the package has no
  `commonware-storage` dependency and no dependency may be added; an engine under B's
  identity during the prefix; a twin pair before the release; and an engine that starts from
  another floor than genesis.
