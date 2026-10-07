### Simplex (`consensus/src/simplex/`)

- Editable code: non-test code in `consensus/src/simplex/`, except `mocks/` and
  `scheme/`.
- Components: the voter, batcher and resolver actors in `consensus/src/simplex/actors/`,
  which exchange messages through mailboxes, and the journal replay path on restart.
- Adversary: the fuzzer runs honest replicas next to Byzantine ones, which equivocate,
  mutate messages and split the network. Some targets of `consensus/fuzz/simplex` also
  crash honest replicas and restart them from their journal (the Chaos, Chaos-Twins and
  Mallory drivers), so journal replay runs while fuzzing.
- Byzantine participants the guard does not know: tests wrap a participant's scheme in
  `mocks::wrapped::Scheme`, which runs the real engine with a misbehaving scheme. With
  `Behavior::CorruptSignature`, used for participant 0 of the `test_invalid_*` tests in
  the test gate, every vote it signs carries a corrupted signature: its engine publishes
  those votes, and every other replica rejects them, so a count of distinct voters that
  includes them can reach a quorum no replica can certify. With `Behavior::RecoveryFailure`
  certificate assembly fails even from a valid quorum.
- Fuzz targets: every consensus target uses the `cert_mock` scheme, which hides the
  signer set.
- Replica index, in `consensus/src/simplex/` only (marshal code has its own rule):
  `self.scheme.me()` wherever a scheme is in scope. The batcher and the
  resolver actors hold one; the voter actor does not, because `Actor::new` moves the
  scheme into `StateConfig`, so read the index from its `State` through a
  `// [statelens] me` accessor rather than keeping a second copy. Where no scheme is
  reachable at all, add a `// [statelens] me` field of type
  `Option<crate::simplex::statelens::Participant>`, set where the struct is created.
- Asynchrony worth probing: the view advances while work is outstanding, a timeout races
  a certificate, a verification or certification result arrives after the state moved
  on, equivocation is detected after acceptance, state is rebuilt from the journal.
- Where the voter decides and where it commits are different functions, separated by a
  reply from the application: `State::try_propose` chooses the parent, and
  `Actor::process_proposed` records the payload and hands it to the broadcaster;
  `State::try_verify` chooses the candidate, and `Actor::process_verified` acts on the
  answer; `State::certify_candidates` dispatches certification, and
  `Actor::process_certified` turns the result into a finalize or a nullify. The replica
  handles certificates, votes and timeouts in between, so a check on the first site of a
  pair says nothing about what the second one does.
