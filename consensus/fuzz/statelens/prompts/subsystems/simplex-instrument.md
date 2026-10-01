### Simplex (`consensus/src/simplex/`)

- Editable code: non-test code in `consensus/src/simplex/`, except `mocks/` and
  `scheme/`.
- Components: the voter, batcher and resolver actors in `consensus/src/simplex/actors/`,
  which exchange messages through mailboxes, and the journal replay path on restart.
- Replica index: `self.scheme.me()` wherever a scheme is in scope. The batcher and the
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
