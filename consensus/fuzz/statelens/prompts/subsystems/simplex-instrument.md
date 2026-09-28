### Simplex (`consensus/src/simplex/`)

- Editable code: non-test code in `consensus/src/simplex/`, except `mocks/` and
  `scheme/`.
- Components: the voter, batcher and resolver actors in `consensus/src/simplex/actors/`,
  which exchange messages through mailboxes, and the journal replay path on restart.
- Replica index: `self.scheme.me()` wherever a scheme is in scope (the voter, batcher and
  resolver all hold one). Where it is not, add a `// [statelens] me` field of type
  `Option<crate::simplex::statelens::Participant>`, set where the struct is created.
- Asynchrony worth probing: the view advances while work is outstanding, a timeout races
  a certificate, a verification or certification result arrives after the state moved
  on, equivocation is detected after acceptance, state is rebuilt from the journal.
