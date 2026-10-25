## How to read knowledge-base findings

- The sources are the findings of a private knowledge base, reported against this workspace,
  whose `module` belongs to this registry. Each is listed under Sources with its state,
  severity, remediation status and summary. Read them only through these commands, run from
  the root of the repository; there is no other way to the corpus:

{{QUERY}}

- Start with `show <identifier>` for a finding's claim block, then read its state-bearing
  sections: `Root Cause`, `Lifecycle Events`, `Exploitation Or Trigger Conditions` and
  `Context`. Then read the code it concerns as it is today: a finding cites files and lines
  of the revision it was reported against, and they may have moved.
- Reconstruct the bug: the state that triggered it, what the implementation did, and why
  that was wrong. Write the invariants the bug violated, generalized so that they also catch
  variants of the bug on other paths while staying true for every correct execution. Where a
  finding describes a crash, cover both sides: what the system must never do, and what it
  must do instead.
- A finding's state is evidence, not truth. One judged `invalid` describes behavior that was
  found correct, so it is no evidence of a rule: write an invariant from it only when the
  code or its documentation states the property. Prefer `valid` and `tested` findings, and
  say in the Rationale how strong the evidence is.
- Set `source_ref` to `finding <identifier>`. In Evidence, describe the violating scenario in
  two to five sentences in the terms of Context, without reproduction steps or exploit code,
  and cite the code it concerns as it reads at `{{COMMIT}}`.
- What you write stays out of git, in the local registry, because a finding is private.
  Write it as though it might be read anyway.
- Write nothing for a finding about tooling, tests, documentation or another crate.
