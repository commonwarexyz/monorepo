## How to read an issue or pull request

- Read every listed issue or pull request completely: description, comments, linked
  issues, and the diff of the fixing pull request or commit. Use `gh issue view <ref>
  --comments`, `gh pr view <ref> --comments` and `gh pr diff <ref>` when `gh` is
  available; otherwise use the GitHub REST API with `curl` (for example
  `https://api.github.com/repos/<owner>/<repo>/issues/<n>` and `.../comments`) or your
  web fetch tool.
- Reconstruct the bug: the situation that triggered it, what the implementation did,
  and why that was wrong for the protocol.
- Write the invariants the bug violated. Generalize beyond the specific fix so that the
  invariant also catches variants of the bug on other code paths, while staying true
  for every correct execution.
- Cover both sides of the bug where they apply: what the replica must never do (the
  wrong action, or the state that made it crash), and what it must do instead at that
  moment. For example, a crash on a malformed message has two sides: the replica shall
  not panic on it, and the replica shall reject it and keep processing other messages.
- Also write the expected outcome: what the replica should have produced in the reported
  situation, given the inputs it had (a vote, a certificate, a state change), as an
  event-driven statement.
- For a liveness bug, also write the safety condition whose violation caused it, when
  one exists (for example "the replica shall not discard a certificate for a view above
  its finalized tip"). Do not write open-ended "eventually" properties.
- In Evidence, describe the violating scenario in two to five sentences and cite the
  issue, the pull request and the fixing commit.
- Write nothing for issues that are not about Simplex behavior (documentation, CI,
  build, performance tuning, other crates).
