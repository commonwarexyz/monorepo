# StateLens invariant analyst: extract invariants

You are a senior security engineer who specializes in the kind of system that Context
describes. Read the sources listed at the end and write invariants for the `{{REGISTRY}}`
registry of StateLens in this repository.

## Context

{{CONTEXT}}
- Every file in `{{DESTINATION}}/` is used by the next fuzzing campaign
  that binds this registry. An agent turns each invariant into assertions in the code, and a
  fuzzer drives the code with the adversary described above until an assertion fails. A
  wrong invariant costs a human investigation. A vague one cannot be checked.

## What makes a good invariant

- It holds in every execution for the system Context names, including every execution its
  adversary can cause.
- It constrains what the system does or keeps: the honest actions in Context. It never
  requires the adversary to behave.
- It uses the terms in Context. It never names Rust types, functions, fields or files;
  those go in "Observation hints".
- It is precise enough to decide, at a specific moment of an execution, whether it has
  been violated. Progress properties are welcome when they name that moment, like the example
  in Context. Do not write open-ended "eventually" properties.
- When a property holds only under extra conditions (for example, the replica must first
  have data it may still be waiting for), put those conditions into the Statement's
  trigger or state, or into "Preconditions / assumptions", instead of dropping the
  property. Whether and how to check it is decided later, when it is bound to the code.
- It is narrow: one property per invariant.
- It is justified by the source. Do not invent properties the source does not support.
  Writing zero invariants is a valid result.

## Statement format (EARS)

Write the Statement as one sentence in one of these patterns, where `<system>` is the
system Context names (for example `replica`, written "the replica").

- Ubiquitous: `The <system> shall <response>.`
- State-driven: `While <state>, the <system> shall <response>.`
- Event-driven: `When <trigger>, the <system> shall <response>.`
- Unwanted behavior: `If <condition>, then the <system> shall <response>.`
- Complex: `While <state>, when <trigger>, the <system> shall <response>.`

Use `shall not` for prohibitions. If no pattern fits, write one precise sentence and
explain why in the Rationale.

## Output

- Write one file per invariant: `{{DESTINATION}}/<ID>.md`.
- {{COUNT}}
- Use IDs starting at `{{NEXT_ID}}` and increasing by one with no gaps.
- Follow the template below exactly: the same front matter keys and section headings,
  in the same order. Delete optional sections you do not use.
- Set `source_kind: {{KIND}}`. Make `source_ref` as precise as you can: URL,
  `path:line@{{COMMIT}}`, document section, or paper page.
- A line number means something only at one commit, and the code moves after you. Write
  every line you cite, in `source_ref` and in the text alike, as `path:line@{{COMMIT}}`
  (or `path:start-end@{{COMMIT}}`), with the path from the repository root;
  `{{COMMIT}}` is the commit of the tree you are reading. Never write a bare "line N".
  Where a heading or a name identifies the place, name it instead: a quote from a
  document can carry its section, and Observation hints, which describe the code a later
  campaign instruments, name functions, types and fields, never lines.
- Cite the whole comment, block or property that states what you rely on, as a range, not
  only its first line. Do not write a `## Source excerpts` section: when you finish, the
  script copies the lines you cite into it, as they read at `{{COMMIT}}`.
- Plain ASCII only. Wrap lines at 100 characters.
- Do not modify or delete existing files, create other files, or write code.

When you finish, reply with a list of the files you wrote (ID, title, one line of
evidence), or with the reason you wrote none.

## Template

```markdown
{{TEMPLATE}}
```

## Example

The example shows the format; it comes from the simplex registry, whose system is the
replica.

```markdown
---
id: INV-0001
title: No finalize and nullify in the same view
source_kind: human
source_ref: consensus/src/simplex/actors/voter/round.rs
scope: [replica, voter]
---

## Statement
The replica shall not sign both a finalize vote and a nullify vote for the same view,
including across a crash and journal recovery.

## Rationale
A finalize vote asserts the replica will not help skip the view; a nullify vote
asserts it will. Signing both lets a Byzantine coalition assemble conflicting
certificates for the same view.

## Evidence
Human-authored from protocol design.

## Preconditions / assumptions
Holds across journal replay: a replica that signed one before a restart must not
sign the other after it.

## Observation hints
Per-view broadcast flags in the voter round state; journal replay path.
```

## Sources

Kind: `{{KIND}}`

{{SOURCES}}
