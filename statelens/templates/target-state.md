---
id: TS-NNNN
title: <one line, at most 80 characters>
source_kind: <human | issue | design | comment | spec | paper | kb | test | text>
source_ref: <URL (merged as <commit>) or (head <commit>), path:line@commit (test name), path or URL, text: <title>, or finding <identifier>>
scope: [<one or more of the registry's scope values, listed in the prompt context>]
---

## Statement
<One sentence: "While <conditions>, the replica <is doing or holds> <state>." About honest
replicas; no implementation identifiers.>

## Rationale
<What can go wrong in this state, and why reaching it matters.>

## Evidence
<The source and what it shows. Cite a line as path:line@commit, with the path from the
repository root, at most about 40 lines per range. For a text source, quote the passages that
define the History verbatim and summarize the rest. For a fix, describe the state the bug
needed, not its outcome.>

## History
E1. <actor: harness, or an honest replica's name>: <what happens, naming its entities>.
    Check (<entities it binds; one bound earlier is written x as Ek>): <what is observable
    once E1 happened>.
E2. <actor>: <the event that brings about the target state>.
    Holds (<entities>): <the target state as it holds at handoff>.
Order: <Optional: Ei and Ej in either order. Delete this line if unused.>

## Knobs
<Either the line None. or the table below, with 1 to 16 rows; keep one and delete this line.>
| Knob | Event | Domain | Source value |
|---|---|---|---|
| <name> | <Ek, or Ei-Ej> | <two or more values the fuzzer may choose, the source value first> | <the source's value> |

## Observation hints
<Optional and non-binding: functions, types, tests and INV ids that implement or watch the
events. No line numbers and no probe labels. Delete this section if unused.>
