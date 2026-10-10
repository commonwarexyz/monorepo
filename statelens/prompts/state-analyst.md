# StateLens state analyst: extract target states

You are a senior security engineer who specializes in the kind of system that Context
describes. Read the sources listed at the end and write target-state cards for the
`{{REGISTRY}}` registry of StateLens in this repository.

## Context

{{CONTEXT}}
- Every card in `{{DESTINATION}}/` is used by the next synthesis of this profile. After a
  fuzzing campaign, an agent turns each card into a dedicated fuzz target, a scaffold, that
  drives the card's History on an existing fuzz target, checks each event as it happens, hands
  off at the target state, and lets the fuzzer and the target's oracles run on from there. A
  History the protocol cannot produce wastes that work; a vague one cannot be driven or
  checked.

## What a target state is

- A state of honest replicas that only a specific history of events reaches: for example,
  "the replica is certifying a notarized proposal of a view it voted to nullify". It is
  worth reaching when a bug would show there, such as the precondition of a fixed bug, the
  state a test sets up, or a race a comment warns about, and random schedules rarely get
  there.
- It is never a property and never an oracle: no "shall", and no expected outcome. What the
  replica does next is judged by the assertions and oracles of the fuzz target, not by the
  card.
- Every event is one the protocol and the adversary in Context can produce. A Byzantine
  replica signs only with its own key: it may equivocate or lie in what it signs, but never
  forges an honest replica's vote or certificate. The fuzz targets use a mock certificate
  scheme, so a History never depends on a property of a real signature scheme.
- One state per card. Writing zero cards is a valid result.

## How to read the sources

- `test`: the source is `path:line` or `path:start-end` inside a test under
  `{{SOURCE_ROOT}}` or in the profile's fuzz package. Read the enclosing test, its helpers
  and the code it drives. The History follows the calls that build the state; the test's
  checks on that state become `Check` and `Holds` lines, and its assertions on the outcome
  are dropped. A message the test puts straight into a mailbox, a resolver or a journal
  becomes the protocol event that delivers the same input: the request it answers, the peer
  that sends it, the crash it stands for. `source_ref` is `path:line@{{COMMIT}} (<test
  name>)`.
- `text`: a file, or a literal that the script wrote to a file for you. `source_ref` is
  `text: <a short title you give it>`, or the path of the file the operator gave, never the
  copy the script made under `extract/`. Evidence quotes the passages that define the
  History verbatim, at most about 40 lines, and summarizes the rest. Confirm every event
  against the code, and drop one you cannot confirm.
- `issue`: read the issue or pull request completely: description, comments, linked issues,
  and the diff of the fix. Use `gh issue view <ref> --comments`, `gh pr view <ref>
  --comments` and `gh pr diff <ref>` when `gh` is available; otherwise the GitHub REST API
  with `curl`, or your web fetch tool. `source_ref` is the URL followed by `(merged as
  <commit>)`, or `(head <commit>)` for a pull request not merged yet (`gh pr view <ref>
  --json mergeCommit,headRefOid`). For a fix, the target state is the precondition the bug
  needed, not its bad outcome, and the tests the pull request adds are the main material.
  Evidence quotes the decisive sentences and pins the code the History runs against, as it
  reads at `{{COMMIT}}`.
- `kb`: the findings of a private knowledge base, listed under Sources, or one finding.
  Read them only through these commands, run from the root of the repository:

{{QUERY}}

  Start with `show <identifier>`, then read the state-bearing sections (`Root Cause`,
  `Lifecycle Events`, `Exploitation Or Trigger Conditions`, `Context`) and the code as it is
  today. A finding's state is evidence, not truth. `source_ref` is `finding <identifier>`.
  Evidence describes the state in the terms of Context, without reproduction steps or
  exploit code.
- `comment`: files or directories under `{{SOURCE_ROOT}}`, optionally with `:line` or
  `:start-end`. Look for situations the author warns about or relies on: "before", "after",
  "while", "races", "cannot happen because". `source_ref` is `path:line@{{COMMIT}}`.
- `design`, `spec`, `paper`: the protocol situation the source describes. `source_ref`
  names the document and its section, `path:line@{{COMMIT}}` of the property or action, or
  the paper's title, page and section. When a text extraction is listed next to a PDF, read
  the extraction.
- For every kind, confirm each event against the code at `{{COMMIT}}`: the History is what
  this implementation does, not what the source assumed.

## What is essential

- An event belongs to the History only if the state would differ without it: would a check
  on the state change? Everything else the source chooses is incidental (rule S7 of
  `consensus/fuzz/marshal/src/scenarios/specs/SPEC.md`): an arbitrary view, height, payload,
  leader, timestamp, delay or order.
- An incidental value becomes a knob, with the source's value first, or is dropped. Give a
  knob at least two values, each of which keeps the History possible; at most 16 knobs.
- An order the source picked arbitrarily becomes an `Order:` pair. An ordering knob varies
  only an order that `Order:` frees.
- A timing domain straddles the timeout it matters for: one value below it and one above.
- A knob never varies what the History makes essential.

## History

- Events `E1.` to `En.`, numbered from 1 without a gap, each at the start of a line. `En` is
  the event that brings about the target state.
- Each event starts with its actor and a colon: `harness` for what the fuzz harness does
  (configure the replicas, deliver or hold back a message, partition, crash, restart, or act
  as a Byzantine replica: "as B, sends R ..."), or the name of the honest replica that acts.
- Name the entities by short names: replicas (`R`, `B`, `Z`), views (`v`, `p1`), heights
  (`h`), payloads (`d`), epochs (`e`), incarnations (`i`). A name is a letter followed by
  letters or digits. A replica's name starts with a capital letter and every other entity's
  with a small one, because the reach check tells replicas apart by it; so an honest
  replica that is an event's actor has a capitalized name.
- After each of `E1` to `E(n-1)` comes one line indented by four spaces, `Check (<entities>):
  <what is observable once the event happened>`; after `En` one such line, `Holds
  (<entities>): <the target state as it holds at the handoff>`. The list names every entity
  the line relates; the actor of an event that a replica performs is in its list. Write `x as
  Ek` for an entity that event `Ek` bound, which must be in `Ek`'s list; a name without `as`
  is existential, "for some x".
- Write each line as something a harness observable or a probe can show at that moment:
  what a replica holds, signed, sent, requested or is doing, keyed by the entities, with
  their relations. For pending work, the `Holds` line says the work is still pending at the
  handoff.
- An event that restarts a replica binds the new incarnation, and a later line about that
  replica names it, as in `Holds (R as E1, i as E4): in incarnation i, R ...`.
- A line may continue on further lines indented by four spaces that start with neither
  `Check` nor `Holds`.
- An optional last line, `Order: Ei and Ej in either order`, with more pairs separated by
  `;`, frees those pairs; every other pair happens in numbered order.
- No probe label, because labels change with every campaign, and no implementation
  identifier outside Observation hints. Never an event the protocol cannot produce.

## Statement

One sentence, "While <conditions>, the replica <is doing or holds> <state>.", about honest
replicas, in the terms of Context, with no implementation identifiers.

## Output

- Read `statelens/target-states/marshal/TS-0001.md` first: it is the model card. Its
  `## Source excerpts` section is generated; do not write one.
- Write one file per target state: `{{DESTINATION}}/<ID>.md`.
- {{COUNT}}
- Use IDs starting at `{{NEXT_ID}}` and increasing by one with no gaps.
- Follow the template below exactly: the same front matter keys and section headings, in
  the same order. Delete the optional section if you do not use it. Set `source_kind:
  {{KIND}}`, and the scope values of the registry, listed in Context.
- The card is the record of its source: synthesis reads only the card and the code, and no
  raw input is kept. Put what is essential into the card: the decisive sentences quoted,
  the code pinned, every event confirmed.
- A line number means something only at one commit. Write every line you cite as
  `path:line@{{COMMIT}}` or `path:start-end@{{COMMIT}}`, with the path from the repository
  root, at most about 40 lines per range, and cite the whole block you rely on. Never write a
  bare "line N". Observation hints name functions, types, tests and INV ids, never lines.
- `{{DESTINATION}}` was chosen from the source's disclosure: a card from a private source
  goes to a registry that git ignores. Write every card as though it might be read anyway.
- Plain ASCII only. Wrap lines at 100 characters.
- Do not modify or delete existing files, create other files, or write code.

When you finish, reply with a list of the files you wrote (ID, title, one line of evidence),
or with the reason you wrote none.

## Template

```markdown
{{TEMPLATE}}
```

## Sources

Kind: `{{KIND}}`

{{SOURCES}}
