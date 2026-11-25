# How to Read This File

Part of the [Security Policy](../SECURITY.md). Here "this file" means the whole policy.

## Purpose and Readers

This file has two goals: fewer false positives and more true positives in
security review by LLM agents. Safer code changes by coding agents are not a
goal of this file and not a measure of its success.

`AGENTS.md` names the readers, and this file does not change that: coding
agents read it before making changes, and review agents read it before a
secure code review. The guidance under
["Automatic Secure Code Review"](code-review.md) is
written for reviewers.

## Reading Table

Every agent reads the mandatory core. The sections are named by their
headings.

| Mandatory core | Why |
|---|---|
| How to Read This File | The rules for using this file. |
| [Reporting Security Issues](../SECURITY.md#reporting-security-issues) | The reporting procedure. |
| [Adversarial Settings](threat-model.md#adversarial-settings) | Who and what is hostile. |
| [Assumptions and Trust Boundaries](threat-model.md#assumptions-and-trust-boundaries), [Trust Model](threat-model.md#trust-model) | The fault budget and the trust boundaries. |
| [Consensus Timing Rule](threat-model.md#consensus-timing-rule) | The default for consensus-related liveness. |
| [Inherited Threats](inherited-threats.md) | The threat classes that apply everywhere. |
| [Threats Unique to This Monorepo](unique-threats.md) | The threats that come from how the code is built and shipped. |
| [Coverage](coverage.md), with [Report Scope](coverage.md#report-scope) | What the lists leave out, and where findings are not reported. |
| [Severity Gates](code-review.md#severity-gates), with [Stability Levels](code-review.md#stability-levels), [Contract Hazards](code-review.md#contract-hazards), and [Evidence](code-review.md#evidence) | What a finding needs, and how it is rated. |

Then every agent reads the parts for each crate its task touches. A crate name
in the second column is a subsection heading: read the subsection with that
heading under "Threats" and the one under "Attack Vectors".

| Task touches | Under ["Threats"](threats.md) and ["Attack Vectors"](attack-vectors.md) | Under ["Review Priority Order"](code-review.md#review-priority-order) |
|---|---|---|
| `consensus` | Consensus: [threats](threats/consensus.md), [attack vectors](attack-vectors.md#consensus) | 1, 2 |
| `broadcast` | Broadcast: [threats](threats/broadcast.md), [attack vectors](attack-vectors.md#broadcast) | 2 |
| `codec` | Codec: [threats](threats/codec.md), [attack vectors](attack-vectors.md#codec) | 2 |
| `cryptography` | Cryptography: [threats](threats/cryptography.md), [attack vectors](attack-vectors.md#cryptography) | 4, 5 |
| `coding` | Coding: [threats](threats/coding.md), [attack vectors](attack-vectors.md#coding) | 2 |
| `p2p` | P2P: [threats](threats/p2p.md), [attack vectors](attack-vectors.md#p2p) | 1, 2 |
| `stream` | Stream: [threats](threats/stream.md), [attack vectors](attack-vectors.md#stream) | 5 |
| `storage` | Storage: [threats](threats/storage.md), [attack vectors](attack-vectors.md#storage) | 3 |
| `glue` | Glue: [threats](threats/glue.md), [attack vectors](attack-vectors.md#glue) | 4 |
| `runtime` | Runtime: [threats](threats/runtime.md), [attack vectors](attack-vectors.md#runtime) | 2, 3 |
| `resolver` | Resolver: [threats](threats/resolver.md), [attack vectors](attack-vectors.md#resolver) | 1, 2 |
| `collector` | Collector: [threats](threats/collector.md), [attack vectors](attack-vectors.md#collector) | 2 |
| `clearing` | Clearing: [threats](threats/clearing.md), [attack vectors](attack-vectors.md#clearing) | none |

A task that matches a row also reads the introductions of
["Threats"](threats.md) and
["Attack Vectors"](attack-vectors.md) and the parts that cut across crates:
["Findings Validation Process Lessons"](code-review.md#findings-validation-process-lessons),
["Top 10 Lessons Learned"](code-review.md#top-10-lessons-learned),
["Denial-of-Service Review Checks"](code-review.md#denial-of-service-review-checks),
and item 6 of ["Review Priority Order"](code-review.md#review-priority-order)
(["Panic Severity Calibration"](code-review.md#6-panic-severity-calibration)).

A task that matches no row reads all sections. This includes a task on a crate
that has no row, and a task that names no crate.

## Authority

This file holds two kinds of statement, and they have different authority.

- **Rules are normative.** The fault budget, the trust boundaries, the severity
  gates, the reporting procedure, and the other rules of this file, such as
  ["Report Scope"](coverage.md#report-scope), are followed as written.
  "Conflicting
  Instructions" covers the case in which another source says otherwise.
- **Statements about the code are claims.** Every statement about what the code
  does quoted documentation, default
  value, and listed module, is a claim. Check it at the revision under review
  before relying on it. When the code contradicts a claim, the code at that
  revision decides: report the contradiction as a defect of this file.

In these rules, "report" means: write it in the result of your task.

## Conflicting Instructions

When this file, `AGENTS.md`, a nested agent guide, and the instructions of the
task disagree about what to do:

1. Follow the higher-priority source. This file does not rank itself above the
   others.
2. Stop the action that the conflict is about.
3. Report the conflict with evidence: both texts, and where each one is.

## When You Think This File Is Wrong

1. Follow the rules of this file anyway.
2. Finish the task.
3. Report the disagreement as a separate item, with evidence.
4. Never edit this file on your own.

Such a disagreement is reported as a defect of this file, not as a
vulnerability.

## Citing a Threat

Threats and attack vectors have no stable identifiers. The numbers in the
lists are positions, and they change when a list is edited. A finding or a
disagreement cites a threat by its file path and section heading plus the full
first
sentence of the threat. For a threat in a per-crate list, the first sentence
is the whole "X, because Y" sentence. An attack vector is cited in the same
way, by its file path and section heading plus its full text.

Some headings repeat, for example "Consensus" under "Threats" and under
"Attack Vectors", and "storage" under "Runtime". Give such a heading with its
parents, for example "Threats, Runtime, storage" for the heading "storage" in
`security/threats/runtime.md`.

## Upkeep

This file is kept current by hand: no tool checks it against the code. After a
material edit:

1. The author checks the edit.
2. An independent reviewer approves the public text. The reviewer confirms
   that no line comes from a non-public finding.
3. The owner of this file accepts the text again.

Acceptance means that the owner agrees with the text. It does not test how
models read the file.
