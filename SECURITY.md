# Security Policy

## Reporting Security Issues

We welcome security disclosures and are committed to providing prompt attention
to any confirmed security issues.

Vulnerabilities should be reported privately
[via GitHub Security](https://github.com/commonwarexyz/monorepo/security)
instead of as a public issue.

We do not yet offer a bounty program for responsible disclosure of security
vulnerabilities; however, we do track contributions and record them on the
leaderboard below.

### Leaderboard

1. (Your Name Here)

## How to Read This Policy

The policy is this file plus the files under [`security/`](security/).
In all of them, "this file" means the whole policy. These rules come first;
their full text is in
[How to Read This File](security/how-to-read.md).

- **Purpose.** The policy has two goals: fewer false positives and more true
  positives in security review by LLM agents. Coding agents read it before
  making changes, and review agents read it before a secure code review.
- **Authority.** Rules are normative: follow them as written. Statements about
  the code are claims: check each one at the revision under review, and when
  the code contradicts a claim, the code at that revision decides.
- **Conflicting instructions.** When the policy, `AGENTS.md`, a nested agent
  guide, and the instructions of the task disagree, follow the higher-priority
  source, stop the action that the conflict is about, and report the conflict
  with evidence. The policy does not rank itself above the others.
- **When you think the policy is wrong.** Follow its rules anyway, finish the
  task, report the disagreement as a separate item, and never edit the policy
  on your own.
- **What to read.** Every agent reads the mandatory core, then the parts for
  each crate its task touches. The
  [Reading Table](security/how-to-read.md#reading-table) names both.

## Threat Model

- [Threat Model](security/threat-model.md): the adversarial settings, the
  assumptions and trust boundaries, the trust model, and the consensus timing
  rule. Mandatory core: every agent reads it.
- [Inherited Threats](security/inherited-threats.md): the threat classes
  that apply everywhere. Mandatory core: every agent reads it.
- [Threats Unique to This Monorepo](security/unique-threats.md): the
  threats that come from how the code is built and shipped. Mandatory core:
  every agent reads it.
- [Coverage](security/coverage.md): what the threat lists leave out, and
  where findings are not reported. Mandatory core: every agent reads it.
- [Threats](security/threats.md): how a threat is written and cited, and
  the list of per-crate threat files. Read the introduction and the file of
  each crate the task touches:
  [consensus](security/threats/consensus.md),
  [broadcast](security/threats/broadcast.md),
  [codec](security/threats/codec.md),
  [cryptography](security/threats/cryptography.md),
  [coding](security/threats/coding.md),
  [p2p](security/threats/p2p.md),
  [stream](security/threats/stream.md),
  [storage](security/threats/storage.md),
  [glue](security/threats/glue.md),
  [runtime](security/threats/runtime.md),
  [resolver](security/threats/resolver.md),
  [collector](security/threats/collector.md),
  [clearing](security/threats/clearing.md).
- [Attack Vectors](security/attack-vectors.md): the paths by which a
  threat is reached, one subsection per crate. Read the introduction and the
  subsection of each crate the task touches.

## Automatic Secure Code Review

- [Automatic Secure Code Review](security/code-review.md): the severity
  gates, the findings validation process lessons, the top 10 lessons learned,
  the denial-of-service review checks, and the review priority order. It is
  written for reviewers. The severity gates are mandatory core for every
  agent; the Reading Table says when a task reads the other parts.
