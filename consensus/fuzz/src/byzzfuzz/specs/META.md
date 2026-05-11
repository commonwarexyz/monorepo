# Specification System

This document defines the format, rules, and procedures for creating and maintaining the ByzzFuzz specification system.

## Purpose

Specifications provide deterministic context about the intended behavior of `consensus/fuzz/src/byzzfuzz`. They are written for agents and reviewers changing the ByzzFuzz harness without repeatedly rediscovering every fault-flow boundary.

## Principles

1. **Self-standing documents** - specs are not generated from code. A discrepancy between spec and code indicates a bug in the code or the spec.
2. **Agent-optimized** - predictable structure, explicit cross-references, no filler prose.
3. **Living documents** - updated after code changes that alter documented behavior.
4. **Domain-based** - organized by conceptual domains, not by source file names.
5. **Contracts are first-class** - sync/async and harness/module boundaries have dedicated documents.
6. **Invariants are centralized** - invariant statements live in `invariants/invariants.md`; other specs link to the relevant invariant section.

## File Organization

```
consensus/fuzz/src/byzzfuzz/specs/
├── META.md
├── INDEX.md
├── WORKFLOW.md
│
├── architecture/
│   ├── fault-flow.md
│   └── layers.md
│
├── domains/
│   ├── fault-scheduling.md
│   ├── network-interception/
│   │   ├── README.md
│   │   └── round-tracking.md
│   ├── observability.md
│   ├── process-injection/
│   │   ├── README.md
│   │   └── mutator.md
│   └── runner-liveness.md
│
├── invariants/
│   └── invariants.md
│
├── contracts/
│   ├── byzzfuzz-harness.md
│   └── forwarder-injector.md
│
└── decisions/
    ├── _template.md
    ├── 001-single-byzantine-index.md
    ├── 002-semantically-mutate-votes-only.md
    ├── 003-post-gst-liveness-check.md
    ├── 004-byzzfuzz-local-small-scope-strategy.md
    └── 005-post-gst-required-container-catch-up.md
```

The invariant catalog is [invariants/invariants.md](invariants/invariants.md). Invariant statements belong there, and domain or architecture specs link to the relevant section.

## Naming Conventions

- Files: `kebab-case.md`
- Directories within `domains/`: created when a domain requires multiple files
- `README.md` inside a domain directory: overview and entry point for that domain
- `_template.md` prefix: template files
- ADR files: `NNN-kebab-case-slug.md`

## Document Formats

### Domain README (`domains/*/README.md` or `domains/*.md`)

Required sections in order:

```markdown
# [Domain Name]

## Purpose

1-3 sentences. What this domain does in the system.

## Key Files

- `path/from/repo/root/file.ext` - role description

## Core Types

Key type definitions or signatures with brief explanations.

## Flow

ASCII diagram or numbered sequence showing the primary happy path.

## Related Invariants

- [Invariant Group](../invariants/invariants.md#section-name) - properties that must hold.

## Configuration

Key parameters with defaults and valid values.

## Extension Points

How to add new behavior without breaking existing functionality.

## Related Specs

- [link](relative/path.md) - context of relationship
```

### Domain Detail (`domains/*/<name>.md`)

```markdown
# [Component Name]

## Role

1 sentence: what this component does within its domain.

## Key Files

- `path/to/file.ext` - description

## Behavior

Detailed description. May include state machines, decision tables, pseudocode, or sequence diagrams.

## Error Handling

How this component handles and propagates errors.

## Related Invariants

- [Invariant Group](../../invariants/invariants.md#section-name) - properties that must hold.

## Related Specs

- [link](relative/path.md) - relationship context
```

### Contract (`contracts/*.md`)

```markdown
# Contract: [Layer A] <-> [Layer B]

## Boundary Rule

One sentence: direction of dependency and what is allowed.

## Interfaces

| Interface | Package | Consumed By | Purpose |
| --------- | ------- | ----------- | ------- |

## Initialization

How components are wired together at startup.

## Data Flow Across Boundary

What data crosses the boundary, in what form, in which direction.

## Error Propagation

Rules for wrapping or transforming errors at this boundary.

## Breaking Change Checklist

If you change X, you must also update Y.
```

### Architecture (`architecture/*.md`)

```markdown
# [Topic]

## Context

Why this architectural aspect matters.

## [Main Content]

Diagrams, rules, descriptions. Structure varies by topic.

## Related Invariants

- [Invariant Group](../invariants/invariants.md#section-name) - architectural properties that must hold.

## Anti-Patterns

What not to do, with brief explanation.
```

### ADR (`decisions/NNN-slug.md`)

```markdown
# ADR-NNN: [Title]

## Status

Accepted | Superseded by [NNN](./NNN-slug.md)

## Context

The problem or question that required a decision.

## Decision

What was decided.

## Consequences

Positive and negative impacts on the codebase.

## Alternatives Considered

What was evaluated and why it was rejected.
```

### Invariant Catalog (`invariants/invariants.md`)

```markdown
# Invariants

## Purpose

How to use the invariant catalog.

## [Invariant Group]

- Affirmative property that always holds.
```

## Cross-References

- Use relative paths from this `specs/` directory.
- Format: `[display text](relative/path.md)`.
- Section anchors: lowercase, hyphen-separated.
- Source code references: repo-root paths in backticks, for example `consensus/fuzz/src/byzzfuzz/runner.rs`.

## Update Protocol

### When to update specs

- After any change that alters documented behavior.
- After adding, removing, or renaming interfaces that appear in a contract.
- After changing architectural boundaries or invariants.
- After making a new architectural decision.

### How to update

1. Read the current spec fully before modifying it.
2. Preserve the document format and section ordering defined here.
3. Update cross-references if file paths changed.
4. Check the affected invariant group in `invariants/invariants.md` and keep every applicable invariant true.
5. After adding or removing a spec file, update `INDEX.md`.
6. ADRs with `Status: Accepted` are immutable. Create a new ADR to supersede.

### Validation checklist

- [ ] All sections from the template are present.
- [ ] Cross-references point to existing files.
- [ ] Code paths in Key Files are accurate.
- [ ] Affected invariants in `invariants/invariants.md` have been checked and still hold.
- [ ] Invariant statements are centralized in `invariants/invariants.md` and stated affirmatively.
- [ ] `INDEX.md` reflects the current file set.
