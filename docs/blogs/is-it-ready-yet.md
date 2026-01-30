---
title: "Is it ready yet?"
description: "Large parts of the Commonware Library are now BETA. Stability levels tell you exactly which parts are ready for production and which are still evolving."
date: "January 30th, 2026"
published-time: "2026-01-30T00:00:00Z"
modified-time: "2026-01-30T00:00:00Z"
author: "Patrick O'Grady"
author_twitter: "https://x.com/_patrickogrady"
url: "https://commonware.xyz/blogs/is-it-ready-yet"
image: "https://commonware.xyz/imgs/is-it-ready-yet-card.png"
---

The [Commonware Library](https://github.com/commonwarexyz/monorepo) now has over 30 primitives (and primitive dialects). Some have been battle-tested for over a year. Others landed last week. More will be added next month.

How do you communicate what's ready without documentation that rots the moment you publish it?

## Using the Compiler to Enforce Stability

Every public API in the Commonware Library is now annotated with a stability level. These annotations aren't just labels - they're `cfg` flags that Rust's compiler understands.

Filter rustdoc to show only APIs at your desired stability level:

```bash
RUSTFLAGS="--cfg commonware_stability_BETA" \
RUSTDOCFLAGS="--cfg commonware_stability_BETA -A rustdoc::broken_intra_doc_links" \
cargo doc --open
```

Fail your build if you depend on an unstable API:

```bash
RUSTFLAGS="--cfg commonware_stability_BETA" cargo build -p my-app
```

Verify stability annotations are internally consistent:

```bash
just check-stability
```

This works transitively. If a BETA function internally calls an ALPHA function, that's our problem to fix - not yours to discover in production.

## The Levels

| Level        | Index | What it Means |
|--------------|-------|---------------|
| **ALPHA**    | 0     | Expect breaking changes. No migration path. |
| **BETA**     | 1     | Wire and storage formats stable. Breaking changes come with migrations. |
| **GAMMA**    | 2     | API stable. Extensively tested and fuzzed. |
| **DELTA**    | 3     | Battle-tested. Bug bounty eligible. |
| **EPSILON**  | 4     | Feature-frozen. Bug fixes only. |

**BETA is the threshold for serious use.** If you're building something real, you want BETA or higher. The wire format won't change out from under you. If we do make breaking changes, we'll provide a migration path.

## What's BETA Now

The core building blocks are ready:

- **runtime** - async execution with deterministic testing
- **cryptography** - Ed25519, BLS12-381, signatures, DKG
- **codec** - zero-copy serialization
- **p2p** - authenticated peer-to-peer networking
- **storage** - persistent key-value storage
- **stream** - encrypted message streams
- **broadcast** - reliable data dissemination
- **consensus** - BFT agreement (Simplex)
- **resolver** - content-addressed data retrieval
- **utils** - common utilities
- **math** - numerical primitives
- **parallel** - parallel execution helpers

This isn't a collection of experiments. These primitives power [Alto](https://github.com/commonwarexyz/alto), our reference blockchain implementation. They've been tested under adversarial conditions, fuzzed extensively, and optimized for performance.

## Date Versioning

We're also moving to date-based versions: `v2026.1.30`.

Primitives evolve at their own pace. We add new ones when they're ready. We stabilize existing ones when they've proven themselves. The stability level tells you what's ready - the version just tells you when it was released.

## What's Next

More primitives will reach BETA. Some will reach GAMMA as fuzzing coverage expands. A few battle-tested ones will eventually hit DELTA.

You'll always know exactly where each one stands.

Build something: [github.com/commonwarexyz/monorepo](https://github.com/commonwarexyz/monorepo)