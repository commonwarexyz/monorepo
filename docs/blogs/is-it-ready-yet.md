---
title: "Is it ready yet?"
description: "How compiler-enforced stability levels help you know what's production-ready in the Commonware Library."
date: "February 3rd, 2026"
published-time: "2026-02-03T00:00:00Z"
modified-time: "2026-02-03T00:00:00Z"
author: "Patrick O'Grady"
author_twitter: "https://x.com/_patrickogrady"
url: "https://commonware.xyz/blogs/is-it-ready-yet"
image: "https://commonware.xyz/imgs/is-it-ready-yet-card.png"
---

As we've added more and more primitives to the Commonware Library, it's become increasingly difficult to keep track of what is "ready" and what is not (especially when you consider primitive dependencies).

The [Commonware Library](https://github.com/commonwarexyz/monorepo) now has over 30 primitives (and primitive dialects). Some have been battle-tested for over a year. Others landed last week. More will be added next month.

How do you communicate what's ready without documentation that rots the moment you publish it?

## Obvious Compatibility

The obvious answer is semantic versioning. Slap a version number on each primitive, publish them as separate crates, and let Cargo sort it out. `1.0` means stable. `0.x` means experimental. It just works.

Except it doesn't. Even if we broke every primitive into its own crate, features within a single crate can be at different stability levels. And publishing separate crates creates an exponential blowup in version combinations. Just because `cryptography@2.3` compiles with `consensus@1.5` doesn't mean that combination has been tested together. "It compiles" is not the same as "it works."

We want to be explicit about what has been tested and what has not. So we're switching to calendar versioning (YYYY.M.patch) for the library as a whole, and using a different mechanism entirely for stability.

You might suggest Cargo features - gate unstable APIs behind an `unstable` feature flag, like Tokio does. But feature flags propagate through the dependency tree. If your crate depends on `commonware-consensus`, and you want access to an unstable API in `commonware-cryptography`, then `commonware-consensus` needs to expose and forward that feature. Every intermediate crate in the dependency chain needs to opt in. With `cfg` flags set via `RUSTFLAGS`, you set your stability threshold once and it applies globally.

## Using Config Flags to Enforce Stability

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

This works transitively. When CI builds with `--cfg commonware_stability_BETA`, any BETA function that calls an ALPHA function fails to compile - the ALPHA function simply doesn't exist at that stability level. If something is marked BETA, you can trust that its entire dependency chain within the library is BETA or higher.

Cargo features provide the same transitive guarantee, but with the propagation problem mentioned above. Every crate in the dependency chain needs to expose and forward the feature flag. With `cfg` flags via `RUSTFLAGS`, you set your stability threshold once and get uniform enforcement - both within our workspace and when you compile your own code against the library.

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

## What's Next

More primitives will reach BETA. Some will reach GAMMA as fuzzing coverage expands. A few battle-tested ones will eventually hit DELTA.

You'll always know exactly where each one stands.

Build something: [github.com/commonwarexyz/monorepo](https://github.com/commonwarexyz/monorepo)