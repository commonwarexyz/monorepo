---
title: "Is it ready yet?"
description: "The Commonware Library is now home to 17 primitives and over 50 primitive dialects, with 93% test coverage and 1500 daily benchmarks. The only number that probably matters to you, however, is how many primitives are ready to use."
date: "February 5th, 2026"
published-time: "2026-02-05T00:00:00Z"
modified-time: "2026-02-05T00:00:00Z"
author: "Patrick O'Grady"
author_twitter: "https://x.com/_patrickogrady"
url: "https://commonware.xyz/blogs/is-it-ready-yet"
image: "https://commonware.xyz/imgs/is-it-ready-yet.png"
---

The [Commonware Library](https://github.com/commonwarexyz/monorepo) is now home to 17 primitives and over 50 primitive dialects (cryptography::bls12381, cryptography::ed25519, etc.), with [93% test coverage](https://app.codecov.io/gh/commonwarexyz/monorepo) and [1500 daily benchmarks](https://commonware.xyz/benchmarks.html).

The only number that probably matters to you, however, is how many primitives are ready to use.

Today, we are sharing our approach to versioning, explaining how we enforce consistent stability with the compiler, and (most importantly) graduating a large number of primitives to [BETA](https://github.com/commonwarexyz/monorepo#stability).

## Solving a "Solved" Problem

The obvious approach to tracking stability is [semantic versioning](https://semver.org/): break each primitive into its own crate, use `0.x` for unstable and `1.0+` for stable, bump major versions for breaking changes, and gate experimental features behind an `unstable` flag.

While building with different teams, however, this approach proved insufficient:

**Compatibility is unclear.** With many crates versioned independently, it is not clear what combinations have been tested together. `consensus-simplex@1.1.3` "should" work with `storage-journal@2.3.45` if it compiles. In a world where a wrong guess means a network halt or loss of funds, however, we found this didn't cut it.

**Coarse readiness slows development and is error-prone for applications.** Without more granularity, new features tend to sit in "unstable" purgatory for too long. When incorporated into downstream applications, all of "unstable" is available making it easy to accidentally rely on something much less stable than intended (with nuance hidden deep in documentation that nobody reads).

**Long-Term Support is not apparent.** We take a Linux-like approach to stability: once something is marked as "stable," it must remain supported indefinitely. If we need to make a significant change, it must be backwards-compatible or introduced in a new crate. There is no `2.x` for a primitive.


## Tiered Stability and Calendar Versioning

We've broken stability into the following levels:

| Level        | Index | Description                                                                              |
|--------------|-------|------------------------------------------------------------------------------------------|
| **ALPHA**    | 0     | Breaking changes expected. No migration path provided.                                   |
| **BETA**     | 1     | Wire and storage formats stable. Breaking changes include a migration path.              |
| **GAMMA**    | 2     | API stable. Extensively tested and fuzzed.                                               |
| **DELTA**    | 3     | Battle-tested. Bug bounty eligible.                                                      |
| **EPSILON**  | 4     | Feature-frozen. Only bug fixes and performance improvements accepted.                    |

Once a primitive is marked `BETA`, it is eligible for Long-Term Support (LTS). Barring any critical vulnerabilities, the wire and storage format will remain backwards-compatible indefinitely.

For compatibility, we also needed to rethink our versioning scheme. The Commonware Library now uses [calendar versioning (YYYY.M.patch)](https://calver.org/). This provides obvious compatibility without implying stability (a library-wide semver like `1.2.1` would incorrectly suggest that every crate, including brand-new ones, is equally mature).

## Programmatic Enforcement

Every public object in the Commonware Library is annotated with a stability level using proc macros that expand to `cfg` attributes.

Set your minimum stability level once via `RUSTFLAGS` and it applies globally:

```bash
RUSTFLAGS="--cfg commonware_stability_BETA" cargo build -p my-app
```

If your code depends on an `ALPHA` API, it won't compile. No runtime checks. No documentation to read. The compiler tells you.

You can also filter rustdoc to show only APIs at your desired stability level:

```bash
RUSTFLAGS="--cfg commonware_stability_BETA" \
RUSTDOCFLAGS="--cfg commonware_stability_BETA" \
cargo doc --open
```

We also enforce stability transitively in CI: any object must only depend on objects at the same or higher stability level. If something is marked `BETA`, its entire dependency chain within the library is `BETA` or higher.

![Stability consistency is enforced by the compiler.](/imgs/is-it-ready-yet.png)

## Graduation Day

Here are some of the primitive dialects we now consider `BETA` (eligible for LTS):

- **codec** - Serialize structured data.
- **runtime::tokio** - A production-focused runtime based on [Tokio](https://tokio.rs) with secure randomness and storage backed by the local filesystem.
- **parallel::rayon** - Parallelize fold operations with [Rayon](https://docs.rs/rayon/latest/rayon/).
- **math::poly** - Operations over polynomials.
- **cryptography::ed25519** - [Ed25519](https://ed25519.cr.yp.to/) signatures.
- **cryptography::bls12381** - [BLS12-381](https://electriccoin.co/blog/new-snark-curve/) multi-signatures, DKG/Reshare, and threshold signatures.
- **stream::encrypted** - Encrypted stream implementation using [ChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305).
- **p2p::authenticated::discovery** - Communicate with a fixed set of authenticated peers without known addresses over encrypted connections.
- **p2p::authenticated::lookup** - Communicate with a fixed set of authenticated peers with known addresses over encrypted connections.
- **broadcast::buffered** - Broadcast messages to and cache messages from untrusted peers.
- **resolver::p2p** - Resolve data identified by a fixed-length key by using the P2P network.
- **storage::journal** - An append-only log for storing arbitrary data.
- **storage::archive** - A write-once key-value store for ordered data.
- **consensus::simplex** - Simple and fast BFT agreement inspired by [Simplex Consensus](https://simplex.blog/).
- **consensus::marshal** - Ordered delivery of finalized blocks.

## Is It Ready for Production?

The [Commonware Library](https://github.com/commonwarexyz/monorepo) isn't battle-tested (yet). However, we are shooting for the "next best thing."

From the start, we've prioritized robustness and testing above all else. Our [deterministic runtime](/blogs/commonware-runtime.html) has allowed us to reach [93% test coverage](https://app.codecov.io/gh/commonwarexyz/monorepo) across the repository and [97% test coverage](https://app.codecov.io/gh/commonwarexyz/monorepo/tree/main/consensus%2Fsrc%2Fsimplex%2Factors) in critical components (like `consensus::simplex`).

For over 10 months, we've been running all `BETA` primitives listed above in [Alto](https://github.com/commonwarexyz/alto). For the last 9 months, we've been collaborating with [Asymmetric Research](https://x.com/_patrickogrady/status/1915407345414492497) on fuzzing and [manual code review](https://github.com/commonwarexyz/monorepo/issues?q=is%3Aissue%20label%3A%22asymmetric%20research%22).

We have yet to mark any primitives as `DELTA` (bug bounty eligible) but hope to do so in the coming months. In the meantime, we welcome responsible disclosures via [GitHub Vulnerability Reporting](https://github.com/commonwarexyz/monorepo/security).

Interested in helping us get to `GAMMA`, `DELTA`, and `EPSILON`? [We're hiring for great engineers (and offering significant equity)](https://commonware.xyz/hiring.html).