---
title: "Is it ready yet?"
description: "How compiler-enforced stability levels help you know what's production-ready in the Commonware Library."
date: "February 5rd, 2026"
published-time: "2026-02-05T00:00:00Z"
modified-time: "2026-02-05T00:00:00Z"
author: "Patrick O'Grady"
author_twitter: "https://x.com/_patrickogrady"
url: "https://commonware.xyz/blogs/is-it-ready-yet"
image: "https://commonware.xyz/imgs/is-it-ready-yet.png"
---

The [Commonware Library](https://github.com/commonwarexyz/monorepo) is now home to 17 primitives and over 50 primitive dialects (cryptography::bls12381, cryptography::ed25519, etc.), with [93% test coverage](https://app.codecov.io/gh/commonwarexyz/monorepo) and [1500 daily benchmarks](https://commonware.xyz/benchmarks.html).

The only number that probably matters to you, however, is how many are ready to use.

Today, we are sharing our approach to stability, explaining how we enforce consistent stability with the compiler, and graduate a large number of primitives to [BETA](https://github.com/commonwarexyz/monorepo#stability).

## Solving a "Solved" Problem

The obvious approach to tracking stability is to break each primitive (and primitive dialect) into its own crate and to apply [semantic versioning](https://semver.org/). `1.0` means stable. `0.x` means unstable. Major bump is breaking changes. Minor bump is breaking API. Patch bump is bug fixes. Hide new features that are still in development behind an `unstable` feature flag. End blog here?

While working with different teams, we found that this approach didn't cut it. In an environment where a subtle breaking change means a network halt or a loss of funds, we opted to take a more "paranoid" approach. The root issues:

- With many crates all versioned independently, (tested) compatibility is no longer obvious. While `consensus-simplex@1.1.3` may compile with `storage-journal@2.3.45` and "should" work, it doesn't mean the combination has been tested together.
- Dependency risk is difficult to assess when things are coarsely broken into "stable" and "unstable". Often wrapped with documents that few people read, it is pretty easy to incorporate functionality once "unstable" is permitted that is a lot more "unstable" than you expected.
- Feature flags are viral. If your crate depends on `commonware-consensus` and you want access to an unstable API in `commonware-cryptography`, then `commonware-consensus` needs to expose and forward that feature. Every intermediate crate in the dependency chain needs to opt in. This becomes unwieldy fast.
- Doesn't imply anything about backwards-compatibility. Once something is considered "stable", it should remain supported indefinitely. This is equivalent to one major version that doesn't get incremented.

## Tiered Stability and Calendar Versioning

We've broken stability into the following levels:

| Level        | Index | Description                                                                              |
|--------------|-------|------------------------------------------------------------------------------------------|
| **ALPHA**    | 0     | Breaking changes expected. No migration path provided.                                   |
| **BETA**     | 1     | Wire and storage formats stable. Breaking changes include a migration path.              |
| **GAMMA**    | 2     | API stable. Extensively tested and fuzzed.                                               |
| **DELTA**    | 3     | Battle-tested. Bug bounty eligible.                                                      |
| **EPSILON**  | 4     | Feature-frozen. Only bug fixes and performance improvements accepted.                    |

We take Long-Term Support (LTS) seriously. We expect to support primitives that are marked as wire/format stable for years. Likewise, primitives that are massive changes won't replace existing ones. Instead they'll be new primitive dialects.

The Commonware Library is versioned using calendar versioning (YYYY.M.patch). Uniform versioning across primitives for "obvious" compatibility without implying stability (a uniform library version of `1.2.1` may imply a brand new crate is much stabler than it is).

## Programmatic Enforcement

Every public object in the Commonware Library is annotated with a stability level using proc macros that expand to `cfg` attributes.

Set your minimum stability level once via `RUSTFLAGS` and it applies globally:

```bash
RUSTFLAGS="--cfg commonware_stability_BETA" cargo build -p my-app
```

If your code depends on an ALPHA API, it won't compile. No runtime checks. No documentation to read. The compiler tells you.

You can also filter rustdoc to show only APIs at your desired stability level:

```bash
RUSTFLAGS="--cfg commonware_stability_BETA" \
RUSTDOCFLAGS="--cfg commonware_stability_BETA" \
cargo doc --open
```

### Testing Consistency

In CI, we enforce that any object of some level must rely on objects with the same or higher level. If something is marked BETA, you can trust that its entire dependency chain within the library is BETA or higher.

![Figure 1: The stability levels are enforced by the compiler](/imgs/is-it-ready-yet.png)

## Graduation Day

Here are some of the primitive dialects we now consider `BETA` (wire and storage format stable):

* **codec** - Serialize structured data.
* **runtime::tokio** - A production-focused runtime based on [Tokio](https://tokio.rs) with secure randomness and storage backed by the local filesystem.
* **parallel::rayon** - Parallelize fold operations with [Rayon](https://docs.rs/rayon/latest/rayon/).
* **math::poly** - Operations over polynomials.
* **cryptography::ed25519** - [Ed25519](https://ed25519.cr.yp.to/) signatures.
* **cryptography::bls12381** - [BLS12-381](https://electriccoin.co/blog/new-snark-curve/) multi-signatures, DKG/Reshare, and threshold signatures.
* **stream::encrypted** - Encrypted stream implementation using [ChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305).
* **p2p::authenticated::discovery** - Communicate with a fixed set of authenticated peers without known addresses over encrypted connections.
* **p2p::authenticated::lookup** - Communicate with a fixed set of authenticated peers with known addresses over encrypted connections.
* **broadcast::buffered** - Broadcast messages to and cache messages from untrusted peers.
* **resolver::p2p** - Resolve data identified by a fixed-length key by using the P2P network.
* **storage::journal** - An append-only log for storing arbitrary data.
* **storage::archive** - A write-once key-value store for ordered data.
* **consensus::simplex** - Simple and fast BFT agreement inspired by [Simplex Consensus](https://simplex.blog/).
* **consensus::marshal** - Ordered delivery of finalized blocks.

## Is It Ready for Production?

The [Commonware Library](https://github.com/commonwarexyz/monorepo) isn't battle-tested (yet). However, we believe the Commonware Library is the "next best thing."

From the start, we've prioritized robustness and testing above all else. Our [deterministic runtime](/blogs/commonware-runtime.html) has allowed us to reach [93% test coverage](https://app.codecov.io/gh/commonwarexyz/monorepo) across the repository and [97% test coverage](https://app.codecov.io/gh/commonwarexyz/monorepo/tree/main/consensus%2Fsrc%2Fsimplex%2Factors) in critical components (like `consensus::simplex`).

For over 10 months, we've been running all `BETA` primitives listed above in [Alto](https://github.com/commonwarexyz/alto). For the last 9 months, we've been collaborating with [Asymmetric Research](https://x.com/_patrickogrady/status/1915407345414492497) on fuzzing and [manual code review](https://github.com/commonwarexyz/monorepo/issues?q=is%3Aissue%20label%3A%22asymmetric%20research%22).

We have yet to mark any primitives as `DELTA` (bug bounty eligible) but hope to do so in the coming months. In the meantime, we welcome responsible disclosures via [GitHub Vulnerability Reporting](https://github.com/commonwarexyz/monorepo/security).