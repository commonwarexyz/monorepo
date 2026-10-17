# commonware

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![Discussions](https://img.shields.io/github/discussions/commonwarexyz/monorepo?label=Discussions&color=purple)](https://github.com/commonwarexyz/monorepo/discussions)
[![Coverage](https://codecov.io/gh/commonwarexyz/monorepo/graph/badge.svg?token=847TBNH49H)](https://codecov.io/gh/commonwarexyz/monorepo)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/commonwarexyz/monorepo)
[![X Follow](https://img.shields.io/twitter/follow/commonwarexyz?style=social)](https://x.com/commonwarexyz)

## Primitives

_Primitives are designed for deployment in adversarial environments. If you find an exploit, please refer to our [security policy](./SECURITY.md) before disclosing it publicly (an exploit may equip a malicious party to attack users of a primitive)._

* [actor](./actor/README.md): Safely coordinate concurrent components.
* [broadcast](./broadcast/README.md): Disseminate data over a wide-area network.
* [codec](./codec/README.md): Serialize structured data.
* [coding](./coding/README.md): Encode data to enable recovery from a subset of fragments.
* [collector](./collector/README.md): Collect responses to committable requests.
* [conformance](./conformance/README.md): Automatically assert the stability of encoding and mechanisms over time.
* [consensus](./consensus/README.md): Order opaque messages in a Byzantine environment.
* [cryptography](./cryptography/README.md): Generate keys, sign arbitrary messages, and deterministically verify signatures.
* [deployer](./deployer/README.md): Deploy infrastructure across cloud providers.
* [glue](./glue/README.md): Default constructions that span multiple primitives.
* [math](./math/README.md): Create and manipulate mathematical objects.
* [p2p](./p2p/README.md): Communicate with authenticated peers.
* [parallel](./parallel/README.md): Parallelize fold operations with pluggable execution strategies.
* [resolver](./resolver/README.md): Resolve data identified by a fixed-length key.
* [runtime](./runtime/README.md): Execute asynchronous tasks with a configurable scheduler.
* [storage](./storage/README.md): Persist and retrieve data from an abstract store.
* [stream](./stream/README.md): Exchange messages over arbitrary transport.

## Examples

_Examples may include insecure code (i.e. deriving keypairs from an integer arguments) to make them easier to run. Examples are not intended to be used directly in production._

* [alto](https://github.com/commonwarexyz/alto): A minimal (and wicked fast) blockchain built with the Commonware Library.
* [battleware](https://github.com/commonwarexyz/battleware): An onchain battle secured by a VRF, Timelock Encryption, and MMRs.
* [bridge](./examples/bridge/README.md): Send succinct consensus certificates between two networks.
* [chat](./examples/chat/README.md): Send encrypted messages to a group of friends.
* [dkg](./examples/dkg/README.md): Generate and reshare a threshold secret over an epoched log.
* [estimator](./examples/estimator/README.md): Simulate mechanism performance under realistic network conditions.
* [flood](./examples/flood/README.md): Spam peers deployed to AWS EC2 with random messages.
* [log](./examples/log/README.md): Commit to a secret log and agree to its hash.

## Miscellaneous

_Sometimes, we opt to maintain software that is neither a primitive nor an example to make it easier to interact with the Commonware Library. Unless otherwise indicated, code in this section is intended to be used in production. Please refer to our [security policy](./SECURITY.md) before disclosing an exploit publicly._

* [docs](./docs): Access information about Commonware at https://commonware.xyz.
* [allocator](./allocator/README.md): Configure and observe the global allocator.
* [docker](./docker): Dockerfiles used for cross-compilation and CI.
* [formatting](./formatting/README.md): Format and parse encoded data.
* [invariants](./invariants/README.md): Define and exercise invariants.
* [macros](./macros/README.md): Augment the development of primitives with procedural macros.
* [mcp](./mcp/README.md): Interact with the Commonware Library via MCP at https://mcp.commonware.xyz.
* [pipeline](./pipeline): Mechanisms under development.
* [sol](./sol/README.md): Verify proofs and certificates in Solidity.
* [utils](./utils/README.md): Leverage common functionality across multiple primitives.

## Stability

All public primitives (and primitive dialects) in the Commonware Library are annotated with a stability level:

| Level        | Index | Description                                                                              |
|--------------|-------|------------------------------------------------------------------------------------------|
| **ALPHA**    | 0     | Breaking changes expected. No migration path provided.                                   |
| **BETA**     | 1     | Wire and storage formats stable. Breaking changes include a migration path.              |
| **GAMMA**    | 2     | API stable. Extensively tested and fuzzed.                                               |
| **DELTA**    | 3     | Battle-tested. Bug bounty eligible.                                                      |
| **EPSILON**  | 4     | Feature-frozen. Only bug fixes and performance improvements accepted.                    |

_Stability is transitive in the Commonware Library; primitives only depend on primitives with equal or higher stability. All `examples` are considered to be at `ALPHA` stability (and will continue to be for the foreseeable future)._

Users employing the Commonware Library can compile with the `commonware_stability_<level>` configuration flag to both view scoped documentation and enforce their application only depends on primitives of a minimum stability:

```bash
# Generate docs for only code with stability >= BETA (level 1)
RUSTFLAGS="--cfg commonware_stability_BETA" RUSTDOCFLAGS="--cfg commonware_stability_BETA -A rustdoc::broken_intra_doc_links" cargo doc --open

# Check if your application only uses commonware APIs with stability >= BETA
RUSTFLAGS="--cfg commonware_stability_BETA" cargo build -p my-app
```

## Platform Compatibility

The Commonware Library supports Linux and macOS, although only Linux is recommended for production use. Select primitives also support `wasm32-unknown-unknown` and `no_std` (for browsers and zkVMs).

x86-64 builds require AVX2, BMI2, and ADX (Intel Broadwell, AMD Zen, or newer). SHA-NI and AVX-512 are detected at runtime. AArch64 builds assume NEON. Only little-endian targets are supported.

_Windows is not a supported target. Running the Commonware Library on Windows may result in undefined behavior._

## Memory Allocation

The Commonware Library does not ship a buffer pool. I/O buffers (`IoBuf` and `IoBufMut` in [runtime](./runtime/README.md)) request exactly the size and alignment they need from the global allocator and leave reuse, caching, and retention to it. Production binaries should run on [mimalloc](https://github.com/microsoft/mimalloc) through [allocator](./allocator/README.md), which builds a vendored copy, lets the binary configure it (how long freed memory is retained, a pinned reservation that is never released, huge pages) instead of relying on environment variables, and exposes its statistics so the runtime can export them as metrics (the `mimalloc` feature of `commonware-runtime`):

```rust
use commonware_allocator::mimalloc::{Config, MiMalloc, Purge, Reserve};
use std::time::Duration;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc::new(Config {
    purge: Purge::After(Duration::from_secs(10)),
    reserve: Some(Reserve::pinned(2 << 30)),
    ..Config::DEFAULT
});
```

Objects above mimalloc's large-object limit (512 KiB by default) get a page of their own, which costs an arena operation per allocation instead of a free-list pop: about 0.3-0.4 us, and 1.5-2 us when eight threads allocate at once. A binary that allocates such buffers on a hot path can raise the limit with the allocator's `large-objects-2m` feature, which brings a 1 MiB allocation to 20-30 ns; in the storage benchmarks this changed nothing end to end and grew peak resident memory by 9-60%, because every page a thread holds per size class grows with the limit. A pool reimplements what a size-class allocator already does (per-thread caches, size classes, lock-free cross-thread frees) and must be threaded through every API that allocates buffers. Measured end to end on mimalloc with exact-size allocations ([#4975](https://github.com/commonwarexyz/monorepo/issues/4975)), journal and paged-cache benchmarks ran within 10% of pooled buffers on Zen 5 and Graviton4, most within 2%; the one consistent exception, replay with 64 KiB buffers, was 7-10% slower under the default purge delay and at parity with purging disabled or large OS pages enabled. Below the large-object limit an exact-size allocation costs 10-35 ns against 4-11 ns for a pool hit, and cross-thread handoff was within noise on one machine and mixed sign on the other. What a pool does provide is retention: memory that stays resident across idle periods so bursts do not page fault. That is a policy for the whole process, and the allocator already offers it: disabling purging (`Purge::Never`) or a pinned reservation gives the same fault-free bursts, and a purge delay longer than the idle gaps bounds the cost to one purge pass per window. A pool only pays off on glibc, whose thread cache serves requests up to about 1 KiB, so I/O-sized aligned buffers go to its arena and every aligned allocation from 1 MiB up was a fresh `mmap` in our measurements (about 100 us per touched MiB), which is one more reason to run on mimalloc.

## Licensing

This repository is dual-licensed under both the [Apache 2.0](./LICENSE-APACHE) and [MIT](./LICENSE-MIT) licenses. You may choose either license when employing this code.

## Contributing

We encourage external contributors to submit issues and pull requests to the Commonware Library. To learn more, please refer to our [contributing guidelines](./CONTRIBUTING.md).

All work is coordinated via the [tracker](https://github.com/orgs/commonwarexyz/projects/2). If something in [the backlog](https://github.com/orgs/commonwarexyz/projects/2/views/3) looks particularly useful, leave a comment so we can prioritize it!

## MCP Support (for LLMs)

Make your LLM more effective by connecting to the [Commonware Library MCP server](https://mcp.commonware.xyz). Learn more [here](https://commonware.xyz/mcp).

### Claude Code

```bash
claude mcp add --transport http commonware-library https://mcp.commonware.xyz
```

### Cursor

```json
{
  "mcpServers": {
    "commonware-library": {
      "url": "https://mcp.commonware.xyz"
    }
  }
}
```

## Support

If you have any questions about using the Commonware Library, we encourage you to post in [GitHub Discussions](https://github.com/commonwarexyz/monorepo/discussions). We're happy to help!
