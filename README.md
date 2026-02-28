# commonware

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![Discussions](https://img.shields.io/github/discussions/commonwarexyz/monorepo?label=Discussions&color=purple)](https://github.com/commonwarexyz/monorepo/discussions)
[![Benchmarks](https://img.shields.io/badge/1042-benchmarks?style=flat&label=Benchmarks&color=orange)](https://commonware.xyz/benchmarks.html)
[![Coverage](https://codecov.io/gh/commonwarexyz/monorepo/graph/badge.svg?token=847TBNH49H)](https://codecov.io/gh/commonwarexyz/monorepo)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/commonwarexyz/monorepo)
[![X Follow](https://img.shields.io/twitter/follow/commonwarexyz?style=social)](https://x.com/commonwarexyz)

## Status

_Stabilized primitives guarantee no wire/storage format changes until the next minor release._

* [broadcast](./broadcast/README.md): Alpha, not stabilized
* [codec](./codec/README.md): Alpha, not stabilized
* [coding](./coding/README.md): Alpha, not stabilized
* [collector](./collector/README.md): Alpha, not stabilized
* [conformance](./conformance/README.md): Alpha, not stabilized
* [consensus](./consensus/README.md): Alpha, not stabilized
* [cryptography](./cryptography/README.md): Alpha, not stabilized
* [deployer](./deployer/README.md): Alpha, not stabilized
* [math](./math/README.md): Alpha, not stabilized
* [p2p](./p2p/README.md): Alpha, not stabilized
* [resolver](./resolver/README.md): Alpha, not stabilized
* [runtime](./runtime/README.md): Alpha, not stabilized
* [storage](./storage/README.md): Alpha, not stabilized
* [stream](./stream/README.md): Alpha, not stabilized

## Primitives

_Primitives are designed for deployment in adversarial environments. If you find an exploit, please refer to our [security policy](./SECURITY.md) before disclosing it publicly (an exploit may equip a malicious party to attack users of a primitive)._

* [broadcast](./broadcast/README.md): Disseminate data over a wide-area network.
* [codec](./codec/README.md): Serialize structured data.
* [coding](./coding/README.md): Encode data to enable recovery from a subset of fragments.
* [collector](./collector/README.md): Collect responses to committable requests.
* [conformance](./conformance/README.md): Automatically assert the stability of encoding and mechanisms over time.
* [consensus](./consensus/README.md): Order opaque messages in a Byzantine environment.
* [cryptography](./cryptography/README.md): Generate keys, sign arbitrary messages, and deterministically verify signatures.
* [deployer](./deployer/README.md): Deploy infrastructure across cloud providers.
* [math](./math/README.md): Create and manipulate mathematical objects.
* [p2p](./p2p/README.md): Communicate with authenticated peers over encrypted connections.
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
* [estimator](./examples/estimator/README.md): Simulate mechanism performance under realistic network conditions.
* [flood](./examples/flood/README.md): Spam peers deployed to AWS EC2 with random messages.
* [log](./examples/log/README.md): Commit to a secret log and agree to its hash.
* [reshare](./examples/reshare/README.md): Reshare a threshold secret over an epoched log.
* [sync](./examples/sync/README.md): Synchronize state between a server and client.

## Miscellaneous

_Sometimes, we opt to maintain software that is neither a primitive nor an example to make it easier to interact with the Commonware Library. Unless otherwise indicated, code in this section is intended to be used in production. Please refer to our [security policy](./SECURITY.md) before disclosing an exploit publicly._

* [docs](./docs): Access information about Commonware at https://commonware.xyz.
* [docker](./docker): Dockerfiles used for cross-compilation and CI.
* [invariants](./invariants/README.md): Define and exercise invariants.
* [macros](./macros/README.md): Augment the development of primitives with procedural macros.
* [mcp](./mcp/README.md): Interact with the Commonware Library via MCP at https://mcp.commonware.xyz.
* [pipeline](./pipeline): Mechanisms under development.
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
