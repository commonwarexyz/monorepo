# commonware

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![Discussions](https://img.shields.io/github/discussions/commonwarexyz/monorepo?label=Discussions&color=purple)](https://github.com/commonwarexyz/monorepo/discussions)
[![Benchmarks](https://img.shields.io/badge/1042-benchmarks?style=flat&label=Benchmarks&color=orange)](https://commonware.xyz/benchmarks.html)
[![Coverage](https://codecov.io/gh/commonwarexyz/monorepo/graph/badge.svg?token=847TBNH49H)](https://codecov.io/gh/commonwarexyz/monorepo)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/commonwarexyz/monorepo)
[![X Follow](https://img.shields.io/twitter/follow/commonwarexyz?style=social)](https://x.com/commonwarexyz)

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
* [macros](./macros/README.md): Augment the development of primitives with procedural macros.
* [mcp](./mcp/README.md): Interact with the Commonware Library via MCP at https://mcp.commonware.xyz.
* [pipeline](./pipeline): Mechanisms under development.
* [utils](./utils/README.md): Leverage common functionality across multiple primitives.

## Stability

Each public API item in the Commonware Library is annotated with a stability level:

| Level | Description |
|-------|-------------|
| **ALPHA** | Significant breaking changes expected with no migration path. Critical vulnerabilities possible. |
| **BETA** | Wire and storage format stable. All breaking changes include a migration path. |
| **GAMMA** | API stable. Audited multiple times and fuzzed extensively. |
| **DELTA** | Battle-tested. Only changes expected are performance optimizations. |
| **EPSILON** | Primitive is frozen. No changes expected. |

Higher stability code can only depend on code with equal or higher stability. This is enforced at compile time:

```bash
# Generate docs for only code with stability >= GAMMA (level 2)
RUSTFLAGS="--cfg commonware_stability_GAMMA" RUSTDOCFLAGS="--cfg commonware_stability_GAMMA" cargo doc

# Check if your application only uses commonware APIs with stability >= GAMMA
RUSTFLAGS="--cfg commonware_stability_GAMMA" cargo build -p my-app
```

Level names: `ALPHA` (0), `BETA` (1), `GAMMA` (2), `DELTA` (3), `EPSILON` (4).

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
